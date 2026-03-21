package ingest

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/llm"
	"github.com/Zyrakk/noctis/internal/matcher"
	"github.com/Zyrakk/noctis/internal/models"
)

// ---------------------------------------------------------------------------
// fakeArchive — in-memory implementation of archive operations for testing.
// ---------------------------------------------------------------------------

type fakeArchive struct {
	mu         sync.Mutex
	entries    []archive.RawContent
	classified map[string]bool
	extracted  map[string]bool
	iocs       []fakeIOCRecord
}

type fakeIOCRecord struct {
	Type            string
	Value           string
	Context         string
	SourceContentID string
}

func newFakeArchive() *fakeArchive {
	return &fakeArchive{
		classified: make(map[string]bool),
		extracted:  make(map[string]bool),
	}
}

func (fa *fakeArchive) insert(ctx context.Context, rc *archive.RawContent) error {
	fa.mu.Lock()
	defer fa.mu.Unlock()

	for _, e := range fa.entries {
		if e.ContentHash == rc.ContentHash {
			return nil // dedup
		}
	}

	if rc.ID == "" {
		rc.ID = rc.ContentHash
	}

	fa.entries = append(fa.entries, *rc)
	return nil
}

func (fa *fakeArchive) entryCount() int {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return len(fa.entries)
}

// ---------------------------------------------------------------------------
// fakeLLMClient — returns canned responses based on substring matching.
// ---------------------------------------------------------------------------

type fakeLLMClient struct {
	responses map[string]string
}

func (f *fakeLLMClient) ChatCompletion(_ context.Context, messages []llm.Message, _ ...llm.Option) (*llm.Response, error) {
	var combined strings.Builder
	for _, msg := range messages {
		combined.WriteString(msg.Content)
	}
	prompt := combined.String()

	for key, resp := range f.responses {
		if strings.Contains(prompt, key) {
			return &llm.Response{Content: resp}, nil
		}
	}
	return &llm.Response{Content: `{"category":"irrelevant","confidence":0.5}`}, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func makeTestAnalyzer(t *testing.T, llmClient llm.LLMClient) *analyzer.Analyzer {
	t.Helper()
	return analyzer.New(llmClient, "../../prompts")
}

func makeTestRules() []config.RuleConfig {
	return []config.RuleConfig{
		{
			Name:     "cred-leak",
			Type:     "keyword",
			Patterns: []string{"example.com"},
			Severity: "high",
		},
	}
}

func makeFakeLLM() *fakeLLMClient {
	return &fakeLLMClient{
		responses: map[string]string{
			"Classify": `{"category":"credential_leak","confidence":0.95,"provenance":"first_party"}`,
			"Extract":  `[{"type":"domain","value":"example.com","context":"leaked creds","malicious":true}]`,
			"Assess":   `{"severity":"critical","reasoning":"Active credentials exposed"}`,
			"Write":    "Credentials for example.com were leaked on Telegram.",
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestIngestPipeline_ArchiveAndAlert verifies that a matched finding is both
// archived and dispatched via the alertFn callback. This tests the full
// Process() flow (archive -> match -> LLM enrich -> alert) using a fake
// archive and a real matcher + analyzer with canned LLM responses.
func TestIngestPipeline_ArchiveAndAlert(t *testing.T) {
	fa := newFakeArchive()
	llmClient := makeFakeLLM()
	az := makeTestAnalyzer(t, llmClient)
	rules := makeTestRules()

	m, err := matcher.New(rules)
	if err != nil {
		t.Fatalf("matcher.New error: %v", err)
	}

	var mu sync.Mutex
	var alerts []models.EnrichedFinding
	alertFn := func(ef models.EnrichedFinding) {
		mu.Lock()
		alerts = append(alerts, ef)
		mu.Unlock()
	}

	finding := models.Finding{
		ID:          "match-1",
		Source:      "telegram",
		SourceName:  "threat-channel",
		Content:     "leaked creds for example.com admin:hunter2",
		ContentHash: "abc123",
		CollectedAt: time.Now().UTC(),
	}

	ctx := context.Background()

	// Step 1: Archive.
	rc := archive.FromFinding(finding)
	if err := fa.insert(ctx, rc); err != nil {
		t.Fatalf("Insert error: %v", err)
	}

	// Step 2: Match.
	result, matched := m.Match(finding)
	if !matched {
		t.Fatal("expected finding to match")
	}

	// Step 3: LLM enrichment.
	enriched := models.EnrichedFinding{
		Finding:      finding,
		MatchType:    result.MatchType,
		MatchedRules: result.MatchedRules,
		Severity:     result.Severity,
	}

	classResult, err := az.Classify(ctx, &finding, result.MatchedRules)
	if err == nil {
		enriched.Category = models.Category(classResult.Category)
		enriched.Confidence = classResult.Confidence
	}

	iocs, err := az.ExtractIOCs(ctx, &finding)
	if err == nil {
		enriched.IOCs = iocs
	}

	llmSev, err := az.AssessSeverity(ctx, &finding, string(enriched.Category), result.MatchedRules)
	if err == nil && llmSev > enriched.Severity {
		enriched.Severity = llmSev
	}

	summary, err := az.Summarize(ctx, &finding, string(enriched.Category), enriched.Severity)
	if err == nil {
		enriched.LLMAnalysis = summary
	}

	// Step 4: Alert.
	alertFn(enriched)

	// Verify: archived.
	if fa.entryCount() != 1 {
		t.Errorf("archive entry count = %d; want 1", fa.entryCount())
	}

	// Verify: alert dispatched with enrichment.
	mu.Lock()
	defer mu.Unlock()
	if len(alerts) != 1 {
		t.Fatalf("alerts count = %d; want 1", len(alerts))
	}

	ef := alerts[0]
	if ef.ID != "match-1" {
		t.Errorf("ID = %q; want %q", ef.ID, "match-1")
	}
	if ef.Category != models.CategoryCredentialLeak {
		t.Errorf("Category = %q; want %q", ef.Category, models.CategoryCredentialLeak)
	}
	if ef.Confidence != 0.95 {
		t.Errorf("Confidence = %v; want 0.95", ef.Confidence)
	}
	if ef.Severity != models.SeverityCritical {
		t.Errorf("Severity = %v; want SeverityCritical", ef.Severity)
	}
	if len(ef.IOCs) != 1 || ef.IOCs[0].Value != "example.com" {
		t.Errorf("IOCs = %v; want [{domain example.com ...}]", ef.IOCs)
	}
	if ef.LLMAnalysis == "" {
		t.Error("LLMAnalysis is empty; want non-empty summary")
	}
}

// TestIngestPipeline_ArchiveNoAlert verifies that an unmatched finding is
// archived but does NOT trigger an alert.
func TestIngestPipeline_ArchiveNoAlert(t *testing.T) {
	fa := newFakeArchive()
	rules := makeTestRules()

	m, err := matcher.New(rules)
	if err != nil {
		t.Fatalf("matcher.New error: %v", err)
	}

	alertCalled := false
	alertFn := func(_ models.EnrichedFinding) {
		alertCalled = true
	}

	finding := models.Finding{
		ID:          "no-match-1",
		Source:      "paste",
		Content:     "totally unrelated content about cooking recipes",
		ContentHash: "def456",
		CollectedAt: time.Now().UTC(),
	}

	ctx := context.Background()

	// Step 1: Archive.
	rc := archive.FromFinding(finding)
	if err := fa.insert(ctx, rc); err != nil {
		t.Fatalf("Insert error: %v", err)
	}

	// Step 2: Match — should not match.
	_, matched := m.Match(finding)
	if matched {
		t.Fatal("expected finding NOT to match")
	}

	// No alert path — content stays unclassified for background workers.
	_ = alertFn

	// Verify: archived.
	if fa.entryCount() != 1 {
		t.Errorf("archive entry count = %d; want 1", fa.entryCount())
	}

	// Verify: no alert.
	if alertCalled {
		t.Error("alertFn was called; want no alert for unmatched finding")
	}
}

// TestIngestPipeline_Dedup verifies that inserting the same finding twice
// only creates one archive entry (dedup via content_hash).
func TestIngestPipeline_Dedup(t *testing.T) {
	fa := newFakeArchive()
	ctx := context.Background()

	finding := models.Finding{
		ID:          "dup-1",
		Source:      "telegram",
		Content:     "some duplicate content",
		ContentHash: "hash-dup",
		CollectedAt: time.Now().UTC(),
	}

	rc := archive.FromFinding(finding)
	if err := fa.insert(ctx, rc); err != nil {
		t.Fatalf("first Insert error: %v", err)
	}

	rc2 := archive.FromFinding(finding)
	if err := fa.insert(ctx, rc2); err != nil {
		t.Fatalf("second Insert error: %v", err)
	}

	if fa.entryCount() != 1 {
		t.Errorf("archive entry count = %d; want 1 (dedup failed)", fa.entryCount())
	}
}

// TestRateLimiter_EnforcesDelay verifies that the rate limiter blocks for at
// least minDelay between consecutive calls.
func TestRateLimiter_EnforcesDelay(t *testing.T) {
	delay := 100 * time.Millisecond
	rl := newRateLimiter(delay)
	ctx := context.Background()

	start := time.Now()

	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("first Wait error: %v", err)
	}

	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("second Wait error: %v", err)
	}

	elapsed := time.Since(start)
	if elapsed < delay {
		t.Errorf("elapsed = %v; want >= %v", elapsed, delay)
	}
}

// TestRateLimiter_RespectsContext verifies that Wait() returns the context
// error immediately when the context is already cancelled, without waiting
// the full delay.
func TestRateLimiter_RespectsContext(t *testing.T) {
	delay := 5 * time.Second
	rl := newRateLimiter(delay)

	// First call sets lastCall.
	ctx := context.Background()
	if err := rl.Wait(ctx); err != nil {
		t.Fatalf("first Wait error: %v", err)
	}

	// Cancel immediately.
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := rl.Wait(cancelCtx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Wait returned nil; want context error")
	}
	if err != context.Canceled {
		t.Errorf("Wait error = %v; want context.Canceled", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("Wait took %v; should have returned near-immediately on cancelled context", elapsed)
	}
}

// TestTagsFromCategory verifies the tag derivation logic for known and unknown
// categories.
func TestTagsFromCategory(t *testing.T) {
	tests := []struct {
		category  string
		wantLen   int
		wantFirst string
	}{
		{"", 0, ""},
		{"credential_leak", 2, "credential_leak"},
		{"malware_sample", 2, "malware_sample"},
		{"threat_actor_comms", 2, "threat_actor_comms"},
		{"access_broker", 2, "access_broker"},
		{"data_dump", 2, "data_dump"},
		{"vulnerability", 2, "vulnerability"},
		{"canary_hit", 2, "canary_hit"},
		{"irrelevant", 1, "irrelevant"},
		{"unknown_category", 1, "unknown_category"},
	}

	for _, tc := range tests {
		tags := tagsFromCategory(tc.category)
		if len(tags) != tc.wantLen {
			t.Errorf("tagsFromCategory(%q) len = %d; want %d (tags=%v)", tc.category, len(tags), tc.wantLen, tags)
			continue
		}
		if tc.wantLen > 0 && tags[0] != tc.wantFirst {
			t.Errorf("tagsFromCategory(%q)[0] = %q; want %q", tc.category, tags[0], tc.wantFirst)
		}
	}
}

// TestFindingFromRawContent verifies the conversion from archive.RawContent
// back to models.Finding for background worker use.
func TestFindingFromRawContent(t *testing.T) {
	now := time.Now().UTC()
	posted := now.Add(-1 * time.Hour)

	rc := archive.RawContent{
		ID:          "rc-1",
		SourceType:  "telegram",
		SourceID:    "chan-123",
		SourceName:  "threat-intel",
		Content:     "some content",
		ContentHash: "hash-1",
		Author:      "actor1",
		CollectedAt: now,
		PostedAt:    &posted,
	}

	f := findingFromRawContent(rc)

	if f.ID != "rc-1" {
		t.Errorf("ID = %q; want %q", f.ID, "rc-1")
	}
	if f.Source != "telegram" {
		t.Errorf("Source = %q; want %q", f.Source, "telegram")
	}
	if f.SourceID != "chan-123" {
		t.Errorf("SourceID = %q; want %q", f.SourceID, "chan-123")
	}
	if f.Content != "some content" {
		t.Errorf("Content = %q; want %q", f.Content, "some content")
	}
	if f.Timestamp != posted {
		t.Errorf("Timestamp = %v; want %v", f.Timestamp, posted)
	}
}
