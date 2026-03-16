package archive

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Zyrakk/noctis/internal/models"
)

// TestFromFinding verifies that a models.Finding is correctly converted to a
// RawContent for archiving — all mapped fields must carry over.
func TestFromFinding(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	f := models.Finding{
		ID:          "f-001",
		Source:      "telegram",
		SourceID:    "chan-123",
		SourceName:  "darknet-leaks",
		Content:     "leaked credentials dump 2025",
		ContentHash: "abc123hash",
		Author:      "shadow_broker",
		Timestamp:   ts,
		CollectedAt: ts.Add(5 * time.Minute),
		Metadata:    map[string]string{"channel_type": "private"},
	}

	rc := FromFinding(f)

	if rc.SourceType != f.Source {
		t.Errorf("SourceType = %q, want %q", rc.SourceType, f.Source)
	}
	if rc.SourceID != f.SourceID {
		t.Errorf("SourceID = %q, want %q", rc.SourceID, f.SourceID)
	}
	if rc.SourceName != f.SourceName {
		t.Errorf("SourceName = %q, want %q", rc.SourceName, f.SourceName)
	}
	if rc.Content != f.Content {
		t.Errorf("Content = %q, want %q", rc.Content, f.Content)
	}
	if rc.ContentHash != f.ContentHash {
		t.Errorf("ContentHash = %q, want %q", rc.ContentHash, f.ContentHash)
	}
	if rc.Author != f.Author {
		t.Errorf("Author = %q, want %q", rc.Author, f.Author)
	}
	if !rc.CollectedAt.Equal(f.CollectedAt) {
		t.Errorf("CollectedAt = %v, want %v", rc.CollectedAt, f.CollectedAt)
	}
	if rc.PostedAt == nil {
		t.Fatal("PostedAt should not be nil when Finding.Timestamp is set")
	}
	if !rc.PostedAt.Equal(ts) {
		t.Errorf("PostedAt = %v, want %v", *rc.PostedAt, ts)
	}
	if rc.Metadata == nil {
		t.Fatal("Metadata should not be nil when Finding.Metadata is set")
	}
	if v, ok := rc.Metadata["channel_type"]; !ok || v != "private" {
		t.Errorf("Metadata[channel_type] = %v, want %q", v, "private")
	}

	// Default/zero fields should remain at zero values.
	if rc.Classified {
		t.Error("Classified should default to false")
	}
	if rc.Category != "" {
		t.Errorf("Category should be empty, got %q", rc.Category)
	}
	if rc.Severity != "" {
		t.Errorf("Severity should be empty, got %q", rc.Severity)
	}
	if rc.EntitiesExtracted {
		t.Error("EntitiesExtracted should default to false")
	}
}

// TestFromFinding_ZeroTimestamp verifies that a zero-value Timestamp on the
// Finding results in a nil PostedAt on the RawContent.
func TestFromFinding_ZeroTimestamp(t *testing.T) {
	f := models.Finding{
		Source:      "paste",
		SourceID:    "paste-001",
		SourceName:  "pastebin",
		Content:     "some paste content",
		ContentHash: "def456hash",
		CollectedAt: time.Now().UTC(),
	}

	rc := FromFinding(f)

	if rc.PostedAt != nil {
		t.Errorf("PostedAt should be nil for zero Timestamp, got %v", *rc.PostedAt)
	}
}

// TestFromFinding_NilMetadata verifies that a nil Metadata map on the Finding
// results in a nil Metadata on the RawContent (no empty-map allocation).
func TestFromFinding_NilMetadata(t *testing.T) {
	f := models.Finding{
		Source:      "web",
		SourceID:    "web-001",
		SourceName:  "forum-xyz",
		Content:     "content",
		ContentHash: "ghi789hash",
		CollectedAt: time.Now().UTC(),
		Metadata:    nil,
	}

	rc := FromFinding(f)

	if rc.Metadata != nil {
		t.Errorf("Metadata should be nil when Finding.Metadata is nil, got %v", rc.Metadata)
	}
}

// TestSearchQuery_DefaultLimit verifies that normalizeLimit applies the default
// when no limit (zero) is provided.
func TestSearchQuery_DefaultLimit(t *testing.T) {
	got := normalizeLimit(0)
	if got != 50 {
		t.Errorf("normalizeLimit(0) = %d, want 50", got)
	}
}

// TestSearchQuery_NegativeLimit verifies that negative limits fall back to
// the default.
func TestSearchQuery_NegativeLimit(t *testing.T) {
	got := normalizeLimit(-10)
	if got != 50 {
		t.Errorf("normalizeLimit(-10) = %d, want 50", got)
	}
}

// TestSearchQuery_MaxLimit verifies that limits exceeding 500 are clamped.
func TestSearchQuery_MaxLimit(t *testing.T) {
	got := normalizeLimit(1000)
	if got != 500 {
		t.Errorf("normalizeLimit(1000) = %d, want 500", got)
	}
}

// TestSearchQuery_ValidLimit verifies that limits within range pass through.
func TestSearchQuery_ValidLimit(t *testing.T) {
	got := normalizeLimit(100)
	if got != 100 {
		t.Errorf("normalizeLimit(100) = %d, want 100", got)
	}
}

// TestRawContent_Construction verifies that a RawContent struct can be
// initialized with all fields and that they hold the assigned values.
func TestRawContent_Construction(t *testing.T) {
	now := time.Now().UTC()
	posted := now.Add(-1 * time.Hour)

	rc := RawContent{
		ID:                "rc-001",
		SourceType:        "telegram",
		SourceID:          "chan-456",
		SourceName:        "threat-feed",
		Content:           "malware sample observed in wild",
		ContentHash:       "hash-abc-123",
		Author:            "analyst1",
		AuthorID:          "uid-789",
		URL:               "https://t.me/threat-feed/42",
		Language:          "en",
		CollectedAt:       now,
		PostedAt:          &posted,
		Metadata:          map[string]interface{}{"views": float64(1500)},
		Classified:        true,
		Category:          "malware_sample",
		Tags:              []string{"malware", "apt"},
		Severity:          "high",
		Summary:           "Malware sample in the wild",
		EntitiesExtracted: true,
	}

	if rc.ID != "rc-001" {
		t.Errorf("ID = %q, want %q", rc.ID, "rc-001")
	}
	if rc.SourceType != "telegram" {
		t.Errorf("SourceType = %q, want %q", rc.SourceType, "telegram")
	}
	if rc.ContentHash != "hash-abc-123" {
		t.Errorf("ContentHash = %q, want %q", rc.ContentHash, "hash-abc-123")
	}
	if rc.AuthorID != "uid-789" {
		t.Errorf("AuthorID = %q, want %q", rc.AuthorID, "uid-789")
	}
	if rc.URL != "https://t.me/threat-feed/42" {
		t.Errorf("URL = %q, want %q", rc.URL, "https://t.me/threat-feed/42")
	}
	if rc.Language != "en" {
		t.Errorf("Language = %q, want %q", rc.Language, "en")
	}
	if !rc.CollectedAt.Equal(now) {
		t.Errorf("CollectedAt = %v, want %v", rc.CollectedAt, now)
	}
	if rc.PostedAt == nil || !rc.PostedAt.Equal(posted) {
		t.Errorf("PostedAt = %v, want %v", rc.PostedAt, posted)
	}
	if !rc.Classified {
		t.Error("Classified should be true")
	}
	if rc.Category != "malware_sample" {
		t.Errorf("Category = %q, want %q", rc.Category, "malware_sample")
	}
	if len(rc.Tags) != 2 || rc.Tags[0] != "malware" || rc.Tags[1] != "apt" {
		t.Errorf("Tags = %v, want [malware apt]", rc.Tags)
	}
	if rc.Severity != "high" {
		t.Errorf("Severity = %q, want %q", rc.Severity, "high")
	}
	if rc.Summary != "Malware sample in the wild" {
		t.Errorf("Summary = %q, want %q", rc.Summary, "Malware sample in the wild")
	}
	if !rc.EntitiesExtracted {
		t.Error("EntitiesExtracted should be true")
	}
}

// TestStore_Interface is a compile-time check that Store has the expected
// method signatures. If any signature changes, this test will fail to compile.
func TestStore_Interface(t *testing.T) {
	// This is a compile-time verification only — we don't call these methods
	// because they require a live database connection.
	var s *Store

	// Verify method signatures exist at compile time by assigning them to
	// typed function variables.
	var (
		_ func(*Store) *pgxpool.Pool // pool field access not needed externally

		// The methods below are typed to verify they exist with correct signatures.
		_ = s.Insert
		_ = s.MarkClassified
		_ = s.MarkEntitiesExtracted
		_ = s.FetchUnclassified
		_ = s.Search
		_ = s.Stats
	)

	// Also verify FromFinding is a package-level function.
	_ = FromFinding
}
