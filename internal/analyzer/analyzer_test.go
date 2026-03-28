package analyzer

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/llm"
	"github.com/Zyrakk/noctis/internal/models"
)

// mockLLMClient routes calls to canned responses by substring-matching the
// combined prompt text against known keys.
type mockLLMClient struct {
	// responses maps a substring to match in the prompt to the desired response.
	responses map[string]string
}

func (m *mockLLMClient) ChatCompletion(_ context.Context, messages []llm.Message, _ ...llm.Option) (*llm.Response, error) {
	// Concatenate all message content for matching.
	var combined strings.Builder
	for _, msg := range messages {
		combined.WriteString(msg.Content)
	}
	prompt := combined.String()

	for key, resp := range m.responses {
		if strings.Contains(prompt, key) {
			return &llm.Response{Content: resp}, nil
		}
	}
	return &llm.Response{Content: ""}, nil
}

// newTestAnalyzer creates an Analyzer pointing at the shared prompts directory.
func newTestAnalyzer(t *testing.T, client llm.LLMClient) *Analyzer {
	t.Helper()
	a := New(client, "../../prompts")
	return a
}

// testFinding returns a minimal Finding suitable for all test cases.
func testFinding() *models.Finding {
	return &models.Finding{
		Source:     "telegram",
		SourceName: "test-channel",
		Content:    "admin:hunter2 password leaked for example.com, C2 at 192.168.1.100",
		Author:     "testuser",
		Timestamp:  time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC),
	}
}

// TestExtractJSON verifies that JSON is correctly extracted from LLM responses
// that may include preamble text, code fences, or postamble commentary.
func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain json", `{"a":"b"}`, `{"a":"b"}`},
		{"json fence", "```json\n{\"a\":\"b\"}\n```", `{"a":"b"}`},
		{"bare fence", "```\n{\"a\":\"b\"}\n```", `{"a":"b"}`},
		{"trailing fence only", "{\"a\":\"b\"}\n```", `{"a":"b"}`},
		{"with whitespace", "  ```json\n{\"a\":\"b\"}\n```  ", `{"a":"b"}`},
		{"array", "```json\n[1,2,3]\n```", `[1,2,3]`},
		{"trailing newlines", "```json\n{\"a\":\"b\"}\n```\n\n", `{"a":"b"}`},
		{"no newline after tag", "```json{\"a\":\"b\"}```", `{"a":"b"}`},
		{"preamble text", "Here is the result:\n```json\n{\"a\":\"b\"}\n```", `{"a":"b"}`},
		{"preamble bare fence", "Here is the output:\n\n```\n{\"a\":\"b\"}\n```", `{"a":"b"}`},
		{"preamble with lang tag", "Based on analysis:\n\n```json\n{\"a\":\"b\"}\n```\n", `{"a":"b"}`},
		{"preamble and postamble", "Result:\n{\"a\":\"b\"}\nNote: done.", `{"a":"b"}`},
		{"real classify response", "Here is the classification:\n\n```json\n{\"category\":\"malware_sample\",\"confidence\":0.9}\n```", `{"category":"malware_sample","confidence":0.9}`},
		// Production failures: postamble after code fence contains {} which confused old LastIndexByte logic.
		{"fence with postamble braces", "```json\n{\"a\":\"b\"}\n```\n\nNote: based on {rules}.", `{"a":"b"}`},
		{"preamble fence postamble braces", "Here is the classification:\n\n```json\n{\"category\":\"access_broker\",\"confidence\":0.8}\n```\n\nThis analysis is based on {{classification rules}}.", `{"category":"access_broker","confidence":0.8}`},
		{"prose fence array postamble", "After analyzing the content:\n\n```json\n[{\"type\":\"ip\",\"value\":\"1.2.3.4\"}]\n```\n\nThese IOCs were found in {context}.", `[{"type":"ip","value":"1.2.3.4"}]`},
		{"truncated response no closing fence", "```json\n{\"a\":\"b\",\"c\":\"d\"}", `{"a":"b","c":"d"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractJSON(tt.input)
			if err != nil {
				t.Fatalf("ExtractJSON(%q) unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Errorf("ExtractJSON(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestExtractJSON_ProseOnly verifies that extractJSON returns an error when
// the LLM response contains no valid JSON (e.g. Cyrillic prose analysis).
func TestExtractJSON_ProseOnly(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"cyrillic prose", "## Classification\n\nя не всё вспомнил..."},
		{"english prose", "This is a plain text analysis with no JSON content whatsoever."},
		{"empty string", ""},
		{"code fence with prose", "```\nThis is just commentary, no JSON here\n```"},
		{"braces in prose", "The {rules} say this is {not valid} JSON at all."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractJSON(tt.input)
			if err == nil {
				t.Errorf("ExtractJSON(%q) expected error, got nil", tt.input)
			}
		})
	}
}

// TestAnalyzer_Classify_WithCodeFences verifies parsing works when the LLM
// wraps its JSON response in markdown code fences (as GLM does).
func TestAnalyzer_Classify_WithCodeFences(t *testing.T) {
	client := &mockLLMClient{
		responses: map[string]string{
			"Classify": "```json\n{\"category\":\"malware_sample\",\"confidence\":0.88,\"provenance\":\"third_party_reporting\",\"severity\":\"high\",\"reasoning\":\"New malware variant with IOCs\"}\n```",
		},
	}

	a := newTestAnalyzer(t, client)
	result, err := a.Classify(context.Background(), testFinding(), []string{"rule1"})
	if err != nil {
		t.Fatalf("Classify() with code fences: %v", err)
	}
	if result.Category != "malware_sample" {
		t.Errorf("Category = %q; want %q", result.Category, "malware_sample")
	}
}

// TestAnalyzer_Classify verifies that the classify method parses a valid JSON
// classification response and returns the expected category and confidence.
func TestAnalyzer_Classify(t *testing.T) {
	client := &mockLLMClient{
		responses: map[string]string{
			// classify.tmpl contains the word "Classify"
			"Classify": `{"category":"credential_leak","confidence":0.95,"provenance":"first_party","severity":"critical","reasoning":"Active credentials exposed"}`,
		},
	}

	a := newTestAnalyzer(t, client)
	result, err := a.Classify(context.Background(), testFinding(), []string{"cred-rule"})
	if err != nil {
		t.Fatalf("Classify() unexpected error: %v", err)
	}
	if result.Category != "credential_leak" {
		t.Errorf("Category = %q; want %q", result.Category, "credential_leak")
	}
	if result.Confidence != 0.95 {
		t.Errorf("Confidence = %v; want 0.95", result.Confidence)
	}
	if result.Provenance != "first_party" {
		t.Errorf("Provenance = %q; want %q", result.Provenance, "first_party")
	}
	if result.Severity != "critical" {
		t.Errorf("Severity = %q; want %q", result.Severity, "critical")
	}
	if result.Reasoning != "Active credentials exposed" {
		t.Errorf("Reasoning = %q; want %q", result.Reasoning, "Active credentials exposed")
	}
}

// TestAnalyzer_ExtractIOCs verifies that IOC extraction parses the JSON array
// and returns the correct IOC count, type, and value.
func TestAnalyzer_ExtractIOCs(t *testing.T) {
	client := &mockLLMClient{
		responses: map[string]string{
			// extract_iocs.tmpl contains the word "Extract"
			"Extract": `[{"type":"ip","value":"192.168.1.100","context":"C2 server","malicious":true}]`,
		},
	}

	a := newTestAnalyzer(t, client)
	iocs, err := a.ExtractIOCs(context.Background(), testFinding())
	if err != nil {
		t.Fatalf("ExtractIOCs() unexpected error: %v", err)
	}
	if len(iocs) != 1 {
		t.Fatalf("len(IOCs) = %d; want 1", len(iocs))
	}
	if iocs[0].Type != "ip" {
		t.Errorf("IOC.Type = %q; want %q", iocs[0].Type, "ip")
	}
	if iocs[0].Value != "192.168.1.100" {
		t.Errorf("IOC.Value = %q; want %q", iocs[0].Value, "192.168.1.100")
	}
}

// TestAnalyzer_ExtractIOCs_FiltersMalicious verifies that IOCs with
// malicious=false are filtered out and only malicious IOCs are returned.
func TestAnalyzer_ExtractIOCs_FiltersMalicious(t *testing.T) {
	client := &mockLLMClient{
		responses: map[string]string{
			"Extract": `[
				{"type":"ip","value":"45.33.32.156","context":"C2 server","malicious":true},
				{"type":"domain","value":"watchtowr.com","context":"research blog","malicious":false},
				{"type":"hash_sha256","value":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","context":"malware sample","malicious":true}
			]`,
		},
	}

	a := newTestAnalyzer(t, client)
	iocs, err := a.ExtractIOCs(context.Background(), testFinding())
	if err != nil {
		t.Fatalf("ExtractIOCs() unexpected error: %v", err)
	}
	if len(iocs) != 2 {
		t.Fatalf("len(IOCs) = %d; want 2 (non-malicious should be filtered)", len(iocs))
	}
	if iocs[0].Value != "45.33.32.156" {
		t.Errorf("IOC[0].Value = %q; want %q", iocs[0].Value, "45.33.32.156")
	}
	if iocs[1].Type != "hash_sha256" {
		t.Errorf("IOC[1].Type = %q; want %q", iocs[1].Type, "hash_sha256")
	}
}

// TestAnalyzer_ExtractIOCs_WrappedObject verifies fallback when the LLM wraps
// IOCs in an object like {"iocs": [...]}.
func TestAnalyzer_ExtractIOCs_WrappedObject(t *testing.T) {
	client := &mockLLMClient{
		responses: map[string]string{
			"Extract": `{"iocs": [{"type":"ip","value":"10.0.0.1","context":"C2","malicious":true}]}`,
		},
	}

	a := newTestAnalyzer(t, client)
	iocs, err := a.ExtractIOCs(context.Background(), testFinding())
	if err != nil {
		t.Fatalf("ExtractIOCs() wrapped object: unexpected error: %v", err)
	}
	if len(iocs) != 1 {
		t.Fatalf("len(IOCs) = %d; want 1", len(iocs))
	}
	if iocs[0].Value != "10.0.0.1" {
		t.Errorf("IOC.Value = %q; want %q", iocs[0].Value, "10.0.0.1")
	}
}

// TestAnalyzer_ExtractIOCs_EmptyContent verifies that empty content returns
// an empty IOC list without calling the LLM.
func TestAnalyzer_ExtractIOCs_EmptyContent(t *testing.T) {
	client := &mockLLMClient{
		responses: map[string]string{
			"Extract": `should not be called`,
		},
	}

	a := newTestAnalyzer(t, client)
	f := testFinding()
	f.Content = "   "
	iocs, err := a.ExtractIOCs(context.Background(), f)
	if err != nil {
		t.Fatalf("ExtractIOCs() empty content: unexpected error: %v", err)
	}
	if len(iocs) != 0 {
		t.Errorf("len(IOCs) = %d; want 0 for empty content", len(iocs))
	}
}

// TestAnalyzer_AssessSeverity verifies that the severity assessment parses the
// JSON response and maps the string level to models.SeverityCritical.
func TestAnalyzer_AssessSeverity(t *testing.T) {
	client := &mockLLMClient{
		responses: map[string]string{
			// severity.tmpl contains "Assess the severity"
			"Assess the severity": `{"severity":"critical","reasoning":"Active credentials"}`,
		},
	}

	a := newTestAnalyzer(t, client)
	sev, err := a.AssessSeverity(context.Background(), testFinding(), "credential_leak", []string{"cred-rule"})
	if err != nil {
		t.Fatalf("AssessSeverity() unexpected error: %v", err)
	}
	if sev != models.SeverityCritical {
		t.Errorf("Severity = %v; want SeverityCritical", sev)
	}
}

// TestAnalyzer_Summarize verifies that Summarize returns a non-empty string
// from the LLM without attempting to parse it as JSON.
func TestAnalyzer_Summarize(t *testing.T) {
	const wantSummary = "A credential dump affecting example.com was observed on the telegram channel test-channel. Immediate rotation of affected credentials is recommended."

	client := &mockLLMClient{
		responses: map[string]string{
			// summarize.tmpl contains the word "Write"
			"Write": wantSummary,
		},
	}

	a := newTestAnalyzer(t, client)
	summary, err := a.Summarize(context.Background(), testFinding(), "credential_leak", models.SeverityCritical)
	if err != nil {
		t.Fatalf("Summarize() unexpected error: %v", err)
	}
	if summary == "" {
		t.Error("Summarize() returned empty string; want non-empty")
	}
}

// TestAnalyzer_ExtractEntities verifies entity extraction with provenance-aware
// observed flags and confidence levels.
func TestAnalyzer_ExtractEntities(t *testing.T) {
	client := &mockLLMClient{
		responses: map[string]string{
			"Extract named entities": `{
				"entities": [
					{"type": "threat_actor", "name": "APT29", "aliases": ["Cozy Bear"], "observed": true, "confidence": "high"},
					{"type": "malware", "name": "Cobalt Strike", "aliases": [], "observed": true, "confidence": "high"}
				],
				"relationships": [
					{"source": "APT29", "target": "Cobalt Strike", "relationship": "uses"}
				]
			}`,
		},
	}

	a := newTestAnalyzer(t, client)
	f := testFinding()
	result, err := a.ExtractEntities(context.Background(), f, "malware_sample", "test-channel", "telegram", "first_party")
	if err != nil {
		t.Fatalf("ExtractEntities() unexpected error: %v", err)
	}
	if len(result.Entities) != 2 {
		t.Fatalf("len(Entities) = %d; want 2", len(result.Entities))
	}
	if !result.Entities[0].Observed {
		t.Error("Entities[0].Observed = false; want true")
	}
	if result.Entities[0].Confidence != "high" {
		t.Errorf("Entities[0].Confidence = %q; want %q", result.Entities[0].Confidence, "high")
	}
	if len(result.Relationships) != 1 {
		t.Fatalf("len(Relationships) = %d; want 1", len(result.Relationships))
	}
}
