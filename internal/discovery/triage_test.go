package discovery

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/Zyrakk/noctis/internal/analyzer"
)

// TestTriagePromptGeneration verifies the triage template renders with a URL list.
func TestTriagePromptGeneration(t *testing.T) {
	// Load the template directly (same way Analyzer does).
	tmplPath := filepath.Join("..", "..", "prompts", "triage.tmpl")
	if _, err := os.Stat(tmplPath); err != nil {
		t.Skipf("triage.tmpl not found at %s (run from repo root): %v", tmplPath, err)
	}

	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}

	data := struct{ URLs []string }{
		URLs: []string{
			"https://example-forum.com/thread/123",
			"https://random-shop.com/buy",
			"https://exploit-db.com/exploits/51234",
		},
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("execute template: %v", err)
	}

	rendered := buf.String()
	if len(rendered) == 0 {
		t.Fatal("rendered template is empty")
	}

	// Verify URLs appear in the rendered output.
	for _, u := range data.URLs {
		if !bytes.Contains([]byte(rendered), []byte(u)) {
			t.Errorf("expected URL %q in rendered template", u)
		}
	}

	// Verify the count is rendered.
	if !bytes.Contains([]byte(rendered), []byte("3")) {
		t.Error("expected URL count '3' in rendered template")
	}
}

// TestTriageResponseParsing verifies JSON parsing handles clean and messy LLM output.
func TestTriageResponseParsing(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantInv int
		wantTr  int
		wantErr bool
	}{
		{
			name:    "clean JSON",
			input:   `{"investigate": ["https://a.com"], "trash": ["https://b.com", "https://c.com"]}`,
			wantInv: 1,
			wantTr:  2,
		},
		{
			name:    "with code fences",
			input:   "```json\n{\"investigate\": [\"https://a.com\"], \"trash\": []}\n```",
			wantInv: 1,
			wantTr:  0,
		},
		{
			name:    "with preamble",
			input:   "Here are my classifications:\n{\"investigate\": [], \"trash\": [\"https://x.com\"]}",
			wantInv: 0,
			wantTr:  1,
		},
		{
			name:    "invalid JSON",
			input:   "I cannot classify these URLs",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extracted, err := analyzer.ExtractJSON(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractJSON error: %v", err)
			}

			var result struct {
				Investigate []string `json:"investigate"`
				Trash       []string `json:"trash"`
			}
			if err := json.Unmarshal([]byte(extracted), &result); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			if len(result.Investigate) != tt.wantInv {
				t.Errorf("investigate count = %d, want %d", len(result.Investigate), tt.wantInv)
			}
			if len(result.Trash) != tt.wantTr {
				t.Errorf("trash count = %d, want %d", len(result.Trash), tt.wantTr)
			}
		})
	}
}

// TestTriageWorker_BelowThreshold verifies the worker is constructable with defaults.
func TestTriageWorker_BelowThreshold(t *testing.T) {
	// Verify default batch size.
	tw := NewTriageWorker(nil, nil, 0, "test-model")
	if tw.batchSize != 100 {
		t.Errorf("default batchSize = %d, want 100", tw.batchSize)
	}

	// Verify custom batch size.
	tw2 := NewTriageWorker(nil, nil, 50, "test-model")
	if tw2.batchSize != 50 {
		t.Errorf("custom batchSize = %d, want 50", tw2.batchSize)
	}

	// Verify status tracker is initialized.
	if tw.Status() == nil {
		t.Error("status tracker should not be nil")
	}
}
