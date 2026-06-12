package processor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
)

func TestBudgetCircuitBreaker_SetAndCheck(t *testing.T) {
	var flag atomic.Bool

	if flag.Load() {
		t.Error("expected flag to be false initially")
	}

	flag.Store(true)
	if !flag.Load() {
		t.Error("expected flag to be true after Store(true)")
	}

	flag.Store(false)
	if flag.Load() {
		t.Error("expected flag to be false after reset")
	}
}

func TestBudgetPauseBackoff(t *testing.T) {
	pause := budgetPauseDuration
	if pause < 10*time.Minute || pause > 60*time.Minute {
		t.Errorf("budgetPauseDuration = %v; expected between 10m and 60m", pause)
	}
}

// ---------------------------------------------------------------------------
// Extraction skip for irrelevant items
// ---------------------------------------------------------------------------

type mockExtractionMarker struct {
	markedIDs []string
	err       error
}

func (m *mockExtractionMarker) MarkEntitiesExtracted(_ context.Context, id string) error {
	if m.err != nil {
		return m.err
	}
	m.markedIDs = append(m.markedIDs, id)
	return nil
}

type mockPipelineMetrics struct {
	junkGate          int
	extractionSkipped int
}

func (m *mockPipelineMetrics) RecordJunkGate()          { m.junkGate++ }
func (m *mockPipelineMetrics) RecordExtractionSkipped() { m.extractionSkipped++ }

// TestSkipIrrelevantExtraction proves that irrelevant items (junk-gated or
// LLM-classified) are taken out of the extraction queue without any analyzer
// call: the helper has no access to analyzers, and the worker invokes it
// before any LLM use.
func TestSkipIrrelevantExtraction(t *testing.T) {
	tests := []struct {
		name        string
		category    string
		markErr     error
		wantHandled bool
		wantMarked  bool
		wantMetric  int
	}{
		{"irrelevant item is marked and skipped", "irrelevant", nil, true, true, 1},
		{"credential_leak proceeds to extraction", "credential_leak", nil, false, false, 0},
		{"threat_actor_comms proceeds to extraction", "threat_actor_comms", nil, false, false, 0},
		{"empty category proceeds to extraction", "", nil, false, false, 0},
		{"mark error still skips llm calls", "irrelevant", errors.New("db down"), true, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &mockExtractionMarker{err: tt.markErr}
			metrics := &mockPipelineMetrics{}
			entry := archive.RawContent{ID: "rc-1", Category: tt.category}

			handled := skipIrrelevantExtraction(context.Background(), 0, entry, store, metrics)

			if handled != tt.wantHandled {
				t.Errorf("handled = %v, want %v", handled, tt.wantHandled)
			}
			marked := len(store.markedIDs) == 1 && store.markedIDs[0] == "rc-1"
			if marked != tt.wantMarked {
				t.Errorf("marked = %v (ids=%v), want %v", marked, store.markedIDs, tt.wantMarked)
			}
			if metrics.extractionSkipped != tt.wantMetric {
				t.Errorf("extractionSkipped = %d, want %d", metrics.extractionSkipped, tt.wantMetric)
			}
		})
	}

	t.Run("nil metrics does not panic", func(t *testing.T) {
		store := &mockExtractionMarker{}
		entry := archive.RawContent{ID: "rc-2", Category: "irrelevant"}
		if !skipIrrelevantExtraction(context.Background(), 0, entry, store, nil) {
			t.Error("expected irrelevant entry to be handled with nil metrics")
		}
		if len(store.markedIDs) != 1 || store.markedIDs[0] != "rc-2" {
			t.Errorf("expected rc-2 to be marked, got %v", store.markedIDs)
		}
	})
}
