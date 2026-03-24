package processor

import (
	"context"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/modules"
)

// Librarian is the sub-classification sub-module. It uses the full LLM to
// assign a fine-grained sub-category and structured metadata to each finding
// that has already been classified and entity-extracted.
type Librarian struct {
	analyzer *analyzer.Analyzer
	sem      *ConcurrencyLimiter
	status   *modules.StatusTracker
}

// NewLibrarian creates a Librarian with its own concurrency limiter and status tracker.
func NewLibrarian(a *analyzer.Analyzer, concurrency int, provider, model string) *Librarian {
	lib := &Librarian{
		analyzer: a,
		sem:      NewConcurrencyLimiter(concurrency),
		status:   modules.NewStatusTracker(modules.ModLibrarian, "Librarian", "processor"),
	}
	lib.status.SetAIInfo(provider, model)
	lib.status.SetEnabled(true)
	return lib
}

// SubClassify runs the LLM sub-classification on a single finding.
func (l *Librarian) SubClassify(ctx context.Context, finding *models.Finding, category, provenance string, entities, iocs []string) (*analyzer.SubClassifyResult, error) {
	if err := l.sem.Acquire(ctx); err != nil {
		return nil, err
	}
	defer l.sem.Release()

	result, err := l.analyzer.SubClassify(ctx, finding, category, provenance, entities, iocs)
	if err != nil {
		l.status.RecordError(err)
		return nil, err
	}
	l.status.RecordSuccess()
	return result, nil
}

func (l *Librarian) Status() modules.ModuleStatus { return l.status.Status() }
