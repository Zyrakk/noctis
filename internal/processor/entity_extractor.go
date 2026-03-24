package processor

import (
	"context"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/modules"
)

// EntityExtractor is the named entity extraction sub-module. It uses the
// full LLM to extract actors, malware, campaigns, TTPs from findings.
type EntityExtractor struct {
	analyzer *analyzer.Analyzer
	sem      *ConcurrencyLimiter
	status   *modules.StatusTracker
}

func NewEntityExtractor(a *analyzer.Analyzer, concurrency int, provider, model string) *EntityExtractor {
	e := &EntityExtractor{
		analyzer: a,
		sem:      NewConcurrencyLimiter(concurrency),
		status:   modules.NewStatusTracker(modules.ModEntityExtractor, "Entity Extractor", "processor"),
	}
	e.status.SetAIInfo(provider, model)
	e.status.SetEnabled(true)
	return e
}

// Extract runs LLM entity extraction on a classified finding.
func (e *EntityExtractor) Extract(ctx context.Context, finding *models.Finding, category, sourceName, sourceType, provenance string) (*analyzer.EntityExtractionResult, error) {
	if err := e.sem.Acquire(ctx); err != nil {
		return nil, err
	}
	defer e.sem.Release()

	result, err := e.analyzer.ExtractEntities(ctx, finding, category, sourceName, sourceType, provenance)
	if err != nil {
		e.status.RecordError(err)
		return nil, err
	}
	e.status.RecordSuccess()
	return result, nil
}

func (e *EntityExtractor) Status() modules.ModuleStatus { return e.status.Status() }
