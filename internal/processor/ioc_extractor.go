package processor

import (
	"context"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/modules"
)

// IOCExtractor is the IOC extraction sub-module. It uses the full LLM to
// extract indicators of compromise from findings.
type IOCExtractor struct {
	analyzer *analyzer.Analyzer
	sem      *ConcurrencyLimiter
	status   *modules.StatusTracker
}

func NewIOCExtractor(a *analyzer.Analyzer, concurrency int, provider, model string) *IOCExtractor {
	e := &IOCExtractor{
		analyzer: a,
		sem:      NewConcurrencyLimiter(concurrency),
		status:   modules.NewStatusTracker(modules.ModIOCExtractor, "IOC Extractor", "processor"),
	}
	e.status.SetAIInfo(provider, model)
	e.status.SetEnabled(true)
	return e
}

// Extract runs LLM IOC extraction on a finding.
func (e *IOCExtractor) Extract(ctx context.Context, finding *models.Finding) ([]models.IOC, error) {
	if err := e.sem.Acquire(ctx); err != nil {
		return nil, err
	}
	defer e.sem.Release()

	iocs, err := e.analyzer.ExtractIOCs(ctx, finding)
	if err != nil {
		e.status.RecordError(err)
		return nil, err
	}
	e.status.RecordSuccess()
	return iocs, nil
}

func (e *IOCExtractor) Status() modules.ModuleStatus { return e.status.Status() }
