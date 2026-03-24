package processor

import (
	"context"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/modules"
)

// Summarizer is the summarization sub-module. It uses the full LLM to
// produce a text summary for classified findings.
type Summarizer struct {
	analyzer *analyzer.Analyzer
	sem      *ConcurrencyLimiter
	status   *modules.StatusTracker
}

func NewSummarizer(a *analyzer.Analyzer, concurrency int, provider, model string) *Summarizer {
	s := &Summarizer{
		analyzer: a,
		sem:      NewConcurrencyLimiter(concurrency),
		status:   modules.NewStatusTracker(modules.ModSummarizer, "Summarizer", "processor"),
	}
	s.status.SetAIInfo(provider, model)
	s.status.SetEnabled(true)
	return s
}

// Summarize produces a text summary for a classified finding.
func (s *Summarizer) Summarize(ctx context.Context, finding *models.Finding, category string, severity models.Severity) (string, error) {
	if err := s.sem.Acquire(ctx); err != nil {
		return "", err
	}
	defer s.sem.Release()

	summary, err := s.analyzer.Summarize(ctx, finding, category, severity)
	if err != nil {
		s.status.RecordError(err)
		return "", err
	}
	s.status.RecordSuccess()
	return summary, nil
}

func (s *Summarizer) Status() modules.ModuleStatus { return s.status.Status() }
