package processor

import (
	"context"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/modules"
)

// ClassifyResult holds the output of a classification call.
// Defined here because analyzer.classifyResponse is unexported.
type ClassifyResult struct {
	Category   string
	Confidence float64
	Severity   string
	Provenance string
}

// Classifier is the classification sub-module. It uses the fast LLM to
// assign a category, confidence, severity, and provenance to each finding.
type Classifier struct {
	analyzer *analyzer.Analyzer
	sem      *ConcurrencyLimiter
	status   *modules.StatusTracker
}

func NewClassifier(a *analyzer.Analyzer, concurrency int, provider, model string) *Classifier {
	c := &Classifier{
		analyzer: a,
		sem:      NewConcurrencyLimiter(concurrency),
		status:   modules.NewStatusTracker(modules.ModClassifier, "Classifier", "processor"),
	}
	c.status.SetAIInfo(provider, model)
	c.status.SetEnabled(true)
	return c
}

// Classify runs the LLM classification on a single finding.
func (c *Classifier) Classify(ctx context.Context, finding *models.Finding) (*ClassifyResult, error) {
	if err := c.sem.Acquire(ctx); err != nil {
		return nil, err
	}
	defer c.sem.Release()

	resp, err := c.analyzer.Classify(ctx, finding, nil)
	if err != nil {
		c.status.RecordError(err)
		return nil, err
	}
	c.status.RecordSuccess()
	return &ClassifyResult{
		Category:   resp.Category,
		Confidence: resp.Confidence,
		Severity:   resp.Severity,
		Provenance: resp.Provenance,
	}, nil
}

func (c *Classifier) Status() modules.ModuleStatus { return c.status.Status() }
