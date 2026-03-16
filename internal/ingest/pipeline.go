// Package ingest implements the archive-everything ingest pipeline. Every
// collected finding is persisted to the raw_content archive before any
// analysis takes place. Findings that match real-time rules are enriched
// synchronously and dispatched via the alertFn callback. All remaining
// content is picked up by background classification and entity-extraction
// workers running in their own goroutines.
package ingest

import (
	"context"
	"log"
	"sync"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/dispatcher"
	"github.com/Zyrakk/noctis/internal/matcher"
	"github.com/Zyrakk/noctis/internal/models"
)

// IngestPipeline is the core processing engine. Collectors call Process() for
// each finding; Run() starts the background workers.
type IngestPipeline struct {
	archive   *archive.Store
	matcher   *matcher.Matcher
	analyzer  *analyzer.Analyzer
	metrics   *dispatcher.PrometheusMetrics
	alertFn   func(models.EnrichedFinding)
	workerCfg config.CollectionConfig

	// Rate limiters are shared across workers of the same type.
	initLimitersOnce sync.Once
	classifyRL       *rateLimiter
	extractRL        *rateLimiter
}

// initLimiters lazily creates the shared rate limiters.
func (p *IngestPipeline) initLimiters() {
	p.classifyRL = newRateLimiter(defaultRateLimitDelay)
	p.extractRL = newRateLimiter(defaultRateLimitDelay)
}

// NewIngestPipeline creates a pipeline that archives every finding and runs
// real-time matching with optional LLM enrichment for alert-path items.
func NewIngestPipeline(
	archiveStore *archive.Store,
	matcherRules []config.RuleConfig,
	az *analyzer.Analyzer,
	metrics *dispatcher.PrometheusMetrics,
	alertFn func(models.EnrichedFinding),
	workerCfg config.CollectionConfig,
) (*IngestPipeline, error) {
	m, err := matcher.New(matcherRules)
	if err != nil {
		return nil, err
	}

	// Apply defaults for zero-value config fields.
	if workerCfg.ClassificationWorkers <= 0 {
		workerCfg.ClassificationWorkers = 2
	}
	if workerCfg.EntityExtractionWorkers <= 0 {
		workerCfg.EntityExtractionWorkers = 1
	}
	if workerCfg.ClassificationBatchSize <= 0 {
		workerCfg.ClassificationBatchSize = 10
	}

	return &IngestPipeline{
		archive:   archiveStore,
		matcher:   m,
		analyzer:  az,
		metrics:   metrics,
		alertFn:   alertFn,
		workerCfg: workerCfg,
	}, nil
}

// Process is the per-finding entry point called by collectors. It archives
// the finding unconditionally, then runs the alert path (matcher + LLM
// enrichment) synchronously if the finding matches a rule.
func (p *IngestPipeline) Process(ctx context.Context, f models.Finding) error {
	// 1. Convert Finding to archive representation.
	rc := archive.FromFinding(f)

	// 2. Insert into archive (dedup via content_hash).
	if err := p.archive.Insert(ctx, rc); err != nil {
		log.Printf("ingest: archive insert error for %s: %v", f.ID, err)
		return nil // never propagate — pipeline must not crash
	}

	// 3. Run matcher.
	result, matched := p.matcher.Match(f)

	if !matched {
		// Content stays unclassified; background worker will handle it.
		if p.metrics != nil {
			p.metrics.RecordMatcherDrop()
		}
		return nil
	}

	// Record matcher match metrics.
	if p.metrics != nil {
		for _, rule := range result.MatchedRules {
			p.metrics.RecordMatcherMatch(rule)
		}
	}

	// 4. Alert path: full LLM analysis.
	enriched := models.EnrichedFinding{
		Finding:      f,
		MatchType:    result.MatchType,
		MatchedRules: result.MatchedRules,
		Severity:     result.Severity,
	}

	// 4a. Classify.
	classResult, err := p.analyzer.Classify(ctx, &f, result.MatchedRules)
	if err != nil {
		log.Printf("ingest: classify error for %s: %v", f.ID, err)
	} else {
		enriched.Category = models.Category(classResult.Category)
		enriched.Confidence = classResult.Confidence
	}

	// 4b. Extract IOCs.
	iocs, err := p.analyzer.ExtractIOCs(ctx, &f)
	if err != nil {
		log.Printf("ingest: extract IOCs error for %s: %v", f.ID, err)
	} else {
		enriched.IOCs = iocs
	}

	// 4c. Assess severity — upgrade if LLM says higher.
	llmSev, err := p.analyzer.AssessSeverity(ctx, &f, string(enriched.Category), result.MatchedRules)
	if err != nil {
		log.Printf("ingest: severity assessment error for %s: %v", f.ID, err)
	} else if llmSev > enriched.Severity {
		enriched.Severity = llmSev
	}

	// 4d. Summarize.
	summary, err := p.analyzer.Summarize(ctx, &f, string(enriched.Category), enriched.Severity)
	if err != nil {
		log.Printf("ingest: summarize error for %s: %v", f.ID, err)
	} else {
		enriched.LLMAnalysis = summary
	}

	// 5. Dispatch alert.
	p.alertFn(enriched)

	// 6. Mark content as classified in archive.
	tags := tagsFromCategory(string(enriched.Category))
	if err := p.archive.MarkClassified(ctx, rc.ID, string(enriched.Category), tags, enriched.Severity.String(), summary); err != nil {
		log.Printf("ingest: mark classified error for %s: %v", rc.ID, err)
	}

	// 7. Record Prometheus metrics.
	if p.metrics != nil {
		p.metrics.RecordFinding(enriched)
	}

	return nil
}

// Run starts all background workers and blocks until ctx is cancelled.
func (p *IngestPipeline) Run(ctx context.Context) {
	var wg sync.WaitGroup

	// Start classification workers.
	for i := 0; i < p.workerCfg.ClassificationWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.classificationWorker(ctx, id)
		}(i)
	}

	// Start entity extraction workers.
	for i := 0; i < p.workerCfg.EntityExtractionWorkers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.entityExtractionWorker(ctx, id)
		}(i)
	}

	wg.Wait()
}

// tagsFromCategory derives a basic tag set from the classification category.
func tagsFromCategory(category string) []string {
	if category == "" {
		return nil
	}
	tags := []string{category}

	// Add additional contextual tags for well-known categories.
	switch models.Category(category) {
	case models.CategoryCredentialLeak:
		tags = append(tags, "credentials")
	case models.CategoryMalwareSample:
		tags = append(tags, "malware")
	case models.CategoryThreatActorComms:
		tags = append(tags, "threat_actor")
	case models.CategoryAccessBroker:
		tags = append(tags, "access_sale")
	case models.CategoryDataDump:
		tags = append(tags, "data_breach")
	case models.CategoryCanaryHit:
		tags = append(tags, "canary")
	}

	return tags
}
