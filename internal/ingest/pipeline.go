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
	archive          *archive.Store
	matcher          *matcher.Matcher
	classifyAnalyzer *analyzer.Analyzer // GLM-4-Plus (fast, high-volume classification)
	fullAnalyzer     *analyzer.Analyzer // GLM-5 (smart, summarization + extraction)
	metrics          *dispatcher.PrometheusMetrics
	alertFn          func(models.EnrichedFinding)
	workerCfg        config.CollectionConfig
	corrCfg          config.CorrelationConfig
	corrStore        correlationStore

	// Concurrency limiters replace the old time-delay rate limiters.
	classifySem *concurrencyLimiter // limits concurrent classification calls (GLM-4-Plus)
	extractSem  *concurrencyLimiter // limits concurrent extraction/summarize calls (GLM-5)
}

// NewIngestPipeline creates a pipeline that archives every finding and runs
// real-time matching with optional LLM enrichment for alert-path items.
func NewIngestPipeline(
	archiveStore *archive.Store,
	matcherRules []config.RuleConfig,
	classifyAnalyzer *analyzer.Analyzer,
	fullAnalyzer *analyzer.Analyzer,
	metrics *dispatcher.PrometheusMetrics,
	alertFn func(models.EnrichedFinding),
	workerCfg config.CollectionConfig,
	corrCfg config.CorrelationConfig,
	classifyConcurrency int,
	extractConcurrency int,
) (*IngestPipeline, error) {
	m, err := matcher.New(matcherRules)
	if err != nil {
		return nil, err
	}

	// Apply defaults for zero-value config fields.
	if workerCfg.ClassificationWorkers <= 0 {
		workerCfg.ClassificationWorkers = 8
	}
	if workerCfg.EntityExtractionWorkers <= 0 {
		workerCfg.EntityExtractionWorkers = 2
	}
	if workerCfg.ClassificationBatchSize <= 0 {
		workerCfg.ClassificationBatchSize = 10
	}

	return &IngestPipeline{
		archive:          archiveStore,
		matcher:          m,
		classifyAnalyzer: classifyAnalyzer,
		fullAnalyzer:     fullAnalyzer,
		metrics:          metrics,
		alertFn:          alertFn,
		workerCfg:        workerCfg,
		corrCfg:          corrCfg,
		corrStore:        archiveStore,
		classifySem:      newConcurrencyLimiter(classifyConcurrency),
		extractSem:       newConcurrencyLimiter(extractConcurrency),
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

	// 4. Alert path: full LLM analysis.
	enriched := models.EnrichedFinding{
		Finding:      f,
		MatchType:    result.MatchType,
		MatchedRules: result.MatchedRules,
		Severity:     result.Severity,
	}

	// 4a. Classify (GLM-4-Plus).
	var provenance string
	p.classifySem.Acquire(ctx)
	classResult, err := p.classifyAnalyzer.Classify(ctx, &f, result.MatchedRules)
	p.classifySem.Release()
	if err != nil {
		log.Printf("ingest: classify error for %s: %v", f.ID, err)
	} else {
		enriched.Category = models.Category(classResult.Category)
		enriched.Confidence = classResult.Confidence
		provenance = classResult.Provenance
		switch provenance {
		case "first_party", "third_party_reporting", "unknown":
			// valid
		default:
			provenance = "unknown"
		}
	}

	// 4b. Extract IOCs (GLM-5).
	p.extractSem.Acquire(ctx)
	iocs, err := p.fullAnalyzer.ExtractIOCs(ctx, &f)
	p.extractSem.Release()
	if err != nil {
		log.Printf("ingest: extract IOCs error for %s: %v", f.ID, err)
	} else {
		enriched.IOCs = iocs
	}

	// 4c. Extract severity from the merged classify response.
	if classResult != nil && classResult.Severity != "" {
		llmSev, err := models.ParseSeverity(classResult.Severity)
		if err != nil {
			log.Printf("ingest: severity parse error for %s: %v", f.ID, err)
		} else if llmSev > enriched.Severity {
			enriched.Severity = llmSev
		}
	}

	// 4d. Summarize (GLM-5).
	p.extractSem.Acquire(ctx)
	summary, err := p.fullAnalyzer.Summarize(ctx, &f, string(enriched.Category), enriched.Severity)
	p.extractSem.Release()
	if err != nil {
		log.Printf("ingest: summarize error for %s: %v", f.ID, err)
	} else {
		enriched.LLMAnalysis = summary
	}

	// 5. Dispatch alert.
	p.alertFn(enriched)

	// 6. Mark content as classified in archive.
	tags := tagsFromCategory(string(enriched.Category))
	if enriched.Confidence < 0.80 {
		tags = append(tags, "needs_review")
	}
	if err := p.archive.MarkClassified(ctx, rc.ID, string(enriched.Category), tags, enriched.Severity.String(), summary, provenance, currentClassificationVersion); err != nil {
		log.Printf("ingest: mark classified error for %s: %v", rc.ID, err)
	}

	// Metrics recording is handled by alertFn callback to avoid double-counting.

	return nil
}

// Run starts all background workers and blocks until ctx is cancelled.
func (p *IngestPipeline) Run(ctx context.Context) {
	// Reset old classifications for reprocessing with the current pipeline version.
	if count, err := p.archive.ResetOldClassifications(ctx, currentClassificationVersion); err != nil {
		log.Printf("ingest: reclassification reset error: %v", err)
	} else if count > 0 {
		log.Printf("ingest: reset %d entries for reclassification (version < %d)", count, currentClassificationVersion)
	}

	// Backfill entities from existing IOCs on startup.
	if count, err := p.archive.BackfillEntitiesFromIOCs(ctx); err != nil {
		log.Printf("ingest: entity backfill error: %v", err)
	} else if count > 0 {
		log.Printf("ingest: backfilled %d entities from existing IOCs", count)
	}

	// Cleanup stale associated_with edges from non-observed entities.
	if count, err := p.archive.CleanupAssociatedWithEdges(ctx); err != nil {
		log.Printf("ingest: edge cleanup error: %v", err)
	} else if count > 0 {
		log.Printf("ingest: cleaned up %d associated_with edges → referenced_in", count)
	}

	// Backfill IOC sightings on startup.
	if count, err := p.archive.BackfillIOCSightings(ctx); err != nil {
		log.Printf("ingest: ioc sightings backfill error: %v", err)
	} else if count > 0 {
		log.Printf("ingest: backfilled %d ioc sightings", count)
	}

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

	// Start correlation worker (single instance).
	if p.corrCfg.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p.correlationWorker(ctx)
		}()
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
	case models.CategoryVulnerability:
		tags = append(tags, "cve")
	case models.CategoryCanaryHit:
		tags = append(tags, "canary")
	}

	return tags
}
