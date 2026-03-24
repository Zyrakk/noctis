// Package ingest implements the archive-everything ingest pipeline. Every
// collected finding is persisted to the raw_content archive before any
// analysis takes place. Findings that match real-time rules are enriched
// synchronously and dispatched via the alertFn callback. Background
// classification/extraction are handled by processor, correlation by brain.
package ingest

import (
	"context"
	"log"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/dispatcher"
	"github.com/Zyrakk/noctis/internal/matcher"
	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/processor"
)

// IngestPipeline handles real-time matching and the alert path for incoming
// findings. Background workers have moved to processor.ProcessingEngine and
// brain.Brain.
type IngestPipeline struct {
	archive          *archive.Store
	matcher          *matcher.Matcher
	classifyAnalyzer *analyzer.Analyzer // fast LLM for alert-path classification
	fullAnalyzer     *analyzer.Analyzer // full LLM for alert-path summarization + extraction
	metrics          *dispatcher.PrometheusMetrics
	alertFn          func(models.EnrichedFinding)
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
) (*IngestPipeline, error) {
	m, err := matcher.New(matcherRules)
	if err != nil {
		return nil, err
	}

	return &IngestPipeline{
		archive:          archiveStore,
		matcher:          m,
		classifyAnalyzer: classifyAnalyzer,
		fullAnalyzer:     fullAnalyzer,
		metrics:          metrics,
		alertFn:          alertFn,
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

	// 4a. Classify (fast LLM).
	var provenance string
	classResult, err := p.classifyAnalyzer.Classify(ctx, &f, result.MatchedRules)
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

	// 4b. Extract IOCs (full LLM).
	iocs, err := p.fullAnalyzer.ExtractIOCs(ctx, &f)
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

	// 4d. Summarize (full LLM).
	summary, err := p.fullAnalyzer.Summarize(ctx, &f, string(enriched.Category), enriched.Severity)
	if err != nil {
		log.Printf("ingest: summarize error for %s: %v", f.ID, err)
	} else {
		enriched.LLMAnalysis = summary
	}

	// 5. Dispatch alert.
	p.alertFn(enriched)

	// 6. Mark content as classified in archive.
	tags := processor.TagsFromCategory(string(enriched.Category))
	if enriched.Confidence < 0.80 {
		tags = append(tags, "needs_review")
	}
	if err := p.archive.MarkClassified(ctx, rc.ID, string(enriched.Category), tags, enriched.Severity.String(), summary, provenance, processor.CurrentClassificationVersion); err != nil {
		log.Printf("ingest: mark classified error for %s: %v", rc.ID, err)
	}

	// Metrics recording is handled by alertFn callback to avoid double-counting.

	return nil
}
