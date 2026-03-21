package ingest

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/models"
)

const (
	// defaultRateLimitDelay is the minimum time between LLM API calls per
	// rate limiter instance, used to avoid burning through the GLM quota.
	defaultRateLimitDelay = 2 * time.Second

	// workerIdleInterval is how long workers sleep when there is no work.
	workerIdleInterval = 30 * time.Second

	// workerLogInterval is how many items to process between progress logs.
	workerLogInterval = 10
)

// currentClassificationVersion is incremented when the classification
// pipeline changes materially. Workers stamp this version on each
// processed entry; on startup, entries with an older version are reset
// for reprocessing.
const currentClassificationVersion = 2

// rateLimiter enforces a minimum delay between LLM API calls. It is safe for
// concurrent use and should be shared across all workers of the same type.
type rateLimiter struct {
	minDelay time.Duration
	mu       sync.Mutex
	lastCall time.Time
}

func newRateLimiter(minDelay time.Duration) *rateLimiter {
	return &rateLimiter{minDelay: minDelay}
}

// Wait blocks until minDelay has elapsed since the last call. Returns
// ctx.Err() if the context is cancelled while waiting.
// The time slot is claimed optimistically under the lock to prevent
// concurrent workers from bypassing the delay (TOCTOU fix).
func (r *rateLimiter) Wait(ctx context.Context) error {
	r.mu.Lock()

	now := time.Now()
	elapsed := now.Sub(r.lastCall)
	remaining := r.minDelay - elapsed

	if remaining <= 0 {
		r.lastCall = now
		r.mu.Unlock()
		return nil
	}

	// Claim the slot now so the next caller sees the updated lastCall.
	r.lastCall = now.Add(remaining)
	r.mu.Unlock()

	select {
	case <-time.After(remaining):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// classificationWorker polls the archive for unclassified content and runs
// LLM classification on each entry. It shares a rate limiter with all other
// classification workers to throttle GLM API usage.
func (p *IngestPipeline) classificationWorker(ctx context.Context, workerID int) {
	limiter := p.classifyLimiter()
	batchSize := p.workerCfg.ClassificationBatchSize
	var totalClassified int

	log.Printf("ingest: classification worker %d started (batch=%d)", workerID, batchSize)

	for {
		if ctx.Err() != nil {
			log.Printf("ingest: classification worker %d stopping", workerID)
			return
		}

		entries, err := p.archive.FetchUnclassified(ctx, batchSize)
		if err != nil {
			log.Printf("ingest: classification worker %d: fetch error: %v", workerID, err)
			if !sleepOrCancel(ctx, workerIdleInterval) {
				return
			}
			continue
		}

		if len(entries) == 0 {
			if !sleepOrCancel(ctx, workerIdleInterval) {
				return
			}
			continue
		}

		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}

			if err := limiter.Wait(ctx); err != nil {
				return
			}

			// Build a minimal Finding for the analyzer.
			finding := findingFromRawContent(entry)

			// Classify.
			classResult, err := p.analyzer.Classify(ctx, &finding, nil)
			if err != nil {
				log.Printf("ingest: classification worker %d: classify error for %s: %v", workerID, entry.ID, err)
				continue
			}

			category := classResult.Category
			provenance := classResult.Provenance
			switch provenance {
			case "first_party", "third_party_reporting", "unknown":
				// valid
			default:
				provenance = "unknown"
			}
			tags := tagsFromCategory(category)

			// Flag low-confidence classifications for review.
			if classResult.Confidence < 0.80 {
				tags = append(tags, "needs_review")
			}

			// Assess severity.
			severity := models.SeverityInfo
			sev, err := p.analyzer.AssessSeverity(ctx, &finding, category, nil)
			if err != nil {
				log.Printf("ingest: classification worker %d: severity error for %s: %v", workerID, entry.ID, err)
			} else {
				severity = sev
			}

			// Wait before the next LLM call (summarize).
			if err := limiter.Wait(ctx); err != nil {
				return
			}

			// Summarize.
			summary, err := p.analyzer.Summarize(ctx, &finding, category, severity)
			if err != nil {
				log.Printf("ingest: classification worker %d: summarize error for %s: %v", workerID, entry.ID, err)
				summary = ""
			}

			// Persist classification results.
			if err := p.archive.MarkClassified(ctx, entry.ID, category, tags, severity.String(), summary, provenance, currentClassificationVersion); err != nil {
				log.Printf("ingest: classification worker %d: mark classified error for %s: %v", workerID, entry.ID, err)
				continue
			}

			totalClassified++
			if totalClassified%workerLogInterval == 0 {
				log.Printf("ingest: classification worker %d: classified %d items", workerID, totalClassified)
			}
		}
	}
}

// entityExtractionWorker polls the archive for classified-but-not-extracted
// content and runs LLM entity extraction on each entry. It shares a rate
// limiter with all other entity extraction workers.
func (p *IngestPipeline) entityExtractionWorker(ctx context.Context, workerID int) {
	limiter := p.extractLimiter()
	batchSize := p.workerCfg.ClassificationBatchSize // reuse same batch size
	var totalExtracted int

	log.Printf("ingest: entity extraction worker %d started (batch=%d)", workerID, batchSize)

	for {
		if ctx.Err() != nil {
			log.Printf("ingest: entity extraction worker %d stopping", workerID)
			return
		}

		entries, err := p.archive.FetchClassifiedUnextracted(ctx, batchSize)
		if err != nil {
			log.Printf("ingest: entity extraction worker %d: fetch error: %v", workerID, err)
			if !sleepOrCancel(ctx, workerIdleInterval) {
				return
			}
			continue
		}

		if len(entries) == 0 {
			if !sleepOrCancel(ctx, workerIdleInterval) {
				return
			}
			continue
		}

		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}

			if err := limiter.Wait(ctx); err != nil {
				return
			}

			finding := findingFromRawContent(entry)

			iocs, err := p.analyzer.ExtractIOCs(ctx, &finding)
			if err != nil {
				log.Printf("ingest: entity extraction worker %d: extract error for %s: %v", workerID, entry.ID, err)
				continue
			}

			// Upsert each IOC.
			for _, ioc := range iocs {
				if err := p.archive.UpsertIOC(ctx, ioc.Type, ioc.Value, ioc.Context, entry.ID); err != nil {
					log.Printf("ingest: entity extraction worker %d: upsert ioc error: %v", workerID, err)
				}
			}

			// Bridge IOCs into the entity graph.
			if len(iocs) > 0 {
				p.bridgeEntitiesToGraph(ctx, entry, iocs, workerID)
			}

			// LLM entity extraction for non-irrelevant findings.
			if entry.Category != "" && entry.Category != "irrelevant" {
				if err := limiter.Wait(ctx); err != nil {
					return
				}

				finding2 := findingFromRawContent(entry)
				result, err := p.analyzer.ExtractEntities(ctx, &finding2, entry.Category, entry.SourceName, entry.SourceType, entry.Provenance)
				if err != nil {
					log.Printf("ingest: entity extraction worker %d: extract entities error for %s: %v", workerID, entry.ID, err)
				} else {
					p.bridgeLLMEntitiesToGraph(ctx, entry, result, workerID)
				}
			}

			// Mark as entity-extracted.
			if err := p.archive.MarkEntitiesExtracted(ctx, entry.ID); err != nil {
				log.Printf("ingest: entity extraction worker %d: mark extracted error for %s: %v", workerID, entry.ID, err)
				continue
			}

			totalExtracted++
			if totalExtracted%workerLogInterval == 0 {
				log.Printf("ingest: entity extraction worker %d: extracted %d items", workerID, totalExtracted)
			}
		}
	}
}

// bridgeEntitiesToGraph creates entities and edges from extracted IOCs and the
// source channel. Each IOC becomes a graph entity linked to the source entity.
func (p *IngestPipeline) bridgeEntitiesToGraph(ctx context.Context, entry archive.RawContent, iocs []models.IOC, workerID int) {
	// Map IOC types to entity graph types.
	iocEntityType := func(iocType string) string {
		switch iocType {
		case "ip":
			return "ip"
		case "domain":
			return "domain"
		case "hash_md5", "hash_sha1", "hash_sha256":
			return "hash"
		case "cve":
			return "cve"
		case "url":
			return "url"
		case "email":
			return "email"
		default:
			return "ioc"
		}
	}

	// Upsert source entity.
	sourceName := entry.SourceName
	if sourceName == "" {
		sourceName = entry.SourceID
	}
	sourceEntityID := fmt.Sprintf("source:%s", sourceName)
	sourceProps := map[string]interface{}{
		"name":        sourceName,
		"source_type": entry.SourceType,
	}
	if err := p.archive.UpsertEntity(ctx, sourceEntityID, "channel", sourceProps); err != nil {
		log.Printf("ingest: entity bridge worker %d: upsert source entity: %v", workerID, err)
	}

	// Upsert each IOC as an entity and create an edge to the source.
	for _, ioc := range iocs {
		entityID := fmt.Sprintf("ioc:%s:%s", ioc.Type, ioc.Value)
		entityType := iocEntityType(ioc.Type)
		props := map[string]interface{}{
			"value": ioc.Value,
		}
		if ioc.Context != "" {
			props["context"] = ioc.Context
		}

		if err := p.archive.UpsertEntity(ctx, entityID, entityType, props); err != nil {
			log.Printf("ingest: entity bridge worker %d: upsert ioc entity: %v", workerID, err)
			continue
		}

		// Edge: IOC → source (found_in)
		edgeID := fmt.Sprintf("edge:%s:%s:found_in", entityID, sourceEntityID)
		if err := p.archive.UpsertEdge(ctx, edgeID, entityID, sourceEntityID, "found_in"); err != nil {
			log.Printf("ingest: entity bridge worker %d: upsert edge: %v", workerID, err)
		}
	}
}

// bridgeLLMEntitiesToGraph creates entities and edges from LLM-extracted named
// entities (actors, malware, campaigns) and their relationships. It respects
// the observed flag and confidence level to prevent false graph pollution.
func (p *IngestPipeline) bridgeLLMEntitiesToGraph(ctx context.Context, entry archive.RawContent, result *analyzer.EntityExtractionResult, workerID int) {
	if result == nil {
		return
	}

	// Build a name->ID map and name->observed map for relationship resolution.
	nameToID := make(map[string]string)
	nameObserved := make(map[string]bool)

	for _, ent := range result.Entities {
		if ent.Name == "" {
			continue
		}

		// Skip low-confidence entities entirely.
		if ent.Confidence == "low" {
			log.Printf("ingest: entity bridge worker %d: skipping low-confidence entity %q", workerID, ent.Name)
			continue
		}

		entityID := fmt.Sprintf("entity:%s:%s", ent.Type, strings.ToLower(strings.ReplaceAll(ent.Name, " ", "_")))
		props := map[string]interface{}{
			"name": ent.Name,
		}
		if len(ent.Aliases) > 0 {
			props["aliases"] = ent.Aliases
		}
		if ent.Observed {
			props["observed"] = true
		}
		// Mark medium-confidence entities for review.
		if ent.Confidence == "medium" {
			props["needs_review"] = true
		}

		if err := p.archive.UpsertEntity(ctx, entityID, ent.Type, props); err != nil {
			log.Printf("ingest: entity bridge worker %d: upsert llm entity: %v", workerID, err)
			continue
		}
		nameToID[ent.Name] = entityID
		nameObserved[ent.Name] = ent.Observed

		// Also link this entity to the source channel.
		sourceName := entry.SourceName
		if sourceName == "" {
			sourceName = entry.SourceID
		}
		sourceEntityID := fmt.Sprintf("source:%s", sourceName)
		edgeID := fmt.Sprintf("edge:%s:%s:mentioned_in", entityID, sourceEntityID)
		p.archive.UpsertEdge(ctx, edgeID, entityID, sourceEntityID, "mentioned_in")
	}

	// Create relationship edges between named entities.
	for _, rel := range result.Relationships {
		srcID, srcOK := nameToID[rel.Source]
		tgtID, tgtOK := nameToID[rel.Target]
		if !srcOK || !tgtOK || rel.Relationship == "" {
			continue
		}

		// Safety net: non-observed entities can only have weak relationships,
		// regardless of what the LLM returned.
		relType := rel.Relationship
		if !nameObserved[rel.Source] {
			if relType != "referenced_in" && relType != "associated_with" {
				relType = "associated_with"
			}
		}

		edgeID := fmt.Sprintf("edge:%s:%s:%s", srcID, tgtID, relType)
		if err := p.archive.UpsertEdge(ctx, edgeID, srcID, tgtID, relType); err != nil {
			log.Printf("ingest: entity bridge worker %d: upsert llm edge: %v", workerID, err)
		}
	}
}

// classifyLimiter returns the shared rate limiter for classification workers.
// It is lazily initialised on first access.
func (p *IngestPipeline) classifyLimiter() *rateLimiter {
	p.initLimitersOnce.Do(p.initLimiters)
	return p.classifyRL
}

// extractLimiter returns the shared rate limiter for entity extraction workers.
func (p *IngestPipeline) extractLimiter() *rateLimiter {
	p.initLimitersOnce.Do(p.initLimiters)
	return p.extractRL
}

// findingFromRawContent creates a minimal models.Finding from an archive entry
// so it can be passed to the analyzer methods.
func findingFromRawContent(rc archive.RawContent) models.Finding {
	f := models.Finding{
		ID:          rc.ID,
		Source:      rc.SourceType,
		SourceID:    rc.SourceID,
		SourceName:  rc.SourceName,
		Content:     rc.Content,
		ContentHash: rc.ContentHash,
		Author:      rc.Author,
		CollectedAt: rc.CollectedAt,
	}
	if rc.PostedAt != nil {
		f.Timestamp = *rc.PostedAt
	}
	return f
}

// sleepOrCancel sleeps for d or returns false if ctx is cancelled.
func sleepOrCancel(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}
