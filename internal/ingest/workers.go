package ingest

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/models"
)

const (
	// workerIdleInterval is how long workers sleep when there is no work.
	workerIdleInterval = 30 * time.Second

	// workerLogInterval is how many items to process between progress logs.
	workerLogInterval = 10
)

// currentClassificationVersion is incremented when the classification
// pipeline changes materially. Workers stamp this version on each
// processed entry; on startup, entries with an older version are reset
// for reprocessing.
const currentClassificationVersion = 3

// concurrencyLimiter limits the number of concurrent in-flight requests.
// It uses a buffered channel as a counting semaphore.
type concurrencyLimiter struct {
	sem chan struct{}
}

func newConcurrencyLimiter(maxConcurrent int) *concurrencyLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 2
	}
	return &concurrencyLimiter{
		sem: make(chan struct{}, maxConcurrent),
	}
}

// Acquire blocks until a slot is available or ctx is cancelled.
func (c *concurrencyLimiter) Acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a slot. Must be called after Acquire.
func (c *concurrencyLimiter) Release() {
	<-c.sem
}

// classificationWorker polls the archive for unclassified content and runs
// LLM classification on each entry. Classification uses the fast analyzer
// (GLM-4-Plus) and summarization uses the full analyzer (GLM-5).
func (p *IngestPipeline) classificationWorker(ctx context.Context, workerID int) {
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

			// Build a minimal Finding for the analyzer.
			finding := findingFromRawContent(entry)

			// Classify (GLM-4-Plus via classifySem).
			if err := p.classifySem.Acquire(ctx); err != nil {
				return
			}
			classResult, err := p.classifyAnalyzer.Classify(ctx, &finding, nil)
			p.classifySem.Release()
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

			// Extract severity from the merged classify response.
			severity := models.SeverityInfo
			if classResult.Severity != "" {
				sev, err := models.ParseSeverity(classResult.Severity)
				if err != nil {
					log.Printf("ingest: classification worker %d: severity parse error for %s: %v", workerID, entry.ID, err)
				} else {
					severity = sev
				}
			}

			// Summarize (GLM-5 via extractSem).
			if err := p.extractSem.Acquire(ctx); err != nil {
				return
			}
			summary, err := p.fullAnalyzer.Summarize(ctx, &finding, category, severity)
			p.extractSem.Release()
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
// content and runs LLM entity extraction on each entry using the full
// analyzer (GLM-5) gated by the extract semaphore.
func (p *IngestPipeline) entityExtractionWorker(ctx context.Context, workerID int) {
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

			finding := findingFromRawContent(entry)

			if err := p.extractSem.Acquire(ctx); err != nil {
				return
			}
			iocs, err := p.fullAnalyzer.ExtractIOCs(ctx, &finding)
			p.extractSem.Release()
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
				if err := p.extractSem.Acquire(ctx); err != nil {
					return
				}
				finding2 := findingFromRawContent(entry)
				result, err := p.fullAnalyzer.ExtractEntities(ctx, &finding2, entry.Category, entry.SourceName, entry.SourceType, entry.Provenance)
				p.extractSem.Release()
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

		// Safety net: if neither entity is observed, force weak relationship.
		relType := rel.Relationship
		if !nameObserved[rel.Source] && !nameObserved[rel.Target] {
			if relType != "referenced_in" && relType != "mentioned_in" {
				relType = "referenced_in"
			}
		}

		edgeID := fmt.Sprintf("edge:%s:%s:%s", srcID, tgtID, relType)
		if err := p.archive.UpsertEdge(ctx, edgeID, srcID, tgtID, relType); err != nil {
			log.Printf("ingest: entity bridge worker %d: upsert llm edge: %v", workerID, err)
		}
	}
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
