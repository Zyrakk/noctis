package processor

import (
	"context"
	"log"

	"github.com/Zyrakk/noctis/internal/models"
)

// classifyPipelineWorker polls for unclassified content and runs it through
// the Classifier → Summarizer pipeline. Each sub-module tracks its own health.
func (e *ProcessingEngine) classifyPipelineWorker(ctx context.Context, workerID int) {
	batchSize := e.workerCfg.ClassificationBatchSize
	var totalClassified int

	log.Printf("processor: classification worker %d started (batch=%d)", workerID, batchSize)

	for {
		if ctx.Err() != nil {
			log.Printf("processor: classification worker %d stopping", workerID)
			return
		}

		entries, err := e.archive.FetchUnclassified(ctx, batchSize)
		if err != nil {
			log.Printf("processor: classification worker %d: fetch error: %v", workerID, err)
			if !SleepOrCancel(ctx, WorkerIdleInterval) {
				return
			}
			continue
		}

		if len(entries) == 0 {
			if !SleepOrCancel(ctx, WorkerIdleInterval) {
				return
			}
			continue
		}

		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}

			finding := FindingFromRawContent(entry)

			// Classify (fast LLM).
			classResult, err := e.classifier.Classify(ctx, &finding)
			if err != nil {
				log.Printf("processor: classification worker %d: classify error for %s: %v", workerID, entry.ID, err)
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
			tags := TagsFromCategory(category)

			// Flag low-confidence classifications for review.
			if classResult.Confidence < 0.80 {
				tags = append(tags, "needs_review")
			}

			// Extract severity from the classify response.
			severity := models.SeverityInfo
			if classResult.Severity != "" {
				sev, err := models.ParseSeverity(classResult.Severity)
				if err != nil {
					log.Printf("processor: classification worker %d: severity parse error for %s: %v", workerID, entry.ID, err)
				} else {
					severity = sev
				}
			}

			// Summarize (full LLM).
			summary, err := e.summarizer.Summarize(ctx, &finding, category, severity)
			if err != nil {
				log.Printf("processor: classification worker %d: summarize error for %s: %v", workerID, entry.ID, err)
				summary = ""
			}

			// Persist classification results.
			if err := e.archive.MarkClassified(ctx, entry.ID, category, tags, severity.String(), summary, provenance, CurrentClassificationVersion); err != nil {
				log.Printf("processor: classification worker %d: mark classified error for %s: %v", workerID, entry.ID, err)
				continue
			}

			totalClassified++
			if totalClassified%WorkerLogInterval == 0 {
				log.Printf("processor: classification worker %d: classified %d items", workerID, totalClassified)
			}
		}
	}
}

// extractPipelineWorker polls for classified-but-not-extracted content and runs
// IOCExtractor → GraphBridge → EntityExtractor → GraphBridge pipeline.
func (e *ProcessingEngine) extractPipelineWorker(ctx context.Context, workerID int) {
	batchSize := e.workerCfg.ClassificationBatchSize // reuse same batch size
	var totalExtracted int

	log.Printf("processor: entity extraction worker %d started (batch=%d)", workerID, batchSize)

	for {
		if ctx.Err() != nil {
			log.Printf("processor: entity extraction worker %d stopping", workerID)
			return
		}

		entries, err := e.archive.FetchClassifiedUnextracted(ctx, batchSize)
		if err != nil {
			log.Printf("processor: entity extraction worker %d: fetch error: %v", workerID, err)
			if !SleepOrCancel(ctx, WorkerIdleInterval) {
				return
			}
			continue
		}

		if len(entries) == 0 {
			if !SleepOrCancel(ctx, WorkerIdleInterval) {
				return
			}
			continue
		}

		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}

			finding := FindingFromRawContent(entry)

			// Extract IOCs (full LLM).
			iocs, err := e.iocExtract.Extract(ctx, &finding)
			if err != nil {
				log.Printf("processor: entity extraction worker %d: extract error for %s: %v", workerID, entry.ID, err)
				continue
			}

			// Upsert each IOC.
			for _, ioc := range iocs {
				if err := e.archive.UpsertIOC(ctx, ioc.Type, ioc.Value, ioc.Context, entry.ID); err != nil {
					log.Printf("processor: entity extraction worker %d: upsert ioc error: %v", workerID, err)
				}
			}

			// Bridge IOCs into the entity graph.
			if len(iocs) > 0 {
				if err := e.graphBridge.BridgeIOCs(ctx, entry, iocs); err != nil {
					log.Printf("processor: entity extraction worker %d: bridge iocs error for %s: %v", workerID, entry.ID, err)
				}
			}

			// LLM entity extraction for non-irrelevant findings.
			if entry.Category != "" && entry.Category != "irrelevant" {
				finding2 := FindingFromRawContent(entry)
				result, err := e.entExtract.Extract(ctx, &finding2, entry.Category, entry.SourceName, entry.SourceType, entry.Provenance)
				if err != nil {
					log.Printf("processor: entity extraction worker %d: extract entities error for %s: %v", workerID, entry.ID, err)
				} else {
					if err := e.graphBridge.BridgeEntities(ctx, entry, result); err != nil {
						log.Printf("processor: entity extraction worker %d: bridge entities error for %s: %v", workerID, entry.ID, err)
					}
				}
			}

			// Mark as entity-extracted.
			if err := e.archive.MarkEntitiesExtracted(ctx, entry.ID); err != nil {
				log.Printf("processor: entity extraction worker %d: mark extracted error for %s: %v", workerID, entry.ID, err)
				continue
			}

			totalExtracted++
			if totalExtracted%WorkerLogInterval == 0 {
				log.Printf("processor: entity extraction worker %d: extracted %d items", workerID, totalExtracted)
			}
		}
	}
}

// librarianPipelineWorker polls for classified+extracted content that hasn't
// been sub-classified yet, and runs the Librarian to assign fine-grained
// sub-categories and structured metadata.
func (e *ProcessingEngine) librarianPipelineWorker(ctx context.Context, workerID int) {
	batchSize := e.workerCfg.ClassificationBatchSize
	var totalProcessed int

	log.Printf("processor: librarian worker %d started (batch=%d)", workerID, batchSize)

	for {
		if ctx.Err() != nil {
			log.Printf("processor: librarian worker %d stopping", workerID)
			return
		}

		entries, err := e.archive.FetchUnsubclassified(ctx, batchSize)
		if err != nil {
			log.Printf("processor: librarian worker %d: fetch error: %v", workerID, err)
			if !SleepOrCancel(ctx, WorkerIdleInterval) {
				return
			}
			continue
		}

		if len(entries) == 0 {
			if !SleepOrCancel(ctx, WorkerIdleInterval) {
				return
			}
			continue
		}

		for _, entry := range entries {
			if ctx.Err() != nil {
				return
			}

			// canary_hit gets no sub-classification — mark as processed immediately.
			if entry.Category == "canary_hit" {
				if err := e.archive.MarkSubClassified(ctx, entry.ID, "", nil); err != nil {
					log.Printf("processor: librarian worker %d: mark canary error for %s: %v", workerID, entry.ID, err)
				}
				totalProcessed++
				continue
			}

			finding := FindingFromRawContent(entry)

			// Gather entity names and IOC values for context.
			entityNames := e.getEntityNamesForFinding(ctx, entry.ID)
			iocValues := e.getIOCValuesForFinding(ctx, entry.ID)

			result, err := e.librarian.SubClassify(ctx, &finding, entry.Category, entry.Provenance, entityNames, iocValues)
			if err != nil {
				log.Printf("processor: librarian worker %d: sub-classify error for %s: %v", workerID, entry.ID, err)
				continue
			}

			if err := e.archive.MarkSubClassified(ctx, entry.ID, result.SubCategory, result.SubMetadata); err != nil {
				log.Printf("processor: librarian worker %d: mark sub-classified error for %s: %v", workerID, entry.ID, err)
				continue
			}

			totalProcessed++
			if totalProcessed%WorkerLogInterval == 0 {
				log.Printf("processor: librarian worker %d: sub-classified %d items", workerID, totalProcessed)
			}
		}
	}
}

// getEntityNamesForFinding returns entity names linked to a finding via edges.
// Errors are logged and an empty slice is returned so the worker can continue.
func (e *ProcessingEngine) getEntityNamesForFinding(ctx context.Context, findingID string) []string {
	names, err := e.archive.FetchEntityNamesForFinding(ctx, findingID)
	if err != nil {
		log.Printf("processor: librarian: entity names lookup error for %s: %v", findingID, err)
		return nil
	}
	return names
}

// getIOCValuesForFinding returns IOC values linked to a finding.
// Errors are logged and an empty slice is returned so the worker can continue.
func (e *ProcessingEngine) getIOCValuesForFinding(ctx context.Context, findingID string) []string {
	values, err := e.archive.FetchIOCValuesForFinding(ctx, findingID)
	if err != nil {
		log.Printf("processor: librarian: ioc values lookup error for %s: %v", findingID, err)
		return nil
	}
	return values
}
