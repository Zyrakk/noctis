package processor

import (
	"context"
	"log"
	"time"

	"github.com/Zyrakk/noctis/internal/llm"
	"github.com/Zyrakk/noctis/internal/models"
)

// budgetPauseDuration is how long workers pause when a budget limit is hit.
const budgetPauseDuration = 30 * time.Minute

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

			// Circuit breaker: if budget is exhausted, pause all workers.
			if e.budgetExhausted.Load() {
				log.Printf("processor: classification worker %d: budget exhausted, pausing %v", workerID, budgetPauseDuration)
				if !SleepOrCancel(ctx, budgetPauseDuration) {
					return
				}
				e.budgetExhausted.Store(false)
				log.Printf("processor: classification worker %d: budget pause ended, resuming", workerID)
			}

			// Skip items already marked as poison by another worker.
			e.classifyFailMu.Lock()
			alreadyPoison := e.classifyFailCounts[entry.ID] >= 5
			e.classifyFailMu.Unlock()
			if alreadyPoison {
				continue
			}

			finding := FindingFromRawContentWithLimit(entry, e.maxContentLength)

			// Classify (fast LLM).
			classResult, err := e.classifier.Classify(ctx, &finding)
			if err != nil {
				// Budget exhausted — trip the circuit breaker for all workers.
				if llm.IsBudgetExhausted(err) {
					log.Printf("processor: classification worker %d: budget exhausted: %v", workerID, err)
					e.budgetExhausted.Store(true)
					break // exit batch loop; circuit breaker at top will handle pause
				}

				log.Printf("processor: classification worker %d: classify error for %s: %v", workerID, entry.ID, err)

				e.classifyFailMu.Lock()
				e.classifyFailCounts[entry.ID]++
				count := e.classifyFailCounts[entry.ID]
				e.classifyFailMu.Unlock()

				log.Printf("processor: classification worker %d: poison item failure count id=%s count=%d", workerID, entry.ID, count)

				if count >= 5 {
					log.Printf("processor: classification worker %d: skipping poison item %s after %d consecutive classify failures", workerID, entry.ID, count)
					tags := []string{"unclassifiable", "poison_item"}
					if markErr := e.archive.MarkClassified(ctx, entry.ID, "irrelevant", tags, "info", "", "unknown", CurrentClassificationVersion); markErr != nil {
						log.Printf("processor: classification worker %d: mark poison error for %s: %v", workerID, entry.ID, markErr)
					} else {
						e.classifyFailMu.Lock()
						delete(e.classifyFailCounts, entry.ID)
						e.classifyFailMu.Unlock()
					}
				}
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

			// Override: irrelevant content must not have elevated severity.
			if category == "irrelevant" && severity > models.SeverityInfo {
				severity = models.SeverityInfo
			}

			// Summarize (fast LLM) — skip for irrelevant items to save tokens.
			var summary string
			if category != "irrelevant" {
				summary, err = e.summarizer.Summarize(ctx, &finding, category, severity)
				if err != nil {
					if llm.IsBudgetExhausted(err) {
						log.Printf("processor: classification worker %d: budget exhausted during summarize: %v", workerID, err)
						e.budgetExhausted.Store(true)
						break
					}
					log.Printf("processor: classification worker %d: summarize error for %s: %v", workerID, entry.ID, err)
					summary = ""
				}
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

			// Circuit breaker: if budget is exhausted, pause all workers.
			if e.budgetExhausted.Load() {
				log.Printf("processor: entity extraction worker %d: budget exhausted, pausing %v", workerID, budgetPauseDuration)
				if !SleepOrCancel(ctx, budgetPauseDuration) {
					return
				}
				e.budgetExhausted.Store(false)
				log.Printf("processor: entity extraction worker %d: budget pause ended, resuming", workerID)
			}

			finding := FindingFromRawContentWithLimit(entry, e.maxContentLength)

			// Extract IOCs (fast LLM).
			iocs, err := e.iocExtract.Extract(ctx, &finding)
			if err != nil {
				if llm.IsBudgetExhausted(err) {
					log.Printf("processor: entity extraction worker %d: budget exhausted: %v", workerID, err)
					e.budgetExhausted.Store(true)
					break
				}

				log.Printf("processor: entity extraction worker %d: extract error for %s: %v", workerID, entry.ID, err)

				e.extractFailMu.Lock()
				e.extractFailCounts[entry.ID]++
				count := e.extractFailCounts[entry.ID]
				e.extractFailMu.Unlock()

				log.Printf("processor: entity extraction worker %d: poison item failure count id=%s count=%d", workerID, entry.ID, count)

				if count >= 5 {
					log.Printf("processor: entity extraction worker %d: skipping poison item %s after %d consecutive extract failures", workerID, entry.ID, count)
					if markErr := e.archive.MarkEntitiesExtracted(ctx, entry.ID); markErr != nil {
						log.Printf("processor: entity extraction worker %d: mark poison error for %s: %v", workerID, entry.ID, markErr)
					} else {
						e.extractFailMu.Lock()
						delete(e.extractFailCounts, entry.ID)
						e.extractFailMu.Unlock()
					}
				}
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
				finding2 := FindingFromRawContentWithLimit(entry, e.maxContentLength)
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

			finding := FindingFromRawContentWithLimit(entry, e.maxContentLength)

			// Gather entity names and IOC values for context.
			entityNames := e.getEntityNamesForFinding(ctx, entry.ID)
			iocValues := e.getIOCValuesForFinding(ctx, entry.ID)

			result, err := e.librarian.SubClassify(ctx, &finding, entry.Category, entry.Provenance, entityNames, iocValues)
			if err != nil {
				log.Printf("processor: librarian worker %d: sub-classify error for %s: %v", workerID, entry.ID, err)

				e.librarianFailMu.Lock()
				e.librarianFailCounts[entry.ID]++
				count := e.librarianFailCounts[entry.ID]
				e.librarianFailMu.Unlock()

				log.Printf("processor: librarian worker %d: poison item failure count id=%s count=%d", workerID, entry.ID, count)

				if count >= 5 {
					log.Printf("processor: librarian worker %d: skipping poison item %s after %d consecutive sub-classify failures", workerID, entry.ID, count)
					if markErr := e.archive.MarkSubClassified(ctx, entry.ID, "unclassifiable", nil); markErr != nil {
						log.Printf("processor: librarian worker %d: mark poison error for %s: %v", workerID, entry.ID, markErr)
					} else {
						e.librarianFailMu.Lock()
						delete(e.librarianFailCounts, entry.ID)
						e.librarianFailMu.Unlock()
					}
				}
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
