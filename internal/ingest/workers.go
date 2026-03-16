package ingest

import (
	"context"
	"log"
	"sync"
	"time"

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

	r.mu.Unlock()

	select {
	case <-time.After(remaining):
	case <-ctx.Done():
		return ctx.Err()
	}

	r.mu.Lock()
	r.lastCall = time.Now()
	r.mu.Unlock()
	return nil
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
			tags := tagsFromCategory(category)

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
			if err := p.archive.MarkClassified(ctx, entry.ID, category, tags, severity.String(), summary); err != nil {
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
