package processor

import (
	"context"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/models"
)

const (
	// WorkerIdleInterval is how long workers sleep when there is no work.
	WorkerIdleInterval = 30 * time.Second

	// WorkerLogInterval is how many items to process between progress logs.
	WorkerLogInterval = 10

	// CurrentClassificationVersion is incremented when the classification
	// pipeline changes materially. Workers stamp this version on each
	// processed entry; on startup, entries with an older version are reset
	// for reprocessing.
	CurrentClassificationVersion = 3
)

// ConcurrencyLimiter limits the number of concurrent in-flight requests.
// It uses a buffered channel as a counting semaphore.
type ConcurrencyLimiter struct {
	sem chan struct{}
}

func NewConcurrencyLimiter(maxConcurrent int) *ConcurrencyLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 2
	}
	return &ConcurrencyLimiter{
		sem: make(chan struct{}, maxConcurrent),
	}
}

// Acquire blocks until a slot is available or ctx is cancelled.
func (c *ConcurrencyLimiter) Acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees a slot. Must be called after Acquire.
func (c *ConcurrencyLimiter) Release() {
	<-c.sem
}

// FindingFromRawContent creates a minimal models.Finding from an archive entry
// so it can be passed to the analyzer methods.
func FindingFromRawContent(rc archive.RawContent) models.Finding {
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

// SleepOrCancel sleeps for d or returns false if ctx is cancelled.
func SleepOrCancel(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}

// TagsFromCategory derives a basic tag set from the classification category.
func TagsFromCategory(category string) []string {
	if category == "" {
		return nil
	}
	tags := []string{category}

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
