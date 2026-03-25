package enrichment

import (
	"context"
	"log"
	"math"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/modules"
)

// EnrichmentProvider is the interface for each enrichment source.
type EnrichmentProvider interface {
	Name() string
	SupportedTypes() []string
	Enrich(ctx context.Context, iocType, value string) (*EnrichmentResult, error)
	RateLimit() time.Duration
}

// EnrichmentResult holds the output of an enrichment lookup.
type EnrichmentResult struct {
	Provider  string         `json:"provider"`
	Malicious *bool          `json:"malicious,omitempty"`
	Score     *float64       `json:"score,omitempty"`
	Data      map[string]any `json:"data"`
}

// Enricher runs a background pipeline that enriches IOCs using external APIs.
type Enricher struct {
	archive   *archive.Store
	providers []EnrichmentProvider
	status    *modules.StatusTracker
	cfg       config.EnrichmentConfig
}

// NewEnricher creates an enricher with the given providers.
func NewEnricher(archiveStore *archive.Store, cfg config.EnrichmentConfig, providers []EnrichmentProvider) *Enricher {
	e := &Enricher{
		archive:   archiveStore,
		providers: providers,
		cfg:       cfg,
		status:    modules.NewStatusTracker(modules.ModEnrichment, "IOC Enrichment", "processor"),
	}
	e.status.SetEnabled(cfg.Enabled)
	return e
}

// Status returns the module status tracker for registry registration.
func (e *Enricher) Status() *modules.StatusTracker {
	return e.status
}

// Run starts the periodic enrichment loop.
func (e *Enricher) Run(ctx context.Context) {
	if !e.cfg.Enabled || len(e.providers) == 0 {
		return
	}
	e.status.MarkStarted()
	defer e.status.MarkStopped()

	interval := time.Duration(e.cfg.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	e.status.SetExtra("interval", interval.String())
	e.status.SetExtra("providers", providerNames(e.providers))

	batchSize := e.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 20
	}

	log.Printf("enrichment: started (interval=%s, batch=%d, providers=%v)",
		interval, batchSize, providerNames(e.providers))

	e.runCycle(ctx, batchSize)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("enrichment: stopping")
			return
		case <-ticker.C:
			e.runCycle(ctx, batchSize)
		}
	}
}

func (e *Enricher) runCycle(ctx context.Context, batchSize int) {
	start := time.Now()

	iocs, err := e.archive.FetchUnenrichedIOCs(ctx, batchSize)
	if err != nil {
		e.status.RecordError(err)
		log.Printf("enrichment: fetch error: %v", err)
		return
	}

	if len(iocs) == 0 {
		return
	}

	var enriched int

	for _, ioc := range iocs {
		if ctx.Err() != nil {
			return
		}

		allResults := make(map[string]any)
		var sources []string
		var maxScore float64

		for _, provider := range e.providers {
			if !contains(provider.SupportedTypes(), ioc.Type) {
				continue
			}

			// Per-provider rate limit.
			time.Sleep(provider.RateLimit())

			result, err := provider.Enrich(ctx, ioc.Type, ioc.Value)
			if err != nil {
				log.Printf("enrichment: %s error for %s:%s: %v",
					provider.Name(), ioc.Type, ioc.Value, err)
				continue
			}

			allResults[provider.Name()] = result.Data
			sources = append(sources, provider.Name())

			if result.Score != nil && *result.Score > maxScore {
				maxScore = *result.Score
			}
		}

		if len(sources) == 0 {
			// No providers ran — mark as enriched with empty results
			// to avoid re-processing
			e.archive.MarkIOCEnriched(ctx, ioc.Type, ioc.Value, allResults, sources, ioc.BaseScore)
			continue
		}

		// Enrichment boosts base_score but never lowers it.
		newBaseScore := ioc.BaseScore
		if maxScore > 0 {
			newBaseScore = math.Max(ioc.BaseScore, maxScore*0.8)
		}

		if err := e.archive.MarkIOCEnriched(ctx, ioc.Type, ioc.Value, allResults, sources, newBaseScore); err != nil {
			e.status.RecordError(err)
			log.Printf("enrichment: mark enriched error for %s:%s: %v", ioc.Type, ioc.Value, err)
		} else {
			e.status.RecordSuccess()
			enriched++
		}
	}

	e.status.SetExtra("last_cycle_duration", time.Since(start).String())
	e.status.SetExtra("last_cycle_enriched", enriched)
	e.status.SetExtra("last_cycle_total", len(iocs))

	log.Printf("enrichment: cycle complete in %s — enriched %d/%d IOCs",
		time.Since(start).Round(time.Millisecond), enriched, len(iocs))
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func providerNames(providers []EnrichmentProvider) []string {
	names := make([]string, len(providers))
	for i, p := range providers {
		names[i] = p.Name()
	}
	return names
}
