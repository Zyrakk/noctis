package collector

import (
	"context"
	"log"
	"math"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Zyrakk/noctis/internal/modules"
)

// sourceValueRef holds the fields needed to identify a source and match
// its content in raw_content. Used by SourceValueAnalyzer.
type sourceValueRef struct {
	id, sourceType, identifier, name string
}

// SourceValueAnalyzer periodically computes value metrics for each source
// and writes results to the sources table.
type SourceValueAnalyzer struct {
	pool   *pgxpool.Pool
	status *modules.StatusTracker
}

// NewSourceValueAnalyzer creates a source value analyzer.
func NewSourceValueAnalyzer(pool *pgxpool.Pool) *SourceValueAnalyzer {
	return &SourceValueAnalyzer{
		pool:   pool,
		status: modules.NewStatusTracker(modules.ModSourceAnalyzer, "Source Analyzer", "infra"),
	}
}

// Status returns the module status tracker for registry registration.
func (a *SourceValueAnalyzer) Status() *modules.StatusTracker {
	return a.status
}

// Run starts the periodic source value computation and blocks until ctx is cancelled.
func (a *SourceValueAnalyzer) Run(ctx context.Context) {
	a.status.SetEnabled(true)
	a.status.MarkStarted()
	defer a.status.MarkStopped()

	const interval = 6 * time.Hour
	a.status.SetExtra("interval", interval.String())

	log.Printf("collector: source value analyzer started (interval=%s)", interval)

	// Run once on startup, then on interval.
	a.runCycle(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runCycle(ctx)
		}
	}
}

func (a *SourceValueAnalyzer) runCycle(ctx context.Context) {
	start := time.Now()

	// Get all sources with their names, types, and identifiers.
	rows, err := a.pool.Query(ctx, `
		SELECT id, type, identifier, COALESCE(name, identifier) FROM sources
		WHERE status IN ('active', 'approved', 'discovered')`)
	if err != nil {
		a.status.RecordError(err)
		log.Printf("collector: source value: fetch sources error: %v", err)
		return
	}

	var sources []sourceValueRef
	for rows.Next() {
		var s sourceValueRef
		if err := rows.Scan(&s.id, &s.sourceType, &s.identifier, &s.name); err != nil {
			continue
		}
		sources = append(sources, s)
	}
	rows.Close()

	if len(sources) == 0 {
		return
	}

	for _, src := range sources {
		if ctx.Err() != nil {
			return
		}
		a.computeSourceValue(ctx, src)
	}

	a.status.RecordSuccess()
	a.status.SetExtra("last_cycle_duration", time.Since(start).String())
	a.status.SetExtra("last_cycle_sources", len(sources))

	log.Printf("collector: source value cycle complete in %s — %d sources",
		time.Since(start).Round(time.Millisecond), len(sources))
}

func (a *SourceValueAnalyzer) computeSourceValue(ctx context.Context, src sourceValueRef) {
	// Resolve match parameters. For telegram sources, extract the username
	// from the t.me URL and resolve the numeric channel ID so we can match
	// ALL messages (both catchup and live) regardless of source_name variant.
	sourceName := src.name
	channelID := "" // populated for telegram sources

	if strings.HasPrefix(src.sourceType, "telegram") {
		username := extractUsername(src.identifier)
		if username != "" {
			sourceName = username
			_ = a.pool.QueryRow(ctx, `
				SELECT source_id FROM raw_content
				WHERE source_type = 'telegram' AND source_name = $1
				LIMIT 1`, username).Scan(&channelID)
		}
	}

	// 1. unique_iocs: IOCs first seen in this source (not seen elsewhere within 7 days prior).
	var uniqueIOCs int
	a.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT s.ioc_value) FROM ioc_sightings s
		WHERE (s.source_name = $1 OR s.source_id = $2)
		AND NOT EXISTS (
			SELECT 1 FROM ioc_sightings s2
			WHERE s2.ioc_value = s.ioc_value AND s2.ioc_type = s.ioc_type
			AND NOT (s2.source_name = $1 OR s2.source_id = $2)
			AND s2.created_at < s.created_at
			AND s2.created_at > s.created_at - INTERVAL '7 days'
		)`, sourceName, channelID).Scan(&uniqueIOCs)

	// 2. correlation_contributions: correlations where a finding from this source appears.
	var correlationContribs int
	a.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT c.id) FROM correlations c
		WHERE EXISTS (
			SELECT 1 FROM unnest(c.finding_ids) fid
			JOIN raw_content rc ON rc.id = fid::uuid
			WHERE rc.source_name = $1 OR rc.source_id = $2
		)`, sourceName, channelID).Scan(&correlationContribs)

	// 3. avg_severity: numeric average (critical=4, high=3, medium=2, low=1, info=0).
	var avgSeverity float64
	a.pool.QueryRow(ctx, `
		SELECT COALESCE(AVG(
			CASE severity
				WHEN 'critical' THEN 4
				WHEN 'high' THEN 3
				WHEN 'medium' THEN 2
				WHEN 'low' THEN 1
				WHEN 'info' THEN 0
				ELSE 0
			END
		), 0)
		FROM raw_content
		WHERE (source_name = $1 OR source_id = $2) AND classified = true
		AND category IS NOT NULL AND category != 'irrelevant'`, sourceName, channelID).Scan(&avgSeverity)

	// 4. signal_to_noise: non-irrelevant / total.
	var totalFindings, nonIrrelevant int
	a.pool.QueryRow(ctx, `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE category IS NOT NULL AND category != 'irrelevant')
		FROM raw_content
		WHERE (source_name = $1 OR source_id = $2) AND classified = true`, sourceName, channelID,
	).Scan(&totalFindings, &nonIrrelevant)

	var signalToNoise float64
	if totalFindings > 0 {
		signalToNoise = float64(nonIrrelevant) / float64(totalFindings)
	}

	// 5. freshness_score: 1.0 if something in last 24h, exponential decay.
	var lastCollectedAt *time.Time
	a.pool.QueryRow(ctx, `
		SELECT MAX(collected_at) FROM raw_content
		WHERE source_name = $1 OR source_id = $2`, sourceName, channelID,
	).Scan(&lastCollectedAt)

	freshnessScore := 0.0
	if lastCollectedAt != nil {
		hoursSince := time.Since(*lastCollectedAt).Hours()
		freshnessScore = math.Exp(-hoursSince / 24.0) // 1.0 at 0h, ~0.37 at 24h, ~0.14 at 48h
	}

	// 6. value_score: weighted combination.
	iocRatio := 0.0
	corrRatio := 0.0
	if totalFindings > 0 {
		iocRatio = float64(uniqueIOCs) / float64(totalFindings)
		corrRatio = float64(correlationContribs) / float64(totalFindings)
	}

	valueScore := 0.3*iocRatio +
		0.2*corrRatio +
		0.2*(avgSeverity/4.0) +
		0.15*signalToNoise +
		0.15*freshnessScore

	// Clamp to [0, 1].
	if valueScore > 1.0 {
		valueScore = 1.0
	}

	// Write results.
	_, err := a.pool.Exec(ctx, `
		UPDATE sources
		SET unique_iocs = $2,
		    correlation_contributions = $3,
		    avg_severity = $4,
		    signal_to_noise = $5,
		    value_score = $6,
		    value_computed_at = NOW()
		WHERE id = $1`,
		src.id, uniqueIOCs, correlationContribs, avgSeverity, signalToNoise, valueScore)
	if err != nil {
		log.Printf("collector: source value: update error for %s: %v", sourceName, err)
	}
}
