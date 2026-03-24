package archive

import (
	"context"
	"fmt"
)

// UpdateIOCScores applies exponential decay to all active IOCs based on time since last sighting.
// Formula: threat_score = base_score * exp(-0.3 * days_since_last_seen / lifetime_days)
// Deactivates IOCs whose threat_score drops below the threshold.
func (s *Store) UpdateIOCScores(ctx context.Context, deactivateThreshold float64) (updated int64, deactivated int64, err error) {
	const decayQuery = `
	UPDATE iocs
	SET threat_score = base_score * exp(
		-0.3 * (EXTRACT(EPOCH FROM (NOW() - last_seen)) / 86400.0)
		/ COALESCE(NULLIF(lifetime_days, 0), CASE type
			WHEN 'ip' THEN 30
			WHEN 'domain' THEN 90
			WHEN 'url' THEN 14
			WHEN 'hash_md5' THEN 365
			WHEN 'hash_sha256' THEN 365
			WHEN 'email' THEN 180
			WHEN 'cve' THEN 180
			WHEN 'crypto_wallet' THEN 365
			ELSE 90
		END)
	)
	WHERE active = TRUE`

	ct, err := s.pool.Exec(ctx, decayQuery)
	if err != nil {
		return 0, 0, fmt.Errorf("archive: decay ioc scores: %w", err)
	}
	updated = ct.RowsAffected()

	const deactivateQuery = `
	UPDATE iocs
	SET active = FALSE, deactivated_at = NOW()
	WHERE active = TRUE AND threat_score < $1`

	ct, err = s.pool.Exec(ctx, deactivateQuery, deactivateThreshold)
	if err != nil {
		return updated, 0, fmt.Errorf("archive: deactivate iocs: %w", err)
	}
	deactivated = ct.RowsAffected()

	return updated, deactivated, nil
}

// ReactivateIOC marks an IOC as active again (e.g., when re-sighted).
func (s *Store) ReactivateIOC(ctx context.Context, iocType, value string, newBaseScore float64) error {
	const query = `
	UPDATE iocs SET active = TRUE, deactivated_at = NULL,
		base_score = $3, threat_score = $3, last_seen = NOW(),
		sighting_count = sighting_count + 1
	WHERE type = $1 AND value = $2`

	_, err := s.pool.Exec(ctx, query, iocType, value, newBaseScore)
	if err != nil {
		return fmt.Errorf("archive: reactivate ioc (%s, %s): %w", iocType, value, err)
	}
	return nil
}

// SetIOCLifetimeDefaults sets the expected lifetime for IOCs that don't have one set yet.
func (s *Store) SetIOCLifetimeDefaults(ctx context.Context) error {
	const query = `
	UPDATE iocs SET lifetime_days = CASE type
		WHEN 'ip' THEN 30
		WHEN 'domain' THEN 90
		WHEN 'url' THEN 14
		WHEN 'hash_md5' THEN 365
		WHEN 'hash_sha256' THEN 365
		WHEN 'email' THEN 180
		WHEN 'cve' THEN 180
		WHEN 'crypto_wallet' THEN 365
		ELSE 90
	END
	WHERE lifetime_days IS NULL`

	_, err := s.pool.Exec(ctx, query)
	if err != nil {
		return fmt.Errorf("archive: set ioc lifetime defaults: %w", err)
	}
	return nil
}
