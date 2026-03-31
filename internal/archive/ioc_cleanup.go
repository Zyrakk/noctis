package archive

import (
	"context"
	"fmt"
)

// ActiveIOC is a minimal IOC record for cleanup iteration.
type ActiveIOC struct {
	Type  string
	Value string
}

// CleanupIOCsByPattern deactivates IOCs matching known-bad patterns using SQL.
// Returns the number of deactivated rows.
func (s *Store) CleanupIOCsByPattern(ctx context.Context) (int64, error) {
	const query = `
	UPDATE iocs SET active = FALSE, deactivated_at = NOW()
	WHERE active = TRUE AND (
		-- Spaces or tabs (descriptions, not real IOCs)
		value ~ '[\s\t]'
		-- Wildcards
		OR value LIKE '%*%'
		-- Defanged brackets (report artifacts)
		OR value LIKE '%[.]%'
		OR value LIKE '%[:]%'
		-- RFC 2606 reserved domains (exact and subdomains)
		OR (type IN ('domain', 'url') AND (
			value ~* '(^|://|\.)(example\.com|example\.org|example\.net)(/|$|:)'
			OR value ~* '(^|://|\.)(example\.com|example\.org|example\.net)$'
		))
		-- RFC 6761 reserved TLDs
		OR (type IN ('domain', 'url') AND
			value ~* '\.(test|invalid|localhost|example)(/|$|:)')
	)`

	ct, err := s.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("archive: cleanup iocs by pattern: %w", err)
	}
	return ct.RowsAffected(), nil
}

// ListActiveIOCsByType returns all active IOCs of the given types.
func (s *Store) ListActiveIOCsByType(ctx context.Context, types []string) ([]ActiveIOC, error) {
	const query = `
	SELECT type, value FROM iocs
	WHERE active = TRUE AND type = ANY($1)
	ORDER BY first_seen ASC`

	rows, err := s.pool.Query(ctx, query, types)
	if err != nil {
		return nil, fmt.Errorf("archive: list active iocs: %w", err)
	}
	defer rows.Close()

	var iocs []ActiveIOC
	for rows.Next() {
		var ioc ActiveIOC
		if err := rows.Scan(&ioc.Type, &ioc.Value); err != nil {
			return nil, fmt.Errorf("archive: scan active ioc: %w", err)
		}
		iocs = append(iocs, ioc)
	}
	return iocs, rows.Err()
}

// DeactivateIOC marks a single IOC as inactive.
func (s *Store) DeactivateIOC(ctx context.Context, iocType, value string) error {
	const query = `
	UPDATE iocs SET active = FALSE, deactivated_at = NOW()
	WHERE type = $1 AND value = $2 AND active = TRUE`

	_, err := s.pool.Exec(ctx, query, iocType, value)
	if err != nil {
		return fmt.Errorf("archive: deactivate ioc (%s, %s): %w", iocType, value, err)
	}
	return nil
}
