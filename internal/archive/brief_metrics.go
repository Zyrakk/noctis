package archive

import (
	"context"
	"fmt"
	"time"
)

// BriefMetrics holds aggregated metrics for a time period.
type BriefMetrics struct {
	FindingsBySeverity map[string]int64 `json:"findings_by_severity"`
	FindingsByCategory map[string]int64 `json:"findings_by_category"`
	NewIOCsByType      map[string]int64 `json:"new_iocs_by_type"`
	NewCorrelations    int64            `json:"new_correlations"`
	AnalystConfirmed   int64            `json:"analyst_confirmed"`
	NewNotes           int64            `json:"new_notes"`
	DeactivatedIOCs    int64            `json:"deactivated_iocs"`
	SourceActivity     []SourceMetric   `json:"source_activity"`
}

// SourceMetric tracks a source's activity in a time period.
type SourceMetric struct {
	Name         string  `json:"name"`
	FindingCount int64   `json:"finding_count"`
	ValueScore   float64 `json:"value_score"`
}

// TopFinding is a high-severity finding summary for briefs.
type TopFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	SubCategory string `json:"sub_category"`
	Summary     string `json:"summary"`
	SourceName  string `json:"source_name"`
}

// TrendingEntity tracks entity mention frequency changes.
type TrendingEntity struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	MentionCount int64  `json:"mention_count"`
	PrevCount    int64  `json:"prev_count"`
}

// FetchBriefMetrics returns aggregated metrics for a time period.
func (s *Store) FetchBriefMetrics(ctx context.Context, start, end time.Time) (*BriefMetrics, error) {
	m := &BriefMetrics{
		FindingsBySeverity: make(map[string]int64),
		FindingsByCategory: make(map[string]int64),
		NewIOCsByType:      make(map[string]int64),
	}

	// Findings by severity
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(severity, 'info'), COUNT(*)
		FROM raw_content
		WHERE collected_at BETWEEN $1 AND $2 AND classified = TRUE
		GROUP BY severity`, start, end)
	if err != nil {
		return nil, fmt.Errorf("archive: brief metrics severity: %w", err)
	}
	for rows.Next() {
		var sev string
		var cnt int64
		if err := rows.Scan(&sev, &cnt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("archive: brief metrics severity scan: %w", err)
		}
		m.FindingsBySeverity[sev] = cnt
	}
	rows.Close()

	// Findings by category
	rows, err = s.pool.Query(ctx, `
		SELECT COALESCE(category, 'uncategorized'), COUNT(*)
		FROM raw_content
		WHERE collected_at BETWEEN $1 AND $2 AND classified = TRUE
		GROUP BY category`, start, end)
	if err != nil {
		return nil, fmt.Errorf("archive: brief metrics category: %w", err)
	}
	for rows.Next() {
		var cat string
		var cnt int64
		if err := rows.Scan(&cat, &cnt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("archive: brief metrics category scan: %w", err)
		}
		m.FindingsByCategory[cat] = cnt
	}
	rows.Close()

	// New IOCs by type (first_seen in range)
	rows, err = s.pool.Query(ctx, `
		SELECT type, COUNT(*)
		FROM iocs
		WHERE first_seen BETWEEN $1 AND $2
		GROUP BY type`, start, end)
	if err != nil {
		return nil, fmt.Errorf("archive: brief metrics iocs: %w", err)
	}
	for rows.Next() {
		var iocType string
		var cnt int64
		if err := rows.Scan(&iocType, &cnt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("archive: brief metrics iocs scan: %w", err)
		}
		m.NewIOCsByType[iocType] = cnt
	}
	rows.Close()

	// New correlations
	err = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM correlations
		WHERE created_at BETWEEN $1 AND $2`, start, end).Scan(&m.NewCorrelations)
	if err != nil {
		return nil, fmt.Errorf("archive: brief metrics correlations: %w", err)
	}

	// Analyst-confirmed correlations
	err = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM correlations
		WHERE created_at BETWEEN $1 AND $2 AND method = 'analyst'`, start, end).Scan(&m.AnalystConfirmed)
	if err != nil {
		return nil, fmt.Errorf("archive: brief metrics analyst: %w", err)
	}

	// New analytical notes
	err = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM analytical_notes
		WHERE created_at BETWEEN $1 AND $2`, start, end).Scan(&m.NewNotes)
	if err != nil {
		return nil, fmt.Errorf("archive: brief metrics notes: %w", err)
	}

	// Deactivated IOCs
	err = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM iocs
		WHERE deactivated_at BETWEEN $1 AND $2`, start, end).Scan(&m.DeactivatedIOCs)
	if err != nil {
		return nil, fmt.Errorf("archive: brief metrics deactivated: %w", err)
	}

	// Source activity
	rows, err = s.pool.Query(ctx, `
		SELECT rc.source_name, COUNT(*) AS cnt,
		       COALESCE(s.value_score, 0) AS value_score
		FROM raw_content rc
		LEFT JOIN sources s ON s.name = rc.source_name
		WHERE rc.collected_at BETWEEN $1 AND $2 AND rc.classified = TRUE
		GROUP BY rc.source_name, s.value_score
		ORDER BY cnt DESC
		LIMIT 10`, start, end)
	if err != nil {
		return nil, fmt.Errorf("archive: brief metrics sources: %w", err)
	}
	for rows.Next() {
		var sm SourceMetric
		if err := rows.Scan(&sm.Name, &sm.FindingCount, &sm.ValueScore); err != nil {
			rows.Close()
			return nil, fmt.Errorf("archive: brief metrics sources scan: %w", err)
		}
		m.SourceActivity = append(m.SourceActivity, sm)
	}
	rows.Close()

	return m, nil
}

// FetchTopFindings returns the highest-severity findings in a time period.
func (s *Store) FetchTopFindings(ctx context.Context, start, end time.Time, limit int) ([]TopFinding, error) {
	if limit <= 0 {
		limit = 10
	}
	const query = `
	SELECT id, COALESCE(severity, 'info'), COALESCE(category, ''),
	       COALESCE(sub_category, ''), COALESCE(summary, LEFT(content, 200)),
	       source_name
	FROM raw_content
	WHERE collected_at BETWEEN $1 AND $2 AND classified = TRUE
	ORDER BY CASE severity
		WHEN 'critical' THEN 0
		WHEN 'high' THEN 1
		WHEN 'medium' THEN 2
		WHEN 'low' THEN 3
		ELSE 4
	END, collected_at DESC
	LIMIT $3`

	rows, err := s.pool.Query(ctx, query, start, end, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: top findings: %w", err)
	}
	defer rows.Close()

	var results []TopFinding
	for rows.Next() {
		var f TopFinding
		if err := rows.Scan(&f.ID, &f.Severity, &f.Category, &f.SubCategory, &f.Summary, &f.SourceName); err != nil {
			return nil, fmt.Errorf("archive: top findings scan: %w", err)
		}
		results = append(results, f)
	}
	return results, rows.Err()
}

// FetchTrendingEntities returns entities with the most mentions in a period,
// compared against the previous equivalent period.
func (s *Store) FetchTrendingEntities(ctx context.Context, start, end time.Time, limit int) ([]TrendingEntity, error) {
	if limit <= 0 {
		limit = 10
	}
	duration := end.Sub(start)
	prevStart := start.Add(-duration)

	const query = `
	WITH current AS (
		SELECT e.id, e.type, COUNT(DISTINCT ed.source_id || ed.target_id) AS cnt
		FROM entities e
		JOIN edges ed ON ed.source_id = e.id OR ed.target_id = e.id
		WHERE ed.created_at BETWEEN $1 AND $2
		GROUP BY e.id, e.type
	),
	previous AS (
		SELECT e.id, COUNT(DISTINCT ed.source_id || ed.target_id) AS cnt
		FROM entities e
		JOIN edges ed ON ed.source_id = e.id OR ed.target_id = e.id
		WHERE ed.created_at BETWEEN $3 AND $4
		GROUP BY e.id
	)
	SELECT c.id, c.type, c.cnt, COALESCE(p.cnt, 0)
	FROM current c
	LEFT JOIN previous p ON p.id = c.id
	ORDER BY c.cnt DESC
	LIMIT $5`

	rows, err := s.pool.Query(ctx, query, start, end, prevStart, start, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: trending entities: %w", err)
	}
	defer rows.Close()

	var results []TrendingEntity
	for rows.Next() {
		var e TrendingEntity
		if err := rows.Scan(&e.ID, &e.Type, &e.MentionCount, &e.PrevCount); err != nil {
			return nil, fmt.Errorf("archive: trending entities scan: %w", err)
		}
		results = append(results, e)
	}
	return results, rows.Err()
}
