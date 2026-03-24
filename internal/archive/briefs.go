package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// IntelligenceBrief represents a generated intelligence report covering a time period.
type IntelligenceBrief struct {
	ID                   string         `json:"id"`
	PeriodStart          time.Time      `json:"period_start"`
	PeriodEnd            time.Time      `json:"period_end"`
	BriefType            string         `json:"brief_type"`
	Title                string         `json:"title"`
	ExecutiveSummary     string         `json:"executive_summary"`
	Content              string         `json:"content"`
	Sections             map[string]any `json:"sections"`
	Metrics              map[string]any `json:"metrics"`
	ModelUsed            *string        `json:"model_used,omitempty"`
	GenerationDurationMs int            `json:"generation_duration_ms"`
	GeneratedAt          time.Time      `json:"generated_at"`
}

// InsertBrief stores a generated intelligence brief.
func (s *Store) InsertBrief(ctx context.Context, brief *IntelligenceBrief) error {
	sectionsJSON, err := json.Marshal(brief.Sections)
	if err != nil {
		return fmt.Errorf("archive: marshal brief sections: %w", err)
	}
	metricsJSON, err := json.Marshal(brief.Metrics)
	if err != nil {
		return fmt.Errorf("archive: marshal brief metrics: %w", err)
	}

	const query = `
	INSERT INTO intelligence_briefs (
		period_start, period_end, brief_type, title, executive_summary,
		content, sections, metrics, model_used, generation_duration_ms
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	RETURNING id, generated_at`

	err = s.pool.QueryRow(ctx, query,
		brief.PeriodStart, brief.PeriodEnd, brief.BriefType, brief.Title,
		brief.ExecutiveSummary, brief.Content, sectionsJSON, metricsJSON,
		brief.ModelUsed, brief.GenerationDurationMs,
	).Scan(&brief.ID, &brief.GeneratedAt)
	if err != nil {
		return fmt.Errorf("archive: insert brief: %w", err)
	}
	return nil
}

// FetchLatestBrief returns the most recent brief of a given type.
func (s *Store) FetchLatestBrief(ctx context.Context, briefType string) (*IntelligenceBrief, error) {
	const query = `
	SELECT id, period_start, period_end, brief_type, title, executive_summary,
	       content, sections, metrics, model_used, generation_duration_ms, generated_at
	FROM intelligence_briefs
	WHERE brief_type = $1
	ORDER BY period_end DESC LIMIT 1`

	var b IntelligenceBrief
	var sectionsJSON, metricsJSON []byte

	err := s.pool.QueryRow(ctx, query, briefType).Scan(
		&b.ID, &b.PeriodStart, &b.PeriodEnd, &b.BriefType, &b.Title,
		&b.ExecutiveSummary, &b.Content, &sectionsJSON, &metricsJSON,
		&b.ModelUsed, &b.GenerationDurationMs, &b.GeneratedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch latest brief (%s): %w", briefType, err)
	}

	if len(sectionsJSON) > 0 {
		if err := json.Unmarshal(sectionsJSON, &b.Sections); err != nil {
			return nil, fmt.Errorf("archive: unmarshal brief sections: %w", err)
		}
	}
	if len(metricsJSON) > 0 {
		if err := json.Unmarshal(metricsJSON, &b.Metrics); err != nil {
			return nil, fmt.Errorf("archive: unmarshal brief metrics: %w", err)
		}
	}

	return &b, nil
}

// FetchBriefs returns paginated briefs of a given type.
func (s *Store) FetchBriefs(ctx context.Context, briefType string, limit, offset int) ([]IntelligenceBrief, int64, error) {
	limit = normalizeLimit(limit)
	if offset < 0 {
		offset = 0
	}

	var total int64
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM intelligence_briefs WHERE brief_type = $1`,
		briefType,
	).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("archive: count briefs: %w", err)
	}

	const query = `
	SELECT id, period_start, period_end, brief_type, title, executive_summary,
	       content, sections, metrics, model_used, generation_duration_ms, generated_at
	FROM intelligence_briefs
	WHERE brief_type = $1
	ORDER BY period_end DESC
	LIMIT $2 OFFSET $3`

	rows, err := s.pool.Query(ctx, query, briefType, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("archive: fetch briefs: %w", err)
	}
	defer rows.Close()

	var results []IntelligenceBrief
	for rows.Next() {
		var b IntelligenceBrief
		var sectionsJSON, metricsJSON []byte

		err := rows.Scan(
			&b.ID, &b.PeriodStart, &b.PeriodEnd, &b.BriefType, &b.Title,
			&b.ExecutiveSummary, &b.Content, &sectionsJSON, &metricsJSON,
			&b.ModelUsed, &b.GenerationDurationMs, &b.GeneratedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("archive: scan brief: %w", err)
		}

		if len(sectionsJSON) > 0 {
			if err := json.Unmarshal(sectionsJSON, &b.Sections); err != nil {
				return nil, 0, fmt.Errorf("archive: unmarshal brief sections: %w", err)
			}
		}
		if len(metricsJSON) > 0 {
			if err := json.Unmarshal(metricsJSON, &b.Metrics); err != nil {
				return nil, 0, fmt.Errorf("archive: unmarshal brief metrics: %w", err)
			}
		}

		results = append(results, b)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("archive: fetch briefs rows: %w", err)
	}

	return results, total, nil
}
