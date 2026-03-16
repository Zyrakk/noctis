// Package archive provides a persistence layer for raw content collected from
// threat-intelligence sources. It wraps the raw_content table defined in
// migrations/003_pivot.sql and supports insert-with-dedup, classification
// marking, full-text search, and aggregate statistics.
package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Zyrakk/noctis/internal/models"
)

// RawContent is the archive-specific representation of a collected item.
// It mirrors the raw_content table schema from 003_pivot.sql.
type RawContent struct {
	ID                string
	SourceType        string
	SourceID          string
	SourceName        string
	Content           string
	ContentHash       string
	Author            string
	AuthorID          string
	URL               string
	Language          string
	CollectedAt       time.Time
	PostedAt          *time.Time
	Metadata          map[string]interface{}
	Classified        bool
	Category          string
	Tags              []string
	Severity          string
	Summary           string
	EntitiesExtracted bool
}

// SearchQuery defines the filter parameters for searching the raw content
// archive. Empty/nil fields are ignored when building the query.
type SearchQuery struct {
	Text     string
	Category string
	Tags     []string
	Since    *time.Time
	Author   string
	Limit    int
}

// ArchiveStats holds aggregate counts about the raw content archive.
type ArchiveStats struct {
	TotalCount      int64
	ClassifiedCount int64
	BySource        map[string]int64
	ByCategory      map[string]int64
}

// Store provides CRUD and query operations on the raw_content table.
type Store struct {
	pool *pgxpool.Pool
}

// New creates a new archive Store backed by the given connection pool.
func New(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Insert persists a RawContent record and populates rc.ID with the database-
// generated UUID. Duplicates (identified by content_hash) are not re-written;
// the existing row's ID is returned instead via a cheap index lookup.
func (s *Store) Insert(ctx context.Context, rc *RawContent) error {
	metaJSON, err := json.Marshal(rc.Metadata)
	if err != nil {
		return fmt.Errorf("archive: marshal metadata: %w", err)
	}

	// CTE approach: INSERT ... DO NOTHING RETURNING id for new rows,
	// fall back to SELECT id for existing duplicates. Avoids phantom
	// UPDATE writes, WAL churn, and dead-tuple bloat from self-assignment.
	const query = `
WITH ins AS (
    INSERT INTO raw_content (
        source_type, source_id, source_name, content, content_hash,
        author, author_id, url, language, collected_at, posted_at,
        metadata, classified, category, tags, severity, summary,
        entities_extracted
    ) VALUES (
        $1, $2, $3, $4, $5,
        $6, $7, $8, $9, $10, $11,
        $12, $13, $14, $15, $16, $17,
        $18
    )
    ON CONFLICT (content_hash) DO NOTHING
    RETURNING id
)
SELECT id FROM ins
UNION ALL
SELECT id FROM raw_content WHERE content_hash = $5
LIMIT 1`

	err = s.pool.QueryRow(ctx, query,
		rc.SourceType, rc.SourceID, rc.SourceName, rc.Content, rc.ContentHash,
		rc.Author, rc.AuthorID, rc.URL, rc.Language, rc.CollectedAt, rc.PostedAt,
		metaJSON, rc.Classified, rc.Category, rc.Tags, rc.Severity, rc.Summary,
		rc.EntitiesExtracted,
	).Scan(&rc.ID)
	if err != nil {
		return fmt.Errorf("archive: insert raw_content: %w", err)
	}

	return nil
}

// MarkClassified updates a raw_content record with classification results
// produced by the AI pipeline.
func (s *Store) MarkClassified(ctx context.Context, id string, category string, tags []string, severity string, summary string) error {
	const query = `
UPDATE raw_content
SET classified = true, category = $2, tags = $3, severity = $4, summary = $5
WHERE id = $1`

	ct, err := s.pool.Exec(ctx, query, id, category, tags, severity, summary)
	if err != nil {
		return fmt.Errorf("archive: mark classified %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("archive: mark classified: no row with id %s", id)
	}
	return nil
}

// MarkEntitiesExtracted flags a record as having had its entities extracted.
func (s *Store) MarkEntitiesExtracted(ctx context.Context, id string) error {
	const query = `UPDATE raw_content SET entities_extracted = true WHERE id = $1`

	ct, err := s.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("archive: mark entities_extracted %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("archive: mark entities_extracted: no row with id %s", id)
	}
	return nil
}

// FetchUnclassified returns up to limit records that have not yet been
// classified, ordered oldest-first (FIFO) for fair processing.
func (s *Store) FetchUnclassified(ctx context.Context, limit int) ([]RawContent, error) {
	const query = `
SELECT id, source_type, source_id, source_name, content, content_hash,
       author, author_id, url, language, collected_at, posted_at,
       metadata, classified, category, tags, severity, summary,
       entities_extracted
FROM raw_content
WHERE classified = false
ORDER BY collected_at ASC
LIMIT $1`

	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch unclassified: %w", err)
	}
	defer rows.Close()

	var results []RawContent
	for rows.Next() {
		rc, err := scanRawContent(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, rc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch unclassified rows: %w", err)
	}

	return results, nil
}

// FetchClassifiedUnextracted returns up to limit records that have been
// classified but not yet had their entities extracted, ordered oldest-first.
func (s *Store) FetchClassifiedUnextracted(ctx context.Context, limit int) ([]RawContent, error) {
	const query = `
SELECT id, source_type, source_id, source_name, content, content_hash,
       author, author_id, url, language, collected_at, posted_at,
       metadata, classified, category, tags, severity, summary,
       entities_extracted
FROM raw_content
WHERE classified = true AND entities_extracted = false
ORDER BY collected_at ASC
LIMIT $1`

	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch classified unextracted: %w", err)
	}
	defer rows.Close()

	var results []RawContent
	for rows.Next() {
		rc, err := scanRawContent(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, rc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch classified unextracted rows: %w", err)
	}

	return results, nil
}

// UpsertIOC inserts an IOC record or increments its sighting count if an IOC
// with the same type and value already exists.
func (s *Store) UpsertIOC(ctx context.Context, iocType, value, iocContext, sourceContentID string) error {
	const query = `
INSERT INTO iocs (type, value, context, source_content_id)
VALUES ($1, $2, $3, $4)
ON CONFLICT (type, value) DO UPDATE
SET sighting_count = iocs.sighting_count + 1,
    last_seen = NOW()`

	_, err := s.pool.Exec(ctx, query, iocType, value, iocContext, sourceContentID)
	if err != nil {
		return fmt.Errorf("archive: upsert ioc (%s, %s): %w", iocType, value, err)
	}
	return nil
}

// Search queries the archive with dynamic filtering. Only non-empty fields in
// the SearchQuery are included in the WHERE clause.
func (s *Store) Search(ctx context.Context, query SearchQuery) ([]RawContent, error) {
	limit := normalizeLimit(query.Limit)

	var (
		conditions []string
		args       []interface{}
		argIdx     int
	)

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if query.Text != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("content ILIKE '%%' || %s || '%%'", p))
		args = append(args, query.Text)
	}
	if query.Category != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("category = %s", p))
		args = append(args, query.Category)
	}
	if len(query.Tags) > 0 {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("tags @> %s", p))
		args = append(args, query.Tags)
	}
	if query.Since != nil {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("collected_at >= %s", p))
		args = append(args, *query.Since)
	}
	if query.Author != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("author ILIKE '%%' || %s || '%%'", p))
		args = append(args, query.Author)
	}

	sql := `
SELECT id, source_type, source_id, source_name, content, content_hash,
       author, author_id, url, language, collected_at, posted_at,
       metadata, classified, category, tags, severity, summary,
       entities_extracted
FROM raw_content`

	if len(conditions) > 0 {
		sql += "\nWHERE " + strings.Join(conditions, " AND ")
	}

	limitP := nextArg()
	sql += fmt.Sprintf("\nORDER BY collected_at DESC\nLIMIT %s", limitP)
	args = append(args, limit)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("archive: search: %w", err)
	}
	defer rows.Close()

	var results []RawContent
	for rows.Next() {
		rc, err := scanRawContent(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, rc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: search rows: %w", err)
	}

	return results, nil
}

// Stats returns aggregate counts about the archive.
func (s *Store) Stats(ctx context.Context) (*ArchiveStats, error) {
	stats := &ArchiveStats{
		BySource:   make(map[string]int64),
		ByCategory: make(map[string]int64),
	}

	// Total and classified counts in a single query.
	err := s.pool.QueryRow(ctx, `
SELECT COUNT(*),
       COUNT(*) FILTER (WHERE classified = true)
FROM raw_content`).Scan(&stats.TotalCount, &stats.ClassifiedCount)
	if err != nil {
		return nil, fmt.Errorf("archive: stats totals: %w", err)
	}

	// Counts by source_type.
	rows, err := s.pool.Query(ctx, `
SELECT source_type, COUNT(*) FROM raw_content GROUP BY source_type`)
	if err != nil {
		return nil, fmt.Errorf("archive: stats by source: %w", err)
	}
	for rows.Next() {
		var st string
		var cnt int64
		if err := rows.Scan(&st, &cnt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("archive: stats by source scan: %w", err)
		}
		stats.BySource[st] = cnt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: stats by source rows: %w", err)
	}

	// Counts by category (only classified rows).
	rows, err = s.pool.Query(ctx, `
SELECT category, COUNT(*) FROM raw_content
WHERE classified = true AND category IS NOT NULL
GROUP BY category`)
	if err != nil {
		return nil, fmt.Errorf("archive: stats by category: %w", err)
	}
	for rows.Next() {
		var cat string
		var cnt int64
		if err := rows.Scan(&cat, &cnt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("archive: stats by category scan: %w", err)
		}
		stats.ByCategory[cat] = cnt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: stats by category rows: %w", err)
	}

	return stats, nil
}

// FromFinding converts a models.Finding into a RawContent suitable for
// archiving. It maps the Finding's fields to their archive equivalents.
func FromFinding(f models.Finding) *RawContent {
	rc := &RawContent{
		SourceType:  f.Source,
		SourceID:    f.SourceID,
		SourceName:  f.SourceName,
		Content:     f.Content,
		ContentHash: f.ContentHash,
		Author:      f.Author,
		CollectedAt: f.CollectedAt,
	}

	if !f.Timestamp.IsZero() {
		ts := f.Timestamp
		rc.PostedAt = &ts
	}

	if f.Metadata != nil {
		rc.Metadata = make(map[string]interface{}, len(f.Metadata))
		for k, v := range f.Metadata {
			rc.Metadata[k] = v
		}
	}

	return rc
}

// normalizeLimit clamps the search limit to sane bounds.
func normalizeLimit(limit int) int {
	const (
		defaultLimit = 50
		maxLimit     = 500
	)
	if limit <= 0 {
		return defaultLimit
	}
	if limit > maxLimit {
		return maxLimit
	}
	return limit
}

// scanner is a minimal interface satisfied by pgx.Rows so scanRawContent can
// be used for both Query and QueryRow result sets.
type scanner interface {
	Scan(dest ...interface{}) error
}

// scanRawContent reads a single row into a RawContent struct.
func scanRawContent(row scanner) (RawContent, error) {
	var rc RawContent
	var metaJSON []byte

	err := row.Scan(
		&rc.ID, &rc.SourceType, &rc.SourceID, &rc.SourceName,
		&rc.Content, &rc.ContentHash,
		&rc.Author, &rc.AuthorID, &rc.URL, &rc.Language,
		&rc.CollectedAt, &rc.PostedAt,
		&metaJSON,
		&rc.Classified, &rc.Category, &rc.Tags,
		&rc.Severity, &rc.Summary,
		&rc.EntitiesExtracted,
	)
	if err != nil {
		return RawContent{}, fmt.Errorf("archive: scan raw_content: %w", err)
	}

	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &rc.Metadata); err != nil {
			return RawContent{}, fmt.Errorf("archive: unmarshal metadata: %w", err)
		}
	}

	return rc, nil
}
