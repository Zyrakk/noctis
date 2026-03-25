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
	EntitiesExtracted     bool
	Provenance            string
	ClassificationVersion int
	SubCategory           string
	SubMetadata           map[string]any
	SubClassified         bool
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

// --- Correlation types ---

// SharedIOCResult represents an IOC value found across multiple sources.
type SharedIOCResult struct {
	IOCType     string
	IOCValue    string
	Sources     []string
	FindingIDs  []string
	SourceCount int
}

// HandleReuseResult represents an author handle found across multiple sources.
type HandleReuseResult struct {
	Author      string
	AuthorID    string
	Sources     []string
	SourceIDs   []string
	FindingIDs  []string
	SourceCount int
}

// TemporalOverlapResult represents a pair of findings sharing IOCs within a time window.
type TemporalOverlapResult struct {
	FindingA    string
	FindingB    string
	SourceA     string
	SourceB     string
	SharedIOCs  []string // format: "type:value"
	SharedCount int
}

// EntityClusterResult represents a pair of entities sharing downstream connections.
type EntityClusterResult struct {
	EntityA     string
	NameA       string
	EntityB     string
	NameB       string
	SharedIDs   []string
	SharedNames []string
	SharedCount int
}

// Correlation represents a confirmed correlation stored in the correlations table.
type Correlation struct {
	ID              string
	ClusterID       string
	EntityIDs       []string
	FindingIDs      []string
	CorrelationType string
	Confidence      float64
	Method          string
	Evidence        map[string]interface{}
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// CorrelationCandidate represents a weak correlation candidate.
type CorrelationCandidate struct {
	ID            string
	ClusterID     string
	EntityIDs     []string
	FindingIDs    []string
	CandidateType string
	SignalCount   int
	Signals       map[string]interface{}
	SeenCount     int
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AnalyticalNote represents a note produced by the Brain or Analyst.
type AnalyticalNote struct {
	ID            string    `json:"id"`
	FindingID     *string   `json:"finding_id,omitempty"`
	EntityID      *string   `json:"entity_id,omitempty"`
	CorrelationID *string   `json:"correlation_id,omitempty"`
	IOCType       *string   `json:"ioc_type,omitempty"`
	IOCValue      *string   `json:"ioc_value,omitempty"`
	NoteType      string    `json:"note_type"`
	Title         string    `json:"title"`
	Content       string    `json:"content"`
	Confidence    float64   `json:"confidence"`
	CreatedBy     string    `json:"created_by"`
	ModelUsed     *string   `json:"model_used,omitempty"`
	Status        string    `json:"status"`
	SupersededBy  *string   `json:"superseded_by,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// CorrelationDecision records an Analyst's decision about a correlation candidate.
type CorrelationDecision struct {
	ID                    string         `json:"id"`
	CandidateID           string         `json:"candidate_id"`
	ClusterID             string         `json:"cluster_id"`
	Decision              string         `json:"decision"`
	Confidence            float64        `json:"confidence"`
	Reasoning             string         `json:"reasoning"`
	PromotedCorrelationID *string        `json:"promoted_correlation_id,omitempty"`
	ContextSnapshot       map[string]any `json:"context_snapshot"`
	ModelUsed             *string        `json:"model_used,omitempty"`
	CreatedAt             time.Time      `json:"created_at"`
}

// CorrelationFilter controls filtering for FetchCorrelations.
type CorrelationFilter struct {
	Type          string
	MinConfidence float64
	Since         *time.Time
	Limit         int
	Offset        int
}

// Entity represents a node in the entity graph.
type Entity struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
}

// NeighborEntity represents an adjacent entity in the graph.
type NeighborEntity struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Relationship string `json:"relationship"`
	Direction    string `json:"direction"` // "outgoing" or "incoming"
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
func (s *Store) MarkClassified(ctx context.Context, id string, category string, tags []string, severity string, summary string, provenance string, classificationVersion int) error {
	const query = `
UPDATE raw_content
SET classified = true, category = $2, tags = $3, severity = $4, summary = $5,
    provenance = $6, classification_version = $7
WHERE id = $1`

	ct, err := s.pool.Exec(ctx, query, id, category, tags, severity, summary, provenance, classificationVersion)
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
       entities_extracted, provenance, classification_version,
       sub_category, sub_metadata, sub_classified
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
       entities_extracted, provenance, classification_version,
       sub_category, sub_metadata, sub_classified
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

// ResetOldClassifications resets classification state for entries with a
// classification_version below targetVersion, so background workers will
// reprocess them with the current pipeline version.
func (s *Store) ResetOldClassifications(ctx context.Context, targetVersion int) (int64, error) {
	const query = `
UPDATE raw_content
SET classified = FALSE, entities_extracted = FALSE
WHERE classification_version IS NULL OR classification_version < $1`

	ct, err := s.pool.Exec(ctx, query, targetVersion)
	if err != nil {
		return 0, fmt.Errorf("archive: reset old classifications: %w", err)
	}
	return ct.RowsAffected(), nil
}

// UpsertIOC inserts an IOC record or increments its sighting count if an IOC
// with the same type and value already exists. Also records the sighting in
// ioc_sightings for cross-source correlation.
func (s *Store) UpsertIOC(ctx context.Context, iocType, value, iocContext, sourceContentID string) error {
	const query = `
INSERT INTO iocs (type, value, context, source_content_id, base_score, threat_score, active)
VALUES ($1, $2, $3, $4, 0.5, 0.5, TRUE)
ON CONFLICT (type, value) DO UPDATE
SET sighting_count = iocs.sighting_count + 1,
    last_seen = NOW(),
    active = TRUE,
    deactivated_at = NULL,
    base_score = GREATEST(iocs.base_score, 0.5),
    threat_score = GREATEST(iocs.threat_score, 0.5)`

	_, err := s.pool.Exec(ctx, query, iocType, value, iocContext, sourceContentID)
	if err != nil {
		return fmt.Errorf("archive: upsert ioc (%s, %s): %w", iocType, value, err)
	}

	// Record sighting for cross-source correlation (best-effort).
	const sightingQuery = `
INSERT INTO ioc_sightings (ioc_type, ioc_value, raw_content_id, source_id, source_name)
SELECT $1, $2, $3::uuid, rc.source_id, rc.source_name
FROM raw_content rc WHERE rc.id = $3::uuid
ON CONFLICT (ioc_type, ioc_value, raw_content_id) DO NOTHING`

	_, _ = s.pool.Exec(ctx, sightingQuery, iocType, value, sourceContentID)

	return nil
}

// BackfillIOCSightings populates ioc_sightings from existing IOCs. Each IOC
// has one stored source_content_id, so this creates one sighting per IOC.
// Going forward, UpsertIOC records sightings automatically.
func (s *Store) BackfillIOCSightings(ctx context.Context) (int, error) {
	const query = `
INSERT INTO ioc_sightings (ioc_type, ioc_value, raw_content_id, source_id, source_name)
SELECT i.type, i.value, i.source_content_id, rc.source_id, rc.source_name
FROM iocs i
JOIN raw_content rc ON rc.id = i.source_content_id
WHERE i.source_content_id IS NOT NULL
ON CONFLICT (ioc_type, ioc_value, raw_content_id) DO NOTHING`

	ct, err := s.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("archive: backfill ioc sightings: %w", err)
	}
	return int(ct.RowsAffected()), nil
}

// CleanupAssociatedWithEdges remaps associated_with edges to referenced_in
// when both source and target entities are non-observed. This corrects edges
// created before the stricter relationship rules were enforced.
func (s *Store) CleanupAssociatedWithEdges(ctx context.Context) (int64, error) {
	const query = `
UPDATE edges SET relationship = 'referenced_in'
WHERE relationship = 'associated_with'
AND source_id IN (SELECT id FROM entities WHERE properties->>'observed' IS NULL OR properties->>'observed' = 'false')
AND target_id IN (SELECT id FROM entities WHERE properties->>'observed' IS NULL OR properties->>'observed' = 'false')`

	ct, err := s.pool.Exec(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("archive: cleanup associated_with edges: %w", err)
	}
	return ct.RowsAffected(), nil
}

// FindSharedIOCs finds IOC values that appear in findings from multiple distinct sources.
func (s *Store) FindSharedIOCs(ctx context.Context, minSources int) ([]SharedIOCResult, error) {
	const query = `
SELECT s.ioc_type, s.ioc_value,
       array_agg(DISTINCT s.source_name) AS sources,
       array_agg(DISTINCT s.raw_content_id::text) AS finding_ids,
       COUNT(DISTINCT s.source_id) AS source_count
FROM ioc_sightings s
JOIN raw_content rc ON rc.id = s.raw_content_id
WHERE rc.classified = true
  AND rc.category != 'irrelevant'
  AND rc.provenance = 'first_party'
GROUP BY s.ioc_type, s.ioc_value
HAVING COUNT(DISTINCT s.source_id) >= $1`

	rows, err := s.pool.Query(ctx, query, minSources)
	if err != nil {
		return nil, fmt.Errorf("archive: find shared iocs: %w", err)
	}
	defer rows.Close()

	var results []SharedIOCResult
	for rows.Next() {
		var r SharedIOCResult
		if err := rows.Scan(&r.IOCType, &r.IOCValue, &r.Sources, &r.FindingIDs, &r.SourceCount); err != nil {
			return nil, fmt.Errorf("archive: scan shared ioc: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: find shared iocs rows: %w", err)
	}

	return results, nil
}

// FindHandleReuse finds author handles that appear across multiple distinct sources.
func (s *Store) FindHandleReuse(ctx context.Context, minSources int) ([]HandleReuseResult, error) {
	const query = `
SELECT author, COALESCE(author_id, ''),
       array_agg(DISTINCT source_name) AS sources,
       array_agg(DISTINCT source_id) AS source_ids,
       array_agg(DISTINCT id::text) AS finding_ids,
       COUNT(DISTINCT source_id) AS source_count
FROM raw_content
WHERE classified = true
  AND category != 'irrelevant'
  AND provenance = 'first_party'
  AND author != '' AND author IS NOT NULL
GROUP BY author, author_id
HAVING COUNT(DISTINCT source_id) >= $1`

	rows, err := s.pool.Query(ctx, query, minSources)
	if err != nil {
		return nil, fmt.Errorf("archive: find handle reuse: %w", err)
	}
	defer rows.Close()

	var results []HandleReuseResult
	for rows.Next() {
		var r HandleReuseResult
		if err := rows.Scan(&r.Author, &r.AuthorID, &r.Sources, &r.SourceIDs, &r.FindingIDs, &r.SourceCount); err != nil {
			return nil, fmt.Errorf("archive: scan handle reuse: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: find handle reuse rows: %w", err)
	}

	return results, nil
}

// FindTemporalIOCOverlap finds pairs of findings from different sources that were
// collected within a time window and share multiple IOCs.
func (s *Store) FindTemporalIOCOverlap(ctx context.Context, windowHours int, minSharedIOCs int) ([]TemporalOverlapResult, error) {
	const query = `
WITH finding_iocs AS (
    SELECT s.raw_content_id AS finding_id, rc.source_id, rc.source_name, rc.collected_at,
           s.ioc_type, s.ioc_value
    FROM ioc_sightings s
    JOIN raw_content rc ON rc.id = s.raw_content_id
    WHERE rc.classified = true
      AND rc.category != 'irrelevant'
      AND rc.provenance = 'first_party'
      AND rc.collected_at > NOW() - make_interval(hours => $1)
)
SELECT a.finding_id::text AS finding_a, b.finding_id::text AS finding_b,
       a.source_name AS source_a, b.source_name AS source_b,
       array_agg(DISTINCT a.ioc_type || ':' || a.ioc_value) AS shared_iocs,
       COUNT(DISTINCT a.ioc_type || ':' || a.ioc_value) AS shared_count
FROM finding_iocs a
JOIN finding_iocs b ON a.ioc_value = b.ioc_value
                    AND a.ioc_type = b.ioc_type
                    AND a.source_id != b.source_id
                    AND a.finding_id < b.finding_id
                    AND ABS(EXTRACT(EPOCH FROM a.collected_at - b.collected_at)) <= $1 * 3600
GROUP BY a.finding_id, b.finding_id, a.source_name, b.source_name
HAVING COUNT(DISTINCT a.ioc_type || ':' || a.ioc_value) >= $2`

	rows, err := s.pool.Query(ctx, query, windowHours, minSharedIOCs)
	if err != nil {
		return nil, fmt.Errorf("archive: find temporal ioc overlap: %w", err)
	}
	defer rows.Close()

	var results []TemporalOverlapResult
	for rows.Next() {
		var r TemporalOverlapResult
		if err := rows.Scan(&r.FindingA, &r.FindingB, &r.SourceA, &r.SourceB, &r.SharedIOCs, &r.SharedCount); err != nil {
			return nil, fmt.Errorf("archive: scan temporal overlap: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: find temporal overlap rows: %w", err)
	}

	return results, nil
}

// FindEntityClusters finds entities of a given type that share connections to
// the same downstream entities (e.g., actors using the same malware, malware
// connecting to the same C2).
func (s *Store) FindEntityClusters(ctx context.Context, entityType string, minConnections int) ([]EntityClusterResult, error) {
	const query = `
SELECT e1.id AS entity_a, COALESCE(e1.properties->>'name', e1.id) AS name_a,
       e2.id AS entity_b, COALESCE(e2.properties->>'name', e2.id) AS name_b,
       array_agg(DISTINCT shared.id) AS shared_entity_ids,
       array_agg(DISTINCT COALESCE(shared.properties->>'name', shared.id)) AS shared_names,
       COUNT(DISTINCT shared.id) AS shared_count
FROM entities e1
JOIN edges edge1 ON edge1.source_id = e1.id
JOIN edges edge2 ON edge2.target_id = edge1.target_id AND edge2.source_id != e1.id
JOIN entities e2 ON e2.id = edge2.source_id AND e2.type = e1.type
JOIN entities shared ON shared.id = edge1.target_id
WHERE e1.type = $1
  AND e1.id < e2.id
GROUP BY e1.id, e1.properties->>'name', e2.id, e2.properties->>'name'
HAVING COUNT(DISTINCT shared.id) >= $2`

	rows, err := s.pool.Query(ctx, query, entityType, minConnections)
	if err != nil {
		return nil, fmt.Errorf("archive: find entity clusters: %w", err)
	}
	defer rows.Close()

	var results []EntityClusterResult
	for rows.Next() {
		var r EntityClusterResult
		if err := rows.Scan(&r.EntityA, &r.NameA, &r.EntityB, &r.NameB, &r.SharedIDs, &r.SharedNames, &r.SharedCount); err != nil {
			return nil, fmt.Errorf("archive: scan entity cluster: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: find entity clusters rows: %w", err)
	}

	return results, nil
}

// UpsertCorrelation inserts a correlation or updates it if the same cluster_id exists.
func (s *Store) UpsertCorrelation(ctx context.Context, c *Correlation) error {
	evidenceJSON, err := json.Marshal(c.Evidence)
	if err != nil {
		return fmt.Errorf("archive: marshal correlation evidence: %w", err)
	}

	findingIDs := c.FindingIDs
	if findingIDs == nil {
		findingIDs = []string{}
	}

	const query = `
INSERT INTO correlations (cluster_id, entity_ids, finding_ids, correlation_type, confidence, method, evidence)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (cluster_id) DO UPDATE
SET entity_ids = $2, finding_ids = $3, confidence = $5, evidence = $7, updated_at = NOW()`

	_, err = s.pool.Exec(ctx, query, c.ClusterID, c.EntityIDs, findingIDs, c.CorrelationType, c.Confidence, c.Method, evidenceJSON)
	if err != nil {
		return fmt.Errorf("archive: upsert correlation: %w", err)
	}
	return nil
}

// UpsertCandidate inserts a correlation candidate or increments seen_count if
// the same cluster_id exists.
func (s *Store) UpsertCandidate(ctx context.Context, c *CorrelationCandidate) error {
	signalsJSON, err := json.Marshal(c.Signals)
	if err != nil {
		return fmt.Errorf("archive: marshal candidate signals: %w", err)
	}

	findingIDs := c.FindingIDs
	if findingIDs == nil {
		findingIDs = []string{}
	}

	const query = `
INSERT INTO correlation_candidates (cluster_id, entity_ids, finding_ids, candidate_type, signal_count, signals)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (cluster_id) DO UPDATE
SET signal_count = $5, signals = $6, seen_count = correlation_candidates.seen_count + 1, updated_at = NOW()`

	_, err = s.pool.Exec(ctx, query, c.ClusterID, c.EntityIDs, findingIDs, c.CandidateType, c.SignalCount, signalsJSON)
	if err != nil {
		return fmt.Errorf("archive: upsert candidate: %w", err)
	}
	return nil
}

// FetchCorrelations queries correlations with optional filtering.
func (s *Store) FetchCorrelations(ctx context.Context, filter CorrelationFilter) ([]Correlation, error) {
	limit := normalizeLimit(filter.Limit)

	var (
		conditions []string
		args       []interface{}
		argIdx     int
	)

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if filter.Type != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("correlation_type = %s", p))
		args = append(args, filter.Type)
	}
	if filter.MinConfidence > 0 {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("confidence >= %s", p))
		args = append(args, filter.MinConfidence)
	}
	if filter.Since != nil {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("created_at >= %s", p))
		args = append(args, *filter.Since)
	}

	sql := `
SELECT id, cluster_id, entity_ids, finding_ids, correlation_type,
       confidence, method, evidence, created_at, updated_at
FROM correlations`

	if len(conditions) > 0 {
		sql += "\nWHERE " + strings.Join(conditions, " AND ")
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql += fmt.Sprintf("\nORDER BY created_at DESC\nLIMIT %s OFFSET %s", limitP, offsetP)

	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch correlations: %w", err)
	}
	defer rows.Close()

	var results []Correlation
	for rows.Next() {
		var c Correlation
		var evidenceJSON []byte
		err := rows.Scan(
			&c.ID, &c.ClusterID, &c.EntityIDs, &c.FindingIDs,
			&c.CorrelationType, &c.Confidence, &c.Method,
			&evidenceJSON, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("archive: scan correlation: %w", err)
		}
		if len(evidenceJSON) > 0 {
			if err := json.Unmarshal(evidenceJSON, &c.Evidence); err != nil {
				return nil, fmt.Errorf("archive: unmarshal correlation evidence: %w", err)
			}
		}
		results = append(results, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch correlations rows: %w", err)
	}

	return results, nil
}

// UpsertEntity inserts an entity or updates its properties if it already exists.
func (s *Store) UpsertEntity(ctx context.Context, id, entityType string, properties map[string]interface{}) error {
	propsJSON, err := json.Marshal(properties)
	if err != nil {
		return fmt.Errorf("archive: marshal entity properties: %w", err)
	}

	const query = `
INSERT INTO entities (id, type, properties)
VALUES ($1, $2, $3)
ON CONFLICT (id) DO UPDATE
SET properties = entities.properties || $3,
    updated_at = NOW()`

	_, err = s.pool.Exec(ctx, query, id, entityType, propsJSON)
	if err != nil {
		return fmt.Errorf("archive: upsert entity (%s): %w", id, err)
	}
	return nil
}

// UpsertEdge inserts an edge or ignores if it already exists.
func (s *Store) UpsertEdge(ctx context.Context, id, sourceID, targetID, relationship string) error {
	const query = `
INSERT INTO edges (id, source_id, target_id, relationship)
VALUES ($1, $2, $3, $4)
ON CONFLICT (id) DO NOTHING`

	_, err := s.pool.Exec(ctx, query, id, sourceID, targetID, relationship)
	if err != nil {
		return fmt.Errorf("archive: upsert edge (%s -> %s): %w", sourceID, targetID, err)
	}
	return nil
}

// BackfillEntitiesFromIOCs creates entities and edges from existing IOCs that
// don't yet have corresponding entities in the graph. Returns the number of
// entities created.
func (s *Store) BackfillEntitiesFromIOCs(ctx context.Context) (int, error) {
	// Find IOCs that don't have a corresponding entity yet.
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT i.type, i.value, i.context, rc.source_name, rc.source_type
		FROM iocs i
		JOIN raw_content rc ON rc.id = i.source_content_id
		WHERE NOT EXISTS (
			SELECT 1 FROM entities WHERE id = 'ioc:' || i.type || ':' || i.value
		)
		LIMIT 5000`)
	if err != nil {
		return 0, fmt.Errorf("archive: backfill query: %w", err)
	}
	defer rows.Close()

	type iocRow struct {
		iocType, value, iocContext, sourceName, sourceType string
	}
	var toBackfill []iocRow
	for rows.Next() {
		var r iocRow
		if err := rows.Scan(&r.iocType, &r.value, &r.iocContext, &r.sourceName, &r.sourceType); err != nil {
			return 0, fmt.Errorf("archive: backfill scan: %w", err)
		}
		toBackfill = append(toBackfill, r)
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("archive: backfill rows: %w", err)
	}

	count := 0
	for _, r := range toBackfill {
		// IOC entity type mapping.
		entityType := r.iocType
		switch r.iocType {
		case "hash_md5", "hash_sha1", "hash_sha256":
			entityType = "hash"
		}

		entityID := fmt.Sprintf("ioc:%s:%s", r.iocType, r.value)
		props := map[string]interface{}{"value": r.value}
		if r.iocContext != "" {
			props["context"] = r.iocContext
		}

		if err := s.UpsertEntity(ctx, entityID, entityType, props); err != nil {
			continue
		}

		// Source entity.
		sourceEntityID := fmt.Sprintf("source:%s", r.sourceName)
		sourceProps := map[string]interface{}{
			"name":        r.sourceName,
			"source_type": r.sourceType,
		}
		s.UpsertEntity(ctx, sourceEntityID, "channel", sourceProps)

		// Edge.
		edgeID := fmt.Sprintf("edge:%s:%s:found_in", entityID, sourceEntityID)
		s.UpsertEdge(ctx, edgeID, entityID, sourceEntityID, "found_in")

		count++
	}

	return count, nil
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
       entities_extracted, provenance, classification_version,
       sub_category, sub_metadata, sub_classified
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
	var subMetaJSON []byte

	// Nullable TEXT columns use *string scan targets so NULL becomes ""
	// instead of a scan error. sub_category is NULL for all rows not yet
	// sub-classified; the others are nullable per schema even though
	// current INSERT paths always write empty strings.
	var author, authorID, url, language *string
	var category, severity, summary *string
	var provenance, subCategory *string

	err := row.Scan(
		&rc.ID, &rc.SourceType, &rc.SourceID, &rc.SourceName,
		&rc.Content, &rc.ContentHash,
		&author, &authorID, &url, &language,
		&rc.CollectedAt, &rc.PostedAt,
		&metaJSON,
		&rc.Classified, &category, &rc.Tags,
		&severity, &summary,
		&rc.EntitiesExtracted,
		&provenance, &rc.ClassificationVersion,
		&subCategory, &subMetaJSON, &rc.SubClassified,
	)
	if err != nil {
		return RawContent{}, fmt.Errorf("archive: scan raw_content: %w", err)
	}

	if author != nil {
		rc.Author = *author
	}
	if authorID != nil {
		rc.AuthorID = *authorID
	}
	if url != nil {
		rc.URL = *url
	}
	if language != nil {
		rc.Language = *language
	}
	if category != nil {
		rc.Category = *category
	}
	if severity != nil {
		rc.Severity = *severity
	}
	if summary != nil {
		rc.Summary = *summary
	}
	if provenance != nil {
		rc.Provenance = *provenance
	}
	if subCategory != nil {
		rc.SubCategory = *subCategory
	}

	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &rc.Metadata); err != nil {
			return RawContent{}, fmt.Errorf("archive: unmarshal metadata: %w", err)
		}
	}
	if len(subMetaJSON) > 0 {
		if err := json.Unmarshal(subMetaJSON, &rc.SubMetadata); err != nil {
			return RawContent{}, fmt.Errorf("archive: unmarshal sub_metadata: %w", err)
		}
	}

	return rc, nil
}

// ---------------------------------------------------------------------------
// Sub-classification (Librarian)
// ---------------------------------------------------------------------------

// FetchUnsubclassified returns classified + entity-extracted items that haven't
// been sub-classified yet, ordered oldest first.
func (s *Store) FetchUnsubclassified(ctx context.Context, limit int) ([]RawContent, error) {
	const query = `
SELECT id, source_type, source_id, source_name, content, content_hash,
       author, author_id, url, language, collected_at, posted_at,
       metadata, classified, category, tags, severity, summary,
       entities_extracted, provenance, classification_version,
       sub_category, sub_metadata, sub_classified
FROM raw_content
WHERE classified = TRUE
  AND entities_extracted = TRUE
  AND sub_classified = FALSE
  AND category IS NOT NULL
  AND category != 'irrelevant'
ORDER BY collected_at ASC
LIMIT $1`

	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch unsubclassified: %w", err)
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
		return nil, fmt.Errorf("archive: fetch unsubclassified rows: %w", err)
	}

	return results, nil
}

// MarkSubClassified updates a raw_content record with Librarian results.
func (s *Store) MarkSubClassified(ctx context.Context, id string, subCategory string, subMetadata map[string]any) error {
	metaJSON, err := json.Marshal(subMetadata)
	if err != nil {
		return fmt.Errorf("archive: marshal sub_metadata: %w", err)
	}
	const query = `
UPDATE raw_content
SET sub_classified = true, sub_category = $2, sub_metadata = $3
WHERE id = $1`

	ct, err := s.pool.Exec(ctx, query, id, subCategory, metaJSON)
	if err != nil {
		return fmt.Errorf("archive: mark sub_classified %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("archive: mark sub_classified: no row with id %s", id)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Analytical Notes (Brain memory)
// ---------------------------------------------------------------------------

// InsertAnalyticalNote stores a new analytical note.
func (s *Store) InsertAnalyticalNote(ctx context.Context, note *AnalyticalNote) error {
	const query = `
INSERT INTO analytical_notes (
    finding_id, entity_id, correlation_id, ioc_type, ioc_value,
    note_type, title, content, confidence,
    created_by, model_used, status
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id, created_at`

	return s.pool.QueryRow(ctx, query,
		note.FindingID, note.EntityID, note.CorrelationID, note.IOCType, note.IOCValue,
		note.NoteType, note.Title, note.Content, note.Confidence,
		note.CreatedBy, note.ModelUsed, note.Status,
	).Scan(&note.ID, &note.CreatedAt)
}

// FetchAnalyticalNotesForEntity returns active notes relevant to an entity.
func (s *Store) FetchAnalyticalNotesForEntity(ctx context.Context, entityID string, limit int) ([]AnalyticalNote, error) {
	const query = `
SELECT id, finding_id, entity_id, correlation_id, ioc_type, ioc_value,
       note_type, title, content, confidence, created_by, model_used,
       status, created_at, updated_at
FROM analytical_notes
WHERE entity_id = $1 AND status = 'active'
ORDER BY created_at DESC
LIMIT $2`

	rows, err := s.pool.Query(ctx, query, entityID, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch notes for entity %s: %w", entityID, err)
	}
	defer rows.Close()

	var results []AnalyticalNote
	for rows.Next() {
		n, err := scanAnalyticalNote(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch notes for entity rows: %w", err)
	}
	return results, nil
}

// FetchRecentAnalyticalNotes returns the most recent active notes.
func (s *Store) FetchRecentAnalyticalNotes(ctx context.Context, limit int) ([]AnalyticalNote, error) {
	const query = `
SELECT id, finding_id, entity_id, correlation_id, ioc_type, ioc_value,
       note_type, title, content, confidence, created_by, model_used,
       status, created_at, updated_at
FROM analytical_notes
WHERE status = 'active'
ORDER BY created_at DESC
LIMIT $1`

	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch recent notes: %w", err)
	}
	defer rows.Close()

	var results []AnalyticalNote
	for rows.Next() {
		n, err := scanAnalyticalNote(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch recent notes rows: %w", err)
	}
	return results, nil
}

// FetchNotesForCorrelationContext returns notes relevant to a set of entity IDs,
// for feeding into the Analyst's prompt as context.
func (s *Store) FetchNotesForCorrelationContext(ctx context.Context, entityIDs []string) ([]AnalyticalNote, error) {
	const query = `
SELECT id, finding_id, entity_id, correlation_id, ioc_type, ioc_value,
       note_type, title, content, confidence, created_by, model_used,
       status, created_at, updated_at
FROM analytical_notes
WHERE entity_id = ANY($1) AND status = 'active'
ORDER BY created_at DESC
LIMIT 20`

	rows, err := s.pool.Query(ctx, query, entityIDs)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch notes for correlation context: %w", err)
	}
	defer rows.Close()

	var results []AnalyticalNote
	for rows.Next() {
		n, err := scanAnalyticalNote(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch notes for correlation context rows: %w", err)
	}
	return results, nil
}

// scanAnalyticalNote reads a single row into an AnalyticalNote struct.
func scanAnalyticalNote(row scanner) (AnalyticalNote, error) {
	var n AnalyticalNote
	err := row.Scan(
		&n.ID, &n.FindingID, &n.EntityID, &n.CorrelationID,
		&n.IOCType, &n.IOCValue,
		&n.NoteType, &n.Title, &n.Content, &n.Confidence,
		&n.CreatedBy, &n.ModelUsed,
		&n.Status, &n.CreatedAt, &n.UpdatedAt,
	)
	if err != nil {
		return AnalyticalNote{}, fmt.Errorf("archive: scan analytical_note: %w", err)
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// Correlation Decisions (Analyst audit trail)
// ---------------------------------------------------------------------------

// InsertCorrelationDecision logs an Analyst decision about a candidate.
func (s *Store) InsertCorrelationDecision(ctx context.Context, d *CorrelationDecision) error {
	snapshotJSON, err := json.Marshal(d.ContextSnapshot)
	if err != nil {
		return fmt.Errorf("archive: marshal context_snapshot: %w", err)
	}
	const query = `
INSERT INTO correlation_decisions (
    candidate_id, cluster_id, decision, confidence, reasoning,
    promoted_correlation_id, context_snapshot, model_used
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, created_at`

	return s.pool.QueryRow(ctx, query,
		d.CandidateID, d.ClusterID, d.Decision, d.Confidence, d.Reasoning,
		d.PromotedCorrelationID, snapshotJSON, d.ModelUsed,
	).Scan(&d.ID, &d.CreatedAt)
}

// UpdateCandidateStatus updates the status of a correlation candidate.
func (s *Store) UpdateCandidateStatus(ctx context.Context, id string, status string) error {
	const query = `UPDATE correlation_candidates SET status = $2, updated_at = NOW() WHERE id = $1`
	_, err := s.pool.Exec(ctx, query, id, status)
	if err != nil {
		return fmt.Errorf("archive: update candidate status %s: %w", id, err)
	}
	return nil
}

// FetchPendingCandidates returns correlation candidates that haven't been
// evaluated by the Analyst, ordered by signal strength.
func (s *Store) FetchPendingCandidates(ctx context.Context, limit int) ([]CorrelationCandidate, error) {
	const query = `
SELECT id, cluster_id, entity_ids, finding_ids, candidate_type,
       signal_count, signals, seen_count, status, created_at, updated_at
FROM correlation_candidates
WHERE status = 'pending'
ORDER BY signal_count DESC, created_at ASC
LIMIT $1`

	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch pending candidates: %w", err)
	}
	defer rows.Close()

	var results []CorrelationCandidate
	for rows.Next() {
		var c CorrelationCandidate
		var signalsJSON []byte
		err := rows.Scan(
			&c.ID, &c.ClusterID, &c.EntityIDs, &c.FindingIDs,
			&c.CandidateType, &c.SignalCount, &signalsJSON,
			&c.SeenCount, &c.Status, &c.CreatedAt, &c.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("archive: scan pending candidate: %w", err)
		}
		if len(signalsJSON) > 0 {
			if err := json.Unmarshal(signalsJSON, &c.Signals); err != nil {
				return nil, fmt.Errorf("archive: unmarshal candidate signals: %w", err)
			}
		}
		results = append(results, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch pending candidates rows: %w", err)
	}
	return results, nil
}

// ---------------------------------------------------------------------------
// Finding context lookups (for Librarian sub-classification)
// ---------------------------------------------------------------------------

// FetchEntityNamesForFinding returns entity names linked to a finding via
// IOC sightings and graph edges.
func (s *Store) FetchEntityNamesForFinding(ctx context.Context, findingID string) ([]string, error) {
	const query = `
SELECT DISTINCT name FROM (
    -- IOC entities linked via sightings
    SELECT COALESCE(e.properties->>'value', e.properties->>'name', e.id) AS name
    FROM ioc_sightings s
    JOIN entities e ON e.id = 'ioc:' || s.ioc_type || ':' || s.ioc_value
    WHERE s.raw_content_id = $1::uuid
    UNION
    -- Named entities mentioned in the same source
    SELECT COALESCE(e.properties->>'name', e.id) AS name
    FROM entities e
    JOIN edges edge ON edge.source_id = e.id
    JOIN raw_content rc ON edge.target_id = 'source:' || rc.source_name AND rc.id = $1::uuid
    WHERE e.type NOT IN ('channel')
) sub
LIMIT 50`

	rows, err := s.pool.Query(ctx, query, findingID)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch entity names for finding %s: %w", findingID, err)
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("archive: scan entity name: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch entity names rows: %w", err)
	}
	return names, nil
}

// FetchIOCValuesForFinding returns IOC "type:value" strings linked to a finding.
func (s *Store) FetchIOCValuesForFinding(ctx context.Context, findingID string) ([]string, error) {
	const query = `
SELECT DISTINCT ioc_type || ':' || ioc_value
FROM ioc_sightings
WHERE raw_content_id = $1::uuid
ORDER BY 1
LIMIT 50`

	rows, err := s.pool.Query(ctx, query, findingID)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch ioc values for finding %s: %w", findingID, err)
	}
	defer rows.Close()

	var values []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("archive: scan ioc value: %w", err)
		}
		values = append(values, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch ioc values rows: %w", err)
	}
	return values, nil
}

// ---------------------------------------------------------------------------
// Single-record lookups (for Analyst context building)
// ---------------------------------------------------------------------------

// FetchRawContentByID returns a single raw_content record by UUID.
func (s *Store) FetchRawContentByID(ctx context.Context, id string) (*RawContent, error) {
	const query = `
SELECT id, source_type, source_id, source_name, content, content_hash,
       author, author_id, url, language, collected_at, posted_at,
       metadata, classified, category, tags, severity, summary,
       entities_extracted, provenance, classification_version,
       sub_category, sub_metadata, sub_classified
FROM raw_content
WHERE id = $1`

	rc, err := scanRawContent(s.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("archive: fetch raw_content by id %s: %w", id, err)
	}
	return &rc, nil
}

// FetchEntityByID returns a single entity from the graph.
func (s *Store) FetchEntityByID(ctx context.Context, entityID string) (*Entity, error) {
	const query = `SELECT id, type, properties FROM entities WHERE id = $1`

	var e Entity
	var propsJSON []byte
	err := s.pool.QueryRow(ctx, query, entityID).Scan(&e.ID, &e.Type, &propsJSON)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch entity %s: %w", entityID, err)
	}
	if len(propsJSON) > 0 {
		if err := json.Unmarshal(propsJSON, &e.Properties); err != nil {
			return nil, fmt.Errorf("archive: unmarshal entity properties: %w", err)
		}
	}
	return &e, nil
}

// FetchEntityNeighbors returns entities connected to entityID within the given
// number of hops. Currently supports 1-hop only.
func (s *Store) FetchEntityNeighbors(ctx context.Context, entityID string, _ int) ([]NeighborEntity, error) {
	const query = `
SELECT e.id, e.type, edge.relationship, 'outgoing'
FROM edges edge
JOIN entities e ON e.id = edge.target_id
WHERE edge.source_id = $1
UNION ALL
SELECT e.id, e.type, edge.relationship, 'incoming'
FROM edges edge
JOIN entities e ON e.id = edge.source_id
WHERE edge.target_id = $1
LIMIT 30`

	rows, err := s.pool.Query(ctx, query, entityID)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch neighbors for %s: %w", entityID, err)
	}
	defer rows.Close()

	var neighbors []NeighborEntity
	for rows.Next() {
		var n NeighborEntity
		if err := rows.Scan(&n.ID, &n.Type, &n.Relationship, &n.Direction); err != nil {
			return nil, fmt.Errorf("archive: scan neighbor: %w", err)
		}
		neighbors = append(neighbors, n)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch neighbors rows: %w", err)
	}
	return neighbors, nil
}

// Pool returns the underlying connection pool for transaction use.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// IOCForEnrichment holds the IOC fields needed by the enrichment pipeline.
type IOCForEnrichment struct {
	ID          string
	Type        string
	Value       string
	Context     string
	FirstSeen   time.Time
	ThreatScore float64
	BaseScore   float64
}

// FetchUnenrichedIOCs returns active IOCs that haven't been enriched yet.
func (s *Store) FetchUnenrichedIOCs(ctx context.Context, limit int) ([]IOCForEnrichment, error) {
	if limit <= 0 {
		limit = 20
	}
	const query = `
	SELECT id, type, value, COALESCE(context, ''), first_seen,
	       COALESCE(threat_score, 0.5), COALESCE(base_score, 0.5)
	FROM iocs
	WHERE active = TRUE AND enriched_at IS NULL
	ORDER BY first_seen ASC
	LIMIT $1`

	rows, err := s.pool.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("archive: fetch unenriched iocs: %w", err)
	}
	defer rows.Close()

	var results []IOCForEnrichment
	for rows.Next() {
		var ioc IOCForEnrichment
		if err := rows.Scan(&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Context,
			&ioc.FirstSeen, &ioc.ThreatScore, &ioc.BaseScore); err != nil {
			return nil, fmt.Errorf("archive: scan unenriched ioc: %w", err)
		}
		results = append(results, ioc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("archive: fetch unenriched iocs rows: %w", err)
	}
	return results, nil
}

// MarkIOCEnriched stores enrichment results for an IOC.
func (s *Store) MarkIOCEnriched(ctx context.Context, iocType, value string, enrichment map[string]any, sources []string, newBaseScore float64) error {
	enrichJSON, err := json.Marshal(enrichment)
	if err != nil {
		return fmt.Errorf("archive: marshal enrichment: %w", err)
	}
	const query = `
	UPDATE iocs
	SET enrichment = $3, enriched_at = NOW(), enrichment_sources = $4,
	    base_score = GREATEST(base_score, $5), threat_score = GREATEST(threat_score, $5)
	WHERE type = $1 AND value = $2`
	_, err = s.pool.Exec(ctx, query, iocType, value, enrichJSON, sources, newBaseScore)
	if err != nil {
		return fmt.Errorf("archive: mark ioc enriched (%s, %s): %w", iocType, value, err)
	}
	return nil
}
