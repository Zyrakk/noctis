package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// --- Response types ---

// StatsResponse holds aggregate counts for the overview dashboard.
type StatsResponse struct {
	TotalContent   int64            `json:"totalContent"`
	Classified     int64            `json:"classified"`
	TotalIOCs      int64            `json:"totalIocs"`
	ActiveSources  int64            `json:"activeSources"`
	DiscoveredSrc  int64            `json:"discoveredSources"`
	PausedSources  int64            `json:"pausedSources"`
	BySource       map[string]int64 `json:"bySource"`
	BySeverity     map[string]int64 `json:"bySeverity"`
}

// FindingSummary is a compact representation for list views.
type FindingSummary struct {
	ID          string         `json:"id"`
	SourceType  string         `json:"sourceType"`
	SourceName  string         `json:"sourceName"`
	Category    *string        `json:"category"`
	SubCategory *string        `json:"subCategory,omitempty"`
	Severity    *string        `json:"severity"`
	Summary     *string        `json:"summary"`
	Author      *string        `json:"author"`
	CollectedAt time.Time      `json:"collectedAt"`
	PostedAt    *time.Time     `json:"postedAt"`
	SubMetadata map[string]any `json:"subMetadata,omitempty"`
}

// FindingsResponse wraps paginated findings.
type FindingsResponse struct {
	Findings []FindingSummary `json:"findings"`
	Total    int64            `json:"total"`
}

// FindingDetail is a full finding with content and linked IOCs.
type FindingDetail struct {
	FindingSummary
	Content  string    `json:"content"`
	URL      *string   `json:"url"`
	Tags     []string  `json:"tags"`
	IOCs     []IOCItem `json:"iocs"`
	Metadata any       `json:"metadata"`
}

// IOCItem represents an indicator of compromise.
type IOCItem struct {
	ID                string         `json:"id"`
	Type              string         `json:"type"`
	Value             string         `json:"value"`
	Context           *string        `json:"context"`
	FirstSeen         time.Time      `json:"firstSeen"`
	LastSeen          time.Time      `json:"lastSeen"`
	SightingCount     int            `json:"sightingCount"`
	ThreatScore       *float64       `json:"threatScore,omitempty"`
	Active            bool           `json:"active"`
	Enrichment        map[string]any `json:"enrichment,omitempty"`
	EnrichedAt        *time.Time     `json:"enrichedAt,omitempty"`
	EnrichmentSources []string       `json:"enrichmentSources,omitempty"`
}

// IOCsResponse wraps paginated IOCs.
type IOCsResponse struct {
	IOCs  []IOCItem `json:"iocs"`
	Total int64     `json:"total"`
}

// SourceItem represents a source in API responses.
type SourceItem struct {
	ID                 string     `json:"id"`
	Type               string     `json:"type"`
	Identifier         string     `json:"identifier"`
	Name               *string    `json:"name"`
	Status             string     `json:"status"`
	LastCollected      *time.Time `json:"lastCollected"`
	ErrorCount         int        `json:"errorCount"`
	CreatedAt          time.Time  `json:"createdAt"`
	ContentCount       int64      `json:"contentCount"`
}

// CategoryCount holds a category name and its count.
type CategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// TimelinePoint holds a time bucket and its count.
type TimelinePoint struct {
	Bucket time.Time `json:"bucket"`
	Count  int64     `json:"count"`
}

// GraphNode represents a node in the entity graph.
type GraphNode struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
}

// GraphEdge represents an edge in the entity graph.
type GraphEdge struct {
	Source       string `json:"source"`
	Target       string `json:"target"`
	Relationship string `json:"relationship"`
}

// GraphResponse holds the graph traversal result.
type GraphResponse struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// --- Query functions ---

func queryStats(ctx context.Context, pool *pgxpool.Pool) (*StatsResponse, error) {
	stats := &StatsResponse{
		BySource:   make(map[string]int64),
		BySeverity: make(map[string]int64),
	}

	// Content totals
	err := pool.QueryRow(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE classified = true)
		FROM raw_content`).Scan(&stats.TotalContent, &stats.Classified)
	if err != nil {
		return nil, fmt.Errorf("stats: content totals: %w", err)
	}

	// IOC total
	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM iocs`).Scan(&stats.TotalIOCs)
	if err != nil {
		return nil, fmt.Errorf("stats: ioc total: %w", err)
	}

	// Active sources: count distinct sources that have actually produced content
	err = pool.QueryRow(ctx, `SELECT COUNT(DISTINCT source_name) FROM raw_content`).Scan(&stats.ActiveSources)
	if err != nil {
		return nil, fmt.Errorf("stats: active sources: %w", err)
	}

	// Discovered and paused counts from the sources table
	rows, err := pool.Query(ctx, `SELECT status, COUNT(*) FROM sources WHERE status IN ('discovered', 'paused') GROUP BY status`)
	if err != nil {
		return nil, fmt.Errorf("stats: source counts: %w", err)
	}
	for rows.Next() {
		var status string
		var cnt int64
		if err := rows.Scan(&status, &cnt); err != nil {
			rows.Close()
			return nil, err
		}
		switch status {
		case "discovered":
			stats.DiscoveredSrc = cnt
		case "paused":
			stats.PausedSources = cnt
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("stats: source counts rows: %w", err)
	}

	// By source_type
	rows, err = pool.Query(ctx, `SELECT source_type, COUNT(*) FROM raw_content GROUP BY source_type`)
	if err != nil {
		return nil, fmt.Errorf("stats: by source: %w", err)
	}
	for rows.Next() {
		var st string
		var cnt int64
		if err := rows.Scan(&st, &cnt); err != nil {
			rows.Close()
			return nil, err
		}
		stats.BySource[st] = cnt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("stats: by source rows: %w", err)
	}

	// By severity
	rows, err = pool.Query(ctx, `
		SELECT COALESCE(severity, 'unclassified'), COUNT(*)
		FROM raw_content
		GROUP BY severity`)
	if err != nil {
		return nil, fmt.Errorf("stats: by severity: %w", err)
	}
	for rows.Next() {
		var sev string
		var cnt int64
		if err := rows.Scan(&sev, &cnt); err != nil {
			rows.Close()
			return nil, err
		}
		stats.BySeverity[sev] = cnt
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("stats: by severity rows: %w", err)
	}

	return stats, nil
}

// findingsFilter holds parsed query parameters for findings search.
type findingsFilter struct {
	Category    string
	SubCategory string
	Severity    string
	Source      string
	Since       *time.Time
	Query       string
	Limit       int
	Offset      int
}

func queryFindings(ctx context.Context, pool *pgxpool.Pool, f findingsFilter) (*FindingsResponse, error) {
	var conditions []string
	var args []interface{}
	argIdx := 0

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if f.Category != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("category = %s", p))
		args = append(args, f.Category)
	}
	if f.SubCategory != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("sub_category = %s", p))
		args = append(args, f.SubCategory)
	}
	if f.Severity != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("severity = %s", p))
		args = append(args, f.Severity)
	}
	if f.Source != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("source_type = %s", p))
		args = append(args, f.Source)
	}
	if f.Since != nil {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("collected_at >= %s", p))
		args = append(args, *f.Since)
	}
	if f.Query != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("(content ILIKE '%%' || %s || '%%' OR summary ILIKE '%%' || %s || '%%')", p, p))
		args = append(args, f.Query)
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching
	var total int64
	countSQL := "SELECT COUNT(*) FROM raw_content " + where
	err := pool.QueryRow(ctx, countSQL, args...).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("findings: count: %w", err)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql := fmt.Sprintf(`
		SELECT id, source_type, source_name, category, sub_category, severity,
		       COALESCE(summary, LEFT(content, 120)) AS summary,
		       author, collected_at, posted_at, sub_metadata
		FROM raw_content %s
		ORDER BY collected_at DESC
		LIMIT %s OFFSET %s`, where, limitP, offsetP)
	args = append(args, limit, f.Offset)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("findings: query: %w", err)
	}
	defer rows.Close()

	var findings []FindingSummary
	for rows.Next() {
		var fs FindingSummary
		var subMetaJSON []byte
		if err := rows.Scan(&fs.ID, &fs.SourceType, &fs.SourceName, &fs.Category, &fs.SubCategory, &fs.Severity, &fs.Summary, &fs.Author, &fs.CollectedAt, &fs.PostedAt, &subMetaJSON); err != nil {
			return nil, fmt.Errorf("findings: scan: %w", err)
		}
		if len(subMetaJSON) > 0 {
			json.Unmarshal(subMetaJSON, &fs.SubMetadata)
		}
		findings = append(findings, fs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("findings rows: %w", err)
	}
	if findings == nil {
		findings = []FindingSummary{}
	}

	return &FindingsResponse{Findings: findings, Total: total}, nil
}

func queryFinding(ctx context.Context, pool *pgxpool.Pool, id string) (*FindingDetail, error) {
	var fd FindingDetail
	var metaJSON []byte
	err := pool.QueryRow(ctx, `
		SELECT id, source_type, source_name, category, severity, summary, author,
		       collected_at, posted_at, content, url, tags, metadata
		FROM raw_content WHERE id = $1`, id).Scan(
		&fd.ID, &fd.SourceType, &fd.SourceName, &fd.Category, &fd.Severity, &fd.Summary, &fd.Author,
		&fd.CollectedAt, &fd.PostedAt, &fd.Content, &fd.URL, &fd.Tags, &metaJSON,
	)
	if err != nil {
		return nil, fmt.Errorf("finding: %w", err)
	}

	if len(metaJSON) > 0 {
		json.Unmarshal(metaJSON, &fd.Metadata)
	}
	if fd.Tags == nil {
		fd.Tags = []string{}
	}

	// Linked IOCs
	rows, err := pool.Query(ctx, `
		SELECT id, type, value, context, first_seen, last_seen, sighting_count, threat_score, active, enrichment, enriched_at, enrichment_sources
		FROM iocs WHERE source_content_id = $1
		ORDER BY sighting_count DESC`, id)
	if err != nil {
		return nil, fmt.Errorf("finding iocs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ioc IOCItem
		var enrichJSON []byte
		if err := rows.Scan(&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Context, &ioc.FirstSeen, &ioc.LastSeen, &ioc.SightingCount, &ioc.ThreatScore, &ioc.Active, &enrichJSON, &ioc.EnrichedAt, &ioc.EnrichmentSources); err != nil {
			return nil, fmt.Errorf("finding ioc scan: %w", err)
		}
		if len(enrichJSON) > 0 {
			json.Unmarshal(enrichJSON, &ioc.Enrichment)
		}
		fd.IOCs = append(fd.IOCs, ioc)
	}
	if fd.IOCs == nil {
		fd.IOCs = []IOCItem{}
	}

	return &fd, nil
}

// iocsFilter holds parsed query parameters for IOC search.
type iocsFilter struct {
	Type         string
	Query        string
	ActiveOnly   bool
	EnrichedOnly bool
	Limit        int
	Offset       int
}

func queryIOCs(ctx context.Context, pool *pgxpool.Pool, f iocsFilter) (*IOCsResponse, error) {
	var conditions []string
	var args []interface{}
	argIdx := 0

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if f.Type != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("type = %s", p))
		args = append(args, f.Type)
	}
	if f.Query != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("value ILIKE '%%' || %s || '%%'", p))
		args = append(args, f.Query)
	}
	if f.ActiveOnly {
		conditions = append(conditions, "active = TRUE")
	}
	if f.EnrichedOnly {
		conditions = append(conditions, "enriched_at IS NOT NULL")
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM iocs "+where, args...).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("iocs count: %w", err)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql := fmt.Sprintf(`
		SELECT id, type, value, context, first_seen, last_seen, sighting_count, threat_score, active, enrichment, enriched_at, enrichment_sources
		FROM iocs %s
		ORDER BY threat_score DESC NULLS LAST
		LIMIT %s OFFSET %s`, where, limitP, offsetP)
	args = append(args, limit, f.Offset)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("iocs query: %w", err)
	}
	defer rows.Close()

	var iocs []IOCItem
	for rows.Next() {
		var ioc IOCItem
		var enrichJSON []byte
		if err := rows.Scan(&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Context, &ioc.FirstSeen, &ioc.LastSeen, &ioc.SightingCount, &ioc.ThreatScore, &ioc.Active, &enrichJSON, &ioc.EnrichedAt, &ioc.EnrichmentSources); err != nil {
			return nil, fmt.Errorf("iocs scan: %w", err)
		}
		if len(enrichJSON) > 0 {
			json.Unmarshal(enrichJSON, &ioc.Enrichment)
		}
		iocs = append(iocs, ioc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iocs rows: %w", err)
	}
	if iocs == nil {
		iocs = []IOCItem{}
	}

	return &IOCsResponse{IOCs: iocs, Total: total}, nil
}

// SourcesResponse wraps paginated sources.
type SourcesResponse struct {
	Sources []SourceItem `json:"sources"`
	Total   int64        `json:"total"`
}

func querySources(ctx context.Context, pool *pgxpool.Pool, status, sourceType string, limit, offset int) (*SourcesResponse, error) {
	var conditions []string
	var args []interface{}
	argIdx := 0

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if status != "" {
		if status == "active" {
			conditions = append(conditions, "s.status IN ('active', 'approved')")
		} else {
			p := nextArg()
			conditions = append(conditions, fmt.Sprintf("s.status = %s", p))
			args = append(args, status)
		}
	}
	if sourceType != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("s.type = %s", p))
		args = append(args, sourceType)
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	var total int64
	err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM sources s "+where, args...).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("sources count: %w", err)
	}

	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql := fmt.Sprintf(`
		SELECT s.id, s.type, s.identifier, s.name, s.status, s.last_collected,
		       s.error_count, s.created_at,
		       COALESCE(c.cnt, 0) AS content_count
		FROM sources s
		LEFT JOIN (
			SELECT source_id, COUNT(*) AS cnt
			FROM raw_content
			GROUP BY source_id
		) c ON c.source_id = s.identifier
		%s
		ORDER BY s.created_at DESC
		LIMIT %s OFFSET %s`, where, limitP, offsetP)
	args = append(args, limit, offset)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("sources query: %w", err)
	}
	defer rows.Close()

	var sources []SourceItem
	for rows.Next() {
		var si SourceItem
		if err := rows.Scan(&si.ID, &si.Type, &si.Identifier, &si.Name, &si.Status, &si.LastCollected, &si.ErrorCount, &si.CreatedAt, &si.ContentCount); err != nil {
			return nil, fmt.Errorf("sources scan: %w", err)
		}
		sources = append(sources, si)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sources rows: %w", err)
	}
	if sources == nil {
		sources = []SourceItem{}
	}

	return &SourcesResponse{Sources: sources, Total: total}, nil
}

func approveSource(ctx context.Context, pool *pgxpool.Pool, id string) error {
	ct, err := pool.Exec(ctx, `UPDATE sources SET status = 'approved', updated_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("approve source: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("source not found: %s", id)
	}
	return nil
}

func rejectSource(ctx context.Context, pool *pgxpool.Pool, id string) error {
	ct, err := pool.Exec(ctx, `UPDATE sources SET status = 'rejected', updated_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("reject source: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("source not found: %s", id)
	}
	return nil
}

func addSource(ctx context.Context, pool *pgxpool.Pool, sourceType, identifier string) (string, error) {
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO sources (type, identifier, name, status)
		VALUES ($1, $2, $2, 'active')
		ON CONFLICT (identifier) DO UPDATE SET status = 'active', updated_at = NOW()
		RETURNING id`, sourceType, identifier).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("add source: %w", err)
	}
	return id, nil
}

func queryCategories(ctx context.Context, pool *pgxpool.Pool) ([]CategoryCount, error) {
	rows, err := pool.Query(ctx, `
		SELECT COALESCE(category, 'unclassified'), COUNT(*)
		FROM raw_content
		WHERE classified = true AND category IS NOT NULL
		GROUP BY category
		ORDER BY COUNT(*) DESC`)
	if err != nil {
		return nil, fmt.Errorf("categories: %w", err)
	}
	defer rows.Close()

	var cats []CategoryCount
	for rows.Next() {
		var c CategoryCount
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, fmt.Errorf("categories scan: %w", err)
		}
		cats = append(cats, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("categories rows: %w", err)
	}
	if cats == nil {
		cats = []CategoryCount{}
	}
	return cats, nil
}

func queryTimeline(ctx context.Context, pool *pgxpool.Pool, since time.Time, interval string) ([]TimelinePoint, error) {
	// Validate interval to prevent injection (only allow safe PostgreSQL intervals)
	validIntervals := map[string]bool{"1 hour": true, "6 hours": true, "1 day": true, "1 week": true}
	if !validIntervals[interval] {
		interval = "1 hour"
	}

	// Use date_bin for proper interval-based bucketing
	rows, err := pool.Query(ctx, `
		SELECT date_bin($2::interval, collected_at, '2000-01-01'::timestamptz) AS bucket, COUNT(*)
		FROM raw_content
		WHERE collected_at >= $1
		GROUP BY bucket
		ORDER BY bucket ASC`, since, interval)
	if err != nil {
		return nil, fmt.Errorf("timeline: %w", err)
	}
	defer rows.Close()

	var points []TimelinePoint
	for rows.Next() {
		var tp TimelinePoint
		if err := rows.Scan(&tp.Bucket, &tp.Count); err != nil {
			return nil, fmt.Errorf("timeline scan: %w", err)
		}
		points = append(points, tp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("timeline rows: %w", err)
	}
	if points == nil {
		points = []TimelinePoint{}
	}
	return points, nil
}

func queryGraph(ctx context.Context, pool *pgxpool.Pool, entityID string, hops int) (*GraphResponse, error) {
	if hops <= 0 {
		hops = 2
	}
	if hops > 5 {
		hops = 5
	}

	// Node-centric BFS: find reachable nodes first, then fetch edges between them.
	rows, err := pool.Query(ctx, `
		WITH RECURSIVE reachable AS (
			SELECT $1::text AS node_id, 0 AS depth
			UNION
			SELECT DISTINCT
				CASE WHEN e.source_id = r.node_id THEN e.target_id ELSE e.source_id END,
				r.depth + 1
			FROM edges e
			JOIN reachable r ON (e.source_id = r.node_id OR e.target_id = r.node_id)
			WHERE r.depth < $2
		)
		SELECT DISTINCT e.source_id, e.target_id, e.relationship
		FROM edges e
		WHERE e.source_id IN (SELECT node_id FROM reachable)
		  AND e.target_id IN (SELECT node_id FROM reachable)`, entityID, hops)
	if err != nil {
		return nil, fmt.Errorf("graph edges: %w", err)
	}
	defer rows.Close()

	nodeIDs := make(map[string]bool)
	var edges []GraphEdge
	for rows.Next() {
		var e GraphEdge
		if err := rows.Scan(&e.Source, &e.Target, &e.Relationship); err != nil {
			return nil, fmt.Errorf("graph edge scan: %w", err)
		}
		edges = append(edges, e)
		nodeIDs[e.Source] = true
		nodeIDs[e.Target] = true
	}

	if edges == nil {
		return &GraphResponse{Nodes: []GraphNode{}, Edges: []GraphEdge{}}, nil
	}

	// Fetch node details
	ids := make([]string, 0, len(nodeIDs))
	for id := range nodeIDs {
		ids = append(ids, id)
	}

	nodeRows, err := pool.Query(ctx, `
		SELECT id, type, properties FROM entities WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("graph nodes: %w", err)
	}
	defer nodeRows.Close()

	var nodes []GraphNode
	for nodeRows.Next() {
		var n GraphNode
		var propsJSON []byte
		if err := nodeRows.Scan(&n.ID, &n.Type, &propsJSON); err != nil {
			return nil, fmt.Errorf("graph node scan: %w", err)
		}
		if len(propsJSON) > 0 {
			json.Unmarshal(propsJSON, &n.Properties)
		}
		if n.Properties == nil {
			n.Properties = map[string]any{}
		}
		nodes = append(nodes, n)
	}

	return &GraphResponse{Nodes: nodes, Edges: edges}, nil
}

// --- Entity listing ---

// EntitySummary is a compact representation of an entity for list views.
type EntitySummary struct {
	ID         string         `json:"id"`
	Type       string         `json:"type"`
	Properties map[string]any `json:"properties"`
	EdgeCount  int64          `json:"edgeCount"`
	CreatedAt  time.Time      `json:"createdAt"`
}

// EntitiesResponse wraps paginated entities.
type EntitiesResponse struct {
	Entities []EntitySummary `json:"entities"`
	Total    int64           `json:"total"`
}

func queryEntities(ctx context.Context, pool *pgxpool.Pool, entityType, query string, limit, offset int) (*EntitiesResponse, error) {
	var conditions []string
	var args []interface{}
	argIdx := 0

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if entityType != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("e.type = %s", p))
		args = append(args, entityType)
	}
	if query != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("(e.id ILIKE '%%' || %s || '%%' OR e.properties::text ILIKE '%%' || %s || '%%')", p, p))
		args = append(args, query)
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM entities e "+where, args...).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("entities count: %w", err)
	}

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql := fmt.Sprintf(`
		SELECT e.id, e.type, e.properties, e.created_at,
		       COALESCE(ec.cnt, 0) AS edge_count
		FROM entities e
		LEFT JOIN (
			SELECT id, COUNT(*) AS cnt FROM (
				SELECT source_id AS id FROM edges
				UNION ALL
				SELECT target_id AS id FROM edges
			) sub GROUP BY id
		) ec ON ec.id = e.id
		%s
		ORDER BY e.created_at DESC
		LIMIT %s OFFSET %s`, where, limitP, offsetP)
	args = append(args, limit, offset)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("entities query: %w", err)
	}
	defer rows.Close()

	var entities []EntitySummary
	for rows.Next() {
		var es EntitySummary
		var propsJSON []byte
		if err := rows.Scan(&es.ID, &es.Type, &propsJSON, &es.CreatedAt, &es.EdgeCount); err != nil {
			return nil, fmt.Errorf("entities scan: %w", err)
		}
		if len(propsJSON) > 0 {
			json.Unmarshal(propsJSON, &es.Properties)
		}
		if es.Properties == nil {
			es.Properties = map[string]any{}
		}
		entities = append(entities, es)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("entities rows: %w", err)
	}
	if entities == nil {
		entities = []EntitySummary{}
	}

	return &EntitiesResponse{Entities: entities, Total: total}, nil
}

// --- Public (unauthenticated) queries ---

// PublicStats holds aggregate counts safe for unauthenticated display.
type PublicStats struct {
	TotalFindings int64 `json:"totalFindings"`
	TotalIOCs     int64 `json:"totalIocs"`
	ActiveSources int64 `json:"activeSources"`
	TotalEntities int64 `json:"totalEntities"`
}

func queryPublicStats(ctx context.Context, pool *pgxpool.Pool) (*PublicStats, error) {
	s := &PublicStats{}

	err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM raw_content`).Scan(&s.TotalFindings)
	if err != nil {
		return nil, fmt.Errorf("public stats: findings: %w", err)
	}

	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM iocs`).Scan(&s.TotalIOCs)
	if err != nil {
		return nil, fmt.Errorf("public stats: iocs: %w", err)
	}

	err = pool.QueryRow(ctx, `SELECT COUNT(DISTINCT source_name) FROM raw_content`).Scan(&s.ActiveSources)
	if err != nil {
		return nil, fmt.Errorf("public stats: sources: %w", err)
	}

	err = pool.QueryRow(ctx, `SELECT COUNT(*) FROM entities`).Scan(&s.TotalEntities)
	if err != nil {
		return nil, fmt.Errorf("public stats: entities: %w", err)
	}

	return s, nil
}

// PublicFinding is a sanitized finding for unauthenticated display.
type PublicFinding struct {
	Category   *string   `json:"category"`
	Severity   *string   `json:"severity"`
	SourceType string    `json:"sourceType"`
	Summary    string    `json:"summary"`
	CollectedAt time.Time `json:"collectedAt"`
}

func queryPublicRecent(ctx context.Context, pool *pgxpool.Pool) ([]PublicFinding, error) {
	rows, err := pool.Query(ctx, `
		SELECT category, severity, source_type,
		       CASE WHEN length(summary) > 100 THEN left(summary, 100) || '...' ELSE summary END,
		       collected_at
		FROM raw_content
		WHERE classified = true AND category IS NOT NULL AND category != 'irrelevant' AND summary IS NOT NULL
		ORDER BY collected_at DESC
		LIMIT 4`)
	if err != nil {
		return nil, fmt.Errorf("public recent: %w", err)
	}
	defer rows.Close()

	var findings []PublicFinding
	for rows.Next() {
		var f PublicFinding
		if err := rows.Scan(&f.Category, &f.Severity, &f.SourceType, &f.Summary, &f.CollectedAt); err != nil {
			return nil, fmt.Errorf("public recent scan: %w", err)
		}
		findings = append(findings, f)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("public recent rows: %w", err)
	}
	if findings == nil {
		findings = []PublicFinding{}
	}
	return findings, nil
}

// --- Correlations ---

// correlationFilter holds parsed query parameters for correlation search.
type correlationFilter struct {
	Type          string
	MinConfidence float64
	Since         *time.Time
	Limit         int
	Offset        int
}

// CorrelationItem represents a correlation in API responses.
type CorrelationItem struct {
	ID              string         `json:"id"`
	ClusterID       string         `json:"clusterId"`
	EntityIDs       []string       `json:"entityIds"`
	FindingIDs      []string       `json:"findingIds"`
	CorrelationType string         `json:"correlationType"`
	Confidence      float64        `json:"confidence"`
	Method          string         `json:"method"`
	Evidence        map[string]any `json:"evidence"`
	CreatedAt       time.Time      `json:"createdAt"`
	UpdatedAt       time.Time      `json:"updatedAt"`
}

// CorrelationsResponse wraps paginated correlations.
type CorrelationsResponse struct {
	Correlations []CorrelationItem `json:"correlations"`
	Total        int64             `json:"total"`
}

func queryCorrelations(ctx context.Context, pool *pgxpool.Pool, f correlationFilter) (*CorrelationsResponse, error) {
	var conditions []string
	var args []interface{}
	argIdx := 0

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if f.Type != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("correlation_type = %s", p))
		args = append(args, f.Type)
	}
	if f.MinConfidence > 0 {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("confidence >= %s", p))
		args = append(args, f.MinConfidence)
	}
	if f.Since != nil {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("created_at >= %s", p))
		args = append(args, *f.Since)
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	err := pool.QueryRow(ctx, "SELECT COUNT(*) FROM correlations "+where, args...).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("correlations count: %w", err)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql := fmt.Sprintf(`
		SELECT id, cluster_id, entity_ids, finding_ids, correlation_type,
		       confidence, method, evidence, created_at, updated_at
		FROM correlations %s
		ORDER BY created_at DESC
		LIMIT %s OFFSET %s`, where, limitP, offsetP)
	args = append(args, limit, f.Offset)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("correlations query: %w", err)
	}
	defer rows.Close()

	var correlations []CorrelationItem
	for rows.Next() {
		var c CorrelationItem
		var evidenceJSON []byte
		if err := rows.Scan(&c.ID, &c.ClusterID, &c.EntityIDs, &c.FindingIDs,
			&c.CorrelationType, &c.Confidence, &c.Method, &evidenceJSON,
			&c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, fmt.Errorf("correlations scan: %w", err)
		}
		if len(evidenceJSON) > 0 {
			json.Unmarshal(evidenceJSON, &c.Evidence)
		}
		if c.Evidence == nil {
			c.Evidence = map[string]any{}
		}
		if c.EntityIDs == nil {
			c.EntityIDs = []string{}
		}
		if c.FindingIDs == nil {
			c.FindingIDs = []string{}
		}
		correlations = append(correlations, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("correlations rows: %w", err)
	}
	if correlations == nil {
		correlations = []CorrelationItem{}
	}

	return &CorrelationsResponse{Correlations: correlations, Total: total}, nil
}

// --- Actor Profile ---

// ActorProfile is a comprehensive dossier built dynamically from the graph.
type ActorProfile struct {
	EntityID   string         `json:"entityId"`
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	Aliases    []string       `json:"aliases"`
	Properties map[string]any `json:"properties"`

	Malware        []LinkedEntity       `json:"malware"`
	Tools          []LinkedEntity       `json:"tools"`
	Infrastructure []LinkedEntity       `json:"infrastructure"`
	Targets        []LinkedEntity       `json:"targets"`
	Campaigns      []LinkedEntity       `json:"campaigns"`

	RecentFindings  []ActorFindingSummary `json:"recentFindings"`
	FindingCount    int                   `json:"findingCount"`
	Correlations    []CorrelationItem     `json:"correlations"`
	AnalyticalNotes []AnalyticalNoteItem  `json:"analyticalNotes"`

	FirstSeen   *time.Time `json:"firstSeen"`
	LastSeen    *time.Time `json:"lastSeen"`
	ThreatLevel string     `json:"threatLevel"`
}

// LinkedEntity is an entity connected to the actor via graph edges.
type LinkedEntity struct {
	EntityID     string         `json:"entityId"`
	Type         string         `json:"type"`
	Name         string         `json:"name"`
	Properties   map[string]any `json:"properties"`
	Relationship string         `json:"relationship"`
	EdgeCount    int            `json:"edgeCount"`
}

// ActorFindingSummary is a compact finding for actor profile views.
type ActorFindingSummary struct {
	ID          string    `json:"id"`
	Category    string    `json:"category"`
	SubCategory *string   `json:"subCategory,omitempty"`
	Severity    string    `json:"severity"`
	Summary     string    `json:"summary"`
	SourceName  string    `json:"sourceName"`
	CollectedAt time.Time `json:"collectedAt"`
}

// AnalyticalNoteItem is a note for API responses.
type AnalyticalNoteItem struct {
	ID         string    `json:"id"`
	NoteType   string    `json:"noteType"`
	Title      string    `json:"title"`
	Content    string    `json:"content"`
	Confidence float64   `json:"confidence"`
	CreatedBy  string    `json:"createdBy"`
	CreatedAt  time.Time `json:"createdAt"`
}

func queryActorProfile(ctx context.Context, pool *pgxpool.Pool, id string) (*ActorProfile, error) {
	// 1. Fetch the entity.
	var entityType string
	var propsJSON []byte
	err := pool.QueryRow(ctx,
		`SELECT type, properties FROM entities WHERE id = $1`, id,
	).Scan(&entityType, &propsJSON)
	if err != nil {
		return nil, fmt.Errorf("entity not found: %w", err)
	}

	props := map[string]any{}
	if len(propsJSON) > 0 {
		json.Unmarshal(propsJSON, &props)
	}

	name := id
	if n, ok := props["name"].(string); ok && n != "" {
		name = n
	}

	var aliases []string
	if a, ok := props["aliases"].([]any); ok {
		for _, v := range a {
			if s, ok := v.(string); ok {
				aliases = append(aliases, s)
			}
		}
	}
	if aliases == nil {
		aliases = []string{}
	}

	profile := &ActorProfile{
		EntityID:   id,
		Name:       name,
		Type:       entityType,
		Aliases:    aliases,
		Properties: props,
	}

	// 2. Fetch connected entities via edges.
	rows, err := pool.Query(ctx, `
		SELECT e.id, e.type, COALESCE(e.properties->>'name', e.id),
		       e.properties, edge.relationship, COUNT(*) OVER (PARTITION BY e.id)
		FROM edges edge
		JOIN entities e ON e.id = edge.target_id
		WHERE edge.source_id = $1
		UNION ALL
		SELECT e.id, e.type, COALESCE(e.properties->>'name', e.id),
		       e.properties, edge.relationship, COUNT(*) OVER (PARTITION BY e.id)
		FROM edges edge
		JOIN entities e ON e.id = edge.source_id
		WHERE edge.target_id = $1
		LIMIT 100`, id)
	if err != nil {
		return nil, fmt.Errorf("edges query: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var le LinkedEntity
		var lePropsJSON []byte
		if err := rows.Scan(&le.EntityID, &le.Type, &le.Name, &lePropsJSON, &le.Relationship, &le.EdgeCount); err != nil {
			continue
		}
		if len(lePropsJSON) > 0 {
			json.Unmarshal(lePropsJSON, &le.Properties)
		}
		if le.Properties == nil {
			le.Properties = map[string]any{}
		}

		switch {
		case le.Type == "malware":
			profile.Malware = append(profile.Malware, le)
		case le.Type == "tool":
			profile.Tools = append(profile.Tools, le)
		case le.Type == "ip" || le.Type == "domain" || le.Type == "url":
			profile.Infrastructure = append(profile.Infrastructure, le)
		case le.Type == "campaign":
			profile.Campaigns = append(profile.Campaigns, le)
		case le.Relationship == "targets":
			profile.Targets = append(profile.Targets, le)
		}
	}
	rows.Close()

	// Initialize nil slices.
	if profile.Malware == nil {
		profile.Malware = []LinkedEntity{}
	}
	if profile.Tools == nil {
		profile.Tools = []LinkedEntity{}
	}
	if profile.Infrastructure == nil {
		profile.Infrastructure = []LinkedEntity{}
	}
	if profile.Targets == nil {
		profile.Targets = []LinkedEntity{}
	}
	if profile.Campaigns == nil {
		profile.Campaigns = []LinkedEntity{}
	}

	// 3. Fetch findings referencing this actor via entity edges to source entities.
	err = pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT rc.id)
		FROM raw_content rc
		JOIN edges edge ON edge.target_id = 'source:' || rc.source_name
		WHERE edge.source_id = $1
		  AND rc.classified = true AND rc.category != 'irrelevant'`, id,
	).Scan(&profile.FindingCount)
	if err != nil {
		profile.FindingCount = 0
	}

	findingRows, err := pool.Query(ctx, `
		SELECT DISTINCT rc.id, COALESCE(rc.category, ''), rc.sub_category,
		       COALESCE(rc.severity, ''), COALESCE(rc.summary, ''),
		       rc.source_name, rc.collected_at
		FROM raw_content rc
		JOIN edges edge ON edge.target_id = 'source:' || rc.source_name
		WHERE edge.source_id = $1
		  AND rc.classified = true AND rc.category != 'irrelevant'
		ORDER BY rc.collected_at DESC
		LIMIT 20`, id)
	if err == nil {
		defer findingRows.Close()
		for findingRows.Next() {
			var f ActorFindingSummary
			if err := findingRows.Scan(&f.ID, &f.Category, &f.SubCategory,
				&f.Severity, &f.Summary, &f.SourceName, &f.CollectedAt); err != nil {
				continue
			}
			profile.RecentFindings = append(profile.RecentFindings, f)
		}
		findingRows.Close()
	}
	if profile.RecentFindings == nil {
		profile.RecentFindings = []ActorFindingSummary{}
	}

	// 4. Fetch correlations involving this actor.
	corrRows, err := pool.Query(ctx, `
		SELECT id, cluster_id, entity_ids, finding_ids, correlation_type,
		       confidence, method, evidence, created_at, updated_at
		FROM correlations
		WHERE $1 = ANY(entity_ids)
		ORDER BY created_at DESC
		LIMIT 20`, id)
	if err == nil {
		defer corrRows.Close()
		for corrRows.Next() {
			var c CorrelationItem
			var evidenceJSON []byte
			if err := corrRows.Scan(&c.ID, &c.ClusterID, &c.EntityIDs, &c.FindingIDs,
				&c.CorrelationType, &c.Confidence, &c.Method, &evidenceJSON,
				&c.CreatedAt, &c.UpdatedAt); err != nil {
				continue
			}
			if len(evidenceJSON) > 0 {
				json.Unmarshal(evidenceJSON, &c.Evidence)
			}
			if c.Evidence == nil {
				c.Evidence = map[string]any{}
			}
			if c.EntityIDs == nil {
				c.EntityIDs = []string{}
			}
			if c.FindingIDs == nil {
				c.FindingIDs = []string{}
			}
			profile.Correlations = append(profile.Correlations, c)
		}
		corrRows.Close()
	}
	if profile.Correlations == nil {
		profile.Correlations = []CorrelationItem{}
	}

	// 5. Fetch analytical notes.
	noteRows, err := pool.Query(ctx, `
		SELECT id, note_type, title, content, confidence, created_by, created_at
		FROM analytical_notes
		WHERE entity_id = $1 AND status = 'active'
		ORDER BY created_at DESC
		LIMIT 20`, id)
	if err == nil {
		defer noteRows.Close()
		for noteRows.Next() {
			var n AnalyticalNoteItem
			if err := noteRows.Scan(&n.ID, &n.NoteType, &n.Title, &n.Content,
				&n.Confidence, &n.CreatedBy, &n.CreatedAt); err != nil {
				continue
			}
			profile.AnalyticalNotes = append(profile.AnalyticalNotes, n)
		}
		noteRows.Close()
	}
	if profile.AnalyticalNotes == nil {
		profile.AnalyticalNotes = []AnalyticalNoteItem{}
	}

	// 6. First/last seen from findings.
	var firstSeen, lastSeen *time.Time
	pool.QueryRow(ctx, `
		SELECT MIN(rc.collected_at), MAX(rc.collected_at)
		FROM raw_content rc
		JOIN edges edge ON edge.target_id = 'source:' || rc.source_name
		WHERE edge.source_id = $1`, id,
	).Scan(&firstSeen, &lastSeen)
	profile.FirstSeen = firstSeen
	profile.LastSeen = lastSeen

	// 7. Threat level from actor_profiles if exists, otherwise derive.
	var threatLevel string
	err = pool.QueryRow(ctx,
		`SELECT threat_level FROM actor_profiles WHERE id = $1`, id,
	).Scan(&threatLevel)
	if err != nil || threatLevel == "" {
		threatLevel = "unknown"
	}
	profile.ThreatLevel = threatLevel

	return profile, nil
}

// --- Source Value ---

// SourceValueItem represents a source with its computed value metrics.
type SourceValueItem struct {
	ID                      string     `json:"id"`
	Type                    string     `json:"type"`
	Identifier              string     `json:"identifier"`
	Name                    *string    `json:"name"`
	Status                  string     `json:"status"`
	UniqueIOCs              int        `json:"uniqueIocs"`
	CorrelationContributions int       `json:"correlationContributions"`
	AvgSeverity             float64    `json:"avgSeverity"`
	SignalToNoise           float64    `json:"signalToNoise"`
	ValueScore              float64    `json:"valueScore"`
	ValueComputedAt         *time.Time `json:"valueComputedAt"`
	ContentCount            int        `json:"contentCount"`
}

// SourceValueResponse wraps source value results.
type SourceValueResponse struct {
	Sources []SourceValueItem `json:"sources"`
}

func querySourceValues(ctx context.Context, pool *pgxpool.Pool) (*SourceValueResponse, error) {
	rows, err := pool.Query(ctx, `
		SELECT s.id, s.type, s.identifier, s.name, s.status,
		       COALESCE(s.unique_iocs, 0),
		       COALESCE(s.correlation_contributions, 0),
		       COALESCE(s.avg_severity, 0),
		       COALESCE(s.signal_to_noise, 0),
		       COALESCE(s.value_score, 0),
		       s.value_computed_at,
		       (SELECT COUNT(*) FROM raw_content rc WHERE rc.source_name = s.name)
		FROM sources s
		WHERE s.status IN ('active', 'approved', 'discovered')
		ORDER BY COALESCE(s.value_score, 0) DESC`)
	if err != nil {
		return nil, fmt.Errorf("source values query: %w", err)
	}
	defer rows.Close()

	var sources []SourceValueItem
	for rows.Next() {
		var sv SourceValueItem
		if err := rows.Scan(&sv.ID, &sv.Type, &sv.Identifier, &sv.Name, &sv.Status,
			&sv.UniqueIOCs, &sv.CorrelationContributions, &sv.AvgSeverity,
			&sv.SignalToNoise, &sv.ValueScore, &sv.ValueComputedAt,
			&sv.ContentCount); err != nil {
			continue
		}
		sources = append(sources, sv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("source values rows: %w", err)
	}
	if sources == nil {
		sources = []SourceValueItem{}
	}

	return &SourceValueResponse{Sources: sources}, nil
}

// --- Sub-categories ---

// SubCategoryCount represents a sub-category with its parent category and count.
type SubCategoryCount struct {
	SubCategory string `json:"sub_category"`
	Category    string `json:"category"`
	Count       int    `json:"count"`
}

func querySubcategories(ctx context.Context, pool *pgxpool.Pool) ([]SubCategoryCount, error) {
	rows, err := pool.Query(ctx, `
		SELECT sub_category, category, COUNT(*) AS cnt
		FROM raw_content
		WHERE sub_category IS NOT NULL AND sub_category != ''
		GROUP BY sub_category, category
		ORDER BY category, cnt DESC`)
	if err != nil {
		return nil, fmt.Errorf("subcategories query: %w", err)
	}
	defer rows.Close()

	var results []SubCategoryCount
	for rows.Next() {
		var sc SubCategoryCount
		if err := rows.Scan(&sc.SubCategory, &sc.Category, &sc.Count); err != nil {
			continue
		}
		results = append(results, sc)
	}
	if results == nil {
		results = []SubCategoryCount{}
	}
	return results, nil
}

// --- Analytical Notes ---

// NotesResponse wraps paginated analytical notes.
type NotesResponse struct {
	Notes []NoteListItem `json:"notes"`
	Total int64          `json:"total"`
}

// NoteListItem is a note for list views.
type NoteListItem struct {
	ID            string    `json:"id"`
	FindingID     *string   `json:"findingId,omitempty"`
	EntityID      *string   `json:"entityId,omitempty"`
	CorrelationID *string   `json:"correlationId,omitempty"`
	NoteType      string    `json:"noteType"`
	Title         string    `json:"title"`
	Content       string    `json:"content"`
	Confidence    float64   `json:"confidence"`
	CreatedBy     string    `json:"createdBy"`
	ModelUsed     *string   `json:"modelUsed,omitempty"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"createdAt"`
}

type notesFilter struct {
	NoteType string
	Status   string
	EntityID string
	Limit    int
	Offset   int
}

func queryNotes(ctx context.Context, pool *pgxpool.Pool, f notesFilter) (*NotesResponse, error) {
	var conditions []string
	var args []interface{}
	argIdx := 0

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if f.NoteType != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("note_type = %s", p))
		args = append(args, f.NoteType)
	}
	if f.Status != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("status = %s", p))
		args = append(args, f.Status)
	} else {
		conditions = append(conditions, "status = 'active'")
	}
	if f.EntityID != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("entity_id = %s", p))
		args = append(args, f.EntityID)
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	pool.QueryRow(ctx, "SELECT COUNT(*) FROM analytical_notes "+where, args...).Scan(&total)

	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql := fmt.Sprintf(`
		SELECT id, finding_id, entity_id, correlation_id,
		       note_type, title, content, confidence,
		       created_by, model_used, status, created_at
		FROM analytical_notes %s
		ORDER BY created_at DESC
		LIMIT %s OFFSET %s`, where, limitP, offsetP)
	args = append(args, limit, f.Offset)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("notes query: %w", err)
	}
	defer rows.Close()

	var notes []NoteListItem
	for rows.Next() {
		var n NoteListItem
		if err := rows.Scan(&n.ID, &n.FindingID, &n.EntityID, &n.CorrelationID,
			&n.NoteType, &n.Title, &n.Content, &n.Confidence,
			&n.CreatedBy, &n.ModelUsed, &n.Status, &n.CreatedAt); err != nil {
			continue
		}
		notes = append(notes, n)
	}
	if notes == nil {
		notes = []NoteListItem{}
	}

	return &NotesResponse{Notes: notes, Total: total}, nil
}

// --- Correlation Decisions ---

// DecisionsResponse wraps paginated correlation decisions.
type DecisionsResponse struct {
	Decisions []DecisionItem `json:"decisions"`
	Total     int64          `json:"total"`
}

// DecisionItem represents a correlation decision for API responses.
type DecisionItem struct {
	ID                    string    `json:"id"`
	CandidateID           string    `json:"candidateId"`
	ClusterID             string    `json:"clusterId"`
	Decision              string    `json:"decision"`
	Confidence            float64   `json:"confidence"`
	Reasoning             string    `json:"reasoning"`
	PromotedCorrelationID *string   `json:"promotedCorrelationId,omitempty"`
	ModelUsed             *string   `json:"modelUsed,omitempty"`
	CreatedAt             time.Time `json:"createdAt"`
}

type decisionsFilter struct {
	Decision string
	Limit    int
	Offset   int
}

func queryCorrelationDecisions(ctx context.Context, pool *pgxpool.Pool, f decisionsFilter) (*DecisionsResponse, error) {
	var conditions []string
	var args []interface{}
	argIdx := 0

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if f.Decision != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("decision = %s", p))
		args = append(args, f.Decision)
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	pool.QueryRow(ctx, "SELECT COUNT(*) FROM correlation_decisions "+where, args...).Scan(&total)

	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql := fmt.Sprintf(`
		SELECT id, candidate_id, cluster_id, decision, confidence,
		       reasoning, promoted_correlation_id, model_used, created_at
		FROM correlation_decisions %s
		ORDER BY created_at DESC
		LIMIT %s OFFSET %s`, where, limitP, offsetP)
	args = append(args, limit, f.Offset)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("decisions query: %w", err)
	}
	defer rows.Close()

	var decisions []DecisionItem
	for rows.Next() {
		var d DecisionItem
		if err := rows.Scan(&d.ID, &d.CandidateID, &d.ClusterID, &d.Decision,
			&d.Confidence, &d.Reasoning, &d.PromotedCorrelationID,
			&d.ModelUsed, &d.CreatedAt); err != nil {
			continue
		}
		decisions = append(decisions, d)
	}
	if decisions == nil {
		decisions = []DecisionItem{}
	}

	return &DecisionsResponse{Decisions: decisions, Total: total}, nil
}

// --- Intelligence Briefs ---

// BriefListItem is a compact representation for the briefs list view.
type BriefListItem struct {
	ID               string         `json:"id"`
	PeriodStart      time.Time      `json:"periodStart"`
	PeriodEnd        time.Time      `json:"periodEnd"`
	BriefType        string         `json:"briefType"`
	Title            string         `json:"title"`
	ExecutiveSummary string         `json:"executiveSummary"`
	Metrics          map[string]any `json:"metrics"`
	GeneratedAt      time.Time      `json:"generatedAt"`
}

// BriefDetail is the full brief including content and sections.
type BriefDetail struct {
	BriefListItem
	Content              string         `json:"content"`
	Sections             map[string]any `json:"sections"`
	ModelUsed            *string        `json:"modelUsed,omitempty"`
	GenerationDurationMs int            `json:"generationDurationMs"`
}

// BriefsResponse wraps paginated briefs.
type BriefsResponse struct {
	Briefs []BriefListItem `json:"briefs"`
	Total  int64           `json:"total"`
}

func queryBriefs(ctx context.Context, pool *pgxpool.Pool, briefType string, limit, offset int) (*BriefsResponse, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	var total int64
	err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM intelligence_briefs WHERE brief_type = $1`,
		briefType,
	).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("briefs: count: %w", err)
	}

	rows, err := pool.Query(ctx, `
		SELECT id, period_start, period_end, brief_type, title, executive_summary,
		       metrics, generated_at
		FROM intelligence_briefs
		WHERE brief_type = $1
		ORDER BY period_end DESC
		LIMIT $2 OFFSET $3`, briefType, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("briefs: query: %w", err)
	}
	defer rows.Close()

	var briefs []BriefListItem
	for rows.Next() {
		var b BriefListItem
		var metricsJSON []byte
		if err := rows.Scan(&b.ID, &b.PeriodStart, &b.PeriodEnd, &b.BriefType,
			&b.Title, &b.ExecutiveSummary, &metricsJSON, &b.GeneratedAt); err != nil {
			return nil, fmt.Errorf("briefs: scan: %w", err)
		}
		if len(metricsJSON) > 0 {
			json.Unmarshal(metricsJSON, &b.Metrics)
		}
		briefs = append(briefs, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("briefs rows: %w", err)
	}
	if briefs == nil {
		briefs = []BriefListItem{}
	}

	return &BriefsResponse{Briefs: briefs, Total: total}, nil
}

func queryLatestBrief(ctx context.Context, pool *pgxpool.Pool, briefType string) (*BriefDetail, error) {
	var b BriefDetail
	var sectionsJSON, metricsJSON []byte

	err := pool.QueryRow(ctx, `
		SELECT id, period_start, period_end, brief_type, title, executive_summary,
		       content, sections, metrics, model_used, generation_duration_ms, generated_at
		FROM intelligence_briefs
		WHERE brief_type = $1
		ORDER BY period_end DESC LIMIT 1`, briefType).Scan(
		&b.ID, &b.PeriodStart, &b.PeriodEnd, &b.BriefType, &b.Title,
		&b.ExecutiveSummary, &b.Content, &sectionsJSON, &metricsJSON,
		&b.ModelUsed, &b.GenerationDurationMs, &b.GeneratedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("latest brief: %w", err)
	}

	if len(sectionsJSON) > 0 {
		json.Unmarshal(sectionsJSON, &b.Sections)
	}
	if len(metricsJSON) > 0 {
		json.Unmarshal(metricsJSON, &b.Metrics)
	}

	return &b, nil
}

// --- Vulnerability Intelligence ---

// VulnListItem is a compact vulnerability for list views.
type VulnListItem struct {
	ID               string     `json:"id"`
	CVEID            string     `json:"cveId"`
	Description      *string    `json:"description,omitempty"`
	CVSSV31Score     *float64   `json:"cvssScore,omitempty"`
	CVSSSeverity     *string    `json:"cvssSeverity,omitempty"`
	EPSSScore        *float64   `json:"epssScore,omitempty"`
	EPSSPercentile   *float64   `json:"epssPercentile,omitempty"`
	KEVListed        bool       `json:"kevListed"`
	KEVRansomwareUse bool       `json:"kevRansomwareUse"`
	ExploitAvailable bool       `json:"exploitAvailable"`
	DarkWebMentions  int        `json:"darkWebMentions"`
	PriorityScore    *float64   `json:"priorityScore,omitempty"`
	PriorityLabel    *string    `json:"priorityLabel,omitempty"`
	PublishedAt      *time.Time `json:"publishedAt,omitempty"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

// VulnsResponse wraps paginated vulnerabilities.
type VulnsResponse struct {
	Vulnerabilities []VulnListItem `json:"vulnerabilities"`
	Total           int64          `json:"total"`
}

type vulnsFilter struct {
	MinPriority *float64
	KEVOnly     bool
	MinEPSS     *float64
	HasExploit  bool
	HasMentions bool
	Query       string
	Limit       int
	Offset      int
}

func queryVulnerabilities(ctx context.Context, pool *pgxpool.Pool, f vulnsFilter) (*VulnsResponse, error) {
	var conditions []string
	var args []interface{}
	argIdx := 0

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if f.MinPriority != nil {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("priority_score >= %s", p))
		args = append(args, *f.MinPriority)
	}
	if f.KEVOnly {
		conditions = append(conditions, "kev_listed = TRUE")
	}
	if f.MinEPSS != nil {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("epss_score >= %s", p))
		args = append(args, *f.MinEPSS)
	}
	if f.HasExploit {
		conditions = append(conditions, "exploit_available = TRUE")
	}
	if f.HasMentions {
		conditions = append(conditions, "dark_web_mentions > 0")
	}
	if f.Query != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("cve_id ILIKE '%%' || %s || '%%'", p))
		args = append(args, f.Query)
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	countSQL := "SELECT COUNT(*) FROM vulnerabilities " + where
	if err := pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("vulns: count: %w", err)
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql := fmt.Sprintf(`
		SELECT id, cve_id, description, cvss_v31_score, cvss_severity,
		       epss_score, epss_percentile,
		       kev_listed, kev_ransomware_use,
		       exploit_available, dark_web_mentions,
		       priority_score, priority_label,
		       published_at, updated_at
		FROM vulnerabilities %s
		ORDER BY priority_score DESC NULLS LAST
		LIMIT %s OFFSET %s`, where, limitP, offsetP)
	args = append(args, limit, f.Offset)

	rows, err := pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("vulns: query: %w", err)
	}
	defer rows.Close()

	var vulns []VulnListItem
	for rows.Next() {
		var v VulnListItem
		if err := rows.Scan(
			&v.ID, &v.CVEID, &v.Description, &v.CVSSV31Score, &v.CVSSSeverity,
			&v.EPSSScore, &v.EPSSPercentile,
			&v.KEVListed, &v.KEVRansomwareUse,
			&v.ExploitAvailable, &v.DarkWebMentions,
			&v.PriorityScore, &v.PriorityLabel,
			&v.PublishedAt, &v.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("vulns: scan: %w", err)
		}
		vulns = append(vulns, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vulns rows: %w", err)
	}
	if vulns == nil {
		vulns = []VulnListItem{}
	}

	return &VulnsResponse{Vulnerabilities: vulns, Total: total}, nil
}

// VulnDetail is the full vulnerability with all fields.
type VulnDetail struct {
	VulnListItem
	CVSSV31Vector    *string    `json:"cvssVector,omitempty"`
	CWEIDs           []string   `json:"cweIds"`
	AffectedProducts []any      `json:"affectedProducts"`
	ReferenceURLs    []any      `json:"referenceUrls"`
	EPSSUpdatedAt    *time.Time `json:"epssUpdatedAt,omitempty"`
	KEVDateAdded     *time.Time `json:"kevDateAdded,omitempty"`
	KEVDueDate       *time.Time `json:"kevDueDate,omitempty"`
	FirstSeenNoctis  *time.Time `json:"firstSeenNoctis,omitempty"`
	LastSeenNoctis   *time.Time `json:"lastSeenNoctis,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
}

func queryVulnerabilityDetail(ctx context.Context, pool *pgxpool.Pool, cveID string) (*VulnDetail, error) {
	var v VulnDetail
	var affectedJSON, refsJSON []byte

	err := pool.QueryRow(ctx, `
		SELECT id, cve_id, description, cvss_v31_score, cvss_severity, cvss_v31_vector,
		       epss_score, epss_percentile, epss_updated_at,
		       kev_listed, kev_ransomware_use, kev_date_added, kev_due_date,
		       exploit_available, dark_web_mentions,
		       priority_score, priority_label,
		       cwe_ids, affected_products, reference_urls,
		       first_seen_noctis, last_seen_noctis,
		       published_at, updated_at, created_at
		FROM vulnerabilities WHERE cve_id = $1`, cveID).Scan(
		&v.ID, &v.CVEID, &v.Description, &v.CVSSV31Score, &v.CVSSSeverity, &v.CVSSV31Vector,
		&v.EPSSScore, &v.EPSSPercentile, &v.EPSSUpdatedAt,
		&v.KEVListed, &v.KEVRansomwareUse, &v.KEVDateAdded, &v.KEVDueDate,
		&v.ExploitAvailable, &v.DarkWebMentions,
		&v.PriorityScore, &v.PriorityLabel,
		&v.CWEIDs, &affectedJSON, &refsJSON,
		&v.FirstSeenNoctis, &v.LastSeenNoctis,
		&v.PublishedAt, &v.UpdatedAt, &v.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("vuln detail: %w", err)
	}

	if len(affectedJSON) > 0 {
		json.Unmarshal(affectedJSON, &v.AffectedProducts)
	}
	if len(refsJSON) > 0 {
		json.Unmarshal(refsJSON, &v.ReferenceURLs)
	}

	return &v, nil
}

// --- Intelligence Overview ---

// ActorSummary represents a threat actor with activity metrics.
type ActorSummary struct {
	EntityID       string    `json:"entityId"`
	Name           string    `json:"name"`
	ThreatLevel    string    `json:"threatLevel"`
	RecentFindings int       `json:"recentFindings"`
	LinkedMalware  []string  `json:"linkedMalware"`
	LinkedInfra    int       `json:"linkedInfra"`
	LastSeen       time.Time `json:"lastSeen"`
	LatestNote     *string   `json:"latestNote,omitempty"`
}

// CampaignSummary represents an active correlation campaign.
type CampaignSummary struct {
	ClusterID       string    `json:"clusterId"`
	CorrelationType string    `json:"correlationType"`
	Confidence      float64   `json:"confidence"`
	Method          string    `json:"method"`
	EntityNames     []string  `json:"entityNames"`
	FindingCount    int       `json:"findingCount"`
	CreatedAt       time.Time `json:"createdAt"`
}

// OverviewMetrics holds key counts for the intelligence overview.
type OverviewMetrics struct {
	TotalFindings         int64 `json:"totalFindings"`
	ActiveIOCs            int64 `json:"activeIocs"`
	ConfirmedCorrelations int64 `json:"confirmedCorrelations"`
	AnalyticalNotes       int64 `json:"analyticalNotes"`
	TrackedActors         int64 `json:"trackedActors"`
	TrackedVulns          int64 `json:"trackedVulns"`
	KEVCount              int64 `json:"kevCount"`
}

// BriefSummary is a compact latest brief for the overview.
type BriefSummary struct {
	ID               string    `json:"id"`
	Title            string    `json:"title"`
	ExecutiveSummary string    `json:"executiveSummary"`
	GeneratedAt      time.Time `json:"generatedAt"`
}

// IntelligenceOverview is the full intelligence picture response.
type IntelligenceOverview struct {
	ActiveActors     []ActorSummary    `json:"activeActors"`
	ActiveCampaigns  []CampaignSummary `json:"activeCampaigns"`
	RecentNotes      []NoteListItem    `json:"recentNotes"`
	TrendingEntities []TrendingItem    `json:"trendingEntities"`
	TopVulns         []VulnListItem    `json:"topVulnerabilities"`
	LatestBrief      *BriefSummary     `json:"latestBrief,omitempty"`
	Metrics          OverviewMetrics   `json:"metrics"`
}

// TrendingItem is a compact trending entity for the overview.
type TrendingItem struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	MentionCount int64  `json:"mentionCount"`
	PrevCount    int64  `json:"prevCount"`
}

func queryIntelligenceOverview(ctx context.Context, pool *pgxpool.Pool) (*IntelligenceOverview, error) {
	overview := &IntelligenceOverview{}

	// 1. Metrics
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM raw_content WHERE classified = TRUE`).Scan(&overview.Metrics.TotalFindings)
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM iocs WHERE active = TRUE`).Scan(&overview.Metrics.ActiveIOCs)
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM correlations`).Scan(&overview.Metrics.ConfirmedCorrelations)
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM analytical_notes WHERE status = 'active'`).Scan(&overview.Metrics.AnalyticalNotes)
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM entities WHERE type = 'threat_actor'`).Scan(&overview.Metrics.TrackedActors)
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM vulnerabilities`).Scan(&overview.Metrics.TrackedVulns)
	pool.QueryRow(ctx, `SELECT COUNT(*) FROM vulnerabilities WHERE kev_listed = TRUE`).Scan(&overview.Metrics.KEVCount)

	// 2. Active threat actors
	actorRows, err := pool.Query(ctx, `
		SELECT e.id, COALESCE(e.properties->>'name', e.id),
		       COALESCE(e.properties->>'threat_level', 'unknown'),
		       COALESCE(e.updated_at, e.created_at)
		FROM entities e
		WHERE e.type = 'threat_actor'
		ORDER BY COALESCE(e.updated_at, e.created_at) DESC
		LIMIT 10`)
	if err == nil {
		defer actorRows.Close()
		for actorRows.Next() {
			var a ActorSummary
			if err := actorRows.Scan(&a.EntityID, &a.Name, &a.ThreatLevel, &a.LastSeen); err != nil {
				continue
			}

			// Count recent findings via edges
			pool.QueryRow(ctx, `
				SELECT COUNT(DISTINCT ed.target_id)
				FROM edges ed
				WHERE ed.source_id = $1
				AND ed.created_at > NOW() - INTERVAL '7 days'`, a.EntityID).Scan(&a.RecentFindings)

			// Linked malware
			malwareRows, _ := pool.Query(ctx, `
				SELECT COALESCE(e2.properties->>'name', e2.id)
				FROM edges ed
				JOIN entities e2 ON e2.id = ed.target_id
				WHERE ed.source_id = $1 AND e2.type = 'malware'
				LIMIT 5`, a.EntityID)
			if malwareRows != nil {
				for malwareRows.Next() {
					var name string
					if malwareRows.Scan(&name) == nil {
						a.LinkedMalware = append(a.LinkedMalware, name)
					}
				}
				malwareRows.Close()
			}
			if a.LinkedMalware == nil {
				a.LinkedMalware = []string{}
			}

			// Linked infra count
			pool.QueryRow(ctx, `
				SELECT COUNT(*)
				FROM edges ed
				JOIN entities e2 ON e2.id = ed.target_id
				WHERE ed.source_id = $1 AND e2.type IN ('ip', 'domain')`, a.EntityID).Scan(&a.LinkedInfra)

			// Latest note
			var noteContent string
			err := pool.QueryRow(ctx, `
				SELECT content FROM analytical_notes
				WHERE entity_id = $1 AND status = 'active'
				ORDER BY created_at DESC LIMIT 1`, a.EntityID).Scan(&noteContent)
			if err == nil {
				if len(noteContent) > 200 {
					noteContent = noteContent[:200] + "..."
				}
				a.LatestNote = &noteContent
			}

			overview.ActiveActors = append(overview.ActiveActors, a)
		}
	}
	if overview.ActiveActors == nil {
		overview.ActiveActors = []ActorSummary{}
	}

	// 3. Active campaigns (recent correlations)
	campaignRows, err := pool.Query(ctx, `
		SELECT cluster_id, correlation_type, confidence, method,
		       entity_ids, finding_ids, created_at
		FROM correlations
		WHERE confidence > 0.5
		ORDER BY created_at DESC
		LIMIT 10`)
	if err == nil {
		defer campaignRows.Close()
		for campaignRows.Next() {
			var c CampaignSummary
			var entityIDs, findingIDs []string
			if err := campaignRows.Scan(&c.ClusterID, &c.CorrelationType, &c.Confidence,
				&c.Method, &entityIDs, &findingIDs, &c.CreatedAt); err != nil {
				continue
			}
			c.FindingCount = len(findingIDs)

			// Resolve entity names
			for _, eid := range entityIDs {
				var name string
				err := pool.QueryRow(ctx, `SELECT COALESCE(properties->>'name', id) FROM entities WHERE id = $1`, eid).Scan(&name)
				if err == nil {
					c.EntityNames = append(c.EntityNames, name)
				}
			}
			if c.EntityNames == nil {
				c.EntityNames = []string{}
			}

			overview.ActiveCampaigns = append(overview.ActiveCampaigns, c)
		}
	}
	if overview.ActiveCampaigns == nil {
		overview.ActiveCampaigns = []CampaignSummary{}
	}

	// 4. Recent analytical notes
	noteRows, err := pool.Query(ctx, `
		SELECT id, finding_id, entity_id, correlation_id, note_type, title,
		       content, confidence, created_by, model_used, status, created_at
		FROM analytical_notes
		WHERE status = 'active'
		ORDER BY created_at DESC
		LIMIT 10`)
	if err == nil {
		defer noteRows.Close()
		for noteRows.Next() {
			var n NoteListItem
			if err := noteRows.Scan(&n.ID, &n.FindingID, &n.EntityID, &n.CorrelationID,
				&n.NoteType, &n.Title, &n.Content, &n.Confidence,
				&n.CreatedBy, &n.ModelUsed, &n.Status, &n.CreatedAt); err != nil {
				continue
			}
			overview.RecentNotes = append(overview.RecentNotes, n)
		}
	}
	if overview.RecentNotes == nil {
		overview.RecentNotes = []NoteListItem{}
	}

	// 5. Trending entities (last 7d vs previous 7d by edge activity)
	trendRows, err := pool.Query(ctx, `
		WITH current AS (
			SELECT e.id, e.type, COUNT(DISTINCT ed.source_id || ed.target_id) AS cnt
			FROM entities e
			JOIN edges ed ON ed.source_id = e.id OR ed.target_id = e.id
			WHERE ed.created_at > NOW() - INTERVAL '7 days'
			GROUP BY e.id, e.type
		),
		previous AS (
			SELECT e.id, COUNT(DISTINCT ed.source_id || ed.target_id) AS cnt
			FROM entities e
			JOIN edges ed ON ed.source_id = e.id OR ed.target_id = e.id
			WHERE ed.created_at BETWEEN NOW() - INTERVAL '14 days' AND NOW() - INTERVAL '7 days'
			GROUP BY e.id
		)
		SELECT c.id, c.type, c.cnt, COALESCE(p.cnt, 0)
		FROM current c
		LEFT JOIN previous p ON p.id = c.id
		ORDER BY c.cnt DESC
		LIMIT 10`)
	if err == nil {
		defer trendRows.Close()
		for trendRows.Next() {
			var t TrendingItem
			if err := trendRows.Scan(&t.ID, &t.Type, &t.MentionCount, &t.PrevCount); err != nil {
				continue
			}
			overview.TrendingEntities = append(overview.TrendingEntities, t)
		}
	}
	if overview.TrendingEntities == nil {
		overview.TrendingEntities = []TrendingItem{}
	}

	// 6. Top priority vulnerabilities
	vulnRows, err := pool.Query(ctx, `
		SELECT id, cve_id, description, cvss_v31_score, cvss_severity,
		       epss_score, epss_percentile,
		       kev_listed, kev_ransomware_use,
		       exploit_available, dark_web_mentions,
		       priority_score, priority_label,
		       published_at, updated_at
		FROM vulnerabilities
		ORDER BY priority_score DESC NULLS LAST
		LIMIT 10`)
	if err == nil {
		defer vulnRows.Close()
		for vulnRows.Next() {
			var v VulnListItem
			if err := vulnRows.Scan(
				&v.ID, &v.CVEID, &v.Description, &v.CVSSV31Score, &v.CVSSSeverity,
				&v.EPSSScore, &v.EPSSPercentile,
				&v.KEVListed, &v.KEVRansomwareUse,
				&v.ExploitAvailable, &v.DarkWebMentions,
				&v.PriorityScore, &v.PriorityLabel,
				&v.PublishedAt, &v.UpdatedAt,
			); err != nil {
				continue
			}
			overview.TopVulns = append(overview.TopVulns, v)
		}
	}
	if overview.TopVulns == nil {
		overview.TopVulns = []VulnListItem{}
	}

	// 7. Latest brief
	var brief BriefSummary
	err = pool.QueryRow(ctx, `
		SELECT id, title, executive_summary, generated_at
		FROM intelligence_briefs
		WHERE brief_type = 'daily'
		ORDER BY period_end DESC
		LIMIT 1`).Scan(&brief.ID, &brief.Title, &brief.ExecutiveSummary, &brief.GeneratedAt)
	if err == nil {
		overview.LatestBrief = &brief
	}

	return overview, nil
}
