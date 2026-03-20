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
	ID          string     `json:"id"`
	SourceType  string     `json:"sourceType"`
	SourceName  string     `json:"sourceName"`
	Category    *string    `json:"category"`
	Severity    *string    `json:"severity"`
	Summary     *string    `json:"summary"`
	Author      *string    `json:"author"`
	CollectedAt time.Time  `json:"collectedAt"`
	PostedAt    *time.Time `json:"postedAt"`
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
	ID             string    `json:"id"`
	Type           string    `json:"type"`
	Value          string    `json:"value"`
	Context        *string   `json:"context"`
	FirstSeen      time.Time `json:"firstSeen"`
	LastSeen       time.Time `json:"lastSeen"`
	SightingCount  int       `json:"sightingCount"`
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
	Category string
	Severity string
	Source   string
	Since    *time.Time
	Query    string
	Limit    int
	Offset   int
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
		SELECT id, source_type, source_name, category, severity, summary, author, collected_at, posted_at
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
		if err := rows.Scan(&fs.ID, &fs.SourceType, &fs.SourceName, &fs.Category, &fs.Severity, &fs.Summary, &fs.Author, &fs.CollectedAt, &fs.PostedAt); err != nil {
			return nil, fmt.Errorf("findings: scan: %w", err)
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
		SELECT id, type, value, context, first_seen, last_seen, sighting_count
		FROM iocs WHERE source_content_id = $1
		ORDER BY sighting_count DESC`, id)
	if err != nil {
		return nil, fmt.Errorf("finding iocs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ioc IOCItem
		if err := rows.Scan(&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Context, &ioc.FirstSeen, &ioc.LastSeen, &ioc.SightingCount); err != nil {
			return nil, fmt.Errorf("finding ioc scan: %w", err)
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
	Type   string
	Query  string
	Limit  int
	Offset int
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
		SELECT id, type, value, context, first_seen, last_seen, sighting_count
		FROM iocs %s
		ORDER BY last_seen DESC
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
		if err := rows.Scan(&ioc.ID, &ioc.Type, &ioc.Value, &ioc.Context, &ioc.FirstSeen, &ioc.LastSeen, &ioc.SightingCount); err != nil {
			return nil, fmt.Errorf("iocs scan: %w", err)
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
