// Package discovery implements the source discovery engine for Noctis. It
// extracts URLs from collected content, classifies them by source type, and
// manages the lifecycle of discovered sources in the database.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Zyrakk/noctis/internal/config"
)

// Source represents a row in the sources table. Each source is a threat
// intelligence feed endpoint (Telegram channel, forum, paste site, etc.)
// that Noctis may collect from.
type Source struct {
	ID                 string
	Type               string // telegram_channel, telegram_group, forum, paste_site, web, rss
	Identifier         string // unique key: channel username, URL, etc.
	Name               string
	Status             string // discovered, approved, active, paused, dead, banned
	DiscoveredFrom     string // source_content_id UUID
	LastCollected      *time.Time
	CollectionInterval string
	ErrorCount         int
	Metadata           map[string]interface{}
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Engine discovers new intelligence sources by extracting and classifying
// URLs found in collected content. It manages the full source lifecycle
// from discovery through approval and active collection.
type Engine struct {
	pool            *pgxpool.Pool
	config          config.DiscoveryConfig
	urlRegexes      []*regexp.Regexp    // compiled URL extraction patterns
	blacklistDomains map[string]struct{} // domains to skip during discovery
}

// NewEngine creates a discovery Engine with pre-compiled URL extraction
// regexes. The regexes are ordered so more specific patterns (onion,
// Telegram, pastebin) are tried before the generic HTTP catch-all.
func NewEngine(pool *pgxpool.Pool, cfg config.DiscoveryConfig) *Engine {
	regexes := []*regexp.Regexp{
		// .onion URLs
		regexp.MustCompile(`https?://[a-z2-7]{16,56}\.onion[/\S]*`),
		// Telegram invite/channel links
		regexp.MustCompile(`(?:https?://)?t\.me/(?:joinchat/|\+)?[A-Za-z0-9_]+`),
		// Pastebin-like sites
		regexp.MustCompile(`https?://(?:pastebin\.com|ghostbin\.\w+|privatebin\.\w+|rentry\.co)/[A-Za-z0-9]+`),
		// Generic HTTP(S) URLs (catch-all)
		regexp.MustCompile("https?://[^\\s<>\"{}|\\\\^`\\[\\]]+"),
	}

	blacklist := make(map[string]struct{}, len(cfg.DomainBlacklist))
	for _, d := range cfg.DomainBlacklist {
		blacklist[strings.ToLower(d)] = struct{}{}
	}

	return &Engine{
		pool:             pool,
		config:           cfg,
		urlRegexes:       regexes,
		blacklistDomains: blacklist,
	}
}

// ExtractURLs returns a deduplicated list of URLs found in the given content.
// It applies all compiled regexes in order and merges the results.
func (e *Engine) ExtractURLs(content string) []string {
	seen := make(map[string]struct{})
	var urls []string

	for _, re := range e.urlRegexes {
		for _, match := range re.FindAllString(content, -1) {
			// Strip trailing punctuation that is not part of URLs.
			match = strings.TrimRight(match, ".,;:!?)'\"")

			if _, exists := seen[match]; exists {
				continue
			}
			seen[match] = struct{}{}
			urls = append(urls, match)
		}
	}

	return urls
}

// isBlacklisted returns true if the URL's domain matches any entry in the
// domain blacklist, or if the URL is malformed (e.g. bare "https://").
func (e *Engine) isBlacklisted(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return true // malformed or bare scheme — skip
	}

	host := strings.ToLower(parsed.Hostname())
	for domain := range e.blacklistDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// classifySource determines the source type for a given URL using simple
// heuristic rules. No LLM call is needed for this classification.
func classifySource(url string) string {
	lower := strings.ToLower(url)

	switch {
	case strings.Contains(lower, "t.me/joinchat/") || strings.Contains(lower, "t.me/+"):
		return "telegram_group"
	case strings.Contains(lower, "t.me/"):
		return "telegram_channel"
	case strings.Contains(lower, ".onion"):
		return "forum"
	case strings.Contains(lower, "pastebin.com") ||
		strings.Contains(lower, "ghostbin.") ||
		strings.Contains(lower, "privatebin.") ||
		strings.Contains(lower, "rentry.co"):
		return "paste_site"
	case strings.HasSuffix(lower, ".xml") ||
		strings.Contains(lower, "/feed") ||
		strings.Contains(lower, "/rss") ||
		strings.Contains(lower, "/atom"):
		return "rss"
	default:
		return "web"
	}
}

// ProcessContent extracts URLs from content, classifies each one, and
// inserts newly discovered sources into the database. Existing sources
// (matched by identifier) are silently skipped.
func (e *Engine) ProcessContent(ctx context.Context, content string, sourceContentID string) error {
	if !e.config.Enabled {
		return nil
	}

	urls := e.ExtractURLs(content)
	if len(urls) == 0 {
		return nil
	}

	status := "discovered"
	if e.config.AutoApprove {
		status = "approved"
	}

	for _, u := range urls {
		if e.isBlacklisted(u) {
			slog.Debug("discovery: skipping blacklisted URL", "url", u)
			continue
		}

		srcType := classifySource(u)

		// Insert with ON CONFLICT to avoid N+1 existence checks.
		tag, err := e.pool.Exec(ctx, `
INSERT INTO sources (type, identifier, name, status, discovered_from, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (identifier) DO NOTHING`,
			srcType, u, u, status, nilIfEmpty(sourceContentID), []byte("{}"),
		)
		if err != nil {
			return fmt.Errorf("discovery: insert source %q: %w", u, err)
		}

		if tag.RowsAffected() > 0 {
			slog.Info("discovered new source",
				"identifier", u,
				"type", srcType,
				"status", status,
			)
		}
	}

	return nil
}

// ListSources returns sources filtered by status and/or type. Pass empty
// strings to skip a filter. Results are ordered newest-first.
func (e *Engine) ListSources(ctx context.Context, status string, sourceType string) ([]Source, error) {
	const query = `
SELECT id, type, identifier, name, status, discovered_from,
       last_collected, collection_interval, error_count, metadata,
       created_at, updated_at
FROM sources
WHERE (status = $1 OR $1 = '')
  AND (type = $2 OR $2 = '')
ORDER BY created_at DESC`

	rows, err := e.pool.Query(ctx, query, status, sourceType)
	if err != nil {
		return nil, fmt.Errorf("discovery: list sources: %w", err)
	}
	defer rows.Close()

	var sources []Source
	for rows.Next() {
		s, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("discovery: list sources rows: %w", err)
	}

	return sources, nil
}

// ApproveSource transitions a source from discovered to approved, making
// it eligible for collection.
func (e *Engine) ApproveSource(ctx context.Context, id string) error {
	return e.updateStatus(ctx, id, "approved")
}

// AddSource explicitly adds a new source with status "active". If a source
// with the same identifier already exists, it is reactivated (status set to
// "active"). Returns the source ID.
func (e *Engine) AddSource(ctx context.Context, sourceType, identifier string) (string, error) {
	var id string
	err := e.pool.QueryRow(ctx, `
INSERT INTO sources (type, identifier, name, status)
VALUES ($1, $2, $2, 'active')
ON CONFLICT (identifier) DO UPDATE SET status = 'active', updated_at = NOW()
RETURNING id`, sourceType, identifier).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("discovery: add source %q: %w", identifier, err)
	}
	return id, nil
}

// PauseSource pauses collection for a source.
func (e *Engine) PauseSource(ctx context.Context, id string) error {
	return e.updateStatus(ctx, id, "paused")
}

// MarkActive marks a source as actively being collected.
func (e *Engine) MarkActive(ctx context.Context, id string) error {
	return e.updateStatus(ctx, id, "active")
}

// RemoveSource permanently deletes a source from the database.
func (e *Engine) RemoveSource(ctx context.Context, id string) error {
	ct, err := e.pool.Exec(ctx, `DELETE FROM sources WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("discovery: remove source %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("discovery: remove source: no row with id %s", id)
	}
	return nil
}

// RecordCollection updates a source after a successful collection cycle,
// resetting the error count and recording the collection timestamp.
func (e *Engine) RecordCollection(ctx context.Context, id string) error {
	ct, err := e.pool.Exec(ctx, `
UPDATE sources SET last_collected = NOW(), error_count = 0, updated_at = NOW()
WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("discovery: record collection %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("discovery: record collection: no row with id %s", id)
	}
	return nil
}

// RecordError increments the error count for a source after a failed
// collection attempt.
func (e *Engine) RecordError(ctx context.Context, id string) error {
	ct, err := e.pool.Exec(ctx, `
UPDATE sources SET error_count = error_count + 1, updated_at = NOW()
WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("discovery: record error %s: %w", id, err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("discovery: record error: no row with id %s", id)
	}
	return nil
}

// GetApprovedSources returns all sources with status 'approved' or 'active'
// for the given source type.
func (e *Engine) GetApprovedSources(ctx context.Context, sourceType string) ([]Source, error) {
	const query = `
SELECT id, type, identifier, name, status, discovered_from,
       last_collected, collection_interval, error_count, metadata,
       created_at, updated_at
FROM sources
WHERE status IN ('approved', 'active')
  AND type = $1`

	rows, err := e.pool.Query(ctx, query, sourceType)
	if err != nil {
		return nil, fmt.Errorf("discovery: get approved sources: %w", err)
	}
	defer rows.Close()

	var sources []Source
	for rows.Next() {
		s, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("discovery: get approved sources rows: %w", err)
	}

	return sources, nil
}

// updateStatus is a helper that sets the status field and bumps updated_at.
func (e *Engine) updateStatus(ctx context.Context, id string, status string) error {
	ct, err := e.pool.Exec(ctx, `
UPDATE sources SET status = $2, updated_at = NOW()
WHERE id = $1`, id, status)
	if err != nil {
		return fmt.Errorf("discovery: update status %s to %q: %w", id, status, err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("discovery: update status: no row with id %s", id)
	}
	return nil
}

// scanner is a minimal interface satisfied by pgx.Rows so scanSource can
// be used for both Query and QueryRow result sets.
type scanner interface {
	Scan(dest ...interface{}) error
}

// scanSource reads a single row into a Source struct.
func scanSource(row scanner) (Source, error) {
	var s Source
	var metaJSON []byte
	var discoveredFrom *string

	err := row.Scan(
		&s.ID, &s.Type, &s.Identifier, &s.Name, &s.Status,
		&discoveredFrom, &s.LastCollected, &s.CollectionInterval,
		&s.ErrorCount, &metaJSON, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		return Source{}, fmt.Errorf("discovery: scan source: %w", err)
	}

	if discoveredFrom != nil {
		s.DiscoveredFrom = *discoveredFrom
	}

	if len(metaJSON) > 0 {
		if err := json.Unmarshal(metaJSON, &s.Metadata); err != nil {
			return Source{}, fmt.Errorf("discovery: unmarshal metadata: %w", err)
		}
	}

	return s, nil
}

// nilIfEmpty returns nil if s is empty, otherwise returns a pointer to s.
// Used to insert NULL into nullable UUID columns.
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
