// Package discovery implements the source discovery engine for Noctis. It
// extracts URLs from collected content, classifies them by source type, and
// manages the lifecycle of discovered sources in the database.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
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
	pool              *pgxpool.Pool
	config            config.DiscoveryConfig
	urlRegexes        []*regexp.Regexp     // compiled URL extraction patterns
	blacklistDomains  map[string]struct{}  // domains to skip during discovery
	allowDomains      map[string]struct{}  // domains that bypass triage
	monitoredChannels map[string]struct{}  // telegram usernames already in config (lowercase)
	autoBlacklist     map[string]struct{}  // learned blacklist from triage trash decisions
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

	// Hardcoded domains that should never be discovered as sources,
	// regardless of config. These are social media, URL shorteners,
	// search engines, and documentation sites.
	hardcoded := []string{
		"lnkd.in", "youtube.com", "youtu.be", "docs.google.com",
		"google.com", "linkedin.com", "twitter.com", "x.com",
		"discord.gg", "mega.nz", "boosty.to", "skillbox.ru",
		"habr.com", "medium.com", "yandex.com", "localhost",
		"127.0.0.1", "w3.org", "schemas.xmlsoap.org", "microsoft.com",
		"images.contentstack.io", "brighttalk.com", "paloaltonetworks.com",
	}
	blacklist := make(map[string]struct{}, len(cfg.DomainBlacklist)+len(hardcoded))
	for _, d := range hardcoded {
		blacklist[d] = struct{}{}
	}
	for _, d := range cfg.DomainBlacklist {
		blacklist[strings.ToLower(d)] = struct{}{}
	}

	allow := make(map[string]struct{}, len(cfg.AllowDomains))
	for _, d := range cfg.AllowDomains {
		allow[strings.ToLower(d)] = struct{}{}
	}

	// Normalize allow patterns to lowercase for case-insensitive matching.
	for i, p := range cfg.AllowPatterns {
		cfg.AllowPatterns[i] = strings.ToLower(p)
	}

	e := &Engine{
		pool:              pool,
		config:            cfg,
		urlRegexes:        regexes,
		blacklistDomains:  blacklist,
		allowDomains:      allow,
		monitoredChannels: make(map[string]struct{}),
		autoBlacklist:     make(map[string]struct{}),
	}

	// Pre-load learned blacklist from DB if available.
	if pool != nil {
		if err := e.LoadAutoBlacklist(context.Background()); err != nil {
			slog.Warn("discovery: failed to load auto-blacklist on startup", "error", err)
		}
	}

	return e
}

// SetMonitoredChannels registers Telegram channel usernames that are already
// in the config. Discovered t.me URLs matching these usernames are skipped
// to avoid creating duplicate sources.
func (e *Engine) SetMonitoredChannels(usernames []string) {
	e.monitoredChannels = make(map[string]struct{}, len(usernames))
	for _, u := range usernames {
		e.monitoredChannels[strings.ToLower(u)] = struct{}{}
	}
}

// autoBlacklistThreshold is the number of trash decisions a domain must
// accumulate before being auto-blacklisted.
const autoBlacklistThreshold = 3

// LoadAutoBlacklist reads domains from the discovered_blacklist table that
// have reached the trash threshold and populates the in-memory map.
func (e *Engine) LoadAutoBlacklist(ctx context.Context) error {
	rows, err := e.pool.Query(ctx,
		`SELECT domain FROM discovered_blacklist WHERE trash_count >= $1`,
		autoBlacklistThreshold,
	)
	if err != nil {
		return fmt.Errorf("discovery: load auto-blacklist: %w", err)
	}
	defer rows.Close()

	bl := make(map[string]struct{})
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return fmt.Errorf("discovery: scan auto-blacklist row: %w", err)
		}
		bl[domain] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("discovery: auto-blacklist rows: %w", err)
	}

	e.autoBlacklist = bl
	slog.Info("discovery: loaded auto-blacklist", "domains", len(bl))
	return nil
}

// RefreshAutoBlacklist reloads the auto-blacklist from the database. Called
// by the triage worker after each batch so newly blacklisted domains take
// effect immediately.
func (e *Engine) RefreshAutoBlacklist(ctx context.Context) {
	if err := e.LoadAutoBlacklist(ctx); err != nil {
		slog.Error("discovery: refresh auto-blacklist failed", "error", err)
	}
}

// isAutoBlacklisted returns true if the URL's domain appears in the learned
// auto-blacklist (domains trashed >= threshold times by triage).
func (e *Engine) isAutoBlacklisted(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return false
	}

	host := strings.ToLower(parsed.Hostname())
	for domain := range e.autoBlacklist {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// isDomainAllowed returns true if the domain is in the allowDomains set or
// matches any allow pattern. Used to prevent auto-blacklisting of explicitly
// allowed domains.
func (e *Engine) isDomainAllowed(domain string) bool {
	domain = strings.ToLower(domain)

	if _, ok := e.allowDomains[domain]; ok {
		return true
	}
	for d := range e.allowDomains {
		if strings.HasSuffix(domain, "."+d) {
			return true
		}
	}

	for _, pattern := range e.config.AllowPatterns {
		switch {
		case strings.HasPrefix(pattern, "*."):
			if strings.HasSuffix(domain, pattern[1:]) {
				return true
			}
		case strings.HasSuffix(pattern, ".*"):
			prefix := pattern[:len(pattern)-2]
			if domain == prefix || strings.HasPrefix(domain, prefix+".") {
				return true
			}
		default:
			if domain == pattern || strings.HasSuffix(domain, "."+pattern) {
				return true
			}
		}
	}

	return false
}

// normalizeTelegramURL cleans up a t.me URL for source storage:
//   - Strips message ID suffixes: t.me/channel/123 → t.me/channel
//   - Returns "" for bot usernames (ending in "bot", case-insensitive)
//   - Returns "" for usernames already in the monitored channels set
//
// Returns the cleaned URL or "" if it should be skipped.
func (e *Engine) normalizeTelegramURL(rawURL string) string {
	// Extract the path after t.me/
	lower := strings.ToLower(rawURL)
	idx := strings.Index(lower, "t.me/")
	if idx == -1 {
		return rawURL
	}

	path := rawURL[idx+5:] // everything after "t.me/"
	path = strings.TrimSuffix(path, "/")

	// Skip invite/group links — these are handled by classifySource separately
	if strings.HasPrefix(strings.ToLower(path), "joinchat/") || strings.HasPrefix(path, "+") {
		return rawURL
	}

	// Split on / — first segment is the username, rest is message ID or subpath
	parts := strings.SplitN(path, "/", 2)
	username := parts[0]

	if username == "" {
		return ""
	}

	// Skip bots
	if strings.HasSuffix(strings.ToLower(username), "bot") {
		return ""
	}

	// Skip channels already in config
	if _, monitored := e.monitoredChannels[strings.ToLower(username)]; monitored {
		return ""
	}

	// Return bare username — all telegram_channel identifiers are stored as
	// plain usernames for consistency with config channels.
	return username
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

// matchesAllowlist returns true if the URL matches any configured allow
// pattern or domain. Telegram links (t.me/*) are always allowed.
func (e *Engine) matchesAllowlist(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return false
	}

	host := strings.ToLower(parsed.Hostname())

	// Telegram links always pass.
	if host == "t.me" {
		return true
	}

	// Check exact allow domains.
	if _, ok := e.allowDomains[host]; ok {
		return true
	}
	// Check subdomain match against allow domains.
	for domain := range e.allowDomains {
		if strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	// Check allow patterns from config.
	for _, pattern := range e.config.AllowPatterns {
		switch {
		case strings.HasPrefix(pattern, "*."): // suffix match: *.onion
			suffix := pattern[1:] // ".onion"
			if strings.HasSuffix(host, suffix) {
				return true
			}
		case strings.HasSuffix(pattern, ".*"): // prefix match: ghostbin.*
			prefix := pattern[:len(pattern)-2] // "ghostbin"
			if host == prefix || strings.HasPrefix(host, prefix+".") {
				return true
			}
		default: // exact match: pastebin.com, rentry.co
			if host == pattern || strings.HasSuffix(host, "."+pattern) {
				return true
			}
		}
	}

	return false
}

// shouldSkipURL returns true for URLs that are clearly not useful intelligence
// sources: fuzzing templates, private IPs, truncated addresses, localhost, and
// URLs too short to be meaningful.
func shouldSkipURL(rawURL string) bool {
	// Skip fuzzing templates
	if strings.Contains(rawURL, "FUZZ") {
		return true
	}
	// Skip localhost references
	if strings.Contains(strings.ToLower(rawURL), "localhost") {
		return true
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true
	}

	host := parsed.Hostname()

	// Skip private/reserved IPs
	if ip := net.ParseIP(host); ip != nil {
		privateRanges := []string{"10.", "127.", "192.168.", "169.254.", "::1", "fe80:"}
		for _, prefix := range privateRanges {
			if strings.HasPrefix(host, prefix) {
				return true
			}
		}
		// 172.16.0.0/12
		if strings.HasPrefix(host, "172.") {
			parts := strings.SplitN(host, ".", 3)
			if len(parts) >= 2 {
				if octet, err := strconv.Atoi(parts[1]); err == nil && octet >= 16 && octet <= 31 {
					return true
				}
			}
		}
	}

	// Skip truncated IPs (like http://45.76.155 — only 3 octets, no path)
	if net.ParseIP(host) == nil && isPartialIP(host) {
		return true
	}

	// Skip image/media URLs
	imageExts := []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp"}
	lowerPath := strings.ToLower(parsed.Path)
	for _, ext := range imageExts {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}

	// Skip URLs too short to be meaningful (domain + less than 2 chars of path)
	path := strings.TrimRight(parsed.Path, "/")
	if len(path) < 2 && parsed.RawQuery == "" {
		return true
	}

	return false
}

// isPartialIP returns true for strings that look like truncated IP addresses
// (e.g., "45.76.155" — three numeric octets with no further path).
func isPartialIP(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	// 2 or 3 octets is a partial IP; 4 octets is handled by net.ParseIP
	return len(parts) < 4
}

// extractInviteHash extracts the invite hash from a t.me invite link and
// returns it in "+hash" format. Handles both t.me/+hash and t.me/joinchat/hash.
// Returns "" if the URL is not an invite link.
func extractInviteHash(rawURL string) string {
	lower := strings.ToLower(rawURL)
	idx := strings.Index(lower, "t.me/")
	if idx == -1 {
		return ""
	}

	path := rawURL[idx+5:]
	path = strings.TrimSuffix(path, "/")

	if strings.HasPrefix(path, "+") {
		// Strip any trailing subpath (e.g. "+hash/123" → "+hash").
		if slashIdx := strings.Index(path[1:], "/"); slashIdx != -1 {
			path = path[:slashIdx+1]
		}
		return path
	}
	if strings.HasPrefix(strings.ToLower(path), "joinchat/") {
		hash := path[9:]
		// Strip trailing subpath if present.
		if slashIdx := strings.Index(hash, "/"); slashIdx != -1 {
			hash = hash[:slashIdx]
		}
		return "+" + hash
	}
	return ""
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

	for _, u := range urls {
		if e.isBlacklisted(u) || e.isAutoBlacklisted(u) || shouldSkipURL(u) {
			slog.Debug("discovery: skipping filtered URL", "url", u)
			continue
		}

		srcType := classifySource(u)

		// Check allowlist before normalization (normalized identifiers like
		// "invite:+hash" are not parseable URLs).
		allowed := e.matchesAllowlist(u)

		// Normalize telegram URLs: strip message IDs, skip bots and monitored channels.
		if srcType == "telegram_channel" {
			u = e.normalizeTelegramURL(u)
			if u == "" {
				continue
			}
		}

		// Normalize invite links to "invite:+hash" identifier format.
		if srcType == "telegram_group" {
			hash := extractInviteHash(u)
			if hash == "" {
				continue
			}
			u = "invite:" + hash
		}

		// Three-tier status: allowlist -> discovered, unknown -> pending_triage.
		status := "pending_triage"
		if allowed {
			status = "discovered"
			if e.config.AutoApprove {
				status = "approved"
			}
		}

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

// RecordCollectionByIdentifier updates last_collected for a source matched
// by its identifier string. Returns nil silently if no row matches (e.g.
// config-only sources that have no DB record).
func (e *Engine) RecordCollectionByIdentifier(ctx context.Context, identifier string) error {
	if identifier == "" {
		return nil
	}
	_, err := e.pool.Exec(ctx, `
UPDATE sources SET last_collected = NOW(), error_count = 0, updated_at = NOW()
WHERE identifier = $1`, identifier)
	if err != nil {
		return fmt.Errorf("discovery: record collection by identifier %q: %w", identifier, err)
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
