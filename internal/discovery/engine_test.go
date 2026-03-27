package discovery

import (
	"testing"

	"github.com/Zyrakk/noctis/internal/config"
)

// newTestEngine creates an Engine with discovery enabled and no DB pool
// (nil pool is fine for extraction/classification tests).
func newTestEngine() *Engine {
	return NewEngine(nil, config.DiscoveryConfig{
		Enabled:     true,
		AutoApprove: false,
	})
}

// TestExtractURLs_TelegramLinks verifies that both channel and group
// invite Telegram links are extracted from content.
func TestExtractURLs_TelegramLinks(t *testing.T) {
	e := newTestEngine()

	content := "Join our channel https://t.me/darkleaks and group t.me/joinchat/abc123xyz"
	urls := e.ExtractURLs(content)

	want := map[string]bool{
		"https://t.me/darkleaks":    false,
		"t.me/joinchat/abc123xyz":   false,
	}

	for _, u := range urls {
		if _, ok := want[u]; ok {
			want[u] = true
		}
	}

	for u, found := range want {
		if !found {
			t.Errorf("expected URL %q not found in extracted URLs: %v", u, urls)
		}
	}
}

// TestExtractURLs_OnionURLs verifies that .onion URLs are extracted.
func TestExtractURLs_OnionURLs(t *testing.T) {
	e := newTestEngine()

	content := "Check the forum at http://abc2345678901234567.onion/forum/thread"
	urls := e.ExtractURLs(content)

	found := false
	for _, u := range urls {
		if u == "http://abc2345678901234567.onion/forum/thread" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("onion URL not found in extracted URLs: %v", urls)
	}
}

// TestExtractURLs_PastebinURLs verifies that pastebin, rentry, and
// privatebin URLs are extracted.
func TestExtractURLs_PastebinURLs(t *testing.T) {
	e := newTestEngine()

	content := `
Dump at https://pastebin.com/abc123
Mirror: https://rentry.co/xyz789
Also: https://privatebin.net/p12345
`
	urls := e.ExtractURLs(content)

	want := map[string]bool{
		"https://pastebin.com/abc123":   false,
		"https://rentry.co/xyz789":      false,
		"https://privatebin.net/p12345": false,
	}

	for _, u := range urls {
		if _, ok := want[u]; ok {
			want[u] = true
		}
	}

	for u, found := range want {
		if !found {
			t.Errorf("expected URL %q not found in extracted URLs: %v", u, urls)
		}
	}
}

// TestExtractURLs_Mixed verifies that multiple URL types are all extracted
// and deduplicated when the same URL appears more than once.
func TestExtractURLs_Mixed(t *testing.T) {
	e := newTestEngine()

	content := `
Links:
- https://t.me/darkleaks
- https://pastebin.com/abc123
- https://example.com/page
- https://t.me/darkleaks
- http://abcdef1234567890abcdef.onion/market
`
	urls := e.ExtractURLs(content)

	// Check deduplication: count occurrences of t.me/darkleaks.
	count := 0
	for _, u := range urls {
		if u == "https://t.me/darkleaks" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected https://t.me/darkleaks exactly once, got %d times in %v", count, urls)
	}

	// Should have at least 4 unique URLs.
	if len(urls) < 4 {
		t.Errorf("expected at least 4 unique URLs, got %d: %v", len(urls), urls)
	}
}

// TestExtractURLs_NoURLs verifies that plain text with no URLs returns
// an empty result.
func TestExtractURLs_NoURLs(t *testing.T) {
	e := newTestEngine()

	content := "This is just plain text with no links at all. Nothing to see here."
	urls := e.ExtractURLs(content)

	if len(urls) != 0 {
		t.Errorf("expected no URLs, got %v", urls)
	}
}

// TestClassifySource_Telegram verifies that a regular t.me link is
// classified as telegram_channel.
func TestClassifySource_Telegram(t *testing.T) {
	got := classifySource("https://t.me/darkleaks")
	if got != "telegram_channel" {
		t.Errorf("classifySource(t.me/darkleaks) = %q, want %q", got, "telegram_channel")
	}
}

// TestClassifySource_TelegramGroup verifies that joinchat and + invite
// links are classified as telegram_group.
func TestClassifySource_TelegramGroup(t *testing.T) {
	tests := []string{
		"https://t.me/joinchat/abc123",
		"https://t.me/+xyz789",
	}

	for _, url := range tests {
		got := classifySource(url)
		if got != "telegram_group" {
			t.Errorf("classifySource(%q) = %q, want %q", url, got, "telegram_group")
		}
	}
}

// TestClassifySource_Onion verifies that .onion URLs are classified as forum.
func TestClassifySource_Onion(t *testing.T) {
	got := classifySource("http://abcdef1234567890.onion/forum")
	if got != "forum" {
		t.Errorf("classifySource(.onion) = %q, want %q", got, "forum")
	}
}

// TestClassifySource_Paste verifies that known paste sites are classified
// as paste_site.
func TestClassifySource_Paste(t *testing.T) {
	tests := []string{
		"https://pastebin.com/abc123",
		"https://ghostbin.co/paste/xyz",
		"https://privatebin.net/p12345",
		"https://rentry.co/abc",
	}

	for _, url := range tests {
		got := classifySource(url)
		if got != "paste_site" {
			t.Errorf("classifySource(%q) = %q, want %q", url, got, "paste_site")
		}
	}
}

// TestClassifySource_RSS verifies that feed-like URLs are classified as rss.
func TestClassifySource_RSS(t *testing.T) {
	tests := []string{
		"https://example.com/feed.xml",
		"https://example.com/feed",
		"https://example.com/rss",
		"https://example.com/atom",
	}

	for _, url := range tests {
		got := classifySource(url)
		if got != "rss" {
			t.Errorf("classifySource(%q) = %q, want %q", url, got, "rss")
		}
	}
}

// TestClassifySource_Web verifies that generic HTTP URLs default to web.
func TestClassifySource_Web(t *testing.T) {
	got := classifySource("https://example.com/page")
	if got != "web" {
		t.Errorf("classifySource(example.com/page) = %q, want %q", got, "web")
	}
}

// TestEngine_Construction verifies that NewEngine compiles regexes and
// stores the configuration.
func TestEngine_Construction(t *testing.T) {
	cfg := config.DiscoveryConfig{
		Enabled:     true,
		AutoApprove: true,
	}

	e := NewEngine(nil, cfg)

	if e.config.Enabled != true {
		t.Error("expected Enabled to be true")
	}
	if e.config.AutoApprove != true {
		t.Error("expected AutoApprove to be true")
	}
	if len(e.urlRegexes) != 4 {
		t.Errorf("expected 4 compiled regexes, got %d", len(e.urlRegexes))
	}
}

// newBlacklistEngine creates an Engine with the default domain blacklist.
func newBlacklistEngine() *Engine {
	return NewEngine(nil, config.DiscoveryConfig{
		Enabled: true,
		DomainBlacklist: []string{
			"nvd.nist.gov",
			"cwe.mitre.org",
			"first.org",
			"github.com",
			"wikipedia.org",
			"siemens.com",
			"honeywell.com",
		},
	})
}

// TestIsBlacklisted_MatchesDomain verifies that URLs on blacklisted
// domains are correctly identified.
func TestIsBlacklisted_MatchesDomain(t *testing.T) {
	e := newBlacklistEngine()

	blocked := []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
		"https://cwe.mitre.org/data/definitions/79.html",
		"https://www.first.org/cvss/calculator/3.1",
		"https://github.com/some/repo",
		"https://en.wikipedia.org/wiki/SQL_injection",
		"https://siemens.com/advisory/ssa-123456",
		"https://honeywell.com/security",
	}

	for _, u := range blocked {
		if !e.isBlacklisted(u) {
			t.Errorf("expected %q to be blacklisted", u)
		}
	}
}

// TestIsBlacklisted_AllowsLegitSources verifies that non-blacklisted
// URLs pass through.
func TestIsBlacklisted_AllowsLegitSources(t *testing.T) {
	e := newBlacklistEngine()

	allowed := []string{
		"https://pastebin.com/abc123",
		"https://t.me/darkleaks",
		"https://example.com/feed.xml",
		"http://abc2345678901234567.onion/forum",
	}

	for _, u := range allowed {
		if e.isBlacklisted(u) {
			t.Errorf("expected %q to NOT be blacklisted", u)
		}
	}
}

// TestIsBlacklisted_SubdomainMatch verifies that subdomains of blacklisted
// domains are also blocked.
func TestIsBlacklisted_SubdomainMatch(t *testing.T) {
	e := newBlacklistEngine()

	if !e.isBlacklisted("https://web.nvd.nist.gov/view/vuln/detail") {
		t.Error("expected subdomain of nvd.nist.gov to be blacklisted")
	}
}

// TestIsBlacklisted_BareScheme verifies that bare "https://" with no
// host is rejected.
func TestIsBlacklisted_BareScheme(t *testing.T) {
	e := newBlacklistEngine()

	if !e.isBlacklisted("https://") {
		t.Error("expected bare https:// to be blacklisted")
	}
}

// TestIsBlacklisted_EmptyBlacklist verifies that an engine with no
// blacklist allows all valid URLs through.
func TestIsBlacklisted_EmptyBlacklist(t *testing.T) {
	e := newTestEngine()

	if e.isBlacklisted("https://nvd.nist.gov/vuln/detail/CVE-2024-1234") {
		t.Error("with empty blacklist, no URLs should be blocked")
	}
}

// TestNilIfEmpty verifies the nilIfEmpty helper returns nil for empty
// strings and a pointer for non-empty strings.
func TestNilIfEmpty(t *testing.T) {
	if nilIfEmpty("") != nil {
		t.Error("nilIfEmpty(\"\") should return nil")
	}

	got := nilIfEmpty("abc")
	if got == nil || *got != "abc" {
		t.Errorf("nilIfEmpty(\"abc\") = %v, want pointer to \"abc\"", got)
	}
}

// TestNormalizeTelegramURL_StripMessageID verifies that telegram channel
// URLs are normalized to bare usernames.
func TestNormalizeTelegramURL_StripMessageID(t *testing.T) {
	e := newTestEngine()

	tests := []struct {
		input string
		want  string
	}{
		{"https://t.me/darkleaks/456", "darkleaks"},
		{"https://t.me/darkleaks/123456", "darkleaks"},
		{"t.me/darkleaks/99", "darkleaks"},
		{"https://t.me/darkleaks", "darkleaks"},       // no message ID
		{"https://t.me/darkleaks/", "darkleaks"},      // trailing slash only
		{"https://t.me/joinchat/abc123", "https://t.me/joinchat/abc123"}, // invite link unchanged
		{"https://t.me/+xyz789", "https://t.me/+xyz789"},           // group invite unchanged
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := e.normalizeTelegramURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeTelegramURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestNormalizeTelegramURL_SkipBots verifies that bot usernames are filtered.
func TestNormalizeTelegramURL_SkipBots(t *testing.T) {
	e := newTestEngine()

	bots := []string{
		"https://t.me/zerohexbot",
		"https://t.me/SomeToolBot",
		"https://t.me/MyBot",
		"t.me/testbot",
	}

	for _, u := range bots {
		t.Run(u, func(t *testing.T) {
			got := e.normalizeTelegramURL(u)
			if got != "" {
				t.Errorf("normalizeTelegramURL(%q) = %q, want empty (bot should be skipped)", u, got)
			}
		})
	}
}

// TestNormalizeTelegramURL_SkipMonitored verifies that channels already
// in config are skipped.
func TestNormalizeTelegramURL_SkipMonitored(t *testing.T) {
	e := newTestEngine()
	e.SetMonitoredChannels([]string{"ad_poheque", "RalfHackerChannel"})

	tests := []struct {
		input string
		want  string
	}{
		{"https://t.me/ad_poheque", ""},
		{"https://t.me/ad_poheque/123", ""},
		{"https://t.me/RalfHackerChannel", ""},
		{"https://t.me/ralfhackerchannel/456", ""},  // case-insensitive
		{"https://t.me/newchannel", "newchannel"},     // not monitored — keep
		{"https://t.me/newchannel/789", "newchannel"}, // not monitored — strip msg ID
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := e.normalizeTelegramURL(tt.input)
			if got != tt.want {
				t.Errorf("normalizeTelegramURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// newAllowlistEngine creates an Engine with allowlist patterns and domains configured.
func newAllowlistEngine() *Engine {
	return NewEngine(nil, config.DiscoveryConfig{
		Enabled: true,
		AllowPatterns: []string{
			"*.onion",
			"pastebin.com",
			"ghostbin.*",
			"privatebin.*",
			"rentry.co",
		},
		AllowDomains: []string{
			"leakbase.la",
			"breachforums.st",
		},
	})
}

func TestMatchesAllowlist_OnionURL(t *testing.T) {
	e := newAllowlistEngine()
	if !e.matchesAllowlist("http://abc2345678901234567.onion/forum/thread") {
		t.Error("expected .onion URL to match allowlist")
	}
}

func TestMatchesAllowlist_PasteSite(t *testing.T) {
	e := newAllowlistEngine()
	tests := []string{
		"https://pastebin.com/abc123",
		"https://ghostbin.co/paste/xyz",
		"https://privatebin.net/p12345",
		"https://rentry.co/abc",
	}
	for _, u := range tests {
		if !e.matchesAllowlist(u) {
			t.Errorf("expected %q to match allowlist", u)
		}
	}
}

func TestMatchesAllowlist_TelegramLink(t *testing.T) {
	e := newAllowlistEngine()
	if !e.matchesAllowlist("https://t.me/darkleaks") {
		t.Error("expected t.me link to match allowlist")
	}
}

func TestMatchesAllowlist_AllowedDomain(t *testing.T) {
	e := newAllowlistEngine()
	if !e.matchesAllowlist("https://leakbase.la/threads/dump") {
		t.Error("expected allowDomains entry to match")
	}
	if !e.matchesAllowlist("https://breachforums.st/thread/123") {
		t.Error("expected allowDomains entry to match")
	}
}

func TestMatchesAllowlist_UnknownDomain(t *testing.T) {
	e := newAllowlistEngine()
	if e.matchesAllowlist("https://randomsite.com/page") {
		t.Error("expected unknown domain to NOT match allowlist")
	}
}

func TestProcessContent_StatusDetermination(t *testing.T) {
	e := newAllowlistEngine()

	// Allowlisted URL — should get "discovered" status
	if e.matchesAllowlist("https://pastebin.com/abc123") != true {
		t.Error("pastebin.com should be allowlisted")
	}

	// Unknown URL — should NOT match allowlist (goes to pending_triage)
	if e.matchesAllowlist("https://randomforum.xyz/thread/1") != false {
		t.Error("unknown domain should not match allowlist")
	}

	// Blacklisted URL — should be blocked
	eBlack := NewEngine(nil, config.DiscoveryConfig{
		Enabled:     true,
		AllowPatterns: []string{"*.onion"},
		DomainBlacklist: []string{"google.com"},
	})
	if !eBlack.isBlacklisted("https://google.com/search") {
		t.Error("google.com should be blacklisted")
	}
}

func TestIsAutoBlacklisted(t *testing.T) {
	e := newTestEngine()
	e.autoBlacklist = map[string]struct{}{
		"spam-domain.com":  {},
		"trash-forum.net":  {},
	}

	blocked := []string{
		"https://spam-domain.com/page",
		"https://sub.spam-domain.com/path",
		"https://trash-forum.net/thread/1",
	}
	for _, u := range blocked {
		if !e.isAutoBlacklisted(u) {
			t.Errorf("expected %q to be auto-blacklisted", u)
		}
	}

	allowed := []string{
		"https://legit-site.com/page",
		"https://pastebin.com/abc",
	}
	for _, u := range allowed {
		if e.isAutoBlacklisted(u) {
			t.Errorf("expected %q to NOT be auto-blacklisted", u)
		}
	}
}

func TestIsAutoBlacklisted_EmptyMap(t *testing.T) {
	e := newTestEngine()
	if e.isAutoBlacklisted("https://anything.com/page") {
		t.Error("empty auto-blacklist should not block anything")
	}
}

func TestIsDomainAllowed(t *testing.T) {
	e := newAllowlistEngine()

	allowed := []string{
		"leakbase.la",
		"breachforums.st",
		"sub.leakbase.la",
		"pastebin.com",
		"ghostbin.co",
		"ghostbin.net",
		"something.onion",
	}
	for _, d := range allowed {
		if !e.isDomainAllowed(d) {
			t.Errorf("expected domain %q to be allowed", d)
		}
	}

	blocked := []string{
		"randomsite.com",
		"spam-domain.com",
	}
	for _, d := range blocked {
		if e.isDomainAllowed(d) {
			t.Errorf("expected domain %q to NOT be allowed", d)
		}
	}
}

func TestExtractInviteHash(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://t.me/+rZSKKHihZjk1NDI0", "+rZSKKHihZjk1NDI0"},
		{"t.me/+abc123", "+abc123"},
		{"https://t.me/joinchat/abc123xyz", "+abc123xyz"},
		{"t.me/joinchat/XYZ789", "+XYZ789"},
		{"https://t.me/joinchat/abc123/", "+abc123"},
		{"https://t.me/publicchannel", ""},       // not an invite link
		{"https://example.com/page", ""},          // not a t.me link
		{"https://t.me/+rZSKK/extra", "+rZSKK"},  // strip trailing path — TrimSuffix only trims /
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractInviteHash(tt.input)
			if got != tt.want {
				t.Errorf("extractInviteHash(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestClassifySource_InviteLinkFormats(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://t.me/+rZSKKHihZjk1NDI0", "telegram_group"},
		{"t.me/joinchat/abc123", "telegram_group"},
		{"https://t.me/joinchat/XYZ", "telegram_group"},
		{"https://t.me/publicchannel", "telegram_channel"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := classifySource(tt.input)
			if got != tt.want {
				t.Errorf("classifySource(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
