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
