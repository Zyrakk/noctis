package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/models"
)

// userAgents is a pool of modern browser User-Agent strings for rotation.
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
}

// pastebinScrapeItem represents a single entry from the Pastebin scrape API.
type pastebinScrapeItem struct {
	ScrapeURL string `json:"scrape_url"`
	FullURL   string `json:"full_url"`
	Date      string `json:"date"`
	Key       string `json:"key"`
	Title     string `json:"title"`
	User      string `json:"user"`
}

// hrefPattern matches href attributes in anchor tags.
var hrefPattern = regexp.MustCompile(`<a\s[^>]*href=["']([^"']+)["']`)

// pasteIDPattern matches URL path segments that look like paste IDs:
// short alphanumeric strings (6-20 chars) as a path segment.
var pasteIDPattern = regexp.MustCompile(`^/[A-Za-z0-9]{6,20}$`)

// PasteCollector scrapes paste sites for threat intelligence.
type PasteCollector struct {
	cfg    *config.PasteConfig
	torCfg *config.TorConfig

	httpClient *http.Client
	torClient  *http.Client

	// pastebinListURL is the Pastebin scraping API endpoint.
	// Overridable for testing.
	pastebinListURL string

	mu   sync.Mutex
	seen map[string]bool

	uaIdx   int
	uaIdxMu sync.Mutex
}

// NewPasteCollector creates a PasteCollector from the given configuration.
func NewPasteCollector(cfg *config.PasteConfig, torCfg *config.TorConfig) *PasteCollector {
	pc := &PasteCollector{
		cfg:             cfg,
		torCfg:          torCfg,
		httpClient:      &http.Client{Timeout: 30 * time.Second},
		pastebinListURL: "https://scrape.pastebin.com/api_scraping.php?limit=50",
		seen:            make(map[string]bool),
	}

	// Attempt to build a Tor-routed client if configured.
	if torCfg != nil && torCfg.SocksProxy != "" {
		timeout := torCfg.RequestTimeout
		if timeout == 0 {
			timeout = 60 * time.Second
		}
		transport, err := NewTorTransport(torCfg.SocksProxy, timeout)
		if err != nil {
			log.Printf("[paste] warning: failed to create Tor transport: %v", err)
		} else {
			pc.torClient = &http.Client{
				Transport: transport,
				Timeout:   timeout,
			}
		}
	}

	return pc
}

// Name returns the collector's identifier.
func (pc *PasteCollector) Name() string {
	return "paste"
}

// Start runs the paste collector until ctx is cancelled.
// It closes the out channel on return.
func (pc *PasteCollector) Start(ctx context.Context, out chan<- models.Finding) error {
	defer close(out)

	var wg sync.WaitGroup

	if pc.cfg.Pastebin.Enabled {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pc.pollPastebin(ctx, out)
		}()
	}

	for i := range pc.cfg.Scrapers {
		sc := pc.cfg.Scrapers[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			pc.pollScraper(ctx, out, &sc)
		}()
	}

	wg.Wait()
	return nil
}

// rotateUA returns the next User-Agent string in a round-robin fashion.
func (pc *PasteCollector) rotateUA() string {
	pc.uaIdxMu.Lock()
	defer pc.uaIdxMu.Unlock()
	ua := userAgents[pc.uaIdx%len(userAgents)]
	pc.uaIdx++
	return ua
}

// markSeen returns true if the key was already seen, false otherwise.
// If not seen, it marks the key as seen.
func (pc *PasteCollector) markSeen(key string) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.seen[key] {
		return true
	}
	pc.seen[key] = true
	return false
}

// pollPastebin periodically fetches new pastes from the Pastebin scraping API.
func (pc *PasteCollector) pollPastebin(ctx context.Context, out chan<- models.Finding) {
	interval := pc.cfg.Pastebin.Interval
	if interval == 0 {
		interval = 60 * time.Second
	}

	// Fetch immediately on start.
	pc.fetchPastebinItems(ctx, out)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pc.fetchPastebinItems(ctx, out)
		}
	}
}

// fetchPastebinItems retrieves the list of recent pastes and fetches each one's content.
func (pc *PasteCollector) fetchPastebinItems(ctx context.Context, out chan<- models.Finding) {
	body, err := pc.doGet(ctx, pc.pastebinListURL, pc.httpClient)
	if err != nil {
		log.Printf("[paste] pastebin list fetch error: %v", err)
		return
	}

	var items []pastebinScrapeItem
	if err := json.Unmarshal(body, &items); err != nil {
		log.Printf("[paste] pastebin JSON parse error: %v", err)
		return
	}

	for _, item := range items {
		if ctx.Err() != nil {
			return
		}
		if item.Key == "" {
			continue
		}
		if pc.markSeen(item.Key) {
			continue
		}

		content, err := pc.doGet(ctx, item.ScrapeURL, pc.httpClient)
		if err != nil {
			log.Printf("[paste] pastebin content fetch error (key=%s): %v", item.Key, err)
			continue
		}

		f := models.NewFinding(models.SourceTypePaste, item.Key, "pastebin", string(content))
		f.Author = item.User
		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["title"] = item.Title
		f.Metadata["full_url"] = item.FullURL

		select {
		case out <- *f:
		case <-ctx.Done():
			return
		}
	}
}

// pollScraper periodically fetches a generic paste site and extracts paste links.
func (pc *PasteCollector) pollScraper(ctx context.Context, out chan<- models.Finding, sc *config.ScraperConfig) {
	interval := sc.Interval
	if interval == 0 {
		interval = 120 * time.Second
	}

	client := pc.clientFor(sc.Tor)

	// Fetch immediately on start.
	pc.fetchScraperPage(ctx, out, sc, client)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pc.fetchScraperPage(ctx, out, sc, client)
		}
	}
}

// fetchScraperPage fetches the index page from a scraper URL, extracts paste
// links, fetches each paste's content, and emits Findings.
func (pc *PasteCollector) fetchScraperPage(ctx context.Context, out chan<- models.Finding, sc *config.ScraperConfig, client *http.Client) {
	body, err := pc.doGet(ctx, sc.URL, client)
	if err != nil {
		log.Printf("[paste] scraper %q fetch error: %v", sc.Name, err)
		return
	}

	links := extractLinks(string(body), sc.URL)

	for _, link := range links {
		if ctx.Err() != nil {
			return
		}
		if pc.markSeen(link) {
			continue
		}

		content, err := pc.doGet(ctx, link, client)
		if err != nil {
			log.Printf("[paste] scraper %q content fetch error (%s): %v", sc.Name, link, err)
			continue
		}

		f := models.NewFinding(models.SourceTypePaste, link, sc.Name, string(content))
		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["url"] = link

		select {
		case out <- *f:
		case <-ctx.Done():
			return
		}
	}
}

// extractLinks parses HTML to find links that look like paste URLs.
func extractLinks(html, baseURL string) []string {
	// Normalise base URL: strip trailing slash.
	baseURL = strings.TrimRight(baseURL, "/")

	matches := hrefPattern.FindAllStringSubmatch(html, -1)
	var links []string
	seen := make(map[string]bool)

	for _, m := range matches {
		href := m[1]

		// Skip anchors, javascript, empty.
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
			continue
		}

		// Check if this looks like a paste link.
		if !isPasteLink(href) {
			continue
		}

		// Resolve relative URLs.
		fullURL := resolveURL(href, baseURL)

		if !seen[fullURL] {
			seen[fullURL] = true
			links = append(links, fullURL)
		}
	}

	return links
}

// isPasteLink returns true if the href looks like a paste link.
func isPasteLink(href string) bool {
	lower := strings.ToLower(href)

	// Explicit paste-related path segments.
	if strings.Contains(lower, "/paste") || strings.Contains(lower, "/raw") {
		return true
	}

	// Extract path part (strip any scheme/host prefix for relative URLs).
	path := href
	if idx := strings.Index(href, "://"); idx != -1 {
		rest := href[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
			path = rest[slashIdx:]
		} else {
			return false
		}
	}

	// Check if the path looks like a paste ID (short alphanumeric segment).
	return pasteIDPattern.MatchString(path)
}

// resolveURL resolves a potentially relative URL against a base URL.
func resolveURL(href, baseURL string) string {
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}
	if strings.HasPrefix(href, "/") {
		// Absolute path — find the scheme+host from baseURL.
		if idx := strings.Index(baseURL, "://"); idx != -1 {
			rest := baseURL[idx+3:]
			if slashIdx := strings.Index(rest, "/"); slashIdx != -1 {
				return baseURL[:idx+3+slashIdx] + href
			}
			return baseURL + href
		}
		return baseURL + href
	}
	return baseURL + "/" + href
}

// clientFor returns the Tor client if tor is true and available, otherwise the
// regular HTTP client.
func (pc *PasteCollector) clientFor(tor bool) *http.Client {
	if tor && pc.torClient != nil {
		return pc.torClient
	}
	return pc.httpClient
}

// doGet performs an HTTP GET request with User-Agent rotation and returns the
// response body. The caller is expected to handle []byte conversion.
func (pc *PasteCollector) doGet(ctx context.Context, url string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", url, err)
	}
	req.Header.Set("User-Agent", pc.rotateUA())
	req.Header.Set("Accept", "text/html,application/json,text/plain;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading body from %s: %w", url, err)
	}

	return body, nil
}
