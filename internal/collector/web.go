package collector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/mmcdole/gofeed"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/models"
)

// WebCollector collects threat intelligence from RSS feeds, web scraping,
// and search engine result parsing.
type WebCollector struct {
	cfg    *config.WebSourcesConfig
	torCfg *config.TorConfig

	httpClient *http.Client
	torClient  *http.Client

	seen map[string]bool
	mu   sync.Mutex

	uaIdx   int
	uaIdxMu sync.Mutex
}

// NewWebCollector creates a WebCollector from the given configuration.
func NewWebCollector(cfg *config.WebSourcesConfig, torCfg *config.TorConfig) *WebCollector {
	wc := &WebCollector{
		cfg:        cfg,
		torCfg:     torCfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		seen:       make(map[string]bool),
	}

	if torCfg != nil && torCfg.SocksProxy != "" {
		timeout := torCfg.RequestTimeout
		if timeout == 0 {
			timeout = 60 * time.Second
		}
		transport, err := NewTorTransport(torCfg.SocksProxy, timeout)
		if err != nil {
			log.Printf("[web] warning: failed to create Tor transport: %v", err)
		} else {
			wc.torClient = &http.Client{
				Transport: transport,
				Timeout:   timeout,
			}
		}
	}

	return wc
}

// Name returns the collector's identifier.
func (wc *WebCollector) Name() string {
	return "web"
}

// Start runs the web collector until ctx is cancelled.
// It closes the out channel on return.
func (wc *WebCollector) Start(ctx context.Context, out chan<- models.Finding) error {
	defer close(out)

	if !wc.cfg.Enabled {
		log.Printf("[web] collector disabled")
		<-ctx.Done()
		return ctx.Err()
	}

	var wg sync.WaitGroup

	for i := range wc.cfg.Feeds {
		feed := wc.cfg.Feeds[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch feed.Type {
			case "rss":
				wc.pollRSS(ctx, &feed, out)
			case "scrape":
				wc.pollScrape(ctx, &feed, out)
			case "search":
				wc.pollSearch(ctx, &feed, out)
			default:
				log.Printf("[web] unknown feed type %q for %s", feed.Type, feed.Name)
			}
		}()
	}

	wg.Wait()
	return nil
}

// pollRSS periodically fetches and parses an RSS/Atom feed.
func (wc *WebCollector) pollRSS(ctx context.Context, feedCfg *config.WebConfig, out chan<- models.Finding) {
	interval := feedCfg.Interval
	if interval == 0 {
		interval = 5 * time.Minute
	}

	client := wc.clientFor(feedCfg.Tor)

	// Fetch immediately on start.
	wc.fetchRSS(ctx, feedCfg, client, out)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wc.fetchRSS(ctx, feedCfg, client, out)
		}
	}
}

// fetchRSS fetches an RSS/Atom feed URL and emits Findings for each item.
func (wc *WebCollector) fetchRSS(ctx context.Context, feedCfg *config.WebConfig, client *http.Client, out chan<- models.Finding) {
	// Cap dedup map to prevent unbounded growth. Archive handles true dedup.
	wc.mu.Lock()
	if len(wc.seen) > 100000 {
		wc.seen = make(map[string]bool)
	}
	wc.mu.Unlock()
	body, err := wc.doGet(ctx, feedCfg.URL, client)
	if err != nil {
		log.Printf("[web] RSS feed %q fetch error: %v", feedCfg.Name, err)
		return
	}

	fp := gofeed.NewParser()
	feed, err := fp.Parse(strings.NewReader(string(body)))
	if err != nil {
		log.Printf("[web] RSS feed %q parse error: %v", feedCfg.Name, err)
		return
	}

	for _, item := range feed.Items {
		if ctx.Err() != nil {
			return
		}

		content := item.Description
		if content == "" {
			content = item.Content
		}
		if content == "" {
			continue
		}

		hash := webContentHash(content)
		if wc.markSeen(hash) {
			continue
		}

		f := models.NewFinding(models.SourceTypeWeb, feedCfg.URL, feedCfg.Name, content)

		if item.Author != nil {
			f.Author = item.Author.Name
			if f.Author == "" {
				f.Author = item.Author.Email
			}
		}
		// Fallback: some feeds put author in Authors slice.
		if f.Author == "" && len(item.Authors) > 0 && item.Authors[0] != nil {
			f.Author = item.Authors[0].Name
			if f.Author == "" {
				f.Author = item.Authors[0].Email
			}
		}

		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		if item.Link != "" {
			f.Metadata["url"] = item.Link
		}
		if item.Title != "" {
			f.Metadata["title"] = item.Title
		}
		if item.PublishedParsed != nil {
			f.Timestamp = *item.PublishedParsed
		}

		select {
		case out <- *f:
		case <-ctx.Done():
			return
		}
	}
}

// pollScrape periodically fetches a web page and extracts content using a CSS selector.
func (wc *WebCollector) pollScrape(ctx context.Context, feedCfg *config.WebConfig, out chan<- models.Finding) {
	interval := feedCfg.Interval
	if interval == 0 {
		interval = 5 * time.Minute
	}

	client := wc.clientFor(feedCfg.Tor)

	// Fetch immediately on start.
	wc.fetchScrape(ctx, feedCfg, client, out)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wc.fetchScrape(ctx, feedCfg, client, out)
		}
	}
}

// fetchScrape fetches a web page, selects elements by CSS selector, and emits Findings.
func (wc *WebCollector) fetchScrape(ctx context.Context, feedCfg *config.WebConfig, client *http.Client, out chan<- models.Finding) {
	if feedCfg.ContentSelector == "" {
		log.Printf("[web] scrape feed %q has no contentSelector", feedCfg.Name)
		return
	}

	body, err := wc.doGet(ctx, feedCfg.URL, client)
	if err != nil {
		log.Printf("[web] scrape feed %q fetch error: %v", feedCfg.Name, err)
		return
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		log.Printf("[web] scrape feed %q HTML parse error: %v", feedCfg.Name, err)
		return
	}

	doc.Find(feedCfg.ContentSelector).Each(func(_ int, s *goquery.Selection) {
		if ctx.Err() != nil {
			return
		}

		content := strings.TrimSpace(s.Text())
		if content == "" {
			return
		}

		hash := webContentHash(content)
		if wc.markSeen(hash) {
			return
		}

		f := models.NewFinding(models.SourceTypeWeb, feedCfg.URL, feedCfg.Name, content)
		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["url"] = feedCfg.URL

		select {
		case out <- *f:
		case <-ctx.Done():
		}
	})
}

// pollSearch periodically runs search queries and extracts results.
func (wc *WebCollector) pollSearch(ctx context.Context, feedCfg *config.WebConfig, out chan<- models.Finding) {
	interval := feedCfg.Interval
	if interval == 0 {
		interval = 15 * time.Minute
	}

	client := wc.clientFor(feedCfg.Tor)

	// Fetch immediately on start.
	wc.fetchSearch(ctx, feedCfg, client, out)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wc.fetchSearch(ctx, feedCfg, client, out)
		}
	}
}

// fetchSearch runs each configured query against the URL template and extracts results.
func (wc *WebCollector) fetchSearch(ctx context.Context, feedCfg *config.WebConfig, client *http.Client, out chan<- models.Finding) {
	for _, query := range feedCfg.Queries {
		if ctx.Err() != nil {
			return
		}

		searchURL := strings.ReplaceAll(feedCfg.URL, "{query}", url.QueryEscape(query))

		body, err := wc.doGet(ctx, searchURL, client)
		if err != nil {
			log.Printf("[web] search %q query %q fetch error: %v", feedCfg.Name, query, err)
			continue
		}

		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		if err != nil {
			log.Printf("[web] search %q query %q parse error: %v", feedCfg.Name, query, err)
			continue
		}

		// Extract all links from the search results page.
		base, err := url.Parse(searchURL)
		if err != nil {
			continue
		}

		var resultLinks []string
		doc.Find("a[href]").Each(func(_ int, s *goquery.Selection) {
			href, exists := s.Attr("href")
			if !exists || href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
				return
			}
			ref, err := url.Parse(href)
			if err != nil {
				return
			}
			resolved := base.ResolveReference(ref).String()
			resultLinks = append(resultLinks, resolved)
		})

		// Cap results to prevent fetching hundreds of nav/footer links.
		const maxSearchResults = 20
		if len(resultLinks) > maxSearchResults {
			resultLinks = resultLinks[:maxSearchResults]
		}

		// Fetch each result link and extract text content.
		for _, link := range resultLinks {
			if ctx.Err() != nil {
				return
			}

			hash := webContentHash(link)
			if wc.markSeen(hash) {
				continue
			}

			resultBody, err := wc.doGet(ctx, link, client)
			if err != nil {
				log.Printf("[web] search %q result fetch error (%s): %v", feedCfg.Name, link, err)
				continue
			}

			resultDoc, err := goquery.NewDocumentFromReader(strings.NewReader(string(resultBody)))
			if err != nil {
				continue
			}

			content := strings.TrimSpace(resultDoc.Find("body").Text())
			if content == "" {
				continue
			}

			f := models.NewFinding(models.SourceTypeWeb, link, feedCfg.Name, content)
			if f.Metadata == nil {
				f.Metadata = make(map[string]string)
			}
			f.Metadata["query"] = query
			f.Metadata["url"] = link
			f.Metadata["extracted_links"] = strings.Join(resultLinks, ",")

			select {
			case out <- *f:
			case <-ctx.Done():
				return
			}
		}
	}
}

// clientFor returns the Tor client if tor is true and available, otherwise the
// regular HTTP client.
func (wc *WebCollector) clientFor(tor bool) *http.Client {
	if tor && wc.torClient != nil {
		return wc.torClient
	}
	return wc.httpClient
}

// rotateUA returns the next User-Agent string in a round-robin fashion.
func (wc *WebCollector) rotateUA() string {
	wc.uaIdxMu.Lock()
	defer wc.uaIdxMu.Unlock()
	ua := userAgents[wc.uaIdx%len(userAgents)]
	wc.uaIdx++
	return ua
}

// markSeen returns true if the hash was already seen, false otherwise.
func (wc *WebCollector) markSeen(hash string) bool {
	wc.mu.Lock()
	defer wc.mu.Unlock()
	if wc.seen[hash] {
		return true
	}
	wc.seen[hash] = true
	return false
}

// resetSeen clears the dedup map to prevent unbounded memory growth.
func (wc *WebCollector) resetSeen() {
	wc.mu.Lock()
	wc.seen = make(map[string]bool)
	wc.mu.Unlock()
}

// doGet performs an HTTP GET request with User-Agent rotation and returns the
// response body.
func (wc *WebCollector) doGet(ctx context.Context, rawURL string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", wc.rotateUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", rawURL, resp.StatusCode)
	}

	// Cap response size at 10 MB to prevent memory exhaustion from large/malicious responses.
	const maxResponseBytes = 10 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading body from %s: %w", rawURL, err)
	}

	return body, nil
}

// webContentHash returns the hex SHA-256 of content for dedup purposes.
func webContentHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", sum)
}
