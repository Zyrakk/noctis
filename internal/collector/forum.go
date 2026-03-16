package collector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/models"
)

// forumPost holds the content and author extracted from a single forum post.
type forumPost struct {
	Content string
	Author  string
}

// circuitBreaker tracks consecutive HTTP errors per forum and implements
// exponential backoff.
type circuitBreaker struct {
	consecutiveErrors int
	backoffDuration   time.Duration
}

const (
	circuitBreakerThreshold = 5
	circuitBreakerInitial   = 30 * time.Second
	circuitBreakerMax       = 1 * time.Hour
)

// ForumCollector scrapes underground forums for threat intelligence.
type ForumCollector struct {
	cfg    *config.ForumsConfig
	torCfg *config.TorConfig

	httpClient *http.Client
	torClient  *http.Client

	seen map[string]bool
	mu   sync.Mutex

	// Per-site circuit breakers persist across crawl cycles.
	breakers   map[string]*circuitBreaker
	breakersMu sync.Mutex

	uaIdx   int
	uaIdxMu sync.Mutex
}

// NewForumCollector creates a ForumCollector from the given configuration.
func NewForumCollector(cfg *config.ForumsConfig, torCfg *config.TorConfig) *ForumCollector {
	fc := &ForumCollector{
		cfg:        cfg,
		torCfg:     torCfg,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		seen:       make(map[string]bool),
		breakers:   make(map[string]*circuitBreaker),
	}

	if torCfg != nil && torCfg.SocksProxy != "" {
		timeout := torCfg.RequestTimeout
		if timeout == 0 {
			timeout = 60 * time.Second
		}
		transport, err := NewTorTransport(torCfg.SocksProxy, timeout)
		if err != nil {
			log.Printf("[forum] warning: failed to create Tor transport: %v", err)
		} else {
			fc.torClient = &http.Client{
				Transport: transport,
				Timeout:   timeout,
			}
		}
	}

	return fc
}

// Name returns the collector's identifier.
func (fc *ForumCollector) Name() string {
	return "forum"
}

// Start runs the forum collector until ctx is cancelled.
// It closes the out channel on return.
func (fc *ForumCollector) Start(ctx context.Context, out chan<- models.Finding) error {
	defer close(out)

	if !fc.cfg.Enabled {
		log.Printf("[forum] collector disabled")
		<-ctx.Done()
		return ctx.Err()
	}

	var wg sync.WaitGroup

	for i := range fc.cfg.Sites {
		site := fc.cfg.Sites[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			fc.pollForum(ctx, &site, out)
		}()
	}

	wg.Wait()
	return nil
}

// pollForum periodically crawls a single forum site.
func (fc *ForumCollector) pollForum(ctx context.Context, site *config.ForumConfig, out chan<- models.Finding) {
	interval := site.Interval
	if interval == 0 {
		interval = 5 * time.Minute
	}

	// Crawl immediately on start.
	fc.crawlForum(ctx, site, out)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fc.crawlForum(ctx, site, out)
		}
	}
}

// crawlForum performs a single crawl cycle of a forum site.
func (fc *ForumCollector) crawlForum(ctx context.Context, site *config.ForumConfig, out chan<- models.Finding) {
	// Cap dedup map to prevent unbounded growth. Archive handles true dedup via content_hash.
	fc.mu.Lock()
	if len(fc.seen) > 100000 {
		fc.seen = make(map[string]bool)
	}
	fc.mu.Unlock()
	cb := fc.getBreaker(site.Name)

	client := fc.clientFor(site)

	// Authenticate if login is configured.
	if site.Auth.LoginURL != "" {
		authedClient, err := fc.login(ctx, site, client)
		if err != nil {
			log.Printf("[forum] %s: login failed: %v", site.Name, err)
			return
		}
		client = authedClient
	}

	delay := site.RequestDelay
	if delay == 0 {
		delay = 3 * time.Second
	}

	maxPages := site.MaxPagesPerCrawl
	if maxPages <= 0 {
		maxPages = 5
	}

	// Collect thread URLs across paginated thread list pages.
	var threadURLs []string
	currentPageURL := site.URL
	pagesVisited := 0

	for currentPageURL != "" && pagesVisited < maxPages {
		if ctx.Err() != nil {
			return
		}

		doc, err := fc.fetchDocument(ctx, client, currentPageURL)
		if err != nil {
			log.Printf("[forum] %s: error fetching thread list %s: %v", site.Name, currentPageURL, err)
			if cb.recordError() {
				fc.backoff(ctx, cb, site.Name)
			}
			break
		}
		cb.reset()

		links := extractLinksGoquery(doc, site.Scraper.ThreadListSelector, currentPageURL)
		threadURLs = append(threadURLs, links...)

		// Follow pagination.
		nextPage := ""
		if site.Scraper.PaginationSelector != "" {
			nextLinks := extractLinksGoquery(doc, site.Scraper.PaginationSelector, currentPageURL)
			if len(nextLinks) > 0 {
				nextPage = nextLinks[len(nextLinks)-1]
			}
		}

		pagesVisited++
		currentPageURL = nextPage

		if currentPageURL != "" {
			fc.rateLimit(ctx, delay)
		}
	}

	// Scrape each thread page.
	for _, threadURL := range threadURLs {
		if ctx.Err() != nil {
			return
		}

		fc.rateLimit(ctx, delay)

		doc, err := fc.fetchDocument(ctx, client, threadURL)
		if err != nil {
			log.Printf("[forum] %s: error fetching thread %s: %v", site.Name, threadURL, err)
			if cb.recordError() {
				fc.backoff(ctx, cb, site.Name)
			}
			continue
		}
		cb.reset()

		posts := extractPosts(doc, site.Scraper.ThreadContentSelector, site.Scraper.AuthorSelector)

		// Collect all thread URLs found on this page for metadata.
		pageLinks := extractLinksGoquery(doc, "a[href]", threadURL)

		for _, post := range posts {
			if post.Content == "" {
				continue
			}

			hash := forumContentHash(post.Content)
			if fc.markSeen(hash) {
				continue
			}

			f := models.NewFinding(models.SourceTypeForum, threadURL, site.Name, post.Content)
			f.Author = post.Author
			if f.Metadata == nil {
				f.Metadata = make(map[string]string)
			}
			f.Metadata["thread_url"] = threadURL
			if len(pageLinks) > 0 {
				f.Metadata["extracted_links"] = strings.Join(pageLinks, ",")
			}

			select {
			case out <- *f:
			case <-ctx.Done():
				return
			}
		}
	}
}

// login authenticates to a forum and returns an HTTP client with session cookies.
func (fc *ForumCollector) login(ctx context.Context, site *config.ForumConfig, baseClient *http.Client) (*http.Client, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("creating cookie jar: %w", err)
	}

	// Build a client that inherits the transport from the base client but adds a cookie jar.
	client := &http.Client{
		Transport: baseClient.Transport,
		Timeout:   baseClient.Timeout,
		Jar:       jar,
	}

	usernameField := site.Auth.UsernameField
	if usernameField == "" {
		usernameField = "username"
	}
	passwordField := site.Auth.PasswordField
	if passwordField == "" {
		passwordField = "password"
	}

	formData := url.Values{
		usernameField: {site.Auth.Username},
		passwordField: {site.Auth.Password},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, site.Auth.LoginURL,
		strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", fc.rotateUA())

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("login POST to %s: %w", site.Auth.LoginURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("login failed with status %d", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("login failed with status %d", resp.StatusCode)
	}

	return client, nil
}

// fetchDocument fetches a URL and parses the HTML into a goquery document.
func (fc *ForumCollector) fetchDocument(ctx context.Context, client *http.Client, rawURL string) (*goquery.Document, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", fc.rotateUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", rawURL, resp.StatusCode)
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing HTML from %s: %w", rawURL, err)
	}

	return doc, nil
}

// extractLinksGoquery finds all elements matching selector, extracts href
// attributes, and resolves them against baseURL.
func extractLinksGoquery(doc *goquery.Document, selector, baseURL string) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}

	var links []string
	seen := make(map[string]bool)

	doc.Find(selector).Each(func(_ int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists || href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(href, "javascript:") {
			return
		}

		ref, err := url.Parse(href)
		if err != nil {
			return
		}

		resolved := base.ResolveReference(ref).String()
		if !seen[resolved] {
			seen[resolved] = true
			links = append(links, resolved)
		}
	})

	return links
}

// extractPosts finds all post elements and extracts content and author.
func extractPosts(doc *goquery.Document, contentSel, authorSel string) []forumPost {
	if contentSel == "" {
		return nil
	}

	var posts []forumPost

	// Find the nearest common parent that contains both content and author.
	// Strategy: for each content element, look for an author sibling within the
	// same parent container.
	doc.Find(contentSel).Each(func(_ int, s *goquery.Selection) {
		content := strings.TrimSpace(s.Text())
		author := ""

		if authorSel != "" {
			// Look for the author in the closest ancestor that also contains an author element.
			parent := s.Parent()
			for i := 0; i < 5; i++ {
				if parent.Length() == 0 {
					break
				}
				authorEl := parent.Find(authorSel).First()
				if authorEl.Length() > 0 {
					author = strings.TrimSpace(authorEl.Text())
					break
				}
				parent = parent.Parent()
			}
		}

		posts = append(posts, forumPost{
			Content: content,
			Author:  author,
		})
	})

	return posts
}

// clientFor returns the appropriate HTTP client for the given forum config.
func (fc *ForumCollector) clientFor(site *config.ForumConfig) *http.Client {
	if site.Tor && fc.torClient != nil {
		return fc.torClient
	}
	return fc.httpClient
}

// rotateUA returns the next User-Agent string in a round-robin fashion.
func (fc *ForumCollector) rotateUA() string {
	fc.uaIdxMu.Lock()
	defer fc.uaIdxMu.Unlock()
	ua := userAgents[fc.uaIdx%len(userAgents)]
	fc.uaIdx++
	return ua
}

// markSeen returns true if the hash was already seen, false otherwise.
func (fc *ForumCollector) markSeen(hash string) bool {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	if fc.seen[hash] {
		return true
	}
	fc.seen[hash] = true
	return false
}

// resetSeen clears the dedup map to prevent unbounded memory growth.
// Safe to call between crawl cycles since the archive handles true dedup.
func (fc *ForumCollector) resetSeen() {
	fc.mu.Lock()
	fc.seen = make(map[string]bool)
	fc.mu.Unlock()
}

// getBreaker returns the persistent circuit breaker for a given forum site.
func (fc *ForumCollector) getBreaker(siteName string) *circuitBreaker {
	fc.breakersMu.Lock()
	defer fc.breakersMu.Unlock()
	cb, ok := fc.breakers[siteName]
	if !ok {
		cb = &circuitBreaker{backoffDuration: circuitBreakerInitial}
		fc.breakers[siteName] = cb
	}
	return cb
}

// forumContentHash returns the hex SHA-256 of content for dedup purposes.
func forumContentHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", sum)
}

// rateLimit sleeps for the given duration, respecting context cancellation.
func (fc *ForumCollector) rateLimit(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-ctx.Done():
	}
}

// backoff sleeps for the circuit breaker's current backoff duration.
func (fc *ForumCollector) backoff(ctx context.Context, cb *circuitBreaker, forumName string) {
	log.Printf("[forum] %s: circuit breaker triggered, backing off %v", forumName, cb.backoffDuration)
	select {
	case <-time.After(cb.backoffDuration):
	case <-ctx.Done():
	}
	// Double backoff for next time, capped at max.
	cb.backoffDuration *= 2
	if cb.backoffDuration > circuitBreakerMax {
		cb.backoffDuration = circuitBreakerMax
	}
}

// recordError increments the consecutive error count.
// Returns true if the circuit breaker threshold has been reached.
func (cb *circuitBreaker) recordError() bool {
	cb.consecutiveErrors++
	return cb.consecutiveErrors >= circuitBreakerThreshold
}

// reset clears the consecutive error count and resets the backoff duration.
func (cb *circuitBreaker) reset() {
	cb.consecutiveErrors = 0
	cb.backoffDuration = circuitBreakerInitial
}
