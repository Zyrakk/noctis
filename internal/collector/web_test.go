package collector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/models"
)

const testRSSFeed = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
<channel>
  <title>Security Feed</title>
  <item>
    <title>New Ransomware Variant</title>
    <description>A new LockBit variant was observed targeting healthcare.</description>
    <link>https://example.com/article1</link>
    <author>researcher@example.com</author>
    <pubDate>Mon, 16 Mar 2026 10:00:00 GMT</pubDate>
  </item>
  <item>
    <title>CVE-2026-1234 Disclosed</title>
    <description>Critical vulnerability in Fortinet firewalls allows RCE.</description>
    <link>https://example.com/article2</link>
    <author>analyst@example.com</author>
    <pubDate>Mon, 16 Mar 2026 11:00:00 GMT</pubDate>
  </item>
</channel>
</rss>`

const testScrapeHTML = `<html><body>
<div class="breach-entry">Breach data: 50k records from example.com leaked</div>
<div class="breach-entry">Credential dump: admin@corp.com found on paste site</div>
<div class="other">Unrelated content</div>
</body></html>`

func TestWebCollector_RSS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, testRSSFeed)
	}))
	defer srv.Close()

	cfg := &config.WebSourcesConfig{
		Enabled: true,
		Feeds: []config.WebConfig{
			{
				Name:     "test-rss",
				URL:      srv.URL,
				Type:     "rss",
				Interval: 1 * time.Hour, // long interval; we only need one fetch
			},
		},
	}

	wc := NewWebCollector(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan models.Finding, 10)
	go wc.Start(ctx, out)

	findings := make(map[string]models.Finding)
	deadline := time.After(10 * time.Second)

	for len(findings) < 2 {
		select {
		case f := <-out:
			findings[f.Content] = f
		case <-deadline:
			t.Fatalf("timed out: got %d findings, expected 2", len(findings))
		}
	}

	cancel()

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check first item.
	f1, ok := findings["A new LockBit variant was observed targeting healthcare."]
	if !ok {
		t.Fatal("missing finding for LockBit article")
	}
	if f1.Source != models.SourceTypeWeb {
		t.Errorf("expected Source=%q, got %q", models.SourceTypeWeb, f1.Source)
	}
	if f1.SourceName != "test-rss" {
		t.Errorf("expected SourceName=%q, got %q", "test-rss", f1.SourceName)
	}
	if f1.Metadata["title"] != "New Ransomware Variant" {
		t.Errorf("expected title=%q, got %q", "New Ransomware Variant", f1.Metadata["title"])
	}
	if f1.Metadata["url"] != "https://example.com/article1" {
		t.Errorf("expected url=%q, got %q", "https://example.com/article1", f1.Metadata["url"])
	}
	if f1.Author != "researcher@example.com" {
		t.Errorf("expected Author=%q, got %q", "researcher@example.com", f1.Author)
	}

	// Check second item.
	f2, ok := findings["Critical vulnerability in Fortinet firewalls allows RCE."]
	if !ok {
		t.Fatal("missing finding for CVE article")
	}
	if f2.Metadata["title"] != "CVE-2026-1234 Disclosed" {
		t.Errorf("expected title=%q, got %q", "CVE-2026-1234 Disclosed", f2.Metadata["title"])
	}
	if f2.Author != "analyst@example.com" {
		t.Errorf("expected Author=%q, got %q", "analyst@example.com", f2.Author)
	}
}

func TestWebCollector_Scrape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, testScrapeHTML)
	}))
	defer srv.Close()

	cfg := &config.WebSourcesConfig{
		Enabled: true,
		Feeds: []config.WebConfig{
			{
				Name:            "test-scrape",
				URL:             srv.URL,
				Type:            "scrape",
				ContentSelector: ".breach-entry",
				Interval:        1 * time.Hour,
			},
		},
	}

	wc := NewWebCollector(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan models.Finding, 10)
	go wc.Start(ctx, out)

	findings := make(map[string]models.Finding)
	deadline := time.After(10 * time.Second)

	for len(findings) < 2 {
		select {
		case f := <-out:
			findings[f.Content] = f
		case <-deadline:
			t.Fatalf("timed out: got %d findings, expected 2", len(findings))
		}
	}

	cancel()

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1, ok := findings["Breach data: 50k records from example.com leaked"]
	if !ok {
		t.Fatal("missing finding for breach data")
	}
	if f1.Source != models.SourceTypeWeb {
		t.Errorf("expected Source=%q, got %q", models.SourceTypeWeb, f1.Source)
	}
	if f1.SourceName != "test-scrape" {
		t.Errorf("expected SourceName=%q, got %q", "test-scrape", f1.SourceName)
	}

	f2, ok := findings["Credential dump: admin@corp.com found on paste site"]
	if !ok {
		t.Fatal("missing finding for credential dump")
	}
	if f2.Source != models.SourceTypeWeb {
		t.Errorf("expected Source=%q, got %q", models.SourceTypeWeb, f2.Source)
	}
}

func TestWebCollector_Search(t *testing.T) {
	// Mock result pages with actual content.
	resultPage1 := `<html><body><p>Ransomware attack report with detailed IOCs and TTPs.</p></body></html>`
	resultPage2 := `<html><body><p>Threat actor profile: APT group targeting finance sector.</p></body></html>`

	// Mock search results page that contains links to result pages.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/search":
			query := r.URL.Query().Get("q")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body>
				<h1>Results for: %s</h1>
				<a href="/result/1">Result 1</a>
				<a href="/result/2">Result 2</a>
			</body></html>`, query)
		case "/result/1":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, resultPage1)
		case "/result/2":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, resultPage2)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.WebSourcesConfig{
		Enabled: true,
		Feeds: []config.WebConfig{
			{
				Name:     "test-search",
				URL:      srv.URL + "/search?q={query}",
				Type:     "search",
				Queries:  []string{"ransomware"},
				Interval: 1 * time.Hour,
			},
		},
	}

	wc := NewWebCollector(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan models.Finding, 20)
	go wc.Start(ctx, out)

	var findings []models.Finding
	deadline := time.After(10 * time.Second)

	// We expect 2 findings (one per result page).
	for len(findings) < 2 {
		select {
		case f := <-out:
			findings = append(findings, f)
		case <-deadline:
			t.Fatalf("timed out: got %d findings, expected 2", len(findings))
		}
	}

	cancel()

	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(findings))
	}

	// Verify metadata contains query.
	for _, f := range findings {
		if f.Source != models.SourceTypeWeb {
			t.Errorf("expected Source=%q, got %q", models.SourceTypeWeb, f.Source)
		}
		if f.Metadata["query"] != "ransomware" {
			t.Errorf("expected query=%q in metadata, got %q", "ransomware", f.Metadata["query"])
		}
		if f.Metadata["url"] == "" {
			t.Error("expected url in metadata, got empty")
		}
		if f.Metadata["extracted_links"] == "" {
			t.Error("expected extracted_links in metadata, got empty")
		}
	}
}

func TestWebCollector_Dedup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, testRSSFeed)
	}))
	defer srv.Close()

	cfg := &config.WebSourcesConfig{
		Enabled: true,
		Feeds: []config.WebConfig{
			{
				Name:     "dedup-rss",
				URL:      srv.URL,
				Type:     "rss",
				Interval: 300 * time.Millisecond, // fast interval to trigger multiple fetches
			},
		},
	}

	wc := NewWebCollector(cfg, nil)

	// Run long enough for at least 2 fetch cycles.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan models.Finding, 50)
	go wc.Start(ctx, out)

	// Wait for context to expire.
	<-ctx.Done()

	// Give Start() time to wind down and close the channel.
	time.Sleep(200 * time.Millisecond)

	count := 0
	for range out {
		count++
	}

	// With dedup, we should see exactly 2 findings (one per unique RSS item)
	// despite multiple fetch cycles.
	if count != 2 {
		t.Errorf("expected exactly 2 findings due to dedup, got %d", count)
	}
}

func TestWebCollector_Name(t *testing.T) {
	wc := NewWebCollector(&config.WebSourcesConfig{}, nil)
	if wc.Name() != "web" {
		t.Errorf("expected Name()=%q, got %q", "web", wc.Name())
	}
}
