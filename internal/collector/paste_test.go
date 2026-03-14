package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/models"
)

func TestPasteCollector_PastebinAPI(t *testing.T) {
	const pasteContent = "leaked credentials admin:p@ssw0rd"
	const pasteKey = "abc123XY"
	const pasteUser = "darkuser42"
	const pasteTitle = "dump-2026"

	// Mock content server — serves paste content at /api_scrape_item.php.
	contentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("i") == pasteKey {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, pasteContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer contentSrv.Close()

	scrapeURL := contentSrv.URL + "/api_scrape_item.php?i=" + pasteKey

	// Mock list server — returns JSON array with one item.
	items := []pastebinScrapeItem{
		{
			ScrapeURL: scrapeURL,
			FullURL:   "https://pastebin.com/" + pasteKey,
			Date:      "1709200000",
			Key:       pasteKey,
			Title:     pasteTitle,
			User:      pasteUser,
		},
	}
	listBody, _ := json.Marshal(items)

	listSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(listBody)
	}))
	defer listSrv.Close()

	cfg := &config.PasteConfig{
		Enabled: true,
		Pastebin: config.PastebinConfig{
			Enabled:  true,
			Interval: 1 * time.Second,
		},
	}

	pc := NewPasteCollector(cfg, nil)
	pc.pastebinListURL = listSrv.URL

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan models.Finding, 10)
	go pc.Start(ctx, out)

	select {
	case f := <-out:
		if f.Source != models.SourceTypePaste {
			t.Errorf("expected Source=%q, got %q", models.SourceTypePaste, f.Source)
		}
		if f.SourceName != "pastebin" {
			t.Errorf("expected SourceName=%q, got %q", "pastebin", f.SourceName)
		}
		if f.Author != pasteUser {
			t.Errorf("expected Author=%q, got %q", pasteUser, f.Author)
		}
		if f.Content != pasteContent {
			t.Errorf("expected Content=%q, got %q", pasteContent, f.Content)
		}
		if f.Content == "" {
			t.Error("content must not be empty")
		}
		if f.SourceID != pasteKey {
			t.Errorf("expected SourceID=%q, got %q", pasteKey, f.SourceID)
		}
		if f.Metadata["title"] != pasteTitle {
			t.Errorf("expected metadata title=%q, got %q", pasteTitle, f.Metadata["title"])
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for Finding from Pastebin API")
	}
}

func TestPasteCollector_GenericScraper(t *testing.T) {
	const paste1Content = "SELECT * FROM users WHERE 1=1"
	const paste2Content = "aws_secret_access_key=AKIA..."

	// Mock server that serves both the index page and individual pastes.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body>
				<a href="/paste/p001">Paste 1</a>
				<a href="/paste/p002">Paste 2</a>
				<a href="/about">About</a>
			</body></html>`)
		case "/paste/p001":
			fmt.Fprint(w, paste1Content)
		case "/paste/p002":
			fmt.Fprint(w, paste2Content)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.PasteConfig{
		Enabled: true,
		Scrapers: []config.ScraperConfig{
			{
				Name:     "test-scraper",
				URL:      srv.URL,
				Interval: 1 * time.Second,
			},
		},
	}

	pc := NewPasteCollector(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan models.Finding, 10)
	go pc.Start(ctx, out)

	findings := make(map[string]models.Finding)
	deadline := time.After(3 * time.Second)

	for len(findings) < 2 {
		select {
		case f := <-out:
			findings[f.Content] = f
		case <-deadline:
			t.Fatalf("timed out: got %d findings, expected 2", len(findings))
		}
	}

	for _, f := range findings {
		if f.Source != models.SourceTypePaste {
			t.Errorf("expected Source=%q, got %q", models.SourceTypePaste, f.Source)
		}
		if f.SourceName != "test-scraper" {
			t.Errorf("expected SourceName=%q, got %q", "test-scraper", f.SourceName)
		}
	}

	if _, ok := findings[paste1Content]; !ok {
		t.Error("missing finding for paste1")
	}
	if _, ok := findings[paste2Content]; !ok {
		t.Error("missing finding for paste2")
	}
}

func TestPasteCollector_Dedup(t *testing.T) {
	const pasteContent = "same paste content every time"
	const pasteKey = "dupKey999"

	// Content server.
	contentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, pasteContent)
	}))
	defer contentSrv.Close()

	scrapeURL := contentSrv.URL + "/api_scrape_item.php?i=" + pasteKey

	items := []pastebinScrapeItem{
		{
			ScrapeURL: scrapeURL,
			FullURL:   "https://pastebin.com/" + pasteKey,
			Date:      "1709200000",
			Key:       pasteKey,
			Title:     "dup-test",
			User:      "dupuser",
		},
	}
	listBody, _ := json.Marshal(items)

	// List server returns the same single item every time.
	listSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(listBody)
	}))
	defer listSrv.Close()

	cfg := &config.PasteConfig{
		Enabled: true,
		Pastebin: config.PastebinConfig{
			Enabled:  true,
			Interval: 500 * time.Millisecond, // Poll fast to trigger multiple cycles.
		},
	}

	pc := NewPasteCollector(cfg, nil)
	pc.pastebinListURL = listSrv.URL

	// Run long enough for at least 3 poll cycles.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan models.Finding, 20)
	go pc.Start(ctx, out)

	// Wait for the context to expire, then drain and count.
	<-ctx.Done()

	// Give Start() a moment to wind down and close the channel.
	time.Sleep(200 * time.Millisecond)

	count := 0
	for range out {
		count++
	}

	if count != 1 {
		t.Errorf("expected exactly 1 Finding due to dedup, got %d", count)
	}
}

func TestNewTorTransport(t *testing.T) {
	transport, err := NewTorTransport("127.0.0.1:9050", 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if transport == nil {
		t.Fatal("expected non-nil transport")
	}
	if transport.DialContext == nil {
		t.Error("expected DialContext to be set")
	}
}

func TestNewTorTransport_InvalidAddr(t *testing.T) {
	_, err := NewTorTransport("", 30*time.Second)
	if err == nil {
		t.Fatal("expected error for empty proxy address")
	}
}
