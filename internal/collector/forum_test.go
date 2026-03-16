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

const threadListHTML = `<html><body>
<div class="thread-list">
    <a href="/thread/1">Thread One</a>
    <a href="/thread/2">Thread Two</a>
</div>
</body></html>`

const threadPageHTML1 = `<html><body>
<div class="post">
    <span class="author">user1</span>
    <div class="post-body">Post content here</div>
</div>
<div class="post">
    <span class="author">user2</span>
    <div class="post-body">Another post content</div>
</div>
</body></html>`

const threadPageHTML2 = `<html><body>
<div class="post">
    <span class="author">user3</span>
    <div class="post-body">Third post content</div>
</div>
<div class="post">
    <span class="author">user4</span>
    <div class="post-body">Fourth post content</div>
</div>
</body></html>`

func TestForumCollector_PublicScrape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, threadListHTML)
		case "/thread/1":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, threadPageHTML1)
		case "/thread/2":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, threadPageHTML2)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.ForumsConfig{
		Enabled: true,
		Sites: []config.ForumConfig{
			{
				Name:             "test-forum",
				URL:              srv.URL,
				Interval:         1 * time.Hour, // long interval; we only need one crawl
				MaxPagesPerCrawl: 1,
				RequestDelay:     10 * time.Millisecond,
				Scraper: config.ForumScraperConfig{
					ThreadListSelector:    ".thread-list a",
					ThreadContentSelector: ".post-body",
					AuthorSelector:        ".author",
				},
			},
		},
	}

	fc := NewForumCollector(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan models.Finding, 20)
	go fc.Start(ctx, out)

	findings := make(map[string]models.Finding)
	deadline := time.After(10 * time.Second)

	for len(findings) < 4 {
		select {
		case f := <-out:
			findings[f.Content] = f
		case <-deadline:
			t.Fatalf("timed out: got %d findings, expected 4", len(findings))
		}
	}

	cancel()

	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	expectedContents := []string{
		"Post content here",
		"Another post content",
		"Third post content",
		"Fourth post content",
	}

	for _, content := range expectedContents {
		f, ok := findings[content]
		if !ok {
			t.Errorf("missing finding with content %q", content)
			continue
		}
		if f.Source != models.SourceTypeForum {
			t.Errorf("expected Source=%q, got %q for content %q", models.SourceTypeForum, f.Source, content)
		}
		if f.SourceName != "test-forum" {
			t.Errorf("expected SourceName=%q, got %q for content %q", "test-forum", f.SourceName, content)
		}
		if f.Content == "" {
			t.Errorf("content must not be empty for finding %q", content)
		}
	}

	// Verify authors are extracted.
	if f, ok := findings["Post content here"]; ok {
		if f.Author != "user1" {
			t.Errorf("expected Author=%q, got %q", "user1", f.Author)
		}
	}
	if f, ok := findings["Another post content"]; ok {
		if f.Author != "user2" {
			t.Errorf("expected Author=%q, got %q", "user2", f.Author)
		}
	}
}

func TestForumCollector_AuthenticatedScrape(t *testing.T) {
	const sessionCookie = "forum_session=abc123"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			// Set a session cookie.
			http.SetCookie(w, &http.Cookie{
				Name:  "forum_session",
				Value: "abc123",
				Path:  "/",
			})
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "login ok")

		case "/":
			// Check for session cookie.
			cookie, err := r.Cookie("forum_session")
			if err != nil || cookie.Value != "abc123" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, threadListHTML)

		case "/thread/1":
			cookie, err := r.Cookie("forum_session")
			if err != nil || cookie.Value != "abc123" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, threadPageHTML1)

		case "/thread/2":
			cookie, err := r.Cookie("forum_session")
			if err != nil || cookie.Value != "abc123" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, threadPageHTML2)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.ForumsConfig{
		Enabled: true,
		Sites: []config.ForumConfig{
			{
				Name:             "auth-forum",
				URL:              srv.URL,
				Interval:         1 * time.Hour,
				MaxPagesPerCrawl: 1,
				RequestDelay:     10 * time.Millisecond,
				Auth: config.ForumAuthConfig{
					Username:      "testuser",
					Password:      "testpass",
					LoginURL:      srv.URL + "/login",
					UsernameField: "username",
					PasswordField: "password",
				},
				Scraper: config.ForumScraperConfig{
					ThreadListSelector:    ".thread-list a",
					ThreadContentSelector: ".post-body",
					AuthorSelector:        ".author",
				},
			},
		},
	}

	fc := NewForumCollector(cfg, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan models.Finding, 20)
	go fc.Start(ctx, out)

	findings := make(map[string]models.Finding)
	deadline := time.After(10 * time.Second)

	for len(findings) < 4 {
		select {
		case f := <-out:
			findings[f.Content] = f
		case <-deadline:
			t.Fatalf("timed out: got %d findings, expected 4", len(findings))
		}
	}

	cancel()

	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Source != models.SourceTypeForum {
			t.Errorf("expected Source=%q, got %q", models.SourceTypeForum, f.Source)
		}
		if f.SourceName != "auth-forum" {
			t.Errorf("expected SourceName=%q, got %q", "auth-forum", f.SourceName)
		}
	}
}

func TestForumCollector_Dedup(t *testing.T) {
	crawlCount := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			crawlCount++
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, threadListHTML)
		case "/thread/1":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, threadPageHTML1)
		case "/thread/2":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, threadPageHTML2)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	cfg := &config.ForumsConfig{
		Enabled: true,
		Sites: []config.ForumConfig{
			{
				Name:             "dedup-forum",
				URL:              srv.URL,
				Interval:         300 * time.Millisecond, // fast interval to trigger multiple crawls
				MaxPagesPerCrawl: 1,
				RequestDelay:     10 * time.Millisecond,
				Scraper: config.ForumScraperConfig{
					ThreadListSelector:    ".thread-list a",
					ThreadContentSelector: ".post-body",
					AuthorSelector:        ".author",
				},
			},
		},
	}

	fc := NewForumCollector(cfg, nil)

	// Run long enough for at least 2 crawl cycles.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := make(chan models.Finding, 50)
	go fc.Start(ctx, out)

	// Wait for context to expire.
	<-ctx.Done()

	// Give Start() time to wind down and close the channel.
	time.Sleep(200 * time.Millisecond)

	count := 0
	for range out {
		count++
	}

	if crawlCount < 2 {
		t.Fatalf("expected at least 2 crawl cycles, got %d", crawlCount)
	}

	// With dedup, we should see exactly 4 findings (one per unique post)
	// despite multiple crawl cycles.
	if count != 4 {
		t.Errorf("expected exactly 4 findings due to dedup, got %d (across %d crawl cycles)", count, crawlCount)
	}
}

func TestForumCollector_Name(t *testing.T) {
	fc := NewForumCollector(&config.ForumsConfig{}, nil)
	if fc.Name() != "forum" {
		t.Errorf("expected Name()=%q, got %q", "forum", fc.Name())
	}
}
