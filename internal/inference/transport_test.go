package inference

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportSSRFLocalAuthorityAndRedirect(t *testing.T) {
	ctx := context.Background()
	s := Store{}
	for _, raw := range []string{"http://127.0.0.1:1", "https://127.0.0.1:1", "https://[::1]:1", "https://169.254.169.254/latest", "https://user:secret@example.org", "https://example.org/?key=value"} {
		if _, close, e := s.client(ctx, raw); e == nil {
			close()
			t.Fatalf("unsafe endpoint accepted: %s", raw)
		}
	}
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	u, _ := url.Parse(redirect.URL)
	s.AllowLocal = map[string]bool{u.Host: true}
	client, close, e := s.client(ctx, redirect.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer close()
	req, _ := http.NewRequest("POST", redirect.URL, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer synthetic")
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 302 || hits.Load() != 0 {
		t.Fatal("credential redirect followed")
	}
	// A port change never inherits a local exception.
	if _, close, e = s.client(ctx, target.URL); e == nil {
		close()
		t.Fatal("local exception crossed authority")
	}
}

func TestTransportBindingDeadlineAndClosedDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name     string
		delay    time.Duration
		budget   int
		parent   time.Duration
		body     bool
		category string
	}{
		{"delayed_headers_within_binding", 30 * time.Millisecond, 250, 0, false, ""},
		{"header_deadline", 150 * time.Millisecond, 30, 0, false, "deadline"},
		{"parent_cancel", 150 * time.Millisecond, 250, 20 * time.Millisecond, false, "cancel"},
		{"body_deadline", 150 * time.Millisecond, 30, 0, true, "deadline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if tc.body {
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
				}
				select {
				case <-time.After(tc.delay):
				case <-r.Context().Done():
					return
				}
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			s := Store{AllowLocal: map[string]bool{u.Host: true}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.parent > 0 {
				timer := time.AfterFunc(tc.parent, cancel)
				defer timer.Stop()
			}
			b := Binding{Model: "synthetic", PromptVersion: "1", Limits: Limits{MaxInputTokens: 65536, MaxOutputTokens: 16, DeadlineMS: tc.budget}}
			_, err := s.wire(ctx, b, Connection{URL: srv.URL, Adapter: "openai-responses"}, "synthetic-secret", "synthetic", Snapshot{}, []Function{"evidence.translate"}, func(context.Context) error { return nil })
			if hits.Load() != 1 {
				t.Fatalf("physical calls=%d", hits.Load())
			}
			var diag *TransportDiagnostic
			if tc.category != "" {
				if !errors.As(err, &diag) || diag.Category != tc.category || !diag.Gateway.Uncertain {
					t.Fatalf("diagnostic=%v", err)
				}
				if strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), srv.URL) {
					t.Fatal("unsafe error retained")
				}
			} else if errors.As(err, &diag) {
				t.Fatalf("headers within budget failed: %v", err)
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	client, close, err := (Store{AllowLocal: map[string]bool{u.Host: true}}).client(ctx, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	timeout := client.Transport.(*http.Transport).ResponseHeaderTimeout
	if timeout <= 119*time.Second || timeout > 120*time.Second {
		t.Fatal("binding deadline replaced by fixed header timeout", timeout)
	}
}
