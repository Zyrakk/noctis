package inference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransportHTTPStatusClassification(t *testing.T) {
	result := Result{SchemaVersion: "1", Kind: "query.plan", Text: "synthetic", Labels: []string{}, Intent: "unknown", Claims: []Claim{}, Entities: []Entity{}, Roles: []Role{}, Limitations: []string{}, Plan: &QueryPlan{Version: "1", Entity: "observations", Operation: "search", Mode: "exact", Limit: 1}}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	type statusCase struct {
		name       string
		status     int
		invalid    bool
		code       string
		permanent  bool
		uncertain  bool
		retryAfter time.Duration
	}
	cases := []statusCase{
		{"200_valid", 200, false, "", false, false, 0},
		{"200_invalid", 200, true, "response_invalid", true, true, 0},
		{"400", 400, false, "invalid_request", true, false, 0},
		{"401", 401, false, "authentication_denied", true, false, 0},
		{"403", 403, false, "authentication_denied", true, false, 0},
		{"429", 429, false, "rate_limited", false, false, 3 * time.Second},
		{"302", 302, false, "redirect_denied", true, false, 0},
		{"307", 307, false, "redirect_denied", true, false, 0},
		{"500", 500, false, "upstream_error", false, true, 0},
	}
	for _, status := range []int{201, 202, 203, 204, 205, 206, 207, 226, 250, 299} {
		cases = append(cases, statusCase{fmt.Sprint(status), status, false, "response_status_invalid", true, true, 0})
	}
	for _, adapter := range []string{"openai-chat", "openai-responses"} {
		t.Run(adapter, func(t *testing.T) {
			envelope := map[string]any{"model": "synthetic", "choices": []any{map[string]any{"finish_reason": "stop", "message": map[string]any{"content": string(raw)}}}, "usage": map[string]int{"prompt_tokens": 12, "completion_tokens": 30}}
			if adapter == "openai-responses" {
				envelope = map[string]any{"status": "completed", "model": "synthetic", "usage": map[string]int{"input_tokens": 12, "output_tokens": 30}, "output": []any{map[string]any{"type": "message", "status": "completed", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": string(raw)}}}}}
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					var calls atomic.Int32
					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls.Add(1)
						w.Header().Set("Location", "/poll")
						w.Header().Set("Retry-After", "3")
						w.WriteHeader(tc.status)
						if tc.status == http.StatusNoContent {
							return
						}
						if tc.invalid {
							fmt.Fprint(w, `{`)
							return
						}
						json.NewEncoder(w).Encode(envelope)
					}))
					defer srv.Close()
					u, _ := url.Parse(srv.URL)
					s := Store{AllowLocal: map[string]bool{u.Host: true}}
					b := Binding{Model: "synthetic", PromptVersion: "1", Limits: Limits{MaxInputTokens: 65536, MaxOutputTokens: 100, DeadlineMS: 2000}}
					out, err := s.wire(context.Background(), b, Connection{URL: srv.URL, Adapter: adapter}, "synthetic", "status-test", Snapshot{}, []Function{"query.plan"}, func(context.Context) error { return nil })
					if calls.Load() != 1 {
						t.Fatalf("physical calls=%d", calls.Load())
					}
					if tc.code == "" {
						if err != nil || out.Model != "synthetic" || !reflect.DeepEqual(out.Result, result) || out.Usage == nil || *out.Usage != (Usage{12, 30}) {
							t.Fatalf("valid result/usage lost: %+v, %v", out, err)
						}
						return
					}
					var ge *GatewayError
					if !errors.As(err, &ge) || ge.Code != tc.code || ge.Permanent != tc.permanent || ge.Uncertain != tc.uncertain || ge.RetryAfter != tc.retryAfter {
						t.Fatalf("classification=%+v, error=%v", ge, err)
					}
					if !reflect.DeepEqual(out, GatewayResult{}) {
						t.Fatalf("unsupported response accepted result or usage: %+v", out)
					}
				})
			}
		})
	}
}

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
