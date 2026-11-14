package runtimev2

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

func TestPublicLandingSeparateFromPrivateApplication(t *testing.T) {
	handler := frontendHandler()
	for _, route := range []string{"/", "/index.html", "/v2/login", "/v2/today", "/demo?story=B", "/presentation", "/app.html"} {
		t.Run(route, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", route, nil))
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			body, policy := w.Body.String(), w.Header().Get("Content-Security-Policy")
			if w.Header().Get("Cache-Control") != "no-cache" {
				t.Fatal("HTML must revalidate")
			}
			landing := route == "/" || route == "/index.html"
			if landing {
				if !strings.Contains(body, "From noise") || strings.Contains(body, `id="root"`) {
					t.Fatal("expected standalone landing")
				}
				for _, match := range regexp.MustCompile(`(?s)<script\b[^>]*>(.*?)</script>`).FindAllStringSubmatch(body, -1) {
					digest := sha256.Sum256([]byte(match[1]))
					if !strings.Contains(policy, "'sha256-"+base64.StdEncoding.EncodeToString(digest[:])+"'") {
						t.Fatal("inline script missing CSP hash")
					}
				}
			} else {
				if !strings.Contains(body, `id="root"`) {
					t.Fatal("expected React application")
				}
				if strings.Contains(policy, "cloudfront") || strings.Contains(policy, "sha256-") {
					t.Fatal("private app policy permits landing resources")
				}
			}
			if strings.Contains(strings.Split(policy, ";")[1], "unsafe-inline") {
				t.Fatal("inline scripts must be hash restricted")
			}
			head := httptest.NewRecorder()
			handler.ServeHTTP(head, httptest.NewRequest("HEAD", route, nil))
			if head.Code != 200 || head.Body.Len() != 0 {
				t.Fatal("HEAD must return no body")
			}
		})
	}
	for _, route := range []string{"/api/unknown", "/missing.js"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", route, nil))
		if w.Code != 404 {
			t.Fatalf("%s must not return HTML fallback", route)
		}
	}
}
