package health_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zyrakk/noctis/internal/health"
)

func TestHealthzHandler_ReturnsOK(t *testing.T) {
	s := health.NewServer(":0", nil)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	s.Mux().ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("expected body 'ok', got %q", string(body))
	}
}

func TestReadyzHandler_NotReady(t *testing.T) {
	s := health.NewServer(":0", nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	s.Mux().ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestReadyzHandler_Ready(t *testing.T) {
	s := health.NewServer(":0", nil)
	s.SetReady(true)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	s.Mux().ServeHTTP(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ready" {
		t.Fatalf("expected body 'ready', got %q", string(body))
	}
}
