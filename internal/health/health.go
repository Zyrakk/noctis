package health

import (
	"net/http"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server exposes /healthz, /readyz, and /metrics over HTTP.
type Server struct {
	mux   *http.ServeMux
	ready atomic.Bool
	addr  string
}

// NewServer creates a Server listening on addr and registers all handlers.
func NewServer(addr string) *Server {
	s := &Server{
		mux:  http.NewServeMux(),
		addr: addr,
	}

	s.mux.HandleFunc("/healthz", s.healthzHandler)
	s.mux.HandleFunc("/readyz", s.readyzHandler)
	s.mux.Handle("/metrics", promhttp.Handler())

	return s
}

// Mux returns the underlying ServeMux so tests can call ServeHTTP directly.
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// SetReady sets the readiness state of the server.
func (s *Server) SetReady(v bool) {
	s.ready.Store(v)
}

// ListenAndServe starts the HTTP server and blocks until it returns an error.
func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.addr, s.mux)
}

func (s *Server) healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) readyzHandler(w http.ResponseWriter, _ *http.Request) {
	if s.ready.Load() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
	}
}
