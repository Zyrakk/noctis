package dashboard

import (
	"context"
	"embed"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed static
var staticFiles embed.FS

// Server serves the Noctis web dashboard and API.
type Server struct {
	pool   *pgxpool.Pool
	apiKey string
	mux    *http.ServeMux
	httpSrv *http.Server
}

// NewServer creates a dashboard Server listening on addr. It requires a
// PostgreSQL connection pool and an API key for authenticating API requests.
func NewServer(addr string, pool *pgxpool.Pool, apiKey string) *Server {
	s := &Server{
		pool:   pool,
		apiKey: apiKey,
		mux:    http.NewServeMux(),
	}
	s.registerRoutes()
	s.httpSrv = &http.Server{
		Addr:    addr,
		Handler: s.mux,
	}
	return s
}

// ListenAndServe starts the HTTP server and blocks until it returns an error.
func (s *Server) ListenAndServe() error {
	slog.Info("dashboard server starting", "addr", s.httpSrv.Addr)
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully shuts down the dashboard server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) registerRoutes() {
	// Static file server from embedded FS
	staticFS, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))

	// API routes (auth required)
	s.mux.Handle("GET /api/stats", s.authMiddleware(http.HandlerFunc(s.handleStats)))
	s.mux.Handle("GET /api/findings/{id}", s.authMiddleware(http.HandlerFunc(s.handleFinding)))
	s.mux.Handle("GET /api/findings", s.authMiddleware(http.HandlerFunc(s.handleFindings)))
	s.mux.Handle("GET /api/iocs", s.authMiddleware(http.HandlerFunc(s.handleIOCs)))
	s.mux.Handle("GET /api/sources", s.authMiddleware(http.HandlerFunc(s.handleSources)))
	s.mux.Handle("POST /api/sources/{id}/approve", s.authMiddleware(http.HandlerFunc(s.handleApproveSource)))
	s.mux.Handle("POST /api/sources", s.authMiddleware(http.HandlerFunc(s.handleAddSource)))
	s.mux.Handle("GET /api/categories", s.authMiddleware(http.HandlerFunc(s.handleCategories)))
	s.mux.Handle("GET /api/timeline", s.authMiddleware(http.HandlerFunc(s.handleTimeline)))
	s.mux.Handle("GET /api/graph", s.authMiddleware(http.HandlerFunc(s.handleGraph)))

	// Auth validation endpoint
	s.mux.Handle("POST /api/auth/check", s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"valid": true})
	})))

	// Public endpoints (no auth — safe aggregate data only)
	s.mux.HandleFunc("GET /api/public-stats", s.handlePublicStats)
	s.mux.HandleFunc("GET /api/public-recent", s.handlePublicRecent)

	// SPA catch-all: serve static files, fall back to index.html for client routes
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Serve root or index.html directly
		if path == "/" || path == "/index.html" {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Try to serve a static file at this path
		if f, err := fs.Stat(staticFS, path[1:]); err == nil && !f.IsDir() {
			fileServer.ServeHTTP(w, r)
			return
		}

		// SPA fallback: serve index.html for client-side routing
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}
