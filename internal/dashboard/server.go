package dashboard

import (
	"context"
	"embed"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Zyrakk/noctis/internal/modules"
)

//go:embed static
var staticFiles embed.FS

// Server serves the Noctis web dashboard and API.
type Server struct {
	pool     *pgxpool.Pool
	apiKey   string
	registry *modules.Registry
	mux      *http.ServeMux
	httpSrv  *http.Server
}

// NewServer creates a dashboard Server listening on addr. It requires a
// PostgreSQL connection pool, an API key for authenticating API requests,
// and a module registry for system status reporting.
func NewServer(addr string, pool *pgxpool.Pool, apiKey string, registry *modules.Registry) *Server {
	s := &Server{
		pool:     pool,
		apiKey:   apiKey,
		registry: registry,
		mux:      http.NewServeMux(),
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
	s.mux.Handle("POST /api/sources/{id}/reject", s.authMiddleware(http.HandlerFunc(s.handleRejectSource)))
	s.mux.Handle("POST /api/sources", s.authMiddleware(http.HandlerFunc(s.handleAddSource)))
	s.mux.Handle("GET /api/categories", s.authMiddleware(http.HandlerFunc(s.handleCategories)))
	s.mux.Handle("GET /api/timeline", s.authMiddleware(http.HandlerFunc(s.handleTimeline)))
	s.mux.Handle("GET /api/entities", s.authMiddleware(http.HandlerFunc(s.handleEntities)))
	s.mux.Handle("GET /api/graph", s.authMiddleware(http.HandlerFunc(s.handleGraph)))
	s.mux.Handle("GET /api/correlations", s.authMiddleware(http.HandlerFunc(s.handleCorrelations)))
	s.mux.Handle("GET /api/correlation-decisions", s.authMiddleware(http.HandlerFunc(s.handleCorrelationDecisions)))
	s.mux.Handle("GET /api/subcategories", s.authMiddleware(http.HandlerFunc(s.handleSubcategories)))
	s.mux.Handle("GET /api/notes", s.authMiddleware(http.HandlerFunc(s.handleNotes)))
	s.mux.Handle("GET /api/actors/{id}/profile", s.authMiddleware(http.HandlerFunc(s.handleActorProfile)))
	s.mux.Handle("GET /api/sources/value", s.authMiddleware(http.HandlerFunc(s.handleSourceValues)))
	s.mux.Handle("GET /api/system/status", s.authMiddleware(http.HandlerFunc(s.handleSystemStatus)))
	s.mux.Handle("GET /api/briefs", s.authMiddleware(http.HandlerFunc(s.handleBriefs)))
	s.mux.Handle("GET /api/briefs/latest", s.authMiddleware(http.HandlerFunc(s.handleLatestBrief)))
	s.mux.Handle("GET /api/vulnerabilities", s.authMiddleware(http.HandlerFunc(s.handleVulnerabilities)))

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

func (s *Server) handleSystemStatus(w http.ResponseWriter, _ *http.Request) {
	if s.registry == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"available": false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"available": true,
		"modules":   s.registry.StatusesByCategory(),
		"timestamp": time.Now().UTC(),
	})
}
