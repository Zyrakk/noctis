package dashboard

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := queryStats(r.Context(), s.pool)
	if err != nil {
		slog.Error("dashboard: stats", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch stats"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := findingsFilter{
		Category: q.Get("category"),
		Severity: q.Get("severity"),
		Source:   q.Get("source"),
		Query:    q.Get("q"),
		Limit:    parseIntParam(q.Get("limit"), 50),
		Offset:   parseIntParam(q.Get("offset"), 0),
	}

	if since := q.Get("since"); since != "" {
		t, err := parseSince(since)
		if err == nil {
			f.Since = &t
		}
	}

	resp, err := queryFindings(r.Context(), s.pool, f)
	if err != nil {
		slog.Error("dashboard: findings", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch findings"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}

	fd, err := queryFinding(r.Context(), s.pool, id)
	if err != nil {
		slog.Error("dashboard: finding", "err", err, "id", id)
		if strings.Contains(err.Error(), "no rows") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "finding not found"})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch finding"})
		}
		return
	}
	writeJSON(w, http.StatusOK, fd)
}

func (s *Server) handleIOCs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := iocsFilter{
		Type:   q.Get("type"),
		Query:  q.Get("q"),
		Limit:  parseIntParam(q.Get("limit"), 50),
		Offset: parseIntParam(q.Get("offset"), 0),
	}

	resp, err := queryIOCs(r.Context(), s.pool, f)
	if err != nil {
		slog.Error("dashboard: iocs", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch IOCs"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleSources(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	resp, err := querySources(r.Context(), s.pool, q.Get("status"), q.Get("type"),
		parseIntParam(q.Get("limit"), 50), parseIntParam(q.Get("offset"), 0))
	if err != nil {
		slog.Error("dashboard: sources", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch sources"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleApproveSource(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}

	if err := approveSource(r.Context(), s.pool, id); err != nil {
		slog.Error("dashboard: approve source", "err", err, "id", id)
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "source not found"})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to approve source"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

func (s *Server) handleAddSource(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	var req struct {
		Type       string `json:"type"`
		Identifier string `json:"identifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Type == "" || req.Identifier == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type and identifier are required"})
		return
	}

	validTypes := map[string]bool{
		"telegram_channel": true, "telegram_group": true, "forum": true,
		"paste_site": true, "web": true, "rss": true,
	}
	if !validTypes[req.Type] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid source type"})
		return
	}

	id, err := addSource(r.Context(), s.pool, req.Type, req.Identifier)
	if err != nil {
		slog.Error("dashboard: add source", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to add source"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "active"})
}

func (s *Server) handleCategories(w http.ResponseWriter, r *http.Request) {
	cats, err := queryCategories(r.Context(), s.pool)
	if err != nil {
		slog.Error("dashboard: categories", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch categories"})
		return
	}
	writeJSON(w, http.StatusOK, cats)
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	since := time.Now().Add(-7 * 24 * time.Hour) // default: 7 days
	if s := q.Get("since"); s != "" {
		if t, err := parseSince(s); err == nil {
			since = t
		}
	}

	interval := q.Get("interval")
	if interval == "" {
		interval = "1 hour"
	}

	points, err := queryTimeline(r.Context(), s.pool, since, interval)
	if err != nil {
		slog.Error("dashboard: timeline", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch timeline"})
		return
	}
	writeJSON(w, http.StatusOK, points)
}

func (s *Server) handleEntities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	resp, err := queryEntities(r.Context(), s.pool, q.Get("type"), q.Get("q"),
		parseIntParam(q.Get("limit"), 20), parseIntParam(q.Get("offset"), 0))
	if err != nil {
		slog.Error("dashboard: entities", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch entities"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	entityID := q.Get("entity_id")
	if entityID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "entity_id is required"})
		return
	}

	hops := parseIntParam(q.Get("hops"), 2)
	graph, err := queryGraph(r.Context(), s.pool, entityID, hops)
	if err != nil {
		slog.Error("dashboard: graph", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch graph"})
		return
	}
	writeJSON(w, http.StatusOK, graph)
}

func (s *Server) handleCorrelations(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := correlationFilter{
		Type:          q.Get("type"),
		MinConfidence: parseFloatParam(q.Get("min_confidence"), 0.0),
		Limit:         parseIntParam(q.Get("limit"), 50),
		Offset:        parseIntParam(q.Get("offset"), 0),
	}

	if since := q.Get("since"); since != "" {
		t, err := parseSince(since)
		if err == nil {
			f.Since = &t
		}
	}

	resp, err := queryCorrelations(r.Context(), s.pool, f)
	if err != nil {
		slog.Error("dashboard: correlations", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch correlations"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- public endpoints (no auth) ---

func (s *Server) handlePublicStats(w http.ResponseWriter, r *http.Request) {
	stats, err := queryPublicStats(r.Context(), s.pool)
	if err != nil {
		slog.Error("dashboard: public-stats", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch stats"})
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handlePublicRecent(w http.ResponseWriter, r *http.Request) {
	findings, err := queryPublicRecent(r.Context(), s.pool)
	if err != nil {
		slog.Error("dashboard: public-recent", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch recent findings"})
		return
	}
	writeJSON(w, http.StatusOK, findings)
}

// --- helpers ---

func parseIntParam(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return defaultVal
	}
	return v
}

func parseFloatParam(s string, defaultVal float64) float64 {
	if s == "" {
		return defaultVal
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 {
		return defaultVal
	}
	return v
}

// parseSince parses a duration string like "7d", "24h", "30m" or an RFC3339 timestamp.
func parseSince(s string) (time.Time, error) {
	// Try duration shorthand first: "7d", "24h", "1h"
	if len(s) > 1 {
		numStr := s[:len(s)-1]
		unit := s[len(s)-1]
		if num, err := strconv.Atoi(numStr); err == nil {
			switch unit {
			case 'd':
				return time.Now().Add(-time.Duration(num) * 24 * time.Hour), nil
			case 'h':
				return time.Now().Add(-time.Duration(num) * time.Hour), nil
			case 'm':
				return time.Now().Add(-time.Duration(num) * time.Minute), nil
			}
		}
	}

	// Try RFC3339
	return time.Parse(time.RFC3339, s)
}
