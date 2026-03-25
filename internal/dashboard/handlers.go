package dashboard

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
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
		Category:    q.Get("category"),
		SubCategory: q.Get("sub_category"),
		Severity:    q.Get("severity"),
		Source:      q.Get("source"),
		Query:       q.Get("q"),
		Limit:       parseIntParam(q.Get("limit"), 50),
		Offset:      parseIntParam(q.Get("offset"), 0),
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
		Type:       q.Get("type"),
		Query:      q.Get("q"),
		ActiveOnly: q.Get("active") != "false",
		Limit:      parseIntParam(q.Get("limit"), 50),
		Offset:     parseIntParam(q.Get("offset"), 0),
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

func (s *Server) handleRejectSource(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}

	if err := rejectSource(r.Context(), s.pool, id); err != nil {
		slog.Error("dashboard: reject source", "err", err, "id", id)
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "source not found"})
		} else {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to reject source"})
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
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

func (s *Server) handleSubcategories(w http.ResponseWriter, r *http.Request) {
	subs, err := querySubcategories(r.Context(), s.pool)
	if err != nil {
		slog.Error("dashboard: subcategories", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch subcategories"})
		return
	}
	writeJSON(w, http.StatusOK, subs)
}

func (s *Server) handleNotes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := notesFilter{
		NoteType: q.Get("type"),
		Status:   q.Get("status"),
		EntityID: q.Get("entity_id"),
		Limit:    parseIntParam(q.Get("limit"), 20),
		Offset:   parseIntParam(q.Get("offset"), 0),
	}

	resp, err := queryNotes(r.Context(), s.pool, f)
	if err != nil {
		slog.Error("dashboard: notes", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch notes"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCorrelationDecisions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := decisionsFilter{
		Decision: q.Get("decision"),
		Limit:    parseIntParam(q.Get("limit"), 20),
		Offset:   parseIntParam(q.Get("offset"), 0),
	}

	resp, err := queryCorrelationDecisions(r.Context(), s.pool, f)
	if err != nil {
		slog.Error("dashboard: correlation decisions", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch decisions"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleActorProfile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id"})
		return
	}

	profile, err := queryActorProfile(r.Context(), s.pool, id)
	if err != nil {
		slog.Error("dashboard: actor profile", "err", err, "id", id)
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "actor not found"})
		return
	}
	writeJSON(w, http.StatusOK, profile)
}

func (s *Server) handleSourceValues(w http.ResponseWriter, r *http.Request) {
	resp, err := querySourceValues(r.Context(), s.pool)
	if err != nil {
		slog.Error("dashboard: source values", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch source values"})
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

func (s *Server) handleBriefs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	briefType := q.Get("type")
	if briefType == "" {
		briefType = "daily"
	}

	resp, err := queryBriefs(r.Context(), s.pool, briefType,
		parseIntParam(q.Get("limit"), 20),
		parseIntParam(q.Get("offset"), 0))
	if err != nil {
		slog.Error("dashboard: briefs", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch briefs"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleLatestBrief(w http.ResponseWriter, r *http.Request) {
	briefType := r.URL.Query().Get("type")
	if briefType == "" {
		briefType = "daily"
	}

	brief, err := queryLatestBrief(r.Context(), s.pool, briefType)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no brief found"})
			return
		}
		slog.Error("dashboard: latest brief", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch latest brief"})
		return
	}
	writeJSON(w, http.StatusOK, brief)
}

func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := vulnsFilter{
		KEVOnly:     q.Get("kev") == "true",
		HasExploit:  q.Get("exploit") == "true",
		HasMentions: q.Get("mentions") == "true",
		Query:       q.Get("q"),
		Limit:       parseIntParam(q.Get("limit"), 50),
		Offset:      parseIntParam(q.Get("offset"), 0),
	}

	if v := q.Get("min_priority"); v != "" {
		p := parseFloatParam(v, 0)
		f.MinPriority = &p
	}
	if v := q.Get("min_epss"); v != "" {
		p := parseFloatParam(v, 0)
		f.MinEPSS = &p
	}

	resp, err := queryVulnerabilities(r.Context(), s.pool, f)
	if err != nil {
		slog.Error("dashboard: vulnerabilities", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to fetch vulnerabilities"})
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleVulnerabilityDetail(w http.ResponseWriter, r *http.Request) {
	cveID := r.PathValue("cve")
	if cveID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing CVE ID"})
		return
	}

	detail, err := queryVulnerabilityDetail(r.Context(), s.pool, cveID)
	if err != nil {
		slog.Error("dashboard: vuln detail", "cve", cveID, "err", err)
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "vulnerability not found"})
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	if s.queryEngine == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "query engine not available"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16) // 64KB max

	var req struct {
		Question string `json:"question"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Question == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "question is required"})
		return
	}

	result, err := s.queryEngine.Query(r.Context(), req.Question)
	if err != nil {
		slog.Error("dashboard: query", "question", req.Question, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "query failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, result)
}
