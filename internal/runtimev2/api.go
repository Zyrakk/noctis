package runtimev2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type API struct {
	cfg                configv2.Config
	username, password string
}

func NewHandler(cfg configv2.Config) (http.Handler, error) {
	if cfg.AdminFile == "" || cfg.Origin == "" {
		return nil, errors.New("admin secret file and canonical origin required")
	}
	raw, e := os.ReadFile(cfg.AdminFile)
	if e != nil {
		return nil, errors.New("admin secret unavailable")
	}
	var a struct{ Username, Password string }
	if e = json.Unmarshal(raw, &a); e != nil || a.Username == "" || len(a.Password) < 16 {
		return nil, errors.New("admin secret requires username and password >=16 bytes")
	}
	if a.Username == inference.AutomaticActor {
		return nil, fmt.Errorf("admin username %q is reserved for automatic inference", inference.AutomaticActor)
	}
	api := &API{cfg: cfg, username: a.Username, password: a.Password}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/", api.handle)
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, r *http.Request) {
		response(w, map[string]any{"live": true, "mode": cfg.Mode})
	})
	ready := func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		h, e := Check(ctx, cfg.DatabaseURL, cfg.Mode)
		if e != nil || cfg.Mode != "api" {
			w.WriteHeader(503)
		}
		json.NewEncoder(w).Encode(h)
	}
	mux.HandleFunc("GET /readyz", ready)
	mux.HandleFunc("GET /healthz", ready)
	mux.Handle("/", frontendHandler())
	return mux, nil
}
func failure(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": strings.ReplaceAll(code, "_", " "), "request_id": uuid.NewString()}})
}
func response(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"data": data, "meta": map[string]any{"generated_at": time.Now().UTC(), "coverage": "feed_window_only; independence_unknown", "degraded": true, "next_cursor": nil}})
}
func random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func tokenHash(token string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(token))) }
func (a *API) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	path := strings.TrimPrefix(r.URL.Path, "/api/v2/")
	if r.Method != "GET" && r.Method != "POST" && r.Method != "PUT" {
		failure(w, 405, "method_not_allowed")
		return
	}
	if r.Method != "GET" && r.Header.Get("Origin") != a.cfg.Origin {
		failure(w, 403, "origin_denied")
		return
	}
	c, e := pgx.Connect(ctx, a.cfg.DatabaseURL)
	if e != nil {
		failure(w, 503, "database_unavailable")
		return
	}
	defer c.Close(context.Background())
	if path == "auth/login" && r.Method == "POST" {
		a.login(w, r, c)
		return
	}
	cookie, e := r.Cookie("noctis_v2_session")
	if e != nil {
		failure(w, 401, "authentication_required")
		return
	}
	var username, csrf string
	e = c.QueryRow(ctx, `SELECT username,csrf FROM noctis_v2.sessions WHERE token_hash=$1 AND expires_at>clock_timestamp() AND NOT revoked`, tokenHash(cookie.Value)).Scan(&username, &csrf)
	if errors.Is(e, pgx.ErrNoRows) {
		failure(w, 401, "authentication_required")
		return
	}
	if e != nil {
		failure(w, 503, "database_unavailable")
		return
	}
	if username == inference.AutomaticActor {
		failure(w, 403, "reserved_actor_identity")
		return
	}
	if path == "auth/session" && r.Method == "GET" {
		response(w, map[string]any{"user": map[string]string{"username": username}, "permissions": []string{"admin", "read"}, "csrf": csrf})
		return
	}
	if r.Method != "GET" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf)) != 1 {
		failure(w, 403, "csrf_denied")
		return
	}
	if path == "auth/logout" && r.Method == "POST" {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(csrf)) != 1 {
			failure(w, 403, "csrf_denied")
			return
		}
		_, e = c.Exec(ctx, `UPDATE noctis_v2.sessions SET revoked=true WHERE token_hash=$1`, tokenHash(cookie.Value))
		if e != nil {
			failure(w, 503, "database_unavailable")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "noctis_v2_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		response(w, map[string]bool{"logged_out": true})
		return
	}
	if a.handleAI(w, r, path, username) {
		return
	}
	if handled, e := a.handleOperations(w, r, c, path, username); handled {
		if e != nil {
			failure(w, 503, "operation_unavailable")
		}
		return
	}
	if r.Method != "GET" {
		if handled, e := a.mutateDomain(w, r, c, path, username); handled {
			if e != nil {
				failure(w, 400, "mutation_rejected")
			}
			return
		}
		failure(w, 405, "method_not_allowed")
		return
	}
	if e = a.read(w, r, c, path); errors.Is(e, pgx.ErrNoRows) {
		failure(w, 404, "not_found")
	} else if e != nil {
		failure(w, 503, "query_unavailable")
	}
}
func (a *API) login(w http.ResponseWriter, r *http.Request, c *pgx.Conn) {
	var input struct{ Username, Password string }
	dec := json.NewDecoder(io.LimitReader(r.Body, 4097))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&input); e != nil {
		failure(w, 400, "invalid_login")
		return
	}
	expected := sha256.Sum256([]byte(a.username + "\x00" + a.password))
	actual := sha256.Sum256([]byte(input.Username + "\x00" + input.Password))
	if subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
		failure(w, 401, "invalid_credentials")
		return
	}
	token, csrf := random(), random()
	_, e := c.Exec(r.Context(), `INSERT INTO noctis_v2.sessions(token_hash,username,csrf,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '8 hours')`, tokenHash(token), a.username, csrf)
	if e != nil {
		failure(w, 503, "database_unavailable")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "noctis_v2_session", Value: token, Path: "/", MaxAge: 28800, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	response(w, map[string]any{"user": map[string]string{"username": a.username}, "permissions": []string{"admin", "read"}, "csrf": csrf})
}
func (a *API) read(w http.ResponseWriter, r *http.Request, c *pgx.Conn, path string) error {
	ctx := r.Context()
	if handled, e := a.readDomain(w, r, c, path); handled {
		return e
	}
	switch {
	case path == "cases":
		cursor, limit, e := pageRequest(r, "cases:"+r.URL.Query().Get("q"))
		if e != nil || cursor.ID != "" && cursor.At.IsZero() {
			failure(w, 400, "invalid_pagination")
			return nil
		}
		rows, e := c.Query(ctx, `SELECT cr.body,ic.updated_at,ic.id::text FROM noctis_v2.intelligence_cases ic JOIN noctis_v2.case_revisions cr ON cr.case_id=ic.id AND cr.revision=ic.revision WHERE ($1='' OR ic.title ILIKE '%'||$1||'%') AND ($2='' OR (ic.updated_at,ic.id::text)<($3::timestamptz,$2)) ORDER BY ic.updated_at DESC,ic.id DESC LIMIT $4`, r.URL.Query().Get("q"), cursor.ID, cursor.At, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		data := []any{}
		var next *pageCursor
		for rows.Next() {
			var raw []byte
			var updated time.Time
			var id string
			if e = rows.Scan(&raw, &updated, &id); e != nil {
				return e
			}
			var v map[string]any
			if e = json.Unmarshal(raw, &v); e != nil {
				return e
			}
			v["updated_at"] = updated
			data = append(data, v)
			if len(data) == limit {
				next = &pageCursor{Kind: cursor.Kind, ID: id, At: updated}
			}
		}
		if e = rows.Err(); e != nil {
			return e
		}
		if len(data) > limit {
			data = data[:limit]
		} else {
			next = nil
		}
		pageResponse(w, data, next)
	case strings.HasPrefix(path, "cases/"):
		id := strings.TrimPrefix(path, "cases/")
		if _, e := uuid.Parse(id); e != nil {
			return pgx.ErrNoRows
		}
		var raw []byte
		var updated time.Time
		e := c.QueryRow(ctx, `SELECT cr.body,ic.updated_at FROM noctis_v2.intelligence_cases ic JOIN noctis_v2.case_revisions cr ON cr.case_id=ic.id AND cr.revision=ic.revision WHERE ic.id=$1`, id).Scan(&raw, &updated)
		if e != nil {
			return e
		}
		var v map[string]any
		if e = json.Unmarshal(raw, &v); e != nil {
			return e
		}
		v["updated_at"] = updated
		changes, e := readChanges(ctx, c, id)
		if e != nil {
			return e
		}
		v["timeline"] = changes
		response(w, v)
	case strings.HasPrefix(path, "evidence/"):
		id := strings.TrimPrefix(path, "evidence/")
		if _, e := uuid.Parse(id); e != nil {
			return pgx.ErrNoRows
		}
		var text []byte
		var expired bool
		if e := c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.observations WHERE id=$1 AND revision=$2 AND retention_expired_at IS NOT NULL)`, id, r.URL.Query().Get("revision")).Scan(&expired); e != nil {
			return e
		}
		if expired {
			failure(w, 410, "evidence_expired")
			return nil
		}
		var hash, rep, source, revision string
		var published *time.Time
		var collected time.Time
		var deleted bool
		var superseded *string
		e := c.QueryRow(ctx, `SELECT b.payload,o.hash,o.representation,COALESCE(NULLIF(s.name,''),s.kind),o.revision,o.published_at,o.collected_at,o.source_deleted,o.superseded_by::text FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) JOIN noctis_v2.sources s ON s.id=o.source_id WHERE o.id=$1 AND o.revision=$2 AND o.retention_expired_at IS NULL`, id, r.URL.Query().Get("revision")).Scan(&text, &hash, &rep, &source, &revision, &published, &collected, &deleted, &superseded)
		if e != nil {
			return e
		}
		response(w, map[string]any{"text": string(text), "hash": hash, "representation": rep, "source": source, "revision": revision, "published_at": published, "collected_at": collected, "retention_status": "retained", "source_deleted": deleted, "superseded_by": superseded})
	case path == "today":
		changes, e := readChanges(ctx, c, "")
		if e != nil {
			return e
		}
		var raw []byte
		var brief any
		e = c.QueryRow(ctx, `SELECT body||jsonb_build_object('invalidated',invalidated) FROM noctis_v2.briefs WHERE period=$1 ORDER BY policy_version DESC LIMIT 1`, time.Now().UTC().Format("2006-01-02")).Scan(&raw)
		if e == nil {
			if e = json.Unmarshal(raw, &brief); e != nil {
				return e
			}
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		response(w, map[string]any{"changes": changes, "brief": brief})
	case path == "sources":
		cursor, limit, e := pageRequest(r, path)
		if e != nil {
			failure(w, 400, "invalid_pagination")
			return nil
		}
		rows, e := c.Query(ctx, `SELECT id::text,COALESCE(NULLIF(name,''),kind),enabled,`+intelligence.SourceAuthorizedSQL+`,last_success_at,last_error,coverage,policy_version,policy_revision FROM noctis_v2.sources s WHERE ($1='' OR id::text>$1) ORDER BY id LIMIT $2`, cursor.ID, limit+1)
		if e != nil {
			return e
		}
		defer rows.Close()
		data := []any{}
		var next *pageCursor
		for rows.Next() {
			var id, name, coverage, policyVersion string
			var policyRevision int64
			var enabled, effective bool
			var success *time.Time
			var lastError *string
			if e = rows.Scan(&id, &name, &enabled, &effective, &success, &lastError, &coverage, &policyVersion, &policyRevision); e != nil {
				return e
			}
			status := "paused"
			if effective {
				status = "enabled"
			}
			if lastError != nil && effective {
				status = "degraded"
			}
			data = append(data, map[string]any{"id": id, "name": name, "enabled": enabled, "effective_enabled": effective, "status": status, "last_success_at": success, "last_error": lastError, "coverage": coverage, "policy_version": policyVersion, "policy_revision": policyRevision})
			if len(data) == limit {
				next = &pageCursor{Kind: path, ID: id}
			}
		}
		if e = rows.Err(); e != nil {
			return e
		}
		if len(data) > limit {
			data = data[:limit]
		} else {
			next = nil
		}
		pageResponse(w, data, next)
	case path == "system":
		var backlog int
		var oldest *time.Time
		e := c.QueryRow(ctx, `SELECT count(*),min(at) FROM (SELECT COALESCE(o.collected_at,j.created_at) at FROM noctis_v2.jobs j LEFT JOIN noctis_v2.observations o ON o.id=j.input_id WHERE j.state NOT IN ('succeeded','cancelled') UNION ALL SELECT created_at FROM noctis_v2.ai_jobs WHERE state NOT IN ('succeeded','cancelled','failed')) queue`).Scan(&backlog, &oldest)
		if e != nil {
			return e
		}
		errs := []string{}
		rows, e := c.Query(ctx, `SELECT DISTINCT last_error_code FROM noctis_v2.jobs WHERE last_error_code IS NOT NULL UNION SELECT DISTINCT last_error FROM noctis_v2.sources WHERE last_error IS NOT NULL UNION SELECT DISTINCT error_code FROM noctis_v2.ai_jobs WHERE error_code IS NOT NULL`)
		if e != nil {
			return e
		}
		for rows.Next() {
			var v string
			if e = rows.Scan(&v); e != nil {
				rows.Close()
				return e
			}
			errs = append(errs, v)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return e
		}
		aiStatus := "disabled"
		var enabled bool
		if e = c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.ai_configs c CROSS JOIN LATERAL jsonb_array_elements(c.body->'bindings') b WHERE c.revision=(SELECT max(revision) FROM noctis_v2.ai_configs) AND (b->>'enabled')::boolean)`).Scan(&enabled); e != nil {
			return e
		}
		if enabled {
			aiStatus = "configured; permissions, credentials, dependencies and budget checked per attempt"
		}
		var progress []byte
		if e = c.QueryRow(ctx, `SELECT jsonb_build_object('paused',(SELECT paused FROM noctis_v2.runtime_control),'checkpoints',(SELECT count(*) FROM noctis_v2.checkpoints),'inbox',(SELECT count(*) FROM noctis_v2.telegram_inbox),'observations',(SELECT count(*) FROM noctis_v2.observations),'expired_observations',(SELECT count(*) FROM noctis_v2.observations WHERE retention_expired_at IS NOT NULL),'job_states',(SELECT COALESCE(jsonb_object_agg(state,n),'{}') FROM (SELECT state,count(*) n FROM noctis_v2.jobs GROUP BY state)j),'outbox_states',(SELECT COALESCE(jsonb_object_agg(state,n),'{}') FROM (SELECT state,count(*) n FROM noctis_v2.outbox GROUP BY state)o),'ai_exposure_units',(SELECT COALESCE(sum(exposure_units),0) FROM noctis_v2.ai_attempts),'ai_uncertain_attempts',(SELECT count(*) FROM noctis_v2.ai_attempts WHERE state='uncertain'),'ai_accounting_exceptions',(SELECT count(*) FROM noctis_v2.ai_attempts WHERE accounting_exception IS NOT NULL),'last_capture_at',(SELECT max(last_success_at) FROM noctis_v2.sources))`).Scan(&progress); e != nil {
			return e
		}
		status := "ready"
		if len(errs) > 0 {
			status = "degraded"
		}
		response(w, map[string]any{"status": status, "backlog": backlog, "oldest_job_at": oldest, "errors": errs, "progress": json.RawMessage(progress), "ai": map[string]string{"status": aiStatus}})
	default:
		return pgx.ErrNoRows
	}
	return nil
}
func readChanges(ctx context.Context, c *pgx.Conn, caseID string) ([]any, error) {
	rows, e := c.Query(ctx, `SELECT body,created_at FROM noctis_v2.case_changes WHERE ($1='' OR case_id::text=$1) AND ($1<>'' OR created_at>=date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC') ORDER BY created_at DESC,id LIMIT 200`, caseID)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := []any{}
	for rows.Next() {
		var raw []byte
		var created time.Time
		if e = rows.Scan(&raw, &created); e != nil {
			return nil, e
		}
		var v map[string]any
		if e = json.Unmarshal(raw, &v); e != nil {
			return nil, e
		}
		v["created_at"] = created
		result = append(result, v)
	}
	return result, rows.Err()
}
