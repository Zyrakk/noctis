package runtimev2

import (
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"strconv"
	"strings"
)

func inferenceStore(cfg configv2.Config) inference.Store {
	allow := map[string]bool{}
	for _, v := range cfg.AIAuthorities {
		allow[v] = true
	}
	return inference.Store{DSN: cfg.DatabaseURL, KeyFile: cfg.AIKeyFile, CAFile: cfg.AICAFile, AllowLocal: allow}
}
func (a *API) handleAI(w http.ResponseWriter, r *http.Request, path, actor string) bool {
	if !strings.HasPrefix(path, "ai/") && path != "query" {
		return false
	}
	s := inferenceStore(a.cfg)
	ctx := r.Context()
	reject := func(e error) {
		switch {
		case errors.Is(e, inference.ErrConflict):
			failure(w, 412, "configuration_conflict")
		case errors.Is(e, pgx.ErrNoRows):
			failure(w, 404, "not_found")
		default:
			failure(w, 400, "ai_request_rejected")
		}
	}
	decode := func(v any) error {
		raw, e := io.ReadAll(io.LimitReader(r.Body, 256<<10+1))
		if e != nil || len(raw) > 256<<10 {
			return inference.ErrInvalid
		}
		return inference.Strict(raw, v)
	}
	switch {
	case path == "ai/config" && r.Method == "GET":
		v, e := s.Read(ctx)
		if e != nil {
			reject(e)
			return true
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, v.Revision))
		response(w, v)
	case path == "ai/config" && r.Method == "PUT":
		var c inference.Config
		if e := decode(&c); e != nil {
			reject(e)
			return true
		}
		etag := r.Header.Get("If-Match")
		expected, e := strconv.ParseInt(strings.Trim(etag, `"`), 10, 64)
		if e != nil || etag != fmt.Sprintf(`"%d"`, expected) {
			failure(w, 428, "if_match_required")
			return true
		}
		v, e := s.Save(ctx, c, expected, actor)
		if e != nil {
			reject(e)
			return true
		}
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, v.Revision))
		response(w, v)
	case path == "ai/validate" && r.Method == "POST":
		var c inference.Config
		if e := decode(&c); e != nil {
			reject(e)
			return true
		}
		if e := s.Validate(c); e != nil {
			reject(e)
			return true
		}
		response(w, map[string]any{"valid": true, "provider_contacted": false, "quality_validated": false})
	case path == "ai/jobs" && r.Method == "POST":
		var in inference.Submit
		if e := decode(&in); e != nil {
			reject(e)
			return true
		}
		j, e := s.Submit(ctx, in, actor)
		if e != nil {
			reject(e)
			return true
		}
		w.Header().Set("Location", j.StatusURL)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		response(w, j)
	case strings.HasPrefix(path, "ai/jobs/"):
		id := strings.TrimPrefix(path, "ai/jobs/")
		if strings.HasSuffix(id, "/cancel") && r.Method == "POST" {
			id = strings.TrimSuffix(id, "/cancel")
			if e := s.Cancel(ctx, id, actor); e != nil {
				reject(e)
				return true
			}
			j, e := s.Job(ctx, id, actor)
			if e != nil {
				reject(e)
				return true
			}
			response(w, j)
		} else if r.Method == "GET" && !strings.Contains(id, "/") {
			j, e := s.Job(ctx, id, actor)
			if e != nil {
				reject(e)
				return true
			}
			response(w, j)
		} else {
			failure(w, 405, "method_not_allowed")
		}
	case path == "query" && r.Method == "POST":
		var in struct {
			Plan inference.QueryPlan `json:"plan"`
		}
		if e := decode(&in); e != nil {
			reject(e)
			return true
		}
		v, e := s.Query(ctx, in.Plan, actor)
		if e != nil {
			reject(e)
			return true
		}
		response(w, v)
	default:
		failure(w, 405, "method_not_allowed")
	}
	return true
}
