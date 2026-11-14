package runtimev2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/google/uuid"
)

func historyAPI(t *testing.T, f *aiFixture, actor string) func(string, string, string, int) []byte {
	t.Helper()
	token, csrf := random(), random()
	if _, err := f.conn.Exec(context.Background(), `INSERT INTO noctis_v2.sessions VALUES($1,$2,$3,clock_timestamp()+interval '1 hour',false)`, tokenHash(token), actor, csrf); err != nil {
		t.Fatal(err)
	}
	a := &API{cfg: configv2.Config{DatabaseURL: f.dsn, Origin: "https://synthetic.invalid"}}
	return func(method, path, body string, want int) []byte {
		t.Helper()
		r := httptest.NewRequest(method, "/api/v2/ai/jobs"+path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "noctis_v2_session", Value: token})
		r.Header.Set("Origin", a.cfg.Origin)
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		a.handle(w, r)
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s %s: status %d wanted %d, cache %q: %s", method, path, w.Code, want, w.Header().Get("Cache-Control"), w.Body.String())
		}
		return w.Body.Bytes()
	}
}

func historyPage(t *testing.T, raw []byte) inference.JobPage {
	t.Helper()
	var body struct{ Data inference.JobPage }
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	var exact struct {
		Data struct{ Jobs []map[string]any }
	}
	if err := json.Unmarshal(raw, &exact); err != nil {
		t.Fatal(err)
	}
	for _, j := range exact.Data.Jobs {
		if len(j) != 4 || j["id"] == nil || j["function_id"] == nil || j["created_at"] == nil || j["state"] == nil {
			t.Fatal("history disclosed fields beyond its four-field contract", j)
		}
	}
	return body.Data
}

func TestAIHistoryPaginationPrivacyAndActorPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	a, b := historyAPI(t, f, "fixture-admin"), historyAPI(t, f, "other-actor")
	if p := historyPage(t, a("GET", "", "", 200)); p.Jobs == nil || len(p.Jobs) != 0 || p.NextCursor != "" {
		t.Fatal("empty history", p)
	}
	// Deliberately malformed result/snapshot prove listing never decodes or
	// revalidates them. All dates are equal to exercise the UUID tie breaker.
	_, err := f.conn.Exec(ctx, `INSERT INTO noctis_v2.ai_jobs(id,actor,request_id,function_id,input,snapshot,config_revision,state,result,error_code,cache_key,created_at) SELECT md5('history-'||n)::uuid,'fixture-admin','private-request-'||n,'query.plan','{"text":"private-input"}','{"prompt":"private-snapshot"}',$1,'succeeded','{"private":"result"}','private-internal-error','private-cache','2026-01-01T00:00:00.123456Z' FROM generate_series(1,103) n`, f.cfg.Revision)
	if err != nil {
		t.Fatal(err)
	}
	firstRaw := a("GET", "", "", 200)
	first := historyPage(t, firstRaw)
	if len(first.Jobs) != 50 || first.NextCursor == "" || strings.Contains(string(firstRaw), "private-") {
		t.Fatal("default limit/privacy", string(firstRaw))
	}
	if p := historyPage(t, a("GET", "?limit=100", "", 200)); len(p.Jobs) != 100 || p.NextCursor == "" {
		t.Fatal("maximum limit", p)
	}
	for _, path := range []string{"?limit=0", "?limit=101", "?limit=-1", "?limit=x", "?limit=", "?limit=1&limit=2", "?actor=fixture-admin", "?cursor=%zz", "?cursor=invalid", "?cursor=" + strings.Repeat("a", 257)} {
		a("GET", path, "", 400)
	}
	for _, raw := range []string{`{"created_at":"bad","id":"bad"}`, `{"created_at":"2026-01-01T00:00:00Z","id":"bad"}`, `{"created_at":"2026-01-01T00:00:00Z","id":"00000000-0000-0000-0000-000000000001","extra":true}`, `{"created_at":"2026-01-01T00:00:00Z","id":"00000000-0000-0000-0000-000000000001"}`} {
		a("GET", "?cursor="+base64.RawURLEncoding.EncodeToString([]byte(raw)), "", 400)
	}
	b("GET", "?cursor="+url.QueryEscape(first.NextCursor), "", 400)
	otherID := uuid.NewString()
	if _, err = f.conn.Exec(ctx, `INSERT INTO noctis_v2.ai_jobs(id,actor,request_id,function_id,input,snapshot,config_revision,state,cache_key) VALUES($1,'other-actor','other-request','query.plan','{}','{}',$2,'queued','other-cache')`, otherID, f.cfg.Revision); err != nil {
		t.Fatal(err)
	}
	a("GET", "/"+otherID, "", 404)
	a("POST", "/"+otherID+"/cancel", "", 404)
	foreignID := first.Jobs[0].ID
	b("GET", "/"+foreignID, "", 404)
	b("POST", "/"+foreignID+"/cancel", "", 404)
	if p := historyPage(t, b("GET", "", "", 200)); len(p.Jobs) != 1 || p.Jobs[0].ID != otherID || p.Jobs[0].State != "queued" {
		t.Fatal("foreign jobs disclosed", p)
	}
	// A newer insertion belongs on refresh, never on a continuation page.
	newID := uuid.NewString()
	_, err = f.conn.Exec(ctx, `INSERT INTO noctis_v2.ai_jobs(id,actor,request_id,function_id,input,snapshot,config_revision,state,cache_key) VALUES($1,'fixture-admin','new-request','query.plan','{}','{}',$2,'queued','new-cache')`, newID, f.cfg.Revision)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	p := first
	last := ""
	for {
		for _, j := range p.Jobs {
			if seen[j.ID] || j.ID == newID || (last != "" && j.ID >= last) {
				t.Fatal("duplicate/new/out-of-order history", j.ID)
			}
			seen[j.ID] = true
			last = j.ID
		}
		if p.NextCursor == "" {
			break
		}
		p = historyPage(t, a("GET", "?cursor="+url.QueryEscape(p.NextCursor), "", 200))
	}
	if len(seen) != 103 {
		t.Fatal("missing history rows", len(seen))
	}
	newSession := historyAPI(t, f, "fixture-admin")
	if p := historyPage(t, newSession("GET", "?limit=1", "", 200)); len(p.Jobs) != 1 || p.Jobs[0].ID != newID {
		t.Fatal("same actor/new session did not recover", p)
	}
	var state string
	if err = f.conn.QueryRow(ctx, `SELECT state FROM noctis_v2.ai_jobs WHERE id=$1`, foreignID).Scan(&state); err != nil || state != "succeeded" {
		t.Fatal("foreign cancel altered job", state, err)
	}
}

func TestAIHistoryLostResponseRecoverCancelAndAccountingPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	call := historyAPI(t, f, "fixture-admin")
	body := fmt.Sprintf(`{"function_id":"query.plan","input":{"kind":"query","text":"Find synthetic ACME"},"request_id":%q}`, uuid.NewString())
	// The response is discarded after the HTTP handler has committed the POST.
	call("POST", "", body, 202)
	p := historyPage(t, call("GET", "", "", 200))
	if len(p.Jobs) != 1 {
		t.Fatal(p)
	}
	id := p.Jobs[0].ID
	f.mode.Store("waitvalid")
	f.block = make(chan struct{})
	f.entered = make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- f.store.Once(ctx) }()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway was not entered")
	}
	newSession := historyAPI(t, f, "fixture-admin")
	newSession("GET", "/"+id, "", 200)
	newSession("POST", "/"+id+"/cancel", "", 200)
	close(f.block)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		var out struct{ Data inference.JobView }
		if err := json.Unmarshal(newSession("GET", "/"+id, "", 200), &out); err != nil || out.Data.State != "cancelled" || !out.Data.Terminal || out.Data.Result != nil {
			t.Fatal("cancelled publication", out, err)
		}
	}
	var actual, exposure int64
	var count int
	if err := f.conn.QueryRow(ctx, `SELECT actual_units,exposure_units FROM noctis_v2.ai_attempts WHERE job_id=$1`, id).Scan(&actual, &exposure); err != nil || actual != 140 || exposure != 140 {
		t.Fatal("real accounting lost", actual, exposure, err)
	}
	if err := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_jobs`).Scan(&count); err != nil || count != 1 || f.calls.Load() != 1 {
		t.Fatal("recovery resent a request", count, f.calls.Load(), err)
	}
}

func TestAIHistoryOpeningRevalidatesEvidencePostgres(t *testing.T) {
	for _, change := range []string{"revoked", "expired"} {
		t.Run(change, func(t *testing.T) {
			f := newAIFixture(t)
			ctx := context.Background()
			call := historyAPI(t, f, "fixture-admin")
			j, err := f.store.Submit(ctx, inference.Submit{Function: "evidence.translate", Input: f.input(t, "observation"), RequestID: uuid.NewString()}, "fixture-admin")
			if err != nil {
				t.Fatal(err)
			}
			if err = f.store.Once(ctx); err != nil {
				t.Fatal(err)
			}
			if change == "revoked" {
				_, err = f.conn.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=false WHERE id=$1`, f.source)
			} else {
				_, err = f.conn.Exec(ctx, `UPDATE noctis_v2.observations SET retention_expired_at=clock_timestamp() WHERE id=$1`, f.observation)
			}
			if err != nil {
				t.Fatal(err)
			}
			p := historyPage(t, call("GET", "", "", 200))
			if len(p.Jobs) != 1 || p.Jobs[0].State != "succeeded" {
				t.Fatal("list must preserve durable state", p)
			}
			var out struct{ Data inference.JobView }
			if err = json.Unmarshal(call("GET", "/"+j.ID, "", 200), &out); err != nil || out.Data.State != "dependency_blocked" || out.Data.Result != nil || !out.Data.Terminal || out.Data.Error != "result_requires_revalidation" {
				t.Fatal("stale evidence exposed", out, err)
			}
			if f.calls.Load() != 1 {
				t.Fatal("opening result sent inference", f.calls.Load())
			}
		})
	}
}
