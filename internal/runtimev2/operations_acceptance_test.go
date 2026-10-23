package runtimev2

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/Zyrakk/noctis/internal/legacyimport"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func operationsClient(t *testing.T, f *aiFixture) func(string, string, any, int) map[string]any {
	t.Helper()
	secret := filepath.Join(t.TempDir(), "admin.json")
	if e := os.WriteFile(secret, []byte(`{"username":"fixture-admin","password":"synthetic-only-long-password"}`), 0600); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	h, e := NewHandler(configv2.Config{DatabaseURL: f.dsn, Mode: "api", AdminFile: secret, Origin: origin})
	if e != nil {
		t.Fatal(e)
	}
	server.Config.Handler = h
	server.StartTLS()
	t.Cleanup(server.Close)
	token, csrf := random(), random()
	if _, e = f.conn.Exec(context.Background(), `INSERT INTO noctis_v2.sessions VALUES($1,'fixture-admin',$2,clock_timestamp()+interval '1 hour',false)`, tokenHash(token), csrf); e != nil {
		t.Fatal(e)
	}
	return func(method, path string, in any, want int) map[string]any {
		t.Helper()
		if m, ok := in.(map[string]any); ok && m["request_id"] == nil && path != "query" {
			m["request_id"] = uuid.NewString()
		}
		raw, _ := json.Marshal(in)
		req, _ := http.NewRequest(method, server.URL+"/api/v2/"+path, strings.NewReader(string(raw)))
		req.Header.Set("Origin", origin)
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(&http.Cookie{Name: "noctis_v2_session", Value: token})
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		var body map[string]any
		if e = json.NewDecoder(res.Body).Decode(&body); e != nil {
			t.Fatal(e)
		}
		if res.StatusCode != want {
			t.Fatalf("%s %s =>%d want%d: %v", method, path, res.StatusCode, want, body)
		}
		return body
	}
}

func TestAttentionCASExportTTLDiscoveryQuotaAndPausePostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	call := operationsClient(t, f)
	ctx := context.Background()
	casePath := "cases/" + f.caseID
	att := call("GET", casePath+"/attention", nil, 200)["data"].(map[string]any)
	body := map[string]any{"action": "seen", "expected_revision": att["revision"], "request_id": uuid.NewString()}
	seen := call("POST", casePath+"/attention", body, 200)["data"].(map[string]any)
	duplicate := call("POST", casePath+"/attention", body, 200)["data"].(map[string]any)
	if seen["revision"] != duplicate["revision"] {
		t.Fatal("idempotency changed revision")
	}
	call("POST", casePath+"/attention", map[string]any{"action": "silence", "expected_revision": att["revision"], "reason": "retain context", "deadline": time.Now().Add(time.Hour)}, 409)
	silent := call("POST", casePath+"/attention", map[string]any{"action": "silence", "expected_revision": seen["revision"], "reason": "wait independent evidence", "deadline": time.Now().Add(time.Hour)}, 200)["data"].(map[string]any)
	if silent["mode"] != "silent_until_change" {
		t.Fatal(silent)
	}
	if _, e := f.conn.Exec(ctx, `UPDATE noctis_v2.intelligence_cases SET revision=revision+1 WHERE id=$1`, f.caseID); e != nil {
		t.Fatal(e)
	}
	reopened := call("GET", casePath+"/attention", nil, 200)["data"].(map[string]any)
	if reopened["mode"] != "automatic" {
		t.Fatal("silence did not reopen", reopened)
	}
	if _, e := f.conn.Exec(ctx, `INSERT INTO noctis_v2.case_revisions(case_id,revision,body) SELECT id,revision,jsonb_build_object('id',id,'revision',revision::text) FROM noctis_v2.intelligence_cases WHERE id=$1`, f.caseID); e != nil {
		t.Fatal(e)
	}
	var revision int64
	f.conn.QueryRow(ctx, `SELECT revision FROM noctis_v2.intelligence_cases WHERE id=$1`, f.caseID).Scan(&revision)
	call("POST", casePath+"/exports", map[string]any{"format": "json", "expected_revision": revision}, 403)
	call("POST", "permissions", map[string]any{"permission": "export", "granted": true}, 200)
	exported := call("POST", casePath+"/exports", map[string]any{"format": "json", "expected_revision": revision}, 200)["data"].(map[string]any)
	path := "exports/" + exported["id"].(string)
	downloaded := call("GET", path, nil, 200)["data"].(map[string]any)
	if len(downloaded["citations"].([]any)) == 0 {
		t.Fatal("export lacks citations")
	}
	if _, e := f.conn.Exec(ctx, `UPDATE noctis_v2.private_exports SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, exported["id"]); e != nil {
		t.Fatal(e)
	}
	call("GET", path, nil, 410)
	question := call("POST", "questions", map[string]any{"title": "Risk to ACME", "terms": []any{map[string]any{"type": "keyword", "value": "ACME"}}}, 200)["data"].(map[string]any)
	var hits atomic.Int32
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); fmt.Fprint(w, "synthetic") }))
	defer fixture.Close()
	proposal := call("POST", "discovery", map[string]any{"question_id": question["id"], "kind": "html", "endpoint": fixture.URL, "reason": "operator PIR match", "provenance": map[string]any{"origin": "operator"}}, 200)["data"].(map[string]any)
	p := "discovery/" + proposal["id"].(string)
	call("GET", "discovery", nil, 200)
	if hits.Load() != 0 {
		t.Fatal("GET used network")
	}
	authorize := map[string]any{"expected_revision": 1, "policy": map[string]any{"allowed": true, "purpose": "bounded synthetic trial"}}
	call("POST", p+"/authorize", authorize, 403)
	call("POST", "permissions", map[string]any{"permission": "discovery_authorize", "granted": true}, 200)
	authorize["request_id"] = uuid.NewString()
	call("POST", p+"/authorize", authorize, 200)
	trial := call("POST", p+"/trial", map[string]any{"expected_revision": 2, "ttl_seconds": 60, "quota": 1}, 200)["data"].(map[string]any)
	id := trial["id"].(string)
	fetcher := capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(fixture.URL, "http://"): true}}
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { done <- RunDiscoveryTrial(ctx, f.dsn, id, fetcher) }()
	}
	success := 0
	for i := 0; i < 2; i++ {
		if <-done == nil {
			success++
		}
	}
	if success != 1 || hits.Load() != 1 {
		t.Fatal("concurrent quota", success, hits.Load())
	}
	trial = call("POST", p+"/trial", map[string]any{"expected_revision": 2, "ttl_seconds": 60, "quota": 1}, 200)["data"].(map[string]any)
	call("POST", p+"/revoke", map[string]any{"expected_revision": 2}, 200)
	if e := RunDiscoveryTrial(ctx, f.dsn, trial["id"].(string), fetcher); e == nil || hits.Load() != 1 {
		t.Fatal("revocation allowed wire", e, hits.Load())
	}
	call("GET", "coverage", nil, 200)
	call("POST", "runtime-control", map[string]any{"expected_revision": 1, "action": "pause", "reason": "synthetic maintenance"}, 200)
	control := call("GET", "runtime-control", nil, 200)["data"].(map[string]any)
	if control["paused"] != true {
		t.Fatal(control)
	}
}

func TestRetentionSharedBlobRedactsDerivedAndEvidencePostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	c := f.conn
	call := operationsClient(t, f)
	j, e := f.store.Submit(ctx, inference.Submit{Function: "case.summarize", Input: f.input(t, "case"), RequestID: uuid.NewString()}, "fixture-admin")
	if e != nil {
		t.Fatal(e)
	}
	if e = f.store.Once(ctx); e != nil {
		t.Fatal(e)
	}
	other := uuid.NewString()
	if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,published_at,collected_at) SELECT $1::uuid,source_id,$1::text,revision,hash,representation,epoch,mode,published_at,clock_timestamp() FROM noctis_v2.observations WHERE id=$2`, other, f.observation); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Exec(ctx, `UPDATE noctis_v2.observations SET collected_at=clock_timestamp()-interval '3 days' WHERE id=$1`, f.observation); e != nil {
		t.Fatal(e)
	}
	call("POST", "permissions", map[string]any{"permission": "retention", "granted": true}, 200)
	call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "policy", "expected_revision": 0, "retain_seconds": 86400}, 200)
	dry := call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "run", "dry_run": true}, 200)["data"].(map[string]any)
	if dry["eligible"] != float64(1) {
		t.Fatal(dry)
	}
	run := call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "run", "expected_revision": 1}, 200)["data"].(map[string]any)
	call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "batch", "run_id": run["run_id"], "limit": 1}, 200)
	var revision string
	var bytes int
	if e = c.QueryRow(ctx, `SELECT revision,octet_length(b.payload) FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE o.id=$1`, other).Scan(&revision, &bytes); e != nil || bytes == 0 {
		t.Fatal("shared active blob cleared", bytes, e)
	}
	call("GET", "evidence/"+f.observation+"?revision="+revision, nil, 410)
	call("GET", "evidence/"+other+"?revision="+revision, nil, 200)
	view, e := f.store.Job(ctx, j.ID, "fixture-admin")
	if e != nil || view.Result != nil {
		t.Fatal("purged AI result served", view, e)
	}
	var redacted bool
	if e = c.QueryRow(ctx, `SELECT result='{}' AND dependencies='{}' FROM noctis_v2.ai_products WHERE job_id=$1`, j.ID).Scan(&redacted); e != nil || !redacted {
		t.Fatal("AI product not redacted", e)
	}
	call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "batch", "run_id": run["run_id"], "limit": 1}, 200)
}

func TestWebAdaptersCaptureAuthPaginationParserReplayPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	c := f.conn
	var hits atomic.Int32
	var oversized atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-protected" {
			w.WriteHeader(401)
			return
		}
		if oversized.Load() {
			fmt.Fprint(w, `<article data-id="x">one</article><article data-id="y">two</article>`)
			return
		}
		if r.URL.Query().Get("page") == "2" {
			fmt.Fprint(w, `<article data-id="two">Second page café</article>`)
		} else {
			fmt.Fprint(w, `<article data-id="one">First page <script>evil()</script> alert</article><a rel="next" href="?page=2">next</a>`)
		}
	}))
	defer server.Close()
	auth := filepath.Join(t.TempDir(), "auth.secret")
	if e := os.WriteFile(auth, []byte("Bearer synthetic-protected"), 0600); e != nil {
		t.Fatal(e)
	}
	id, epoch := uuid.NewString(), uuid.NewString()
	cfg, _ := json.Marshal(capture.WebConfig{ParserVersion: "p1", AuthFile: auth, MaxItems: 1})
	if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,policy_version,enabled,epoch,activated_at,adapter_config) VALUES($1,'forum',$2,'p1',true,$3,clock_timestamp(),$4)`, id, server.URL, epoch, string(cfg)); e != nil {
		t.Fatal(e)
	}
	store := capture.Store{DSN: f.store.DSN}
	fetcher := capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(server.URL, "http://"): true}}
	for i := 0; i < 3; i++ {
		if e := store.PollWeb(ctx, id, fetcher); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e := c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations WHERE source_id=$1`, id).Scan(&count); e != nil || count != 2 {
		t.Fatal("replay inflated native records", count, e)
	}
	cfg, _ = json.Marshal(capture.WebConfig{ParserVersion: "p2", AuthFile: auth, MaxItems: 1})
	if _, e := c.Exec(ctx, `UPDATE noctis_v2.sources SET adapter_config=$2 WHERE id=$1`, id, string(cfg)); e != nil {
		t.Fatal(e)
	}
	if e := store.PollWeb(ctx, id, fetcher); e != nil {
		t.Fatal(e)
	}
	if e := c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations WHERE source_id=$1 AND superseded_by IS NOT NULL`, id).Scan(&count); e != nil || count != 1 {
		t.Fatal("parser revision did not supersede stable identity", count, e)
	}
	var version int64
	if e := c.QueryRow(ctx, `SELECT version FROM noctis_v2.checkpoints WHERE source_id=$1`, id).Scan(&version); e != nil {
		t.Fatal(e)
	}
	oversized.Store(true)
	if e := store.PollWeb(ctx, id, fetcher); e == nil {
		t.Fatal("oversized page silently accepted")
	}
	var after int64
	c.QueryRow(ctx, `SELECT version FROM noctis_v2.checkpoints WHERE source_id=$1`, id).Scan(&after)
	if after != version {
		t.Fatal("failed page advanced checkpoint")
	}
	before := hits.Load()
	if e := os.Chmod(auth, 0644); e != nil {
		t.Fatal(e)
	}
	if e := store.PollWeb(ctx, id, fetcher); e == nil || hits.Load() != before {
		t.Fatal("unsafe auth file reached wire", e)
	}
	if _, e := c.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=false WHERE id=$1`, id); e != nil {
		t.Fatal(e)
	}
	if e := store.PollWeb(ctx, id, fetcher); e == nil || hits.Load() != before {
		t.Fatal("paused source reached wire", e)
	}
}

func TestGraphNeighborLimitAndClaimDependencyPaginationPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	call := operationsClient(t, f)
	for i := 0; i < 21; i++ {
		id := uuid.NewString()
		if _, e := f.conn.Exec(ctx, `INSERT INTO noctis_v2.entities(id,kind) VALUES($1,'handle')`, id); e != nil {
			t.Fatal(e)
		}
		if _, e := f.conn.Exec(ctx, `INSERT INTO noctis_v2.entity_hypotheses(id,left_id,right_id,relation,evidence,status) VALUES($1,$2,$3,'possible_same_handle','[]','unresolved')`, uuid.NewString(), f.left, id); e != nil {
			t.Fatal(e)
		}
	}
	graph := call("GET", "graph?root="+f.left+"&hops=1", nil, 200)["data"].(map[string]any)
	if graph["truncated"] != true || graph["max_neighbors"] != float64(20) || len(graph["nodes"].([]any)) != 21 {
		t.Fatal("neighbor truncation hidden", graph)
	}
	var reasons bool
	for _, r := range graph["truncation_reasons"].([]any) {
		if r == "neighbor_limit" {
			reasons = true
		}
	}
	if !reasons {
		t.Fatal(graph)
	}
	ids := []string{uuid.NewString(), uuid.NewString()}
	for _, id := range ids {
		if _, e := f.conn.Exec(ctx, `INSERT INTO noctis_v2.claim_versions(id,revision,case_id,subject,predicate,object,status,producer,policy_version,evidence) VALUES($1,1,$2,'source','reports','fixture','source_claim','fixture','p1','[]')`, id, f.caseID); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := f.conn.Exec(ctx, `INSERT INTO noctis_v2.claim_dependencies VALUES($1,1,$2,1,'contradicts')`, ids[1], ids[0]); e != nil {
		t.Fatal(e)
	}
	first := call("GET", "claims?case_id="+f.caseID+"&limit=1", nil, 200)
	cursor := first["meta"].(map[string]any)["next_cursor"].(string)
	second := call("GET", "claims?case_id="+f.caseID+"&limit=1&cursor="+cursor, nil, 200)
	total := append(first["data"].([]any), second["data"].([]any)...)
	links := 0
	for _, v := range total {
		for _, d := range v.(map[string]any)["dependencies"].([]any) {
			link := d.(map[string]any)
			if link["relation"] != "contradicts" || link["status"] != "source_claim" {
				t.Fatal(link)
			}
			links++
		}
	}
	if links != 1 || second["meta"].(map[string]any)["next_cursor"] != nil {
		t.Fatal("dependency pagination", first, second)
	}
	call("GET", "claims?case_id="+uuid.NewString()+"&limit=1&cursor="+cursor, nil, 400)
}

func TestLivenessIndependentOfDatabaseReadinessFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	if e := os.WriteFile(path, []byte(`{"username":"fixture","password":"synthetic-only-long-password"}`), 0600); e != nil {
		t.Fatal(e)
	}
	h, e := NewHandler(configv2.Config{DatabaseURL: "postgres://invalid@127.0.0.1:1/noctis_v2_missing?sslmode=disable&connect_timeout=1", AdminFile: path, Origin: "https://fixture.invalid", Mode: "api"})
	if e != nil {
		t.Fatal(e)
	}
	for route, want := range map[string]int{"/livez": 200, "/readyz": 503, "/healthz": 503} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", route, nil))
		if w.Code != want {
			t.Fatal(route, w.Code, want)
		}
	}
}

func TestRetentionLegacyHistoryCannotReconstructExpiredOriginalPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	call := operationsClient(t, f)
	const canary = "legacy-original-private-canary-005"
	batch := legacyimport.HistoryBatch{ImportedAt: time.Now().UTC().Add(-72 * time.Hour), SourceID: f.source, ArchiveDigest: "sha256:synthetic-retention-archive", Table: "findings", Expected: capture.Checkpoint{Value: json.RawMessage("null")}, Next: capture.Checkpoint{Version: 1, Value: json.RawMessage(`{"last_id":"9007199254740993123"}`)}, Records: []legacyimport.HistoryRecord{{SourceID: f.source, ArchiveDigest: "sha256:synthetic-retention-archive", Table: "findings", LegacyID: "9007199254740993123", Text: canary, LegacyJudgment: json.RawMessage(`{"summary":"` + canary + `","status":"confirmed"}`)}}}
	store := legacyimport.Store{DSN: f.store.DSN}
	if _, e := store.ImportHistory(ctx, batch, false); e != nil {
		t.Fatal(e)
	}
	before := call("GET", "history", nil, 200)
	raw, _ := json.Marshal(before)
	if !strings.Contains(string(raw), canary) {
		t.Fatal("fixture original not present before purge")
	}
	plan := map[string]any{"version": "1", "entity": "observations", "operation": "search", "mode": "exact", "text": canary, "limit": 20}
	queryBefore := call("POST", "query", map[string]any{"plan": plan}, 200)["data"].(map[string]any)
	if len(queryBefore["rows"].([]any)) != 1 {
		t.Fatal("fixture query did not capture original", queryBefore)
	}
	call("POST", "permissions", map[string]any{"permission": "retention", "granted": true}, 200)
	call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "policy", "expected_revision": 0, "retain_seconds": 86400}, 200)
	run := call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "run", "expected_revision": 1}, 200)["data"].(map[string]any)
	call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "batch", "run_id": run["run_id"], "limit": 100}, 200)
	after := call("GET", "history", nil, 200)
	raw, _ = json.Marshal(after)
	if strings.Contains(string(raw), canary) {
		t.Fatal("expired original reconstructed through history")
	}
	queryAfter := call("POST", "query", map[string]any{"plan": plan}, 200)["data"].(map[string]any)
	if len(queryAfter["rows"].([]any)) != 0 {
		t.Fatal("expired original reconstructed through query", queryAfter)
	}
	var oldQuery []byte
	if e := f.conn.QueryRow(ctx, `SELECT to_jsonb(q) FROM noctis_v2.ai_query_results q WHERE id::text=$1`, queryBefore["id"]).Scan(&oldQuery); e != nil || strings.Contains(string(oldQuery), canary) {
		t.Fatal("persisted query reconstructs original", e)
	}
	rows := after["data"].([]any)
	if len(rows) != 1 {
		t.Fatal(after)
	}
	record := rows[0].(map[string]any)
	body := record["body"].(map[string]any)
	if record["archive_digest"] != batch.ArchiveDigest || record["legacy_id"] != "9007199254740993123" || body["availability"] != "retention_expired" || record["epistemic_status"] != "legacy_unvalidated" {
		t.Fatal("history provenance lost", after)
	}
	if _, e := store.ImportHistory(ctx, batch, false); e == nil {
		t.Fatal("historical replay restored expired original")
	}
	var retained bool
	if e := f.conn.QueryRow(ctx, `SELECT body::text LIKE '%'||$1::text||'%' FROM noctis_v2.legacy_records WHERE archive_digest=$2`, canary, batch.ArchiveDigest).Scan(&retained); e != nil || retained {
		t.Fatal("legacy mirror still contains purged text", e)
	}
}
