package runtimev2

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func governanceQuestion(call func(string, string, any, int) map[string]any, title string) (string, string) {
	q := call("POST", "questions", map[string]any{"title": title, "terms": []any{map[string]any{"type": "keyword", "value": "alert"}}}, 200)["data"].(map[string]any)
	return q["id"].(string), q["policy_version"].(string)
}

func governanceState(t *testing.T, f *aiFixture, source, question, policy string, revision int64, authorized bool) {
	t.Helper()
	var gotQuestion, gotPolicy string
	var gotRevision int64
	var gotAuthorized bool
	e := f.conn.QueryRow(context.Background(), `SELECT COALESCE(qs.question_id::text,''),s.policy_version,s.policy_revision,`+intelligence.SourceAuthorizedSQL+` FROM noctis_v2.sources s LEFT JOIN noctis_v2.question_sources qs ON qs.source_id=s.id WHERE s.id=$1`, source).Scan(&gotQuestion, &gotPolicy, &gotRevision, &gotAuthorized)
	if e != nil || gotQuestion != question || gotPolicy != policy || gotRevision != revision || gotAuthorized != authorized {
		t.Fatalf("governance: got %s %s %d %t, want %s %s %d %t: %v", gotQuestion, gotPolicy, gotRevision, gotAuthorized, question, policy, revision, authorized, e)
	}
}

func TestSourceGovernanceReplacementValidationAndIndependentPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	// Match production's DML grants without granting this runtime login DDL.
	cfg, e := pgx.ParseConfig(f.store.DSN)
	if e != nil {
		t.Fatal(e)
	}
	coreExec(t, f.conn, `GRANT DELETE ON noctis_v2.question_sources TO `+pgx.Identifier{cfg.User}.Sanitize())
	f.dsn = f.store.DSN
	call := operationsClient(t, f)
	ctx := context.Background()
	a, pa := governanceQuestion(call, "A")
	b, pb := governanceQuestion(call, "B")
	path := "sources/" + f.source + "/policy"
	call("POST", path, map[string]any{"expected_revision": 1, "enabled": true, "policy_version": pa}, 200)
	coreExec(t, f.conn, `UPDATE noctis_v2.question_sources SET independence='verified-A' WHERE source_id=$1`, f.source)
	call("POST", path, map[string]any{"expected_revision": 2, "enabled": true}, 200)
	var metadata string
	if e := f.conn.QueryRow(ctx, `SELECT independence FROM noctis_v2.question_sources WHERE source_id=$1`, f.source).Scan(&metadata); e != nil || metadata != "verified-A" {
		t.Fatal("omission lost relationship metadata", metadata, e)
	}
	request := map[string]any{"expected_revision": 3, "enabled": true, "policy_version": pb, "question_id": b, "request_id": uuid.NewString()}
	call("POST", path, request, 200)
	call("POST", path, request, 200)
	governanceState(t, f, f.source, b, pb, 4, true)
	var n int
	if e := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.jobs WHERE input_id=$1 AND policy_version=$2`, f.observation, pb).Scan(&n); e != nil || n != 1 {
		t.Fatal("reassignment/idempotency jobs", n, e)
	}
	if e := f.conn.QueryRow(ctx, `SELECT independence FROM noctis_v2.question_sources WHERE source_id=$1`, f.source).Scan(&metadata); e != nil || metadata != "unknown" {
		t.Fatal("replacement inherited old metadata", metadata, e)
	}
	call("POST", "questions/"+a+"/policy", map[string]any{"expected_revision": 1, "enabled": false}, 200)
	governanceState(t, f, f.source, b, pb, 4, true)
	if e := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.jobs WHERE input_id=$1 AND policy_version=$2`, f.observation, pa+":r2").Scan(&n); e != nil || n != 0 {
		t.Fatal("old governor created jobs", n, e)
	}
	call("POST", "questions/"+b+"/policy", map[string]any{"expected_revision": 1, "enabled": true, "terms": []any{map[string]any{"type": "keyword", "value": "ACME"}}}, 200)
	pb2 := pb + ":r2"
	governanceState(t, f, f.source, b, pb2, 5, true)
	// Every rejected operation preserves source, relationships, work and receipts.
	snapshot := func() string {
		var state string
		if e := f.conn.QueryRow(ctx, `SELECT jsonb_build_array((SELECT to_jsonb(s) FROM noctis_v2.sources s WHERE id=$1),(SELECT jsonb_agg(qs ORDER BY question_id) FROM noctis_v2.question_sources qs WHERE source_id=$1),(SELECT jsonb_agg(j ORDER BY id) FROM noctis_v2.jobs j),(SELECT jsonb_agg(a ORDER BY request_id) FROM noctis_v2.action_receipts a))::text`, f.source).Scan(&state); e != nil {
			t.Fatal(e)
		}
		return state
	}
	before := snapshot()
	for _, tc := range []struct {
		question, policy, code string
		revision               int
		status                 int
	}{
		{a, pb2, "question_policy_mismatch", 5, 400},
		{b, "p1", "question_policy_mismatch", 5, 400},
		{a, "", "question_policy_mismatch", 5, 400},
		{b, pb, "stale_question_policy", 5, 409},
		{b, pb2, "stale_revision", 4, 409},
		{"", "question:invalid", "invalid_question_policy", 5, 400},
	} {
		body := call("POST", path, map[string]any{"expected_revision": tc.revision, "enabled": true, "policy_version": tc.policy, "question_id": tc.question}, tc.status)
		if body["error"].(map[string]any)["code"] != tc.code || snapshot() != before {
			t.Fatal("rejection changed state or code", tc, body)
		}
	}
	// The current policy produces work; superseded A/B work cannot publish.
	coreDrainParse(t, f)
	if e := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.analyses WHERE observation_id=$1 AND policy_version IN($2,$3)`, f.observation, pa, pb).Scan(&n); e != nil || n != 0 {
		t.Fatal("old policy published", n, e)
	}
	if e := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.analyses WHERE observation_id=$1 AND policy_version=$2`, f.observation, pb2).Scan(&n); e != nil || n != 1 {
		t.Fatal("current policy did not publish", n, e)
	}
	call("POST", path, map[string]any{"expected_revision": 5, "enabled": true, "policy_version": "p1"}, 200)
	governanceState(t, f, f.source, "", "p1", 6, true)
	call("POST", "questions/"+b+"/policy", map[string]any{"expected_revision": 2, "enabled": false}, 200)
	governanceState(t, f, f.source, "", "p1", 6, true)
	call("POST", path, map[string]any{"expected_revision": 6, "enabled": true, "policy_version": pb + ":r3"}, 200)
	governanceState(t, f, f.source, b, pb+":r3", 7, false)
}

func TestSourceGovernanceDiscoveryReassignmentPreservesRevocationPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	call := operationsClient(t, f)
	ctx := context.Background()
	a, pa := governanceQuestion(call, "discovery A")
	b, pb := governanceQuestion(call, "governing B")
	var hits atomic.Int32
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `<rss><channel><item><guid>one</guid><title>alert fixture</title></item></channel></rss>`)
	}))
	defer feed.Close()
	p := call("POST", "discovery", map[string]any{"question_id": a, "kind": "rss", "endpoint": feed.URL, "reason": "synthetic", "provenance": map[string]any{"origin": "operator"}}, 200)["data"].(map[string]any)
	pPath := "discovery/" + p["id"].(string)
	call("POST", "permissions", map[string]any{"permission": "discovery_authorize", "granted": true}, 200)
	call("POST", pPath+"/authorize", map[string]any{"expected_revision": 1, "policy": map[string]any{"allowed": true, "purpose": "synthetic"}}, 200)
	call("POST", pPath+"/activate", map[string]any{"expected_revision": 2, "question_id": b}, 400)
	call("POST", pPath+"/activate", map[string]any{"expected_revision": 2, "policy_version": "p1"}, 400)
	call("POST", "questions/"+a+"/policy", map[string]any{"expected_revision": 1, "enabled": true}, 200)
	activated := call("POST", pPath+"/activate", map[string]any{"expected_revision": 2, "policy_version": pa}, 200)["data"].(map[string]any)
	source := activated["source_id"].(string)
	governanceState(t, f, source, a, pa+":r2", 1, true)
	path := "sources/" + source + "/policy"
	call("POST", path, map[string]any{"expected_revision": 1, "enabled": true, "policy_version": pb}, 200)
	call("POST", "questions/"+a+"/policy", map[string]any{"expected_revision": 2, "enabled": false}, 200)
	governanceState(t, f, source, b, pb, 2, true)
	fetcher := capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feed.URL, "http://"): true}}
	poll := func(wantCalls int32, blocked bool) {
		t.Helper()
		e := (capture.Store{DSN: f.dsn}).Poll(ctx, source, fetcher)
		if (blocked && !errors.Is(e, pgx.ErrNoRows)) || (!blocked && e != nil) || hits.Load() != wantCalls {
			t.Fatal("capture authorization", e, hits.Load(), wantCalls)
		}
	}
	poll(1, false)
	call("POST", "questions/"+b+"/policy", map[string]any{"expected_revision": 1, "enabled": false}, 200)
	poll(1, true)
	coreDrainParse(t, f)
	var n int
	if e := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.analyses a JOIN noctis_v2.observations o ON o.id=a.observation_id WHERE o.source_id=$1`, source).Scan(&n); e != nil || n != 0 {
		t.Fatal("paused governor published", n, e)
	}
	call("POST", path, map[string]any{"expected_revision": 3, "enabled": false}, 200)
	call("POST", "questions/"+b+"/policy", map[string]any{"expected_revision": 2, "enabled": true}, 200)
	governanceState(t, f, source, b, pb+":r3", 5, false)
	poll(1, true)
	call("POST", path, map[string]any{"expected_revision": 5, "enabled": true}, 200)
	call("POST", pPath+"/revoke", map[string]any{"expected_revision": 3}, 200)
	// An explicit analytical assignment still cannot override discovery revocation.
	call("POST", path, map[string]any{"expected_revision": 7, "enabled": true, "policy_version": pb + ":r3"}, 200)
	governanceState(t, f, source, b, pb+":r3", 8, false)
	poll(1, true)
	var origin string
	if e := f.conn.QueryRow(ctx, `SELECT question_id::text FROM noctis_v2.discovery_proposals WHERE id=$1`, p["id"]).Scan(&origin); e != nil || origin != a {
		t.Fatal("discovery provenance changed", origin, e)
	}
}

func TestSourceGovernanceReassignmentSerializesOldEditAndPublicationPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	call := operationsClient(t, f)
	ctx := context.Background()
	a, pa := governanceQuestion(call, "race A")
	b, pb := governanceQuestion(call, "race B")
	path := "sources/" + f.source + "/policy"
	call("POST", path, map[string]any{"expected_revision": 1, "enabled": true, "policy_version": pa}, 200)
	barrier, e := pgx.Connect(ctx, f.dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer barrier.Close(ctx)
	tx, e := barrier.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `SELECT id FROM noctis_v2.sources WHERE id=$1 FOR UPDATE`, f.source); e != nil {
		t.Fatal(e)
	}
	assigned, edited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(assigned)
		call("POST", path, map[string]any{"expected_revision": 2, "enabled": true, "policy_version": pb}, 200)
	}()
	coreWaitLock(t, f.conn, "SELECT policy_version,policy_revision%")
	// Reassignment holds projection admission but has not changed A yet. The
	// worker reads A and waits at Finish; the old question edit also queues.
	processed := make(chan error, 1)
	go func() { processed <- (intelligence.Worker{DSN: f.dsn, Owner: "governance-race"}).Once(ctx) }()
	coreWaitLock(t, f.conn, "SELECT pg_advisory_xact_lock(76238451003)%")
	go func() {
		defer close(edited)
		call("POST", "questions/"+a+"/policy", map[string]any{"expected_revision": 1, "enabled": false}, 200)
	}()
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	<-assigned
	<-edited
	if e = <-processed; e != nil {
		t.Fatal(e)
	}
	governanceState(t, f, f.source, b, pb, 3, true)
	var n int
	if e = f.conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.analyses WHERE policy_version=$1)+(SELECT count(*) FROM noctis_v2.jobs WHERE policy_version=$2)`, pa, pa+":r2").Scan(&n); e != nil || n != 0 {
		t.Fatal("old governor published or created work after replacement", n, e)
	}
	coreDrainParse(t, f)
}

func TestSourceGovernanceReassignmentDoesNotRenewTelegramConsentPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	call := operationsClient(t, f)
	ctx := context.Background()
	_, pa := governanceQuestion(call, "Telegram A")
	_, pb := governanceQuestion(call, "Telegram B")
	path := "sources/" + f.source + "/policy"
	call("POST", path, map[string]any{"expected_revision": 1, "enabled": true, "policy_version": pa}, 200)
	generation := uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES('governance',$1)`, generation)
	coreExec(t, f.conn, `UPDATE noctis_v2.sources SET kind='telegram',native_id='governance:channel:77' WHERE id=$1`, f.source)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.telegram_peers(account_id,peer_type,peer_id,source_id,auth_generation,allowed) VALUES('governance','channel',77,$1,$2,false)`, f.source, generation)
	call("POST", path, map[string]any{"expected_revision": 2, "enabled": true, "policy_version": pb}, 200)
	var allowed bool
	if e := f.conn.QueryRow(ctx, `SELECT allowed FROM noctis_v2.telegram_peers WHERE source_id=$1`, f.source).Scan(&allowed); e != nil || allowed {
		t.Fatal("analytical reassignment renewed revoked consent", allowed, e)
	}
}
