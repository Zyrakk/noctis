package runtimev2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/telegramv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func coreExec(t *testing.T, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, e := c.Exec(context.Background(), sql, args...); e != nil {
		t.Fatal(e)
	}
}

func coreWaitLock(t *testing.T, c *pgx.Conn, query string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for ctx.Err() == nil {
		var waiting bool
		if e := c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)`, query).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("database barrier not reached", query)
}

func corePurge(t *testing.T, f *aiFixture, call func(string, string, any, int) map[string]any) {
	t.Helper()
	call("POST", "permissions", map[string]any{"permission": "retention", "granted": true}, 200)
	call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "policy", "expected_revision": 0, "retain_seconds": 86400}, 200)
	r := call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "run", "expected_revision": 1}, 200)["data"].(map[string]any)
	call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "batch", "run_id": r["run_id"], "limit": 100}, 200)
}

func coreDrainParse(t *testing.T, f *aiFixture) {
	t.Helper()
	for i := 0; i < 50; i++ {
		e := (intelligence.Worker{DSN: f.dsn, Owner: "core005-drain"}).Once(context.Background())
		if errors.Is(e, pgx.ErrNoRows) {
			return
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	t.Fatal("parse queue did not drain")
}

func TestCore005PIRRevisionPauseOwnSourceAndDiscoveryRevokePostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	call := operationsClient(t, f)
	ctx := context.Background()
	coreExec(t, f.conn, `DELETE FROM noctis_v2.outbox`)
	q := call("POST", "questions", map[string]any{"title": "PIR effective", "terms": []any{map[string]any{"type": "keyword", "value": "OLDTERM"}}}, 200)["data"].(map[string]any)
	qid := q["id"].(string)
	call("POST", "permissions", map[string]any{"permission": "discovery_authorize", "granted": true}, 200)
	var hits atomic.Int32
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fmt.Fprint(w, `<rss><channel><item><guid>one</guid><title>NEWTERM 203.0.113.44</title></item></channel></rss>`)
	}))
	defer feed.Close()
	p := call("POST", "discovery", map[string]any{"question_id": qid, "kind": "rss", "endpoint": feed.URL, "reason": "synthetic regression", "provenance": map[string]any{"origin": "operator"}}, 200)["data"].(map[string]any)
	pPath := "discovery/" + p["id"].(string)
	call("POST", pPath+"/authorize", map[string]any{"expected_revision": 1, "policy": map[string]any{"allowed": true, "purpose": "test"}}, 200)
	call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 1, "enabled": true, "terms": []any{map[string]any{"type": "keyword", "value": "NEWTERM"}}}, 200)
	activated := call("POST", pPath+"/activate", map[string]any{"expected_revision": 2, "policy_version": "question:" + qid}, 200)["data"].(map[string]any)
	source := activated["source_id"].(string)
	call("POST", pPath+"/activate", map[string]any{"expected_revision": 3, "policy_version": "question:" + qid}, 409)
	var policy string
	if e := f.conn.QueryRow(ctx, `SELECT policy_version FROM noctis_v2.sources WHERE id=$1`, source).Scan(&policy); e != nil || policy != "question:"+qid+":r2" {
		t.Fatal("activation did not bind current PIR", policy, e)
	}
	store := capture.Store{DSN: f.dsn}
	fetcher := capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feed.URL, "http://"): true}}
	if e := store.Poll(ctx, source, fetcher); e != nil {
		t.Fatal(e)
	}
	if e := (intelligence.Worker{DSN: f.dsn, Owner: "core005"}).Once(ctx); e != nil {
		t.Fatal(e)
	}
	var gate string
	if e := f.conn.QueryRow(ctx, `SELECT a.gate FROM noctis_v2.analyses a JOIN noctis_v2.observations o ON o.id=a.observation_id WHERE o.source_id=$1`, source).Scan(&gate); e != nil || gate != "relevant" {
		t.Fatal("new PIR terms not applied", gate, e)
	}
	call("POST", "sources/"+source+"/policy", map[string]any{"expected_revision": 1, "enabled": false, "policy_version": policy}, 200)
	call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 2, "enabled": false}, 200)
	call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 3, "enabled": true}, 200)
	if e := store.Poll(ctx, source, fetcher); !errors.Is(e, pgx.ErrNoRows) || hits.Load() != 1 {
		t.Fatal("PIR resume overrode own source pause", e, hits.Load())
	}
	call("POST", "sources/"+source+"/policy", map[string]any{"expected_revision": 4, "enabled": true}, 200)
	call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 4, "enabled": false}, 200)
	if e := store.Poll(ctx, source, fetcher); !errors.Is(e, pgx.ErrNoRows) || hits.Load() != 1 {
		t.Fatal("PIR pause allowed capture", e, hits.Load())
	}
	call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 5, "enabled": true}, 200)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.outbox(id,delivery_key,body,state,policy_version) SELECT gen_random_uuid(),gen_random_uuid()::text,jsonb_build_object('citations',jsonb_build_array(jsonb_build_object('observation_id',o.id,'revision',o.revision,'hash',o.hash,'representation',o.representation,'start',0,'end',1))),'queued',s.policy_version FROM noctis_v2.observations o JOIN noctis_v2.sources s ON s.id=o.source_id WHERE s.id=$1`, source)
	call("POST", pPath+"/revoke", map[string]any{"expected_revision": 3}, 200)
	if e := store.Poll(ctx, source, fetcher); !errors.Is(e, pgx.ErrNoRows) || hits.Load() != 1 {
		t.Fatal("revoked activated source contacted wire", e, hits.Load())
	}
	if e := (intelligence.Worker{DSN: f.dsn}).DispatchOnce(ctx, feed.URL, nil); !errors.Is(e, pgx.ErrNoRows) || hits.Load() != 1 {
		t.Fatal("revoked source delivered", e, hits.Load())
	}
	var enabled bool
	if e := f.conn.QueryRow(ctx, `SELECT enabled FROM noctis_v2.sources WHERE id=$1`, source).Scan(&enabled); e != nil || enabled {
		t.Fatal("revocation left source enabled", e)
	}
	var before int
	if e := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_changes c JOIN noctis_v2.observations o ON o.id=c.observation_id WHERE o.source_id=$1`, source).Scan(&before); e != nil {
		t.Fatal(e)
	}
	// Resume jobs created before revocation must not publish from their old policy.
	for i := 0; i < 2; i++ {
		if e := (intelligence.Worker{DSN: f.dsn, Owner: "core005"}).Once(ctx); errors.Is(e, pgx.ErrNoRows) {
			break
		} else if e != nil {
			t.Fatal(e)
		}
	}
	var after int
	if e := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_changes c JOIN noctis_v2.observations o ON o.id=c.observation_id WHERE o.source_id=$1`, source).Scan(&after); e != nil || after != before {
		t.Fatal("revoked job published", before, after, e)
	}
}

func TestCore005RSSPauseDuringFetchDoesNotAdvanceCheckpointPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	entered, release := make(chan struct{}), make(chan struct{})
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
			fmt.Fprint(w, `<rss><channel><item><guid>late</guid><title>CVE-2026-12345</title></item></channel></rss>`)
		case <-r.Context().Done():
		}
	}))
	defer feed.Close()
	source := uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version,epoch) VALUES($1,'rss',$2,true,'p1',$3)`, source, feed.URL, uuid.NewString())
	done := make(chan error, 1)
	go func() {
		done <- (capture.Store{DSN: f.dsn}).Poll(ctx, source, capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feed.URL, "http://"): true}})
	}()
	<-entered
	pauseDone := make(chan error, 1)
	go func() {
		c, e := pgx.Connect(ctx, f.dsn)
		if e != nil {
			pauseDone <- e
			return
		}
		defer c.Close(ctx)
		tx, e := c.Begin(ctx)
		if e != nil {
			pauseDone <- e
			return
		}
		defer tx.Rollback(ctx)
		if e = intelligence.LockProjectionTx(ctx, tx); e == nil {
			_, e = tx.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=false WHERE id=$1`, source)
		}
		if e == nil {
			e = tx.Commit(ctx)
		}
		pauseDone <- e
	}()
	coreWaitLock(t, f.conn, "SELECT pg_advisory_xact_lock(76238451003)%")
	close(release)
	if e := <-pauseDone; e != nil {
		t.Fatal(e)
	}
	if e := <-done; e == nil {
		t.Fatal("capture committed after pause")
	}
	var n int
	if e := f.conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.checkpoints WHERE source_id=$1)+(SELECT count(*) FROM noctis_v2.observations WHERE source_id=$1)`, source).Scan(&n); e != nil || n != 0 {
		t.Fatal("paused fetch advanced state", n, e)
	}
}

func TestCore005PIRPauseFencesTelegramPayloadAndBootstrapPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	call := operationsClient(t, f)
	q := call("POST", "questions", map[string]any{"title": "Native PIR pause", "terms": []any{map[string]any{"type": "keyword", "value": "alert"}}}, 200)["data"].(map[string]any)
	qid := q["id"].(string)
	call("POST", "sources/"+f.source+"/policy", map[string]any{"expected_revision": 1, "enabled": true, "question_id": qid, "policy_version": q["policy_version"]}, 200)
	coreExec(t, f.conn, `UPDATE noctis_v2.sources SET kind='telegram',native_id='core005-native:channel:77' WHERE id=$1`, f.source)
	gen := uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES('core005-native',$1)`, gen)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.telegram_peers(account_id,peer_type,peer_id,source_id,auth_generation,access_hash,allowed) VALUES('core005-native','channel',77,$1,$2,123,true)`, f.source, gen)
	store := telegramv2.Store{DSN: f.dsn}
	provisionNativeBudget(t, f.dsn, f.conn, "core005-native")
	owner, e := store.Acquire(ctx, "core005-native", "core005-native", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	fixture := &protocolFixture{}
	coordinator := telegramv2.Coordinator{Store: store, Owner: owner, RPC: fixture}
	call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 1, "enabled": false}, 200)
	var payloadCalls atomic.Int32
	apply := func(id int, history *telegramv2.HistoryCursor) (telegramv2.Receipt, error) {
		mode := capture.Live
		if history != nil {
			mode = capture.Bootstrap
		}
		return store.CommitUpdates(ctx, owner, telegramv2.Envelope{BatchID: uuid.NewString(), Expected: telegramv2.State{}, Next: telegramv2.State{}, Difference: true, Mode: mode, History: history, Events: []telegramv2.Event{{Peer: telegramv2.Peer{Type: "channel", ID: 77}, MessageID: id, Revision: "1", Kind: "message", Text: func() ([]byte, error) { payloadCalls.Add(1); return []byte("alert native fixture"), nil }}}})
	}
	r, e := apply(51, nil)
	if e != nil || r.Excluded != 1 || payloadCalls.Load() != 0 {
		t.Fatal("paused PIR inspected native payload", r, e, payloadCalls.Load())
	}
	if _, e = coordinator.BackfillPage(ctx, f.source, 100); !errors.Is(e, pgx.ErrNoRows) || fixture.historyCalls.Load() != 0 {
		t.Fatal("paused backfill contacted native RPC", e)
	}
	var bootstrapEpoch string
	if e = f.conn.QueryRow(ctx, `SELECT bootstrap_epoch::text FROM noctis_v2.telegram_peers WHERE source_id=$1`, f.source).Scan(&bootstrapEpoch); e != nil {
		t.Fatal(e)
	}
	if _, e = apply(52, &telegramv2.HistoryCursor{SourceID: f.source, Epoch: bootstrapEpoch, Expected: 0, Next: 52}); e == nil || payloadCalls.Load() != 0 {
		t.Fatal("paused in-flight bootstrap advanced", e, payloadCalls.Load())
	}
	var n int
	if e = f.conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.telegram_history_cursors WHERE source_id=$1)+(SELECT count(*) FROM noctis_v2.checkpoints WHERE source_id=$1 AND mode='bootstrap')`, f.source).Scan(&n); e != nil || n != 0 {
		t.Fatal("paused native history moved", n, e)
	}
	call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 2, "enabled": true}, 200)
	r, e = apply(53, nil)
	if e != nil || r.Included != 1 || payloadCalls.Load() == 0 {
		t.Fatal("native capture did not resume", r, e)
	}
	if complete, e := coordinator.BackfillPage(ctx, f.source, 100); e != nil || !complete || fixture.historyCalls.Load() != 1 {
		t.Fatal("native bootstrap did not resume", e)
	}
	call("POST", "sources/"+f.source+"/policy", map[string]any{"expected_revision": 4, "enabled": false}, 200)
	call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 3, "enabled": false}, 200)
	call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 4, "enabled": true}, 200)
	before := payloadCalls.Load()
	r, e = apply(54, nil)
	if e != nil || r.Excluded != 1 || payloadCalls.Load() != before {
		t.Fatal("PIR resume overrode native own pause", r, e)
	}
	if _, e = coordinator.BackfillPage(ctx, f.source, 100); !errors.Is(e, pgx.ErrNoRows) || fixture.historyCalls.Load() != 1 {
		t.Fatal("own paused bootstrap contacted native RPC", e)
	}
}

func TestCore005PIREditsReprocessCurrentTermsWithoutFalseMaterialChangePostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	call := operationsClient(t, f)
	q := call("POST", "questions", map[string]any{"title": "Reprocess current PIR", "terms": []any{map[string]any{"type": "keyword", "value": "ACME"}}}, 200)["data"].(map[string]any)
	qid := q["id"].(string)
	call("POST", "sources/"+f.source+"/policy", map[string]any{"expected_revision": 1, "enabled": true, "policy_version": q["policy_version"], "question_id": qid}, 200)
	var before int
	if e := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_changes`).Scan(&before); e != nil {
		t.Fatal(e)
	}
	for i, term := range []string{"ABSENT_CURRENT_TERM", "ACME"} {
		updated := call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": i + 1, "enabled": true, "terms": []any{map[string]any{"type": "keyword", "value": term}}}, 200)["data"].(map[string]any)
		coreDrainParse(t, f)
		var gate string
		if e := f.conn.QueryRow(ctx, `SELECT gate FROM noctis_v2.analyses WHERE observation_id=$1 AND policy_version=$2`, f.observation, updated["policy_version"]).Scan(&gate); e != nil {
			t.Fatal(e)
		}
		want := "unknown"
		if i == 1 {
			want = "relevant"
		}
		if gate != want {
			t.Fatal("updated terms not used", gate, want)
		}
	}
	var after int
	if e := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_changes`).Scan(&after); e != nil || after != before {
		t.Fatal("PIR edit manufactured material change", before, after, e)
	}
}

func TestCore005WorkerReadThenPurgeCannotRegrowDerivativesPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	call := operationsClient(t, f)
	text := []byte("CVE-2026-12345 203.0.113.88 WORKER_PURGE_CANARY")
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256(text))
	obs := uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.content_blobs(hash,representation,payload) VALUES($1,'text/plain;utf8;v1',$2)`, hash, text)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) SELECT $1::uuid,source_id,$1::text,'1',$2,'text/plain;utf8;v1',epoch,'live',clock_timestamp()-interval '3 days' FROM noctis_v2.observations WHERE id=$3`, obs, hash, f.observation)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES($1,'parse',$2,'1','p1','1')`, uuid.NewString(), obs)
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
	if _, e = tx.Exec(ctx, `LOCK TABLE noctis_v2.policies IN ACCESS EXCLUSIVE MODE`); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- (intelligence.Worker{DSN: f.dsn, Owner: "read-purge"}).Once(ctx) }()
	coreWaitLock(t, f.conn, "SELECT terms FROM noctis_v2.policies%")
	corePurge(t, f, call)
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	var n int
	if e = f.conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.analyses WHERE observation_id=$1)+(SELECT count(*) FROM noctis_v2.observable_sightings WHERE observation_id=$1)+(SELECT count(*) FROM noctis_v2.case_memberships WHERE observation_id=$1)+(SELECT count(*) FROM noctis_v2.content_blobs WHERE hash=$2 AND octet_length(payload)>0)`, obs, hash).Scan(&n); e != nil || n != 0 {
		t.Fatal("purged RAM input regrew derivatives", n, e)
	}
}

func TestCore005OwnPauseParksAndResumesDurablyWithoutRevivingInvalidJobsPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	call := operationsClient(t, f)
	obs, job := uuid.NewString(), uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) SELECT $1::uuid,source_id,$1::text,'1',hash,representation,epoch,mode,clock_timestamp() FROM noctis_v2.observations WHERE id=$2`, obs, f.observation)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version,attempts) VALUES($1,'parse',$2,'1','p1','1',4)`, job, obs)
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
	if _, e = tx.Exec(ctx, `LOCK TABLE noctis_v2.policies IN ACCESS EXCLUSIVE MODE`); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- (intelligence.Worker{DSN: f.dsn, Owner: "pause-finish"}).Once(ctx) }()
	coreWaitLock(t, f.conn, "SELECT terms FROM noctis_v2.policies%")
	// The actor's pause wins after the worker read, before its Finish admission.
	waitingObs, waitingJob := uuid.NewString(), uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) SELECT $1::uuid,source_id,$1::text,'1',hash,representation,epoch,mode,clock_timestamp() FROM noctis_v2.observations WHERE id=$2`, waitingObs, f.observation)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES($1,'parse',$2,'1','p1','1')`, waitingJob, waitingObs)
	pause, e := f.conn.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = intelligence.LockProjectionTx(ctx, pause); e != nil {
		t.Fatal(e)
	}
	if _, e = pause.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=false,policy_revision=policy_revision+1 WHERE id=$1`, f.source); e != nil {
		t.Fatal(e)
	}
	if e = pauseSourceParseTx(ctx, pause, f.source); e != nil {
		t.Fatal(e)
	}
	if e = pause.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	var state, code string
	var attempts int
	if e = f.conn.QueryRow(ctx, `SELECT state,last_error_code,attempts FROM noctis_v2.jobs WHERE id=$1`, job).Scan(&state, &code, &attempts); e != nil || state != "dependency_blocked" || code != "source_paused" || attempts != 4 {
		t.Fatal("pause consumed claim or lost progress", state, code, attempts, e)
	}
	coreExec(t, f.conn, `UPDATE noctis_v2.jobs SET created_at=clock_timestamp()-interval '2 days' WHERE id=$1`, job)
	coreExec(t, f.conn, `UPDATE noctis_v2.jobs SET created_at=clock_timestamp()-interval '2 days' WHERE id=$1`, waitingJob)
	if e = f.conn.QueryRow(ctx, `SELECT state,last_error_code,attempts FROM noctis_v2.jobs WHERE id=$1`, waitingJob).Scan(&state, &code, &attempts); e != nil || state != "dependency_blocked" || code != "source_paused" || attempts != 0 {
		t.Fatal("queued pause did not preserve progress", state, code, attempts, e)
	}
	quarantined, cancelled, leased, expiredJob := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version,state,last_error_code,attempts) VALUES($1,'parse',$3,'1','p1','quarantine','quarantined','actual_failure',5),($2,'parse',$3,'1','p1','cancelled','cancelled','operator_cancelled',2)`, quarantined, cancelled, f.observation)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version,state,lease_owner,lease_expires_at,fence,attempts) VALUES($1,'parse',$2,'1','p1','leased','leased','other-owner',clock_timestamp()+interval '1 hour',7,3)`, leased, f.observation)
	expired := uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) SELECT $1::uuid,source_id,$1::text,'1',hash,representation,epoch,mode,clock_timestamp()-interval '3 days' FROM noctis_v2.observations WHERE id=$2`, expired, f.observation)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version,state,last_error_code) VALUES($1,'parse',$2,'1','p1','1','dependency_blocked','source_paused')`, expiredJob, expired)
	corePurge(t, f, call)
	// Holding an unrelated leased key must never deadlock the resume transaction.
	locked, e := barrier.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = locked.Exec(ctx, `SELECT id FROM noctis_v2.jobs WHERE id=$1 FOR UPDATE`, leased); e != nil {
		t.Fatal(e)
	}
	call("POST", "sources/"+f.source+"/policy", map[string]any{"expected_revision": 2, "enabled": true}, 200)
	call("POST", "sources/"+f.source+"/policy", map[string]any{"expected_revision": 3, "enabled": true}, 200)
	if e = locked.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	coreDrainParse(t, f)
	if e = f.conn.QueryRow(ctx, `SELECT state,attempts FROM noctis_v2.jobs WHERE id=$1`, waitingJob).Scan(&state, &attempts); e != nil || state != "succeeded" || attempts != 1 {
		t.Fatal("long queued pause aged into quarantine", state, attempts, e)
	}
	var n int
	if e = f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.analyses WHERE observation_id=$1 AND policy_version='p1' AND schema_version='1'`, obs).Scan(&n); e != nil || n != 1 {
		t.Fatal("resume did not produce exactly one analysis", n, e)
	}
	var intact bool
	if e = f.conn.QueryRow(ctx, `SELECT (SELECT state='quarantined' AND attempts=5 AND last_error_code='actual_failure' FROM noctis_v2.jobs WHERE id=$1) AND (SELECT state='cancelled' AND attempts=2 FROM noctis_v2.jobs WHERE id=$2) AND (SELECT state='leased' AND fence=7 AND lease_owner='other-owner' AND attempts=3 FROM noctis_v2.jobs WHERE id=$3) AND (SELECT state='dependency_blocked' AND last_error_code='source_paused' FROM noctis_v2.jobs WHERE id=$4) AND EXISTS(SELECT FROM noctis_v2.retention_tombstones WHERE observation_id=$5)`, quarantined, cancelled, leased, expiredJob, expired).Scan(&intact); e != nil || !intact {
		t.Fatal("resume revived an invalid or in-flight job", e)
	}
	if e = f.conn.QueryRow(ctx, `SELECT state,last_error_code IS NULL,attempts FROM noctis_v2.jobs WHERE id=$1`, job).Scan(&state, &intact, &attempts); e != nil || state != "succeeded" || !intact || attempts != 5 {
		t.Fatal("resume lost attempts/history", state, attempts, e)
	}
	// A PIR edit while the source stays independently paused needs a new key.
	call("POST", "sources/"+f.source+"/policy", map[string]any{"expected_revision": 4, "enabled": false}, 200)
	q := call("POST", "questions", map[string]any{"title": "PIR changed while own paused", "terms": []any{map[string]any{"type": "keyword", "value": "alert"}}}, 200)["data"].(map[string]any)
	qid := q["id"].(string)
	call("POST", "sources/"+f.source+"/policy", map[string]any{"expected_revision": 5, "enabled": false, "question_id": qid, "policy_version": q["policy_version"]}, 200)
	updated := call("POST", "questions/"+qid+"/policy", map[string]any{"expected_revision": 1, "enabled": true, "terms": []any{map[string]any{"type": "keyword", "value": "ACME"}}}, 200)["data"].(map[string]any)
	call("POST", "sources/"+f.source+"/policy", map[string]any{"expected_revision": 7, "enabled": true}, 200)
	coreDrainParse(t, f)
	if e = f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.analyses WHERE policy_version=$1`, updated["policy_version"]).Scan(&n); e != nil || n != 3 {
		t.Fatal("resume failed to insert current PIR keys", n, e)
	}
	if e = f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.analyses WHERE observation_id=$1`, expired).Scan(&n); e != nil || n != 0 {
		t.Fatal("resume reconstructed tombstone", n, e)
	}
}

func TestCore005OwnResumeWinsFinishAdmissionWithoutLostWakePostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	obs := uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) SELECT $1::uuid,source_id,$1::text,'1',hash,representation,epoch,mode,clock_timestamp() FROM noctis_v2.observations WHERE id=$2`, obs, f.observation)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES($1,'parse',$2,'1','p1','1')`, uuid.NewString(), obs)
	coreExec(t, f.conn, `UPDATE noctis_v2.sources SET enabled=false WHERE id=$1`, f.source)
	actor, e := pgx.Connect(ctx, f.dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer actor.Close(ctx)
	tx, e := actor.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- (intelligence.Worker{DSN: f.dsn, Owner: "resume-wins"}).Once(ctx) }()
	coreWaitLock(t, f.conn, "SELECT pg_advisory_xact_lock(76238451003)%")
	if _, e = tx.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=true WHERE id=$1`, f.source); e != nil {
		t.Fatal(e)
	}
	if e = resumeSourceParseTx(ctx, tx, f.source); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	var n int
	if e = f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.analyses WHERE observation_id=$1`, obs).Scan(&n); e != nil || n != 1 {
		t.Fatal("resume before Finish lost wake", n, e)
	}
}

func TestCore005DeliveryAdmissionOrdersRevocationAndUncertainPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	coreExec(t, f.conn, `DELETE FROM noctis_v2.outbox`)
	var hits atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	_, source, _ := qualifiedOutbox(t, f.dsn)
	tx, e := f.conn.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- (intelligence.Worker{DSN: f.dsn}).DispatchOnce(ctx, receiver.URL, nil) }()
	watch, e := pgx.Connect(ctx, f.dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer watch.Close(ctx)
	coreWaitLock(t, watch, "SELECT pg_advisory_lock(76238451003)%")
	if _, e = tx.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=false WHERE id=$1`, source); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; !errors.Is(e, intelligence.ErrDeliveryBlocked) || hits.Load() != 0 {
		t.Fatal("revocation winner leaked body", e, hits.Load())
	}
	id, _, obs := qualifiedOutbox(t, f.dsn)
	entered, release := make(chan struct{}), make(chan struct{})
	uncertainReceiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		close(entered)
		<-release
		w.WriteHeader(503)
	}))
	defer uncertainReceiver.Close()
	go func() { done <- (intelligence.Worker{DSN: f.dsn}).DispatchOnce(ctx, uncertainReceiver.URL, nil) }()
	<-entered
	purgeDone := make(chan error, 1)
	go func() {
		tx, e := watch.Begin(ctx)
		if e != nil {
			purgeDone <- e
			return
		}
		defer tx.Rollback(ctx)
		if e = intelligence.LockProjectionTx(ctx, tx); e == nil {
			e = redactRetentionTx(ctx, tx, []string{obs})
		}
		if e == nil {
			e = tx.Commit(ctx)
		}
		purgeDone <- e
	}()
	coreWaitLock(t, f.conn, "SELECT pg_advisory_xact_lock(76238451003)%")
	close(release)
	if e = <-done; e == nil {
		t.Fatal("ambiguous delivery acknowledged")
	}
	if e = <-purgeDone; e != nil {
		t.Fatal(e)
	}
	var state string
	if e = f.conn.QueryRow(ctx, `SELECT state FROM noctis_v2.outbox WHERE id=$1`, id).Scan(&state); e != nil || state != "uncertain" {
		t.Fatal("admitted delivery lost uncertainty", state, e)
	}
	if e = (intelligence.Worker{DSN: f.dsn}).DispatchOnce(ctx, receiver.URL, nil); !errors.Is(e, pgx.ErrNoRows) || hits.Load() != 1 {
		t.Fatal("uncertain was retried", e, hits.Load())
	}
}

func TestCore005RetentionMultiCitationReasonCannotRecomposePostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	call := operationsClient(t, f)
	canary := "MULTICITATION_REASON_CANARY_EXPIRED_A"
	// B remains current and shares A's valid blob; judgment deliberately stores B
	// as observation_id while citing [B,A] and quoting A in its description.
	b := uuid.NewString()
	coreExec(t, f.conn, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,published_at,collected_at) SELECT $1::uuid,source_id,$1::text,revision,hash,representation,epoch,mode,published_at,clock_timestamp() FROM noctis_v2.observations WHERE id=$2`, b, f.observation)
	var aRef evidence.Ref
	if e := f.conn.QueryRow(ctx, `SELECT o.id::text,o.revision,o.hash,o.representation,octet_length(b.payload) FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE o.id=$1`, f.observation).Scan(&aRef.ObservationID, &aRef.Revision, &aRef.Hash, &aRef.Representation, &aRef.End); e != nil {
		t.Fatal(e)
	}
	bRef := aRef
	bRef.ObservationID = b
	claim := uuid.NewString()
	raw, _ := json.Marshal([]evidence.Ref{bRef, aRef})
	coreExec(t, f.conn, `INSERT INTO noctis_v2.claim_versions(id,revision,case_id,subject,predicate,object,status,producer,policy_version,evidence) VALUES($1,1,$2,'source','claims','multiref','source_claim','operator:test','p1',$3)`, claim, f.caseID, string(raw))
	tx, e := f.conn.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = intelligence.JudgeClaimTx(ctx, tx, intelligence.ClaimVersion{ID: claim, Revision: 1}, "supported", "operator:test", canary, []evidence.Ref{bRef, aRef}); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	// Seed a preexisting extracted value so physical sighting redaction is checked.
	coreExec(t, f.conn, `INSERT INTO noctis_v2.observable_sightings VALUES('keyword',$1,$2,$3,0,1,$4)`, canary, f.observation, aRef.Revision, string(raw))
	coreExec(t, f.conn, `UPDATE noctis_v2.observations SET collected_at=clock_timestamp()-interval '3 days' WHERE id=$1`, f.observation)
	call("POST", "permissions", map[string]any{"permission": "export", "granted": true}, 200)
	var rev int64
	if e = f.conn.QueryRow(ctx, `SELECT revision FROM noctis_v2.intelligence_cases WHERE id=$1`, f.caseID).Scan(&rev); e != nil {
		t.Fatal(e)
	}
	exported := call("POST", "cases/"+f.caseID+"/exports", map[string]any{"expected_revision": rev, "format": "json"}, 200)["data"].(map[string]any)
	job, e := f.store.Submit(ctx, inference.Submit{Function: "case.summarize", Input: f.input(t, "case"), RequestID: uuid.NewString()}, "fixture-admin")
	if e != nil {
		t.Fatal(e)
	}
	corePurge(t, f, call)
	if e = (intelligence.Worker{DSN: f.dsn}).Brief(ctx, time.Now().UTC().Format("2006-01-02"), "p1"); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"cases/" + f.caseID, "today"} {
		body := call("GET", path, nil, 200)
		encoded, _ := json.Marshal(body)
		if strings.Contains(string(encoded), canary) {
			t.Fatal("canary served after purge", path)
		}
	}
	call("GET", "exports/"+exported["id"].(string), nil, 410)
	var leaked bool
	if e = f.conn.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.case_changes WHERE body::text LIKE '%'||$1||'%') OR EXISTS(SELECT FROM noctis_v2.case_revisions WHERE body::text LIKE '%'||$1||'%') OR EXISTS(SELECT FROM noctis_v2.claim_versions WHERE reason LIKE '%'||$1||'%') OR EXISTS(SELECT FROM noctis_v2.observable_sightings WHERE value LIKE '%'||$1||'%') OR EXISTS(SELECT FROM noctis_v2.briefs WHERE body::text LIKE '%'||$1||'%') OR EXISTS(SELECT FROM noctis_v2.private_exports WHERE body::text LIKE '%'||$1||'%') OR EXISTS(SELECT FROM noctis_v2.ai_jobs WHERE snapshot::text LIKE '%'||$1||'%' OR result::text LIKE '%'||$1||'%')`, canary).Scan(&leaked); e != nil || leaked {
		t.Fatal("physical canary retained", leaked, e)
	}
	view, e := f.store.Job(ctx, job.ID, "fixture-admin")
	if e != nil || view.Result != nil {
		t.Fatal("purged snapshot result served", e)
	}
	call("GET", "evidence/"+b+"?revision="+aRef.Revision, nil, 200)
	call("GET", "evidence/"+f.observation+"?revision="+aRef.Revision, nil, 410)
	var retained []byte
	var epoch string
	if e = f.conn.QueryRow(ctx, `SELECT b.payload,o.epoch::text FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE o.id=$1`, b).Scan(&retained, &epoch); e != nil || len(retained) == 0 {
		t.Fatal("valid shared blob cleared", e)
	}
	now := time.Now().UTC()
	_, e = (capture.Store{DSN: f.dsn}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: f.source, Epoch: epoch, Mode: capture.Live, Expected: capture.Checkpoint{Version: 1, Value: json.RawMessage(`1`)}, Next: capture.Checkpoint{Version: 2, Value: json.RawMessage(`2`)}, Items: []capture.Item{{NativeID: "one", Revision: aRef.Revision, Hash: aRef.Hash, Representation: aRef.Representation, Payload: retained, CollectedAt: now, PublishedAt: &now}}})
	if e == nil || !strings.Contains(e.Error(), "expired observation") {
		t.Fatal("replay restored expired identity", e)
	}
}
