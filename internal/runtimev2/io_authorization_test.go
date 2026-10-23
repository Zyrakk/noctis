package runtimev2

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/enrichmentv2"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestIOAIProjectionBindingDeadlinePostgresHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name         string
		budget       int
		parent       time.Duration
		cancelOnPOST bool
		mode         string
		wantState    string
	}{
		{"headers_beyond_twenty_seconds", 30000, 0, false, "headers21s", "succeeded"},
		{"short_binding", 250, 0, false, "timeout", "dependency_blocked"},
		{"earlier_parent", 30000, 300 * time.Millisecond, false, "timeout", "dependency_blocked"},
		{"parent_cancel", 30000, 0, true, "timeout", "dependency_blocked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAIFixture(t)
			cfg := f.cfg
			for i := range cfg.Bindings {
				cfg.Bindings[i].Limits.DeadlineMS = tc.budget
			}
			if _, err := f.store.Save(context.Background(), cfg, cfg.Revision, "fixture-admin"); err != nil {
				t.Fatal(err)
			}
			f.mode.Store(tc.mode)
			f.entered = make(chan struct{}, 1)
			f.block = make(chan struct{})
			defer close(f.block)
			j, err := f.store.Submit(context.Background(), inference.Submit{Function: "evidence.translate", Input: f.input(t, "observation"), RequestID: uuid.NewString()}, "fixture-admin")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.parent > 0 {
				var end context.CancelFunc
				ctx, end = context.WithTimeout(ctx, tc.parent)
				defer end()
			}
			if tc.cancelOnPOST {
				go func() {
					select {
					case <-f.entered:
						cancel()
					case <-ctx.Done():
					}
				}()
			}
			start := time.Now()
			if err = f.store.Once(ctx); err != nil {
				t.Fatal(err)
			}
			if tc.mode == "headers21s" && time.Since(start) < 21*time.Second {
				t.Fatal("fixture did not cross former guard deadline")
			}
			job, err := f.store.Job(context.Background(), j.ID, "fixture-admin")
			if err != nil || job.State != tc.wantState || f.calls.Load() != 1 {
				t.Fatal(job, err, f.calls.Load())
			}
			if tc.wantState == "dependency_blocked" {
				var n int
				if err = f.conn.QueryRow(context.Background(), `SELECT count(*) FROM noctis_v2.ai_attempts WHERE state='uncertain' AND exposure_units>0`).Scan(&n); err != nil || n != 1 {
					t.Fatal("uncertain exposure lost", n, err)
				}
			}
		})
	}
}

func TestProjectionIOExplicitBudgetAndParentPostgres(t *testing.T) {
	dsn := productDB(t)
	c, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	for _, tc := range []struct{ budget, parent, minimum, maximum time.Duration }{
		{120 * time.Second, 0, 119 * time.Second, 120 * time.Second},
		{120 * time.Second, time.Minute, 59 * time.Second, time.Minute},
	} {
		ctx := context.Background()
		cancel := func() {}
		if tc.parent > 0 {
			ctx, cancel = context.WithTimeout(ctx, tc.parent)
		}
		err = intelligence.GuardProjectionIOWithBudget(ctx, c, tc.budget, func(ioCtx context.Context) error {
			deadline, ok := ioCtx.Deadline()
			if remaining := time.Until(deadline); !ok || remaining < tc.minimum || remaining > tc.maximum {
				t.Fatalf("remaining budget %v", remaining)
			}
			return nil
		})
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = intelligence.GuardProjectionIO(context.Background(), c, func(ctx context.Context) error {
		deadline, ok := ctx.Deadline()
		if remaining := time.Until(deadline); !ok || remaining < 19*time.Second || remaining > 20*time.Second {
			t.Fatalf("default budget %v", remaining)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestIOAIStableGuardOrdersConfigAndPIRRevocationPostgresHTTPS(t *testing.T) {
	for _, kind := range []string{"config", "pir", "body"} {
		t.Run(kind, func(t *testing.T) {
			f := newAIFixture(t)
			ctx := context.Background()
			var qid string
			if kind == "pir" {
				qid = uuid.NewString()
				coreExec(t, f.conn, `INSERT INTO noctis_v2.questions(id,title,terms) VALUES($1,'IO PIR','[]')`, qid)
				coreExec(t, f.conn, `INSERT INTO noctis_v2.question_sources(question_id,source_id) VALUES($1,$2)`, qid, f.source)
			}
			f.mode.Store("waitvalid")
			if kind == "body" {
				f.mode.Store("waitbody")
			}
			f.entered = make(chan struct{}, 1)
			f.block = make(chan struct{})
			j, e := f.store.Submit(ctx, inference.Submit{Function: "evidence.translate", Input: f.input(t, "observation"), RequestID: uuid.NewString()}, "fixture-admin")
			if e != nil {
				t.Fatal(e)
			}
			completed := make(chan error, 1)
			go func() { completed <- f.store.Once(ctx) }()
			select {
			case <-f.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("AI fixture not entered")
			}
			revoked := make(chan error, 1)
			go func() {
				if kind == "config" || kind == "body" {
					cfg := f.cfg
					cfg.Bindings[0].Enabled = false
					_, e := f.store.Save(ctx, cfg, cfg.Revision, "fixture-admin")
					revoked <- e
					return
				}
				c, e := pgx.Connect(ctx, f.dsn)
				if e != nil {
					revoked <- e
					return
				}
				defer c.Close(ctx)
				tx, e := c.Begin(ctx)
				if e != nil {
					revoked <- e
					return
				}
				defer tx.Rollback(ctx)
				if e = intelligence.LockProjectionTx(ctx, tx); e == nil {
					_, e = tx.Exec(ctx, `UPDATE noctis_v2.questions SET enabled=false WHERE id=$1`, qid)
				}
				if e == nil {
					e = tx.Commit(ctx)
				}
				revoked <- e
			}()
			lock := "SELECT pg_advisory_xact_lock(76238451003)%"
			if kind == "config" || kind == "body" {
				lock = "SELECT pg_advisory_xact_lock(76238451004)%"
			}
			coreWaitLock(t, f.conn, lock)
			select {
			case e := <-revoked:
				t.Fatal("revocation overtook admitted HTTPS", e)
			default:
			}
			close(f.block)
			if e = <-revoked; e != nil {
				t.Fatal(e)
			}
			if e = <-completed; e != nil {
				t.Fatal(e)
			}
			var n int
			if e = f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_products WHERE job_id=$1`, j.ID).Scan(&n); e != nil || n != 0 {
				t.Fatal("revoked AI RAM snapshot published", n, e)
			}
			if f.calls.Load() != 1 {
				t.Fatal("admitted API calls", f.calls.Load())
			}
			if e = f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_attempts WHERE state IN ('settled','uncertain')`).Scan(&n); e != nil || n != 1 {
				t.Fatal("admitted cost was refunded", n, e)
			}
		})
	}
}

func TestIOEnrichmentGuardAndRevokedCachePublicationPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	coreExec(t, c, `INSERT INTO noctis_v2.enrichment_policies VALUES('virustotal','p1',true,'["private"]',10,60)`)
	admitted := make(chan struct{})
	release := make(chan struct{})
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		close(admitted)
		<-release
		fmt.Fprint(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":1,"suspicious":0,"harmless":0,"undetected":0},"reputation":0}}}`)
	}))
	defer server.Close()
	store := enrichmentv2.Store{DSN: dsn, Secret: "synthetic", Endpoint: server.URL, Fetcher: capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(server.URL, "http://"): true}}}
	done := make(chan error, 1)
	go func() {
		_, e := store.Lookup(ctx, enrichmentv2.Request{Provider: "virustotal", Type: "domain", Value: "example.invalid", DataClass: "private", Permission: true})
		done <- e
	}()
	<-admitted
	revoke := make(chan error, 1)
	go func() {
		db, e := pgx.Connect(ctx, dsn)
		if e != nil {
			revoke <- e
			return
		}
		defer db.Close(ctx)
		tx, e := db.Begin(ctx)
		if e != nil {
			revoke <- e
			return
		}
		defer tx.Rollback(ctx)
		if e = intelligence.LockProjectionTx(ctx, tx); e == nil {
			_, e = tx.Exec(ctx, `UPDATE noctis_v2.enrichment_policies SET enabled=false`)
		}
		if e == nil {
			e = tx.Commit(ctx)
		}
		revoke <- e
	}()
	coreWaitLock(t, c, "SELECT pg_advisory_xact_lock(76238451003)%")
	select {
	case e := <-revoke:
		t.Fatal("provider revoke overtook admitted IO", e)
	default:
	}
	close(release)
	if e = <-revoke; e != nil {
		t.Fatal(e)
	}
	if e = <-done; e == nil {
		t.Fatal("revoked provider result returned")
	}
	var cached, used int
	if e = c.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.enrichment_cache),(SELECT used FROM noctis_v2.enrichment_usage LIMIT 1)`).Scan(&cached, &used); e != nil || cached != 0 || used != 1 {
		t.Fatal("cache publication or reservation refund", cached, used, e)
	}
	if _, e = store.Lookup(ctx, enrichmentv2.Request{Provider: "virustotal", Type: "domain", Value: "example.invalid", DataClass: "private", Permission: true}); e == nil || hits.Load() != 1 {
		t.Fatal("revoked policy invoked", e, hits.Load())
	}
}

func TestIODiscoveryTrialGuardAndRevokedPublicationPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	entered := make(chan struct{})
	release := make(chan struct{})
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		close(entered)
		<-release
		fmt.Fprint(w, "synthetic")
	}))
	defer server.Close()
	q, p, id := uuid.NewString(), uuid.NewString(), uuid.NewString()
	coreExec(t, c, `INSERT INTO noctis_v2.questions(id,title) VALUES($1,'trial')`, q)
	coreExec(t, c, `INSERT INTO noctis_v2.discovery_proposals(id,question_id,kind,endpoint,provenance,reason,score,expires_at,permission_status) VALUES($1,$2,'html',$3,'{}','synthetic','{}',clock_timestamp()+interval '1 hour','authorized')`, p, q, server.URL)
	coreExec(t, c, `INSERT INTO noctis_v2.discovery_trials(id,proposal_id,proposal_revision,expires_at,quota) VALUES($1,$2,1,clock_timestamp()+interval '1 hour',2)`, id, p)
	fetcher := capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(server.URL, "http://"): true}}
	done := make(chan error, 1)
	go func() { done <- RunDiscoveryTrial(ctx, dsn, id, fetcher) }()
	<-entered
	revoked := make(chan error, 1)
	go func() {
		db, e := pgx.Connect(ctx, dsn)
		if e != nil {
			revoked <- e
			return
		}
		defer db.Close(ctx)
		tx, e := db.Begin(ctx)
		if e != nil {
			revoked <- e
			return
		}
		defer tx.Rollback(ctx)
		if e = intelligence.LockProjectionTx(ctx, tx); e == nil {
			_, e = tx.Exec(ctx, `UPDATE noctis_v2.discovery_proposals SET permission_status='revoked',revision=revision+1 WHERE id=$1`, p)
		}
		if e == nil {
			e = tx.Commit(ctx)
		}
		revoked <- e
	}()
	coreWaitLock(t, c, "SELECT pg_advisory_xact_lock(76238451003)%")
	close(release)
	if e = <-revoked; e != nil {
		t.Fatal(e)
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	var succeeded bool
	var used int
	if e = c.QueryRow(ctx, `SELECT last_success_at IS NOT NULL,used FROM noctis_v2.discovery_trials WHERE id=$1`, id).Scan(&succeeded, &used); e != nil || succeeded || used != 1 {
		t.Fatal("revoked trial published/refunded", succeeded, used, e)
	}
	if e = RunDiscoveryTrial(ctx, dsn, id, fetcher); e == nil || hits.Load() != 1 {
		t.Fatal("revoked trial invoked", e, hits.Load())
	}
	coreExec(t, c, `UPDATE noctis_v2.discovery_proposals SET permission_status='authorized' WHERE id=$1`, p)
	coreExec(t, c, `UPDATE noctis_v2.discovery_trials SET proposal_revision=2 WHERE id=$1`, id)
	coreExec(t, c, `UPDATE noctis_v2.questions SET enabled=false,revision=revision+1 WHERE id=$1`, q)
	if e = RunDiscoveryTrial(ctx, dsn, id, fetcher); e == nil || hits.Load() != 1 {
		t.Fatal("paused PIR trial invoked", e, hits.Load())
	}
}
