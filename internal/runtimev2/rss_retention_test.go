package runtimev2

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func rssRetentionFixture(t *testing.T, kind string, handler http.HandlerFunc) (*aiFixture, capture.Fetcher) {
	t.Helper()
	f := &aiFixture{dsn: productDB(t), source: uuid.NewString()}
	var err error
	f.conn, err = pgx.Connect(context.Background(), f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.conn.Close(context.Background()) })
	feed := httptest.NewServer(handler)
	t.Cleanup(feed.Close)
	coreExec(t, f.conn, `INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version,epoch) VALUES($1,$2,$3,true,'p1',$4)`, f.source, kind, feed.URL, uuid.NewString())
	return f, capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feed.URL, "http://"): true}}
}

func rssRetentionDocument(kind string, entries ...[2]string) string {
	var out strings.Builder
	if kind == "atom" {
		out.WriteString(`<feed xmlns="http://www.w3.org/2005/Atom">`)
		for _, entry := range entries {
			fmt.Fprintf(&out, `<entry><id>%s</id><title>%s</title></entry>`, entry[0], entry[1])
		}
		out.WriteString(`</feed>`)
	} else {
		out.WriteString(`<rss><channel>`)
		for _, entry := range entries {
			fmt.Fprintf(&out, `<item><guid>%s</guid><title>%s</title></item>`, entry[0], entry[1])
		}
		out.WriteString(`</channel></rss>`)
	}
	return out.String()
}

func assertRSSRetentionState(t *testing.T, f *aiFixture, raw string, version, observations int) {
	t.Helper()
	var gotVersion, gotObservations, gotJobs, gotReceipts int
	var hash string
	err := f.conn.QueryRow(context.Background(), `SELECT c.version,c.value->>'feed_hash',
 (SELECT count(*) FROM noctis_v2.observations WHERE source_id=$1),
 (SELECT count(*) FROM noctis_v2.jobs j JOIN noctis_v2.observations o ON o.id=j.input_id WHERE o.source_id=$1),
 (SELECT count(*) FROM noctis_v2.batch_receipts)
 FROM noctis_v2.checkpoints c WHERE source_id=$1 AND mode='live'`, f.source).Scan(&gotVersion, &hash, &gotObservations, &gotJobs, &gotReceipts)
	if err != nil || gotVersion != version || gotObservations != observations || gotJobs != observations || gotReceipts != version || hash != fmt.Sprintf("%x", sha256.Sum256([]byte(raw))) {
		t.Fatalf("checkpoint=%d observations=%d jobs=%d receipts=%d hash=%s: %v", gotVersion, gotObservations, gotJobs, gotReceipts, hash, err)
	}
}

func TestRSSRetentionExactRepetitionsAndNewRevisionsPostgresHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name, kind       string
		retained, shared bool
	}{
		{name: "unshared", kind: "rss"},
		{name: "retained_shared_blob", kind: "rss", retained: true, shared: true},
		{name: "new_identity_restores_shared_blob", kind: "atom", shared: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			a := [2]string{"A", "old evidence"}
			entries := [][2]string{a}
			if tc.retained {
				entries = append(entries, [2]string{"C", a[1]})
			}
			var body atomic.Value
			body.Store(rssRetentionDocument(tc.kind, entries...))
			f, fetcher := rssRetentionFixture(t, tc.kind, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body.Load().(string)) })
			store := capture.Store{DSN: f.dsn}
			if err := store.Poll(ctx, f.source, fetcher); err != nil {
				t.Fatal(err)
			}
			var oldID, revision, oldJob string
			if err := f.conn.QueryRow(ctx, `SELECT o.id::text,o.revision,to_jsonb(j)::text FROM noctis_v2.observations o JOIN noctis_v2.jobs j ON j.input_id=o.id WHERE o.source_id=$1 AND o.native_id='A'`, f.source).Scan(&oldID, &revision, &oldJob); err != nil {
				t.Fatal(err)
			}
			coreExec(t, f.conn, `UPDATE noctis_v2.observations SET collected_at=clock_timestamp()-interval '3 days' WHERE id=$1`, oldID)
			call := operationsClient(t, f)
			corePurge(t, f, call)
			var expiredAt time.Time
			if err := f.conn.QueryRow(ctx, `SELECT retention_expired_at FROM noctis_v2.observations WHERE id=$1`, oldID).Scan(&expiredAt); err != nil {
				t.Fatal(err)
			}
			assertExpired := func(wantPayload bool) {
				t.Helper()
				var intact bool
				if err := f.conn.QueryRow(ctx, `SELECT o.retention_expired_at=$2 AND EXISTS(SELECT FROM noctis_v2.retention_tombstones WHERE observation_id=o.id)
 AND (octet_length(b.payload)>0)=$3 AND (SELECT count(*) FROM noctis_v2.jobs WHERE input_id=o.id)=1
 AND (SELECT to_jsonb(j)::text FROM noctis_v2.jobs j WHERE j.input_id=o.id)=$4
 FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE o.id=$1`, oldID, expiredAt, wantPayload, oldJob).Scan(&intact); err != nil || !intact {
					t.Fatal("expired observation, tombstone, blob or job changed", intact, err)
				}
				call("GET", "evidence/"+oldID+"?revision="+revision, nil, http.StatusGone)
			}
			assertExpired(tc.retained)

			// A completely expired feed still publishes its full-feed checkpoint.
			body.Store(rssRetentionDocument(tc.kind, a))
			if err := store.Poll(ctx, f.source, fetcher); err != nil {
				t.Fatal(err)
			}
			assertRSSRetentionState(t, f, body.Load().(string), 2, len(entries))
			assertExpired(tc.retained)

			b := [2]string{"B", "new evidence"}
			if tc.shared {
				b[1] = a[1]
			}
			body.Store(rssRetentionDocument(tc.kind, a, b))
			for version := 3; version <= 4; version++ {
				if err := store.Poll(ctx, f.source, fetcher); err != nil {
					t.Fatal(err)
				}
				assertRSSRetentionState(t, f, body.Load().(string), version, len(entries)+1)
				assertExpired(tc.shared)
			}
			var newID, newRevision string
			if err := f.conn.QueryRow(ctx, `SELECT id::text,revision FROM noctis_v2.observations WHERE source_id=$1 AND native_id='B' AND retention_expired_at IS NULL`, f.source).Scan(&newID, &newRevision); err != nil {
				t.Fatal(err)
			}
			call("GET", "evidence/"+newID+"?revision="+newRevision, nil, http.StatusOK)

			body.Store(rssRetentionDocument(tc.kind, a, [2]string{"A", "revised evidence"}, b))
			if err := store.Poll(ctx, f.source, fetcher); err != nil {
				t.Fatal(err)
			}
			assertRSSRetentionState(t, f, body.Load().(string), 5, len(entries)+2)
			assertExpired(tc.shared)
		})
	}
}

func TestRSSRetentionConcurrentPurgeBeforeCommitPostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var blocking atomic.Bool
	a, b := [2]string{"A", "old evidence"}, [2]string{"B", "new evidence"}
	f, fetcher := rssRetentionFixture(t, "rss", func(w http.ResponseWriter, r *http.Request) {
		if blocking.Load() {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			fmt.Fprint(w, rssRetentionDocument("rss", a, b))
			return
		}
		fmt.Fprint(w, rssRetentionDocument("rss", a))
	})
	store := capture.Store{DSN: f.dsn}
	if err := store.Poll(ctx, f.source, fetcher); err != nil {
		t.Fatal(err)
	}
	coreExec(t, f.conn, `UPDATE noctis_v2.observations SET collected_at=clock_timestamp()-interval '3 days' WHERE source_id=$1`, f.source)
	call := operationsClient(t, f)
	call("POST", "permissions", map[string]any{"permission": "retention", "granted": true}, 200)
	call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "policy", "expected_revision": 0, "retain_seconds": 86400}, 200)
	run := call("POST", "retention", map[string]any{"source_id": f.source, "data_class": "private", "action": "run", "expected_revision": 1}, 200)["data"].(map[string]any)
	blocking.Store(true)
	polled := make(chan error, 1)
	go func() { polled <- store.Poll(ctx, f.source, fetcher) }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	purged := make(chan error, 1)
	go func() {
		conn, err := pgx.Connect(ctx, f.dsn)
		if err != nil {
			purged <- err
			return
		}
		defer conn.Close(context.Background())
		tx, err := conn.Begin(ctx)
		if err != nil {
			purged <- err
			return
		}
		defer tx.Rollback(context.Background())
		if err = intelligence.LockProjectionTx(ctx, tx); err == nil {
			_, err = retentionTx(ctx, tx, operationInput{SourceID: f.source, DataClass: "private", Action: "batch", RunID: run["run_id"].(string), Limit: 100})
		}
		if err == nil {
			err = tx.Commit(ctx)
		}
		purged <- err
	}()
	// Retention waits for the fetch guard, then owns the projection lock before
	// the poll's commit transaction. Filtering must observe that committed purge.
	coreWaitLock(t, f.conn, "SELECT pg_advisory_xact_lock(76238451003)%")
	close(release)
	if err := <-purged; err != nil {
		t.Fatal(err)
	}
	if err := <-polled; err != nil {
		t.Fatal(err)
	}
	assertRSSRetentionState(t, f, rssRetentionDocument("rss", a, b), 2, 2)
	var intact bool
	if err := f.conn.QueryRow(ctx, `SELECT o.retention_expired_at IS NOT NULL AND octet_length(b.payload)=0
 AND EXISTS(SELECT FROM noctis_v2.retention_tombstones WHERE observation_id=o.id)
 FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE o.source_id=$1 AND o.native_id='A'`, f.source).Scan(&intact); err != nil || !intact {
		t.Fatal("poll reactivated concurrently purged observation", intact, err)
	}
}
