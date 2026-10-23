package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	db "github.com/Zyrakk/noctis/internal/database/v2"
	"github.com/Zyrakk/noctis/internal/jobs"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"
)

func isolated(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("NOCTIS_V2_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx := context.Background()
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := "noctis_v2_capture_" + uuid.NewString()[:8]
	if _, e = c.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(dsn)
	u.Path = "/" + name
	t.Cleanup(func() { c.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); c.Close(ctx) })
	ms, _ := db.Load(migrations.Files)
	if e = db.Migrate(ctx, u.String(), ms); e != nil {
		t.Fatal(e)
	}
	return u.String()
}
func batch(t *testing.T, dsn string) Batch {
	t.Helper()
	ctx := context.Background()
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	id, epoch := uuid.NewString(), uuid.NewString()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,policy_version,enabled,epoch,activated_at) VALUES($1::uuid,'rss',$1::text,'p1',true,$2,clock_timestamp()-interval '1 day')`, id, epoch)
	if e != nil {
		t.Fatal(e)
	}
	text := []byte("á証拠 CVE-2026-12345")
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256(text))
	now := time.Now().UTC()
	return Batch{BatchID: uuid.NewString(), Version: "1", SourceID: id, Epoch: epoch, Mode: Live, Expected: Checkpoint{Value: json.RawMessage("null")}, Next: Checkpoint{Version: 1, Value: json.RawMessage(`{"cursor":1}`)}, Items: []Item{{NativeID: "one", Revision: "r1", Payload: text, Hash: hash, Representation: "text-v1", CollectedAt: now, PublishedAt: &now}}}
}
func TestAtomicReplayConflictAndDedupPostgres(t *testing.T) {
	dsn := isolated(t)
	b := batch(t, dsn)
	s := Store{dsn}
	ctx := context.Background()
	first, e := s.CommitBatch(ctx, b)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.CommitBatch(ctx, b)
	if e != nil || !again.CommittedAt.Equal(first.CommittedAt) {
		t.Fatalf("replay %+v %v", again, e)
	}
	changed := b
	changed.Mode = Bootstrap
	if _, e = s.CommitBatch(ctx, changed); !errors.Is(e, ErrConflict) {
		t.Fatalf("batch digest collision accepted %v", e)
	}
	other := batch(t, dsn)
	other.Items = b.Items
	if _, e = s.CommitBatch(ctx, other); e != nil {
		t.Fatal(e)
	}
	c, _ := pgx.Connect(ctx, dsn)
	defer c.Close(ctx)
	for table, want := range map[string]int{"content_blobs": 1, "observations": 2, "jobs": 2, "batch_receipts": 2} {
		var n int
		if e = c.QueryRow(ctx, "SELECT count(*) FROM noctis_v2."+table).Scan(&n); e != nil || n != want {
			t.Fatalf("%s=%d want %d %v", table, n, want, e)
		}
	}
	conflict := b
	conflict.BatchID = uuid.NewString()
	conflict.Expected = b.Next
	conflict.Next = Checkpoint{Version: 2, Value: json.RawMessage("2")}
	conflict.Items = append([]Item(nil), b.Items...)
	conflict.Items[0].Payload = []byte("different")
	conflict.Items[0].Hash = fmt.Sprintf("sha256:%x", sha256.Sum256(conflict.Items[0].Payload))
	if _, e = s.CommitBatch(ctx, conflict); !errors.Is(e, ErrConflict) {
		t.Fatalf("revision conflict accepted %v", e)
	}
	var v int
	if e = c.QueryRow(ctx, `SELECT version FROM noctis_v2.checkpoints WHERE source_id=$1`, b.SourceID).Scan(&v); e != nil || v != 1 {
		t.Fatalf("cursor advanced on failed tx %d %v", v, e)
	}
}
func TestConcurrentClaimsAndStaleFencePostgres(t *testing.T) {
	dsn := isolated(t)
	b := batch(t, dsn)
	ctx := context.Background()
	if _, e := (Store{dsn}).CommitBatch(ctx, b); e != nil {
		t.Fatal(e)
	}
	s := jobs.Store{DSN: dsn}
	var wg sync.WaitGroup
	claimed := make(chan jobs.Job, 2)
	errs := make(chan error, 2)
	for _, owner := range []string{"a", "b"} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			j, e := s.Claim(ctx, owner, 100*time.Millisecond)
			if e == nil {
				claimed <- j
			} else {
				errs <- e
			}
		}(owner)
	}
	wg.Wait()
	close(claimed)
	close(errs)
	if len(claimed) != 1 {
		t.Fatalf("claimed %d", len(claimed))
	}
	for e := range errs {
		if !errors.Is(e, pgx.ErrNoRows) {
			t.Fatal(e)
		}
	}
	old := <-claimed
	time.Sleep(130 * time.Millisecond)
	fresh, e := s.Claim(ctx, "c", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if fresh.Fence <= old.Fence {
		t.Fatal("fence did not increase")
	}
	if e = s.Finish(ctx, old, func(pgx.Tx) error { t.Fatal("stale writer ran"); return nil }); !errors.Is(e, jobs.ErrLeaseLost) {
		t.Fatalf("stale accepted %v", e)
	}
	if e = s.Finish(ctx, fresh, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO noctis_v2.policies VALUES('fenced','[]',clock_timestamp())`)
		return e
	}); e != nil {
		t.Fatal(e)
	}
}

func TestLeaseExpiresDuringDerivedWriteRollsBackPostgres(t *testing.T) {
	dsn := isolated(t)
	b := batch(t, dsn)
	ctx := context.Background()
	if _, e := (Store{dsn}).CommitBatch(ctx, b); e != nil {
		t.Fatal(e)
	}
	s := jobs.Store{DSN: dsn}
	j, e := s.Claim(ctx, "old", 100*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	e = s.Finish(ctx, j, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `INSERT INTO noctis_v2.policies VALUES('must_rollback','[]',clock_timestamp()); SELECT pg_sleep(0.15)`)
		return e
	})
	if !errors.Is(e, jobs.ErrLeaseLost) {
		t.Fatalf("expired transaction succeeded %v", e)
	}
	c, _ := pgx.Connect(ctx, dsn)
	defer c.Close(ctx)
	var n int
	if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.policies`).Scan(&n); e != nil || n != 0 {
		t.Fatalf("derived write survived %d %v", n, e)
	}
	if e = s.Heartbeat(ctx, j, time.Second); !errors.Is(e, jobs.ErrLeaseLost) {
		t.Fatalf("stale heartbeat accepted %v", e)
	}
	newer, e := s.Claim(ctx, "new", time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Fail(ctx, newer, "invalid_input", true); e != nil {
		t.Fatal(e)
	}
	if e = s.Replay(ctx, newer.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.Cancel(ctx, newer.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.Replay(ctx, newer.ID); e != nil {
		t.Fatal(e)
	}
}
