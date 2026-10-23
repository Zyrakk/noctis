package capture

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Child uses the compiled test executable as an independent process. It never
// acknowledges a successful commit until the parent explicitly permits it.
func TestCaptureCrashChild(t *testing.T) {
	if os.Getenv("NOCTIS_CAPTURE_CHILD") != "1" {
		return
	}
	raw, e := os.ReadFile(os.Getenv("NOCTIS_CAPTURE_BATCH"))
	if e != nil {
		os.Exit(2)
	}
	var b Batch
	if json.Unmarshal(raw, &b) != nil {
		os.Exit(3)
	}
	if _, e = (Store{DSN: os.Getenv("NOCTIS_CAPTURE_DSN")}).CommitBatch(context.Background(), b); e != nil {
		os.Exit(4)
	}
	if e = os.WriteFile(os.Getenv("NOCTIS_CAPTURE_COMMITTED"), []byte("committed-before-ack"), 0600); e != nil {
		os.Exit(5)
	}
	select {}
}
func TestProcessDeathBeforeCommitAndAfterCommitBeforeACKPostgres(t *testing.T) {
	dsn := isolated(t)
	b := batch(t, dsn)
	ctx := context.Background()
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	dir := t.TempDir()
	batchFile, marker := filepath.Join(dir, "batch.json"), filepath.Join(dir, "committed")
	raw, _ := json.Marshal(b)
	if e = os.WriteFile(batchFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	start := func() *exec.Cmd {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestCaptureCrashChild$")
		cmd.Env = append(os.Environ(), "NOCTIS_CAPTURE_CHILD=1", "NOCTIS_CAPTURE_BATCH="+batchFile, "NOCTIS_CAPTURE_COMMITTED="+marker, "NOCTIS_CAPTURE_DSN="+dsn)
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		return cmd
	}
	_, e = c.Exec(ctx, `CREATE FUNCTION noctis_v2.test_pause_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(2); RETURN NEW; END $$; CREATE TRIGGER pause_receipt BEFORE INSERT ON noctis_v2.batch_receipts FOR EACH ROW EXECUTE FUNCTION noctis_v2.test_pause_receipt()`)
	if e != nil {
		t.Fatal(e)
	}
	child := start()
	t.Cleanup(func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		var blocked bool
		e = c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep')`).Scan(&blocked)
		if e != nil {
			t.Fatal(e)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child never reached precommit barrier")
		}
		time.Sleep(10 * time.Millisecond)
	}
	child.Process.Kill()
	child.Wait()
	if _, e = c.Exec(ctx, `DROP TRIGGER pause_receipt ON noctis_v2.batch_receipts; DROP FUNCTION noctis_v2.test_pause_receipt()`); e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"observations", "content_blobs", "jobs", "checkpoints", "batch_receipts"} {
		var n int
		if e = c.QueryRow(ctx, "SELECT count(*) FROM noctis_v2."+table).Scan(&n); e != nil || n != 0 {
			t.Fatalf("partial commit %s=%d %v", table, n, e)
		}
	}
	child = start()
	deadline = time.Now().Add(5 * time.Second)
	for {
		if _, e = os.Stat(marker); e == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child never committed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	child.Process.Kill()
	child.Wait()
	receipt, e := (Store{DSN: dsn}).CommitBatch(ctx, b)
	if e != nil || receipt.BatchID != b.BatchID {
		t.Fatalf("postcommit replay failed %+v %v", receipt, e)
	}
	var n int
	if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations`).Scan(&n); e != nil || n != 1 {
		t.Fatalf("replay duplicate %d %v", n, e)
	}
}
