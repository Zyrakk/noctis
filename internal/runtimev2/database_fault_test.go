package runtimev2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	db "github.com/Zyrakk/noctis/internal/database/v2"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestWorkerRecoversAfterActualPostgresProcessRestart(t *testing.T) {
	image := os.Getenv("NOCTIS_V2_FAULT_DOCKER_IMAGE")
	if image == "" {
		t.Skip("requires explicit local PostgreSQL fixture image; never restarts shared database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	name := "noctis-v2-fault-" + uuid.NewString()[:8]
	reservation, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	binding := reservation.Addr().String()
	reservation.Close()
	docker := func(args ...string) string {
		t.Helper()
		out, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
		if e != nil {
			t.Fatalf("isolated Docker fixture %v: %s", e, out)
		}
		return strings.TrimSpace(string(out))
	}
	docker("run", "--detach", "--pull=never", "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-e", "POSTGRES_DB=noctis_v2_fault", "-p", binding+":5432", image)
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if out, e := exec.CommandContext(cleanup, "docker", "rm", "-f", "-v", name).CombinedOutput(); e != nil {
			t.Errorf("fixture removal failed: %v %s", e, out)
		}
	}()
	authority := docker("port", name, "5432/tcp")
	host, _, e := net.SplitHostPort(authority)
	if e != nil || host != "127.0.0.1" {
		t.Fatal("fixture not bound exclusively to loopback", authority)
	}
	dsn := "postgres://postgres@" + authority + "/noctis_v2_fault?sslmode=disable"
	connect := func() *pgx.Conn {
		t.Helper()
		deadline := time.Now().Add(12 * time.Second)
		for {
			c, e := pgx.Connect(ctx, dsn)
			if e == nil {
				return c
			}
			if time.Now().After(deadline) {
				t.Fatal("isolated PostgreSQL did not recover")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	c := connect()
	ms, e := db.Load(migrations.Files)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(ctx, dsn, ms); e != nil {
		t.Fatal(e)
	}
	source, epoch := uuid.NewString(), uuid.NewString()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p1','[{"type":"keyword","value":"alert"}]')`)
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version,epoch) VALUES($1,'rss','synthetic-fault',true,'p1',$2)`, source, epoch)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	text := []byte("alert synthetic restart")
	_, e = (capture.Store{DSN: dsn}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: source, Epoch: epoch, Mode: capture.Bootstrap, Items: []capture.Item{{NativeID: "1", Revision: "1", Hash: fmt.Sprintf("sha256:%x", sha256.Sum256(text)), Payload: text, Representation: "text/plain;utf8;v1", CollectedAt: now}}, Expected: capture.Checkpoint{Value: json.RawMessage(`null`)}, Next: capture.Checkpoint{Version: 1, Value: json.RawMessage(`1`)}})
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.Exec(ctx, `CREATE SEQUENCE noctis_v2.fail_once;CREATE FUNCTION noctis_v2.fail_once() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF nextval('noctis_v2.fail_once')=1 THEN RAISE EXCEPTION 'synthetic transient SQL failure';END IF;RETURN NEW;END$$;CREATE TRIGGER fail_once BEFORE INSERT ON noctis_v2.analyses FOR EACH ROW EXECUTE FUNCTION noctis_v2.fail_once();CREATE ROLE fixture_runtime LOGIN;GRANT USAGE ON SCHEMA noctis_v2 TO fixture_runtime;GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA noctis_v2 TO fixture_runtime;GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA noctis_v2 TO fixture_runtime;GRANT SELECT ON public.noctis_v2_migrations TO fixture_runtime`)
	if e != nil {
		t.Fatal(e)
	}
	runtimeURL, _ := url.Parse(dsn)
	runtimeURL.User = url.User("fixture_runtime")
	workerCtx, stopWorker := context.WithCancel(ctx)
	workerDone := make(chan error, 1)
	go func() {
		workerDone <- Run(workerCtx, configv2.Config{DatabaseURL: runtimeURL.String(), Mode: "worker"})
	}()
	defer func() {
		stopWorker()
		select {
		case e := <-workerDone:
			if e != nil {
				t.Errorf("worker exited unexpectedly: %v", e)
			}
		case <-time.After(5 * time.Second):
			t.Error("worker leaked after test")
		}
	}()
	deadline := time.Now().Add(8 * time.Second)
	for {
		var state string
		if e = c.QueryRow(ctx, `SELECT state FROM noctis_v2.jobs`).Scan(&state); e != nil {
			t.Fatal(e)
		}
		if state == "retry_wait" {
			break
		}
		select {
		case e := <-workerDone:
			workerDone <- e
			t.Fatal("operational failure killed worker", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("durable retry was not observed")
		}
		time.Sleep(25 * time.Millisecond)
	}
	c.Close(ctx)
	docker("stop", "--time", "1", name)
	time.Sleep(1200 * time.Millisecond)
	docker("start", name)
	c = connect()
	defer c.Close(context.Background())
	deadline = time.Now().Add(12 * time.Second)
	for {
		var state string
		var attempts int
		e = c.QueryRow(ctx, `SELECT state,attempts FROM noctis_v2.jobs`).Scan(&state, &attempts)
		if e == nil && state == "succeeded" {
			if attempts < 2 {
				t.Fatal("retry not exercised")
			}
			break
		}
		select {
		case e := <-workerDone:
			workerDone <- e
			t.Fatal("database outage killed worker", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("job failed to resume after actual PostgreSQL restart", state, e)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
