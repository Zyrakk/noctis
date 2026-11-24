package runtimev2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestDomainProcessChild(t *testing.T) {
	mode := os.Getenv("NOCTIS_DOMAIN_CHILD")
	if mode == "" {
		return
	}
	w := intelligence.Worker{DSN: os.Getenv("NOCTIS_DOMAIN_DSN"), Owner: "crash-fixture"}
	var e error
	if mode == "sender" {
		e = w.DispatchOnce(context.Background(), os.Getenv("NOCTIS_DOMAIN_RECEIVER"), nil)
	} else {
		e = w.Once(context.Background())
	}
	if e != nil {
		os.Exit(4)
	}
}
func TestSenderSIGKILLAfterReceiverAcceptanceRemainsUncertainPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	id, _, _ := qualifiedOutbox(t, dsn)
	accepted := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		accepted <- struct{}{}
		<-release
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	child := exec.Command(os.Args[0], "-test.run=^TestDomainProcessChild$")
	child.Env = append(os.Environ(), "NOCTIS_DOMAIN_CHILD=sender", "NOCTIS_DOMAIN_DSN="+dsn, "NOCTIS_DOMAIN_RECEIVER="+receiver.URL)
	if e = child.Start(); e != nil {
		close(release)
		t.Fatal(e)
	}
	defer func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	select {
	case <-accepted:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("child never reached receiver acceptance")
	}
	child.Process.Kill()
	child.Wait()
	close(release)
	var state string
	if e = c.QueryRow(ctx, `SELECT state FROM noctis_v2.outbox WHERE id=$1`, id).Scan(&state); e != nil || state != "uncertain" {
		t.Fatal("postaccept uncertainty lost", state, e)
	}
	e = (intelligence.Worker{DSN: dsn, Owner: "new-sender"}).DispatchOnce(ctx, receiver.URL, nil)
	if !errors.Is(e, pgx.ErrNoRows) || calls.Load() != 1 {
		t.Fatal("uncertain delivery resent", e, calls.Load())
	}
}

func qualifiedOutbox(t *testing.T, dsn string) (string, string, string) {
	t.Helper()
	ctx := context.Background()
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	source, epoch := uuid.NewString(), uuid.NewString()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version,epoch,activated_at) VALUES($1,'rss',$3,true,'p1',$2,clock_timestamp()-interval '1 hour')`, source, epoch, source)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	text := []byte("synthetic delivery evidence")
	hash := fmt.Sprintf("sha256:%x", sha256.Sum256(text))
	_, e = (capture.Store{DSN: dsn}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: source, Epoch: epoch, Mode: capture.Live, Items: []capture.Item{{NativeID: "1", Revision: "1", Hash: hash, Payload: text, Representation: "text/plain;utf8;v1", PublishedAt: &now, CollectedAt: now}}, Expected: capture.Checkpoint{Value: json.RawMessage(`null`)}, Next: capture.Checkpoint{Version: 1, Value: json.RawMessage(`1`)}})
	if e != nil {
		t.Fatal(e)
	}
	var obs string
	if e = c.QueryRow(ctx, `SELECT id::text FROM noctis_v2.observations WHERE source_id=$1`, source).Scan(&obs); e != nil {
		t.Fatal(e)
	}
	body, _ := json.Marshal(map[string]any{"synthetic": true, "citations": []evidence.Ref{{ObservationID: obs, Revision: "1", Hash: hash, Representation: "text/plain;utf8;v1", End: len(text)}}})
	id := uuid.NewString()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.outbox(id,delivery_key,body,state,policy_version) VALUES($1,$2,$3,'queued','p1')`, id, uuid.NewString(), string(body))
	if e != nil {
		t.Fatal(e)
	}
	return id, source, obs
}

func TestQueuedDeliveryRevalidatesRevokedSourcePolicyAndEvidencePostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	var calls atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	defer receiver.Close()
	for _, mutation := range []string{"disabled", "policy", "epoch", "deleted", "superseded"} {
		id, source, obs := qualifiedOutbox(t, dsn)
		switch mutation {
		case "disabled":
			_, e = c.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=false WHERE id=$1`, source)
		case "policy":
			_, e = c.Exec(ctx, `UPDATE noctis_v2.sources SET policy_version='p2' WHERE id=$1`, source)
		case "epoch":
			_, e = c.Exec(ctx, `UPDATE noctis_v2.sources SET epoch=$2 WHERE id=$1`, source, uuid.NewString())
		case "deleted":
			_, e = c.Exec(ctx, `UPDATE noctis_v2.observations SET source_deleted=true WHERE id=$1`, obs)
		case "superseded":
			_, e = c.Exec(ctx, `UPDATE noctis_v2.observations SET superseded_by=id WHERE id=$1`, obs)
		}
		if e != nil {
			t.Fatal(e)
		}
		if e = (intelligence.Worker{DSN: dsn}).DispatchOnce(ctx, receiver.URL, nil); !errors.Is(e, intelligence.ErrDeliveryBlocked) {
			t.Fatal("revoked queued delivery not blocked", mutation, e)
		}
		var state, reason string
		if e = c.QueryRow(ctx, `SELECT state,blocked_reason FROM noctis_v2.outbox WHERE id=$1`, id).Scan(&state, &reason); e != nil || state != "blocked" || reason == "" {
			t.Fatal("blocked disposition missing", mutation, state, reason, e)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("revoked deliveries reached receiver", calls.Load())
	}
}
func TestWorkerSIGKILLDerivedTransactionRollsBackAndReclaimsPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	source, epoch := uuid.NewString(), uuid.NewString()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p1','[{"type":"keyword","value":"alert"}]')`)
	if e != nil {
		t.Fatal(e)
	}
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version,epoch) VALUES($1,'rss','synthetic',true,'p1',$2)`, source, epoch)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	text := []byte("alert synthetic crash")
	_, e = (capture.Store{DSN: dsn}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: source, Epoch: epoch, Mode: capture.Bootstrap, Items: []capture.Item{{NativeID: "1", Revision: "1", Hash: fmt.Sprintf("sha256:%x", sha256.Sum256(text)), Payload: text, Representation: "text/plain;utf8;v1", CollectedAt: now}}, Expected: capture.Checkpoint{Value: json.RawMessage(`null`)}, Next: capture.Checkpoint{Version: 1, Value: json.RawMessage(`1`)}})
	if e != nil {
		t.Fatal(e)
	}
	var jobID string
	if e = c.QueryRow(ctx, `SELECT j.id::text FROM noctis_v2.jobs j
 JOIN noctis_v2.observations o ON o.id=j.input_id
 WHERE j.stage='parse' AND o.source_id=$1`, source).Scan(&jobID); e != nil {
		t.Fatal(e)
	}
	_, e = c.Exec(ctx, `CREATE FUNCTION noctis_v2.worker_barrier() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_sleep(2);RETURN NEW;END$$;CREATE TRIGGER worker_barrier BEFORE INSERT ON noctis_v2.analyses FOR EACH ROW EXECUTE FUNCTION noctis_v2.worker_barrier()`)
	if e != nil {
		t.Fatal(e)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestDomainProcessChild$")
	child.Env = append(os.Environ(), "NOCTIS_DOMAIN_CHILD=worker", "NOCTIS_DOMAIN_DSN="+dsn)
	if e = child.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var blocked bool
		if e = c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep')`).Scan(&blocked); e != nil {
			t.Fatal(e)
		}
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker never reached derived write barrier")
		}
		time.Sleep(10 * time.Millisecond)
	}
	child.Process.Kill()
	child.Wait()
	// PostgreSQL notices the dead connection once the deliberately delayed statement returns.
	_, e = c.Exec(ctx, `DROP TRIGGER worker_barrier ON noctis_v2.analyses`)
	if e != nil {
		t.Fatal(e)
	}
	for _, table := range []string{"analyses", "case_memberships", "case_changes", "outbox", "observable_sightings"} {
		var n int
		if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.`+table).Scan(&n); e != nil || n != 0 {
			t.Fatal("partial derived write", table, n, e)
		}
	}
	tag, e := c.Exec(ctx, `UPDATE noctis_v2.jobs
 SET lease_expires_at=clock_timestamp()-interval '1 second'
 WHERE id=$1 AND stage='parse' AND state='leased'
 AND lease_owner='crash-fixture' AND fence=1 AND attempts=1`, jobID)
	if e != nil || tag.RowsAffected() != 1 {
		t.Fatal("original worker lease missing after rollback", tag.RowsAffected(), e)
	}
	if e = (intelligence.Worker{DSN: dsn, Owner: "replacement"}).Once(ctx); e != nil {
		t.Fatal(e)
	}
	var state string
	var fence int
	if e = c.QueryRow(ctx, `SELECT state,fence FROM noctis_v2.jobs WHERE id=$1`, jobID).Scan(&state, &fence); e != nil || state != "succeeded" || fence != 2 {
		t.Fatal("lease recovery failed", state, fence, e)
	}
}
