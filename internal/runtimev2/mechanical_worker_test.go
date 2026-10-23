package runtimev2

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/google/uuid"
)

func TestMechanicalWorkerDoesNotExecuteOrPlanConfiguredAIPostgres(t *testing.T) {
	f := newAIFixture(t) // Every AI binding is enabled against a counting local TLS provider.
	ctx := context.Background()
	j, err := f.store.Submit(ctx, inference.Submit{Function: "query.plan", Input: f.input(t, "query"), RequestID: uuid.NewString()}, "fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	var hash, representation, epoch string
	var payload []byte
	if err = f.conn.QueryRow(ctx, `SELECT o.hash,o.representation,o.epoch::text,b.payload FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE o.id=$1`, f.observation).Scan(&hash, &representation, &epoch, &payload); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err = (capture.Store{DSN: f.store.DSN}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: f.source, Epoch: epoch, Mode: capture.Live, Items: []capture.Item{{NativeID: "mechanical-only", Revision: "1", Payload: payload, Hash: hash, Representation: representation, PublishedAt: &now, CollectedAt: now}}, Expected: capture.Checkpoint{Version: 1, Value: json.RawMessage(`1`)}, Next: capture.Checkpoint{Version: 2, Value: json.RawMessage(`2`)}}); err != nil {
		t.Fatal(err)
	}
	cfg := configv2.Config{Mode: "worker", DatabaseURL: f.store.DSN, AIKeyFile: f.store.KeyFile, AICAFile: f.store.CAFile}
	for authority := range f.store.AllowLocal {
		cfg.AIAuthorities = append(cfg.AIAuthorities, authority)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- Run(workerCtx, cfg) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(8 * time.Second)
	for {
		var complete bool
		err = f.conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM noctis_v2.jobs j JOIN noctis_v2.observations o ON o.id=j.input_id WHERE o.native_id='mechanical-only' AND j.state='succeeded')`).Scan(&complete)
		if err != nil {
			t.Fatal(err)
		}
		if complete {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("mechanical worker did not process observation")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Allow an additional complete tick: both execution and planning must stay off.
	time.Sleep(1200 * time.Millisecond)
	var attempts, planned int
	var state string
	if err = f.conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.ai_attempts),(SELECT count(*) FROM noctis_v2.ai_jobs WHERE actor='system:semantic-planner'),state FROM noctis_v2.ai_jobs WHERE id=$1`, j.ID).Scan(&attempts, &planned, &state); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || planned != 0 || f.calls.Load() != 0 || state != "queued" {
		t.Fatalf("automatic inference escaped disabled worker: attempts=%d planned=%d calls=%d state=%s", attempts, planned, f.calls.Load(), state)
	}
	cancel()
	// Opt-in still uses the same configured provider and durable executor/planner.
	cfg.AutomaticInference = true
	if err = runAutomaticInference(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if err = planAutomaticInference(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != 1 {
		t.Fatal("explicit opt-in did not execute queued inference")
	}
	if err = f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_jobs WHERE actor='system:semantic-planner'`).Scan(&planned); err != nil || planned == 0 {
		t.Fatalf("explicit opt-in did not plan eligible inference: planned=%d err=%v", planned, err)
	}
}
