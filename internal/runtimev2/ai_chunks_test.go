package runtimev2

import (
	"context"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/google/uuid"
	"testing"
)

func TestAILastSegmentObservableContextCacheAndVisibleLimitPostgres(t *testing.T) {
	f := newAIFixture(t)
	f.mode.Store("tail_roles")
	ctx := context.Background()
	submit := func() inference.JobView {
		t.Helper()
		j, e := f.store.Submit(ctx, inference.Submit{Function: "semantic.observable_roles", Input: f.input(t, "observation"), RequestID: uuid.NewString()}, "fixture-admin")
		if e != nil {
			t.Fatal(e)
		}
		if e = f.store.Once(ctx); e != nil {
			t.Fatal(e)
		}
		j, e = f.store.Job(ctx, j.ID, "fixture-admin")
		if e != nil {
			t.Fatal(e)
		}
		return j
	}
	j := submit()
	if j.State != "succeeded" || j.Result == nil || len(j.Result.Roles) != 1 || j.Result.Roles[0].Value != "203.0.113.42" || j.Result.Roles[0].Refs[0].Start < 8192 {
		t.Fatal("last segment IOC not extracted", j)
	}
	submit()
	if f.calls.Load() != 1 {
		t.Fatal("compatible cache missed")
	}
	if _, e := f.conn.Exec(ctx, `UPDATE noctis_v2.analyses SET gate='unknown' WHERE observation_id=$1`, f.observation); e != nil {
		t.Fatal(e)
	}
	j = submit()
	if j.State != "succeeded" || f.calls.Load() != 2 {
		t.Fatal("incompatible context reused cache", j, f.calls.Load())
	}
	cfg := f.cfg
	for i := range cfg.Bindings {
		if cfg.Bindings[i].Function == "semantic.observable_roles" {
			cfg.Bindings[i].Limits.MaxInputTokens = 4096
		}
	}
	if _, e := f.store.Save(ctx, cfg, cfg.Revision, "fixture-admin"); e != nil {
		t.Fatal(e)
	}
	j = submit()
	if j.State != "failed" || j.Error != "input_limit" || f.calls.Load() != 2 {
		t.Fatal("oversized complete document not visibly blocked", j, f.calls.Load())
	}
}
