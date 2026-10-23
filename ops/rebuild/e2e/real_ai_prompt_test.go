package main

import (
	"context"
	database "github.com/Zyrakk/noctis/internal/database/v2"
	"github.com/Zyrakk/noctis/internal/inference"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	promptsv2 "github.com/Zyrakk/noctis/prompts/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompleteReceiptRequiresExactV2FunctionSet(t *testing.T) {
	g := &realGuard{}
	for _, f := range inference.Functions {
		g.consumers = append(g.consumers, realConsumer{Function: f.ID, State: "succeeded", PromptVersion: "2", PromptDigest: promptsv2.DigestV2, CitationsVerified: true})
	}
	if !g.completeV2Coverage() {
		t.Fatal("full registered v2 set rejected")
	}
	g.consumers[0].PromptVersion = "1"
	if g.completeV2Coverage() {
		t.Fatal("mixed versions declared complete")
	}
	g.consumers[0].PromptVersion = "2"
	g.consumers[0].PromptDigest = promptsv2.DigestV1
	if g.completeV2Coverage() {
		t.Fatal("wrong digest declared complete")
	}
	g.consumers[0].PromptDigest = promptsv2.DigestV2
	g.consumers[0].Function = g.consumers[1].Function
	if g.completeV2Coverage() {
		t.Fatal("duplicate/missing function declared complete")
	}
}

func TestPromptTransitionRejectsIncompatiblePendingPostgres(t *testing.T) {
	base := os.Getenv("NOCTIS_AI_RESUME_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("requires isolated PostgreSQL16 NOCTIS_AI_RESUME_TEST_DATABASE_URL")
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.Contains(u.Path, "v2_test") {
		t.Fatal("loopback synthetic test database required")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	name := "noctis_v2_e2e_prompt_" + uuid.NewString()[:8]
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	u.Path = "/" + name
	dsn := u.String()
	ms, err := database.Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.Migrate(ctx, dsn, ms); err != nil {
		t.Fatal(err)
	}
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	key := filepath.Join(dir, "synthetic-master.json")
	if err = os.WriteFile(key, []byte(`{"key_id":"synthetic","key":"`+strings.Repeat("a", 64)+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	inputs := realAIInputs{Adapter: "openai-responses", Provider: "synthetic", Endpoint: "https://example.invalid/v1/responses", Model: "synthetic", Price: inference.Price{Version: "synthetic", Input: 1, Output: 1}, Limits: inference.Limits{MaxInputTokens: 65536, MaxOutputTokens: 16, DeadlineMS: 1000}}
	store := inference.Store{DSN: dsn, KeyFile: key}
	cfg := inference.DefaultConfig()
	cfg.DailyCap = campaignLimit
	cfg.MonthlyCap = campaignLimit
	cfg.Connections = []inference.Connection{{ID: "synthetic", Provider: inputs.Provider, Adapter: inputs.Adapter, URL: inputs.Endpoint, DataClasses: []string{"private-approved"}, SecretAction: "set", APIKey: "SYNTHETIC"}}
	for i := range cfg.Bindings {
		b := &cfg.Bindings[i]
		b.PromptVersion = "1"
		b.Enabled = true
		b.ConnectionID = "synthetic"
		b.Model = inputs.Model
		b.Limits = inputs.Limits
		b.Price = inputs.Price
		b.StructuredJSON = true
		b.DailyCap = campaignLimit
		b.MonthlyCap = campaignLimit
	}
	if _, err = store.Save(ctx, cfg, 0, "synthetic"); err != nil {
		t.Fatal(err)
	}
	job, err := store.Submit(ctx, inference.Submit{Function: "query.plan", Input: inference.Input{Kind: "query", Text: "SYNTHETIC pending input"}, RequestID: "pending-old-prompt"}, "operator")
	if err != nil {
		t.Fatal(err)
	}
	g := &realGuard{store: store, inputs: inputs, expectedPromptVersion: "2"}
	if err = g.preparePromptVersion(ctx, c, true); err == nil {
		t.Fatal("transition rewrote incompatible pending job")
	}
	view, err := store.Read(ctx)
	if err != nil || view.Revision != 1 || view.Bindings[0].PromptVersion != "1" {
		t.Fatal("rejected transition changed config", err)
	}
	// An external explicit config CAS still cannot make a stale queued job safe.
	next := view.Config
	for i := range next.Bindings {
		next.Bindings[i].PromptVersion = "2"
	}
	next.Connections[0].SecretAction = "unchanged"
	if _, err = store.Save(ctx, next, 1, "synthetic-explicit-CAS"); err != nil {
		t.Fatal(err)
	}
	camp, err := openCampaign(filepath.Join(dir, "campaign.json"), "synthetic-fingerprint", true)
	if err != nil {
		t.Fatal(err)
	}
	defer camp.close()
	g.campaign = camp
	g.database = name
	g.receiptPath = filepath.Join(dir, "receipt.json")
	if err = g.once(ctx, "query.plan"); err == nil {
		t.Fatal("stale queued prompt reached reservation")
	}
	if len(camp.state.Entries) != 0 {
		t.Fatal("wrong queued prompt consumed campaign reservation")
	}
	var attempts int
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_attempts`).Scan(&attempts); err != nil || attempts != 0 {
		t.Fatal("wrong queued prompt created physical attempt", attempts, err)
	}
	retained, err := store.Job(ctx, job.ID, "operator")
	if err != nil || retained.State != "queued" {
		t.Fatal("incompatible pending job rewritten", err)
	}
}
