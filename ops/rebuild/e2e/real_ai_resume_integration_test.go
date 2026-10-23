package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	promptsv2 "github.com/Zyrakk/noctis/prompts/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	database "github.com/Zyrakk/noctis/internal/database/v2"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/inference"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This opt-in test creates its own database, uses a fixed synthetic credential
// and only a loopback HTTPS server. It never opens any real campaign or key.
func TestRealAIResumePostgresHTTPS(t *testing.T) {
	runRealAIResumePostgresHTTPS(t, false)
}
func TestRealAIPublicationDispositionPostgresHTTPS(t *testing.T) {
	runRealAIResumePostgresHTTPS(t, true)
}
func runRealAIResumePostgresHTTPS(t *testing.T, publication bool) {
	base := os.Getenv("NOCTIS_AI_RESUME_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("requires isolated PostgreSQL16 NOCTIS_AI_RESUME_TEST_DATABASE_URL")
	}
	u, e := url.Parse(base)
	if e != nil || u.Hostname() != "127.0.0.1" || !strings.Contains(u.Path, "v2_test") {
		t.Fatal("explicit loopback synthetic test database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	admin, e := pgx.Connect(ctx, base)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close(context.Background())
	var version int
	if e = admin.QueryRow(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&version); e != nil || version < 160000 || version >= 170000 {
		t.Fatal("PostgreSQL16 required", version, e)
	}
	name := "noctis_v2_e2e_resume_" + uuid.NewString()[:8]
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	u.Path = "/" + name
	dsn := u.String()
	ms, e := database.Load(migrations.Files)
	if e != nil {
		t.Fatal(e)
	}
	if e = database.Migrate(ctx, dsn, ms); e != nil {
		t.Fatal(e)
	}
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(context.Background())
	ids, e := seedProductFixture(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	period := time.Now().UTC().Format("2006-01-02")
	if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.briefs(period,policy_version,body) VALUES($1,'p7-synthetic-v1','{"synthetic":true}') ON CONFLICT DO NOTHING`, period); e != nil {
		t.Fatal(e)
	}
	role := "resume_" + uuid.NewString()[:8]
	roleSQL := pgx.Identifier{role}.Sanitize()
	if _, e = c.Exec(ctx, "CREATE ROLE "+roleSQL+" LOGIN;GRANT USAGE ON SCHEMA noctis_v2 TO "+roleSQL+";GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA noctis_v2 TO "+roleSQL+";GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA noctis_v2 TO "+roleSQL); e != nil {
		t.Fatal(e)
	}
	defer func() {
		c.Exec(context.Background(), "DROP OWNED BY "+roleSQL)
		c.Exec(context.Background(), "DROP ROLE "+roleSQL)
	}()
	runtimeURL := *u
	runtimeURL.User = url.User(role)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	secret := filepath.Join(dir, "database.secret")
	if e = os.WriteFile(secret, []byte(runtimeURL.String()), 0600); e != nil {
		t.Fatal(e)
	}
	cert, key, e := certificate(dir)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		t.Fatal(e)
	}
	var posts atomic.Int32
	var v1Posts, v2Posts atomic.Int32
	var failAt atomic.Int32
	var invalidAt atomic.Int32
	if publication {
		invalidAt.Store(5)
	}
	wantedAttempts := int32(13)
	wantedJobs := 21
	if publication {
		wantedAttempts = 15
		wantedJobs = 23
	}
	failAt.Store(2)
	gateway := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer SYNTHETIC-OFFLINE-RESPONSES" {
			w.WriteHeader(403)
			return
		}
		n := posts.Add(1)
		if n == failAt.Load() {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				conn.Close()
			}
			return
		}
		var body struct {
			Instructions string `json:"instructions"`
			Model        string `json:"model"`
			Input        string `json:"input"`
			Text         struct {
				Format struct {
					Schema struct {
						Properties struct {
							Kind struct {
								Enum []string `json:"enum"`
							} `json:"kind"`
						} `json:"properties"`
					} `json:"schema"`
				} `json:"format"`
			} `json:"text"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Text.Format.Schema.Properties.Kind.Enum) == 0 {
			w.WriteHeader(400)
			return
		}
		v1, _, _ := promptsv2.Resolve("1")
		v2, _, _ := promptsv2.Resolve("2")
		if strings.HasPrefix(body.Instructions, v1) {
			v1Posts.Add(1)
		} else if strings.HasPrefix(body.Instructions, v2) {
			v2Posts.Add(1)
		} else {
			t.Error("unregistered wire instructions")
		}
		var snap inference.Snapshot
		if json.Unmarshal([]byte(body.Input), &snap) != nil {
			w.WriteHeader(400)
			return
		}
		kind := body.Text.Format.Schema.Properties.Kind.Enum[0]
		if snap.Input.Kind == "observation" && kind != "evidence.translate" {
			kind = "semantic"
		}
		result := inference.Result{SchemaVersion: "1", Kind: kind, Text: "SYNTHETIC offline", Labels: []string{"unknown"}, Intent: "unknown", Claims: []inference.Claim{}, Entities: []inference.Entity{}, Roles: []inference.Role{}, Refs: []evidence.Ref{}, Limitations: []string{"SYNTHETIC"}}
		for _, d := range snap.Documents {
			result.Refs = append(result.Refs, d.Ref)
		}
		if kind == "query.plan" {
			result.Plan = &inference.QueryPlan{Version: "1", Entity: "observations", Operation: "search", Mode: "fulltext", Text: "ACME", Limit: 10}
		}
		if kind == "identity.disambiguate" {
			result.Identity = &inference.Identity{Relation: "unknown", Refs: result.Refs}
		}
		if kind == "vulnerability.context" {
			if len(snap.Documents) != 0 {
				t.Error("vulnerability feed fabricated documents")
			}
			result.Text = "SYNTHETIC feed context only; applicability and local exposure unknown."
		}
		if n == invalidAt.Load() {
			result.Claims = []inference.Claim{{Subject: "SECRET-DECOY-CONTEXT", Predicate: "reports", Object: "unsupported context claim", Refs: []evidence.Ref{}}}
		}
		raw, _ := json.Marshal(result)
		json.NewEncoder(w).Encode(map[string]any{"model": body.Model, "status": "completed", "usage": map[string]int{"input_tokens": 100, "output_tokens": 20}, "output": []any{map[string]any{"type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": string(raw)}}}}})
	}))
	gateway.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	gateway.StartTLS()
	defer gateway.Close()
	gu, _ := url.Parse(gateway.URL)
	inputs := realAIInputs{Adapter: "openai-responses", Provider: "synthetic-offline", Endpoint: gateway.URL + "/v1/responses", Model: "synthetic", APIKeyFile: filepath.Join(dir, "synthetic.key"), Price: inference.Price{Version: "test", Input: 4500, Output: 10000}, Limits: inference.Limits{MaxInputTokens: 65536, MaxOutputTokens: 2048, DeadlineMS: 3000}, ProviderContractReviewed: true}
	os.WriteFile(inputs.APIKeyFile, []byte("SYNTHETIC-OFFLINE-RESPONSES"), 0600)
	campaignPath := filepath.Join(dir, "campaign.json")
	var g *realGuard
	upgradePrompt := false
	setup := func(init, resume bool) func() {
		t.Helper()
		_, _, cleanup, err := setupRealAIFixture(ctx, dir, secret, "https://127.0.0.1", ids, "", campaignPath, init, true, inputs, cert, key, false, realFixtureOptions{Resume: resume, UpgradePromptV2: upgradePrompt, legacyPrompt: !upgradePrompt, OfflineAuthority: gu.Host, observe: func(guard *realGuard) { g = guard }})
		if err != nil {
			t.Fatal(err)
		}
		return cleanup
	}
	closeRun := setup(true, false)
	cfg := inference.DefaultConfig()
	cfg.DailyCap = campaignLimit
	cfg.MonthlyCap = campaignLimit
	cfg.Connections = []inference.Connection{{ID: "synthetic", Provider: inputs.Provider, Adapter: inputs.Adapter, URL: inputs.Endpoint, DataClasses: []string{"private-approved"}, SecretAction: "set", APIKey: "SYNTHETIC-OFFLINE-RESPONSES"}}
	for i := range cfg.Bindings {
		b := &cfg.Bindings[i]
		b.PromptVersion = "1"
		b.Enabled = true
		b.Model = inputs.Model
		b.ConnectionID = "synthetic"
		b.StructuredJSON = true
		b.Price = inputs.Price
		b.Limits = inputs.Limits
		b.DailyCap = campaignLimit
		b.MonthlyCap = campaignLimit
	}
	if _, e = g.store.Save(ctx, cfg, 0, "operator"); e != nil {
		closeRun()
		t.Fatal(e)
	}
	var originalConfig, originalSecretRows []byte
	if e = c.QueryRow(ctx, `SELECT to_jsonb(cfg) FROM noctis_v2.ai_configs cfg WHERE revision=1`).Scan(&originalConfig); e != nil {
		closeRun()
		t.Fatal(e)
	}
	if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(s)) FROM noctis_v2.ai_secrets s WHERE config_revision=1`).Scan(&originalSecretRows); e != nil {
		closeRun()
		t.Fatal(e)
	}
	var rev string
	if e = c.QueryRow(ctx, `SELECT revision FROM noctis_v2.observations WHERE id=$1`, ids["observation_b"]).Scan(&rev); e != nil {
		closeRun()
		t.Fatal(e)
	}
	j, e := g.store.Submit(ctx, inference.Submit{Function: "evidence.translate", Input: inference.Input{Kind: "observation", ID: ids["observation_b"], Revision: rev, Language: "es"}, RequestID: "translation-initial"}, "operator")
	if e != nil {
		closeRun()
		t.Fatal(e)
	}
	if e = g.once(ctx, "evidence.translate"); e != nil {
		closeRun()
		t.Fatal(e)
	}
	j, e = g.store.Job(ctx, j.ID, "operator")
	if e != nil {
		closeRun()
		t.Fatal(e)
	}
	if e = g.record(ctx, j); e != nil {
		closeRun()
		t.Fatal(e)
	}
	if e = g.suite(ctx, ids); e == nil {
		closeRun()
		t.Fatal("synthetic uncertain POST did not stop")
	}
	if posts.Load() != 2 || len(g.campaign.state.Entries) != 2 {
		closeRun()
		t.Fatal("unexpected initial physical attempts")
	}
	oldEntries := append([]campaignEntry{}, g.campaign.state.Entries...)
	oldID := oldEntries[1].Attempt
	var oldLedger []byte
	if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a) ORDER BY created_at,id) FROM noctis_v2.ai_attempts a`).Scan(&oldLedger); e != nil {
		closeRun()
		t.Fatal(e)
	}
	masterBefore, _ := os.ReadFile(filepath.Join(dir, "ai-master.json"))
	closeRun()
	raw, _ := os.ReadFile(campaignPath)
	q := campaignQuarantine{Attempt: oldID, Fingerprint: realFingerprint(inputs), PriorSHA: fmt.Sprintf("%x", sha256.Sum256(raw)), Reason: "SYNTHETIC integration acknowledged unknown usage", Time: time.Now().UTC().Format(time.RFC3339Nano), BinarySHA: strings.Repeat("a", 64)}
	audited, e := openCampaignAudited(campaignPath, realFingerprint(inputs), false, &q)
	if e != nil {
		t.Fatal(e)
	}
	audited.close()
	// Simulate crash after durable audit, then reenter through the actual setup.
	closeRun = setup(false, true)
	var left, right, caseRev string
	if e = c.QueryRow(ctx, `SELECT left_id::text,right_id::text FROM noctis_v2.entity_hypotheses WHERE id=$1`, ids["hypothesis_c"]).Scan(&left, &right); e != nil {
		closeRun()
		t.Fatal(e)
	}
	// A second transport failure occurs on the original identity request after
	// the first binary correction. Preserve it too, then audit a different SHA.
	failAt.Store(3)
	_, e = g.independent(ctx, "identity.disambiguate", inference.Input{Kind: "identity", ID: left, RightID: right})
	if e == nil || posts.Load() != 3 || len(g.campaign.state.Entries) != 3 {
		closeRun()
		t.Fatal("expected original identity uncertainty", e)
	}
	oldEntries = append([]campaignEntry{}, g.campaign.state.Entries...)
	oldIdentity := oldEntries[2].Attempt
	if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a) ORDER BY created_at,id) FROM noctis_v2.ai_attempts a`).Scan(&oldLedger); e != nil {
		closeRun()
		t.Fatal(e)
	}
	var oldBlocked, oldJobRows []byte
	if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM noctis_v2.ai_jobs j WHERE state='dependency_blocked'`).Scan(&oldBlocked); e != nil {
		closeRun()
		t.Fatal(e)
	}
	if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM noctis_v2.ai_jobs j`).Scan(&oldJobRows); e != nil {
		closeRun()
		t.Fatal(e)
	}
	closeRun()
	raw, _ = os.ReadFile(campaignPath)
	q2 := campaignQuarantine{Attempt: oldIdentity, Fingerprint: realFingerprint(inputs), PriorSHA: fmt.Sprintf("%x", sha256.Sum256(raw)), Reason: "SYNTHETIC second corrected binary, exact identity attempt", Time: time.Now().UTC().Format(time.RFC3339Nano), BinarySHA: strings.Repeat("b", 64)}
	audited, e = openCampaignAudited(campaignPath, realFingerprint(inputs), false, &q2)
	if e != nil {
		t.Fatal(e)
	}
	if len(audited.state.Quarantines) != 2 || audited.state.Quarantines[0] != q || validateLatestAuditBinary(audited.state, q2.BinarySHA) != nil || validateLatestAuditBinary(audited.state, q.BinarySHA) == nil {
		audited.close()
		t.Fatal("latest audit binary verification rewrote history or chose old digest")
	}
	audited.close()
	// Crash/reentry after second audit; no reservation or old job is reset.
	upgradePrompt = !publication
	closeRun = setup(false, true)
	if semantic, e := g.quarantinedEvaluation(ctx, c, []inference.Function{"semantic.classify", "semantic.relevance", "semantic.claims", "semantic.entities_relations", "semantic.observable_roles"}); e != nil || semantic != oldID {
		closeRun()
		t.Fatal("semantic target selected by audit order", semantic, e)
	}
	if identity, e := g.quarantinedEvaluation(ctx, c, []inference.Function{"identity.disambiguate"}); e != nil || identity != oldIdentity {
		closeRun()
		t.Fatal("identity target mismatch", identity, e)
	}
	var rejectedJob inference.JobView
	var publicationOld string
	if publication {
		if _, e = g.independent(ctx, "identity.disambiguate", inference.Input{Kind: "identity", ID: left, RightID: right}); e != nil {
			closeRun()
			t.Fatal(e)
		}
		var productsBefore int
		c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.claim_versions`).Scan(&productsBefore)
		if _, e = g.independent(ctx, "vulnerability.context", inference.Input{Kind: "vulnerability", ID: "CVE-2026-12345"}); e == nil || posts.Load() != 5 || !g.campaign.state.Stopped {
			closeRun()
			t.Fatal("settled validation failure did not stop", e)
		}
		oldEntries = append([]campaignEntry{}, g.campaign.state.Entries...)
		publicationOld = oldEntries[4].Attempt
		if len(oldEntries) != 5 || !oldEntries[4].Complete || oldEntries[4].Actual <= 0 {
			closeRun()
			t.Fatal("known usage changed to uncertain")
		}
		var jobID string
		var resultNull bool
		var diagnostic string
		if e = c.QueryRow(ctx, `SELECT j.id::text,j.result IS NULL,j.error_code FROM noctis_v2.ai_jobs j JOIN noctis_v2.ai_attempt_jobs aj ON aj.job_id=j.id WHERE aj.attempt_id=$1`, publicationOld).Scan(&jobID, &resultNull, &diagnostic); e != nil || !resultNull || diagnostic != "result_validation_failed:claim_fields_refs" {
			closeRun()
			t.Fatal("failed publication retained invalid result", e)
		}
		rejectedJob, e = g.store.Job(ctx, jobID, "operator")
		if e != nil || rejectedJob.Error != "result_validation_failed" || rejectedJob.ValidationReason != "claim_fields_refs" || rejectedJob.Result != nil {
			closeRun()
			t.Fatal("unsafe or missing validation reason", e)
		}
		encoded, _ := json.Marshal(rejectedJob)
		if strings.Contains(string(encoded), "SECRET-DECOY") {
			closeRun()
			t.Fatal("provider content leaked through API")
		}
		var productsAfter int
		c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.claim_versions`).Scan(&productsAfter)
		if productsBefore != productsAfter {
			closeRun()
			t.Fatal("invalid result published domain products")
		}
		var published bool
		if e = c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.ai_products WHERE job_id=$1) OR EXISTS(SELECT FROM noctis_v2.ai_publications WHERE job_id=$1)`, jobID).Scan(&published); e != nil || published {
			closeRun()
			t.Fatal("invalid result created publication/product rows", e)
		}
		if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a) ORDER BY created_at,id) FROM noctis_v2.ai_attempts a`).Scan(&oldLedger); e != nil {
			closeRun()
			t.Fatal(e)
		}
		if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM noctis_v2.ai_jobs j WHERE state IN ('dependency_blocked','failed')`).Scan(&oldBlocked); e != nil {
			closeRun()
			t.Fatal(e)
		}
		if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM noctis_v2.ai_jobs j`).Scan(&oldJobRows); e != nil {
			closeRun()
			t.Fatal(e)
		}
		closeRun()
		raw, _ = os.ReadFile(campaignPath)
		p := campaignPublicationDisposition{campaignQuarantine: campaignQuarantine{Attempt: publicationOld, Fingerprint: realFingerprint(inputs), PriorSHA: fmt.Sprintf("%x", sha256.Sum256(raw)), Reason: "SYNTHETIC acknowledged settled validation rejection; distinct evaluation only", Time: time.Now().UTC().Format(time.RFC3339Nano), BinarySHA: strings.Repeat("c", 64)}, State: "settled", Functions: []inference.Function{"vulnerability.context"}, Jobs: []campaignPublicationJob{{ID: jobID, Function: "vulnerability.context", State: "failed", Error: diagnostic}}, Maximum: oldEntries[4].Maximum, Actual: oldEntries[4].Actual}
		binaryPath := filepath.Join(dir, "synthetic-corrected-binary")
		binaryBody := []byte("SYNTHETIC corrected offline binary digest fixture")
		if e = os.WriteFile(binaryPath, binaryBody, 0700); e != nil {
			t.Fatal(e)
		}
		p.BinarySHA = fmt.Sprintf("%x", sha256.Sum256(binaryBody))
		validate := func(camp *campaign, p campaignPublicationDisposition) error {
			return validatePublicationSQL(ctx, dsn, camp, p)
		}
		for _, mutate := range []func(*campaignPublicationDisposition){func(p *campaignPublicationDisposition) { p.Attempt = uuid.NewString() }, func(p *campaignPublicationDisposition) { p.State = "uncertain" }, func(p *campaignPublicationDisposition) { p.PriorSHA = strings.Repeat("0", 64) }, func(p *campaignPublicationDisposition) { p.Fingerprint = "different" }, func(p *campaignPublicationDisposition) { p.Jobs[0].ID = uuid.NewString() }, func(p *campaignPublicationDisposition) { p.Jobs[0].Error = "result_validation_failed:SECRET-DECOY" }, func(p *campaignPublicationDisposition) { p.Jobs[0].State = "succeeded" }, func(p *campaignPublicationDisposition) { p.Functions = []inference.Function{"case.analyze"} }, func(p *campaignPublicationDisposition) { p.Actual++ }} {
			bad := p
			bad.Jobs = append([]campaignPublicationJob{}, p.Jobs...)
			mutate(&bad)
			if opened, err := openCampaignWithAudit(campaignPath, realFingerprint(inputs), false, nil, &bad, validate); err == nil {
				opened.close()
				t.Fatal("invalid publication disposition accepted")
			}
			after, _ := os.ReadFile(campaignPath)
			if string(after) != string(raw) {
				t.Fatal("rejected audit changed original campaign")
			}
		}
		auditJSON, _ := json.Marshal(p)
		var decoded campaignPublicationDisposition
		if strictRealJSON(auditJSON, &decoded) != nil || decoded.Attempt != p.Attempt || len(decoded.Jobs) != 1 || decoded.Jobs[0] != p.Jobs[0] {
			t.Fatal("publication audit JSON contract invalid")
		}
		auditPath := filepath.Join(dir, "publication-audit.json")
		if e = os.WriteFile(auditPath, auditJSON, 0600); e != nil {
			t.Fatal(e)
		}
		t.Setenv("NOCTIS_V2_TEST_DATABASE_URL", base)
		if e = applyPublicationAudit(binaryPath, campaignPath, auditPath, inputs); e != nil {
			t.Fatal("publication audit CLI boundary failed", e)
		}
		audited, e = openCampaign(campaignPath, realFingerprint(inputs), false)
		if e != nil {
			t.Fatal(e)
		}
		if validateLatestAuditBinary(audited.state, p.BinarySHA) != nil || validateLatestAuditBinary(audited.state, q2.BinarySHA) == nil || audited.state.Quarantines[0] != q || audited.state.Quarantines[1] != q2 {
			audited.close()
			t.Fatal("publication audit changed old correction history")
		}
		audited.close()
		if opened, err := openCampaignWithAudit(campaignPath, realFingerprint(inputs), false, nil, &p, validate); err == nil {
			opened.close()
			t.Fatal("publication audit replay accepted")
		}
		upgradePrompt = true
		closeRun = setup(false, true)
	}
	if _, found, err := g.evaluateHistoricalSuccessV2(ctx, c, "evidence.translate"); err != nil || !found {
		closeRun()
		t.Fatal("explicit v2 translation evaluation missing", err)
	}
	if e = c.QueryRow(ctx, `SELECT revision::text FROM noctis_v2.intelligence_cases WHERE id=$1`, ids["case_b"]).Scan(&caseRev); e != nil {
		closeRun()
		t.Fatal(e)
	}
	prefix := []struct {
		id inference.Function
		in inference.Input
	}{
		{"identity.disambiguate", inference.Input{Kind: "identity", ID: left, RightID: right}},
		{"vulnerability.context", inference.Input{Kind: "vulnerability", ID: "CVE-2026-12345"}},
		{"case.analyze", inference.Input{Kind: "case", ID: ids["case_b"], Revision: caseRev}},
		{"case.summarize", inference.Input{Kind: "case", ID: ids["case_b"], Revision: caseRev}},
		{"brief.compose", inference.Input{Kind: "brief", Period: period}},
		{"query.plan", inference.Input{Kind: "query", Text: "Find synthetic ACME observations"}},
	}
	var plan inference.QueryPlan
	for _, p := range prefix {
		j, e = g.independent(ctx, p.id, p.in)
		if e != nil {
			closeRun()
			t.Fatal(p.id, e)
		}
		if p.id == "query.plan" {
			plan = *j.Result.Plan
		}
		if publication && p.id == "vulnerability.context" {
			if j.Result == nil || len(j.Result.Refs) != 0 || len(j.Result.Claims) != 0 || len(j.Result.Entities) != 0 || len(j.Result.Roles) != 0 || g.vulnerabilityEvaluation["prior_failed_settled_attempt"] != publicationOld || g.vulnerabilityEvaluation["new_cve"] == "CVE-2026-12345" {
				closeRun()
				t.Fatal("new context-only vulnerability result or lineage invalid")
			}
			if output := os.Getenv("NOCTIS_AI_VALIDATION_UI_JOB_PATH"); output != "" {
				raw, _ := json.Marshal(map[string]any{"valid": j, "invalid": rejectedJob, "cve": g.vulnerabilityEvaluation["new_cve"]})
				if e = os.WriteFile(output, raw, 0600); e != nil {
					closeRun()
					t.Fatal(e)
				}
			}
		}
	}
	explainInput, e := g.explanationInput(ctx, c, plan)
	if e != nil {
		closeRun()
		t.Fatal(e)
	}
	explain, e := g.store.Submit(ctx, inference.Submit{Function: "query.explain", Input: explainInput, RequestID: "real-e2e-v1-query.explain"}, "operator")
	if e != nil || explain.State != "queued" {
		closeRun()
		t.Fatal("queued explanation setup", e)
	}
	beforeQueued := posts.Load()
	closeRun()
	closeRun = setup(false, true)
	reused, e := g.explanationInput(ctx, c, plan)
	if e != nil || reused != explainInput || posts.Load() != beforeQueued {
		closeRun()
		t.Fatal("queued explain input not reused", e)
	}
	badPlan := plan
	badPlan.Text = "different"
	if _, e = g.explanationInput(ctx, c, badPlan); e == nil {
		closeRun()
		t.Fatal("different plan accepted")
	}
	if e = g.suite(ctx, ids); e != nil {
		closeRun()
		t.Fatal("resumed suite", e)
	}
	if posts.Load() != wantedAttempts || len(g.consumers) != 14 || len(g.campaign.state.Entries) != int(wantedAttempts) {
		closeRun()
		t.Fatal("expected12 total attempts/14 outputs", posts.Load(), len(g.consumers))
	}
	if !g.completeV2Coverage() || v2Posts.Load() != 10 {
		closeRun()
		t.Fatal("not14 exact v2 functions/digest or10 new calls", v2Posts.Load())
	}
	wantedHistorical := 1
	if publication {
		wantedHistorical = 2
	}
	if len(g.historicalConsumers) != wantedHistorical {
		closeRun()
		t.Fatal("historical v1 consumers counted as v2")
	}
	if g.evaluation["new_observation_id"] == ids["observation_b"] || g.evaluation["new_case_id"] == ids["case_b"] || g.evaluation["prior_uncertain_attempt"] != oldID {
		closeRun()
		t.Fatal("semantic evaluation lineage invalid")
	}
	if !publication && (g.identityEvaluation["prior_uncertain_attempt"] != oldIdentity || g.identityEvaluation["new_left_entity_id"] == left || g.identityEvaluation["new_right_entity_id"] == right || g.identityEvaluation["new_case_id"] == ids["case_b"] || g.identityEvaluation["new_observation_id"] == ids["observation_b"]) {
		closeRun()
		t.Fatal("new identity evaluation did not preserve exact lineage/distinct IDs")
	}
	if publication {
		lineage := g.successV2Evaluations["identity.disambiguate"].(map[string]any)
		if lineage["historical_succeeded_attempt_id"] != oldEntries[3].Attempt || lineage["historical_succeeded_attempt_id"] == oldIdentity {
			closeRun()
			t.Fatal("v2 identity linked uncertain job instead of later v1 success")
		}
	}
	for function, value := range g.successV2Evaluations {
		lineage := value.(map[string]any)
		var sameInput, differentCache bool
		if e = c.QueryRow(ctx, `SELECT old.input=new.input,old.cache_key<>new.cache_key FROM noctis_v2.ai_jobs old JOIN noctis_v2.ai_jobs new ON new.id=$2 WHERE old.id=$1`, lineage["historical_succeeded_job_id"], lineage["new_job_id"]).Scan(&sameInput, &differentCache); e != nil || !sameInput || !differentCache {
			closeRun()
			t.Fatal("versioned reevaluation changed input or reused v1 cache", function, e)
		}
	}
	for i, entry := range oldEntries {
		if g.campaign.state.Entries[i] != entry {
			closeRun()
			t.Fatal("old reservation modified")
		}
	}
	var retained []byte
	oldIDs := []string{}
	for _, entry := range oldEntries {
		oldIDs = append(oldIDs, entry.Attempt)
	}
	if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(a) ORDER BY created_at,id) FROM noctis_v2.ai_attempts a WHERE id::text=ANY($1::text[])`, oldIDs).Scan(&retained); e != nil || string(retained) != string(oldLedger) {
		closeRun()
		t.Fatal("old ledger/unknown usage changed", e)
	}
	if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM noctis_v2.ai_jobs j WHERE EXISTS(SELECT FROM noctis_v2.ai_attempt_jobs aj WHERE aj.job_id=j.id AND aj.attempt_id::text=ANY($1::text[]))`, oldIDs).Scan(&retained); e != nil || string(retained) != string(oldJobRows) {
		closeRun()
		t.Fatal("historical v1 jobs/results/config revisions changed", e)
	}
	if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(j) ORDER BY j.id) FROM noctis_v2.ai_jobs j WHERE state IN ('dependency_blocked','failed')`).Scan(&retained); e != nil || string(retained) != string(oldBlocked) {
		closeRun()
		t.Fatal("six original blocked jobs changed", e)
	}
	var blocked int
	if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_jobs j JOIN noctis_v2.ai_attempt_jobs aj ON aj.job_id=j.id WHERE aj.attempt_id=$1 AND j.state='dependency_blocked'`, oldID).Scan(&blocked); e != nil || blocked != 5 {
		closeRun()
		t.Fatal("old uncertain jobs changed", blocked, e)
	}
	var totalJobs, successfulFunctions int
	if e = c.QueryRow(ctx, `SELECT count(*),count(DISTINCT function_id) FILTER(WHERE state='succeeded') FROM noctis_v2.ai_jobs`).Scan(&totalJobs, &successfulFunctions); e != nil || totalJobs != wantedJobs || successfulFunctions != 14 {
		closeRun()
		t.Fatal("expected retained6blocked plus14successful consumers", totalJobs, successfulFunctions, e)
	}
	closeRun()
	// The new semantic observation changes the day-wide brief snapshot. A later
	// suite must fail closed on that historical brief, without another POST or
	// reservation. Explain itself retains its query UUID in both terminal states.
	closeRun = setup(false, true)
	defer closeRun()
	if e = g.suite(ctx, ids); e == nil || !strings.Contains(e.Error(), "brief.compose") {
		t.Fatal("historical brief should require revalidation", e)
	}
	reused, e = g.explanationInput(ctx, c, plan)
	if e != nil || reused != explainInput {
		t.Fatal("completed explain UUID not reused", e)
	}
	if posts.Load() != wantedAttempts || len(g.campaign.state.Entries) != int(wantedAttempts) {
		t.Fatal("repeat suite paid again")
	}
	masterAfter, _ := os.ReadFile(filepath.Join(dir, "ai-master.json"))
	if string(masterAfter) != string(masterBefore) {
		t.Fatal("master key replaced")
	}
	maximum := int64(inputs.Limits.MaxInputTokens)*inputs.Price.Input + int64(inputs.Limits.MaxOutputTokens)*inputs.Price.Output
	if exposure, e := g.campaign.exposure(); e != nil || exposure != int64(wantedAttempts)*maximum {
		t.Fatal("all-time exposure changed", exposure, e)
	}
	var configs, bindings, results int
	if e = c.QueryRow(ctx, `SELECT count(*),max(jsonb_array_length(body->'bindings')) FROM noctis_v2.ai_configs`).Scan(&configs, &bindings); e != nil || configs != 2 || bindings != 14 {
		t.Fatal("configuration history changed", configs, bindings, e)
	}
	if e = c.QueryRow(ctx, `SELECT to_jsonb(cfg) FROM noctis_v2.ai_configs cfg WHERE revision=1`).Scan(&retained); e != nil || string(retained) != string(originalConfig) {
		t.Fatal("old config revision changed", e)
	}
	if e = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(s)) FROM noctis_v2.ai_secrets s WHERE config_revision=1`).Scan(&retained); e != nil || string(retained) != string(originalSecretRows) {
		t.Fatal("old encrypted credential row changed", e)
	}
	if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_query_results`).Scan(&results); e != nil || results != 1 {
		t.Fatal("explain reentry created extra query result", results, e)
	}
	// A newly uncertain UUID is not covered by the old quarantine and stops all
	// further calls, including after reopening the persisted campaign state.
	if publication {
		invalidAt.Store(wantedAttempts + 1)
		if err := g.campaign.reserve(g.database, maximum); err == nil || len(g.campaign.state.Entries) != 15 {
			t.Fatal("sixteenth full reservation allowed by cumulativeUSD5")
		}
	} else {
		failAt.Store(wantedAttempts + 1)
	}
	_, e = g.store.Submit(ctx, inference.Submit{Function: "query.plan", Input: inference.Input{Kind: "query", Text: "SYNTHETIC third uncertainty"}, RequestID: "third-uncertainty-test"}, "operator")
	if e != nil {
		t.Fatal(e)
	}
	if e = g.once(ctx, "query.plan"); e == nil || !g.stopped {
		t.Fatal("third uncertainty did not stop")
	}
	expectedPosts := wantedAttempts + 1
	if publication {
		expectedPosts = wantedAttempts
	}
	if e = g.once(ctx, "query.plan"); e == nil || posts.Load() != expectedPosts {
		t.Fatal("third uncertainty retried")
	}
	closeRun()
	closeRun = func() {}
	if reopened, err := openCampaign(campaignPath, realFingerprint(inputs), false); err == nil {
		reopened.close()
		t.Fatal("old quarantine allowed new uncertainty after restart")
	}
	t.Logf("PG16 + restricted LOGIN + stable fake HTTPS:%d total POSTs for14 exact v2 functions;%d original v1 entries/jobs/config/secrets/usage/reserves unchanged; one explicit CAS;10 new v2 calls; stable success-linked IDs/cache separation; repeated suite zero POST/reservations; next failure or budget exhaustion STOP; publication disposition=%t", wantedAttempts, len(oldEntries), publication)
}
