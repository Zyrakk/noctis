package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/jackc/pgx/v5"
)

type realAIInputs struct {
	Adapter                  string           `json:"adapter"`
	Provider                 string           `json:"provider"`
	Endpoint                 string           `json:"endpoint"`
	Model                    string           `json:"model"`
	APIKeyFile               string           `json:"api_key_file"`
	Price                    inference.Price  `json:"price"`
	Limits                   inference.Limits `json:"limits"`
	ProviderContractReviewed bool             `json:"provider_contract_reviewed"`
}

func strictRealJSON(raw []byte, v any) error { return inference.Strict(raw, v) }
func loadRealAIInputs(path string, wire bool) (*realAIInputs, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, errors.New("real AI configuration unavailable")
	}
	var c realAIInputs
	if strictRealJSON(raw, &c) != nil {
		return nil, errors.New("real AI configuration invalid")
	}
	u, e := url.Parse(c.Endpoint)
	if c.Adapter != "openai-chat" && c.Adapter != "openai-responses" {
		return nil, errors.New("explicit supported adapter required")
	}
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.TrimSpace(c.Provider) == "" || strings.TrimSpace(c.Model) == "" || c.Price.Version == "" || c.Price.Input <= 0 || c.Price.Output <= 0 || c.Price.Input > 1e9 || c.Price.Output > 1e9 || c.Limits.MaxInputTokens < 1 || c.Limits.MaxInputTokens > 1<<20 || c.Limits.MaxOutputTokens < 1 || c.Limits.MaxOutputTokens > 65536 || c.Limits.DeadlineMS < 100 || c.Limits.DeadlineMS > 120000 {
		return nil, errors.New("explicit HTTPS endpoint, model, positive versioned tariffs and bounded limits required")
	}
	if !filepath.IsAbs(c.APIKeyFile) {
		return nil, errors.New("absolute API key file required")
	}
	info, e := os.Lstat(c.APIKeyFile)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("API key file must be regular 0600 (value never read by Go runner)")
	}
	if int64(c.Limits.MaxInputTokens)*c.Price.Input+int64(c.Limits.MaxOutputTokens)*c.Price.Output > campaignLimit {
		return nil, errors.New("one invocation exceeds campaign bound")
	}
	if wire && !c.ProviderContractReviewed {
		return nil, errors.New("wire disabled until provider transport, token bounds and tariffs are reviewed")
	}
	return &c, nil
}
func realFingerprint(c realAIInputs) string {
	// Keep credential contents and local filenames out of durable receipts.
	c.APIKeyFile = ""
	c.ProviderContractReviewed = false // Review approval cannot reset campaign identity.
	raw, _ := json.Marshal(c)
	return fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
}

type realAttempt struct {
	ID         string               `json:"attempt_id"`
	Functions  []inference.Function `json:"functions"`
	Maximum    int64                `json:"maximum_units"`
	Actual     *int64               `json:"actual_units"`
	Model      string               `json:"declared_model"`
	Usage      json.RawMessage      `json:"usage"`
	State      string               `json:"state"`
	Accounting *string              `json:"accounting_exception"`
	Revision   int64                `json:"config_revision"`
}
type realConsumer struct {
	Function          inference.Function `json:"function_id"`
	Job               string             `json:"job_id"`
	State             string             `json:"state"`
	Citations         int                `json:"citations"`
	CitationsVerified bool               `json:"citations_hash_utf8_verified"`
	ProposalOnly      bool               `json:"proposal_only"`
	PromptVersion     string             `json:"prompt_version"`
	PromptDigest      string             `json:"prompt_sha256"`
	Historical        bool               `json:"historical_v1_not_v2_validation"`
}
type realGuard struct {
	mu                      sync.Mutex
	store                   inference.Store
	campaign                *campaign
	inputs                  realAIInputs
	database                string
	stopped                 bool
	offline                 bool
	attempts                []realAttempt
	consumers               []realConsumer
	historicalConsumers     []realConsumer
	successV2Evaluations    map[inference.Function]any
	receiptPath             string
	resume                  bool
	evaluation              map[string]any
	identityEvaluation      map[string]any
	vulnerabilityEvaluation map[string]any
	expectedPromptVersion   string
	promptTransition        map[string]any
}

func (g *realGuard) receipt() error {
	total, e := g.campaign.exposure()
	if e != nil {
		return e
	}
	var known int64
	for _, a := range g.attempts {
		if a.Actual != nil {
			known += *a.Actual
		}
	}
	result := "panel_saved_zero_calls"
	if len(g.attempts) > 0 {
		result = "incomplete"
	}
	if g.completeV2Coverage() && !g.stopped {
		result = "completed_synthetic_real_inference"
		if g.offline {
			result = "completed_synthetic_offline_responses"
		}
	}
	if g.stopped {
		result = "stopped"
	}
	v2 := []inference.Function{}
	historical := []inference.Function{}
	for _, consumer := range g.consumers {
		if consumer.PromptVersion == "2" && !consumer.Historical {
			v2 = append(v2, consumer.Function)
		}
		if consumer.Historical {
			historical = append(historical, consumer.Function)
		}
	}
	for _, consumer := range g.historicalConsumers {
		historical = append(historical, consumer.Function)
	}
	raw, e := json.MarshalIndent(map[string]any{"result": result, "dataset": "SYNTHETIC", "adapter": g.inputs.Adapter, "endpoint": g.inputs.Endpoint, "requested_model": g.inputs.Model, "price": g.inputs.Price, "config_fingerprint": realFingerprint(g.inputs), "campaign_maximum_units": campaignLimit, "campaign_conservative_exposure_units": total, "known_tariff_units_this_database": known, "actual_provider_invoice_verified": false, "attempts_this_database": g.attempts, "consumers": g.consumers, "historical_consumers": g.historicalConsumers, "historical_success_v2_evaluations": g.successV2Evaluations, "quarantines": g.campaign.state.Quarantines, "new_semantic_evaluation": g.evaluation, "new_identity_evaluation": g.identityEvaluation, "publication_dispositions": g.campaign.state.Publications, "new_vulnerability_evaluation": g.vulnerabilityEvaluation, "automatic_retry": false, "continuous_worker": false, "human_quality_gates_closed": false, "quality_promotion": "pending_v2", "required_prompt_version": g.expectedPromptVersion, "prompt_transition": g.promptTransition, "validated_v2_functions": v2, "historical_v1_not_v2_validation": historical, "secrets_in_receipt": false}, "", "  ")
	if e != nil {
		return e
	}
	return os.WriteFile(g.receiptPath, append(raw, '\n'), 0600)
}
func (g *realGuard) ledger(ctx context.Context, c *pgx.Conn) ([]realAttempt, error) {
	rows, e := c.Query(ctx, `SELECT id::text,functions,maximum_units,actual_units,declared_model,usage,state,accounting_exception,config_revision FROM noctis_v2.ai_attempts ORDER BY created_at,id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	all := []realAttempt{}
	for rows.Next() {
		var a realAttempt
		var fs []byte
		var model *string
		if e = rows.Scan(&a.ID, &fs, &a.Maximum, &a.Actual, &model, &a.Usage, &a.State, &a.Accounting, &a.Revision); e != nil {
			return nil, e
		}
		if model != nil {
			a.Model = *model
		}
		if json.Unmarshal(fs, &a.Functions) != nil {
			return nil, errors.New("invalid functions ledger")
		}
		all = append(all, a)
	}
	return all, rows.Err()
}
func (g *realGuard) once(ctx context.Context, expected ...inference.Function) (err error) {
	if g.stopped {
		return errors.New("campaign stopped; no retries")
	}
	defer func() {
		if err != nil {
			g.stopped = true
			g.campaign.state.Stopped = true
			_ = g.campaign.save()
		}
		if re := g.receipt(); err == nil {
			err = re
		}
	}()
	c, e := pgx.Connect(ctx, g.store.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	// In addition to the campaign file lock, refuse another helper against this DB.
	var locked bool
	if e = c.QueryRow(ctx, `SELECT pg_try_advisory_lock(76238451999)`).Scan(&locked); e != nil || !locked {
		return errors.New("real inference database is locked")
	}
	defer c.Exec(context.Background(), `SELECT pg_advisory_unlock(76238451999)`)
	before, e := g.ledger(ctx, c)
	if e != nil {
		return e
	}
	if len(before) != len(g.attempts) {
		return errors.New("untracked inference ledger; no invocation authorized")
	}
	for _, a := range before {
		if g.campaign.quarantined(a.ID) && a.State == "uncertain" && a.Actual == nil && (len(a.Usage) == 0 || string(a.Usage) == "null") {
			continue
		}
		if a.State != "settled" || a.Actual == nil || len(a.Usage) == 0 || string(a.Usage) == "null" || a.Accounting != nil || a.Model != g.inputs.Model {
			return errors.New("prior usage, route or accounting is unsafe")
		}
	}
	var unsafe int
	if e = g.unsafeJobs(ctx, c, &unsafe); e != nil || unsafe != 0 {
		return errors.New("nonqueued or failed job present; retries forbidden")
	}
	view, e := g.store.Read(ctx)
	if e != nil {
		return e
	}
	// Freeze every binding and route; configuration changes are not a fallback.
	if len(view.Connections) != 1 || view.Connections[0].URL != g.inputs.Endpoint || view.Connections[0].Provider != g.inputs.Provider || view.Connections[0].Adapter != g.inputs.Adapter {
		return errors.New("panel connection mismatch")
	}
	for _, b := range view.Bindings {
		if !b.Enabled || b.Model != g.inputs.Model || b.Price != g.inputs.Price || b.Limits != g.inputs.Limits || b.ConnectionID != view.Connections[0].ID || !b.StructuredJSON || b.MaxConcurrent != 1 {
			return errors.New("panel binding mismatch")
		}
	}
	if e = g.validateBindings(view, g.expectedPromptVersion); e != nil {
		return e
	}
	maximum := int64(g.inputs.Limits.MaxInputTokens)*g.inputs.Price.Input + int64(g.inputs.Limits.MaxOutputTokens)*g.inputs.Price.Output
	if e = assertQueuedFunctions(ctx, c, expected); e != nil {
		return e
	}
	if e = assertQueuedPrompt(ctx, c, g.expectedPromptVersion, view.Revision); e != nil {
		return e
	}
	if e = g.campaign.reserve(g.database, maximum); e != nil {
		return e
	}
	callErr := g.store.Once(ctx) // EXACTLY ONCE. Never inspect retry_at to reschedule.
	after, e := g.ledger(context.WithoutCancel(ctx), c)
	if e != nil {
		_ = g.campaign.finish("", 0, false)
		return errors.New("postcall ledger unavailable; exposure unknown")
	}
	g.attempts = after
	if len(after) != len(before)+1 {
		_ = g.campaign.finish("", 0, false)
		return errors.New("expected exactly one physical attempt; stop")
	}
	a := after[len(after)-1]
	actual := int64(0)
	if a.Actual != nil {
		actual = *a.Actual
	}
	good := callErr == nil && a.State == "settled" && a.Actual != nil && len(a.Usage) > 0 && string(a.Usage) != "null" && a.Accounting == nil && a.Model == g.inputs.Model && a.Maximum == maximum
	if e = g.campaign.finish(a.ID, actual, good); e != nil {
		return e
	}
	if !good {
		return errors.New("inference failed, usage missing, model changed or accounting exception; stopped")
	}
	if e = g.unsafeJobs(ctx, c, &unsafe); e != nil || unsafe != 0 {
		return errors.New("job did not publish successfully; stopped")
	}
	return nil
}
func (g *realGuard) record(ctx context.Context, job inference.JobView) error {
	for _, consumer := range g.historicalConsumers {
		if consumer.Job == job.ID {
			return nil
		}
	}
	for _, consumer := range g.consumers {
		if consumer.Job == job.ID {
			return nil
		}
	}
	if job.State != "succeeded" || job.Result == nil {
		return errors.New("consumer result missing")
	}
	c, e := pgx.Connect(ctx, g.store.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	for _, ref := range job.Result.Refs {
		var raw []byte
		var hash, revision string
		if e = c.QueryRow(ctx, `SELECT b.payload,o.hash,o.revision FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE o.id=$1 AND o.representation=$2`, ref.ObservationID, ref.Representation).Scan(&raw, &hash, &revision); e != nil {
			return e
		}
		if hash != ref.Hash || revision != ref.Revision || hash != fmt.Sprintf("sha256:%x", sha256.Sum256(raw)) || ref.Start < 0 || ref.End > len(raw) || ref.End <= ref.Start || !utf8.Valid(raw[ref.Start:ref.End]) {
			return errors.New("citation hash or UTF8 bounds mismatch")
		}
	}
	version, digest, e := promptForJob(ctx, c, job.ID, job.Function)
	if e != nil {
		return e
	}
	consumer := realConsumer{Function: job.Function, Job: job.ID, State: job.State, Citations: len(job.Result.Refs), CitationsVerified: true, ProposalOnly: true, PromptVersion: version, PromptDigest: digest, Historical: g.resume && version == "1" && g.expectedPromptVersion == "2"}
	if consumer.Historical {
		g.historicalConsumers = append(g.historicalConsumers, consumer)
	} else {
		g.consumers = append(g.consumers, consumer)
	}
	return g.receipt()
}

type realFixtureOptions struct {
	Resume          bool
	UpgradePromptV2 bool
	legacyPrompt    bool
	// Fixed local HTTPS authority lets offline integration retain one synthetic
	// server and campaign identity across process reentry. No CLI exposes this.
	OfflineAuthority string
	observe          func(*realGuard)
}

func setupRealAIFixture(ctx context.Context, dir, secret, origin string, ids map[string]string, configPath, campaignPath string, init, wire bool, inputs realAIInputs, cert, tlsKey string, fake bool, options ...realFixtureOptions) ([]string, []string, func(), error) {
	option := realFixtureOptions{}
	if len(options) > 0 {
		option = options[0]
	}
	isResume := option.Resume
	extra := []string{}
	closeFake := func() {}
	setupComplete := false
	defer func() {
		if !setupComplete {
			closeFake()
		}
	}()
	if fake {
		var err error
		inputs, configPath, extra, closeFake, err = setupOfflineResponses(dir, cert, tlsKey, inputs)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	camp, e := openCampaign(campaignPath, realFingerprint(inputs), init)
	if e != nil {
		return nil, nil, nil, e
	}
	dsn, e := os.ReadFile(secret)
	if e != nil {
		camp.close()
		return nil, nil, nil, e
	}
	// The master key is new synthetic harness state, never the provider credential.
	master := filepath.Join(dir, "ai-master.json")
	if !isResume {
		key := make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			camp.close()
			return nil, nil, nil, e
		}
		raw, _ := json.Marshal(map[string]string{"key_id": "synthetic-real-e2e", "key": hex.EncodeToString(key)})
		if e = os.WriteFile(master, raw, 0600); e != nil {
			camp.close()
			return nil, nil, nil, e
		}
	} else if info, err := os.Lstat(master); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		camp.close()
		return nil, nil, nil, errors.New("existing encrypted credential master unavailable")
	}
	u, _ := url.Parse(string(dsn))
	g := &realGuard{store: inference.Store{DSN: string(dsn), KeyFile: master}, campaign: camp, inputs: inputs, database: strings.TrimPrefix(u.Path, "/"), receiptPath: filepath.Join(dir, "real-ai-receipt.json"), attempts: []realAttempt{}, consumers: []realConsumer{}}
	g.resume = isResume
	g.expectedPromptVersion = "2"
	if option.OfflineAuthority != "" {
		u, _ := url.Parse(inputs.Endpoint)
		if inputs.Provider != "synthetic-offline" || filepath.Base(inputs.APIKeyFile) != "synthetic.key" || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Host != option.OfflineAuthority {
			camp.close()
			return nil, nil, nil, errors.New("stable offline authority denied")
		}
		g.offline = true
		g.store.CAFile = cert
		g.store.AllowLocal = map[string]bool{u.Host: true}
		if option.legacyPrompt {
			g.expectedPromptVersion = "1"
		}
	}
	if isResume {
		c, err := pgx.Connect(ctx, g.store.DSN)
		if err != nil {
			camp.close()
			return nil, nil, nil, err
		}
		g.attempts, err = g.ledger(ctx, c)
		if err == nil && len(g.attempts) != len(camp.state.Entries) {
			err = errors.New("campaign ledger mismatch")
		}
		for _, entry := range camp.state.Entries {
			if entry.Database != g.database {
				err = errors.New("campaign database mismatch")
			}
			found := false
			for _, a := range g.attempts {
				if a.ID == entry.Attempt && a.Maximum == entry.Maximum {
					found = true
				}
			}
			if !found {
				err = errors.New("campaign attempt identity mismatch")
			}
		}
		var translation string
		if err == nil {
			var unsafe int
			err = g.unsafeJobs(ctx, c, &unsafe)
			if err == nil && unsafe != 0 {
				err = errors.New("unsafe historical work before prompt transition")
			}
		}
		if err == nil {
			err = g.preparePromptVersion(ctx, c, option.UpgradePromptV2)
		}
		if err == nil {
			var selected *succeededEvaluation
			selected, err = g.succeededEvaluation(ctx, c, "evidence.translate", "1")
			if err == nil && selected == nil {
				selected, err = g.succeededEvaluation(ctx, c, "evidence.translate", "2")
			}
			if err == nil && selected == nil {
				err = errors.New("exact succeeded translation unavailable")
			}
			if err == nil {
				translation = selected.Job
			}
		}
		c.Close(ctx)
		if err == nil {
			var job inference.JobView
			job, err = g.store.Job(ctx, translation, "operator")
			if err == nil {
				err = g.record(ctx, job)
			}
		}
		if err != nil {
			camp.close()
			return nil, nil, nil, err
		}
	}
	if fake {
		g.offline = true
		u, _ := url.Parse(inputs.Endpoint)
		g.store.CAFile = cert
		g.store.AllowLocal = map[string]bool{u.Host: true}
	}
	if e = g.receipt(); e != nil {
		camp.close()
		return nil, nil, nil, e
	}
	if option.observe != nil {
		option.observe(g)
	}
	token := make([]byte, 32)
	if _, e = rand.Read(token); e != nil {
		camp.close()
		return nil, nil, nil, e
	}
	controlToken := hex.EncodeToString(token)
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("X-Harness-Token") != controlToken {
			w.WriteHeader(403)
			return
		}
		g.mu.Lock()
		defer g.mu.Unlock()
		fail := func() {
			g.stopped = true
			g.campaign.state.Stopped = true
			_ = g.campaign.save()
			_ = g.receipt()
			http.Error(w, "real AI campaign stopped; see private sanitized receipt", 409)
		}
		if g.stopped || (!wire && r.URL.Path != "/zero-calls") {
			http.Error(w, "wire disabled or campaign stopped", 409)
			return
		}
		switch r.URL.Path {
		case "/translation-once":
			c, e := pgx.Connect(ctx, g.store.DSN)
			if e != nil {
				fail()
				return
			}
			var id, actor string
			e = c.QueryRow(ctx, `SELECT id::text,actor FROM noctis_v2.ai_jobs WHERE state='queued' AND function_id='evidence.translate'`).Scan(&id, &actor)
			c.Close(ctx)
			if e != nil || actor != "operator" || g.once(ctx, "evidence.translate") != nil {
				fail()
				return
			}
			job, e := g.store.Job(ctx, id, actor)
			if e != nil || g.record(ctx, job) != nil {
				fail()
				return
			}
		case "/suite":
			if len(g.consumers) != 1 || g.consumers[0].Function != "evidence.translate" || g.suite(ctx, ids) != nil {
				fail()
				return
			}
		case "/resume-suite":
			if !g.resume || g.suite(ctx, ids) != nil {
				fail()
				return
			}
		case "/zero-calls":
			c, e := pgx.Connect(ctx, g.store.DSN)
			if e != nil {
				fail()
				return
			}
			var count int
			e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_attempts`).Scan(&count)
			c.Close(ctx)
			if e != nil || count != 0 || len(g.attempts) != 0 {
				fail()
				return
			}
		default:
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(204)
	}))
	absConfig, e := filepath.Abs(configPath)
	if e != nil {
		control.Close()
		camp.close()
		return nil, nil, nil, e
	}
	env := []string{"NOCTIS_V2_REAL_AI_CONFIG=" + absConfig, "NOCTIS_V2_REAL_AI_CONTROL=" + control.URL, "NOCTIS_V2_REAL_AI_TOKEN=" + controlToken, "NOCTIS_V2_REAL_AI_CASE=" + ids["case_b"], fmt.Sprintf("NOCTIS_V2_REAL_AI_WIRE=%t", wire)}
	setupComplete = true
	return append(extra, "--ai-master-key-file", master), env, func() {
		control.Close()
		closeFake()
		g.mu.Lock()
		defer g.mu.Unlock()
		_ = g.receipt()
		camp.close()
	}, nil
}
func (g *realGuard) suite(ctx context.Context, ids map[string]string) error {
	c, e := pgx.Connect(ctx, g.store.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	if g.resume && g.expectedPromptVersion == "2" {
		if _, _, err := g.evaluateHistoricalSuccessV2(ctx, c, "evidence.translate"); err != nil {
			return err
		}
	}
	var obs, obsRev, caseID, caseRev, source, left, right string
	if e = c.QueryRow(ctx, `SELECT o.id::text,o.revision,m.case_id::text,ic.revision::text,o.source_id::text FROM noctis_v2.observations o JOIN noctis_v2.case_memberships m ON m.observation_id=o.id JOIN noctis_v2.intelligence_cases ic ON ic.id=m.case_id WHERE o.id=$1`, ids["observation_b"]).Scan(&obs, &obsRev, &caseID, &caseRev, &source); e != nil {
		return e
	}
	if e = c.QueryRow(ctx, `SELECT left_id::text,right_id::text FROM noctis_v2.entity_hypotheses WHERE id=$1`, ids["hypothesis_c"]).Scan(&left, &right); e != nil {
		return e
	}
	var period string
	if e = c.QueryRow(ctx, `SELECT period::text FROM noctis_v2.briefs ORDER BY period DESC LIMIT 1`).Scan(&period); e != nil {
		return e
	}
	inputs := map[string]inference.Input{"observation": {Kind: "observation", ID: obs, Revision: obsRev}, "identity": {Kind: "identity", ID: left, RightID: right}, "vulnerability": {Kind: "vulnerability", ID: "CVE-2026-12345"}, "case": {Kind: "case", ID: caseID, Revision: caseRev}, "brief": {Kind: "brief", Period: period}, "query": {Kind: "query", Text: "Find synthetic ACME observations"}, "source": {Kind: "source", ID: source}}
	// Submit all five compatible semantic jobs before one Once: five outputs,
	// one physical attempt and one reservation. No per-consumer fabricated calls.
	semantic := []inference.JobView{}
	if !g.resume {
		for _, f := range inference.Functions[:5] {
			j, e := g.store.Submit(ctx, inference.Submit{Function: f.ID, Input: inputs["observation"], RequestID: "real-e2e-v1-" + string(f.ID)}, "operator")
			if e != nil || j.State != "queued" {
				return errors.New("semantic submission blocked")
			}
			semantic = append(semantic, j)
		}
		if e = g.once(ctx, "semantic.classify", "semantic.relevance", "semantic.claims", "semantic.entities_relations", "semantic.observable_roles"); e != nil {
			return e
		}
		for _, j := range semantic {
			got, e := g.store.Job(ctx, j.ID, "operator")
			if e != nil {
				return e
			}
			if e = g.record(ctx, got); e != nil {
				return e
			}
		}
	}
	for _, id := range []inference.Function{"identity.disambiguate", "vulnerability.context", "case.analyze", "case.summarize", "brief.compose", "query.plan", "query.explain", "source.triage"} {
		f, ok := inference.Spec(id)
		if !ok {
			return errors.New("authorized independent consumer missing")
		}
		in, ok := inputs[f.InputKind]
		if !ok {
			return errors.New("missing dependency for consumer")
		}
		j, e := g.independent(ctx, f.ID, in)
		if e != nil {
			return e
		}
		if f.ID == "query.plan" {
			if j.Result.Plan == nil {
				return errors.New("typed query plan missing")
			}
			in, e := g.explanationInput(ctx, c, *j.Result.Plan)
			if e != nil {
				return e
			}
			inputs["query_result"] = in
		}
	}
	if g.resume {
		if e = g.newSemanticEvaluation(ctx, c, ids); e != nil {
			return e
		}
	}
	if !g.completeV2Coverage() {
		return errors.New("expected fourteen consumers")
	}
	return g.receipt()
}
