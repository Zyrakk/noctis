package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (g *realGuard) quarantineIDs() []string {
	ids := []string{}
	for _, q := range g.campaign.state.Quarantines {
		ids = append(ids, q.Attempt)
	}
	return ids
}
func (g *realGuard) unsafeJobs(ctx context.Context, c *pgx.Conn, n *int) error {
	rows, err := c.Query(ctx, `SELECT j.id::text,j.function_id,j.state,COALESCE(j.error_code,''),ARRAY(SELECT aj.attempt_id::text FROM noctis_v2.ai_attempt_jobs aj JOIN noctis_v2.ai_attempts a ON a.id=aj.attempt_id WHERE aj.job_id=j.id AND a.state='settled') FROM noctis_v2.ai_jobs j WHERE j.state NOT IN ('queued','succeeded') AND NOT (j.state='dependency_blocked' AND EXISTS(SELECT FROM noctis_v2.ai_attempt_jobs aj JOIN noctis_v2.ai_attempts a ON a.id=aj.attempt_id WHERE aj.job_id=j.id AND a.id::text=ANY($1::text[]) AND a.state='uncertain'))`, g.quarantineIDs())
	if err != nil {
		return err
	}
	defer rows.Close()
	expected := map[string]campaignPublicationJob{}
	attemptForJob := map[string]string{}
	for _, p := range g.campaign.state.Publications {
		for _, j := range p.Jobs {
			expected[j.ID] = j
			attemptForJob[j.ID] = p.Attempt
		}
	}
	*n = 0
	for rows.Next() {
		var j campaignPublicationJob
		var linked []string
		if err = rows.Scan(&j.ID, &j.Function, &j.State, &j.Error, &linked); err != nil {
			return err
		}
		matchesAttempt := false
		for _, attempt := range linked {
			if attempt != "" && attempt == attemptForJob[j.ID] {
				matchesAttempt = true
			}
		}
		if expected[j.ID] != j || !matchesAttempt {
			*n++
		}
	}
	return rows.Err()
}
func assertQueuedFunctions(ctx context.Context, c *pgx.Conn, expected []inference.Function) error {
	if len(expected) == 0 {
		return errors.New("explicit expected functions required")
	}
	rows, e := c.Query(ctx, `SELECT function_id FROM noctis_v2.ai_jobs WHERE state='queued' ORDER BY created_at,id`)
	if e != nil {
		return e
	}
	defer rows.Close()
	counts := map[inference.Function]int{}
	for _, f := range expected {
		counts[f]++
	}
	n := 0
	for rows.Next() {
		var f inference.Function
		if e = rows.Scan(&f); e != nil {
			return e
		}
		if counts[f] != 1 {
			return errors.New("unexpected next Once function")
		}
		counts[f]--
		n++
	}
	if e = rows.Err(); e != nil {
		return e
	}
	if n != len(expected) {
		return errors.New("queued functions differ from authorized selection")
	}
	return nil
}

// A stable explain request must reuse its original query-result UUID. Validate
// the stored actor and typed plan before trusting that retained input.
func (g *realGuard) explanationInput(ctx context.Context, c *pgx.Conn, plan inference.QueryPlan) (inference.Input, error) {
	var raw []byte
	var function inference.Function
	err := c.QueryRow(ctx, `SELECT function_id,input FROM noctis_v2.ai_jobs WHERE actor='operator' AND request_id='real-e2e-v1-query.explain'`).Scan(&function, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		result, err := g.store.Query(ctx, plan, "operator")
		return inference.Input{Kind: "query_result", ID: result.ID}, err
	}
	if err != nil {
		return inference.Input{}, err
	}
	var input inference.Input
	if function != "query.explain" || json.Unmarshal(raw, &input) != nil || input.Kind != "query_result" || input.ID == "" {
		return inference.Input{}, errors.New("existing explanation input invalid")
	}
	if err = c.QueryRow(ctx, `SELECT plan FROM noctis_v2.ai_query_results WHERE id=$1 AND actor='operator'`, input.ID).Scan(&raw); err != nil {
		return inference.Input{}, errors.New("existing explanation query result unavailable")
	}
	var stored inference.QueryPlan
	if json.Unmarshal(raw, &stored) != nil || stored != plan {
		return inference.Input{}, errors.New("existing explanation plan differs from validated query.plan")
	}
	return input, nil
}

func (g *realGuard) independent(ctx context.Context, id inference.Function, input inference.Input) (inference.JobView, error) {
	request := "real-e2e-v1-" + string(id)
	if g.resume && g.expectedPromptVersion == "2" && id == "identity.disambiguate" {
		c, err := pgx.Connect(ctx, g.store.DSN)
		if err != nil {
			return inference.JobView{}, err
		}
		defer c.Close(context.Background())
		if job, found, err := g.evaluateHistoricalSuccessV2(ctx, c, id); found || err != nil {
			return job, err
		}
	}
	if g.resume && id == "vulnerability.context" {
		old, err := g.publicationEvaluation(id)
		if err != nil {
			return inference.JobView{}, err
		}
		if old != "" {
			c, err := pgx.Connect(ctx, g.store.DSN)
			if err != nil {
				return inference.JobView{}, err
			}
			defer c.Close(context.Background())
			input, err = g.newVulnerabilityInput(ctx, c, old)
			if err != nil {
				return inference.JobView{}, err
			}
			request = "new-vulnerability-evaluation-after-" + old
		}
	}
	if g.resume && id == "identity.disambiguate" {
		c, err := pgx.Connect(ctx, g.store.DSN)
		if err != nil {
			return inference.JobView{}, err
		}
		defer c.Close(context.Background())
		old, err := g.quarantinedEvaluation(ctx, c, []inference.Function{id})
		if err != nil {
			return inference.JobView{}, err
		}
		if old != "" {
			input, err = g.newIdentityInput(ctx, c, old)
			if err != nil {
				return inference.JobView{}, err
			}
			request = "new-identity-evaluation-after-" + old
		}
	}
	j, err := g.store.Submit(ctx, inference.Submit{Function: id, Input: input, RequestID: request}, "operator")
	if err != nil || (j.State != "queued" && !(g.resume && j.State == "succeeded")) {
		return j, fmt.Errorf("consumer %s submission blocked (state %s)", id, j.State)
	}
	if j.State == "queued" {
		if err = g.once(ctx, id); err != nil {
			return j, err
		}
	}
	j, err = g.store.Job(ctx, j.ID, "operator")
	if err != nil {
		return j, err
	}
	return j, g.record(ctx, j)
}

// This is a separate synthetic observation/evaluation linked to the quarantined
// attempt. It never resets or retries the blocked jobs or reuses their input.
func (g *realGuard) newSemanticEvaluation(ctx context.Context, c *pgx.Conn, ids map[string]string) error {
	old, err := g.quarantinedEvaluation(ctx, c, []inference.Function{"semantic.classify", "semantic.relevance", "semantic.claims", "semantic.entities_relations", "semantic.observable_roles"})
	if err != nil {
		return err
	}
	if old == "" {
		return errors.New("explicit quarantined semantic evaluation required")
	}
	policy := "ai-new-evaluation-" + old
	var source, epoch, obs, revision string
	native := "synthetic-new-evaluation-after-" + old
	e := c.QueryRow(ctx, `SELECT id::text,epoch::text FROM noctis_v2.sources WHERE native_id=$1`, native).Scan(&source, &epoch)
	if errors.Is(e, pgx.ErrNoRows) {
		if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES($1,'[{"type":"keyword","value":"NOVA"}]') ON CONFLICT DO NOTHING`, policy); e != nil {
			return e
		}
		source, epoch = uuid.NewString(), uuid.NewString()
		_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,name,enabled,policy_version,epoch,activated_at) VALUES($1,'rss',$2,'SYNTHETIC independent semantic evaluation',true,$4,$3,clock_timestamp()-interval '1 hour')`, source, native, epoch, policy)
		if e != nil {
			return e
		}
		payload := "SYNTHETIC new evaluation: NOVA reports planned maintenance for a laboratory service. This is a scheduled availability notice, with no evidence of intrusion or data exposure. Prior uncertain evaluation reference: " + old
		now := time.Now().UTC()
		hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(payload)))
		_, e = (capture.Store{DSN: g.store.DSN}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: source, Epoch: epoch, Mode: capture.Live, Items: []capture.Item{{NativeID: "independent-maintenance-notice", Revision: "1", Hash: hash, Payload: []byte(payload), Representation: "text/plain;utf8;v1", CollectedAt: now, PublishedAt: &now}}, Expected: capture.Checkpoint{Value: json.RawMessage(`null`)}, Next: capture.Checkpoint{Version: 1, Value: json.RawMessage(`1`)}})
		if e != nil {
			return e
		}
		if e = (intelligence.Worker{DSN: g.store.DSN, Owner: "new-semantic-evaluation"}).Once(ctx); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if e = c.QueryRow(ctx, `SELECT id::text,revision FROM noctis_v2.observations WHERE source_id=$1`, source).Scan(&obs, &revision); e != nil {
		return e
	}
	if obs == ids["observation_b"] {
		return errors.New("semantic evaluation must use distinct observation")
	}
	var caseID string
	if e = c.QueryRow(ctx, `SELECT case_id::text FROM noctis_v2.case_memberships WHERE observation_id=$1`, obs).Scan(&caseID); e != nil {
		return e
	}
	if caseID == ids["case_b"] {
		return errors.New("new semantic evaluation must use separate case")
	}
	g.evaluation = map[string]any{"prior_uncertain_attempt": old, "new_observation_id": obs, "new_source_id": source, "new_case_id": caseID, "new_policy_version": policy, "request_id_prefix": "new-evaluation-after-" + old, "old_jobs_unchanged": true}
	if e = g.receipt(); e != nil {
		return e
	}
	jobs := []inference.JobView{}
	expected := []inference.Function{}
	for _, f := range inference.Functions[:5] {
		j, e := g.store.Submit(ctx, inference.Submit{Function: f.ID, Input: inference.Input{Kind: "observation", ID: obs, Revision: revision}, RequestID: "new-evaluation-after-" + old + "-" + string(f.ID)}, "operator")
		if e != nil || (j.State != "queued" && j.State != "succeeded") {
			return errors.New("new semantic evaluation blocked; no retry")
		}
		jobs = append(jobs, j)
		if j.State == "queued" {
			expected = append(expected, f.ID)
		}
	}
	if len(expected) > 0 {
		if e = g.once(ctx, expected...); e != nil {
			return e
		}
	}
	for _, j := range jobs {
		got, e := g.store.Job(ctx, j.ID, "operator")
		if e != nil {
			return e
		}
		if e = g.record(ctx, got); e != nil {
			return e
		}
	}
	return nil
}

func resumeRealAI(binary, dir, campaignPath, auditPath string, inputs realAIInputs, wire bool, publicationAudit string, upgradePromptV2 bool) error {
	if !filepath.IsAbs(dir) {
		return errors.New("absolute original artifact directory required")
	}
	info, e := os.Stat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private original artifacts required")
	}
	// No provider key is read here. The existing encrypted credential and master
	// remain in the same isolated database/artifact directory.
	if publicationAudit != "" {
		if auditPath != "" {
			return errors.New("one explicit audit disposition at a time required")
		}
		if err := applyPublicationAudit(binary, campaignPath, publicationAudit, inputs); err != nil {
			return err
		}
	}
	if auditPath != "" {
		info, err := os.Lstat(auditPath)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("audit must be regular private0600 file")
		}
		raw, e := os.ReadFile(auditPath)
		if e != nil {
			return errors.New("audit unavailable")
		}
		var q campaignQuarantine
		if strictRealJSON(raw, &q) != nil {
			return errors.New("audit invalid")
		}
		image, e := os.ReadFile(binary)
		if e != nil || q.BinarySHA != fmt.Sprintf("%x", sha256.Sum256(image)) {
			return errors.New("audit binary digest mismatch")
		}
		camp, e := openCampaignAudited(campaignPath, realFingerprint(inputs), false, &q)
		if e != nil {
			return e
		}
		camp.close()
	}
	camp, e := openCampaign(campaignPath, realFingerprint(inputs), false)
	if e != nil {
		return e
	}
	if len(camp.state.Entries) == 0 {
		camp.close()
		return errors.New("resume requires retained entries")
	}
	image, err := os.ReadFile(binary)
	if err != nil {
		camp.close()
		return errors.New("resume binary unavailable")
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(image))
	if err = validateLatestAuditBinary(camp.state, digest); err != nil {
		camp.close()
		return err
	}
	database := camp.state.Entries[0].Database
	camp.close()
	adminURL, e := url.Parse(os.Getenv("NOCTIS_V2_TEST_DATABASE_URL"))
	if e != nil || adminURL.Hostname() != "127.0.0.1" || !strings.Contains(adminURL.Path, "v2_test") || !strings.HasPrefix(database, "noctis_v2_e2e_") {
		return errors.New("explicit local synthetic admin database required")
	}
	adminURL.Path = "/" + database
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	c, e := pgx.Connect(ctx, adminURL.String())
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	role := "e2e_" + uuid.NewString()[:8]
	roleSQL := pgx.Identifier{role}.Sanitize()
	_, e = c.Exec(ctx, "CREATE ROLE "+roleSQL+" LOGIN;GRANT USAGE ON SCHEMA noctis_v2 TO "+roleSQL+";GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA noctis_v2 TO "+roleSQL+";GRANT DELETE ON noctis_v2.question_sources TO "+roleSQL+";GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA noctis_v2 TO "+roleSQL+";GRANT SELECT ON public.noctis_v2_migrations TO "+roleSQL)
	if e != nil {
		return e
	}
	defer func() {
		c.Exec(context.Background(), "DROP OWNED BY "+roleSQL)
		c.Exec(context.Background(), "DROP ROLE "+roleSQL)
	}()
	runtimeURL := *adminURL
	runtimeURL.User = url.User(role)
	secret := filepath.Join(dir, "resume-database.secret")
	if e = os.WriteFile(secret, []byte(runtimeURL.String()), 0600); e != nil {
		return e
	}
	ids := map[string]string{}
	// Reconstruct only stable IDs from retained SQL evidence, never reseed fixture.
	var obs, caseID, hyp string
	selector := &realGuard{}
	translation, e := selector.succeededEvaluation(ctx, c, "evidence.translate", "1")
	if e != nil {
		return e
	}
	if translation == nil {
		translation, e = selector.succeededEvaluation(ctx, c, "evidence.translate", "2")
		if e != nil {
			return e
		}
	}
	if translation == nil {
		return errors.New("exact succeeded translation input unavailable")
	}
	obs = translation.Input.ID
	ids["observation_b"] = obs
	if e = c.QueryRow(ctx, `SELECT case_id::text FROM noctis_v2.case_memberships WHERE observation_id=$1 ORDER BY case_id LIMIT 1`, obs).Scan(&caseID); e != nil {
		return e
	}
	ids["case_b"] = caseID
	if e = c.QueryRow(ctx, `SELECT id::text FROM noctis_v2.entity_hypotheses ORDER BY id LIMIT 1`).Scan(&hyp); e != nil {
		return e
	}
	ids["hypothesis_c"] = hyp
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	addr := listener.Addr().String()
	listener.Close()
	origin := "https://" + addr
	cert, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	extra, env, cleanup, e := setupRealAIFixture(ctx, dir, secret, origin, ids, "", campaignPath, false, wire, inputs, cert, key, false, realFixtureOptions{Resume: true, UpgradePromptV2: upgradePromptV2})
	if e != nil {
		return e
	}
	defer cleanup()
	args := []string{"v2", "--database-secret-file", secret, "serve", "--mode", "api", "--listen", addr, "--admin-secret-file", filepath.Join(dir, "admin.secret"), "--origin", origin, "--tls-cert-file", cert, "--tls-key-file", key}
	args = append(args, extra...)
	log, e := os.OpenFile(filepath.Join(dir, "resume-api.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	defer log.Close()
	server := exec.CommandContext(ctx, binary, args...)
	server.Stdout = log
	server.Stderr = log
	if e = server.Start(); e != nil {
		return e
	}
	defer func() {
		server.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- server.Wait() }()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			server.Process.Kill()
			<-done
		}
	}()
	cmd := exec.CommandContext(ctx, "npx", "playwright", "test", "--config=../ops/rebuild/e2e/real_ai.playwright.cjs")
	cmd.Dir = "web"
	cmd.Env = append(os.Environ(), env...)
	cmd.Env = append(cmd.Env, "NOCTIS_V2_REAL_AI_RESUME=true", "NOCTIS_V2_E2E_URL="+origin, "NOCTIS_V2_E2E_USERNAME=operator", "NOCTIS_V2_E2E_PASSWORD=synthetic-e2e-password-only")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
