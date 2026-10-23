package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func applyPublicationAudit(binaryPath, campaignPath, auditPath string, inputs realAIInputs) error {
	info, err := os.Lstat(auditPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("publication audit must be regular private0600 file")
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		return errors.New("publication audit unavailable")
	}
	var p campaignPublicationDisposition
	if strictRealJSON(raw, &p) != nil {
		return errors.New("publication audit invalid")
	}
	image, err := os.ReadFile(binaryPath)
	if err != nil || p.BinarySHA != fmt.Sprintf("%x", sha256.Sum256(image)) {
		return errors.New("publication audit binary mismatch")
	}
	u, err := url.Parse(os.Getenv("NOCTIS_V2_TEST_DATABASE_URL"))
	if err != nil || u.Hostname() != "127.0.0.1" || !strings.Contains(u.Path, "v2_test") {
		return errors.New("explicit local synthetic audit database required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	camp, err := openCampaignWithAudit(campaignPath, realFingerprint(inputs), false, nil, &p, func(c *campaign, p campaignPublicationDisposition) error {
		if len(c.state.Entries) == 0 {
			return errors.New("publication audit reservation missing")
		}
		database := c.state.Entries[0].Database
		if !strings.HasPrefix(database, "noctis_v2_e2e_") {
			return errors.New("publication audit database denied")
		}
		for _, entry := range c.state.Entries {
			if entry.Database != database {
				return errors.New("publication audit database mismatch")
			}
		}
		u.Path = "/" + database
		return validatePublicationSQL(ctx, u.String(), c, p)
	})
	if err != nil {
		return err
	}
	camp.close()
	return nil
}

type campaignPublicationJob struct {
	ID       string             `json:"job_id"`
	Function inference.Function `json:"function_id"`
	State    string             `json:"state"`
	Error    string             `json:"error_code"`
}
type campaignPublicationDisposition struct {
	campaignQuarantine
	State     string                   `json:"attempt_state"`
	Functions []inference.Function     `json:"functions"`
	Jobs      []campaignPublicationJob `json:"jobs"`
	Maximum   int64                    `json:"maximum_units"`
	Actual    int64                    `json:"actual_units"`
}

func (c *campaign) publicationAcknowledged(id string) bool {
	for _, p := range c.state.Publications {
		if id != "" && p.Attempt == id {
			return true
		}
	}
	return false
}
func validPublicationDisposition(p campaignPublicationDisposition, fingerprint string) bool {
	if uuid.Validate(p.Attempt) != nil || p.Fingerprint != fingerprint || !validSHA(p.PriorSHA) || !validSHA(p.BinarySHA) || strings.TrimSpace(p.Reason) == "" || p.State != "settled" || p.Maximum <= 0 || p.Actual < 0 || p.Actual > p.Maximum || len(p.Functions) == 0 || len(p.Jobs) == 0 {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, p.Time); err != nil {
		return false
	}
	fs := map[inference.Function]bool{}
	for _, f := range p.Functions {
		if _, ok := inference.Spec(f); !ok || fs[f] {
			return false
		}
		fs[f] = true
	}
	jobs := map[string]bool{}
	for _, j := range p.Jobs {
		if uuid.Validate(j.ID) != nil || jobs[j.ID] || !fs[j.Function] || j.State != "failed" || !inference.IsResultValidationCode(j.Error) {
			return false
		}
		jobs[j.ID] = true
	}
	return true
}
func validatePublicationSQL(ctx context.Context, dsn string, campaign *campaign, p campaignPublicationDisposition) error {
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return errors.New("publication audit database unavailable")
	}
	defer c.Close(context.Background())
	var actual *int64
	var maximum int64
	var usage, functions []byte
	var state string
	var accounting *string
	var model, requested *string
	err = c.QueryRow(ctx, `SELECT state,maximum_units,actual_units,usage,functions,accounting_exception,declared_model,requested_model FROM noctis_v2.ai_attempts WHERE id=$1`, p.Attempt).Scan(&state, &maximum, &actual, &usage, &functions, &accounting, &model, &requested)
	if err != nil || state != "settled" || actual == nil || *actual != p.Actual || maximum != p.Maximum || accounting != nil || model == nil || requested == nil || *model != *requested || *model == "" || *model == "unknown" {
		return errors.New("publication audit accounting mismatch")
	}
	var u struct {
		Input  *int64 `json:"input_tokens"`
		Output *int64 `json:"output_tokens"`
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(usage, &u) != nil || u.Input == nil || u.Output == nil || *u.Input < 0 || *u.Output < 0 || *u.Input > 1<<30 || *u.Output > 1<<30 || json.Unmarshal(usage, &fields) != nil || fields["input_tokens"] == nil || fields["output_tokens"] == nil {
		return errors.New("publication audit usage unavailable")
	}
	var fs []inference.Function
	if json.Unmarshal(functions, &fs) != nil || !sameFunctions(fs, p.Functions) {
		return errors.New("publication audit functions mismatch")
	}
	expected := map[string]campaignPublicationJob{}
	for _, j := range p.Jobs {
		expected[j.ID] = j
	}
	rows, err := c.Query(ctx, `SELECT j.id::text,j.function_id,j.state,COALESCE(j.error_code,''),j.actor,j.result IS NULL FROM noctis_v2.ai_jobs j JOIN noctis_v2.ai_attempt_jobs aj ON aj.job_id=j.id WHERE aj.attempt_id=$1`, p.Attempt)
	if err != nil {
		return errors.New("publication audit jobs unavailable")
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var job campaignPublicationJob
		var actor string
		var resultNull bool
		if rows.Scan(&job.ID, &job.Function, &job.State, &job.Error, &actor, &resultNull) != nil || expected[job.ID] != job || actor != "operator" || !resultNull {
			return errors.New("publication audit exact jobs mismatch")
		}
		n++
	}
	if rows.Err() != nil || n != len(expected) {
		return errors.New("publication audit exact jobs mismatch")
	}
	for _, entry := range campaign.state.Entries {
		if entry.Database == "" {
			return errors.New("publication audit database mismatch")
		}
	}
	return nil
}
func sameFunctions(a, b []inference.Function) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[inference.Function]int{}
	for _, f := range a {
		seen[f]++
	}
	for _, f := range b {
		seen[f]--
		if seen[f] < 0 {
			return false
		}
	}
	return true
}

func (g *realGuard) publicationEvaluation(function inference.Function) (string, error) {
	found := ""
	for _, p := range g.campaign.state.Publications {
		relevant := false
		for _, f := range p.Functions {
			if f == function {
				relevant = true
			}
		}
		if !relevant {
			continue
		}
		if found != "" || len(p.Functions) != 1 || p.Functions[0] != function || len(p.Jobs) != 1 || p.Jobs[0].Function != function {
			return "", errors.New("publication evaluation target ambiguous")
		}
		found = p.Attempt
	}
	return found, nil
}

// Context-only synthetic feed: a new CVE and stable snapshot, never a fabricated
// observation. Reentry verifies the same frozen context and does not refresh it.
func (g *realGuard) newVulnerabilityInput(ctx context.Context, c *pgx.Conn, old string) (inference.Input, error) {
	var original []byte
	if err := c.QueryRow(ctx, `SELECT j.input FROM noctis_v2.ai_jobs j JOIN noctis_v2.ai_attempt_jobs aj ON aj.job_id=j.id WHERE aj.attempt_id=$1 AND j.function_id='vulnerability.context' AND j.actor='operator' AND j.state='failed'`, old).Scan(&original); err != nil {
		return inference.Input{}, errors.New("failed vulnerability input unavailable")
	}
	var prior inference.Input
	if json.Unmarshal(original, &prior) != nil || prior.Kind != "vulnerability" {
		return inference.Input{}, errors.New("failed vulnerability input incompatible")
	}
	hash := sha256.Sum256([]byte("new-vulnerability-after-" + old))
	cve := fmt.Sprintf("CVE-2099-%d", 100000+binary.BigEndian.Uint32(hash[:4])%9000000)
	if cve == prior.ID {
		return inference.Input{}, errors.New("new vulnerability must use distinct CVE")
	}
	snapshot := uuid.NewSHA1(uuid.NameSpaceOID, []byte("new-vulnerability-snapshot-after-"+old)).String()
	body, _ := json.Marshal(map[string]any{"cve": cve, "description": "SYNTHETIC context-only laboratory vulnerability notice; applicability and local exposure unknown", "prior_failed_attempt": old, "synthetic": true})
	bodyHash := fmt.Sprintf("sha256:%x", sha256.Sum256(body))
	endpoint := "https://example.invalid/synthetic-context-after-" + old
	tx, err := c.Begin(ctx)
	if err != nil {
		return inference.Input{}, err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `INSERT INTO noctis_v2.feed_snapshots(id,kind,url,hash,as_of,expires_at,payload) VALUES($1,'nvd',$2,$3,clock_timestamp(),clock_timestamp()+interval '24 hours',$4) ON CONFLICT DO NOTHING`, snapshot, endpoint, bodyHash, string(body)); err != nil {
		return inference.Input{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO noctis_v2.vulnerability_facts(snapshot_id,cve,body) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, snapshot, cve, string(body)); err != nil {
		return inference.Input{}, err
	}
	var valid bool
	if err = tx.QueryRow(ctx, `SELECT s.kind='nvd' AND s.url=$3 AND s.hash=$4 AND s.payload=$5::jsonb AND f.body=$5::jsonb AND f.applicability='unknown' AND s.expires_at>clock_timestamp() FROM noctis_v2.feed_snapshots s JOIN noctis_v2.vulnerability_facts f ON f.snapshot_id=s.id WHERE s.id=$1 AND f.cve=$2`, snapshot, cve, endpoint, bodyHash, string(body)).Scan(&valid); err != nil || !valid {
		return inference.Input{}, errors.New("retained synthetic vulnerability context differs or expired")
	}
	if err = tx.Commit(ctx); err != nil {
		return inference.Input{}, err
	}
	g.vulnerabilityEvaluation = map[string]any{"prior_failed_settled_attempt": old, "new_cve": cve, "new_snapshot_id": snapshot, "documents": 0, "request_id": "new-vulnerability-evaluation-after-" + old, "old_jobs_unchanged": true}
	if err = g.receipt(); err != nil {
		return inference.Input{}, err
	}
	return inference.Input{Kind: "vulnerability", ID: cve}, nil
}
