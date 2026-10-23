package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Zyrakk/noctis/internal/inference"
	promptsv2 "github.com/Zyrakk/noctis/prompts/v2"
	"github.com/jackc/pgx/v5"
)

type succeededEvaluation struct {
	Job, Attempt string
	Input        inference.Input
}

func (g *realGuard) succeededEvaluation(ctx context.Context, c *pgx.Conn, function inference.Function, version string) (*succeededEvaluation, error) {
	rows, err := c.Query(ctx, `SELECT j.id::text,a.id::text,j.input FROM noctis_v2.ai_jobs j JOIN noctis_v2.ai_attempt_jobs aj ON aj.job_id=j.id JOIN noctis_v2.ai_attempts a ON a.id=aj.attempt_id JOIN noctis_v2.ai_configs cfg ON cfg.revision=j.config_revision WHERE j.function_id=$1 AND j.actor='operator' AND j.state='succeeded' AND j.result IS NOT NULL AND a.state='settled' AND EXISTS(SELECT FROM jsonb_array_elements(cfg.body->'bindings') b WHERE b->>'function_id'=j.function_id AND b->>'prompt_version'=$2)`, function, version)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var found *succeededEvaluation
	for rows.Next() {
		candidate := &succeededEvaluation{}
		var raw []byte
		if rows.Scan(&candidate.Job, &candidate.Attempt, &raw) != nil || json.Unmarshal(raw, &candidate.Input) != nil {
			return nil, errors.New("historical succeeded evaluation invalid")
		}
		if found != nil {
			return nil, errors.New("historical succeeded evaluation ambiguous")
		}
		found = candidate
	}
	return found, rows.Err()
}

// A new version needs a new request identity. Store.Save alone cannot reevaluate
// a previously succeeded actor/request_id, and never rewrites that old job.
func (g *realGuard) evaluateHistoricalSuccessV2(ctx context.Context, c *pgx.Conn, function inference.Function) (inference.JobView, bool, error) {
	if function != "evidence.translate" && function != "identity.disambiguate" {
		return inference.JobView{}, false, errors.New("historical v2 evaluation function unsupported")
	}
	old, err := g.succeededEvaluation(ctx, c, function, "1")
	if err != nil || old == nil {
		return inference.JobView{}, false, err
	}
	historical, err := g.store.Job(ctx, old.Job, "operator")
	if err != nil {
		return inference.JobView{}, true, err
	}
	if err = g.record(ctx, historical); err != nil {
		return inference.JobView{}, true, err
	}
	request := "v2-eval-success-" + old.Attempt + "-" + promptsv2.DigestV2
	job, err := g.store.Submit(ctx, inference.Submit{Function: function, Input: old.Input, RequestID: request}, "operator")
	if err != nil || (job.State != "queued" && job.State != "succeeded") {
		return job, true, errors.New("new v2 evaluation of historical success blocked")
	}
	if job.State == "queued" {
		if err = g.once(ctx, function); err != nil {
			return job, true, err
		}
	}
	job, err = g.store.Job(ctx, job.ID, "operator")
	if err != nil {
		return job, true, err
	}
	if err = g.record(ctx, job); err != nil {
		return job, true, err
	}
	if g.successV2Evaluations == nil {
		g.successV2Evaluations = map[inference.Function]any{}
	}
	g.successV2Evaluations[function] = map[string]any{"historical_succeeded_job_id": old.Job, "historical_succeeded_attempt_id": old.Attempt, "new_job_id": job.ID, "request_id": request, "prompt_version": "2", "prompt_sha256": promptsv2.DigestV2, "same_synthetic_input": true}
	return job, true, g.receipt()
}

func (g *realGuard) completeV2Coverage() bool {
	if len(g.consumers) != len(inference.Functions) {
		return false
	}
	seen := map[inference.Function]bool{}
	for _, consumer := range g.consumers {
		if consumer.State != "succeeded" || consumer.PromptVersion != "2" || consumer.PromptDigest != promptsv2.DigestV2 || consumer.Historical || !consumer.CitationsVerified || seen[consumer.Function] {
			return false
		}
		seen[consumer.Function] = true
	}
	for _, f := range inference.Functions {
		if !seen[f.ID] {
			return false
		}
	}
	return true
}
