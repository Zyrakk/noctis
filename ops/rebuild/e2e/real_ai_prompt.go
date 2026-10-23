package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Zyrakk/noctis/internal/inference"
	promptsv2 "github.com/Zyrakk/noctis/prompts/v2"
	"github.com/jackc/pgx/v5"
)

func (g *realGuard) validateBindings(view inference.ConfigView, version string) error {
	_, digest, err := promptsv2.Resolve(version)
	if err != nil || (version == "2" && digest != promptsv2.DigestV2) || (version == "1" && digest != promptsv2.DigestV1) {
		return errors.New("expected prompt digest unavailable")
	}
	if len(view.Bindings) != len(inference.Functions) || len(view.Connections) != 1 || view.Connections[0].URL != g.inputs.Endpoint || view.Connections[0].Provider != g.inputs.Provider || view.Connections[0].Adapter != g.inputs.Adapter {
		return errors.New("panel connection mismatch")
	}
	for _, b := range view.Bindings {
		if b.PromptVersion != version || b.SchemaVersion != "1" || !b.Enabled || b.Model != g.inputs.Model || b.Price != g.inputs.Price || b.Limits != g.inputs.Limits || b.ConnectionID != view.Connections[0].ID || !b.StructuredJSON || b.MaxConcurrent != 1 {
			return errors.New("panel binding or prompt version mismatch")
		}
	}
	return nil
}

// This is an explicit configuration CAS, not a campaign reset. It never edits
// prior config/secrets/jobs/results and never cancels incompatible pending work.
func (g *realGuard) preparePromptVersion(ctx context.Context, c *pgx.Conn, upgrade bool) error {
	view, err := g.store.Read(ctx)
	if err != nil {
		return err
	}
	if len(view.Bindings) == 0 {
		return errors.New("prompt transition bindings missing")
	}
	current := view.Bindings[0].PromptVersion
	if err = g.validateBindings(view, current); err != nil {
		return err
	}
	if g.expectedPromptVersion == "1" {
		return nil
	} // Offline historical fixture only.
	if g.expectedPromptVersion != "2" {
		return errors.New("expected prompt version unsupported")
	}
	var incompatible int
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_jobs WHERE state IN ('queued','retry_wait','running') AND (config_revision<>$1 OR $2<>'2')`, view.Revision, current).Scan(&incompatible); err != nil {
		return err
	}
	if incompatible != 0 {
		return errors.New("incompatible pending jobs; prompt transition rejected without rewriting work")
	}
	if current == "2" {
		return nil
	}
	if current != "1" || !upgrade {
		return errors.New("explicit --real-ai-upgrade-prompt-v2 required before new evaluations")
	}
	cfg := view.Config
	for i := range cfg.Bindings {
		cfg.Bindings[i].PromptVersion = "2"
	}
	for i := range cfg.Connections {
		cfg.Connections[i].SecretAction = "unchanged"
		cfg.Connections[i].APIKey = ""
	}
	next, err := g.store.Save(ctx, cfg, view.Revision, "operator:real-ai-prompt-v2-transition")
	if err != nil {
		return errors.New("prompt v2 configuration CAS failed")
	}
	if err = g.validateBindings(next, "2"); err != nil {
		return err
	}
	g.promptTransition = map[string]any{"from_config_revision": view.Revision, "to_config_revision": next.Revision, "prompt_version": "2", "prompt_sha256": promptsv2.DigestV2, "credential_action": "unchanged", "historical_rows_unchanged": true}
	return nil
}

func promptForJob(ctx context.Context, c *pgx.Conn, id string, function inference.Function) (string, string, error) {
	var raw []byte
	if err := c.QueryRow(ctx, `SELECT cfg.body FROM noctis_v2.ai_jobs j JOIN noctis_v2.ai_configs cfg ON cfg.revision=j.config_revision WHERE j.id=$1`, id).Scan(&raw); err != nil {
		return "", "", err
	}
	var cfg inference.Config
	if json.Unmarshal(raw, &cfg) != nil {
		return "", "", errors.New("job prompt configuration invalid")
	}
	for _, b := range cfg.Bindings {
		if b.Function == function {
			_, digest, err := promptsv2.Resolve(b.PromptVersion)
			return b.PromptVersion, digest, err
		}
	}
	return "", "", fmt.Errorf("job prompt binding unavailable")
}

func assertQueuedPrompt(ctx context.Context, c *pgx.Conn, version string, revision int64) error {
	_, expected, err := promptsv2.Resolve(version)
	if err != nil {
		return errors.New("expected prompt registry invalid")
	}
	rows, err := c.Query(ctx, `SELECT j.function_id,j.config_revision,cfg.body FROM noctis_v2.ai_jobs j JOIN noctis_v2.ai_configs cfg ON cfg.revision=j.config_revision WHERE j.state='queued'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var f inference.Function
		var jobRevision int64
		var raw []byte
		if rows.Scan(&f, &jobRevision, &raw) != nil {
			return errors.New("queued prompt configuration unavailable")
		}
		var cfg inference.Config
		if jobRevision != revision || json.Unmarshal(raw, &cfg) != nil {
			return errors.New("queued prompt revision incompatible before reservation")
		}
		matched := false
		for _, b := range cfg.Bindings {
			if b.Function == f {
				_, digest, err := promptsv2.Resolve(b.PromptVersion)
				if err != nil || b.PromptVersion != version || digest != expected || !b.Enabled {
					return errors.New("queued prompt version or digest incompatible before reservation")
				}
				matched = true
			}
		}
		if !matched {
			return errors.New("queued prompt binding unavailable before reservation")
		}
	}
	return rows.Err()
}
