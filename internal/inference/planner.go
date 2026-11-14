package inference

import (
	"context"
	"github.com/jackc/pgx/v5"
)

// AutomaticActor is reserved for server-owned automatic planning. It must never
// be configured as an administrator identity or accepted from an API request.
const AutomaticActor = "system:semantic-planner"

// PlanEligible schedules only mechanically parsed, currently authorized revisions.
// Stable server-owned request IDs make polling/restarts idempotent. Compatible
// functions still coalesce in Once and share one physical reservation.
func (s Store) PlanEligible(ctx context.Context) error {
	view, e := s.Read(ctx)
	if e != nil {
		return e
	}
	if view.Revision == 0 {
		return nil
	}
	enabled := []string{}
	for _, b := range view.Bindings {
		if b.Enabled && semantic(b.Function) {
			enabled = append(enabled, string(b.Function))
		}
	}
	if len(enabled) == 0 {
		return nil
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	rows, e := c.Query(ctx, `SELECT o.id::text,o.revision,f.id FROM noctis_v2.observations o JOIN noctis_v2.sources s ON s.id=o.source_id CROSS JOIN unnest($1::text[]) f(id) WHERE s.enabled AND NOT o.source_deleted AND o.superseded_by IS NULL AND EXISTS(SELECT FROM noctis_v2.analyses a WHERE a.observation_id=o.id AND a.stage='parse' AND a.policy_version=s.policy_version AND a.gate IN ('relevant','unknown')) AND NOT EXISTS(SELECT FROM noctis_v2.ai_jobs j WHERE j.actor=$3 AND j.function_id=f.id AND j.input->>'id'=o.id::text AND j.input->>'revision'=o.revision AND j.config_revision=$2) ORDER BY o.collected_at,o.id,f.id LIMIT 20`, enabled, view.Revision, AutomaticActor)
	if e != nil {
		return e
	}
	inputs := []Submit{}
	for rows.Next() {
		var id, revision string
		var fn Function
		if e = rows.Scan(&id, &revision, &fn); e != nil {
			rows.Close()
			return e
		}
		inputs = append(inputs, Submit{Function: fn, Input: Input{Kind: "observation", ID: id, Revision: revision}, RequestID: "semantic-plan:" + digest([]any{id, revision, fn, view.Revision})})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, in := range inputs {
		if _, e = s.Submit(ctx, in, AutomaticActor); e != nil {
			return e
		}
	}
	return nil
}
