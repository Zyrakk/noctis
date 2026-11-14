package runtimev2

import (
	"context"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/jackc/pgx/v5"
)

// Park waiting work at pause time as well as in-flight work at Finish, so a
// long operator pause cannot age queued work into the processing retry horizon.
// In-flight rows are skipped and observe the pause at their publication fence.
func pauseSourceParseTx(ctx context.Context, tx pgx.Tx, source string) error {
	_, e := tx.Exec(ctx, `WITH park AS(SELECT j.id FROM noctis_v2.jobs j JOIN noctis_v2.observations o ON o.id=j.input_id JOIN noctis_v2.sources s ON s.id=o.source_id WHERE s.id::text=$1 AND `+jobs.ParsePauseEligibleSQL+` AND j.state IN ('queued','retry_wait') FOR UPDATE OF j SKIP LOCKED) UPDATE noctis_v2.jobs j SET state=CASE WHEN j.attempts<5 AND j.retry_deadline_at>statement_timestamp() THEN 'dependency_blocked' ELSE 'quarantined' END,last_error_code=CASE WHEN j.attempts<5 AND j.retry_deadline_at>statement_timestamp() THEN 'source_paused' ELSE 'retry_horizon_exceeded' END,source_paused_at=CASE WHEN j.attempts<5 AND j.retry_deadline_at>statement_timestamp() THEN statement_timestamp() END FROM park WHERE j.id=park.id`, source)
	return e
}

// Called under the projection guard. Never wait on an in-flight job row: its
// Finish callback may be waiting on this guard. A resume that wins that race is
// observed by Finish itself, so it publishes instead of parking (no lost wakeup).
func resumeSourceParseTx(ctx context.Context, tx pgx.Tx, source string) error {
	_, e := tx.Exec(ctx, `WITH wake AS(SELECT j.id FROM noctis_v2.jobs j JOIN noctis_v2.observations o ON o.id=j.input_id JOIN noctis_v2.sources s ON s.id=o.source_id WHERE s.id::text=$1 AND `+intelligence.SourceAuthorizedSQL+` AND `+jobs.ParsePauseEligibleSQL+` AND j.state='dependency_blocked' AND j.last_error_code='source_paused' AND j.source_paused_at IS NOT NULL AND j.retry_deadline_at>j.source_paused_at AND j.attempts<5 AND NOT EXISTS(SELECT FROM noctis_v2.analyses a WHERE a.stage=j.stage AND a.observation_id=j.input_id AND a.input_revision=j.input_revision AND a.policy_version=j.policy_version AND a.schema_version=j.schema_version) FOR UPDATE OF j SKIP LOCKED) UPDATE noctis_v2.jobs j SET state=CASE WHEN j.retry_at>statement_timestamp() THEN 'retry_wait' ELSE 'queued' END,last_error_code=NULL,retry_deadline_at=j.retry_deadline_at+GREATEST(statement_timestamp()-j.source_paused_at,interval '0'),source_paused_at=NULL FROM wake WHERE j.id=wake.id`, source)
	if e != nil {
		return e
	}
	// A PIR may have advanced while the source was independently paused. Create
	// only its missing current key; never reset a cancelled/quarantined/leased key.
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) SELECT gen_random_uuid(),'parse',o.id,o.revision,s.policy_version,'1' FROM noctis_v2.observations o JOIN noctis_v2.sources s ON s.id=o.source_id WHERE s.id::text=$1 AND `+intelligence.SourceAuthorizedSQL+` AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL AND (o.mode<>'live' OR o.epoch=s.epoch) AND NOT EXISTS(SELECT FROM noctis_v2.jobs j WHERE j.stage='parse' AND j.input_id=o.id AND j.input_revision=o.revision AND j.policy_version=s.policy_version AND j.schema_version='1') AND NOT EXISTS(SELECT FROM noctis_v2.analyses a WHERE a.stage='parse' AND a.observation_id=o.id AND a.input_revision=o.revision AND a.policy_version=s.policy_version AND a.schema_version='1') ON CONFLICT DO NOTHING`, source)
	return e
}
