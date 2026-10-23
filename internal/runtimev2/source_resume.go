package runtimev2

import (
	"context"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/jackc/pgx/v5"
)

// Park waiting work at pause time as well as in-flight work at Finish, so a
// long operator pause cannot age queued work into the processing retry horizon.
// In-flight rows are skipped and observe the pause at their publication fence.
func pauseSourceParseTx(ctx context.Context, tx pgx.Tx, source string) error {
	_, e := tx.Exec(ctx, `WITH park AS(SELECT j.id FROM noctis_v2.jobs j JOIN noctis_v2.observations o ON o.id=j.input_id JOIN noctis_v2.sources s ON s.id=o.source_id WHERE s.id::text=$1 AND j.stage='parse' AND j.policy_version=s.policy_version AND j.input_revision=o.revision AND j.state='queued' AND (j.last_error_code IS NULL OR j.last_error_code='source_resumed') AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL AND (o.mode<>'live' OR o.epoch=s.epoch) FOR UPDATE OF j SKIP LOCKED) UPDATE noctis_v2.jobs j SET state='dependency_blocked',last_error_code='source_paused',retry_at=NULL FROM park WHERE j.id=park.id`, source)
	return e
}

// Called under the projection guard. Never wait on an in-flight job row: its
// Finish callback may be waiting on this guard. A resume that wins that race is
// observed by Finish itself, so it publishes instead of parking (no lost wakeup).
func resumeSourceParseTx(ctx context.Context, tx pgx.Tx, source string) error {
	_, e := tx.Exec(ctx, `WITH wake AS(SELECT j.id FROM noctis_v2.jobs j JOIN noctis_v2.observations o ON o.id=j.input_id JOIN noctis_v2.sources s ON s.id=o.source_id WHERE s.id::text=$1 AND `+intelligence.SourceAuthorizedSQL+` AND j.stage='parse' AND j.state='dependency_blocked' AND j.last_error_code='source_paused' AND j.policy_version=s.policy_version AND j.input_revision=o.revision AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL AND (o.mode<>'live' OR o.epoch=s.epoch) AND NOT EXISTS(SELECT FROM noctis_v2.analyses a WHERE a.stage=j.stage AND a.observation_id=j.input_id AND a.input_revision=j.input_revision AND a.policy_version=j.policy_version AND a.schema_version=j.schema_version) FOR UPDATE OF j SKIP LOCKED) UPDATE noctis_v2.jobs j SET state='queued',last_error_code='source_resumed',retry_at=NULL FROM wake WHERE j.id=wake.id`, source)
	if e != nil {
		return e
	}
	// A PIR may have advanced while the source was independently paused. Create
	// only its missing current key; never reset a cancelled/quarantined/leased key.
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) SELECT gen_random_uuid(),'parse',o.id,o.revision,s.policy_version,'1' FROM noctis_v2.observations o JOIN noctis_v2.sources s ON s.id=o.source_id WHERE s.id::text=$1 AND `+intelligence.SourceAuthorizedSQL+` AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL AND (o.mode<>'live' OR o.epoch=s.epoch) AND NOT EXISTS(SELECT FROM noctis_v2.jobs j WHERE j.stage='parse' AND j.input_id=o.id AND j.input_revision=o.revision AND j.policy_version=s.policy_version AND j.schema_version='1') AND NOT EXISTS(SELECT FROM noctis_v2.analyses a WHERE a.stage='parse' AND a.observation_id=o.id AND a.input_revision=o.revision AND a.policy_version=s.policy_version AND a.schema_version='1') ON CONFLICT DO NOTHING`, source)
	return e
}
