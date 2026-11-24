package jobs

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// ParsePauseEligibleSQL expects aliases j,o,s. Revoked or obsolete input is
// never made resumable by a pause. Finish still fences every derived write.
const ParsePauseEligibleSQL = `j.stage='parse' AND j.input_revision=o.revision AND j.policy_version=s.policy_version AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL AND (o.mode<>'live' OR o.epoch=s.epoch) AND NOT EXISTS(SELECT FROM noctis_v2.discovery_proposals dp WHERE dp.source_id=s.id AND dp.permission_status<>'authorized')`

const sourcePausedSQL = `(NOT s.enabled OR EXISTS(SELECT FROM noctis_v2.question_sources qs JOIN noctis_v2.questions q ON q.id=qs.question_id WHERE qs.source_id=s.id AND NOT q.enabled))`

// Same guard as intelligence.LockProjectionTx. Claim takes it before selecting
// SKIP LOCKED rows; Fail holds its fenced job first, like Finish. Pause/resume
// must never wait for a job row while holding this guard.
func lockSourcePauseTx(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(76238451003)`)
	return err
}

func parkPausedParseTx(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `WITH park AS (
 SELECT j.id FROM noctis_v2.jobs j JOIN noctis_v2.observations o ON o.id=j.input_id JOIN noctis_v2.sources s ON s.id=o.source_id
 WHERE `+ParsePauseEligibleSQL+` AND `+sourcePausedSQL+`
 AND j.attempts<5 AND j.retry_deadline_at>statement_timestamp()
 AND (j.state IN ('queued','retry_wait') OR (j.state='leased' AND j.lease_expires_at<=clock_timestamp()))
 FOR UPDATE OF j SKIP LOCKED
) UPDATE noctis_v2.jobs j SET state='dependency_blocked',last_error_code='source_paused',source_paused_at=statement_timestamp(),lease_owner=NULL,lease_expires_at=NULL FROM park WHERE j.id=park.id`)
	return err
}
