package telegramv2

import (
	"context"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/jackc/pgx/v5"
)

func invalidateMessageTx(ctx context.Context, tx pgx.Tx, source, native, revision string, deleted bool) error {
	if e := intelligence.LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	if deleted {
		if _, e := tx.Exec(ctx, `UPDATE noctis_v2.observations SET source_deleted=true WHERE source_id=$1 AND native_id=$2`, source, native); e != nil {
			return e
		}
	} else {
		if _, e := tx.Exec(ctx, `UPDATE noctis_v2.observations old SET superseded_by=current.id FROM noctis_v2.observations current WHERE current.source_id=$1 AND current.native_id=$2 AND current.revision=$3 AND old.source_id=current.source_id AND old.native_id=current.native_id AND old.id<>current.id AND old.superseded_by IS NULL`, source, native, revision); e != nil {
			return e
		}
	}
	rows, e := tx.Query(ctx, `SELECT id::text FROM noctis_v2.observations WHERE source_id=$1 AND native_id=$2 AND (source_deleted OR superseded_by IS NOT NULL)`, source, native)
	if e != nil {
		return e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	e = intelligence.InvalidateProjectionTx(ctx, tx, nil, ids, "native_evidence_changed")
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.briefs b SET invalidated=true WHERE EXISTS(SELECT FROM noctis_v2.observations o WHERE o.source_id=$1 AND o.native_id=$2 AND (o.source_deleted OR o.superseded_by IS NOT NULL) AND b.body::text LIKE '%'||o.id::text||'%')`, source, native)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `WITH updated AS(UPDATE noctis_v2.intelligence_cases ic SET revision=revision+1,updated_at=clock_timestamp() WHERE EXISTS(SELECT FROM noctis_v2.case_memberships m JOIN noctis_v2.observations o ON o.id=m.observation_id WHERE m.case_id=ic.id AND o.source_id=$1 AND o.native_id=$2) RETURNING id,revision) INSERT INTO noctis_v2.case_revisions(case_id,revision,body) SELECT u.id,u.revision,old.body||jsonb_build_object('revision',u.revision::text,'supersedes',(u.revision-1)::text,'claims_status','needs_revalidation','source_evidence_changed',true) FROM updated u JOIN noctis_v2.case_revisions old ON old.case_id=u.id AND old.revision=u.revision-1`, source, native)
	return e
}
