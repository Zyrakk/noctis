package intelligence

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Indicator struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Value         string         `json:"value"`
	Scope         string         `json:"scope"`
	ValidFrom     time.Time      `json:"valid_from"`
	ValidUntil    time.Time      `json:"valid_until"`
	PolicyVersion string         `json:"policy_version"`
	Producer      string         `json:"producer"`
	Reason        string         `json:"reason"`
	Refs          []evidence.Ref `json:"refs"`
}

func CreateIndicatorTx(ctx context.Context, tx pgx.Tx, i Indicator) error {
	if _, e := uuid.Parse(i.ID); e != nil {
		return e
	}
	if !strings.HasPrefix(i.Producer, "operator:") || !bounded(i.Reason, 4096) || !bounded(i.Scope, 256) || !bounded(i.PolicyVersion, 128) || !bounded(i.Value, 2048) || !i.ValidUntil.After(i.ValidFrom) || i.ValidFrom.IsZero() || i.ValidUntil.Sub(i.ValidFrom) > 366*24*time.Hour {
		return errors.New("invalid explicit indicator judgment")
	}
	if e := validateRefsTx(ctx, tx, i.Refs); e != nil {
		return e
	}
	for _, ref := range i.Refs {
		var present bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.observable_sightings WHERE observable_type=$1 AND value=$2 AND observation_id=$3 AND revision=$4 AND start_byte>=$5 AND end_byte<=$6)`, i.Type, i.Value, ref.ObservationID, ref.Revision, ref.Start, ref.End).Scan(&present); e != nil {
			return e
		}
		if !present {
			return errors.New("indicator observable absent from evidence")
		}
	}
	refs, _ := json.Marshal(i.Refs)
	_, e := tx.Exec(ctx, `INSERT INTO noctis_v2.indicator_versions(id,revision,observable_type,value,scope,status,valid_from,valid_until,policy_version,producer,reason,evidence) VALUES($1,1,$2,$3,$4,'active',$5,$6,$7,$8,$9,$10)`, i.ID, i.Type, i.Value, i.Scope, i.ValidFrom, i.ValidUntil, i.PolicyVersion, i.Producer, i.Reason, string(refs))
	return e
}
func RevokeIndicatorTx(ctx context.Context, tx pgx.Tx, id string, revision int, producer, reason string) error {
	if !strings.HasPrefix(producer, "operator:") || !bounded(reason, 4096) {
		return errors.New("operator revocation required")
	}
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,12))`, id); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `INSERT INTO noctis_v2.indicator_versions(id,revision,observable_type,value,scope,status,valid_from,valid_until,policy_version,producer,reason,evidence) SELECT id,revision+1,observable_type,value,scope,'revoked',valid_from,valid_until,policy_version,$3,$4,evidence FROM noctis_v2.indicator_versions WHERE id=$1 AND revision=$2 AND status='active' AND revision=(SELECT max(revision) FROM noctis_v2.indicator_versions WHERE id=$1)`, id, revision, producer, reason)
	if e == nil && tag.RowsAffected() != 1 {
		return errors.New("stale indicator revision")
	}
	return e
}
func recordSightingsTx(ctx context.Context, tx pgx.Tx, observables []Observable) error {
	for _, o := range observables {
		raw, _ := json.Marshal(o.Evidence)
		if _, e := tx.Exec(ctx, `INSERT INTO noctis_v2.observable_sightings VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, o.Type, o.Value, o.Evidence.ObservationID, o.Evidence.Revision, o.Evidence.Start, o.Evidence.End, string(raw)); e != nil {
			return e
		}
	}
	return nil
}
