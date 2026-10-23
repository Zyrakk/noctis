package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrConflict = errors.New("capture identity/checkpoint conflict")

type Store struct{ DSN string }

func (s Store) CommitBatch(ctx context.Context, b Batch) (Receipt, error) {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return Receipt{}, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return Receipt{}, e
	}
	defer tx.Rollback(context.Background())
	r, e := CommitBatchTx(ctx, tx, b)
	if e != nil {
		return Receipt{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return Receipt{}, e
	}
	return r, nil
}

// CommitBatchTx joins capture to an adapter's native state transaction. The
// returned value is provisional until the caller commits; it is not an ACK.
func CommitBatchTx(ctx context.Context, tx pgx.Tx, b Batch) (Receipt, error) {
	if e := b.Validate(); e != nil {
		return Receipt{}, e
	}
	if e := intelligence.LockProjectionTx(ctx, tx); e != nil {
		return Receipt{}, e
	}
	raw, e := json.Marshal(b)
	if e != nil {
		return Receipt{}, e
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	// Lock the logical batch even before its durable receipt exists.
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, b.BatchID); e != nil {
		return Receipt{}, e
	}
	var prior, encoded string
	e = tx.QueryRow(ctx, `SELECT digest,receipt::text FROM noctis_v2.batch_receipts WHERE batch_id=$1`, b.BatchID).Scan(&prior, &encoded)
	if e == nil {
		if prior != digest {
			return Receipt{}, ErrConflict
		}
		var r Receipt
		e = json.Unmarshal([]byte(encoded), &r)
		return r, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return Receipt{}, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.checkpoints(source_id,epoch,mode,version,value) VALUES($1,$2,$3,0,'null') ON CONFLICT DO NOTHING`, b.SourceID, b.Epoch, b.Mode)
	if e != nil {
		return Receipt{}, e
	}
	var version int64
	var value string
	e = tx.QueryRow(ctx, `SELECT version,value::text FROM noctis_v2.checkpoints WHERE source_id=$1 AND epoch=$2 AND mode=$3 FOR UPDATE`, b.SourceID, b.Epoch, b.Mode).Scan(&version, &value)
	if e != nil {
		return Receipt{}, e
	}
	var equal bool
	e = tx.QueryRow(ctx, `SELECT $1::jsonb=$2::jsonb`, value, string(b.Expected.Value)).Scan(&equal)
	if e != nil {
		return Receipt{}, e
	}
	if version != b.Expected.Version || !equal {
		return Receipt{}, ErrConflict
	}
	for _, i := range b.Items {
		var expired bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.observations WHERE source_id=$1 AND native_id=$2 AND revision=$3 AND retention_expired_at IS NOT NULL)`, b.SourceID, i.NativeID, i.Revision).Scan(&expired); e != nil {
			return Receipt{}, e
		}
		if expired {
			return Receipt{}, errors.New("expired observation cannot be reconstructed by replay")
		}
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.content_blobs(hash,representation,payload) VALUES($1,$2,$3) ON CONFLICT(hash,representation) DO UPDATE SET payload=excluded.payload WHERE noctis_v2.content_blobs.payload=''::bytea`, i.Hash, i.Representation, i.Payload)
		if e != nil {
			return Receipt{}, e
		}
		id := uuid.NewString()
		tag, err := tx.Exec(ctx, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,published_at,collected_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`, id, b.SourceID, i.NativeID, i.Revision, i.Hash, i.Representation, b.Epoch, b.Mode, i.PublishedAt, i.CollectedAt)
		if err != nil {
			return Receipt{}, err
		}
		if tag.RowsAffected() == 0 {
			var hash, rep string
			e = tx.QueryRow(ctx, `SELECT id,hash,representation FROM noctis_v2.observations WHERE source_id=$1 AND native_id=$2 AND revision=$3`, b.SourceID, i.NativeID, i.Revision).Scan(&id, &hash, &rep)
			if e != nil {
				return Receipt{}, e
			}
			if hash != i.Hash || rep != i.Representation {
				return Receipt{}, ErrConflict
			}
		}
		if tag.RowsAffected() == 1 {
			rows, err := tx.Query(ctx, `UPDATE noctis_v2.observations SET superseded_by=$1 WHERE source_id=$2 AND native_id=$3 AND id<>$1 AND superseded_by IS NULL RETURNING id::text`, id, b.SourceID, i.NativeID)
			if err != nil {
				return Receipt{}, err
			}
			old := []string{}
			for rows.Next() {
				var oid string
				if err = rows.Scan(&oid); err != nil {
					rows.Close()
					return Receipt{}, err
				}
				old = append(old, oid)
			}
			rows.Close()
			if err = rows.Err(); err != nil {
				return Receipt{}, err
			}
			if len(old) > 0 {
				if err = intelligence.InvalidateProjectionTx(ctx, tx, nil, old, "observation_superseded"); err != nil {
					return Receipt{}, err
				}
			}
		}
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) SELECT $1,'parse',$2,$3,policy_version,'1' FROM noctis_v2.sources WHERE id=$4 ON CONFLICT DO NOTHING`, uuid.NewString(), id, i.Revision, b.SourceID)
		if e != nil {
			return Receipt{}, e
		}
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.checkpoints SET version=$4,value=$5 WHERE source_id=$1 AND epoch=$2 AND mode=$3`, b.SourceID, b.Epoch, b.Mode, b.Next.Version, string(b.Next.Value))
	if e != nil {
		return Receipt{}, e
	}
	var r Receipt
	r.BatchID = b.BatchID
	r.Checkpoint = b.Next
	if e = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&r.CommittedAt); e != nil {
		return Receipt{}, e
	}
	rb, _ := json.Marshal(r)
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.batch_receipts VALUES($1,$2,$3)`, b.BatchID, digest, string(rb))
	if e != nil {
		return Receipt{}, e
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.sources SET last_success_at=CASE WHEN $2='live' THEN clock_timestamp() ELSE last_success_at END,last_error=CASE WHEN $2='live' THEN NULL ELSE last_error END,coverage=CASE WHEN $2='legacy_import' THEN 'legacy_import_partial' WHEN kind='telegram' THEN 'native_updates; historical_gap_unknown' ELSE 'feed_window_only' END WHERE id=$1`, b.SourceID, string(b.Mode))
	if e != nil {
		return Receipt{}, e
	}
	return r, nil
}
