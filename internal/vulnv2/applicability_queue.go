package vulnv2

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/jackc/pgx/v5"
)

// ApplicabilityPageSize bounds both pair writes and dossier publications. Each
// continuation gets a fresh job, so successful pages do not consume retry budget.
const ApplicabilityPageSize = 25

var errApplicabilityPaused = errors.New("applicability globally paused")

func EnqueueAssetApplicabilityTx(ctx context.Context, tx pgx.Tx, asset string, revision int) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT noctis_v2.enqueue_applicability('asset',$1::text,$2::integer,'asset:'||$1::text||':'||$2::text)::text`, asset, revision).Scan(&id)
	return id, err
}

func EnqueueCVEApplicabilityTx(ctx context.Context, tx pgx.Tx, cve, snapshot string, expires time.Time) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT noctis_v2.enqueue_applicability('cve',$1,0,'snapshot:'||$2||':'||$1)::text`, cve, snapshot).Scan(&id)
	if err == nil {
		// Delayed requests are durable but receive a job only when due, preserving
		// the general jobs retry horizon even with a seven-day feed TTL.
		_, err = tx.Exec(ctx, `SELECT noctis_v2.enqueue_applicability('cve',$1,0,'expiry:'||$2||':'||$1,$3)`, cve, snapshot, expires)
	}
	return id, err
}

type ApplicabilityWorker struct{ DSN, Owner string }

// Once executes at most one bounded page, independently of inference settings.
func (w ApplicabilityWorker) Once(ctx context.Context) error {
	c, err := pgx.Connect(ctx, w.DSN)
	if err != nil {
		return err
	}
	defer c.Close(context.Background())
	var paused bool
	if err = c.QueryRow(ctx, `SELECT paused FROM noctis_v2.runtime_control`).Scan(&paused); err != nil {
		return err
	}
	if paused {
		return pgx.ErrNoRows
	}
	_, err = c.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version)
SELECT gen_random_uuid(),'applicability',r.id,r.page::text,r.calculation_version,'1'
FROM noctis_v2.applicability_requests r WHERE r.state='pending' AND r.due_at<=clock_timestamp()
AND NOT EXISTS(SELECT FROM noctis_v2.jobs j WHERE j.stage='applicability' AND j.input_id=r.id AND j.input_revision=r.page::text)
ORDER BY r.due_at,r.id LIMIT $1 ON CONFLICT DO NOTHING`, ApplicabilityPageSize)
	if err != nil {
		return err
	}
	store := jobs.Store{DSN: w.DSN}
	j, err := store.Claim(ctx, w.Owner, time.Minute, "applicability")
	if err != nil {
		return err
	}
	err = w.Process(ctx, j)
	if errors.Is(err, errApplicabilityPaused) {
		_, releaseErr := c.Exec(ctx, `UPDATE noctis_v2.jobs SET state='queued',attempts=GREATEST(attempts-1,0),lease_owner=NULL,lease_expires_at=NULL WHERE id=$1 AND state='leased' AND lease_owner=$2 AND fence=$3 AND lease_expires_at>clock_timestamp()`, j.ID, j.Owner, j.Fence)
		return releaseErr
	}
	if err != nil && !errors.Is(err, jobs.ErrLeaseLost) {
		if failErr := store.Fail(ctx, j, "applicability_page_failed", false); failErr != nil {
			return errors.Join(err, failErr)
		}
	}
	return err
}

type applicabilityRequest struct {
	id, scope, input, phase, cursor, bound, caseBound string
	revision                                          int
	page                                              int64
}

// Process commits results, cursor and the next page atomically with the job's
// lease/fence. It is also exposed for deterministic crash/lease integration tests.
func (w ApplicabilityWorker) Process(ctx context.Context, j jobs.Job) error {
	if j.Stage != "applicability" {
		return errors.New("invalid applicability stage")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	return (jobs.Store{DSN: w.DSN}).Finish(ctx, j, func(tx pgx.Tx) error {
		if err := intelligence.LockProjectionTx(ctx, tx); err != nil {
			return err
		}
		var paused bool
		if err := tx.QueryRow(ctx, `SELECT paused FROM noctis_v2.runtime_control FOR SHARE`).Scan(&paused); err != nil {
			return err
		}
		if paused {
			return errApplicabilityPaused
		}
		var r applicabilityRequest
		err := tx.QueryRow(ctx, `SELECT id::text,scope,input_id,input_revision,phase,page,cursor,upper_bound,case_upper_bound FROM noctis_v2.applicability_requests WHERE id=$1 AND state='pending' FOR UPDATE`, j.InputID).Scan(&r.id, &r.scope, &r.input, &r.revision, &r.phase, &r.page, &r.cursor, &r.bound, &r.caseBound)
		if err != nil {
			return err
		}
		if strconv.FormatInt(r.page, 10) != j.InputRevision {
			return errors.New("applicability page superseded")
		}
		if r.phase == "start" {
			switch r.scope {
			case "asset":
				r.phase = "pairs"
				err = tx.QueryRow(ctx, `SELECT COALESCE(max(f.cve),'') FROM noctis_v2.vulnerability_facts f JOIN noctis_v2.feed_snapshots s ON s.id=f.snapshot_id WHERE s.kind='nvd'`).Scan(&r.bound)
			case "cve", "evidence":
				r.phase = "pairs"
				if r.scope == "evidence" {
					r.phase = "children"
				}
				err = tx.QueryRow(ctx, `SELECT COALESCE(max(id::text),'') FROM noctis_v2.asset_versions`).Scan(&r.bound)
			case "case":
				r.phase = "cases"
				err = tx.QueryRow(ctx, `SELECT COALESCE(max(id::text),'') FROM noctis_v2.intelligence_cases`).Scan(&r.caseBound)
			}
			if err != nil {
				return err
			}
		}
		var pairs, cases int
		if r.phase == "pairs" || r.phase == "children" {
			keys, err := applicabilityKeys(ctx, tx, r)
			if err != nil {
				return err
			}
			for _, key := range keys {
				if r.phase == "children" {
					_, err = tx.Exec(ctx, `SELECT noctis_v2.enqueue_applicability('asset',$1::text,(SELECT max(revision) FROM noctis_v2.asset_versions WHERE id=$1::uuid),'evidence-asset:'||$2::text||':'||$1::text,clock_timestamp(),$2::uuid)`, key, r.id)
				} else {
					cve, asset, revision := r.input, key, 0
					if r.scope == "asset" {
						cve, asset, revision = key, r.input, r.revision
					}
					_, err = EvaluateCurrentPairTx(ctx, tx, cve, asset, "", revision)
				}
				if err != nil {
					return err
				}
				r.cursor = key
			}
			pairs = len(keys)
			if len(keys) < ApplicabilityPageSize {
				// Dossier traversal starts only after pair coverage. Memberships
				// inserted earlier are inside this bound; later memberships own a
				// request that observes the committed pairs, even behind our cursor.
				if err = tx.QueryRow(ctx, `SELECT COALESCE(max(id::text),'') FROM noctis_v2.intelligence_cases`).Scan(&r.caseBound); err != nil {
					return err
				}
				r.phase = "cases"
				r.cursor = ""
				r.bound = r.caseBound
			}
		} else if r.phase == "cases" {
			keys, err := applicabilityCaseKeys(ctx, tx, r)
			if err != nil {
				return err
			}
			for _, id := range keys {
				if err = PublishApplicabilityCaseTx(ctx, tx, id); err != nil {
					return err
				}
				r.cursor = id
			}
			cases = len(keys)
			if len(keys) < ApplicabilityPageSize {
				r.phase = "done"
			}
		}
		state := "pending"
		if r.phase == "done" {
			state = "complete"
		} else {
			r.page++
		}
		_, err = tx.Exec(ctx, `UPDATE noctis_v2.applicability_requests SET phase=$2,page=$3,cursor=$4,upper_bound=$5,case_upper_bound=$6,state=$7,pairs_processed=pairs_processed+$8,cases_processed=cases_processed+$9,updated_at=clock_timestamp() WHERE id=$1`, r.id, r.phase, r.page, r.cursor, r.bound, r.caseBound, state, pairs, cases)
		if err != nil {
			return err
		}
		if state == "pending" {
			_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES(gen_random_uuid(),'applicability',$1,$2,'applicability-v2','1')`, r.id, fmt.Sprint(r.page))
		}
		return err
	})
}

func applicabilityKeys(ctx context.Context, tx pgx.Tx, r applicabilityRequest) ([]string, error) {
	query := `SELECT DISTINCT id::text FROM noctis_v2.asset_versions WHERE id::text>$1 AND id::text<=$2 ORDER BY id::text LIMIT $3`
	args := []any{r.cursor, r.bound, ApplicabilityPageSize}
	if r.scope == "asset" {
		query = `SELECT DISTINCT f.cve FROM noctis_v2.vulnerability_facts f JOIN noctis_v2.feed_snapshots s ON s.id=f.snapshot_id WHERE s.kind='nvd' AND f.cve>$1 AND f.cve<=$2 ORDER BY f.cve LIMIT $3`
	}
	if r.scope == "evidence" {
		query = `SELECT id::text FROM (SELECT DISTINCT ON(id) id,evidence FROM noctis_v2.asset_versions WHERE id::text>$1 AND id::text<=$2 ORDER BY id,revision DESC)a WHERE EXISTS(SELECT FROM jsonb_array_elements(a.evidence) ref WHERE ref->>'observation_id'=$4) ORDER BY id::text LIMIT $3`
		args = append(args, r.input)
	}
	return applicabilityReadKeys(ctx, tx, query, args...)
}
func applicabilityCaseKeys(ctx context.Context, tx pgx.Tx, r applicabilityRequest) ([]string, error) {
	query := `SELECT id::text FROM noctis_v2.intelligence_cases ic WHERE id::text>$1 AND id::text<=$2`
	args := []any{r.cursor, r.caseBound, ApplicabilityPageSize}
	switch r.scope {
	case "case":
		query += ` AND id=$4::uuid`
		args = append(args, r.input)
	case "cve":
		query += ` AND EXISTS(SELECT FROM noctis_v2.case_memberships m JOIN noctis_v2.observable_sightings s USING(observation_id) WHERE m.case_id=ic.id AND s.observable_type='cve' AND s.value=$4)`
		args = append(args, r.input)
	case "evidence":
		query += ` AND EXISTS(SELECT FROM noctis_v2.case_memberships m WHERE m.case_id=ic.id AND m.observation_id=$4::uuid)`
		args = append(args, r.input)
	case "asset":
		query += ` AND EXISTS(SELECT FROM noctis_v2.case_memberships m JOIN noctis_v2.observable_sightings s USING(observation_id) WHERE m.case_id=ic.id AND s.observable_type='cve')`
	}
	return applicabilityReadKeys(ctx, tx, query+` ORDER BY id::text LIMIT $3`, args...)
}
func applicabilityReadKeys(ctx context.Context, tx pgx.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []string{}
	for rows.Next() {
		var key string
		if err = rows.Scan(&key); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}
