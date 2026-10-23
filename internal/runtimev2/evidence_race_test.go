package runtimev2

import (
	"context"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/Zyrakk/noctis/internal/telegramv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestEvidenceValidationAndNativeDeletionBothOrdersPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	db, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close(ctx)
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e = db.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p1','[{"type":"keyword","value":"synthetic"}]')`)
	must(e)
	tgStore := telegramv2.Store{DSN: dsn}
	worker := intelligence.Worker{DSN: dsn, Owner: "race-parser"}
	jobStore := jobs.Store{DSN: dsn}
	for order := 0; order < 2; order++ {
		_, source, obs := qualifiedOutbox(t, dsn)
		must(worker.Once(ctx))
		var caseID, hash, rep string
		var length int
		must(db.QueryRow(ctx, `SELECT m.case_id::text,o.hash,o.representation,octet_length(b.payload) FROM noctis_v2.case_memberships m JOIN noctis_v2.observations o ON o.id=m.observation_id JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE o.id=$1`, obs).Scan(&caseID, &hash, &rep, &length))
		account := uuid.NewString()
		generation := uuid.NewString()
		_, e = db.Exec(ctx, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES($1,$2)`, account, generation)
		must(e)
		_, e = db.Exec(ctx, `UPDATE noctis_v2.sources SET kind='telegram' WHERE id=$1`, source)
		must(e)
		_, e = db.Exec(ctx, `INSERT INTO noctis_v2.telegram_peers(account_id,peer_type,peer_id,source_id,auth_generation,allowed) VALUES($1,'channel',77,$2,$3,true)`, account, source, generation)
		must(e)
		owner, e := tgStore.Acquire(ctx, account, "race-owner", time.Minute)
		provisionNativeBudget(t, dsn, db, account)
		must(e)
		_, e = db.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES($1,'semantic',$2,'1','p1','1')`, uuid.NewString(), obs)
		must(e)
		job, e := jobStore.Claim(ctx, "race-semantic", time.Minute, "semantic")
		must(e)
		ref := evidence.Ref{ObservationID: obs, Revision: "1", Hash: hash, Representation: rep, End: length}
		claimID := uuid.NewString()
		analysis := intelligence.ValidatedAnalysis{JobKey: job.Key, Producer: "fixture:race", Refs: []evidence.Ref{ref}, Claims: []intelligence.AnalysisClaim{{ID: claimID, CaseID: caseID, Subject: "source", Predicate: "claims", Object: "synthetic claim", Refs: []evidence.Ref{ref}}}}
		deleteMessage := func() error {
			_, e := tgStore.CommitUpdates(ctx, owner, telegramv2.Envelope{BatchID: uuid.NewString(), Expected: telegramv2.State{}, Next: telegramv2.State{}, Mode: "live", Events: []telegramv2.Event{{Peer: telegramv2.Peer{Type: "channel", ID: 77}, MessageID: 1, Revision: "delete:1", Kind: "delete", Pts: 1, PtsCount: 1}}})
			return e
		}
		if order == 0 {
			// Hold publication after validation and all derived inserts, before commit.
			_, e = db.Exec(ctx, `CREATE FUNCTION noctis_v2.analysis_barrier() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_advisory_xact_lock(76238451999);RETURN NEW;END$$;CREATE TRIGGER analysis_barrier BEFORE INSERT ON noctis_v2.analysis_results FOR EACH ROW EXECUTE FUNCTION noctis_v2.analysis_barrier();SELECT pg_advisory_lock(76238451999)`)
			must(e)
			analysisDone := make(chan error, 1)
			go func() {
				analysisDone <- jobStore.Finish(ctx, job, func(tx pgx.Tx) error { return intelligence.ApplyAnalysisTx(ctx, tx, analysis) })
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				var blocked bool
				must(db.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'INSERT INTO noctis_v2.analysis_results%')`).Scan(&blocked))
				if blocked {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("analysis did not reach postvalidation barrier")
				}
				time.Sleep(10 * time.Millisecond)
			}
			deletionDone := make(chan error, 1)
			go func() { deletionDone <- deleteMessage() }()
			// SQL wait, not a timing guess, proves invalidation is serialized behind publication.
			deadline = time.Now().Add(5 * time.Second)
			for {
				var blocked bool
				must(db.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT pg_advisory_xact_lock(76238451003)%')`).Scan(&blocked))
				if blocked {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("deletion did not wait for publication")
				}
				time.Sleep(10 * time.Millisecond)
			}
			_, e = db.Exec(ctx, `SELECT pg_advisory_unlock(76238451999)`)
			must(e)
			must(<-analysisDone)
			must(<-deletionDone)
			_, e = db.Exec(ctx, `DROP TRIGGER analysis_barrier ON noctis_v2.analysis_results`)
			must(e)
			var invalid bool
			must(db.QueryRow(ctx, `SELECT invalidated FROM noctis_v2.claim_versions WHERE id=$1`, claimID).Scan(&invalid))
			if !invalid {
				t.Fatal("new old-evidence claim survived deletion")
			}
		} else {
			must(deleteMessage())
			if e = jobStore.Finish(ctx, job, func(tx pgx.Tx) error { return intelligence.ApplyAnalysisTx(ctx, tx, analysis) }); e == nil {
				t.Fatal("claim published after source deletion")
			}
			var n int
			must(db.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.claim_versions WHERE id=$1`, claimID).Scan(&n))
			if n != 0 {
				t.Fatal("rejected claim partially published")
			}
		}
	}
	must(worker.Brief(ctx, time.Now().UTC().Format("2006-01-02"), "p1"))
	var invalid bool
	must(db.QueryRow(ctx, `SELECT invalidated FROM noctis_v2.briefs WHERE policy_version='p1'`).Scan(&invalid))
	if !invalid {
		t.Fatal("brief resurrected invalidated/deleted support")
	}
}
