package runtimev2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestDomainCopiesEditPolicyStageAndClaimsPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p1','[{"type":"keyword","value":"alert"}]'),('p2','[{"type":"keyword","value":"alert"}]')`)
	must(e)
	epoch := uuid.NewString()
	sources := []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
	for i, s := range sources {
		_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,policy_version,enabled,epoch,activated_at) VALUES($1,'rss',$2,'p1',true,$3,clock_timestamp()-interval '1 hour')`, s, fmt.Sprint(i), epoch)
		must(e)
	}
	counts := map[string]int64{}
	insert := func(source, native, revision, text string) string {
		t.Helper()
		n := counts[source]
		counts[source]++
		old := json.RawMessage("null")
		if n > 0 {
			old = json.RawMessage(fmt.Sprint(n))
		}
		now := time.Now().UTC()
		_, e := (capture.Store{DSN: dsn}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: source, Epoch: epoch, Mode: capture.Live, Items: []capture.Item{{NativeID: native, Revision: revision, Payload: []byte(text), Hash: fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text))), Representation: "text/plain;utf8;v1", PublishedAt: &now, CollectedAt: now}}, Expected: capture.Checkpoint{Version: n, Value: old}, Next: capture.Checkpoint{Version: n + 1, Value: json.RawMessage(fmt.Sprint(n + 1))}})
		must(e)
		var id string
		must(c.QueryRow(ctx, `SELECT id::text FROM noctis_v2.observations WHERE source_id=$1 AND native_id=$2 AND revision=$3`, source, native, revision).Scan(&id))
		return id
	}
	w := intelligence.Worker{DSN: dsn, Owner: "domain"}
	a := insert(sources[0], "post", "1", "alert original")
	must(w.Once(ctx))
	insert(sources[0], "post", "2", "alert correction")
	must(w.Once(ctx))
	b := insert(sources[1], "copy", "1", "alert correction")
	must(w.Once(ctx))
	var n int
	// Two material source changes plus the explicit supersession invalidation.
	for table, want := range map[string]int{"intelligence_cases": 1, "case_changes": 3, "outbox": 2, "case_memberships": 3, "case_revisions": 3} {
		must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.`+table).Scan(&n))
		if n != want {
			t.Fatalf("%s=%d want%d", table, n, want)
		}
	}
	// Reprocess same observation under a new policy: another result, no false change.
	_, e = c.Exec(ctx, `UPDATE noctis_v2.sources SET policy_version='p2',policy_revision=policy_revision+1 WHERE id=$1`, sources[1])
	must(e)
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES($1,'parse',$2,'1','p2','1'),($3,'semantic',$2,'1','p1','1')`, uuid.NewString(), b, uuid.NewString())
	must(e)
	must(w.Once(ctx))
	if e = w.Once(ctx); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatalf("parse worker claimed semantic stage: %v", e)
	}
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.analyses WHERE observation_id=$1`, b).Scan(&n))
	if n != 2 {
		t.Fatal("policy result lost", n)
	}
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_changes`).Scan(&n))
	if n != 3 {
		t.Fatal("policy created false change", n)
	}
	// Concurrent copies preserve appearances without multiplying material changes.
	for i := 0; i < 8; i++ {
		insert(sources[2], fmt.Sprint(i), "1", "alert correction")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs <- (intelligence.Worker{DSN: dsn, Owner: fmt.Sprint(i)}).Once(ctx) }(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		must(e)
	}
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_changes`).Scan(&n))
	if n != 3 {
		t.Fatal("copies created changes", n)
	}
	// Immutable source claims, dependency invalidation, real evidence validation.
	store := jobs.Store{DSN: dsn}
	j, e := store.Claim(ctx, "semantic", time.Minute, "semantic")
	must(e)
	var caseID, hash, rep string
	must(c.QueryRow(ctx, `SELECT m.case_id::text,o.hash,o.representation FROM noctis_v2.case_memberships m JOIN noctis_v2.observations o ON o.id=m.observation_id WHERE o.id=$1`, b).Scan(&caseID, &hash, &rep))
	ref := evidence.Ref{ObservationID: b, Revision: "1", Hash: hash, Representation: rep, End: len("alert correction")}
	claimA, claimB := uuid.NewString(), uuid.NewString()
	analysis := intelligence.ValidatedAnalysis{JobKey: j.Key, Producer: "fixture:model", Refs: []evidence.Ref{ref}, Claims: []intelligence.AnalysisClaim{{ID: claimA, CaseID: caseID, Subject: "source", Predicate: "claims", Object: "synthetic allegation", Refs: []evidence.Ref{ref}}, {ID: claimB, CaseID: caseID, Subject: "source", Predicate: "infers", Object: "dependent allegation", Refs: []evidence.Ref{ref}, Dependencies: []intelligence.ClaimDependency{{ClaimVersion: intelligence.ClaimVersion{ID: claimA, Revision: 1}, Relation: "depends_on"}}}}}
	must(store.Finish(ctx, j, func(tx pgx.Tx) error { return intelligence.ApplyAnalysisTx(ctx, tx, analysis) }))
	var status string
	must(c.QueryRow(ctx, `SELECT status FROM noctis_v2.claim_versions WHERE id=$1`, claimA).Scan(&status))
	if status != "source_claim" {
		t.Fatal(status)
	}
	must(w.Brief(ctx, time.Now().UTC().Format("2006-01-02"), "p1"))
	tx, e := c.Begin(ctx)
	must(e)
	must(intelligence.RetractClaimTx(ctx, tx, intelligence.ClaimVersion{ID: claimA, Revision: 1}, "operator:test", "synthetic correction", []evidence.Ref{ref}))
	must(tx.Commit(ctx))
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.claim_versions WHERE invalidated`).Scan(&n))
	if n != 2 {
		t.Fatal("dependency invalidation", n)
	}
	var invalid bool
	must(c.QueryRow(ctx, `SELECT invalidated FROM noctis_v2.briefs`).Scan(&invalid))
	if !invalid {
		t.Fatal("brief not invalidated")
	}
	_ = a
}
