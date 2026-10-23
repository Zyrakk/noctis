package runtimev2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestAIUsagePresenceAndAccountingExceptionsPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	for _, mode := range []string{"nousage", "usage_empty", "usage_partial", "usage_null", "usage_negative", "usage_fractional", "usage_overreserve", "substituted_model"} {
		t.Run(mode, func(t *testing.T) {
			f.mode.Store(mode)
			in := f.input(t, "query")
			in.Text += " " + mode
			j, e := f.store.Submit(ctx, inference.Submit{Function: "query.plan", Input: in, RequestID: uuid.NewString()}, "fixture-admin")
			if e != nil {
				t.Fatal(e)
			}
			if e = f.store.Once(ctx); e != nil {
				t.Fatal(e)
			}
			var state string
			var actual *int64
			var exposure, maximum int64
			var exception *string
			if e = f.conn.QueryRow(ctx, `SELECT state,actual_units,exposure_units,maximum_units,accounting_exception FROM noctis_v2.ai_attempts WHERE job_id=$1`, j.ID).Scan(&state, &actual, &exposure, &maximum, &exception); e != nil {
				t.Fatal(e)
			}
			switch mode {
			case "usage_overreserve":
				if state != "settled" || actual == nil || *actual != 3000000 || exposure != *actual || exposure <= maximum || exception == nil || *exception != "actual_exceeds_reservation" {
					t.Fatal(state, actual, exposure, maximum, exception)
				}
			case "substituted_model":
				view, e := f.store.Job(ctx, j.ID, "fixture-admin")
				if e != nil || view.State != "failed" || view.Error != "model_changed" || actual == nil || *actual != 140 || exception == nil || *exception != "declared_model_changed" {
					t.Fatal(view, e, state, actual, exception)
				}
			default:
				if state != "uncertain" || actual != nil || exposure != maximum || exposure == 0 {
					t.Fatal("unknown usage released exposure", state, actual, exposure, maximum)
				}
			}
		})
	}
}

func TestProjectionTransitiveThreeCasesPostgres(t *testing.T) {
	for _, variant := range []string{"contradicted", "retracted", "unresolved", "edit", "delete", "purge"} {
		t.Run(variant, func(t *testing.T) {
			f := newAIFixture(t)
			ctx := context.Background()
			c := f.conn
			var hash, rep, revision string
			var length int
			if e := c.QueryRow(ctx, `SELECT hash,representation,revision,octet_length(payload) FROM noctis_v2.observations JOIN noctis_v2.content_blobs USING(hash,representation) WHERE id=$1`, f.observation).Scan(&hash, &rep, &revision, &length); e != nil {
				t.Fatal(e)
			}
			cases, claims := []string{f.caseID, uuid.NewString(), uuid.NewString()}, []string{uuid.NewString(), uuid.NewString(), uuid.NewString()}
			for i, id := range cases {
				obs := f.observation
				if i > 0 {
					obs = uuid.NewString()
					if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,published_at,collected_at) SELECT $1::uuid,source_id,$1::text,revision,hash,representation,epoch,mode,published_at,clock_timestamp()+interval '1 hour' FROM noctis_v2.observations WHERE id=$2`, obs, f.observation); e != nil {
						t.Fatal(e)
					}
				}
				if i > 0 {
					if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.intelligence_cases(id,group_key,title,revision) VALUES($1::uuid,$1::text,'dependent',1);`, id); e != nil {
						t.Fatal(e)
					}
					if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.case_revisions(case_id,revision,body) VALUES($1::uuid,1,jsonb_build_object('id',$1::text,'revision','1'))`, id); e != nil {
						t.Fatal(e)
					}
				}
				refs, _ := json.Marshal([]map[string]any{{"observation_id": obs, "revision": revision, "hash": hash, "representation": rep, "start": 0, "end": length}})
				if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.claim_versions(id,revision,case_id,subject,predicate,object,status,producer,policy_version,evidence) VALUES($1,1,$2,'source','reports','test','source_claim','fixture','p1',$3)`, claims[i], id, string(refs)); e != nil {
					t.Fatal(e)
				}
				if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.case_memberships(case_id,observation_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, obs); e != nil {
					t.Fatal(e)
				}
				if i > 0 {
					if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.claim_dependencies VALUES($1,1,$2,1,'depends_on')`, claims[i], claims[i-1]); e != nil {
						t.Fatal(e)
					}
				}
				if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.briefs(period,policy_version,body) VALUES($1,'p1',jsonb_build_object('observation_id',$2::text))`, fmt.Sprint(i), obs); e != nil {
					t.Fatal(e)
				}
				if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.case_attention(case_id,mode) VALUES($1,'silent_until_change')`, id); e != nil {
					t.Fatal(e)
				}
			}
			tx, e := c.Begin(ctx)
			if e != nil {
				t.Fatal(e)
			}
			defer tx.Rollback(ctx)
			switch variant {
			case "contradicted", "retracted", "unresolved":
				e = intelligence.JudgeClaimTx(ctx, tx, intelligence.ClaimVersion{ID: claims[0], Revision: 1}, variant, "operator:fixture", "counterevidence", []evidence.Ref{{ObservationID: f.observation, Revision: revision, Hash: hash, Representation: rep, End: length}})
			case "edit":
				var epoch string
				if e = tx.QueryRow(ctx, `SELECT epoch::text FROM noctis_v2.sources WHERE id=$1`, f.source).Scan(&epoch); e != nil {
					t.Fatal(e)
				}
				now := time.Now().UTC()
				payload := []byte("alert corrected original")
				_, e = capture.CommitBatchTx(ctx, tx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: f.source, Epoch: epoch, Mode: capture.Live, Expected: capture.Checkpoint{Version: 1, Value: json.RawMessage("1")}, Next: capture.Checkpoint{Version: 2, Value: json.RawMessage("2")}, Items: []capture.Item{{NativeID: "one", Revision: "2", Hash: fmt.Sprintf("sha256:%x", sha256.Sum256(payload)), Representation: rep, Payload: payload, CollectedAt: now, PublishedAt: &now}}})
			case "delete":
				if _, e = tx.Exec(ctx, `UPDATE noctis_v2.observations SET source_deleted=true WHERE id=$1`, f.observation); e == nil {
					e = intelligence.InvalidateProjectionTx(ctx, tx, nil, []string{f.observation}, "native_evidence_changed")
				}
			case "purge":
				in := operationInput{SourceID: f.source, DataClass: "private", Action: "policy", RetainSeconds: 0}
				if _, e = retentionTx(ctx, tx, in); e != nil {
					t.Fatal(e)
				}
				in.Action = "run"
				in.ExpectedRevision = 1
				var result any
				result, e = retentionTx(ctx, tx, in)
				if e != nil {
					t.Fatal(e)
				}
				in.Action = "batch"
				in.RunID = result.(map[string]any)["run_id"].(string)
				in.Limit = 100
				_, e = retentionTx(ctx, tx, in)
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = tx.Commit(ctx); e != nil {
				t.Fatal(e)
			}
			var n int
			if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.claim_versions WHERE id::text=ANY($1) AND revision=1 AND invalidated`, claims).Scan(&n); e != nil || n != 3 {
				t.Fatal("closure claims", n, e)
			}
			if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.intelligence_cases WHERE id::text=ANY($1) AND revision>1`, cases).Scan(&n); e != nil || n != 3 {
				t.Fatal("closure case revisions", n, e)
			}
			if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.briefs WHERE invalidated AND period IN ('0','1','2')`).Scan(&n); e != nil || n != 3 {
				t.Fatal("closure briefs", n, e)
			}
			if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_attention WHERE case_id::text=ANY($1) AND mode='automatic'`, cases).Scan(&n); e != nil || n != 3 {
				t.Fatal("closure attention", n, e)
			}
			if e = (intelligence.Worker{DSN: f.store.DSN}).Brief(ctx, time.Now().UTC().Format("2006-01-02"), "p1"); e != nil {
				t.Fatal(e)
			}
			var invalid bool
			if e = c.QueryRow(ctx, `SELECT invalidated FROM noctis_v2.briefs WHERE period=$1 AND policy_version='p1'`, time.Now().UTC().Format("2006-01-02")).Scan(&invalid); e != nil || !invalid {
				t.Fatal("recomposition revived withdrawn support", variant, e)
			}
		})
	}
}
