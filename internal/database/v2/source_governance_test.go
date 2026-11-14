package v2

import (
	"context"
	"strings"
	"testing"

	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestSourceGovernanceMigrationPostgres(t *testing.T) {
	for _, tc := range []struct {
		name, problem                               string
		independent, multiple, oldPaused, newPaused bool
		missing, stale, badTerms, ownPaused         bool
	}{
		{name: "zero independent", independent: true},
		{name: "one canonical"},
		{name: "multiple keep canonical metadata", multiple: true},
		{name: "multiple preserve governing pause", multiple: true, oldPaused: true, newPaused: true},
		{name: "cannot remove veto", multiple: true, oldPaused: true, problem: "would_remove_question_pause"},
		{name: "cannot remove latent veto", multiple: true, oldPaused: true, ownPaused: true, problem: "would_remove_question_pause"},
		{name: "ambiguous relationship", multiple: true, missing: true, problem: "ambiguous_or_incoherent_question_policy"},
		{name: "stale policy", stale: true, problem: "ambiguous_or_incoherent_question_policy"},
		{name: "incoherent terms", badTerms: true, problem: "ambiguous_or_incoherent_question_policy"},
		{name: "independent relationship incoherent", independent: true, multiple: true, problem: "independent_policy_has_question_relationship"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dsn := testDB(t)
			ms, e := Load(migrations.Files)
			if e != nil {
				t.Fatal(e)
			}
			index := -1
			for i, m := range ms {
				if m.Name == "011_source_governance.sql" {
					index = i
				}
			}
			if index < 0 {
				t.Fatal("governance migration missing")
			}
			if e = Migrate(ctx, dsn, ms[:index]); e != nil {
				t.Fatal(e)
			}
			c, e := pgx.Connect(ctx, dsn)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close(ctx)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, e := c.Exec(ctx, sql, args...); e != nil {
					t.Fatal(e)
				}
			}
			a, b, source := uuid.NewString(), uuid.NewString(), uuid.NewString()
			exec(`INSERT INTO noctis_v2.questions(id,title,enabled,revision) VALUES($1,'old',$3,1),($2,'current',$4,2)`, a, b, !tc.oldPaused, !tc.newPaused)
			version := "question:" + b + ":r2"
			terms := `[]`
			if tc.badTerms {
				terms = `[{"type":"keyword","value":"not current"}]`
			}
			exec(`INSERT INTO noctis_v2.policies(version,terms) VALUES($1,'[]'),($2,'[]'),($3,$4),('independent','[]')`, "question:"+a, "question:"+b, version, terms)
			if tc.independent {
				version = "independent"
			} else if tc.stale {
				version = "question:" + b
			}
			exec(`INSERT INTO noctis_v2.sources(id,kind,native_id,policy_version,enabled) VALUES($1::uuid,'rss',$1::text,$2,$3)`, source, version, !tc.ownPaused)
			if !tc.independent && !tc.missing {
				exec(`INSERT INTO noctis_v2.question_sources(question_id,source_id,independence) VALUES($1,$2,'preserve canonical metadata')`, b, source)
			}
			if tc.multiple {
				exec(`INSERT INTO noctis_v2.question_sources(question_id,source_id,independence) VALUES($1,$2,'old metadata')`, a, source)
			}
			proposal := uuid.NewString()
			exec(`INSERT INTO noctis_v2.discovery_proposals(id,question_id,kind,endpoint,provenance,reason,score,expires_at,source_id,permission_status) VALUES($1,$2,'rss','synthetic','{"origin":"historical"}','historical','{}',clock_timestamp()+interval '1 day',$3,'authorized')`, proposal, a, source)
			exec(`INSERT INTO noctis_v2.action_receipts VALUES('fixture','historical','sources/policy','historical','{"preserve":true}')`)
			snapshot := func() string {
				var raw string
				if e := c.QueryRow(ctx, `SELECT jsonb_build_array((SELECT jsonb_agg(s ORDER BY id) FROM noctis_v2.sources s),(SELECT jsonb_agg(q ORDER BY id) FROM noctis_v2.questions q),(SELECT jsonb_agg(p ORDER BY version) FROM noctis_v2.policies p),(SELECT jsonb_agg(qs ORDER BY question_id) FROM noctis_v2.question_sources qs),(SELECT jsonb_agg(d ORDER BY id) FROM noctis_v2.discovery_proposals d),(SELECT jsonb_agg(a ORDER BY request_id) FROM noctis_v2.action_receipts a))::text`).Scan(&raw); e != nil {
					t.Fatal(e)
				}
				return raw
			}
			before := snapshot()
			e = Migrate(ctx, dsn, ms[:index+1])
			if tc.problem != "" {
				if e == nil || !strings.Contains(e.Error(), source) || !strings.Contains(e.Error(), tc.problem) {
					t.Fatal("missing reconciliation diagnostic", e)
				}
				var rolledBack bool
				if e := c.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM public.noctis_v2_migrations WHERE name='011_source_governance.sql') AND NOT EXISTS(SELECT FROM pg_constraint WHERE conname='question_sources_one_governor')`).Scan(&rolledBack); e != nil || !rolledBack || snapshot() != before {
					t.Fatal("migration did not fully roll back", rolledBack, e)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			var metadata, question string
			var count int
			if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.question_sources WHERE source_id=$1`, source).Scan(&count); e != nil {
				t.Fatal(e)
			}
			if tc.independent {
				if count != 0 || before != snapshot() {
					t.Fatal("independent source changed", count)
				}
			} else {
				if e = c.QueryRow(ctx, `SELECT question_id::text,independence FROM noctis_v2.question_sources WHERE source_id=$1`, source).Scan(&question, &metadata); e != nil || count != 1 || question != b || metadata != "preserve canonical metadata" {
					t.Fatal("canonical relationship or metadata lost", question, metadata, count, e)
				}
				if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.question_sources(question_id,source_id) VALUES($1,$2)`, a, source); e == nil {
					t.Fatal("unique governing question not enforced")
				}
			}
			var preserved bool
			if e = c.QueryRow(ctx, `SELECT (SELECT count(*)=4 FROM noctis_v2.policies) AND (SELECT count(*)=2 FROM noctis_v2.questions) AND (SELECT question_id=$2 AND provenance='{"origin":"historical"}'::jsonb FROM noctis_v2.discovery_proposals WHERE id=$1) AND (SELECT enabled=$4 AND policy_version=$5 FROM noctis_v2.sources WHERE id=$3) AND EXISTS(SELECT FROM noctis_v2.action_receipts WHERE request_id='historical')`, proposal, a, source, !tc.ownPaused, version).Scan(&preserved); e != nil || !preserved {
				t.Fatal("historical records or source authorization changed", preserved, e)
			}
		})
	}
}
