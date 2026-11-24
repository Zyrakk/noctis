package runtimev2

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/jackc/pgx/v5"
)

func TestTypedQueryPlanValidationAndPaginationPostgresHTTPS(t *testing.T) {
	dsn := productDB(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	call := operationsClient(t, &aiFixture{dsn: dsn, conn: conn})
	ids := []string{}
	for i := 1; i <= 10; i++ {
		id := fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
		ids = append(ids, id)
		if _, err := conn.Exec(ctx, `INSERT INTO noctis_v2.intelligence_cases(id,group_key,title) VALUES($1,$2,$3)`, id, "typed-query-"+id, "  synthetic alert  "); err != nil {
			t.Fatal(err)
		}
	}
	base := inference.QueryPlan{Version: "1", Operation: "search", Entity: "cases", Mode: "exact", Limit: 7, Filters: inference.QueryFilters{Kind: "case"}}
	query := func(plan inference.QueryPlan) inference.QueryResult {
		t.Helper()
		data := call("POST", "query", map[string]any{"plan": plan}, 200)["data"]
		raw, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		var result inference.QueryResult
		if err := json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(result.Plan, plan) {
			t.Fatalf("API changed plan: got %+v want %+v", result.Plan, plan)
		}
		var stored inference.QueryPlan
		var storedRaw []byte
		if err := conn.QueryRow(ctx, `SELECT plan FROM noctis_v2.ai_query_results WHERE id=$1`, result.ID).Scan(&storedRaw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(storedRaw, &stored); err != nil || !reflect.DeepEqual(stored, plan) {
			t.Fatalf("stored plan differs: %+v %v", stored, err)
		}
		return result
	}
	rowIDs := func(result inference.QueryResult) []string {
		t.Helper()
		got := []string{}
		for _, raw := range result.Rows {
			var row struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(raw, &row); err != nil {
				t.Fatal(err)
			}
			got = append(got, row.ID)
		}
		return got
	}
	for _, text := range []string{"", "  synthetic alert  "} {
		plan := base
		plan.Text = text
		first := query(plan)
		if got := rowIDs(first); !reflect.DeepEqual(got, ids[:7]) || first.NextCursor != ids[6] {
			t.Fatalf("first page: ids=%v cursor=%q", got, first.NextCursor)
		}
		plan.Cursor = first.NextCursor
		last := query(plan)
		if got := rowIDs(last); !reflect.DeepEqual(got, ids[7:]) || last.NextCursor != "" {
			t.Fatalf("last page: ids=%v cursor=%q", got, last.NextCursor)
		}
	}
	plan := base
	plan.Text = "alert"
	plan.Mode = "fulltext"
	plan.Filters.CaseID = ids[9]
	if got := rowIDs(query(plan)); !reflect.DeepEqual(got, ids[9:]) {
		t.Fatalf("fulltext and case filter: %v", got)
	}
	plan = base
	plan.Text = "synthetic alert"
	if got := query(plan); len(got.Rows) != 0 {
		t.Fatal("exact query normalized significant whitespace")
	}
	plan = base
	plan.Filters = inference.QueryFilters{}
	if got := query(plan); len(got.Rows) != 7 {
		t.Fatal("empty text and filters rejected")
	}
	var before int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_query_results`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []map[string]any{{"limit": nil}, {"limit": ""}, {"limit": 1.5}, {"limit": 0}, {"limit": 101}, {"cursor": "invalid"}, {"version": "2"}, {"operation": "delete"}, {"filters": map[string]any{"source_id": "invalid"}}} {
		body := map[string]any{"version": "1", "operation": "search", "entity": "cases", "mode": "exact", "text": "", "filters": map[string]any{}, "limit": 7}
		for k, v := range mutation {
			body[k] = v
		}
		call("POST", "query", map[string]any{"plan": body}, 400)
	}
	var after int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_query_results`).Scan(&after); err != nil || after != before {
		t.Fatalf("invalid queries created results: before=%d after=%d err=%v", before, after, err)
	}
	call("POST", "ai/jobs", map[string]any{"function_id": "query.plan", "input": map[string]any{"kind": "query", "text": "   "}}, 400)
}
