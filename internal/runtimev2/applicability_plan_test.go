package runtimev2

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestApplicabilityCurrentSelectionBoundedPlanPostgres(t *testing.T) {
	f := newApplicabilityFixture(t)
	snapshot := f.feed("2026-01-02T00:00:00Z", f.now, f.now.Add(time.Hour), "2.0")
	f.exec(`INSERT INTO noctis_v2.vulnerability_facts(snapshot_id,cve,body)
		SELECT $1,'CVE-2026-'||n,'{"lastModified":"2026-01-02T00:00:00Z"}'::jsonb
		FROM generate_series(20000,20998) n`, snapshot)
	f.exec(`ANALYZE noctis_v2.vulnerability_facts`)
	f.exec(`ANALYZE noctis_v2.feed_snapshots`)

	queries := []struct {
		name, sql string
	}{
		{"function", `SELECT snapshot_id::text,to_jsonb(s) FROM noctis_v2.select_current_nvd($1) s`},
		{"view", `SELECT snapshot_id::text,to_jsonb(s) FROM noctis_v2.nvd_current_selection s WHERE cve=$1`},
	}
	var selected []byte
	for _, query := range queries {
		var got string
		var row []byte
		f.must(f.c.QueryRow(f.ctx, query.sql, "CVE-2026-12345").Scan(&got, &row))
		if got != snapshot {
			t.Fatalf("%s selected snapshot %s, want %s", query.name, got, snapshot)
		}
		if selected == nil {
			selected = row
		} else if !bytes.Equal(selected, row) {
			t.Fatalf("view changed selector columns or values: function=%s view=%s", selected, row)
		}
	}

	// With one record per CVE, no node should run once per unrelated CVE.
	// Check actual work rather than wall time, which varies across CI hosts.
	type planNode struct {
		NodeType     string     `json:"Node Type"`
		RelationName string     `json:"Relation Name"`
		ActualLoops  float64    `json:"Actual Loops"`
		ActualRows   float64    `json:"Actual Rows"`
		Plans        []planNode `json:"Plans"`
	}
	for _, query := range []struct {
		name, sql string
	}{
		{"function", `SELECT snapshot_id FROM noctis_v2.select_current_nvd($1)`},
		{"view", `SELECT snapshot_id FROM noctis_v2.nvd_current_selection WHERE cve=$1`},
	} {
		t.Run(query.name, func(t *testing.T) {
			var raw []byte
			if err := f.c.QueryRow(f.ctx, "EXPLAIN (ANALYZE,BUFFERS,FORMAT JSON) "+query.sql, "CVE-2026-12345").Scan(&raw); err != nil {
				t.Fatal(err)
			}
			t.Logf("EXPLAIN %s: %s", query.name, raw)
			var plans []struct {
				Plan          planNode
				ExecutionTime float64 `json:"Execution Time"`
			}
			if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
				t.Fatalf("invalid EXPLAIN document: %v", err)
			}
			var maxLoops, factVisits float64
			var visit func(planNode)
			visit = func(node planNode) {
				maxLoops = max(maxLoops, node.ActualLoops)
				if node.RelationName == "vulnerability_facts" {
					factVisits += node.ActualRows * node.ActualLoops
					if node.ActualRows*node.ActualLoops > 1 {
						t.Errorf("%s visited unrelated CVEs: rows=%g loops=%g", node.NodeType, node.ActualRows, node.ActualLoops)
					}
				}
				for _, child := range node.Plans {
					visit(child)
				}
			}
			visit(plans[0].Plan)
			t.Logf("1000 CVEs: max_loops=%g fact_visits=%g execution_ms=%g", maxLoops, factVisits, plans[0].ExecutionTime)
			if maxLoops != 1 || factVisits == 0 {
				t.Fatalf("single-CVE selection must evaluate once: max_loops=%g fact_visits=%g", maxLoops, factVisits)
			}
		})
	}

	f.asset(uuid.NewString(), 1, "1.5")
	f.refresh()
	f.status("affected_version")
	var pairs int
	f.must(f.c.QueryRow(f.ctx, `SELECT count(*) FROM noctis_v2.applicability_current`).Scan(&pairs))
	if pairs != 1 {
		t.Fatalf("single-CVE refresh published %d pairs, want 1", pairs)
	}
}
