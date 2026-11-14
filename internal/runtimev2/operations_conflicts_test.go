package runtimev2

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestOperationalPolicyReadsAndCASPostgresHTTPS(t *testing.T) {
	f := newAIFixture(t)
	call := operationsClient(t, f)
	ctx := context.Background()
	path := "retention?source_id=" + f.source + "&data_class=private"
	assertCode := func(body map[string]any, code string) {
		t.Helper()
		if body["error"].(map[string]any)["code"] != code {
			t.Fatal(body)
		}
	}
	assertCode(call("GET", path, nil, 403), "permission_retention_required")
	call("POST", "permissions", map[string]any{"permission": "retention", "granted": true}, 200)
	for _, suffix := range []string{"", "?source_id=invalid&data_class=private", "?source_id=" + f.source, "?source_id=" + f.source + "&data_class=%20", "?source_id=" + f.source + "&data_class=" + strings.Repeat("x", 65)} {
		call("GET", "retention"+suffix, nil, 400)
	}
	call("GET", "retention?source_id="+uuid.NewString()+"&data_class=private", nil, 404)
	var before, after int
	countWrites := func(target *int) {
		t.Helper()
		if e := f.conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.action_receipts)+(SELECT count(*) FROM noctis_v2.retention_policies)+(SELECT count(*) FROM noctis_v2.retention_runs)`).Scan(target); e != nil {
			t.Fatal(e)
		}
	}
	countWrites(&before)
	absent := call("GET", path, nil, 200)["data"].(map[string]any)
	if absent["present"] != false || absent["revision"] != float64(0) || absent["retain_seconds"] != nil || absent["source_id"] != f.source || absent["data_class"] != "private" {
		t.Fatal(absent)
	}
	countWrites(&after)
	if after != before {
		t.Fatal("absent read created state", before, after)
	}
	policy := func(revision int, seconds int) map[string]any {
		return map[string]any{"source_id": f.source, "data_class": "private", "action": "policy", "expected_revision": revision, "retain_seconds": seconds}
	}
	call("POST", "retention", policy(0, 3600), 200)
	present := call("GET", path, nil, 200)["data"].(map[string]any)
	if present["present"] != true || present["revision"] != float64(1) || present["retain_seconds"] != float64(3600) {
		t.Fatal(present)
	}
	assertCode(call("POST", "retention", policy(0, 7200), 409), "stale_revision")
	call("POST", "retention", policy(1, 7200), 200)
	assertCode(call("POST", "retention", policy(1, 1800), 409), "stale_revision")
	countWrites(&before)
	call("GET", path, nil, 200)
	countWrites(&after)
	if after != before {
		t.Fatal("present read created state", before, after)
	}
	if _, e := f.conn.Exec(ctx, `ALTER TABLE noctis_v2.retention_policies RENAME TO retention_policies_unavailable`); e != nil {
		t.Fatal(e)
	}
	assertCode(call("GET", path, nil, 503), "operation_unavailable")
	if _, e := f.conn.Exec(ctx, `ALTER TABLE noctis_v2.retention_policies_unavailable RENAME TO retention_policies`); e != nil {
		t.Fatal(e)
	}
	var sourceRevision int64
	if e := f.conn.QueryRow(ctx, `SELECT policy_revision FROM noctis_v2.sources WHERE id=$1`, f.source).Scan(&sourceRevision); e != nil {
		t.Fatal(e)
	}
	sourcePath := "sources/" + f.source + "/policy"
	for i := 0; i < 2; i++ {
		body := map[string]any{"expected_revision": sourceRevision, "enabled": false, "policy_version": "p1"}
		saved := call("POST", sourcePath, body, 200)["data"].(map[string]any)
		sourceRevision++
		if saved["policy_revision"] != float64(sourceRevision) {
			t.Fatal("missing confirmed source revision", saved)
		}
		delete(body, "request_id")
		assertCode(call("POST", sourcePath, body, 409), "stale_revision")
	}
	control := call("GET", "runtime-control", nil, 200)["data"].(map[string]any)
	call("POST", "runtime-control", map[string]any{"expected_revision": control["revision"], "action": "pause", "reason": "synthetic CAS"}, 200)
	assertCode(call("POST", "runtime-control", map[string]any{"expected_revision": control["revision"], "action": "resume", "reason": "synthetic CAS"}, 409), "stale_revision")
	call("POST", "permissions", map[string]any{"permission": "retention", "granted": false}, 200)
	assertCode(call("GET", path, nil, 403), "permission_retention_required")
	if _, e := f.conn.Exec(ctx, `UPDATE noctis_v2.sessions SET revoked=true`); e != nil {
		t.Fatal(e)
	}
	assertCode(call("GET", path, nil, 401), "authentication_required")
	t.Log(fmt.Sprintf("read-only retention and three CAS contracts verified for synthetic source %s", f.source))
}
