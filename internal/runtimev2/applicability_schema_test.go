package runtimev2

import (
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/vulnv2"
	"github.com/google/uuid"
)

func TestApplicabilityTransitionsSequenceFreePostgres(t *testing.T) {
	f := newApplicabilityFixture(t)
	// The logical backup shares an MVCC snapshot and deliberately rejects
	// sequences, whose mutable state is not part of that snapshot.
	var sequences int
	f.must(f.c.QueryRow(f.ctx, `SELECT count(*) FROM pg_sequences WHERE schemaname NOT IN ('pg_catalog','information_schema')`).Scan(&sequences))
	if sequences != 0 {
		t.Errorf("migrated schema contains %d sequences; logical backup requires none", sequences)
	}
	f.exec(`REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA noctis_v2 FROM PUBLIC`)
	runtimeDSN, _ := readinessRole(t, f.c, f.dsn, "worker", true)
	login := readinessConnection(t, runtimeDSN)
	var privileged bool
	f.must(login.QueryRow(f.ctx, `SELECT rolsuper OR rolcreatedb OR rolcreaterole OR has_schema_privilege(current_user,'noctis_v2','CREATE') FROM pg_roles WHERE rolname=current_user`).Scan(&privileged))
	if privileged {
		t.Fatal("fixture worker LOGIN has administrative or schema creation privileges")
	}

	asset := uuid.NewString()
	f.feed("2026-01-02T00:00:00Z", f.now, f.now.Add(time.Hour), "2.0")
	for i, version := range []string{"1.5", "3.0"} {
		f.asset(asset, i+1, version)
		tx, err := login.Begin(f.ctx)
		f.must(err)
		defer tx.Rollback(f.ctx)
		applied, err := vulnv2.EvaluateCurrentPairTx(f.ctx, tx, "CVE-2026-12345", asset, "", 0)
		f.must(err)
		if !applied {
			t.Fatal("restricted worker did not publish the current pair")
		}
		f.must(tx.Commit(f.ctx))
	}

	rows, err := f.c.Query(f.ctx, `SELECT id::text,status FROM noctis_v2.applicability_transitions WHERE asset_id=$1`, asset)
	f.must(err)
	defer rows.Close()
	ids := map[uuid.UUID]bool{}
	statuses := map[string]bool{}
	for rows.Next() {
		var raw, status string
		f.must(rows.Scan(&raw, &status))
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || ids[id] {
			t.Fatalf("transition default did not generate a distinct UUID: %q (%v)", raw, err)
		}
		ids[id], statuses[status] = true, true
	}
	f.must(rows.Err())
	if len(ids) != 2 || !statuses["affected_version"] || !statuses["not_affected_version"] {
		t.Fatalf("restricted transitions were not preserved: ids=%d statuses=%v", len(ids), statuses)
	}
}
