package runtimev2

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// This is an operational contract, not an inventory of a backup. Add required
// relations/operations here when extending a mode; regenerate the catalog
// manifest against ALL embedded migrations with TestReadinessContractPostgres.
// No DDL, ownership, superuser, or role-name requirement is inferred.
type readinessPrivilege struct {
	Tables, Privileges string
}

var readinessPrivileges = map[string][]readinessPrivilege{
	"api": {
		{"sessions", "SELECT,INSERT,UPDATE"}, // login, authentication, logout
		{"sources questions discovery_proposals discovery_trials", "SELECT,INSERT,UPDATE"},
		{"question_sources", "SELECT,INSERT,UPDATE,DELETE"}, // replace or remove current governance
		{"policies", "SELECT,INSERT"},
		{"operator_permissions action_receipts case_attention", "SELECT,INSERT,UPDATE"},
		{"runtime_control", "SELECT,UPDATE"},
		{"jobs observations checkpoints content_blobs", "SELECT,INSERT,UPDATE"}, // imports and source resume
		{"batch_receipts", "SELECT,INSERT"},
		{"source_imports source_dispositions legacy_records", "SELECT,INSERT"},
		{"legacy_records", "UPDATE"},
		{"intelligence_cases case_revisions case_changes briefs outbox", "SELECT,UPDATE"},
		{"case_revisions case_changes", "INSERT"},
		{"case_memberships entities", "SELECT"},
		{"claim_dependencies", "SELECT,INSERT"},
		{"claim_versions indicator_versions entity_hypotheses", "SELECT,INSERT,UPDATE"},
		{"entity_aliases", "SELECT,UPDATE"},
		{"asset_versions local_applicability", "SELECT,INSERT"},
		{"applicability_effective nvd_current_selection applicability_work_status", "SELECT"},
		{"applicability_requests", "SELECT,INSERT"}, // asset saves and evidence invalidation enqueue work
		{"feed_snapshots vulnerability_facts", "SELECT"},
		{"enrichment_policies", "SELECT,INSERT,UPDATE"},
		{"enrichment_policy_revisions domain_audit", "INSERT"},
		{"private_exports retention_policies retention_runs", "SELECT,INSERT,UPDATE"},
		{"retention_tombstones", "SELECT,INSERT"}, // immutable-product trigger reads tombstones
		{"invalidated_products", "SELECT"},
		{"analyses analysis_results observable_sightings", "SELECT,UPDATE"},
		{"ai_configs ai_secrets", "SELECT,INSERT"}, // configuration publishing
		{"ai_jobs ai_query_results", "SELECT,INSERT,UPDATE"},
		{"ai_attempts", "SELECT"},
		{"ai_products ai_promotions", "SELECT,UPDATE"},
		{"telegram_inbox telegram_inventory_snapshots", "SELECT"},
		{"telegram_accounts", "SELECT,UPDATE"}, // source binding locks accounts
		{"telegram_generation_transitions telegram_capture_budgets", "SELECT"},
		{"telegram_peers", "SELECT,INSERT,UPDATE"},
		{"telegram_inventory_candidates", "SELECT,UPDATE"},
		{"telegram_channel_states", "INSERT"},
	},
	"worker": {
		{"runtime_control", "SELECT,UPDATE"}, // applicability's FOR SHARE pause fence
		{"ai_configs ai_secrets", "SELECT"},
		{"sources observations", "SELECT,UPDATE"}, // publication fences use FOR SHARE
		{"content_blobs policies discovery_proposals question_sources questions", "SELECT"},
		{"jobs", "SELECT,INSERT,UPDATE"},
		{"analyses analysis_results case_memberships case_revisions case_changes observable_sightings", "SELECT,INSERT"},
		{"case_group_conflicts", "INSERT"},
		{"intelligence_cases outbox briefs", "SELECT,INSERT,UPDATE"},
		{"claim_dependencies claim_versions", "SELECT,INSERT"},
		{"entities", "INSERT"},
		{"entity_aliases", "SELECT,INSERT"},
		{"ai_jobs ai_attempts", "SELECT,INSERT,UPDATE"},
		{"ai_attempt_jobs", "SELECT,INSERT"},
		{"ai_products ai_publications", "INSERT"},
		{"feed_snapshots vulnerability_facts", "SELECT"},
		{"asset_versions", "SELECT,UPDATE"}, // pair evaluation locks the inventory revision
		{"local_applicability", "SELECT,INSERT"},
		{"applicability_current case_applicability_projection applicability_requests", "SELECT,INSERT,UPDATE"},
		{"applicability_transitions", "INSERT"},
		{"applicability_effective nvd_current_selection", "SELECT"},
	},
	"collector": {
		{"runtime_control ai_configs discovery_proposals question_sources questions", "SELECT"},
		{"sources", "SELECT,UPDATE"},
		{"checkpoints content_blobs observations", "SELECT,INSERT,UPDATE"},
		{"batch_receipts", "SELECT,INSERT"},
		{"jobs", "INSERT"},
		{"feed_snapshots vulnerability_facts", "SELECT,INSERT"},
		{"feed_cursors", "SELECT,INSERT,UPDATE"},
		{"applicability_requests", "SELECT,INSERT"}, // feed publication and evidence triggers
		{"applicability_work_status", "SELECT"},     // capture receipt reports durable calculation state
	},
}

// SQL helpers are executable dependencies of views and runtime queries, not
// just trigger implementations. Signatures keep overloaded functions explicit.
var readinessFunctions = map[string][]string{
	"api": {
		"noctis_v2.nvd_revision(text)",
		"noctis_v2.select_current_nvd(text)",
		"noctis_v2.applicability_evidence_current(jsonb)",
		"noctis_v2.case_applicability(uuid)",
		"noctis_v2.case_effective_body(uuid,jsonb)",
		"noctis_v2.change_effective_body(uuid,jsonb)",
		"noctis_v2.brief_applicability_current(jsonb)",
		"noctis_v2.enqueue_applicability(text,text,integer,text,timestamp with time zone,uuid)",
	},
	"worker": {
		"noctis_v2.nvd_revision(text)",
		"noctis_v2.select_current_nvd(text)",
		"noctis_v2.applicability_evidence_current(jsonb)",
		"noctis_v2.case_applicability(uuid)",
		"noctis_v2.case_effective_body(uuid,jsonb)",
		"noctis_v2.brief_applicability_current(jsonb)",
		"noctis_v2.enqueue_applicability(text,text,integer,text,timestamp with time zone,uuid)",
	},
	"collector": {
		"noctis_v2.enqueue_applicability(text,text,integer,text,timestamp with time zone,uuid)",
	},
}

func contractFunctions() []string {
	names := map[string]bool{}
	for _, functions := range readinessFunctions {
		for _, name := range functions {
			names[name] = true
		}
	}
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// Capture and operator changes invalidate dependent projections. These are
// permissions of that actual operation, not CRUD grants.
var projectionPrivileges = []readinessPrivilege{
	{"claim_versions intelligence_cases briefs outbox case_attention", "SELECT,UPDATE"},
	{"claim_dependencies case_memberships ai_products", "SELECT"},
	{"case_revisions case_changes", "SELECT,INSERT"},
	{"invalidated_products", "INSERT"},
}

func privilegesForMode(mode string) (tables, privileges []string) {
	pairs := map[string]bool{}
	requirements := append([]readinessPrivilege{}, readinessPrivileges[mode]...)
	if mode == "api" || mode == "collector" {
		requirements = append(requirements, projectionPrivileges...)
	}
	for _, r := range requirements {
		for _, table := range strings.Fields(r.Tables) {
			for _, privilege := range strings.Split(r.Privileges, ",") {
				pairs[table+":"+privilege] = true
			}
		}
	}
	keys := make([]string, 0, len(pairs))
	for key := range pairs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		pair := strings.Split(key, ":")
		tables = append(tables, pair[0])
		privileges = append(privileges, pair[1])
	}
	return
}

func contractRelations() []string {
	names := map[string]bool{}
	for mode := range readinessPrivileges {
		tables, _ := privilegesForMode(mode)
		for _, table := range tables {
			names[table] = true
		}
	}
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

//go:embed schema_contract.json
var readinessContractJSON []byte

type schemaContract map[string]json.RawMessage

// One grouped catalog read, independent of business-row counts and object
// ownership. Stable deparser output comes from pg_catalog-only search_path.
// Constraints include validated state, supporting index validity and the
// effective FK trigger state. Performance-only indexes are deliberately absent.
const readinessCatalogSQL = `
WITH relations AS (
 SELECT c.* FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='noctis_v2' AND c.relname=ANY($1::text[])
), function_oids AS (
 SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='noctis_v2' AND p.oid::regprocedure::text=ANY($2::text[])
 UNION
 SELECT t.tgfoid FROM relations r JOIN pg_trigger t ON t.tgrelid=r.oid WHERE NOT t.tgisinternal
), objects AS (
 SELECT 'relation:'||r.relname AS key,
 jsonb_build_object('kind',r.relkind,'persistence',r.relpersistence,'row_security',r.relrowsecurity) AS definition
 FROM relations r
 UNION ALL
 SELECT 'view:'||r.relname,
 jsonb_build_object('definition',pg_get_viewdef(r.oid,true),'options',r.reloptions)
 FROM relations r WHERE r.relkind='v'
 UNION ALL
 SELECT 'column:'||r.relname||'.'||a.attname,
 jsonb_build_object('type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,
 'default',pg_get_expr(d.adbin,d.adrelid),'identity',a.attidentity,'generated',a.attgenerated)
 FROM relations r JOIN pg_attribute a ON a.attrelid=r.oid
 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE a.attnum>0 AND NOT a.attisdropped
 UNION ALL
 SELECT 'constraint:'||r.relname||'.'||c.conname,
 jsonb_build_object('definition',pg_get_constraintdef(c.oid,true),'validated',c.convalidated,
 'index_valid',i.indisvalid,'index_ready',i.indisready,
 'fk_triggers_enabled',CASE WHEN c.contype='f' THEN
 (SELECT count(*)=4 AND bool_and(t.tgenabled IN ('O','A')) FROM pg_trigger t WHERE t.tgconstraint=c.oid) END)
 FROM relations r JOIN pg_constraint c ON c.conrelid=r.oid
 LEFT JOIN pg_index i ON i.indexrelid=c.conindid
 WHERE c.contype IN ('p','u','f','c','x')
 UNION ALL
 SELECT 'trigger:'||r.relname||'.'||t.tgname,
 jsonb_build_object('definition',pg_get_triggerdef(t.oid,true),'enabled',t.tgenabled IN ('O','A'))
 FROM relations r JOIN pg_trigger t ON t.tgrelid=r.oid WHERE NOT t.tgisinternal
 UNION ALL
 SELECT 'function:'||p.oid::regprocedure::text,
 jsonb_build_object('definition',pg_get_functiondef(p.oid))
 FROM function_oids f JOIN pg_proc p ON p.oid=f.oid
) SELECT key,definition FROM objects ORDER BY key`

func readSchemaContract(ctx context.Context, tx pgx.Tx) (schemaContract, error) {
	rows, err := tx.Query(ctx, readinessCatalogSQL, contractRelations(), contractFunctions())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	actual := schemaContract{}
	for rows.Next() {
		var key string
		var definition json.RawMessage
		if err = rows.Scan(&key, &definition); err != nil {
			return nil, err
		}
		actual[key] = definition
	}
	return actual, rows.Err()
}

func checkSchemaContract(ctx context.Context, tx pgx.Tx) error {
	var expected schemaContract
	if err := json.Unmarshal(readinessContractJSON, &expected); err != nil || len(expected) == 0 {
		return fmt.Errorf("v2 readiness contract unavailable")
	}
	actual, err := readSchemaContract(ctx, tx)
	if err != nil {
		return fmt.Errorf("v2 schema inspection unavailable")
	}
	for key, want := range expected {
		got, ok := actual[key]
		// JSONB returned by PostgreSQL has stable key ordering and whitespace;
		// compact both sides so the checked-in manifest remains readable.
		var w, g any
		if !ok || json.Unmarshal(want, &w) != nil || json.Unmarshal(got, &g) != nil {
			return fmt.Errorf("v2 schema contract incompatible: %s", key)
		}
		wb, _ := json.Marshal(w)
		gb, _ := json.Marshal(g)
		if string(wb) != string(gb) {
			return fmt.Errorf("v2 schema contract incompatible: %s", key)
		}
	}
	return nil
}

func checkRuntimePrivileges(ctx context.Context, tx pgx.Tx, mode string) error {
	tables, privileges := privilegesForMode(mode)
	var allowed bool
	err := tx.QueryRow(ctx, `SELECT
 has_schema_privilege(current_user,'noctis_v2','USAGE')
 AND has_schema_privilege(current_user,'public','USAGE')
 AND has_table_privilege(current_user,'public.noctis_v2_migrations','SELECT')
 AND current_setting('session_replication_role') IN ('origin','local')
 AND NOT EXISTS (
 SELECT FROM unnest($1::text[],$2::text[]) required(name,privilege)
 LEFT JOIN pg_namespace n ON n.nspname='noctis_v2'
 LEFT JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=required.name
 WHERE c.oid IS NULL OR NOT has_table_privilege(current_user,c.oid,required.privilege)
 )
 AND NOT EXISTS (
 SELECT FROM unnest($3::text[]) required(signature)
 LEFT JOIN pg_namespace n ON n.nspname='noctis_v2'
 LEFT JOIN pg_proc p ON p.pronamespace=n.oid AND p.oid::regprocedure::text=required.signature
 WHERE p.oid IS NULL OR NOT has_function_privilege(current_user,p.oid,'EXECUTE')
 )`, tables, privileges, readinessFunctions[mode]).Scan(&allowed)
	if err != nil || !allowed {
		return fmt.Errorf("v2 runtime privileges unavailable for mode %s", mode)
	}
	return nil
}
