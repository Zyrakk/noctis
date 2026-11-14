-- Durable, bounded applicability traversals. Inputs and requests commit together;
-- bounds are captured by the first worker page, after the input has committed.
CREATE TABLE noctis_v2.applicability_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 idempotency_key text NOT NULL UNIQUE,
 scope text NOT NULL CHECK(scope IN ('asset','cve','case','evidence')),
 input_id text NOT NULL,
 input_revision integer NOT NULL DEFAULT 0,
 calculation_version text NOT NULL DEFAULT 'applicability-v2',
 parent_id uuid REFERENCES noctis_v2.applicability_requests(id),
 due_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','complete')),
 phase text NOT NULL DEFAULT 'start' CHECK(phase IN ('start','pairs','children','cases','done')),
 page bigint NOT NULL DEFAULT 0,
 cursor text NOT NULL DEFAULT '',
 upper_bound text NOT NULL DEFAULT '',
 case_upper_bound text NOT NULL DEFAULT '',
 pairs_processed bigint NOT NULL DEFAULT 0,
 cases_processed bigint NOT NULL DEFAULT 0,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX applicability_due ON noctis_v2.applicability_requests(due_at,id) WHERE state='pending';
CREATE INDEX applicability_request_input ON noctis_v2.applicability_requests(scope,input_id,input_revision);
CREATE INDEX applicability_request_children ON noctis_v2.applicability_requests(parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX applicability_jobs ON noctis_v2.jobs(input_id,input_revision) WHERE stage='applicability';
CREATE INDEX applicability_asset_cursor ON noctis_v2.asset_versions((id::text),revision DESC);
CREATE INDEX applicability_case_cursor ON noctis_v2.intelligence_cases((id::text));
CREATE INDEX applicability_membership_observation ON noctis_v2.case_memberships(observation_id,case_id);

CREATE FUNCTION noctis_v2.enqueue_applicability(p_scope text,p_input text,p_revision integer,p_key text,p_due timestamptz DEFAULT clock_timestamp(),p_parent uuid DEFAULT NULL) RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE request_id uuid;
BEGIN
 INSERT INTO noctis_v2.applicability_requests(scope,input_id,input_revision,idempotency_key,due_at,parent_id)
 VALUES(p_scope,p_input,p_revision,p_key,p_due,p_parent)
 ON CONFLICT(idempotency_key) DO NOTHING RETURNING id INTO request_id;
 IF request_id IS NULL THEN
  SELECT id INTO request_id FROM noctis_v2.applicability_requests WHERE idempotency_key=p_key;
 ELSIF p_due<=clock_timestamp() THEN
  INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version)
  VALUES(gen_random_uuid(),'applicability',request_id,'0','applicability-v2','1');
 END IF;
 RETURN request_id;
END $$;

-- Recovery uses the existing jobs replay command. A quarantined page remains
-- visible as failed; replay keeps its request cursor and creates no duplicate page.
CREATE VIEW noctis_v2.applicability_work_status AS
SELECT r.*,r.id::text AS generation,
 CASE WHEN j.state IN ('quarantined','cancelled','dependency_blocked','budget_blocked')
       OR failed_child.id IS NOT NULL THEN 'failed'
      WHEN r.state='complete' AND NOT EXISTS(SELECT FROM noctis_v2.applicability_requests child WHERE child.parent_id=r.id AND child.state<>'complete') THEN 'complete'
      ELSE 'pending' END AS calculation_state,
 COALESCE(failed_child.id,j.id) AS job_id,COALESCE(failed_child.state,j.state) AS job_state,
 COALESCE(failed_child.attempts,j.attempts) AS attempts,COALESCE(failed_child.last_error_code,j.last_error_code) AS last_error_code
FROM noctis_v2.applicability_requests r
LEFT JOIN noctis_v2.jobs j ON j.stage='applicability' AND j.input_id=r.id AND j.input_revision=r.page::text AND j.policy_version=r.calculation_version AND j.schema_version='1'
LEFT JOIN LATERAL(
 SELECT cj.id,cj.state,cj.attempts,cj.last_error_code
 FROM noctis_v2.applicability_requests child JOIN noctis_v2.jobs cj ON cj.stage='applicability' AND cj.input_id=child.id AND cj.input_revision=child.page::text
 WHERE child.parent_id=r.id AND cj.state IN ('quarantined','cancelled','dependency_blocked','budget_blocked')
 ORDER BY cj.id LIMIT 1
) failed_child ON true;

CREATE FUNCTION noctis_v2.queue_applicability_membership() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE row_case uuid;
BEGIN
 row_case := CASE WHEN TG_OP='DELETE' THEN OLD.case_id ELSE NEW.case_id END;
 PERFORM noctis_v2.enqueue_applicability('case',row_case::text,0,'membership:'||row_case||':'||txid_current()::text);
 RETURN NULL;
END $$;
CREATE TRIGGER applicability_membership AFTER INSERT OR DELETE ON noctis_v2.case_memberships FOR EACH ROW EXECUTE FUNCTION noctis_v2.queue_applicability_membership();

CREATE FUNCTION noctis_v2.queue_applicability_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE observation_id uuid;
BEGIN
 IF TG_TABLE_NAME='observations' THEN observation_id:=NEW.id; ELSE observation_id:=NEW.observation_id; END IF;
 PERFORM noctis_v2.enqueue_applicability('evidence',observation_id::text,0,'evidence:'||observation_id||':'||txid_current()::text);
 RETURN NULL;
END $$;
CREATE TRIGGER applicability_evidence AFTER UPDATE OF source_deleted,superseded_by,retention_expired_at ON noctis_v2.observations FOR EACH ROW WHEN (OLD.source_deleted IS DISTINCT FROM NEW.source_deleted OR OLD.superseded_by IS DISTINCT FROM NEW.superseded_by OR OLD.retention_expired_at IS DISTINCT FROM NEW.retention_expired_at) EXECUTE FUNCTION noctis_v2.queue_applicability_evidence();
CREATE TRIGGER applicability_sighting AFTER INSERT ON noctis_v2.observable_sightings FOR EACH ROW WHEN (NEW.observable_type='cve') EXECUTE FUNCTION noctis_v2.queue_applicability_evidence();

-- Upgrade existing inventory without materializing the Cartesian product.
SELECT noctis_v2.enqueue_applicability('asset',id::text,revision,'asset:'||id||':'||revision::text)
FROM (SELECT DISTINCT ON(id) id,revision FROM noctis_v2.asset_versions ORDER BY id,revision DESC)a;
SELECT noctis_v2.enqueue_applicability('cve',cve,0,'expiry:'||snapshot_id||':'||cve,expires_at)
FROM noctis_v2.nvd_current_selection;
