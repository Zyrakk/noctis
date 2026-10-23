ALTER TABLE noctis_v2.ai_attempts ADD COLUMN accounting_exception text;
ALTER TABLE noctis_v2.intelligence_cases ADD COLUMN lifecycle text NOT NULL DEFAULT 'following' CHECK(lifecycle IN('following','resolved','archived'));
CREATE TABLE noctis_v2.case_attention(case_id uuid PRIMARY KEY REFERENCES noctis_v2.intelligence_cases(id), revision bigint NOT NULL DEFAULT 1,seen_revision bigint NOT NULL DEFAULT 0,mode text NOT NULL DEFAULT 'automatic' CHECK(mode IN('automatic','silent_until_change','exception')),reason text NOT NULL DEFAULT '',silent_until timestamptz,exception jsonb,policy_version text NOT NULL DEFAULT 'attention-v1');
CREATE TABLE noctis_v2.action_receipts(actor text NOT NULL,request_id text NOT NULL,action text NOT NULL,digest text NOT NULL,result jsonb NOT NULL,PRIMARY KEY(actor,request_id));
CREATE TABLE noctis_v2.operator_permissions(actor text NOT NULL,permission text NOT NULL,granted boolean NOT NULL DEFAULT false,PRIMARY KEY(actor,permission));
CREATE TABLE noctis_v2.private_exports(id uuid PRIMARY KEY,actor text NOT NULL,case_id uuid NOT NULL,revision bigint NOT NULL,expires_at timestamptz NOT NULL,body jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE noctis_v2.questions(id uuid PRIMARY KEY,title text NOT NULL,terms jsonb NOT NULL DEFAULT '[]',enabled boolean NOT NULL DEFAULT true);
ALTER TABLE noctis_v2.questions ADD COLUMN revision bigint NOT NULL DEFAULT 1;
CREATE TABLE noctis_v2.question_sources(question_id uuid NOT NULL REFERENCES noctis_v2.questions(id),source_id uuid NOT NULL REFERENCES noctis_v2.sources(id),independence text NOT NULL DEFAULT 'unknown',PRIMARY KEY(question_id,source_id));
CREATE TABLE noctis_v2.discovery_proposals(id uuid PRIMARY KEY,revision bigint NOT NULL DEFAULT 1,question_id uuid NOT NULL REFERENCES noctis_v2.questions(id),kind text NOT NULL,endpoint text NOT NULL,provenance jsonb NOT NULL,reason text NOT NULL,score jsonb NOT NULL,expires_at timestamptz NOT NULL,permission_status text NOT NULL DEFAULT 'proposed' CHECK(permission_status IN('proposed','authorized','revoked')),policy jsonb NOT NULL DEFAULT '{}',source_id uuid REFERENCES noctis_v2.sources(id));
CREATE TABLE noctis_v2.discovery_trials(id uuid PRIMARY KEY,proposal_id uuid NOT NULL REFERENCES noctis_v2.discovery_proposals(id),proposal_revision bigint NOT NULL,expires_at timestamptz NOT NULL,quota integer NOT NULL CHECK(quota BETWEEN 1 AND 100),used integer NOT NULL DEFAULT 0,state text NOT NULL DEFAULT 'active',last_success_at timestamptz,last_error text,coverage text NOT NULL DEFAULT 'unknown',created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE noctis_v2.runtime_control(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),paused boolean NOT NULL DEFAULT false,revision bigint NOT NULL DEFAULT 1,reason text NOT NULL DEFAULT '');
INSERT INTO noctis_v2.runtime_control(singleton) VALUES(true);
ALTER TABLE noctis_v2.sources ADD COLUMN adapter_config jsonb NOT NULL DEFAULT '{}';
ALTER TABLE noctis_v2.sources ADD COLUMN policy_revision bigint NOT NULL DEFAULT 1;
ALTER TABLE noctis_v2.observations ADD COLUMN data_class text NOT NULL DEFAULT 'private',ADD COLUMN retention_expired_at timestamptz;
CREATE TABLE noctis_v2.retention_policies(source_id uuid NOT NULL REFERENCES noctis_v2.sources(id),data_class text NOT NULL,retain_seconds bigint NOT NULL CHECK(retain_seconds>=0),revision bigint NOT NULL DEFAULT 1,PRIMARY KEY(source_id,data_class));
CREATE TABLE noctis_v2.retention_runs(id uuid PRIMARY KEY,source_id uuid NOT NULL,data_class text NOT NULL,policy_revision bigint NOT NULL,cutoff timestamptz NOT NULL,state text NOT NULL DEFAULT 'active',processed bigint NOT NULL DEFAULT 0,created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE noctis_v2.retention_tombstones(observation_id uuid PRIMARY KEY,source_id uuid NOT NULL,hash text NOT NULL,representation text NOT NULL,run_id uuid NOT NULL REFERENCES noctis_v2.retention_runs(id),expired_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE noctis_v2.invalidated_products(job_id uuid PRIMARY KEY REFERENCES noctis_v2.ai_jobs(id),reason text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp());
-- The sole immutable-product exception is destructive retention redaction,
-- tied to already committed-in-transaction tombstones. No replacement result.
CREATE OR REPLACE FUNCTION noctis_v2.ai_immutable_revision() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF TG_TABLE_NAME='ai_products' AND TG_OP='UPDATE' THEN
  IF NEW.result='{}'::jsonb AND NEW.dependencies='{}'::jsonb AND (to_jsonb(NEW)-'result'-'dependencies')=(to_jsonb(OLD)-'result'-'dependencies') AND (EXISTS(SELECT FROM noctis_v2.retention_tombstones t WHERE OLD.dependencies::text LIKE '%'||t.observation_id::text||'%') OR EXISTS(SELECT FROM noctis_v2.invalidated_products p WHERE p.job_id=OLD.job_id AND p.reason='retention_expired')) THEN RETURN NEW; END IF;
 END IF;
 RAISE EXCEPTION 'immutable AI revision';
END$$;
