-- Production consent is independent of the immutable v1 pilot budget.
CREATE TABLE noctis_v2.telegram_capture_consents(
 id uuid PRIMARY KEY, account_id text NOT NULL REFERENCES noctis_v2.telegram_accounts(id),
 auth_generation uuid NOT NULL, predecessor uuid REFERENCES noctis_v2.telegram_capture_consents(id),
 revision bigint NOT NULL, policy_digest text NOT NULL, policy jsonb NOT NULL,
 expires_at timestamptz NOT NULL, actor text NOT NULL, reason text NOT NULL,
 revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(account_id,revision)
);
ALTER TABLE noctis_v2.telegram_accounts ADD COLUMN active_capture_consent uuid REFERENCES noctis_v2.telegram_capture_consents(id), ADD COLUMN consent_revision bigint NOT NULL DEFAULT 0, ADD COLUMN quota_wait_until timestamptz, ADD COLUMN quota_wait_reason text;
ALTER TABLE noctis_v2.telegram_accounts ADD COLUMN capture_failure_revision bigint NOT NULL DEFAULT 0, ADD COLUMN capture_resume_revision bigint NOT NULL DEFAULT 0, ADD CONSTRAINT capture_failure_revision_order CHECK(capture_resume_revision<=capture_failure_revision);
CREATE TABLE noctis_v2.telegram_capture_failures(
 account_id text NOT NULL REFERENCES noctis_v2.telegram_accounts(id),revision bigint NOT NULL,
 auth_generation uuid NOT NULL,consent_id uuid NOT NULL REFERENCES noctis_v2.telegram_capture_consents(id),
 reason text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(account_id,revision)
);
CREATE TABLE noctis_v2.telegram_capture_resumes(
 account_id text NOT NULL, failure_revision bigint NOT NULL,auth_generation uuid NOT NULL,
 consent_id uuid NOT NULL REFERENCES noctis_v2.telegram_capture_consents(id),actor text NOT NULL,reason text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(account_id,failure_revision),
 FOREIGN KEY(account_id,failure_revision) REFERENCES noctis_v2.telegram_capture_failures(account_id,revision)
);
CREATE FUNCTION noctis_v2.capture_audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable capture failure/resume audit'; END $$;
CREATE TRIGGER capture_failure_audit_immutable BEFORE UPDATE OR DELETE ON noctis_v2.telegram_capture_failures FOR EACH ROW EXECUTE FUNCTION noctis_v2.capture_audit_immutable();
CREATE TRIGGER capture_resume_audit_immutable BEFORE UPDATE OR DELETE ON noctis_v2.telegram_capture_resumes FOR EACH ROW EXECUTE FUNCTION noctis_v2.capture_audit_immutable();
CREATE TABLE noctis_v2.telegram_capture_usage(
 account_id text NOT NULL REFERENCES noctis_v2.telegram_accounts(id), auth_generation uuid NOT NULL,
 period_start timestamptz NOT NULL, counters jsonb NOT NULL,
 PRIMARY KEY(account_id,auth_generation,period_start)
);
CREATE FUNCTION noctis_v2.production_consent_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-'revoked_at')<>(to_jsonb(OLD)-'revoked_at') OR OLD.revoked_at IS NOT NULL THEN RAISE EXCEPTION 'immutable production consent'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER production_consent_immutable BEFORE UPDATE OR DELETE ON noctis_v2.telegram_capture_consents FOR EACH ROW EXECUTE FUNCTION noctis_v2.production_consent_immutable();
CREATE FUNCTION noctis_v2.production_usage_monotonic() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE phase text; counter text;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable production usage'; END IF;
 IF TG_OP='UPDATE' AND (NEW.account_id,NEW.auth_generation,NEW.period_start) IS DISTINCT FROM (OLD.account_id,OLD.auth_generation,OLD.period_start) THEN RAISE EXCEPTION 'immutable production usage key'; END IF;
 IF jsonb_typeof(NEW.counters)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(NEW.counters))<>3 THEN RAISE EXCEPTION 'invalid production counters'; END IF;
 FOREACH phase IN ARRAY ARRAY['control','bootstrap','live'] LOOP
  IF jsonb_typeof(NEW.counters->phase)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(NEW.counters->phase))<>4 THEN RAISE EXCEPTION 'invalid production phase'; END IF;
  FOREACH counter IN ARRAY ARRAY['api','observations','payload_bytes','metadata_bytes'] LOOP
   IF jsonb_typeof(NEW.counters->phase->counter)<>'number' OR NOT COALESCE((NEW.counters->phase->>counter) ~ '^[0-9]+$',false) THEN RAISE EXCEPTION 'invalid production counter'; END IF;
   PERFORM (NEW.counters->phase->>counter)::bigint;
   IF TG_OP='UPDATE' AND (NEW.counters->phase->>counter)::bigint<(OLD.counters->phase->>counter)::bigint THEN RAISE EXCEPTION 'production usage cannot decrease'; END IF;
  END LOOP;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER production_usage_monotonic BEFORE INSERT OR UPDATE OR DELETE ON noctis_v2.telegram_capture_usage FOR EACH ROW EXECUTE FUNCTION noctis_v2.production_usage_monotonic();
-- Access hashes remain private and never appear in product responses.
CREATE TABLE noctis_v2.telegram_inventory_snapshots(
 id uuid PRIMARY KEY, account_id text NOT NULL REFERENCES noctis_v2.telegram_accounts(id), auth_generation uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), actor text NOT NULL
);
CREATE TABLE noctis_v2.telegram_inventory_candidates(
 snapshot_id uuid NOT NULL REFERENCES noctis_v2.telegram_inventory_snapshots(id), peer_type text NOT NULL CHECK(peer_type='channel'),
 peer_id bigint NOT NULL CHECK(peer_id>0), name text NOT NULL, access_hash bigint NOT NULL, folder integer NOT NULL,
 pts integer NOT NULL CHECK(pts>=0), source_id uuid REFERENCES noctis_v2.sources(id), PRIMARY KEY(snapshot_id,peer_type,peer_id)
);
ALTER TABLE noctis_v2.telegram_peers ADD COLUMN inventory_snapshot uuid REFERENCES noctis_v2.telegram_inventory_snapshots(id);
