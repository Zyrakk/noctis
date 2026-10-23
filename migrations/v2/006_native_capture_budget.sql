-- Native capture is opt-in. No existing account receives a budget implicitly.
CREATE TABLE noctis_v2.telegram_capture_budgets(
 id uuid PRIMARY KEY,
 account_id text NOT NULL UNIQUE REFERENCES noctis_v2.telegram_accounts(id),
 auth_generation uuid NOT NULL,
 policy_digest text NOT NULL CHECK(policy_digest ~ '^[0-9a-f]{64}$'),
 policy jsonb NOT NULL,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL,
 state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','exhausted','revoked')),
 counters jsonb NOT NULL DEFAULT '{"control":{"api":0,"observations":0,"payload_bytes":0,"metadata_bytes":0},"bootstrap":{"api":0,"observations":0,"payload_bytes":0,"metadata_bytes":0},"live":{"api":0,"observations":0,"payload_bytes":0,"metadata_bytes":0}}',
 CHECK(expires_at>started_at)
);
ALTER TABLE noctis_v2.telegram_accounts ADD COLUMN active_capture_budget uuid REFERENCES noctis_v2.telegram_capture_budgets(id);
CREATE FUNCTION noctis_v2.native_budget_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE phase text; counter text;
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable native budget'; END IF;
 IF TG_OP='UPDATE' AND (to_jsonb(NEW)-'counters'-'state')<>(to_jsonb(OLD)-'counters'-'state') THEN RAISE EXCEPTION 'immutable native budget policy'; END IF;
 IF TG_OP='UPDATE' AND OLD.state<>'active' AND NEW.state<>OLD.state THEN RAISE EXCEPTION 'terminal native budget'; END IF;
 IF jsonb_typeof(NEW.counters)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(NEW.counters))<>3 THEN RAISE EXCEPTION 'invalid native counters'; END IF;
 FOREACH phase IN ARRAY ARRAY['control','bootstrap','live'] LOOP
  IF jsonb_typeof(NEW.counters->phase)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(NEW.counters->phase))<>4 THEN RAISE EXCEPTION 'invalid native phase'; END IF;
  FOREACH counter IN ARRAY ARRAY['api','observations','payload_bytes','metadata_bytes'] LOOP
   IF jsonb_typeof(NEW.counters->phase->counter)<>'number' OR NOT COALESCE((NEW.counters->phase->>counter) ~ '^[0-9]+$',false) THEN RAISE EXCEPTION 'invalid native counter'; END IF;
   PERFORM (NEW.counters->phase->>counter)::bigint;
   IF TG_OP='UPDATE' AND (NEW.counters->phase->>counter)::bigint<(OLD.counters->phase->>counter)::bigint THEN RAISE EXCEPTION 'native counter cannot decrease'; END IF;
  END LOOP;
 END LOOP;
 RETURN NEW;
END$$;
CREATE TRIGGER native_budget_immutable BEFORE INSERT OR UPDATE OR DELETE ON noctis_v2.telegram_capture_budgets FOR EACH ROW EXECUTE FUNCTION noctis_v2.native_budget_immutable();
CREATE FUNCTION noctis_v2.native_budget_binding() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN
 IF OLD.active_capture_budget IS NOT NULL AND NEW.active_capture_budget IS DISTINCT FROM OLD.active_capture_budget THEN RAISE EXCEPTION 'immutable native budget binding'; END IF;
 IF NEW.active_capture_budget IS NOT NULL AND NOT EXISTS(SELECT FROM noctis_v2.telegram_capture_budgets b WHERE b.id=NEW.active_capture_budget AND b.account_id=NEW.id AND b.auth_generation=NEW.auth_generation) THEN RAISE EXCEPTION 'native budget account generation mismatch'; END IF;
 RETURN NEW;
END$$;
CREATE TRIGGER native_budget_binding BEFORE UPDATE ON noctis_v2.telegram_accounts FOR EACH ROW EXECUTE FUNCTION noctis_v2.native_budget_binding();
