-- A prepared authentication is not permission to capture with a new key.
ALTER TABLE noctis_v2.telegram_accounts
 ADD COLUMN authentication_in_progress boolean NOT NULL DEFAULT false,
 ADD COLUMN prepared_auth_generation uuid;
CREATE TABLE noctis_v2.telegram_generation_transitions(
 id uuid PRIMARY KEY, account_id text NOT NULL REFERENCES noctis_v2.telegram_accounts(id),
 from_generation uuid NOT NULL, consent_generation uuid NOT NULL, to_generation uuid NOT NULL,
 consent_id uuid NOT NULL REFERENCES noctis_v2.telegram_capture_consents(id),
 consent_revision bigint NOT NULL, owner_fence bigint NOT NULL,
 actor text NOT NULL, reason text NOT NULL, request_digest text NOT NULL,
 capture_not_before timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(account_id,consent_revision), CHECK(consent_generation<>to_generation)
);
CREATE TRIGGER generation_transition_immutable BEFORE UPDATE OR DELETE ON noctis_v2.telegram_generation_transitions FOR EACH ROW EXECUTE FUNCTION noctis_v2.capture_audit_immutable();
ALTER TABLE noctis_v2.telegram_accounts ADD COLUMN pending_generation_transition uuid REFERENCES noctis_v2.telegram_generation_transitions(id);
