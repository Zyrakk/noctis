-- Existing timestamps cannot prove when an old source pause began. Preserve
-- only the remaining positive budget from this migration forward.
ALTER TABLE noctis_v2.jobs ADD COLUMN retry_deadline_at timestamptz;
ALTER TABLE noctis_v2.jobs ADD COLUMN source_paused_at timestamptz;
UPDATE noctis_v2.jobs SET retry_deadline_at=created_at+interval '24 hours';
UPDATE noctis_v2.jobs SET state='dependency_blocked',
 last_error_code='retry_horizon_unknown',lease_owner=NULL,lease_expires_at=NULL
 WHERE state IN ('queued','retry_wait','leased','dependency_blocked')
 AND last_error_code IN ('source_paused','source_resumed')
 AND retry_deadline_at<=transaction_timestamp();
UPDATE noctis_v2.jobs SET source_paused_at=transaction_timestamp()
 WHERE state='dependency_blocked' AND last_error_code='source_paused'
 AND retry_deadline_at>transaction_timestamp();
UPDATE noctis_v2.jobs SET last_error_code=NULL
 WHERE last_error_code='source_resumed'
 AND state IN ('queued','retry_wait','leased');
ALTER TABLE noctis_v2.jobs ALTER COLUMN retry_deadline_at SET NOT NULL;

-- A caller may supply created_at (imports/tests); derive the initial deadline
-- from that value rather than granting a fresh day from the INSERT time.
CREATE FUNCTION noctis_v2.initialize_job_retry_deadline() RETURNS trigger
 LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.retry_deadline_at IS NULL THEN
  NEW.retry_deadline_at := NEW.created_at+interval '24 hours';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER initialize_job_retry_deadline BEFORE INSERT ON noctis_v2.jobs
 FOR EACH ROW EXECUTE FUNCTION noctis_v2.initialize_job_retry_deadline();
