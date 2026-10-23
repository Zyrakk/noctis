-- Template: run explicitly as owner ONLY in a new, isolated noctis_v2 DB,
-- after the separate migration job succeeds. No passwords or legacy grants.
\set ON_ERROR_STOP on
DO $$ BEGIN
 IF current_database() <> 'noctis_v2' THEN RAISE EXCEPTION 'independent noctis_v2 DB required'; END IF;
 IF to_regclass('public.noctis_v2_migrations') IS NULL THEN RAISE EXCEPTION 'migrate explicitly first'; END IF;
END $$;
CREATE ROLE noctis_v2_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE noctis_v2_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE noctis_v2_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE noctis_v2_collector LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE ROLE noctis_v2_telegram LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA noctis_v2 TO noctis_v2_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA noctis_v2 TO noctis_v2_runtime;
GRANT SELECT ON public.noctis_v2_migrations TO noctis_v2_runtime;
GRANT noctis_v2_runtime TO noctis_v2_api,noctis_v2_worker,noctis_v2_collector,noctis_v2_telegram;
-- Authentication is provisioned privately by the operator; these roles own no
-- objects. Re-run grants explicitly after each additive migration creates tables.
