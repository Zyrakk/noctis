CREATE SCHEMA noctis_v2;
CREATE TABLE noctis_v2.sources (
 id uuid PRIMARY KEY, kind text NOT NULL, native_id text NOT NULL,
 enabled boolean NOT NULL DEFAULT false, policy_version text NOT NULL,
 UNIQUE(kind,native_id)
);
CREATE TABLE noctis_v2.checkpoints (
 source_id uuid NOT NULL REFERENCES noctis_v2.sources(id), epoch uuid NOT NULL,
 mode text NOT NULL CHECK(mode IN ('live','bootstrap','legacy_import')),
 version bigint NOT NULL CHECK(version>=0), value jsonb NOT NULL,
 PRIMARY KEY(source_id,epoch,mode)
);
CREATE TABLE noctis_v2.content_blobs (
 hash text NOT NULL, representation text NOT NULL, payload bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(hash,representation)
);
CREATE TABLE noctis_v2.observations (
 id uuid PRIMARY KEY, source_id uuid NOT NULL REFERENCES noctis_v2.sources(id),
 native_id text NOT NULL, revision text NOT NULL, hash text NOT NULL,
 representation text NOT NULL, epoch uuid NOT NULL,
 mode text NOT NULL CHECK(mode IN ('live','bootstrap','legacy_import')),
 published_at timestamptz, collected_at timestamptz NOT NULL,
 FOREIGN KEY(hash,representation) REFERENCES noctis_v2.content_blobs(hash,representation),
 UNIQUE(source_id,native_id,revision)
);
CREATE TABLE noctis_v2.jobs (
 id uuid PRIMARY KEY, stage text NOT NULL, input_id uuid NOT NULL,
 input_revision text NOT NULL, policy_version text NOT NULL, schema_version text NOT NULL,
 state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','leased','succeeded','retry_wait','budget_blocked','dependency_blocked','quarantined','cancelled')),
 lease_owner text, lease_expires_at timestamptz, fence bigint NOT NULL DEFAULT 0,
 retry_at timestamptz, attempts integer NOT NULL DEFAULT 0, last_error_code text,
 UNIQUE(stage,input_id,input_revision,policy_version,schema_version),
 CHECK((state='leased')=(lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL))
);
