-- Historical calculations remain immutable. Current projections are disposable.
CREATE FUNCTION noctis_v2.nvd_revision(value text) RETURNS timestamptz
LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  IF value IS NULL OR value !~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$' THEN RETURN NULL; END IF;
  RETURN (CASE WHEN value ~ '(Z|[+-]\d{2}:\d{2})$' THEN value ELSE value||'Z' END)::timestamptz;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;

CREATE FUNCTION noctis_v2.select_current_nvd(requested_cve text)
RETURNS TABLE(cve text,snapshot_id uuid,body jsonb,nvd_revision timestamptz,expires_at timestamptz,selection_reason text,generation text)
LANGUAGE sql STABLE AS $$
WITH raw_records AS (
  SELECT f.cve,f.snapshot_id,f.body,s.as_of,s.expires_at,
    noctis_v2.nvd_revision(f.body->>'lastModified') AS nvd_revision
  FROM noctis_v2.vulnerability_facts f JOIN noctis_v2.feed_snapshots s ON s.id=f.snapshot_id WHERE s.kind='nvd' AND f.cve=requested_cve
), records AS (
  SELECT *,CASE WHEN nvd_revision IS NULL THEN body ELSE (body-'lastModified')||jsonb_build_object('lastModified',nvd_revision) END AS semantic_body FROM raw_records
), ranked AS (
  SELECT *,max(nvd_revision) OVER(PARTITION BY cve) AS newest_revision,
    max(as_of) OVER(PARTITION BY cve) AS newest_legacy FROM records
), candidates AS (
  SELECT * FROM ranked WHERE nvd_revision=newest_revision OR (newest_revision IS NULL AND as_of=newest_legacy)
), picked AS (
  SELECT DISTINCT ON(cve) * FROM candidates ORDER BY cve,as_of DESC,snapshot_id
), selected AS (
  SELECT p.*,CASE
    WHEN EXISTS(SELECT FROM candidates c WHERE c.cve=p.cve AND c.semantic_body<>p.semantic_body) THEN 'conflicting_nvd_revision'
    WHEN p.newest_revision IS NOT NULL AND EXISTS(SELECT FROM records r WHERE r.cve=p.cve AND r.nvd_revision IS NULL AND r.as_of>=p.as_of) THEN 'unversioned_nvd_record'
    ELSE '' END AS selection_reason FROM picked p
)
SELECT cve,snapshot_id,body,nvd_revision,expires_at,selection_reason,
  md5(snapshot_id::text||':'||body::text||':'||selection_reason) AS generation FROM selected
$$;

CREATE VIEW noctis_v2.nvd_current_selection AS
-- Expose the outer key so CVE predicates restrict the set before the lateral call.
SELECT c.cve,current.snapshot_id,current.body,current.nvd_revision,current.expires_at,current.selection_reason,current.generation
FROM (SELECT DISTINCT cve FROM noctis_v2.vulnerability_facts) c
CROSS JOIN LATERAL noctis_v2.select_current_nvd(c.cve) current;

CREATE TABLE noctis_v2.applicability_current(
  cve text NOT NULL,asset_id uuid NOT NULL,asset_revision integer NOT NULL,
  snapshot_id uuid NOT NULL,nvd_revision timestamptz,generation text NOT NULL,
  status text NOT NULL CHECK(status IN ('affected_version','not_affected_version','unknown')),
  reason text NOT NULL,expires_at timestamptz NOT NULL,calculated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(cve,asset_id),FOREIGN KEY(snapshot_id,cve) REFERENCES noctis_v2.vulnerability_facts(snapshot_id,cve),
  FOREIGN KEY(asset_id,asset_revision) REFERENCES noctis_v2.asset_versions(id,revision)
);
CREATE INDEX applicability_expiry ON noctis_v2.applicability_current(expires_at,cve);
CREATE INDEX applicability_asset ON noctis_v2.applicability_current(asset_id,cve);
CREATE TABLE noctis_v2.case_applicability_projection(
  case_id uuid PRIMARY KEY REFERENCES noctis_v2.intelligence_cases(id),
  generation text NOT NULL,transition bigint NOT NULL CHECK(transition>0),body jsonb NOT NULL
);
CREATE TABLE noctis_v2.applicability_transitions(
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,cve text NOT NULL,asset_id uuid NOT NULL,
  asset_revision integer NOT NULL,snapshot_id uuid NOT NULL,generation text NOT NULL,status text NOT NULL,
  reason text NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Evidence was validated at insertion; check its identity and availability again on every read.
CREATE FUNCTION noctis_v2.applicability_evidence_current(refs jsonb) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT jsonb_typeof(refs)='array' AND jsonb_array_length(refs)>0 AND NOT EXISTS(
    SELECT FROM jsonb_array_elements(refs) r WHERE NOT EXISTS(
      SELECT FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation)
      WHERE o.id::text=r->>'observation_id' AND o.revision=r->>'revision' AND o.hash=r->>'hash'
        AND o.representation=r->>'representation' AND NOT o.source_deleted AND o.superseded_by IS NULL
        AND o.retention_expired_at IS NULL))
$$;

CREATE VIEW noctis_v2.applicability_effective AS
WITH assets AS (SELECT DISTINCT ON(id) * FROM noctis_v2.asset_versions ORDER BY id,revision DESC),
evaluated AS (
  SELECT n.cve,a.id AS asset_id,a.revision AS asset_revision,n.snapshot_id,n.nvd_revision,n.generation,n.expires_at,
    p.status,p.reason,p.calculated_at,p.calculated_at AS created_at,
    p.snapshot_id AS calculated_snapshot_id,p.asset_revision AS calculated_asset_revision,p.generation AS calculated_generation,
    CASE WHEN n.selection_reason<>'' THEN n.selection_reason
      WHEN n.expires_at<=clock_timestamp() THEN 'feed_snapshot_stale'
      WHEN NOT noctis_v2.applicability_evidence_current(a.evidence) THEN 'asset_evidence_unavailable'
      WHEN p.generation IS DISTINCT FROM n.generation OR p.asset_revision IS DISTINCT FROM a.revision THEN 'calculation_pending'
      ELSE '' END AS invalid_reason
  FROM noctis_v2.nvd_current_selection n CROSS JOIN assets a
  LEFT JOIN noctis_v2.applicability_current p ON p.cve=n.cve AND p.asset_id=a.id
)
SELECT *,CASE WHEN invalid_reason='' THEN status ELSE 'unknown' END AS effective_status,
  CASE WHEN invalid_reason='' THEN 'current' WHEN invalid_reason='calculation_pending' THEN 'pending' ELSE 'stale' END AS freshness,
  'unknown'::text AS local_exposure FROM evaluated;

-- A case covers all its currently evidenced CVEs and every current inventory asset.
-- Missing pairs, invalid membership evidence, and empty coverage never prove exclusion.
CREATE FUNCTION noctis_v2.case_applicability(case_uuid uuid) RETURNS jsonb LANGUAGE sql STABLE AS $$
WITH cves AS (
 SELECT s.value AS cve,bool_or(noctis_v2.applicability_evidence_current(jsonb_build_array(s.evidence))) AS valid
 FROM noctis_v2.case_memberships m JOIN noctis_v2.observable_sightings s ON s.observation_id=m.observation_id
 WHERE m.case_id=case_uuid AND s.observable_type='cve' GROUP BY s.value
), pairs AS (
 SELECT c.cve,c.valid,e.asset_id,e.asset_revision,e.generation,e.snapshot_id,e.expires_at,
 CASE WHEN c.valid THEN COALESCE(e.effective_status,'unknown') ELSE 'unknown' END AS status,
 COALESCE(e.freshness,'pending') AS freshness
 FROM cves c LEFT JOIN noctis_v2.applicability_effective e USING(cve)
), aggregate AS (
 SELECT CASE WHEN bool_or(status='affected_version') THEN 'affected_version'
   WHEN count(*)>0 AND bool_and(status='not_affected_version' AND asset_id IS NOT NULL) THEN 'not_affected_version'
   ELSE 'unknown' END AS status,
   COALESCE(bool_or(freshness<>'current' OR NOT valid OR asset_id IS NULL),true) AS pending,
   md5(COALESCE(string_agg(cve||':'||COALESCE(asset_id::text,'')||':'||COALESCE(asset_revision::text,'')||':'||COALESCE(generation,'')||':'||status||':'||valid::text,'|' ORDER BY cve,asset_id),'')) AS generation,
   min(expires_at) AS expires_at FROM pairs
)
SELECT jsonb_build_object('local_applicability',status,'local_exposure','unknown',
 'applicability_generation',generation,'applicability_pending',pending,'applicability_expires_at',expires_at,
 'priority_reason',CASE status WHEN 'affected_version' THEN 'inventory_version_matches_published_range'
   WHEN 'not_affected_version' THEN 'inventory_versions_excluded_by_published_ranges' ELSE 'applicability_unknown' END)
FROM aggregate
$$;

CREATE FUNCTION noctis_v2.case_effective_body(case_uuid uuid, historical jsonb) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT historical||jsonb_build_object('historical_local_applicability',historical->'local_applicability')
   ||noctis_v2.case_applicability(case_uuid)
$$;

CREATE FUNCTION noctis_v2.change_effective_body(case_uuid uuid, historical jsonb) RETURNS jsonb LANGUAGE sql STABLE AS $$
 SELECT CASE WHEN historical->>'kind'='local_applicability' THEN historical||jsonb_build_object(
   'historical',true,'effective_status',noctis_v2.case_applicability(case_uuid)->>'local_applicability',
   'current_for_alerts',COALESCE(historical->>'applicability_generation'=noctis_v2.case_applicability(case_uuid)->>'applicability_generation',false))
 ELSE historical END
$$;

-- Brief support is checked at read time too, including expiry while workers are stopped.
CREATE FUNCTION noctis_v2.brief_applicability_current(body jsonb) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT NOT EXISTS(SELECT FROM jsonb_array_elements(COALESCE(body->'applicability_support','[]'::jsonb)) s
 WHERE (noctis_v2.case_applicability((s->>'case_id')::uuid)->>'applicability_generation') IS DISTINCT FROM s->>'generation')
 AND (body ? 'applicability_support' OR NOT EXISTS(SELECT FROM noctis_v2.case_changes ch
 WHERE ch.body->>'kind'='local_applicability' AND body::text LIKE '%'||ch.observation_id::text||'%'))
$$;
