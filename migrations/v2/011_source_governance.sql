-- Current governance is zero (independent policy) or one question per source.
-- Discovery provenance and immutable policies/products remain historical.
SELECT pg_advisory_xact_lock(76238451003);
LOCK TABLE noctis_v2.sources, noctis_v2.questions, noctis_v2.question_sources,
    noctis_v2.policies IN SHARE ROW EXCLUSIVE MODE;

CREATE TEMP TABLE source_governance_reconciliation ON COMMIT DROP AS
SELECT s.id AS source_id, q.id AS question_id,
    CASE
        WHEN s.policy_version LIKE 'question:%' AND
            (q.id IS NULL OR p.version IS NULL OR p.terms <> q.terms OR
             NOT EXISTS(SELECT FROM noctis_v2.question_sources qs
                        WHERE qs.source_id=s.id AND qs.question_id=q.id))
            THEN 'ambiguous_or_incoherent_question_policy'
        WHEN s.policy_version NOT LIKE 'question:%' AND
            EXISTS(SELECT FROM noctis_v2.question_sources qs WHERE qs.source_id=s.id)
            THEN 'independent_policy_has_question_relationship'
        -- Preserve even a latent pause: clearing a source pause or renewing a
        -- separate consent later must not silently remove the old question veto.
        WHEN q.enabled AND EXISTS(
            SELECT FROM noctis_v2.question_sources qs JOIN noctis_v2.questions old ON old.id=qs.question_id
            WHERE qs.source_id=s.id AND old.id<>q.id AND NOT old.enabled)
            THEN 'would_remove_question_pause'
    END AS problem
FROM noctis_v2.sources s
LEFT JOIN noctis_v2.questions q ON s.policy_version=
    'question:'||q.id::text||CASE WHEN q.revision>1 THEN ':r'||q.revision::text ELSE '' END
LEFT JOIN noctis_v2.policies p ON p.version=s.policy_version;

DO $$
DECLARE affected text;
BEGIN
    SELECT string_agg(source_id::text||' ('||problem||')', ', ' ORDER BY source_id)
    INTO affected FROM source_governance_reconciliation WHERE problem IS NOT NULL;
    IF affected IS NOT NULL THEN
        RAISE EXCEPTION 'source governance requires explicit reconciliation: %', affected;
    END IF;
END $$;

-- Keep the canonical row intact, including its independence metadata.
DELETE FROM noctis_v2.question_sources qs USING source_governance_reconciliation r
WHERE qs.source_id=r.source_id AND qs.question_id<>r.question_id;

ALTER TABLE noctis_v2.question_sources ADD CONSTRAINT question_sources_one_governor UNIQUE(source_id);
COMMENT ON TABLE noctis_v2.question_sources IS
    'Current governing question per source; zero rows for independent policies. Discovery provenance and historical product references are stored separately.';
