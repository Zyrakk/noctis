-- Purge legacy embedly/safelinks/widget URLs that entered pending_triage
-- before the structural skip filters in engine.go were deployed.
-- These URLs produce responses too long for the LLM output token limit,
-- causing truncated JSON and batch failures in the triage worker.

DELETE FROM sources
WHERE status = 'pending_triage'
  AND (
    identifier LIKE '%embedly.com%'
    OR identifier LIKE '%safelinks.protection.outlook.com%'
    OR identifier LIKE '%blogger.com/video.g%'
    OR identifier LIKE '%player.vimeo.com%'
    OR identifier LIKE '%t.co/%'
  );
