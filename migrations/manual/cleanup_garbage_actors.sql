-- cleanup_garbage_actors.sql
-- One-shot (re-runnable) cleanup: marks existing garbage threat_actor
-- entities as dismissed, mirroring the F0.2 correlator criteria
-- (internal/brain/correlator.go, isGarbageActorHandle). This file lives under
-- migrations/manual/ on purpose: the auto-migration runner skips
-- subdirectories, so it is only ever applied by hand:
--
--   psql "$NOCTIS_DB_DSN" -f migrations/manual/cleanup_garbage_actors.sql
--
-- Requires migration 013 (entities.dismissed) to be applied first.
--
-- Criteria expressed in SQL:
--   (a) handle ends in "_bot" (case-insensitive)
--   (c) fewer than 3 visible characters after stripping whitespace,
--       control characters, and zero-width/format characters
--   (d) whitespace/zero-width only (degenerate case of (c))
--   (e) generic stoplist: admin, support, bot, info, news, channel
--
-- NOT expressible in SQL:
--   (b) the config-driven blacklist (correlation.actor_blacklist lives in
--       config.yaml, not in the database). Mirror any configured handles
--       into the commented manual-blacklist line below before running.

UPDATE entities e
SET dismissed = TRUE
FROM (
    SELECT id,
           lower(btrim(COALESCE(properties->>'name', split_part(id, ':', 3)))) AS trimmed,
           lower(regexp_replace(
               COALESCE(properties->>'name', split_part(id, ':', 3)),
               -- whitespace, control chars, and common zero-width/format
               -- chars: U+200B..U+200F, U+202A..U+202E, U+2060..U+2064,
               -- U+FEFF (BOM), U+00AD (soft hyphen)
               '[[:space:][:cntrl:]' ||
               chr(8203) || chr(8204) || chr(8205) || chr(8206) || chr(8207) ||
               chr(8234) || chr(8235) || chr(8236) || chr(8237) || chr(8238) ||
               chr(8288) || chr(8289) || chr(8290) || chr(8291) || chr(8292) ||
               chr(65279) || chr(173) || ']',
               '', 'g')) AS stripped
    FROM entities
    WHERE type = 'threat_actor'
) g
WHERE e.id = g.id
  AND e.dismissed = FALSE
  AND (
        -- (a) bot accounts (backslash escapes the LIKE "_" wildcard)
        g.stripped LIKE '%\_bot'
        -- (c)+(d) fewer than 3 visible characters
        OR length(g.stripped) < 3
        -- (e) generic stoplist
        OR g.trimmed  IN ('admin', 'support', 'bot', 'info', 'news', 'channel')
        OR g.stripped IN ('admin', 'support', 'bot', 'info', 'news', 'channel')
        -- (b) manual blacklist — mirror config.yaml correlation.actor_blacklist
        --     here (lowercase) before running, e.g.:
        -- OR g.trimmed IN ('somebotname', 'otherhandle')
  );

-- Verification: dismissed vs. active threat actors after the update.
SELECT dismissed, COUNT(*)
FROM entities
WHERE type = 'threat_actor'
GROUP BY dismissed;
