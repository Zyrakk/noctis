-- Normalize telegram_channel identifiers from full URLs (https://t.me/username)
-- to bare usernames, matching the format used by config channels.
-- This resolves a mismatch where discovery stored full URLs but config used
-- bare usernames, preventing reliable matching for last_collected updates.

UPDATE sources
SET identifier = regexp_replace(identifier, '^(https?://)?t\.me/', ''),
    name = regexp_replace(name, '^(https?://)?t\.me/', ''),
    updated_at = NOW()
WHERE type = 'telegram_channel'
  AND identifier ~ '(^https?://t\.me/|^t\.me/)';
