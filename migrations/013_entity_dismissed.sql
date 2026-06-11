ALTER TABLE entities ADD COLUMN IF NOT EXISTS dismissed BOOLEAN DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_entities_active_actors
    ON entities(type) WHERE dismissed = FALSE;
