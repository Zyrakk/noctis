-- Add triage audit log for AI source classification decisions.

CREATE TABLE IF NOT EXISTS source_triage_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_id TEXT NOT NULL,
    identifier TEXT NOT NULL,
    decision TEXT NOT NULL,
    model_used TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_triage_log_batch ON source_triage_log(batch_id);
CREATE INDEX IF NOT EXISTS idx_triage_log_created ON source_triage_log(created_at DESC);

-- Learned domain blacklist: domains auto-blocked after repeated trash decisions.
CREATE TABLE IF NOT EXISTS discovered_blacklist (
    domain TEXT PRIMARY KEY,
    trash_count INTEGER NOT NULL DEFAULT 1,
    auto_added BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
