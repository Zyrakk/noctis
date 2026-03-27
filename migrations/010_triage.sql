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
