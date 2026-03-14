CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    author TEXT,
    timestamp TIMESTAMPTZ NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}',
    match_type TEXT,
    matched_rules JSONB DEFAULT '[]',
    severity TEXT DEFAULT 'info',
    category TEXT,
    iocs JSONB DEFAULT '[]',
    llm_analysis TEXT,
    confidence REAL DEFAULT 0.0
);

CREATE INDEX IF NOT EXISTS idx_findings_content_hash ON findings(content_hash);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_collected_at ON findings(collected_at);

CREATE TABLE IF NOT EXISTS canary_tokens (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL UNIQUE,
    planted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    planted_in TEXT NOT NULL,
    triggered BOOLEAN NOT NULL DEFAULT FALSE,
    triggered_at TIMESTAMPTZ,
    triggered_in TEXT
);

CREATE INDEX IF NOT EXISTS idx_canary_tokens_value ON canary_tokens(value);

CREATE TABLE IF NOT EXISTS actor_profiles (
    id TEXT PRIMARY KEY,
    known_handles JSONB NOT NULL DEFAULT '[]',
    platforms JSONB NOT NULL DEFAULT '[]',
    style_embedding JSONB,
    posting_cadence JSONB,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    threat_level TEXT DEFAULT 'info',
    linked_findings JSONB NOT NULL DEFAULT '[]'
);
