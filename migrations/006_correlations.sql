-- migrations/006_correlations.sql
-- IOC sightings for cross-source correlation and correlation engine tables.

-- Track every IOC sighting across raw_content entries.
-- The existing iocs table has UNIQUE(type, value) with a single source_content_id,
-- which loses multi-source provenance. This table records every sighting.
CREATE TABLE IF NOT EXISTS ioc_sightings (
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    raw_content_id UUID NOT NULL REFERENCES raw_content(id),
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (ioc_type, ioc_value, raw_content_id)
);

CREATE INDEX IF NOT EXISTS idx_ioc_sightings_value ON ioc_sightings(ioc_type, ioc_value);

-- Confirmed correlations that met the evidence threshold.
CREATE TABLE IF NOT EXISTS correlations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id TEXT NOT NULL,
    entity_ids TEXT[] NOT NULL,
    finding_ids TEXT[] NOT NULL DEFAULT '{}',
    correlation_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    method TEXT NOT NULL DEFAULT 'rule',
    evidence JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_correlations_cluster ON correlations(cluster_id);
CREATE INDEX IF NOT EXISTS idx_correlations_type ON correlations(correlation_type);
CREATE INDEX IF NOT EXISTS idx_correlations_created ON correlations(created_at DESC);

-- Weak candidates below the evidence threshold.
-- Fed to the LLM confirmation pipeline in Phase 3.
CREATE TABLE IF NOT EXISTS correlation_candidates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id TEXT NOT NULL,
    entity_ids TEXT[] NOT NULL,
    finding_ids TEXT[] NOT NULL DEFAULT '{}',
    candidate_type TEXT NOT NULL,
    signal_count INTEGER NOT NULL DEFAULT 0,
    signals JSONB NOT NULL DEFAULT '{}',
    seen_count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_correlation_candidates_cluster ON correlation_candidates(cluster_id);
CREATE INDEX IF NOT EXISTS idx_correlation_candidates_status ON correlation_candidates(status);
CREATE INDEX IF NOT EXISTS idx_correlation_candidates_type ON correlation_candidates(candidate_type);
