-- migrations/007_phase2.sql
-- Phase 2: Sub-classification (Librarian), Analytical Notes (Brain memory),
-- Correlation decisions (Analyst audit trail), Source value tracking.

-- ============================================================
-- 1. Sub-classification columns on raw_content (The Librarian)
-- ============================================================

-- Sub-category provides fine-grained content type beyond the 8 top-level categories.
ALTER TABLE raw_content ADD COLUMN IF NOT EXISTS sub_category TEXT;

-- Structured metadata from the Librarian: tool names, availability, hosting type, etc.
-- Stored as JSONB to allow flexible key-value pairs per content type.
ALTER TABLE raw_content ADD COLUMN IF NOT EXISTS sub_metadata JSONB DEFAULT '{}';

-- Track whether the Librarian has processed this item.
ALTER TABLE raw_content ADD COLUMN IF NOT EXISTS sub_classified BOOLEAN DEFAULT FALSE;

-- Indexes for querying by sub-category and finding unprocessed items.
CREATE INDEX IF NOT EXISTS idx_raw_content_sub_category ON raw_content(sub_category) WHERE sub_category IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_raw_content_sub_unclassified ON raw_content(collected_at ASC)
    WHERE classified = TRUE AND entities_extracted = TRUE AND sub_classified = FALSE;

-- ============================================================
-- 2. Analytical Notes (The Brain's persistent memory)
-- ============================================================

CREATE TABLE IF NOT EXISTS analytical_notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- What this note is about (at least one must be set)
    finding_id UUID REFERENCES raw_content(id),
    entity_id TEXT,                              -- entity graph ID (e.g., "entity:threat_actor:apt28")
    correlation_id UUID REFERENCES correlations(id),
    ioc_type TEXT,                               -- for IOC-specific notes
    ioc_value TEXT,                              -- for IOC-specific notes

    -- The note itself
    note_type TEXT NOT NULL,                     -- "correlation_judgment", "attribution", "pattern", "prediction", "warning", "context"
    title TEXT NOT NULL,                         -- Short summary for display
    content TEXT NOT NULL,                       -- Full analytical text
    confidence REAL NOT NULL DEFAULT 0.5,        -- 0.0-1.0

    -- Provenance
    created_by TEXT NOT NULL DEFAULT 'analyst',  -- "analyst" (LLM), "correlator" (rule engine), "human" (manual)
    model_used TEXT,                             -- Which LLM produced this (e.g., "claude-haiku-4.5")

    -- Lifecycle
    status TEXT NOT NULL DEFAULT 'active',       -- "active", "superseded", "retracted"
    superseded_by UUID REFERENCES analytical_notes(id),

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytical_notes_finding ON analytical_notes(finding_id) WHERE finding_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_analytical_notes_entity ON analytical_notes(entity_id) WHERE entity_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_analytical_notes_correlation ON analytical_notes(correlation_id) WHERE correlation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_analytical_notes_type ON analytical_notes(note_type);
CREATE INDEX IF NOT EXISTS idx_analytical_notes_status ON analytical_notes(status) WHERE status = 'active';
CREATE INDEX IF NOT EXISTS idx_analytical_notes_created ON analytical_notes(created_at DESC);

-- ============================================================
-- 3. Correlation Decisions (Analyst audit trail)
-- ============================================================

-- Every time the Analyst evaluates a correlation candidate, the decision is logged here.
-- This builds a fine-tuning dataset for future models.
CREATE TABLE IF NOT EXISTS correlation_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    candidate_id UUID NOT NULL REFERENCES correlation_candidates(id),
    cluster_id TEXT NOT NULL,

    -- The decision
    decision TEXT NOT NULL,                      -- "promote", "reject", "defer"
    confidence REAL NOT NULL,                    -- Analyst's confidence in the decision
    reasoning TEXT NOT NULL,                     -- LLM explanation

    -- If promoted, the resulting correlation
    promoted_correlation_id UUID REFERENCES correlations(id),

    -- Context that was fed to the LLM
    context_snapshot JSONB NOT NULL DEFAULT '{}', -- The evidence + graph context given to the model
    model_used TEXT,                              -- e.g., "claude-haiku-4.5"

    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_correlation_decisions_candidate ON correlation_decisions(candidate_id);
CREATE INDEX IF NOT EXISTS idx_correlation_decisions_cluster ON correlation_decisions(cluster_id);
CREATE INDEX IF NOT EXISTS idx_correlation_decisions_decision ON correlation_decisions(decision);

-- ============================================================
-- 4. Source value tracking columns
-- ============================================================

-- Add value metrics to the sources table for source optimization.
ALTER TABLE sources ADD COLUMN IF NOT EXISTS unique_iocs INTEGER DEFAULT 0;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS correlation_contributions INTEGER DEFAULT 0;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS avg_severity REAL DEFAULT 0.0;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS signal_to_noise REAL DEFAULT 0.0;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS value_score REAL DEFAULT 0.0;
ALTER TABLE sources ADD COLUMN IF NOT EXISTS value_computed_at TIMESTAMPTZ;
