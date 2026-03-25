-- migrations/009_enrichment.sql
-- IOC enrichment results from external APIs.

ALTER TABLE iocs ADD COLUMN IF NOT EXISTS enrichment JSONB DEFAULT '{}';
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS enriched_at TIMESTAMPTZ;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS enrichment_sources TEXT[] DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_iocs_unenriched ON iocs(first_seen ASC)
    WHERE active = TRUE AND enriched_at IS NULL;
