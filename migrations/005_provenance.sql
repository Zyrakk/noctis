-- migrations/005_provenance.sql
-- Add provenance tracking and classification versioning for reclassification support.

ALTER TABLE raw_content ADD COLUMN IF NOT EXISTS provenance TEXT DEFAULT '';
ALTER TABLE raw_content ADD COLUMN IF NOT EXISTS classification_version INTEGER DEFAULT 1;
CREATE INDEX IF NOT EXISTS idx_raw_content_provenance ON raw_content(provenance);
