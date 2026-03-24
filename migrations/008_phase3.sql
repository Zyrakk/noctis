-- migrations/008_phase3.sql
-- Phase 3: IOC lifecycle scoring, Intelligence Briefs (daily summaries), Vulnerabilities (CVE/CVSS/EPSS/KEV tracking).

-- ============================================================
-- 1. IOC Lifecycle columns (threat scoring and activation status)
-- ============================================================

ALTER TABLE iocs ADD COLUMN IF NOT EXISTS threat_score REAL DEFAULT 0.5;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS base_score REAL DEFAULT 0.5;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMPTZ;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS lifetime_days INTEGER;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS publicly_reported BOOLEAN DEFAULT FALSE;

-- Filtered indexes for active IOCs and threat scoring
CREATE INDEX IF NOT EXISTS idx_iocs_active ON iocs(active) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_iocs_threat_score ON iocs(threat_score DESC) WHERE active = TRUE;

-- ============================================================
-- 2. Intelligence Briefs (daily/periodic summaries for analysts)
-- ============================================================

CREATE TABLE IF NOT EXISTS intelligence_briefs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Time period covered by this brief
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,

    -- Brief configuration
    brief_type TEXT NOT NULL DEFAULT 'daily',  -- "daily", "weekly", "monthly", "incident", "threat_actor"

    -- Content
    title TEXT NOT NULL,
    executive_summary TEXT NOT NULL,
    content TEXT NOT NULL,

    -- Structured data
    sections JSONB NOT NULL DEFAULT '{}',     -- Brief sections keyed by section name (findings, indicators, patterns, etc.)
    metrics JSONB NOT NULL DEFAULT '{}',      -- Quantitative metrics (counts, new IOCs, correlations, etc.)

    -- Generation metadata
    model_used TEXT,                           -- Which LLM generated this brief
    generated_at TIMESTAMPTZ DEFAULT NOW(),
    generation_duration_ms INTEGER,            -- How long it took to generate

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_briefs_period ON intelligence_briefs(period_end DESC);
CREATE INDEX IF NOT EXISTS idx_briefs_type ON intelligence_briefs(brief_type);

-- ============================================================
-- 3. Vulnerabilities (CVE/CVSS/EPSS/KEV tracking)
-- ============================================================

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- CVE Identifiers and metadata
    cve_id TEXT NOT NULL UNIQUE,
    description TEXT,

    -- CVSS v3.1 scoring
    cvss_v31_score REAL,
    cvss_v31_vector TEXT,
    cvss_severity TEXT,                       -- "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"

    -- CWE and affected products
    cwe_ids TEXT[] DEFAULT '{}',              -- Common Weakness Enumeration IDs
    affected_products JSONB DEFAULT '[]',     -- Product info from NVD

    -- References (note: "references" is a reserved keyword in SQL)
    reference_urls JSONB DEFAULT '[]',

    -- Publication and modification dates
    published_at TIMESTAMPTZ,
    last_modified_at TIMESTAMPTZ,

    -- EPSS (Exploit Prediction Scoring System)
    epss_score REAL,
    epss_percentile REAL,
    epss_updated_at TIMESTAMPTZ,

    -- CISA KEV (Known Exploited Vulnerabilities) catalog
    kev_listed BOOLEAN DEFAULT FALSE,
    kev_date_added TIMESTAMPTZ,
    kev_due_date TIMESTAMPTZ,
    kev_ransomware_use BOOLEAN DEFAULT FALSE,

    -- Exploit and threat intelligence
    exploit_available BOOLEAN DEFAULT FALSE,
    dark_web_mentions INTEGER DEFAULT 0,

    -- Noctis-specific tracking
    first_seen_noctis TIMESTAMPTZ,
    last_seen_noctis TIMESTAMPTZ,

    -- Priority scoring for remediation
    priority_score REAL,
    priority_label TEXT,

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_priority ON vulnerabilities(priority_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_vulns_kev ON vulnerabilities(kev_listed) WHERE kev_listed = TRUE;
CREATE INDEX IF NOT EXISTS idx_vulns_epss ON vulnerabilities(epss_score DESC NULLS LAST) WHERE epss_score IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_vulns_mentions ON vulnerabilities(dark_web_mentions DESC) WHERE dark_web_mentions > 0;
