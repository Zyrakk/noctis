-- migrations/003_pivot.sql
-- Noctis Pivot: Intelligence archive, source registry, IOC store, artifacts.
-- Additive migration — existing tables (findings, canary_tokens, actor_profiles,
-- entities, edges) are untouched.

-- Raw content archive: stores EVERYTHING collected, regardless of relevance
CREATE TABLE IF NOT EXISTS raw_content (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_type TEXT NOT NULL,          -- telegram, paste, forum, web, rss
    source_id TEXT NOT NULL,            -- channel ID, forum thread URL, etc.
    source_name TEXT NOT NULL,          -- human-readable name
    content TEXT NOT NULL,              -- full raw text
    content_hash TEXT NOT NULL UNIQUE,  -- SHA-256 for dedup
    author TEXT,                        -- handle/username if known
    author_id TEXT,                     -- platform-specific author ID
    url TEXT,                           -- original URL if available
    language TEXT,                      -- detected language
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posted_at TIMESTAMPTZ,             -- original post timestamp
    metadata JSONB DEFAULT '{}',       -- source-specific metadata

    -- AI classification (filled asynchronously after collection)
    classified BOOLEAN DEFAULT FALSE,
    category TEXT,                      -- credential_leak, malware, access_broker, etc.
    tags TEXT[] DEFAULT '{}',           -- AI-generated tags for searchability
    severity TEXT,                      -- critical, high, medium, low, info, none
    summary TEXT,                       -- AI-generated one-line summary
    entities_extracted BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_raw_content_source ON raw_content(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_raw_content_collected ON raw_content(collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_raw_content_category ON raw_content(category);
CREATE INDEX IF NOT EXISTS idx_raw_content_tags ON raw_content USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_raw_content_hash ON raw_content(content_hash);
CREATE INDEX IF NOT EXISTS idx_raw_content_unclassified ON raw_content(collected_at ASC) WHERE classified = FALSE;
CREATE INDEX IF NOT EXISTS idx_raw_content_unextracted ON raw_content(collected_at ASC) WHERE classified = TRUE AND entities_extracted = FALSE;

-- IOC store: all indicators extracted across all content
CREATE TABLE IF NOT EXISTS iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,                 -- ip, domain, hash_md5, hash_sha256, email, crypto_wallet, url, cve
    value TEXT NOT NULL,
    context TEXT,                       -- surrounding text
    source_content_id UUID REFERENCES raw_content(id),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    sighting_count INTEGER DEFAULT 1,
    confidence REAL DEFAULT 0.5,
    UNIQUE(type, value)
);

CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);

-- Downloaded files/artifacts
CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_content_id UUID REFERENCES raw_content(id),
    filename TEXT,
    mime_type TEXT,
    size_bytes BIGINT,
    sha256 TEXT NOT NULL UNIQUE,
    storage_path TEXT NOT NULL,         -- path on NFS volume
    tags TEXT[] DEFAULT '{}',
    collected_at TIMESTAMPTZ DEFAULT NOW(),
    analyzed BOOLEAN DEFAULT FALSE,
    analysis JSONB DEFAULT '{}'         -- AI analysis results
);

CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
CREATE INDEX IF NOT EXISTS idx_artifacts_tags ON artifacts USING GIN(tags);

-- Source registry: all discovered and monitored sources
CREATE TABLE IF NOT EXISTS sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,                 -- telegram_channel, telegram_group, forum, paste_site, web, rss
    identifier TEXT NOT NULL UNIQUE,    -- channel username, forum URL, RSS URL, etc.
    name TEXT,                          -- human-readable name
    status TEXT DEFAULT 'discovered',   -- discovered, approved, active, paused, dead, banned
    discovered_from UUID,              -- source_content_id that led to discovery
    last_collected TIMESTAMPTZ,
    collection_interval TEXT DEFAULT '60s',
    error_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',       -- credentials needed, notes, etc.
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sources_status ON sources(status);
CREATE INDEX IF NOT EXISTS idx_sources_type ON sources(type);
