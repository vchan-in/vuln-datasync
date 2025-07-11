<<<<<<<< HEAD:migrations/001_initial_schema.up.sql
-- Initial schema for vulnerability data synchronization system
-- Based on learnings from ossdeps POC

-- Create vulnerabilities table with optimized structure
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                  TEXT PRIMARY KEY,
    summary             TEXT,                 -- Nullable: some vulns don't have summaries
    details             TEXT,
    severity            TEXT,
    published_at        TIMESTAMP WITH TIME ZONE,
    modified_at         TIMESTAMP WITH TIME ZONE,
    ecosystem           TEXT,
    package_name        TEXT,
    affected_versions   TEXT[],
    fixed_versions      TEXT[],
    aliases             TEXT[],           -- Critical for deduplication
    refs                JSONB,            -- Flexible reference storage
    source              TEXT[],           -- ["osv"], ["gitlab"], ["osv", "gitlab"]
    raw                 JSONB,            -- Original data for audit trail
    data_hash           TEXT,             -- For change detection
    created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Critical indexes for performance based on POC learnings
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_aliases 
    ON vulnerabilities USING GIN(aliases);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_ecosystem 
    ON vulnerabilities(ecosystem);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_package_name 
    ON vulnerabilities(package_name);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_data_hash 
    ON vulnerabilities(data_hash);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_source 
    ON vulnerabilities USING GIN(source);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_published_at 
    ON vulnerabilities(published_at);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_modified_at 
    ON vulnerabilities(modified_at);

-- Index for ecosystem + package queries
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_ecosystem_package 
    ON vulnerabilities(ecosystem, package_name);

-- Create jobs table for background processing
CREATE TABLE IF NOT EXISTS jobs (
    id              SERIAL PRIMARY KEY,
    type            TEXT NOT NULL,
    payload         JSONB NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending',
    queue           TEXT NOT NULL DEFAULT 'default',
    priority        INTEGER NOT NULL DEFAULT 0,
    max_retry       INTEGER NOT NULL DEFAULT 3,
    retried         INTEGER NOT NULL DEFAULT 0,
    error_message   TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at    TIMESTAMP WITH TIME ZONE,
    completed_at    TIMESTAMP WITH TIME ZONE
);

-- Index for job processing
CREATE INDEX IF NOT EXISTS idx_jobs_state_queue 
    ON jobs(state, queue);

CREATE INDEX IF NOT EXISTS idx_jobs_created_at 
    ON jobs(created_at);

-- Create processing_stats table for monitoring
CREATE TABLE IF NOT EXISTS processing_stats (
    id              SERIAL PRIMARY KEY,
    source          TEXT NOT NULL,
    processed_count INTEGER NOT NULL DEFAULT 0,
    ingested_count  INTEGER NOT NULL DEFAULT 0,
    updated_count   INTEGER NOT NULL DEFAULT 0,
    merged_count    INTEGER NOT NULL DEFAULT 0,
    skipped_count   INTEGER NOT NULL DEFAULT 0,
    error_count     INTEGER NOT NULL DEFAULT 0,
    start_time      TIMESTAMP WITH TIME ZONE NOT NULL,
    end_time        TIMESTAMP WITH TIME ZONE,
    duration_ms     INTEGER,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for stats queries
CREATE INDEX IF NOT EXISTS idx_processing_stats_source_start_time 
    ON processing_stats(source, start_time);

-- Create exports table for snapshot tracking
CREATE TABLE IF NOT EXISTS exports (
    id              SERIAL PRIMARY KEY,
    version         TEXT NOT NULL,
    format          TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    file_size       BIGINT,
    checksum        TEXT,
    vulnerability_count INTEGER,
    compression     BOOLEAN DEFAULT FALSE,
    status          TEXT NOT NULL DEFAULT 'pending',
    error_message   TEXT,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at    TIMESTAMP WITH TIME ZONE
);

-- Index for export queries
CREATE INDEX IF NOT EXISTS idx_exports_version 
    ON exports(version);

CREATE INDEX IF NOT EXISTS idx_exports_created_at 
    ON exports(created_at);

-- Create function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';

-- Create trigger for vulnerabilities table
CREATE TRIGGER update_vulnerabilities_updated_at 
    BEFORE UPDATE ON vulnerabilities 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create view for vulnerability statistics
CREATE OR REPLACE VIEW vulnerability_stats AS
SELECT 
    COUNT(*) as total_vulnerabilities,
    COUNT(*) FILTER (WHERE 'osv' = ANY(source)) as osv_count,
    COUNT(*) FILTER (WHERE 'gitlab' = ANY(source)) as gitlab_count,
    COUNT(*) FILTER (WHERE 'cve' = ANY(source)) as cve_count,
    COUNT(*) FILTER (WHERE array_length(source, 1) > 1) as merged_count,
    COUNT(DISTINCT ecosystem) as ecosystem_count,
    COUNT(DISTINCT package_name) as package_count,
    MIN(created_at) as oldest_vulnerability,
    MAX(created_at) as newest_vulnerability,
    MAX(updated_at) as last_updated
FROM vulnerabilities;

-- Create view for recent processing activity
CREATE OR REPLACE VIEW recent_processing AS
SELECT 
    source,
    processed_count,
    ingested_count,
    merged_count,
    error_count,
    duration_ms,
    start_time,
    end_time
FROM processing_stats 
WHERE start_time >= NOW() - INTERVAL '24 hours'
ORDER BY start_time DESC;

-- Add comments for documentation
COMMENT ON TABLE vulnerabilities IS 'Main table storing normalized vulnerability data from multiple sources';
COMMENT ON COLUMN vulnerabilities.aliases IS 'Array of vulnerability identifiers (CVE, GHSA, PYSEC, etc.) used for deduplication';
COMMENT ON COLUMN vulnerabilities.source IS 'Array tracking data sources, e.g., ["osv", "gitlab"]';
COMMENT ON COLUMN vulnerabilities.data_hash IS 'Hash of raw data for change detection and deduplication';
COMMENT ON COLUMN vulnerabilities.raw IS 'Complete original data for audit trail and future processing';

COMMENT ON TABLE jobs IS 'Background job queue for async processing';
COMMENT ON TABLE processing_stats IS 'Statistics tracking for vulnerability processing operations';
COMMENT ON TABLE exports IS 'Tracking table for generated vulnerability database snapshots';
========
>>>>>>>> main:migrations/001_initial_schema.sql
