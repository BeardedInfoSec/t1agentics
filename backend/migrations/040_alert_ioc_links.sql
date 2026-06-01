-- Migration 040: Ensure alert_ioc_links table exists
-- This table was defined in init-db.sql but may be missing on deployments
-- that were set up before it was added.

CREATE TABLE IF NOT EXISTS alert_ioc_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id VARCHAR(255) NOT NULL,
    ioc_value VARCHAR(500) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN (
        'ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email', 'cve'
    )),
    extraction_method VARCHAR(50) DEFAULT 'regex',
    extraction_source VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(alert_id, ioc_value, ioc_type)
);

CREATE INDEX IF NOT EXISTS idx_alert_ioc_links_alert ON alert_ioc_links(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_ioc_links_ioc ON alert_ioc_links(ioc_value, ioc_type);
CREATE INDEX IF NOT EXISTS idx_alert_ioc_links_created ON alert_ioc_links(created_at DESC);
