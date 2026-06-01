-- Migration 050: Breach Intelligence System
-- Platform-level breach tracking and threat landscape monitoring
-- All tenants see the same breach data (like connector_definitions)

-- Breach Intel Sources - configured data feeds
CREATE TABLE IF NOT EXISTS breach_intel_sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    source_type VARCHAR(50) NOT NULL CHECK (source_type IN (
        'rss_feed', 'json_api', 'csv_download', 'web_scraper', 'manual'
    )),
    category VARCHAR(50) NOT NULL CHECK (category IN (
        'breach_disclosure', 'vulnerability', 'government_alert',
        'security_news', 'geopolitical', 'ransomware', 'sec_filing'
    )),
    url TEXT NOT NULL,
    parser_config JSONB DEFAULT '{}',
    enabled BOOLEAN DEFAULT TRUE,
    poll_interval_minutes INTEGER DEFAULT 60,
    last_poll_at TIMESTAMP WITH TIME ZONE,
    last_poll_status VARCHAR(20) CHECK (last_poll_status IN ('success', 'failed', 'partial')),
    last_poll_error TEXT,
    last_poll_item_count INTEGER DEFAULT 0,
    total_items_ingested INTEGER DEFAULT 0,
    next_poll_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_breach_intel_sources_enabled ON breach_intel_sources(enabled);
CREATE INDEX IF NOT EXISTS idx_breach_intel_sources_next_poll ON breach_intel_sources(next_poll_at);

-- Breach Incidents - individual breach/incident records
CREATE TABLE IF NOT EXISTS breach_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    external_id VARCHAR(500),
    fingerprint VARCHAR(64) NOT NULL UNIQUE,

    title VARCHAR(500) NOT NULL,
    summary TEXT,
    raw_content TEXT,
    incident_type VARCHAR(50) NOT NULL CHECK (incident_type IN (
        'data_breach', 'ransomware', 'vulnerability', 'apt_campaign',
        'supply_chain', 'ddos', 'insider_threat', 'government_alert', 'other'
    )),

    affected_org VARCHAR(500),
    affected_sector VARCHAR(100),
    affected_countries TEXT[],
    records_affected BIGINT,

    severity VARCHAR(20) CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    relevance_score DECIMAL(5,2) CHECK (relevance_score >= 0 AND relevance_score <= 100),

    incident_date DATE,
    disclosure_date DATE,
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    source_id VARCHAR(100) REFERENCES breach_intel_sources(source_id),
    source_url TEXT,

    ai_summary TEXT,
    ai_tags TEXT[],
    ai_iocs JSONB DEFAULT '[]',
    ai_ttps JSONB DEFAULT '[]',
    ai_enriched_at TIMESTAMP WITH TIME ZONE,

    related_cves TEXT[],
    related_apt_groups TEXT[],
    related_malware TEXT[],

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_breach_incidents_type ON breach_incidents(incident_type);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_severity ON breach_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_discovered ON breach_incidents(discovered_at DESC);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_incident_date ON breach_incidents(incident_date DESC);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_sector ON breach_incidents(affected_sector);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_fingerprint ON breach_incidents(fingerprint);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_source ON breach_incidents(source_id);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_countries ON breach_incidents USING GIN(affected_countries);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_cves ON breach_incidents USING GIN(related_cves);
CREATE INDEX IF NOT EXISTS idx_breach_incidents_tags ON breach_incidents USING GIN(ai_tags);

-- Geopolitical Events
CREATE TABLE IF NOT EXISTS geopolitical_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    fingerprint VARCHAR(64) NOT NULL UNIQUE,

    title VARCHAR(500) NOT NULL,
    summary TEXT,
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN (
        'armed_conflict', 'sanctions', 'cyber_operation', 'election',
        'treaty', 'diplomatic_crisis', 'critical_infra', 'other'
    )),

    countries_involved TEXT[] NOT NULL,
    region VARCHAR(100),

    cyber_risk_level VARCHAR(20) CHECK (cyber_risk_level IN ('critical', 'high', 'medium', 'low')),
    expected_threat_actors TEXT[],
    expected_ttps TEXT[],
    targeted_sectors TEXT[],

    ai_cyber_assessment TEXT,
    ai_recommendations TEXT[],
    ai_enriched_at TIMESTAMP WITH TIME ZONE,

    event_start_date DATE,
    event_end_date DATE,
    is_ongoing BOOLEAN DEFAULT TRUE,

    source_id VARCHAR(100),
    source_url TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_geopolitical_events_type ON geopolitical_events(event_type);
CREATE INDEX IF NOT EXISTS idx_geopolitical_events_risk ON geopolitical_events(cyber_risk_level);
CREATE INDEX IF NOT EXISTS idx_geopolitical_events_countries ON geopolitical_events USING GIN(countries_involved);
CREATE INDEX IF NOT EXISTS idx_geopolitical_events_ongoing ON geopolitical_events(is_ongoing) WHERE is_ongoing = TRUE;
