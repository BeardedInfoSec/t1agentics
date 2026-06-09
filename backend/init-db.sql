-- T1 Agentics PostgreSQL Schema
-- Production-ready schema for SOC platform
-- Supports alerts, investigations, users, IOCs with full RBAC

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- USERS TABLE
-- ============================================================================
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(20) NOT NULL CHECK (role IN ('admin', 'analyst', 'read_only')),
    disabled BOOLEAN DEFAULT FALSE,
    force_password_reset BOOLEAN DEFAULT FALSE,
    -- Account lockout fields
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    last_failed_login TIMESTAMP WITH TIME ZONE,
    -- MFA/TOTP fields
    totp_secret VARCHAR(64),
    totp_verified BOOLEAN DEFAULT false,
    mfa_enabled BOOLEAN DEFAULT false,
    totp_recovery_codes TEXT,
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);

-- ============================================================================
-- INVESTIGATIONS TABLE (must be before alerts for foreign key)
-- ============================================================================
CREATE TABLE investigations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) UNIQUE NOT NULL,
    alert_id UUID,  -- Will add FK after alerts table exists
    
    -- Workflow fields
    state VARCHAR(50) NOT NULL DEFAULT 'NEW' CHECK (state IN (
        'NEW', 'ANALYZING', 'NEEDS_REVIEW', 'IN_PROGRESS', 'CLOSED'
    )),
    disposition VARCHAR(50) DEFAULT 'UNKNOWN' CHECK (disposition IN (
        -- Canonical verdicts (from models/verdict.py - single source of truth)
        'MALICIOUS', 'SUSPICIOUS', 'BENIGN',
        'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN_POSITIVE',
        'NEEDS_INVESTIGATION', 'INCONCLUSIVE', 'UNKNOWN'
    )),
    priority VARCHAR(10) DEFAULT 'P3' CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    owner VARCHAR(100),
    
    -- Analysis results
    alert_title VARCHAR(500),
    executive_summary TEXT,
    confidence DECIMAL(5,2),
    severity VARCHAR(20) CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    assigned_at TIMESTAMP WITH TIME ZONE,
    
    -- Full investigation data (JSONB for flexibility)
    investigation_data JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_investigations_investigation_id ON investigations(investigation_id);
CREATE INDEX idx_investigations_state ON investigations(state);
CREATE INDEX idx_investigations_disposition ON investigations(disposition);
CREATE INDEX idx_investigations_priority ON investigations(priority);
CREATE INDEX idx_investigations_owner ON investigations(owner);
CREATE INDEX idx_investigations_alert_id ON investigations(alert_id);
CREATE INDEX idx_investigations_created_at ON investigations(created_at DESC);
CREATE INDEX idx_investigations_data ON investigations USING GIN (investigation_data);

-- ============================================================================
-- ALERTS TABLE (Primary)
-- ============================================================================
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id VARCHAR(255) UNIQUE NOT NULL,
    external_id VARCHAR(255),
    
    -- Core fields
    title VARCHAR(500) NOT NULL,
    description TEXT,
    
    -- Classification
    severity VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'closed')),
    source VARCHAR(100),
    source_type VARCHAR(50),
    category VARCHAR(100),
    subcategory VARCHAR(100),
    confidence DECIMAL(5,2) CHECK (confidence >= 0 AND confidence <= 100),

    -- Telemetry classification (three-class model: observations, assertions, decisions)
    -- - observation: Raw log/event data from collectors
    -- - assertion: Vendor claims (webhook alerts from external SIEM/EDR/etc)
    -- - decision: Human/AI investigation conclusions
    event_class VARCHAR(20) NOT NULL DEFAULT 'assertion' CHECK (event_class IN ('observation', 'assertion', 'decision')),

    -- Vendor trust tracking (for assertions from external security tools)
    vendor VARCHAR(100),                                                          -- Vendor name (e.g., 'CrowdStrike', 'SentinelOne')
    vendor_confidence DECIMAL(5,4) CHECK (vendor_confidence >= 0 AND vendor_confidence <= 1),  -- Vendor's stated confidence (0.0-1.0)
    vendor_reputation DECIMAL(5,4) CHECK (vendor_reputation >= 0 AND vendor_reputation <= 1),  -- Calculated reputation score
    false_positive_rate DECIMAL(5,4) CHECK (false_positive_rate >= 0 AND false_positive_rate <= 1),  -- Historical FP rate for this vendor

    -- Correlation: link assertions to supporting observations
    linked_observation_ids UUID[] DEFAULT '{}'::uuid[],

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- AI + Evidence Storage (CRITICAL for AI reasoning)
    raw_event JSONB NOT NULL DEFAULT '{}'::jsonb,
    
    -- Full-text search vector
    search_vector tsvector,
    
    -- Investigation link
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL
);

-- Add foreign key from investigations to alerts
ALTER TABLE investigations ADD CONSTRAINT fk_investigations_alert 
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE;

-- Indexes for performance
CREATE INDEX idx_alerts_alert_id ON alerts(alert_id);
CREATE INDEX idx_alerts_status ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_source ON alerts(source);
CREATE INDEX idx_alerts_created_at ON alerts(created_at DESC);
CREATE INDEX idx_alerts_external_id ON alerts(external_id);
CREATE INDEX idx_alerts_investigation ON alerts(investigation_id);

-- JSONB GIN index for fast queries
CREATE INDEX idx_alerts_raw_event ON alerts USING GIN (raw_event);

-- Full-text search index
CREATE INDEX idx_alerts_search ON alerts USING GIN (search_vector);

-- Telemetry classification indexes (three-class model)
CREATE INDEX idx_alerts_event_class ON alerts(event_class);
CREATE INDEX idx_alerts_vendor ON alerts(vendor);
CREATE INDEX idx_alerts_vendor_reputation ON alerts(vendor_reputation);

-- GIN index for linked observation IDs (for correlation queries)
CREATE INDEX idx_alerts_linked_observations ON alerts USING GIN (linked_observation_ids);

-- ============================================================================
-- IOCS TABLE
-- ============================================================================
CREATE TABLE iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- IOC details
    ioc_value VARCHAR(500) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN (
        'ip', 'domain', 'url', 'hash', 'hash_md5', 'hash_sha1', 'hash_sha256',
        'email', 'username', 'hostname', 'file_path', 'cve', 'mitre_attack'
    )),

    -- Classification
    severity VARCHAR(20) CHECK (severity IN ('unknown', 'low', 'medium', 'high', 'critical')),
    confidence DECIMAL(5,2) CHECK (confidence >= 0 AND confidence <= 100),
    reputation VARCHAR(20) CHECK (reputation IN ('clean', 'suspicious', 'malicious', 'unknown') OR reputation IS NULL),

    -- Tracking
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    occurrences INTEGER DEFAULT 1,

    -- Enrichment data
    enrichment_data JSONB DEFAULT '{}'::jsonb,

    -- Source tracking (legacy field)
    source VARCHAR(100),
    tags TEXT[],

    -- NEW: Enhanced source tracking
    source_type VARCHAR(50) CHECK (source_type IN (
        'manual',           -- User manually submitted via UI
        'ai_agent',         -- AI agent discovered/submitted during investigation
        'event',            -- Extracted from an alert/event
        'investigation',    -- Extracted during investigation analysis
        'threat_feed'       -- Ingested from external threat intel feed
    )),
    source_id VARCHAR(255),            -- Reference ID (alert_id, investigation_id, feed_id, user_id)
    feed_name VARCHAR(100),            -- Name of the threat feed if source_type='threat_feed'
    ingested_at TIMESTAMP WITH TIME ZONE,  -- When IOC was first ingested from feed

    -- NEW: Enrichment tracking for smart re-enrichment
    last_enriched_at TIMESTAMP WITH TIME ZONE,
    enrichment_trigger VARCHAR(50) CHECK (enrichment_trigger IN (
        'manual',           -- User requested enrichment
        'auto_initial',     -- Auto-enriched on first ingestion
        'feed_reappear',    -- Re-enriched because IOC reappeared in threat feed
        'scheduled',        -- Scheduled re-enrichment
        'investigation'     -- Enriched as part of investigation
    )),
    feed_last_seen_at TIMESTAMP WITH TIME ZONE,  -- Last time this IOC appeared in any threat feed
    feed_occurrences INTEGER DEFAULT 0,          -- How many times seen across threat feeds

    -- Unique constraint
    UNIQUE(ioc_value, ioc_type)
);

CREATE INDEX idx_iocs_value ON iocs(ioc_value);
CREATE INDEX idx_iocs_type ON iocs(ioc_type);
CREATE INDEX idx_iocs_severity ON iocs(severity);
CREATE INDEX idx_iocs_last_seen ON iocs(last_seen DESC);
CREATE INDEX idx_iocs_enrichment ON iocs USING GIN (enrichment_data);
CREATE INDEX idx_iocs_tags ON iocs USING GIN (tags);
-- NEW: Indexes for source tracking and smart re-enrichment
CREATE INDEX idx_iocs_source_type ON iocs(source_type);
CREATE INDEX idx_iocs_feed_name ON iocs(feed_name);
CREATE INDEX idx_iocs_last_enriched ON iocs(last_enriched_at);
CREATE INDEX idx_iocs_feed_last_seen ON iocs(feed_last_seen_at DESC);

-- ============================================================================
-- AUDIT LOG TABLE (for RBAC tracking)
-- ============================================================================
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB DEFAULT '{}'::jsonb,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_audit_log_action ON audit_log(action);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at DESC);

-- ============================================================================
-- AI INVESTIGATION NOTES
-- ============================================================================
CREATE TABLE investigation_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    
    -- Note metadata
    note_type VARCHAR(50) NOT NULL CHECK (note_type IN (
        'AI_ANALYSIS', 'AI_RECOMMENDATION', 'AI_OBSERVATION',
        'HUMAN_NOTE', 'SYSTEM_NOTE', 'ESCALATION'
    )),
    author VARCHAR(100) NOT NULL,  -- 'ai_agent', username, 'system'
    author_type VARCHAR(20) NOT NULL CHECK (author_type IN ('AI', 'HUMAN', 'SYSTEM')),
    
    -- Note content
    title VARCHAR(255),
    content TEXT NOT NULL,
    confidence DECIMAL(5,2),  -- For AI notes
    severity VARCHAR(20) CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    
    -- Soft delete (for audit trail)
    deleted_at TIMESTAMP WITH TIME ZONE,
    deleted_by VARCHAR(100)
);

CREATE INDEX idx_investigation_notes_investigation_id ON investigation_notes(investigation_id);
CREATE INDEX idx_investigation_notes_note_type ON investigation_notes(note_type);
CREATE INDEX idx_investigation_notes_author ON investigation_notes(author);
CREATE INDEX idx_investigation_notes_created_at ON investigation_notes(created_at DESC);
CREATE INDEX idx_investigation_notes_metadata ON investigation_notes USING GIN (metadata);

-- ============================================================================
-- AI ACTION LOG (Read-Only Audit Trail)
-- ============================================================================
CREATE TABLE ai_action_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,
    
    -- Action details
    action_type VARCHAR(100) NOT NULL,  -- 'ioc_extraction', 'threat_analysis', 'recommendation_generated', etc.
    action_description TEXT NOT NULL,
    
    -- AI Agent info
    agent_name VARCHAR(100) NOT NULL,  -- 'L1_Triage_Agent', 'L2_Analysis_Agent', etc.
    agent_version VARCHAR(50),
    
    -- Action results
    status VARCHAR(50) NOT NULL CHECK (status IN ('SUCCESS', 'FAILED', 'PARTIAL', 'SKIPPED')),
    confidence DECIMAL(5,2),
    
    -- Input/Output data
    input_data JSONB DEFAULT '{}'::jsonb,
    output_data JSONB DEFAULT '{}'::jsonb,
    error_details TEXT,
    
    -- Timing
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,  -- Duration in milliseconds
    
    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb
);

-- READ-ONLY enforcement: No UPDATE or DELETE allowed
-- Only INSERT is permitted
CREATE RULE ai_action_log_no_update AS ON UPDATE TO ai_action_log DO INSTEAD NOTHING;
CREATE RULE ai_action_log_no_delete AS ON DELETE TO ai_action_log DO INSTEAD NOTHING;

CREATE INDEX idx_ai_action_log_investigation_id ON ai_action_log(investigation_id);
CREATE INDEX idx_ai_action_log_action_type ON ai_action_log(action_type);
CREATE INDEX idx_ai_action_log_agent_name ON ai_action_log(agent_name);
CREATE INDEX idx_ai_action_log_status ON ai_action_log(status);
CREATE INDEX idx_ai_action_log_started_at ON ai_action_log(started_at DESC);
CREATE INDEX idx_ai_action_log_input ON ai_action_log USING GIN (input_data);
CREATE INDEX idx_ai_action_log_output ON ai_action_log USING GIN (output_data);

-- ============================================================================
-- INVESTIGATION AUDIT LOG (Immutable Activity Trail)
-- ============================================================================
-- This table records ALL actions taken on investigations.
-- It is APPEND-ONLY and cannot be modified or deleted.
-- Displayed on the investigation ticket as an immutable activity timeline.
CREATE TABLE investigation_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id VARCHAR(255) NOT NULL REFERENCES investigations(investigation_id) ON DELETE CASCADE,

    -- What action was taken
    action VARCHAR(100) NOT NULL,  -- 'disposition_changed', 'priority_changed', 'reopened', 'closed', 'note_added', etc.
    action_category VARCHAR(50) NOT NULL DEFAULT 'general',  -- 'status', 'disposition', 'priority', 'assignment', 'note', 'ai', 'system'

    -- Who performed the action
    actor_type VARCHAR(20) NOT NULL CHECK (actor_type IN ('human', 'ai_agent', 'system')),
    actor_id VARCHAR(255),  -- user_id or agent name
    actor_name VARCHAR(255) NOT NULL,  -- Display name (username or "Riggs")

    -- What changed
    field_changed VARCHAR(100),  -- 'disposition', 'priority', 'state', etc.
    old_value TEXT,  -- Previous value (null for new items)
    new_value TEXT,  -- New value

    -- Context
    reason TEXT,  -- Why the change was made (user-provided or auto-generated)
    summary TEXT NOT NULL,  -- Human-readable summary: "Changed disposition from benign to malicious"

    -- Additional data
    metadata JSONB DEFAULT '{}'::jsonb,  -- Extra context (tool args, AI confidence, etc.)

    -- Timestamp (immutable)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- CRITICAL: Make this table APPEND-ONLY (immutable)
-- No updates or deletes allowed - this is an audit trail
CREATE RULE investigation_audit_no_update AS ON UPDATE TO investigation_audit_log DO INSTEAD NOTHING;
CREATE RULE investigation_audit_no_delete AS ON DELETE TO investigation_audit_log DO INSTEAD NOTHING;

-- Indexes for fast retrieval
CREATE INDEX idx_inv_audit_investigation_id ON investigation_audit_log(investigation_id);
CREATE INDEX idx_inv_audit_action ON investigation_audit_log(action);
CREATE INDEX idx_inv_audit_actor ON investigation_audit_log(actor_id);
CREATE INDEX idx_inv_audit_created_at ON investigation_audit_log(created_at DESC);
CREATE INDEX idx_inv_audit_category ON investigation_audit_log(action_category);

COMMENT ON TABLE investigation_audit_log IS 'Immutable audit trail for investigation actions. Cannot be modified or deleted.';

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Auto-update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_alerts_updated_at 
    BEFORE UPDATE ON alerts 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_investigations_updated_at 
    BEFORE UPDATE ON investigations 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_investigation_notes_updated_at 
    BEFORE UPDATE ON investigation_notes 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Auto-update search_vector for full-text search
CREATE TRIGGER alerts_search_vector_update 
    BEFORE INSERT OR UPDATE ON alerts 
    FOR EACH ROW EXECUTE FUNCTION 
    tsvector_update_trigger(search_vector, 'pg_catalog.english', title, description);

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Function to get alert with investigation info
CREATE OR REPLACE FUNCTION get_alert_with_investigation(alert_uuid UUID)
RETURNS TABLE (
    alert_id VARCHAR,
    title VARCHAR,
    severity VARCHAR,
    status VARCHAR,
    created_at TIMESTAMP WITH TIME ZONE,
    investigation_state VARCHAR,
    investigation_owner VARCHAR
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.alert_id,
        a.title,
        a.severity,
        a.status,
        a.created_at,
        i.state as investigation_state,
        i.owner as investigation_owner
    FROM alerts a
    LEFT JOIN investigations i ON a.investigation_id = i.id
    WHERE a.id = alert_uuid;
END;
$$ LANGUAGE plpgsql;

-- Function to search alerts (full-text + filters)
CREATE OR REPLACE FUNCTION search_alerts(
    search_query TEXT DEFAULT NULL,
    filter_status VARCHAR DEFAULT NULL,
    filter_severity VARCHAR DEFAULT NULL,
    limit_count INTEGER DEFAULT 100
)
RETURNS SETOF alerts AS $$
BEGIN
    RETURN QUERY
    SELECT a.*
    FROM alerts a
    WHERE 
        (search_query IS NULL OR search_vector @@ plainto_tsquery('english', search_query))
        AND (filter_status IS NULL OR a.status = filter_status)
        AND (filter_severity IS NULL OR a.severity = filter_severity)
    ORDER BY a.created_at DESC
    LIMIT limit_count;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- DEFAULT DATA
-- ============================================================================

-- Note: Default users will be created by the application on startup
-- This ensures passwords are properly hashed using bcrypt

-- Insert sample data for testing (optional - remove in production)
-- This is just for initial testing

COMMENT ON TABLE alerts IS 'Primary alert storage with JSONB raw_event for AI reasoning';
COMMENT ON TABLE investigations IS 'Investigation workflow with state machine';
COMMENT ON TABLE users IS 'User accounts with RBAC roles';
COMMENT ON TABLE iocs IS 'Indicator of Compromise tracking';
COMMENT ON TABLE investigation_notes IS 'Notes added during investigation';
COMMENT ON TABLE audit_log IS 'Audit trail for RBAC and compliance';

-- ============================================================================
-- VIEWS
-- ============================================================================

-- View: Alerts with investigation status
CREATE VIEW alerts_with_investigation AS
SELECT 
    a.id,
    a.alert_id,
    a.title,
    a.description,
    a.severity,
    a.status,
    a.source,
    a.created_at,
    a.updated_at,
    CASE 
        WHEN i.id IS NOT NULL THEN TRUE 
        ELSE FALSE 
    END as has_investigation,
    i.investigation_id,
    i.state as investigation_state,
    i.disposition as investigation_disposition,
    i.owner as investigation_owner,
    i.priority as investigation_priority
FROM alerts a
LEFT JOIN investigations i ON a.investigation_id = i.id;

-- View: Investigation summary
CREATE VIEW investigation_summary AS
SELECT 
    i.id,
    i.investigation_id,
    i.state,
    i.disposition,
    i.priority,
    i.owner,
    i.alert_title,
    i.created_at,
    i.updated_at,
    a.alert_id,
    a.severity as alert_severity,
    a.status as alert_status,
    COUNT(n.id) as note_count
FROM investigations i
LEFT JOIN alerts a ON i.alert_id = a.id
LEFT JOIN investigation_notes n ON i.investigation_id = n.investigation_id
GROUP BY i.id, i.investigation_id, i.state, i.disposition, i.priority, 
         i.owner, i.alert_title, i.created_at, i.updated_at, 
         a.alert_id, a.severity, a.status;

-- ============================================================================
-- GRANTS (adjust based on your security requirements)
-- ============================================================================

-- Grant permissions to application user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO agentcore;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO agentcore;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO agentcore;

-- ============================================================================
-- ============================================================================
-- INTEGRATIONS TABLE
-- Stores configuration for external threat intel providers
-- ============================================================================
CREATE TABLE integrations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    integration_id VARCHAR(100) UNIQUE NOT NULL,
    
    -- Provider info
    provider VARCHAR(100) NOT NULL, -- 'virustotal', 'otx', 'threatfox', etc.
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL CHECK (category IN (
        'threat_intel', 'sandbox', 'siem', 'edr', 'ticketing', 'communication', 'enrichment', 'vulnerability', 'identity', 'network', 'case_management', 'custom'
    )),
    
    -- Connection details
    base_url VARCHAR(500),
    auth_type VARCHAR(50) CHECK (auth_type IN ('api_key', 'oauth', 'basic_auth', 'none')),
    
    -- Configuration (JSONB for flexibility)
    config JSONB DEFAULT '{}',
    
    -- Status
    enabled BOOLEAN DEFAULT TRUE,
    verified BOOLEAN DEFAULT FALSE,
    last_verified_at TIMESTAMP WITH TIME ZONE,
    
    -- Rate limiting
    rate_limit_per_minute INTEGER DEFAULT 4,
    rate_limit_per_day INTEGER DEFAULT 500,
    
    -- Metadata
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE,
    usage_count INTEGER DEFAULT 0
);

CREATE INDEX idx_integrations_provider ON integrations(provider);
CREATE INDEX idx_integrations_category ON integrations(category);
CREATE INDEX idx_integrations_enabled ON integrations(enabled);

-- ============================================================================
-- INTEGRATION_CREDENTIALS TABLE
-- Secure storage for API keys and credentials
-- ============================================================================
CREATE TABLE integration_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    integration_id UUID NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    
    -- Credential data (encrypted in application layer)
    credential_type VARCHAR(50) NOT NULL, -- 'api_key', 'username_password', 'oauth_token'
    api_key TEXT,
    username VARCHAR(255),
    password_encrypted TEXT,
    oauth_token TEXT,
    oauth_refresh_token TEXT,
    oauth_expires_at TIMESTAMP WITH TIME ZONE,
    
    -- Additional fields
    additional_fields JSONB DEFAULT '{}',
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_rotated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_integration_credentials_integration ON integration_credentials(integration_id);

-- ============================================================================
-- ENRICHMENT_CACHE TABLE
-- Cache enrichment results to avoid redundant API calls
-- ============================================================================
CREATE TABLE enrichment_cache (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    
    -- IOC identifiers
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'hash', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email')),
    ioc_value VARCHAR(500) NOT NULL,

    -- Source
    provider VARCHAR(100) NOT NULL,
    
    -- Enrichment data
    enrichment_data JSONB NOT NULL,
    
    -- Reputation scoring
    is_malicious BOOLEAN,
    threat_score INTEGER CHECK (threat_score >= 0 AND threat_score <= 100),
    confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
    
    -- Cache metadata
    cached_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    hit_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_enrichment_cache_ioc ON enrichment_cache(ioc_type, ioc_value);
CREATE INDEX idx_enrichment_cache_provider ON enrichment_cache(provider);
CREATE INDEX idx_enrichment_cache_expires ON enrichment_cache(expires_at);
CREATE INDEX idx_enrichment_cache_malicious ON enrichment_cache(is_malicious) WHERE is_malicious = TRUE;

-- UNIQUE constraint required for ON CONFLICT upsert in threat_intel_service.py
CREATE UNIQUE INDEX idx_enrichment_cache_unique ON enrichment_cache(ioc_type, ioc_value, provider);

-- ============================================================================
-- ENRICHMENT_JOBS TABLE
-- Track bulk enrichment jobs
-- ============================================================================
CREATE TABLE enrichment_jobs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    job_id VARCHAR(100) UNIQUE NOT NULL,
    
    -- Job details
    job_type VARCHAR(50) NOT NULL CHECK (job_type IN ('alert', 'investigation', 'bulk', 'scheduled')),
    resource_id VARCHAR(255), -- alert_id or investigation_id
    
    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'running', 'completed', 'failed', 'cancelled'
    )),
    
    -- Progress
    total_iocs INTEGER DEFAULT 0,
    processed_iocs INTEGER DEFAULT 0,
    failed_iocs INTEGER DEFAULT 0,
    
    -- Results
    results JSONB DEFAULT '{}',
    error_message TEXT,
    
    -- Metadata
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_enrichment_jobs_status ON enrichment_jobs(status);
CREATE INDEX idx_enrichment_jobs_resource ON enrichment_jobs(resource_id);
CREATE INDEX idx_enrichment_jobs_created ON enrichment_jobs(created_at DESC);

-- ============================================================================
-- AI_AGENTS TABLE
-- Configurable AI agents with personalities
-- ============================================================================
CREATE TABLE ai_agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(100) UNIQUE NOT NULL,
    
    -- Agent identity
    name VARCHAR(100) NOT NULL,  -- e.g., "Aaron"
    user_name VARCHAR(100) NOT NULL,  -- Display name
    level INTEGER NOT NULL CHECK (level IN (1, 2, 3)),  -- SOC level
    display_name VARCHAR(200),  -- Computed: "Aaron SOC 1 AI"
    
    -- AI Configuration
    provider VARCHAR(50) NOT NULL CHECK (provider IN ('claude', 'lmstudio', 'openai', 'custom')),
    model VARCHAR(200) NOT NULL,  -- Model name
    system_prompt TEXT NOT NULL,  -- Custom personality/instructions
    
    -- Connection details
    endpoint_url VARCHAR(500),  -- For LM Studio or custom endpoints
    
    -- Status
    enabled BOOLEAN DEFAULT TRUE,
    verified BOOLEAN DEFAULT FALSE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    usage_count INTEGER DEFAULT 0,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ai_agents_level ON ai_agents(level);
CREATE INDEX idx_ai_agents_provider ON ai_agents(provider);
CREATE INDEX idx_ai_agents_enabled ON ai_agents(enabled);

-- ============================================================================
-- AI_AGENT_CREDENTIALS TABLE
-- Separate credentials storage for AI agents
-- ============================================================================
CREATE TABLE ai_agent_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    
    -- Credentials (encrypted in application layer)
    api_key TEXT,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_rotated_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_ai_agent_credentials_agent ON ai_agent_credentials(agent_id);

-- ============================================================================
-- AI_AGENT_ACTIVITY TABLE
-- Track which agent worked on which investigation
-- ============================================================================
CREATE TABLE ai_agent_activity (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(100) NOT NULL,  -- References ai_agents.agent_id
    investigation_id VARCHAR(255),
    alert_id VARCHAR(255),
    
    -- Activity details
    activity_type VARCHAR(50) NOT NULL CHECK (activity_type IN (
        'l1_triage', 'l2_investigation', 'enrichment_decision', 'response_assessment'
    )),
    
    -- Results
    result JSONB,
    confidence DECIMAL(3,2),
    duration_seconds INTEGER,
    
    -- Status
    status VARCHAR(50) NOT NULL CHECK (status IN ('started', 'completed', 'error')),
    error_message TEXT,
    
    -- Timestamps
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_ai_agent_activity_agent ON ai_agent_activity(agent_id);
CREATE INDEX idx_ai_agent_activity_investigation ON ai_agent_activity(investigation_id);
CREATE INDEX idx_ai_agent_activity_type ON ai_agent_activity(activity_type);
CREATE INDEX idx_ai_agent_activity_started ON ai_agent_activity(started_at DESC);

-- ============================================================================
-- API KEYS TABLE
-- For programmatic access to the platform
-- ============================================================================
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'analyst', 'read_only', 'user')),
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE,
    enabled BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_api_keys_key_id ON api_keys(key_id);
CREATE INDEX idx_api_keys_enabled ON api_keys(enabled);

-- ============================================================================
-- WEBHOOKS TABLE
-- ============================================================================
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    endpoint_path VARCHAR(255) NOT NULL,
    token VARCHAR(255),
    enabled BOOLEAN DEFAULT TRUE,
    rate_limit INTEGER DEFAULT 100,
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_triggered TIMESTAMP WITH TIME ZONE,
    trigger_count INTEGER DEFAULT 0
);

CREATE INDEX idx_webhooks_name ON webhooks(name);
CREATE INDEX idx_webhooks_enabled ON webhooks(enabled);

-- ============================================================================
-- CREDENTIALS TABLE (for storing integration credentials)
-- ============================================================================
CREATE TABLE credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    auth_type VARCHAR(50) NOT NULL DEFAULT 'api_key',
    encrypted_value TEXT NOT NULL,
    integration_name VARCHAR(100),
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_credentials_name ON credentials(name);
CREATE INDEX idx_credentials_integration ON credentials(integration_name);

-- ============================================================================
-- CREDENTIALS VAULT TABLE
-- Secure storage for integration credentials with encryption
-- ============================================================================
CREATE TABLE IF NOT EXISTS credentials_vault (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    credential_id VARCHAR(100) UNIQUE NOT NULL,
    
    -- Basic info
    name VARCHAR(100) NOT NULL,
    description TEXT,
    auth_type VARCHAR(50) NOT NULL CHECK (auth_type IN (
        'api_key', 'bearer', 'basic', 'oauth2_client', 
        'oauth2_token', 'aws', 'custom_header', 'none'
    )),
    
    -- API Key config (non-sensitive)
    api_key_header VARCHAR(100),
    api_key_prefix VARCHAR(50),
    api_key_location VARCHAR(20),
    
    -- Basic Auth (non-sensitive parts)
    username VARCHAR(255),
    
    -- OAuth2 (non-sensitive parts)
    client_id VARCHAR(255),
    token_url TEXT,
    scope TEXT,
    
    -- AWS (non-sensitive parts)
    aws_access_key_id VARCHAR(255),
    aws_region VARCHAR(50),
    aws_service VARCHAR(100),
    
    -- Custom headers (names only)
    custom_header_names JSONB,
    
    -- Encrypted secrets blob (all sensitive data)
    encrypted_secrets TEXT NOT NULL,
    
    -- Relationships
    tags JSONB DEFAULT '[]',
    integration_ids JSONB DEFAULT '[]',
    
    -- Metadata
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_credentials_vault_id ON credentials_vault(credential_id);
CREATE INDEX idx_credentials_vault_name ON credentials_vault(name);
CREATE INDEX idx_credentials_vault_auth_type ON credentials_vault(auth_type);
CREATE INDEX idx_credentials_vault_tags ON credentials_vault USING GIN (tags);
CREATE INDEX idx_credentials_vault_integrations ON credentials_vault USING GIN (integration_ids);

-- ============================================================================
-- DISCOVERED_APIS TABLE
-- Cache of discovered APIs from various catalogs
-- ============================================================================
CREATE TABLE IF NOT EXISTS discovered_apis (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- API identification
    api_id VARCHAR(500) UNIQUE NOT NULL,  -- Unique ID from source (e.g., "apis_guru:crowdstrike.com:1.0.0")
    name VARCHAR(255) NOT NULL,
    description TEXT,
    provider VARCHAR(255) NOT NULL,
    version VARCHAR(100),

    -- Classification
    category VARCHAR(100),
    tags JSONB DEFAULT '[]',

    -- Source info
    source VARCHAR(50) NOT NULL CHECK (source IN (
        'apis_guru', 'swaggerhub', 'github', 'rapidapi', 'direct', 'manual'
    )),
    openapi_url TEXT NOT NULL,
    documentation_url TEXT,
    logo_url TEXT,

    -- Metadata
    popularity_score INTEGER DEFAULT 0,
    last_updated_upstream TIMESTAMP WITH TIME ZONE,

    -- Import status
    imported BOOLEAN DEFAULT FALSE,
    imported_integration_id VARCHAR(100),  -- If imported, the resulting integration ID
    imported_at TIMESTAMP WITH TIME ZONE,

    -- Cache metadata
    discovered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_refreshed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_discovered_apis_api_id ON discovered_apis(api_id);
CREATE INDEX idx_discovered_apis_name ON discovered_apis(name);
CREATE INDEX idx_discovered_apis_provider ON discovered_apis(provider);
CREATE INDEX idx_discovered_apis_source ON discovered_apis(source);
CREATE INDEX idx_discovered_apis_category ON discovered_apis(category);
CREATE INDEX idx_discovered_apis_imported ON discovered_apis(imported);
CREATE INDEX idx_discovered_apis_tags ON discovered_apis USING GIN (tags);

-- Full text search on discovered APIs
ALTER TABLE discovered_apis ADD COLUMN IF NOT EXISTS search_vector tsvector;
CREATE INDEX IF NOT EXISTS idx_discovered_apis_search ON discovered_apis USING GIN (search_vector);

CREATE OR REPLACE FUNCTION update_discovered_apis_search_vector()
RETURNS TRIGGER AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        COALESCE(NEW.name, '') || ' ' ||
        COALESCE(NEW.description, '') || ' ' ||
        COALESCE(NEW.provider, '') || ' ' ||
        COALESCE(NEW.category, '')
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS discovered_apis_search_update ON discovered_apis;
CREATE TRIGGER discovered_apis_search_update
    BEFORE INSERT OR UPDATE ON discovered_apis
    FOR EACH ROW EXECUTE FUNCTION update_discovered_apis_search_vector();

-- ============================================================================
-- INTEGRATION_UPDATE_SCHEDULES TABLE
-- Manage weekly auto-updates for integrations
-- ============================================================================
CREATE TABLE IF NOT EXISTS integration_update_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Integration reference
    integration_id VARCHAR(100) UNIQUE NOT NULL,

    -- OpenAPI source for updates
    openapi_spec_url TEXT NOT NULL,

    -- Schedule configuration
    enabled BOOLEAN DEFAULT TRUE,
    update_frequency VARCHAR(50) DEFAULT 'weekly' CHECK (update_frequency IN (
        'daily', 'weekly', 'monthly', 'manual'
    )),
    day_of_week INTEGER DEFAULT 0 CHECK (day_of_week >= 0 AND day_of_week <= 6),  -- 0=Sunday
    time_of_day TIME DEFAULT '03:00:00',  -- Run at 3 AM

    -- Update tracking
    last_check_at TIMESTAMP WITH TIME ZONE,
    last_update_at TIMESTAMP WITH TIME ZONE,
    last_update_status VARCHAR(50) CHECK (last_update_status IN (
        'success', 'failed', 'no_changes', 'pending'
    )),
    last_update_error TEXT,

    -- Change detection
    last_spec_hash VARCHAR(64),  -- SHA256 of last spec content
    actions_added INTEGER DEFAULT 0,
    actions_removed INTEGER DEFAULT 0,
    actions_modified INTEGER DEFAULT 0,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_integration_update_schedules_integration ON integration_update_schedules(integration_id);
CREATE INDEX idx_integration_update_schedules_enabled ON integration_update_schedules(enabled);
CREATE INDEX idx_integration_update_schedules_frequency ON integration_update_schedules(update_frequency);

-- ============================================================================
-- INTEGRATION_UPDATE_HISTORY TABLE
-- History of all integration updates
-- ============================================================================
CREATE TABLE IF NOT EXISTS integration_update_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Integration reference
    integration_id VARCHAR(100) NOT NULL,

    -- Update details
    update_type VARCHAR(50) NOT NULL CHECK (update_type IN (
        'scheduled', 'manual', 'initial_import'
    )),
    status VARCHAR(50) NOT NULL CHECK (status IN (
        'success', 'failed', 'partial', 'no_changes'
    )),

    -- Changes made
    spec_url TEXT,
    previous_version VARCHAR(100),
    new_version VARCHAR(100),
    actions_before INTEGER,
    actions_after INTEGER,
    actions_added JSONB DEFAULT '[]',  -- List of action IDs added
    actions_removed JSONB DEFAULT '[]',  -- List of action IDs removed
    actions_modified JSONB DEFAULT '[]',  -- List of action IDs modified

    -- Error tracking
    error_message TEXT,
    error_details JSONB,

    -- Metadata
    triggered_by VARCHAR(100),  -- 'scheduler', 'user:username', etc.
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER
);

CREATE INDEX idx_integration_update_history_integration ON integration_update_history(integration_id);
CREATE INDEX idx_integration_update_history_status ON integration_update_history(status);
CREATE INDEX idx_integration_update_history_type ON integration_update_history(update_type);
CREATE INDEX idx_integration_update_history_started ON integration_update_history(started_at DESC);

-- ============================================================================
-- AI_TOKEN_USAGE TABLE
-- Track token usage for all AI provider calls
-- ============================================================================
CREATE TABLE IF NOT EXISTS ai_token_usage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Request identification
    request_id VARCHAR(100) NOT NULL,

    -- Provider information
    provider VARCHAR(50) NOT NULL,  -- 'lmstudio', 'openai', 'claude', 'gemini', 'ollama', 'azure_openai'
    model VARCHAR(255) NOT NULL,
    integration_id VARCHAR(100),  -- Reference to integration if applicable

    -- Token counts
    prompt_tokens INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,

    -- Cost estimation (optional, in USD cents)
    estimated_cost_cents DECIMAL(10, 4) DEFAULT 0,

    -- Request details
    endpoint VARCHAR(500),
    request_type VARCHAR(50),  -- 'chat', 'completion', 'embedding', 'triage', 'investigation'

    -- Context
    investigation_id VARCHAR(100),  -- If related to an investigation
    alert_id VARCHAR(100),  -- If related to an alert
    user_id VARCHAR(100),  -- User who initiated the request
    agent_id VARCHAR(100),  -- AI agent ID if applicable

    -- Response metadata
    status VARCHAR(20) NOT NULL DEFAULT 'success' CHECK (status IN ('success', 'failed', 'timeout', 'rate_limited')),
    response_time_ms INTEGER,
    error_message TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ai_token_usage_provider ON ai_token_usage(provider);
CREATE INDEX idx_ai_token_usage_model ON ai_token_usage(model);
CREATE INDEX idx_ai_token_usage_created ON ai_token_usage(created_at DESC);
CREATE INDEX idx_ai_token_usage_investigation ON ai_token_usage(investigation_id);
CREATE INDEX idx_ai_token_usage_user ON ai_token_usage(user_id);
CREATE INDEX idx_ai_token_usage_status ON ai_token_usage(status);

-- Daily aggregation view for quick stats
CREATE OR REPLACE VIEW ai_token_usage_daily AS
SELECT
    DATE(created_at) as usage_date,
    provider,
    model,
    COUNT(*) as request_count,
    SUM(prompt_tokens) as total_prompt_tokens,
    SUM(completion_tokens) as total_completion_tokens,
    SUM(total_tokens) as total_tokens,
    SUM(estimated_cost_cents) as total_cost_cents,
    AVG(response_time_ms) as avg_response_time_ms,
    COUNT(CASE WHEN status = 'success' THEN 1 END) as successful_requests,
    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_requests
FROM ai_token_usage
GROUP BY DATE(created_at), provider, model
ORDER BY usage_date DESC, provider, model;

-- Monthly aggregation view
CREATE OR REPLACE VIEW ai_token_usage_monthly AS
SELECT
    DATE_TRUNC('month', created_at) as usage_month,
    provider,
    model,
    COUNT(*) as request_count,
    SUM(prompt_tokens) as total_prompt_tokens,
    SUM(completion_tokens) as total_completion_tokens,
    SUM(total_tokens) as total_tokens,
    SUM(estimated_cost_cents) as total_cost_cents,
    AVG(response_time_ms) as avg_response_time_ms
FROM ai_token_usage
GROUP BY DATE_TRUNC('month', created_at), provider, model
ORDER BY usage_month DESC, provider, model;

-- ============================================================================
-- CLUSTER & HA TABLES (Phase 0: Deployment Architecture)
-- ============================================================================

-- Node registration for cluster awareness
CREATE TABLE IF NOT EXISTS cluster_nodes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id VARCHAR(100) NOT NULL UNIQUE,
    hostname VARCHAR(255),
    ip_address INET,
    port INTEGER DEFAULT 8000,
    node_role VARCHAR(30) DEFAULT 'worker' CHECK (node_role IN ('worker', 'scheduler', 'all')),
    status VARCHAR(20) DEFAULT 'starting' CHECK (status IN ('starting', 'healthy', 'unhealthy', 'draining', 'stopped')),
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    version VARCHAR(50),
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_cluster_nodes_status ON cluster_nodes(status);
CREATE INDEX idx_cluster_nodes_heartbeat ON cluster_nodes(last_heartbeat);

-- Distributed locks for leader election and singleton tasks
CREATE TABLE IF NOT EXISTS distributed_locks (
    lock_name VARCHAR(100) PRIMARY KEY,
    holder_node_id VARCHAR(100) NOT NULL,
    acquired_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX idx_distributed_locks_expires ON distributed_locks(expires_at);

-- Job queue for background processing (alternative to Redis)
CREATE TABLE IF NOT EXISTS job_queue (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    queue_name VARCHAR(100) NOT NULL,
    job_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL,
    priority INTEGER DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed', 'dead')),
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    scheduled_for TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    locked_by VARCHAR(100),
    locked_until TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    result JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Partial index for pending jobs (most common query)
CREATE INDEX idx_job_queue_pending ON job_queue(queue_name, priority, scheduled_for)
    WHERE status = 'pending';
-- Index for stuck job cleanup
CREATE INDEX idx_job_queue_locked ON job_queue(locked_until)
    WHERE status = 'processing';
-- Index for job history queries
CREATE INDEX idx_job_queue_completed ON job_queue(completed_at DESC)
    WHERE status IN ('completed', 'failed', 'dead');
CREATE INDEX idx_job_queue_type ON job_queue(job_type, status);

-- Cluster-wide configuration store
CREATE TABLE IF NOT EXISTS cluster_config (
    key VARCHAR(255) PRIMARY KEY,
    value JSONB NOT NULL,
    description TEXT,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(100)
);

-- Function to acquire a distributed lock
CREATE OR REPLACE FUNCTION acquire_lock(
    p_lock_name VARCHAR(100),
    p_node_id VARCHAR(100),
    p_ttl_seconds INTEGER DEFAULT 60
) RETURNS BOOLEAN AS $$
DECLARE
    v_acquired BOOLEAN := FALSE;
BEGIN
    -- Try to insert new lock or update expired lock
    INSERT INTO distributed_locks (lock_name, holder_node_id, expires_at)
    VALUES (p_lock_name, p_node_id, CURRENT_TIMESTAMP + (p_ttl_seconds || ' seconds')::INTERVAL)
    ON CONFLICT (lock_name) DO UPDATE
    SET holder_node_id = p_node_id,
        acquired_at = CURRENT_TIMESTAMP,
        expires_at = CURRENT_TIMESTAMP + (p_ttl_seconds || ' seconds')::INTERVAL
    WHERE distributed_locks.expires_at < CURRENT_TIMESTAMP
       OR distributed_locks.holder_node_id = p_node_id;

    -- Check if we got the lock
    SELECT holder_node_id = p_node_id INTO v_acquired
    FROM distributed_locks
    WHERE lock_name = p_lock_name;

    RETURN COALESCE(v_acquired, FALSE);
END;
$$ LANGUAGE plpgsql;

-- Function to release a distributed lock
CREATE OR REPLACE FUNCTION release_lock(
    p_lock_name VARCHAR(100),
    p_node_id VARCHAR(100)
) RETURNS BOOLEAN AS $$
DECLARE
    v_released BOOLEAN := FALSE;
BEGIN
    DELETE FROM distributed_locks
    WHERE lock_name = p_lock_name
      AND holder_node_id = p_node_id;

    GET DIAGNOSTICS v_released = ROW_COUNT;
    RETURN v_released > 0;
END;
$$ LANGUAGE plpgsql;

-- Function to claim a job from the queue
-- FIFO ordering: priority ASC (highest priority first), then created_at ASC (oldest first)
CREATE OR REPLACE FUNCTION claim_job(
    p_queue_name VARCHAR(100),
    p_node_id VARCHAR(100),
    p_lock_seconds INTEGER DEFAULT 300
) RETURNS UUID AS $$
DECLARE
    v_job_id UUID;
BEGIN
    -- Find and lock an available job
    -- Order by: priority (lowest number = highest priority), then created_at (FIFO within same priority)
    UPDATE job_queue
    SET status = 'processing',
        locked_by = p_node_id,
        locked_until = CURRENT_TIMESTAMP + (p_lock_seconds || ' seconds')::INTERVAL,
        started_at = CURRENT_TIMESTAMP,
        attempts = attempts + 1
    WHERE id = (
        SELECT id FROM job_queue
        WHERE queue_name = p_queue_name
          AND status = 'pending'
          AND scheduled_for <= CURRENT_TIMESTAMP
        ORDER BY priority ASC, created_at ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id INTO v_job_id;

    RETURN v_job_id;
END;
$$ LANGUAGE plpgsql;

-- Function to complete a job
CREATE OR REPLACE FUNCTION complete_job(
    p_job_id UUID,
    p_result JSONB DEFAULT NULL
) RETURNS BOOLEAN AS $$
BEGIN
    UPDATE job_queue
    SET status = 'completed',
        completed_at = CURRENT_TIMESTAMP,
        result = p_result,
        locked_by = NULL,
        locked_until = NULL
    WHERE id = p_job_id;

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- Function to fail a job (with retry logic)
CREATE OR REPLACE FUNCTION fail_job(
    p_job_id UUID,
    p_error_message TEXT
) RETURNS BOOLEAN AS $$
DECLARE
    v_attempts INTEGER;
    v_max_attempts INTEGER;
BEGIN
    SELECT attempts, max_attempts INTO v_attempts, v_max_attempts
    FROM job_queue WHERE id = p_job_id;

    IF v_attempts >= v_max_attempts THEN
        -- Move to dead letter
        UPDATE job_queue
        SET status = 'dead',
            error_message = p_error_message,
            completed_at = CURRENT_TIMESTAMP,
            locked_by = NULL,
            locked_until = NULL
        WHERE id = p_job_id;
    ELSE
        -- Retry with exponential backoff
        UPDATE job_queue
        SET status = 'pending',
            error_message = p_error_message,
            scheduled_for = CURRENT_TIMESTAMP + ((2 ^ v_attempts) || ' minutes')::INTERVAL,
            locked_by = NULL,
            locked_until = NULL
        WHERE id = p_job_id;
    END IF;

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql;

-- Clean up stale node registrations and expired locks
CREATE OR REPLACE FUNCTION cleanup_cluster_state() RETURNS void AS $$
BEGIN
    -- Mark nodes with stale heartbeats as unhealthy
    UPDATE cluster_nodes
    SET status = 'unhealthy'
    WHERE last_heartbeat < CURRENT_TIMESTAMP - INTERVAL '2 minutes'
      AND status = 'healthy';

    -- Remove very old stopped nodes
    DELETE FROM cluster_nodes
    WHERE status = 'stopped'
      AND last_heartbeat < CURRENT_TIMESTAMP - INTERVAL '1 day';

    -- Release expired locks
    DELETE FROM distributed_locks
    WHERE expires_at < CURRENT_TIMESTAMP;

    -- Reset stuck jobs (processing but lock expired)
    UPDATE job_queue
    SET status = 'pending',
        locked_by = NULL,
        locked_until = NULL
    WHERE status = 'processing'
      AND locked_until < CURRENT_TIMESTAMP;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- IOC WHITELIST TABLE
-- IOCs that should NOT be enriched (benign, internal, or known-good)
-- ============================================================================
CREATE TABLE IF NOT EXISTS ioc_whitelist (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- IOC details
    ioc_value VARCHAR(500) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN (
        'ip', 'domain', 'url', 'hash', 'hash_md5', 'hash_sha1', 'hash_sha256',
        'email', 'username', 'hostname', 'file_path', 'cve', 'mitre_attack'
    )),

    -- Reason for whitelisting
    reason VARCHAR(500),
    category VARCHAR(50) CHECK (category IN (
        'internal',           -- Internal infrastructure (internal IPs, domains)
        'trusted_vendor',     -- Known-good vendor/partner
        'false_positive',     -- Previously flagged as FP
        'business_critical',  -- Business-critical service that shouldn't be flagged
        'cdn_provider',       -- CDN/cloud provider IPs
        'security_tool',      -- Security tool infrastructure
        'other'
    )),

    -- Pattern matching (optional - for wildcards like *.internal.company.com)
    is_pattern BOOLEAN DEFAULT FALSE,
    pattern_type VARCHAR(20) CHECK (pattern_type IN ('exact', 'prefix', 'suffix', 'contains', 'regex')),

    -- Metadata
    added_by VARCHAR(100),
    notes TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,  -- Optional expiration
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Unique constraint
    UNIQUE(ioc_value, ioc_type)
);

CREATE INDEX idx_ioc_whitelist_value ON ioc_whitelist(ioc_value);
CREATE INDEX idx_ioc_whitelist_type ON ioc_whitelist(ioc_type);
CREATE INDEX idx_ioc_whitelist_category ON ioc_whitelist(category);
CREATE INDEX idx_ioc_whitelist_expires ON ioc_whitelist(expires_at) WHERE expires_at IS NOT NULL;

-- ============================================================================
-- THREAT FEEDS TABLE
-- Configuration for external threat intelligence feeds
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_feeds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    feed_id VARCHAR(100) UNIQUE NOT NULL,

    -- Feed identification
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL CHECK (category IN (
        'ip_blocklist',     -- IP reputation/blocklists (Abuse.ch, Blocklist.de)
        'domain_blocklist', -- Malicious domains
        'url_blocklist',    -- Malicious URLs (URLhaus, PhishTank)
        'hash_list',        -- Malware hashes (MalwareBazaar)
        'mixed',            -- Multiple IOC types
        'cve',              -- Vulnerability feeds (CISA KEV)
        'other'
    )),

    -- Feed source
    url TEXT NOT NULL,
    format VARCHAR(50) NOT NULL CHECK (format IN (
        'txt_lines',        -- Plain text, one IOC per line
        'csv',              -- CSV format
        'json',             -- JSON format
        'json_lines',       -- JSON Lines (one JSON object per line)
        'stix',             -- STIX 2.x format
        'misp',             -- MISP format
        'custom'            -- Requires custom parser
    )),
    parser_config JSONB DEFAULT '{}',  -- Parser-specific config (delimiter, fields, etc.)

    -- Polling configuration
    enabled BOOLEAN DEFAULT TRUE,
    poll_interval_minutes INTEGER DEFAULT 60,
    last_poll_at TIMESTAMP WITH TIME ZONE,
    next_poll_at TIMESTAMP WITH TIME ZONE,

    -- Rate limiting
    max_iocs_per_poll INTEGER DEFAULT 10000,  -- Prevent overwhelming with huge feeds

    -- Polling status
    last_poll_status VARCHAR(50) CHECK (last_poll_status IN (
        'success', 'failed', 'partial', 'pending'
    )),
    last_poll_error TEXT,
    last_poll_ioc_count INTEGER DEFAULT 0,
    total_iocs_ingested INTEGER DEFAULT 0,

    -- Guardrails
    drop_private_ips BOOLEAN DEFAULT TRUE,       -- Drop RFC1918/RFC4193 addresses
    drop_internal_domains BOOLEAN DEFAULT TRUE,  -- Drop .local, .corp, .internal
    dedupe_window_hours INTEGER DEFAULT 24,      -- Don't re-ingest same IOC within window

    -- Metadata
    tags JSONB DEFAULT '[]',
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_threat_feeds_feed_id ON threat_feeds(feed_id);
CREATE INDEX idx_threat_feeds_category ON threat_feeds(category);
CREATE INDEX idx_threat_feeds_enabled ON threat_feeds(enabled);
CREATE INDEX idx_threat_feeds_next_poll ON threat_feeds(next_poll_at) WHERE enabled = TRUE;

-- ============================================================================
-- THREAT FEED INGESTION LOG
-- Track each poll attempt and results
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_feed_ingestion_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    feed_id VARCHAR(100) NOT NULL,

    -- Poll details
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,

    -- Results
    status VARCHAR(50) NOT NULL CHECK (status IN (
        'success', 'failed', 'partial'
    )),
    iocs_fetched INTEGER DEFAULT 0,
    iocs_new INTEGER DEFAULT 0,
    iocs_updated INTEGER DEFAULT 0,
    iocs_skipped INTEGER DEFAULT 0,  -- Duplicates, private IPs, etc.

    -- Error tracking
    error_message TEXT,
    error_details JSONB,

    -- Feed snapshot (for debugging)
    response_size_bytes INTEGER,
    sample_iocs JSONB DEFAULT '[]'  -- Store first 5 IOCs for debugging
);

CREATE INDEX idx_threat_feed_log_feed ON threat_feed_ingestion_log(feed_id);
CREATE INDEX idx_threat_feed_log_started ON threat_feed_ingestion_log(started_at DESC);
CREATE INDEX idx_threat_feed_log_status ON threat_feed_ingestion_log(status);

-- ============================================================================
-- IOC FEED APPEARANCES TABLE
-- Track which feeds an IOC has appeared in (for smart re-enrichment)
-- ============================================================================
CREATE TABLE IF NOT EXISTS ioc_feed_appearances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ioc_value VARCHAR(500) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL,
    feed_id VARCHAR(100) NOT NULL,

    -- Appearance tracking
    first_seen_in_feed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen_in_feed TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    times_seen INTEGER DEFAULT 1,

    -- Unique constraint per IOC per feed
    UNIQUE(ioc_value, ioc_type, feed_id)
);

CREATE INDEX idx_ioc_feed_appearances_ioc ON ioc_feed_appearances(ioc_value, ioc_type);
CREATE INDEX idx_ioc_feed_appearances_feed ON ioc_feed_appearances(feed_id);
CREATE INDEX idx_ioc_feed_appearances_last_seen ON ioc_feed_appearances(last_seen_in_feed DESC);

-- ============================================================================
-- AGENT DEFINITIONS TABLE (New Agent Framework)
-- Enterprise-grade AI agent configuration with enforced authority
-- ============================================================================
CREATE TABLE IF NOT EXISTS agent_definitions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Identity (Cosmetic)
    tier INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
    focus VARCHAR(100) NOT NULL,  -- Alert, Identity, Endpoint, Network, Cloud, Email
    role VARCHAR(100) NOT NULL,   -- Triage, Investigation, Response
    system_name VARCHAR(255) NOT NULL,  -- Auto-generated: "Tier {tier} {focus} {role} Agent"
    codename VARCHAR(100),        -- Optional custom alias (cosmetic only)
    description TEXT,

    -- Authority (Enforced) - stored as JSONB for flexibility
    permissions JSONB NOT NULL DEFAULT '{
        "applications": [],
        "max_actions_per_run": 50,
        "require_approval": true,
        "approval_timeout_minutes": 30
    }',

    -- Guardrails (Safety)
    guardrails JSONB NOT NULL DEFAULT '{
        "confidence_threshold": 0.6,
        "never_rules": [],
        "escalation_triggers": [],
        "allowed_hours": {"enabled": false},
        "rate_limits": {
            "max_investigations_per_hour": 30,
            "max_actions_per_investigation": 50,
            "max_enrichments_per_minute": 20,
            "cooldown_after_destructive_action": 300
        }
    }',

    -- AI Configuration
    model_config JSONB NOT NULL DEFAULT '{
        "provider": "anthropic",
        "model": "claude-sonnet-4-20250514",
        "temperature": 0.1,
        "max_tokens_per_task": 8000,
        "max_cost_per_run": 2.00,
        "context_window": 64000
    }',

    -- Audit Configuration
    audit_config JSONB NOT NULL DEFAULT '{
        "log_level": "standard",
        "require_reasoning": true,
        "evidence_retention_days": 90
    }',

    -- Status
    enabled BOOLEAN DEFAULT true,

    -- Metadata
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    version VARCHAR(20) DEFAULT '1.0.0'
);

CREATE INDEX idx_agent_definitions_tier ON agent_definitions(tier);
CREATE INDEX idx_agent_definitions_focus ON agent_definitions(focus);
CREATE INDEX idx_agent_definitions_enabled ON agent_definitions(enabled);
CREATE INDEX idx_agent_definitions_system_name ON agent_definitions(system_name);
CREATE INDEX idx_agent_definitions_permissions ON agent_definitions USING GIN (permissions);
CREATE INDEX idx_agent_definitions_guardrails ON agent_definitions USING GIN (guardrails);

-- Trigger to auto-generate system_name
CREATE OR REPLACE FUNCTION generate_agent_system_name()
RETURNS TRIGGER AS $$
BEGIN
    NEW.system_name := 'Tier ' || NEW.tier || ' ' || NEW.focus || ' ' || NEW.role || ' Agent';
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER agent_definitions_system_name
    BEFORE INSERT OR UPDATE ON agent_definitions
    FOR EACH ROW EXECUTE FUNCTION generate_agent_system_name();

-- ============================================================================
-- AGENT EXECUTIONS TABLE
-- Track each agent run with full audit trail
-- ============================================================================
CREATE TABLE IF NOT EXISTS agent_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id VARCHAR(100) UNIQUE NOT NULL,
    agent_id UUID NOT NULL REFERENCES agent_definitions(id) ON DELETE CASCADE,

    -- Trigger information
    trigger_type VARCHAR(50) NOT NULL CHECK (trigger_type IN (
        'alert', 'scheduled', 'manual', 'escalation', 'webhook'
    )),
    trigger_source_id VARCHAR(255),  -- alert_id, schedule_id, user_id, etc.
    trigger_source_type VARCHAR(100),

    -- Execution status
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'running', 'paused', 'awaiting_approval',
        'completed', 'failed', 'cancelled', 'timeout'
    )),

    -- Timing
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,

    -- Reasoning chain (full audit trail)
    reasoning JSONB DEFAULT '[]',

    -- Evidence collected
    evidence JSONB DEFAULT '[]',

    -- Actions taken
    actions JSONB DEFAULT '[]',

    -- Outcome
    outcome JSONB DEFAULT '{
        "verdict": null,
        "confidence": null,
        "summary": null,
        "recommendations": []
    }',

    -- Compliance tracking
    compliance JSONB DEFAULT '{
        "actions_attempted": 0,
        "actions_completed": 0,
        "actions_blocked": 0,
        "guardrails_triggered": [],
        "approvals_requested": 0,
        "approvals_granted": 0
    }',

    -- Cost tracking
    tokens_used INTEGER DEFAULT 0,
    cost_usd DECIMAL(10, 4) DEFAULT 0,

    -- Error handling
    error_message TEXT,
    error_details JSONB,

    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_agent_executions_agent ON agent_executions(agent_id);
CREATE INDEX idx_agent_executions_status ON agent_executions(status);
CREATE INDEX idx_agent_executions_trigger ON agent_executions(trigger_type, trigger_source_id);
CREATE INDEX idx_agent_executions_started ON agent_executions(started_at DESC);
CREATE INDEX idx_agent_executions_execution_id ON agent_executions(execution_id);

-- ============================================================================
-- AGENT ACTION LOG TABLE
-- Immutable audit log of all agent actions
-- ============================================================================
CREATE TABLE IF NOT EXISTS agent_action_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID NOT NULL REFERENCES agent_executions(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agent_definitions(id) ON DELETE CASCADE,

    -- Action details
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(100),
    target_id VARCHAR(255),
    action_type VARCHAR(50) NOT NULL CHECK (action_type IN ('read', 'write', 'destructive')),

    -- Status
    status VARCHAR(50) NOT NULL CHECK (status IN (
        'attempted', 'completed', 'blocked', 'pending_approval', 'approved', 'denied', 'failed'
    )),

    -- Approval tracking
    required_approval BOOLEAN DEFAULT false,
    approved_by VARCHAR(255),
    approved_at TIMESTAMP WITH TIME ZONE,

    -- Guardrail tracking
    blocked_by_guardrail VARCHAR(255),
    guardrail_rule TEXT,

    -- Reasoning
    reasoning TEXT,
    confidence DECIMAL(3, 2),

    -- Result
    result JSONB,
    error_message TEXT,

    -- Timing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER
);

-- READ-ONLY enforcement: No UPDATE or DELETE allowed (immutable audit trail)
CREATE RULE agent_action_log_no_update AS ON UPDATE TO agent_action_log DO INSTEAD NOTHING;
CREATE RULE agent_action_log_no_delete AS ON DELETE TO agent_action_log DO INSTEAD NOTHING;

CREATE INDEX idx_agent_action_log_execution ON agent_action_log(execution_id);
CREATE INDEX idx_agent_action_log_agent ON agent_action_log(agent_id);
CREATE INDEX idx_agent_action_log_action ON agent_action_log(action);
CREATE INDEX idx_agent_action_log_status ON agent_action_log(status);
CREATE INDEX idx_agent_action_log_created ON agent_action_log(created_at DESC);

-- ============================================================================
-- AGENT APPROVAL REQUESTS TABLE
-- Human-in-the-loop approval queue
-- ============================================================================
CREATE TABLE IF NOT EXISTS agent_approval_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    request_id VARCHAR(100) UNIQUE NOT NULL,
    execution_id UUID NOT NULL REFERENCES agent_executions(id) ON DELETE CASCADE,
    agent_id UUID NOT NULL REFERENCES agent_definitions(id) ON DELETE CASCADE,
    action_log_id UUID REFERENCES agent_action_log(id),

    -- Action details
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(100),
    target_id VARCHAR(255),
    action_type VARCHAR(50) NOT NULL,

    -- Context for approver
    reasoning TEXT NOT NULL,
    confidence DECIMAL(3, 2),
    evidence JSONB DEFAULT '[]',
    risk_assessment TEXT,

    -- Status
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'approved', 'denied', 'expired', 'cancelled'
    )),

    -- Response
    responded_by VARCHAR(255),
    responded_at TIMESTAMP WITH TIME ZONE,
    response_note TEXT,

    -- Timing
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Notification tracking
    notified_users JSONB DEFAULT '[]',
    notification_sent_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_agent_approval_requests_status ON agent_approval_requests(status);
CREATE INDEX idx_agent_approval_requests_execution ON agent_approval_requests(execution_id);
CREATE INDEX idx_agent_approval_requests_agent ON agent_approval_requests(agent_id);
CREATE INDEX idx_agent_approval_requests_expires ON agent_approval_requests(expires_at) WHERE status = 'pending';
CREATE INDEX idx_agent_approval_requests_request_id ON agent_approval_requests(request_id);

-- ============================================================================
-- AGENT ROLLBACK ACTIONS TABLE
-- Enables "undo" functionality for reversible agent actions
-- ============================================================================
CREATE TABLE IF NOT EXISTS agent_rollback_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    execution_id UUID NOT NULL REFERENCES agent_executions(id) ON DELETE CASCADE,
    original_action_id VARCHAR(100) NOT NULL,
    original_action_type VARCHAR(100) NOT NULL,

    -- Target of the action
    target_type VARCHAR(100) NOT NULL,
    target_id VARCHAR(500) NOT NULL,

    -- Rollback configuration
    rollback_method VARCHAR(100) NOT NULL,
    rollback_params JSONB DEFAULT '{}',

    -- Timing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Execution status
    executed_at TIMESTAMP WITH TIME ZONE,
    executed_by VARCHAR(255),
    success BOOLEAN,
    result JSONB,
    execution_note TEXT
);

CREATE INDEX idx_agent_rollback_execution ON agent_rollback_actions(execution_id);
CREATE INDEX idx_agent_rollback_target ON agent_rollback_actions(target_type, target_id);
CREATE INDEX idx_agent_rollback_expires ON agent_rollback_actions(expires_at) WHERE executed_at IS NULL;
CREATE INDEX idx_agent_rollback_pending ON agent_rollback_actions(created_at DESC) WHERE executed_at IS NULL;

-- ============================================================================
-- AGENT TEMPLATES TABLE
-- Pre-built agent configurations for common use cases
-- ============================================================================
CREATE TABLE IF NOT EXISTS agent_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    template_id VARCHAR(100) UNIQUE NOT NULL,

    -- Template info
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),  -- 'starter', 'advanced', 'enterprise', 'community'

    -- Template configuration (same structure as agent_definitions)
    tier INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
    focus VARCHAR(100) NOT NULL,
    role VARCHAR(100) NOT NULL,
    permissions JSONB NOT NULL,
    guardrails JSONB NOT NULL,
    model_config JSONB NOT NULL,
    audit_config JSONB NOT NULL,

    -- Usage tracking
    usage_count INTEGER DEFAULT 0,

    -- Metadata
    is_default BOOLEAN DEFAULT false,
    is_public BOOLEAN DEFAULT true,
    created_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_agent_templates_tier ON agent_templates(tier);
CREATE INDEX idx_agent_templates_category ON agent_templates(category);
CREATE INDEX idx_agent_templates_is_default ON agent_templates(is_default);

-- ============================================================================
-- Insert default agent templates
-- ============================================================================
INSERT INTO agent_templates (template_id, name, description, category, tier, focus, role, permissions, guardrails, model_config, audit_config, is_default)
VALUES
(
    'tier1-alert-triage',
    'Tier 1 Alert Triage Agent',
    'Monitors incoming alerts, enriches IOCs, and prioritizes for analyst review. Read-only with enrichment capabilities.',
    'starter',
    1,
    'Alert',
    'Triage',
    '{
        "applications": [
            {"id": "siem", "name": "SIEM Platform", "actions": [
                {"action": "read_alerts", "type": "read"},
                {"action": "read_events", "type": "read"},
                {"action": "add_comment", "type": "write", "requires_approval": false}
            ]},
            {"id": "threat_intel", "name": "Threat Intelligence", "actions": [
                {"action": "lookup_ioc", "type": "read"},
                {"action": "lookup_reputation", "type": "read"}
            ]}
        ],
        "max_actions_per_run": 50,
        "require_approval": false,
        "approval_timeout_minutes": 30
    }',
    '{
        "confidence_threshold": 0.3,
        "never_rules": [
            "Never modify alert severity without evidence",
            "Never close alerts automatically",
            "Never enrich private/RFC1918 IP addresses against external sources"
        ],
        "escalation_triggers": [
            "Confidence score below 0.5",
            "Alert involves executive/VIP user",
            "Multiple correlated alerts detected"
        ],
        "allowed_hours": {"enabled": false},
        "rate_limits": {
            "max_investigations_per_hour": 100,
            "max_actions_per_investigation": 20,
            "max_enrichments_per_minute": 30,
            "cooldown_after_destructive_action": 0
        }
    }',
    '{
        "provider": "anthropic",
        "model": "claude-sonnet-4-20250514",
        "temperature": 0.1,
        "max_tokens_per_task": 4000,
        "max_cost_per_run": 0.50,
        "context_window": 32000
    }',
    '{
        "log_level": "standard",
        "require_reasoning": true,
        "evidence_retention_days": 90
    }',
    true
),
(
    'tier2-identity-investigation',
    'Tier 2 Identity Investigation Agent',
    'Investigates identity-related alerts, correlates authentication events, and builds investigation timelines.',
    'starter',
    2,
    'Identity',
    'Investigation',
    '{
        "applications": [
            {"id": "siem", "name": "SIEM Platform", "actions": [
                {"action": "read_alerts", "type": "read"},
                {"action": "read_events", "type": "read"},
                {"action": "update_alert_status", "type": "write"},
                {"action": "add_comment", "type": "write"},
                {"action": "add_tags", "type": "write"}
            ]},
            {"id": "identity_provider", "name": "Identity Provider", "actions": [
                {"action": "read_user_profile", "type": "read"},
                {"action": "read_auth_logs", "type": "read"},
                {"action": "read_mfa_status", "type": "read"}
            ]},
            {"id": "ticketing", "name": "Ticketing System", "actions": [
                {"action": "read_tickets", "type": "read"},
                {"action": "create_ticket", "type": "write"},
                {"action": "update_ticket", "type": "write"}
            ]}
        ],
        "max_actions_per_run": 100,
        "require_approval": false,
        "approval_timeout_minutes": 60
    }',
    '{
        "confidence_threshold": 0.6,
        "never_rules": [
            "Never disable or lock user accounts",
            "Never reset passwords or MFA",
            "Never modify group memberships",
            "Never access executive accounts without explicit approval"
        ],
        "escalation_triggers": [
            "Compromised credential confirmed",
            "Lateral movement detected",
            "Service account involved",
            "Admin/privileged account involved"
        ],
        "allowed_hours": {"enabled": false},
        "rate_limits": {
            "max_investigations_per_hour": 30,
            "max_actions_per_investigation": 50,
            "max_enrichments_per_minute": 20,
            "cooldown_after_destructive_action": 300
        }
    }',
    '{
        "provider": "anthropic",
        "model": "claude-sonnet-4-20250514",
        "temperature": 0.2,
        "max_tokens_per_task": 8000,
        "max_cost_per_run": 2.00,
        "context_window": 64000
    }',
    '{
        "log_level": "verbose",
        "require_reasoning": true,
        "evidence_retention_days": 365
    }',
    true
),
(
    'tier3-endpoint-response',
    'Tier 3 Endpoint Response Agent',
    'Executes endpoint containment and remediation actions with full audit trail and rollback capability.',
    'starter',
    3,
    'Endpoint',
    'Response',
    '{
        "applications": [
            {"id": "siem", "name": "SIEM Platform", "actions": [
                {"action": "read_alerts", "type": "read"},
                {"action": "update_alert_status", "type": "write"},
                {"action": "close_alert", "type": "write", "requires_approval": true}
            ]},
            {"id": "edr", "name": "EDR Platform", "actions": [
                {"action": "read_detections", "type": "read"},
                {"action": "read_process_tree", "type": "read"},
                {"action": "isolate_host", "type": "destructive", "requires_approval": true, "denied_targets": ["domain-controllers"]},
                {"action": "quarantine_file", "type": "destructive", "requires_approval": true},
                {"action": "kill_process", "type": "destructive", "requires_approval": true}
            ]},
            {"id": "firewall", "name": "Firewall", "actions": [
                {"action": "read_rules", "type": "read"},
                {"action": "block_ip", "type": "destructive", "requires_approval": true, "allowed_targets": ["external-ips-only"]}
            ]}
        ],
        "max_actions_per_run": 25,
        "require_approval": true,
        "approval_timeout_minutes": 15
    }',
    '{
        "confidence_threshold": 0.85,
        "never_rules": [
            "Never isolate domain controllers",
            "Never isolate more than 3 hosts without human approval",
            "Never block internal IP ranges",
            "Never execute arbitrary scripts",
            "Never delete files (quarantine only)"
        ],
        "escalation_triggers": [
            "Ransomware indicators detected",
            "Data exfiltration suspected",
            "Nation-state TTPs identified",
            "Multiple hosts affected (>3)",
            "Critical asset involved"
        ],
        "allowed_hours": {"enabled": false},
        "rate_limits": {
            "max_investigations_per_hour": 10,
            "max_actions_per_investigation": 15,
            "max_enrichments_per_minute": 10,
            "cooldown_after_destructive_action": 600
        }
    }',
    '{
        "provider": "anthropic",
        "model": "claude-sonnet-4-20250514",
        "temperature": 0.0,
        "max_tokens_per_task": 12000,
        "max_cost_per_run": 5.00,
        "context_window": 100000
    }',
    '{
        "log_level": "verbose",
        "require_reasoning": true,
        "evidence_retention_days": 730
    }',
    true
)
ON CONFLICT (template_id) DO NOTHING;

-- ============================================================================
-- SMART ENRICHMENT ENGINE TABLES
-- ============================================================================

-- Enrichment Priority Queue - tracks IOCs awaiting enrichment with priority scoring
CREATE TABLE IF NOT EXISTS enrichment_priority_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_value VARCHAR(500) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL,

    -- Priority (1 = highest, 10 = lowest)
    calculated_priority INTEGER NOT NULL DEFAULT 5 CHECK (calculated_priority >= 1 AND calculated_priority <= 10),

    -- Priority factors breakdown (for transparency and debugging)
    priority_factors JSONB DEFAULT '{}',
    -- Example: {"severity": 1, "cache_state": 2, "feed_reappear": 1, "investigation": 0, "total": 4}

    -- Trigger info
    trigger_type VARCHAR(50) NOT NULL DEFAULT 'manual',
    -- Values: manual, auto_initial, feed_reappear, scheduled, investigation, cache_expiry, severity_escalation
    trigger_source VARCHAR(255),  -- alert_id, investigation_id, feed_name, etc.

    -- Status tracking
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    -- Values: pending, processing, completed, failed, cancelled

    -- Provider targeting (optional - null means all available providers)
    target_providers TEXT[],

    -- Scheduling
    scheduled_for TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    delay_reason VARCHAR(255),  -- e.g., "rate_limit_backoff", "provider_cooldown"

    -- Processing metadata
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    last_attempt_at TIMESTAMP WITH TIME ZONE,
    last_error TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Prevent duplicate queue entries (partial unique index)
CREATE UNIQUE INDEX IF NOT EXISTS idx_enrichment_queue_unique_pending ON enrichment_priority_queue(ioc_value, ioc_type) WHERE status IN ('pending', 'processing');
CREATE INDEX IF NOT EXISTS idx_enrichment_queue_priority ON enrichment_priority_queue(calculated_priority, status) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_enrichment_queue_status ON enrichment_priority_queue(status);
CREATE INDEX IF NOT EXISTS idx_enrichment_queue_scheduled ON enrichment_priority_queue(scheduled_for) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_enrichment_queue_ioc ON enrichment_priority_queue(ioc_value, ioc_type);

-- Integration Rate Limits - tracks API usage per provider for smart scheduling
CREATE TABLE IF NOT EXISTS integration_rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    integration_id VARCHAR(100) NOT NULL UNIQUE,

    -- Current usage counters
    minute_requests INTEGER DEFAULT 0,
    daily_requests INTEGER DEFAULT 0,

    -- Reset timestamps
    minute_reset_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    day_reset_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP + INTERVAL '1 day',

    -- Configured limits (cached from integration config)
    minute_limit INTEGER DEFAULT 60,
    daily_limit INTEGER DEFAULT 1000,

    -- Rate limit error tracking
    last_429_error TIMESTAMP WITH TIME ZONE,
    consecutive_429_count INTEGER DEFAULT 0,
    backoff_until TIMESTAMP WITH TIME ZONE,

    -- Performance metrics
    avg_response_time_ms INTEGER,
    success_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_rate_limits_backoff ON integration_rate_limits(backoff_until) WHERE backoff_until IS NOT NULL;

-- Enrichment Health Metrics - time-series data for monitoring and dashboards
CREATE TABLE IF NOT EXISTS enrichment_health_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider VARCHAR(100) NOT NULL,
    measurement_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Performance metrics
    avg_response_time_ms DECIMAL(10,2),
    p95_response_time_ms DECIMAL(10,2),
    success_rate DECIMAL(5,2) CHECK (success_rate >= 0 AND success_rate <= 100),
    error_count INTEGER DEFAULT 0,
    timeout_count INTEGER DEFAULT 0,

    -- Rate limiting
    requests_this_hour INTEGER DEFAULT 0,
    requests_today INTEGER DEFAULT 0,
    quota_remaining_percent DECIMAL(5,2),

    -- Cache efficiency
    cache_hit_count INTEGER DEFAULT 0,
    cache_miss_count INTEGER DEFAULT 0,
    cache_hit_rate DECIMAL(5,2),

    -- Queue stats
    pending_queue_size INTEGER DEFAULT 0,
    avg_queue_wait_seconds DECIMAL(10,2),

    -- Unique per provider per measurement period (hourly)
    UNIQUE(provider, measurement_time)
);

CREATE INDEX idx_health_metrics_provider ON enrichment_health_metrics(provider, measurement_time DESC);
CREATE INDEX idx_health_metrics_time ON enrichment_health_metrics(measurement_time DESC);

-- ============================================================================
-- EXCLUSION_LIST TABLE (Phase 2.1)
-- IOCs to exclude from enrichment (RFC1918, internal, false positives)
-- ============================================================================
CREATE TABLE IF NOT EXISTS exclusion_list (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- IOC details
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'email', 'hash', 'cidr', 'regex')),
    ioc_value TEXT NOT NULL,
    match_type VARCHAR(20) DEFAULT 'exact' CHECK (match_type IN ('exact', 'prefix', 'suffix', 'contains', 'cidr', 'regex')),

    -- Classification
    reason TEXT,
    category VARCHAR(50) DEFAULT 'internal' CHECK (category IN ('internal', 'vendor', 'false_positive', 'whitelist', 'custom')),

    -- Metadata
    added_by VARCHAR(100),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    hit_count INTEGER DEFAULT 0,
    last_hit_at TIMESTAMP WITH TIME ZONE,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(ioc_type, ioc_value, match_type)
);

CREATE INDEX idx_exclusion_type ON exclusion_list(ioc_type);
CREATE INDEX idx_exclusion_active ON exclusion_list(is_active) WHERE is_active = true;
CREATE INDEX idx_exclusion_expires ON exclusion_list(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_exclusion_category ON exclusion_list(category);

-- ============================================================================
-- ENRICHMENT_QUEUE TABLE (Phase 2.5)
-- Background enrichment queue for async processing
-- ============================================================================
CREATE TABLE IF NOT EXISTS enrichment_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- IOC details
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'hash', 'url', 'email')),
    ioc_value TEXT NOT NULL,

    -- Processing priority and status
    priority INTEGER DEFAULT 5 CHECK (priority >= 1 AND priority <= 10), -- 1=highest, 10=lowest
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'complete', 'failed', 'skipped')),

    -- Source tracking
    source_event_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    source_investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,

    -- Processing state
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    last_error TEXT,
    skip_reason TEXT, -- why it was skipped (e.g., "excluded", "cached")

    -- Results
    result_id UUID REFERENCES enrichment_cache(id) ON DELETE SET NULL,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    next_retry_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_enrichment_q_status ON enrichment_queue(status, priority);
CREATE INDEX IF NOT EXISTS idx_enrichment_q_source ON enrichment_queue(source_event_id);
CREATE INDEX IF NOT EXISTS idx_enrichment_q_pending ON enrichment_queue(status, created_at) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_enrichment_q_retry ON enrichment_queue(next_retry_at) WHERE status = 'failed' AND attempts < max_attempts;

-- ============================================================================
-- DEDUPE_CONFIG TABLE (Phase 2.4)
-- Alert deduplication rules configuration
-- ============================================================================
CREATE TABLE IF NOT EXISTS dedupe_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Rule identity
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    enabled BOOLEAN DEFAULT true,

    -- Matching criteria
    source_filter VARCHAR(200), -- regex/glob pattern for alert source
    category_filter VARCHAR(200), -- filter by category
    severity_filter VARCHAR(100)[], -- array of severities to apply rule to

    -- Fingerprint fields to use for deduplication
    fingerprint_fields TEXT[] NOT NULL DEFAULT ARRAY['source', 'category', 'title'],

    -- Time window for deduplication
    window_minutes INTEGER DEFAULT 60, -- group duplicates within this window

    -- Actions
    action VARCHAR(50) DEFAULT 'group' CHECK (action IN ('group', 'suppress', 'merge', 'count_only')),

    -- Priority (lower = higher priority, applied first)
    priority INTEGER DEFAULT 100,

    -- Stats
    total_matches INTEGER DEFAULT 0,
    duplicates_suppressed INTEGER DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX idx_dedupe_config_enabled ON dedupe_config(enabled, priority);

-- ============================================================================
-- ALERT_GROUPS TABLE (Phase 2.4)
-- Groups of deduplicated alerts
-- ============================================================================
CREATE TABLE IF NOT EXISTS alert_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Group identity
    fingerprint VARCHAR(64) NOT NULL, -- SHA-256 hash of key fields

    -- Primary alert
    primary_alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE,

    -- Dedup rule that created this group
    dedupe_config_id UUID REFERENCES dedupe_config(id) ON DELETE SET NULL,

    -- Group stats
    alert_count INTEGER DEFAULT 1,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'resolved', 'expired')),

    UNIQUE(fingerprint)
);

CREATE INDEX idx_alert_groups_fingerprint ON alert_groups(fingerprint);
CREATE INDEX idx_alert_groups_primary ON alert_groups(primary_alert_id);
CREATE INDEX idx_alert_groups_status ON alert_groups(status, last_seen DESC);

-- ============================================================================
-- ALTER ALERTS TABLE for deduplication (Phase 2.4)
-- Add fingerprint and dedup columns
-- ============================================================================
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS fingerprint_fields TEXT[];
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS alert_group_id UUID REFERENCES alert_groups(id) ON DELETE SET NULL;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS is_primary BOOLEAN DEFAULT true;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS duplicate_count INTEGER DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS first_seen TIMESTAMP WITH TIME ZONE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP WITH TIME ZONE;

-- Additional status values for alerts (triaged, enriched)
ALTER TABLE alerts DROP CONSTRAINT IF EXISTS alerts_status_check;
ALTER TABLE alerts ADD CONSTRAINT alerts_status_check CHECK (status IN ('open', 'investigating', 'resolved', 'closed', 'triaged', 'enriched'));

-- AI verdict fields for alerts
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_verdict VARCHAR(50);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_confidence DECIMAL(5,2);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_reasoning TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS enrichment_status VARCHAR(20) DEFAULT 'pending' CHECK (enrichment_status IN ('pending', 'processing', 'complete', 'failed', 'skipped'));
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS enrichment_summary JSONB DEFAULT '{}'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS ai_summary TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolution VARCHAR(255);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS disposition VARCHAR(50);

CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint) WHERE fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_group ON alerts(alert_group_id) WHERE alert_group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_alerts_enrichment ON alerts(enrichment_status);

-- ============================================================================
-- SEED DEFAULT EXCLUSIONS (RFC1918, Loopback, Link-local)
-- ============================================================================
INSERT INTO exclusion_list (ioc_type, ioc_value, match_type, reason, category, added_by) VALUES
    ('cidr', '10.0.0.0/8', 'cidr', 'RFC1918 Private Class A', 'internal', 'system'),
    ('cidr', '172.16.0.0/12', 'cidr', 'RFC1918 Private Class B', 'internal', 'system'),
    ('cidr', '192.168.0.0/16', 'cidr', 'RFC1918 Private Class C', 'internal', 'system'),
    ('cidr', '127.0.0.0/8', 'cidr', 'Loopback', 'internal', 'system'),
    ('cidr', '169.254.0.0/16', 'cidr', 'Link-local (APIPA)', 'internal', 'system'),
    ('ip', '::1', 'exact', 'IPv6 Loopback', 'internal', 'system'),
    ('cidr', 'fe80::/10', 'cidr', 'IPv6 Link-local', 'internal', 'system'),
    ('cidr', 'fc00::/7', 'cidr', 'IPv6 Unique Local Address', 'internal', 'system'),
    ('domain', 'localhost', 'exact', 'Localhost domain', 'internal', 'system'),
    ('domain', '*.local', 'regex', 'Local domains', 'internal', 'system'),
    ('domain', '*.internal', 'regex', 'Internal domains', 'internal', 'system'),
    ('domain', '*.lan', 'regex', 'LAN domains', 'internal', 'system'),
    ('domain', '*.corp', 'regex', 'Corporate domains', 'internal', 'system')
ON CONFLICT (ioc_type, ioc_value, match_type) DO NOTHING;

-- ============================================================================
-- ALERT_IOC_LINKS TABLE (Phase 2.5)
-- Links IOCs extracted from alerts for correlation
-- ============================================================================
CREATE TABLE IF NOT EXISTS alert_ioc_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Alert reference (by alert_id string, not UUID for flexibility)
    alert_id VARCHAR(255) NOT NULL,

    -- IOC details
    ioc_value VARCHAR(500) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email', 'cve')),

    -- Extraction metadata
    extraction_method VARCHAR(50) DEFAULT 'regex',
    extraction_source VARCHAR(100), -- field path where IOC was found

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(alert_id, ioc_value, ioc_type)
);

CREATE INDEX idx_alert_ioc_links_alert ON alert_ioc_links(alert_id);
CREATE INDEX idx_alert_ioc_links_ioc ON alert_ioc_links(ioc_value, ioc_type);
CREATE INDEX idx_alert_ioc_links_created ON alert_ioc_links(created_at DESC);

-- ============================================================================
-- CORRELATION_RULES TABLE (Phase 2.5)
-- Rules for detecting patterns across alerts
-- ============================================================================
CREATE TABLE IF NOT EXISTS correlation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Rule identity
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Rule configuration
    rule_type VARCHAR(50) NOT NULL CHECK (rule_type IN ('ioc_match', 'time_window', 'host_pattern', 'user_pattern', 'technique_match', 'severity_chain', 'custom')),
    parameters JSONB DEFAULT '{}'::jsonb,

    -- Execution
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 100,
    auto_create_campaign BOOLEAN DEFAULT false,

    -- Statistics
    trigger_count INTEGER DEFAULT 0,
    last_triggered_at TIMESTAMP WITH TIME ZONE,

    -- Metadata
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_correlation_rules_enabled ON correlation_rules(enabled, priority);
CREATE INDEX idx_correlation_rules_type ON correlation_rules(rule_type);

-- ============================================================================
-- CORRELATION_EVENTS TABLE (Phase 2.5)
-- Log of correlation events when rules trigger
-- ============================================================================
CREATE TABLE IF NOT EXISTS correlation_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Rule reference
    rule_id UUID REFERENCES correlation_rules(id) ON DELETE SET NULL,
    rule_name VARCHAR(255),

    -- Correlation details
    correlation_type VARCHAR(50),
    correlation_score DECIMAL(5,2),

    -- Matched items
    alert_ids UUID[],
    ioc_values TEXT[],

    -- Campaign if created
    campaign_id UUID,

    -- Action taken
    action_taken VARCHAR(50),

    -- Details
    details JSONB DEFAULT '{}'::jsonb,

    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_correlation_events_rule ON correlation_events(rule_id);
CREATE INDEX idx_correlation_events_campaign ON correlation_events(campaign_id);
CREATE INDEX idx_correlation_events_created ON correlation_events(created_at DESC);

-- ============================================================================
-- CAMPAIGNS TABLE (Phase 2.5)
-- Groups of related alerts/IOCs representing attack campaigns
-- ============================================================================
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Campaign identity
    campaign_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Classification
    campaign_type VARCHAR(50) DEFAULT 'unknown' CHECK (campaign_type IN ('apt', 'ransomware', 'phishing', 'malware', 'botnet', 'data_exfil', 'lateral_movement', 'credential_theft', 'unknown')),
    severity VARCHAR(20) DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence DECIMAL(5,2) DEFAULT 70.0,

    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'investigating', 'contained', 'resolved', 'false_positive')),

    -- Statistics
    alert_count INTEGER DEFAULT 0,
    ioc_count INTEGER DEFAULT 0,

    -- MITRE mapping
    mitre_techniques TEXT[],

    -- Metadata
    created_by VARCHAR(100),
    assigned_to VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_campaigns_status ON campaigns(status);
CREATE INDEX idx_campaigns_type ON campaigns(campaign_type);
CREATE INDEX idx_campaigns_activity ON campaigns(last_activity DESC);

-- ============================================================================
-- CAMPAIGN_MEMBERS TABLE (Phase 2.5)
-- Alerts and investigations linked to campaigns
-- ============================================================================
CREATE TABLE IF NOT EXISTS campaign_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Campaign reference
    campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,

    -- Member reference
    member_type VARCHAR(20) NOT NULL CHECK (member_type IN ('alert', 'investigation')),
    alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE,
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,

    -- Correlation info
    added_by VARCHAR(100),
    correlation_reason TEXT,
    correlation_score DECIMAL(5,2),

    -- Timestamp
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_campaign_members_campaign ON campaign_members(campaign_id);
CREATE INDEX idx_campaign_members_alert ON campaign_members(alert_id);

-- ============================================================================
-- CAMPAIGN_IOCS TABLE (Phase 2.5)
-- IOCs associated with campaigns
-- ============================================================================
CREATE TABLE IF NOT EXISTS campaign_iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Campaign reference
    campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,

    -- IOC details
    ioc_value VARCHAR(500) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL,

    -- Statistics
    occurrence_count INTEGER DEFAULT 1,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Confidence
    confidence DECIMAL(5,2) DEFAULT 70.0,

    UNIQUE(campaign_id, ioc_value, ioc_type)
);

CREATE INDEX idx_campaign_iocs_campaign ON campaign_iocs(campaign_id);
CREATE INDEX idx_campaign_iocs_ioc ON campaign_iocs(ioc_value, ioc_type);

-- ============================================================================
-- IOC_FEED_APPEARANCES TABLE (Phase 2.5)
-- Track when IOCs appear in threat feeds
-- ============================================================================
-- Note: ioc_feed_appearances table already defined earlier in schema

-- Insert default correlation rules
INSERT INTO correlation_rules (rule_id, name, description, rule_type, parameters, enabled, priority, auto_create_campaign) VALUES
    ('rule-ioc-repeat-3', 'Repeated IOC (3+ alerts)', 'Triggers when the same IOC appears in 3 or more alerts within 24 hours', 'ioc_match',
     '{"min_occurrences": 3, "ioc_types": ["ip", "domain", "hash_sha256"], "time_window_hours": 24}'::jsonb,
     true, 100, true),
    ('rule-host-multi-alert', 'Multi-Alert Host', 'Triggers when a host has 3+ different alert types within 24 hours', 'host_pattern',
     '{"min_alert_types": 3, "time_window_hours": 24}'::jsonb,
     true, 90, true),
    ('rule-event-burst', 'Event Burst', 'Triggers when 10+ events occur within 5 minutes from same source', 'time_window',
     '{"window_minutes": 5, "min_events": 10, "group_by": ["source_ip"]}'::jsonb,
     true, 80, false),
    ('rule-technique-match', 'MITRE Technique Match', 'Triggers when 2+ alerts share the same MITRE ATT&CK technique within 48 hours', 'technique_match',
     '{"min_occurrences": 2, "time_window_hours": 48}'::jsonb,
     true, 85, true),
    ('rule-severity-escalation', 'Severity Escalation', 'Triggers when alerts from the same source show severity escalation (low->medium->high)', 'severity_chain',
     '{"time_window_hours": 24, "min_escalations": 2, "group_by": "source_ip"}'::jsonb,
     true, 95, true)
ON CONFLICT (rule_id) DO NOTHING;

-- ============================================================================
-- ACTION REQUESTS TABLE (Phase 5 - Agent Actions)
-- ============================================================================
-- Action requests allow agents to request response actions that require human approval
CREATE TABLE action_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Action identification
    request_id VARCHAR(100) UNIQUE NOT NULL DEFAULT ('ACT-' || upper(substring(gen_random_uuid()::text from 1 for 8))),
    action_type VARCHAR(50) NOT NULL,  -- contain_host, isolate_host, block_ip, disable_user, etc.

    -- Target information
    target_type VARCHAR(50) NOT NULL,  -- host, ip, user, domain, hash, etc.
    target_value TEXT NOT NULL,
    target_metadata JSONB DEFAULT '{}'::jsonb,  -- Additional target info (hostname, asset_id, etc.)

    -- Integration to execute action
    integration_id UUID,  -- FK to integrations table
    integration_name VARCHAR(100),  -- e.g., 'crowdstrike', 'microsoft_defender'
    integration_action_id VARCHAR(100),  -- e.g., 'contain_host', 'isolate_machine'

    -- Action parameters
    parameters JSONB DEFAULT '{}'::jsonb,

    -- Request context
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    requested_by_agent UUID REFERENCES agent_definitions(id) ON DELETE SET NULL,
    requested_by_human VARCHAR(100),  -- If manually requested

    -- Status tracking
    status VARCHAR(30) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending',          -- Awaiting approval
        'approved',         -- Approved, ready to execute
        'denied',           -- Denied by human
        'executing',        -- Currently executing
        'completed',        -- Successfully executed
        'failed',           -- Execution failed
        'expired',          -- Auto-expired without action
        'cancelled'         -- Manually cancelled
    )),

    -- Priority and timing
    priority VARCHAR(20) DEFAULT 'medium' CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    expires_at TIMESTAMP WITH TIME ZONE,  -- Auto-expire if not approved by this time

    -- Approval tracking
    approved_by VARCHAR(100),
    approved_at TIMESTAMP WITH TIME ZONE,
    denied_by VARCHAR(100),
    denied_at TIMESTAMP WITH TIME ZONE,
    denial_reason TEXT,

    -- Execution tracking
    executed_at TIMESTAMP WITH TIME ZONE,
    execution_result JSONB,  -- Response from integration
    error_message TEXT,

    -- Rollback capability
    is_reversible BOOLEAN DEFAULT false,
    rollback_action_type VARCHAR(50),  -- e.g., 'un-contain_host'
    rolled_back_at TIMESTAMP WITH TIME ZONE,
    rolled_back_by VARCHAR(100),

    -- Agent reasoning
    reasoning TEXT,  -- Why the agent requested this action
    confidence DECIMAL(3,2) CHECK (confidence >= 0 AND confidence <= 1),
    evidence JSONB DEFAULT '[]'::jsonb,  -- IOCs, findings that led to request

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for action_requests
CREATE INDEX idx_action_requests_status ON action_requests(status);
CREATE INDEX idx_action_requests_priority ON action_requests(priority, status);
CREATE INDEX idx_action_requests_investigation ON action_requests(investigation_id);
CREATE INDEX idx_action_requests_agent ON action_requests(requested_by_agent);
CREATE INDEX idx_action_requests_target ON action_requests(target_type, target_value);
CREATE INDEX idx_action_requests_expires ON action_requests(expires_at) WHERE status = 'pending';
CREATE INDEX idx_action_requests_created ON action_requests(created_at);

-- ============================================================================
-- ACTION TYPES REFERENCE TABLE
-- ============================================================================
-- Defines available action types and their integration mappings
CREATE TABLE action_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    action_type VARCHAR(50) UNIQUE NOT NULL,  -- e.g., 'contain_host'
    display_name VARCHAR(100) NOT NULL,       -- e.g., 'Contain Host'
    description TEXT,
    category VARCHAR(50) NOT NULL,            -- containment, isolation, block, disable, etc.

    -- Target requirements
    target_type VARCHAR(50) NOT NULL,         -- host, ip, user, domain, hash

    -- Risk and approval
    risk_level VARCHAR(20) DEFAULT 'high' CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    requires_approval BOOLEAN DEFAULT true,
    approval_timeout_minutes INTEGER DEFAULT 240,  -- 4 hours default

    -- Reversibility
    is_reversible BOOLEAN DEFAULT false,
    reverse_action_type VARCHAR(50),          -- FK to self for rollback action

    -- Integration mappings (which integrations support this action)
    integration_mappings JSONB DEFAULT '{}'::jsonb,
    -- Example: {"crowdstrike": "contain_host", "microsoft_defender": "isolate_machine"}

    -- Tier permissions (which agent tiers can request this)
    min_agent_tier INTEGER DEFAULT 2,

    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_action_types_category ON action_types(category);
CREATE INDEX idx_action_types_target ON action_types(target_type);

-- Seed default action types
INSERT INTO action_types (action_type, display_name, description, category, target_type, risk_level, requires_approval, is_reversible, reverse_action_type, integration_mappings, min_agent_tier) VALUES
    -- Host containment actions
    ('contain_host', 'Contain Host', 'Isolate host from network while maintaining management access', 'containment', 'host', 'high', true, true, 'un-contain_host',
     '{"crowdstrike": "contain_host", "microsoft_defender": "isolate_machine", "sentinelone": "disconnect_agent"}'::jsonb, 2),
    ('un-contain_host', 'Release Host', 'Remove network containment from host', 'containment', 'host', 'medium', true, false, NULL,
     '{"crowdstrike": "lift_containment", "microsoft_defender": "release_isolation", "sentinelone": "reconnect_agent"}'::jsonb, 2),

    -- Network blocking actions
    ('block_ip', 'Block IP Address', 'Add IP to firewall/EDR block list', 'block', 'ip', 'medium', true, true, 'unblock_ip',
     '{"crowdstrike": "add_ioc_block", "palo_alto": "add_block_rule"}'::jsonb, 2),
    ('unblock_ip', 'Unblock IP Address', 'Remove IP from block list', 'block', 'ip', 'low', true, false, NULL,
     '{"crowdstrike": "remove_ioc_block", "palo_alto": "remove_block_rule"}'::jsonb, 2),
    ('block_domain', 'Block Domain', 'Add domain to DNS/proxy block list', 'block', 'domain', 'medium', true, true, 'unblock_domain',
     '{"crowdstrike": "add_ioc_block", "zscaler": "add_url_block"}'::jsonb, 2),
    ('unblock_domain', 'Unblock Domain', 'Remove domain from block list', 'block', 'domain', 'low', true, false, NULL,
     '{"crowdstrike": "remove_ioc_block", "zscaler": "remove_url_block"}'::jsonb, 2),

    -- User actions
    ('disable_user', 'Disable User Account', 'Disable user account in identity provider', 'disable', 'user', 'high', true, true, 'enable_user',
     '{"azure_ad": "disable_user", "okta": "suspend_user", "active_directory": "disable_account"}'::jsonb, 2),
    ('enable_user', 'Enable User Account', 'Re-enable disabled user account', 'disable', 'user', 'medium', true, false, NULL,
     '{"azure_ad": "enable_user", "okta": "unsuspend_user", "active_directory": "enable_account"}'::jsonb, 2),
    ('reset_password', 'Force Password Reset', 'Force user to reset password on next login', 'credential', 'user', 'medium', true, false, NULL,
     '{"azure_ad": "force_password_reset", "okta": "expire_password", "active_directory": "reset_password"}'::jsonb, 2),
    ('revoke_sessions', 'Revoke User Sessions', 'Terminate all active sessions for user', 'credential', 'user', 'medium', true, false, NULL,
     '{"azure_ad": "revoke_sessions", "okta": "clear_sessions"}'::jsonb, 2),

    -- File/hash actions
    ('block_hash', 'Block File Hash', 'Add file hash to EDR block list', 'block', 'hash', 'medium', true, true, 'unblock_hash',
     '{"crowdstrike": "add_ioc_block", "microsoft_defender": "add_indicator"}'::jsonb, 2),
    ('unblock_hash', 'Unblock File Hash', 'Remove file hash from block list', 'block', 'hash', 'low', true, false, NULL,
     '{"crowdstrike": "remove_ioc_block", "microsoft_defender": "remove_indicator"}'::jsonb, 2),

    -- Investigation actions
    ('collect_forensics', 'Collect Forensic Data', 'Initiate forensic data collection from host', 'investigate', 'host', 'low', false, false, NULL,
     '{"crowdstrike": "rtr_collect", "microsoft_defender": "collect_investigation_package"}'::jsonb, 1),
    ('run_scan', 'Run Antivirus Scan', 'Initiate full AV scan on host', 'investigate', 'host', 'low', false, false, NULL,
     '{"crowdstrike": "rtr_scan", "microsoft_defender": "run_av_scan"}'::jsonb, 1)
ON CONFLICT (action_type) DO NOTHING;

-- ============================================================================
-- PHASE 3.4: CASE OWNERSHIP & INVESTIGATION STATE MACHINE
-- ============================================================================

-- Add missing columns to investigations table for full workflow support
DO $$
BEGIN
    -- owner_type: who owns this investigation
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'owner_type') THEN
        ALTER TABLE investigations ADD COLUMN owner_type VARCHAR(20) DEFAULT 'unassigned'
            CHECK (owner_type IN ('unassigned', 'human', 'agent', 'team'));
    END IF;

    -- blocked_reason: why investigation is blocked (if status=blocked)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'blocked_reason') THEN
        ALTER TABLE investigations ADD COLUMN blocked_reason TEXT;
    END IF;

    -- blocked_at: when investigation was blocked
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'blocked_at') THEN
        ALTER TABLE investigations ADD COLUMN blocked_at TIMESTAMP WITH TIME ZONE;
    END IF;

    -- resolution_type: how it was resolved
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'resolution_type') THEN
        ALTER TABLE investigations ADD COLUMN resolution_type VARCHAR(50)
            CHECK (resolution_type IN ('verified_malicious', 'false_positive', 'benign_activity',
                                       'inconclusive', 'duplicate', 'escalated', 'auto_closed'));
    END IF;

    -- resolution_notes: detailed resolution explanation
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'resolution_notes') THEN
        ALTER TABLE investigations ADD COLUMN resolution_notes TEXT;
    END IF;

    -- closed_by: who closed the investigation
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'closed_by') THEN
        ALTER TABLE investigations ADD COLUMN closed_by VARCHAR(100);
    END IF;

    -- sla_breach_at: when SLA was breached (if applicable)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'sla_breach_at') THEN
        ALTER TABLE investigations ADD COLUMN sla_breach_at TIMESTAMP WITH TIME ZONE;
    END IF;

    -- last_activity_at: last meaningful activity (for orphan detection)
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'last_activity_at') THEN
        ALTER TABLE investigations ADD COLUMN last_activity_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP;
    END IF;

    -- resolved_at: when investigation was resolved
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'resolved_at') THEN
        ALTER TABLE investigations ADD COLUMN resolved_at TIMESTAMP WITH TIME ZONE;
    END IF;

    -- resolved_by: who resolved the investigation
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'investigations' AND column_name = 'resolved_by') THEN
        ALTER TABLE investigations ADD COLUMN resolved_by VARCHAR(100);
    END IF;

    RAISE NOTICE 'Investigation workflow columns added/verified';
END $$;

-- Create indexes for new columns
CREATE INDEX IF NOT EXISTS idx_investigations_owner_type ON investigations(owner_type);
CREATE INDEX IF NOT EXISTS idx_investigations_resolution_type ON investigations(resolution_type);
CREATE INDEX IF NOT EXISTS idx_investigations_last_activity ON investigations(last_activity_at);

-- ============================================================================
-- ASSIGNMENT RULES TABLE
-- ============================================================================
-- Rules for auto-routing investigations based on conditions
CREATE TABLE IF NOT EXISTS assignment_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    name VARCHAR(100) NOT NULL,
    description TEXT,
    priority INTEGER DEFAULT 100,  -- Lower = higher priority

    -- Conditions for matching (JSONB for flexibility)
    conditions JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- Example: {"severity": "critical", "source": "crowdstrike", "category": "malware"}

    -- Assignment target
    assign_to VARCHAR(100),           -- user ID, team ID, or special value
    assign_to_type VARCHAR(20) NOT NULL CHECK (assign_to_type IN ('user', 'team', 'agent', 'round_robin')),

    -- Round robin state (for round_robin type)
    round_robin_state JSONB DEFAULT '{}'::jsonb,
    -- Example: {"last_assigned_index": 2, "members": ["user1", "user2", "user3"]}

    enabled BOOLEAN DEFAULT true,

    -- Stats
    trigger_count INTEGER DEFAULT 0,
    last_triggered_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_assignment_rules_enabled ON assignment_rules(enabled, priority);
CREATE INDEX IF NOT EXISTS idx_assignment_rules_type ON assignment_rules(assign_to_type);

-- Seed default assignment rules
INSERT INTO assignment_rules (name, description, priority, conditions, assign_to, assign_to_type)
VALUES
    ('Critical to Senior Analysts',
     'Route critical severity investigations to senior analyst team',
     10,
     '{"severity": "critical"}'::jsonb,
     'senior_analysts',
     'team'),
    ('Phishing to Phishing Team',
     'Route phishing-related investigations to specialized team',
     20,
     '{"category": "phishing"}'::jsonb,
     'phishing_analysts',
     'team'),
    ('Malware to Malware Team',
     'Route malware investigations to malware analysts',
     20,
     '{"category": "malware"}'::jsonb,
     'malware_analysts',
     'team'),
    ('Default Round Robin',
     'Default assignment via round robin to all tier 1 analysts',
     1000,
     '{}'::jsonb,
     'tier1_analysts',
     'round_robin')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- INVESTIGATION OWNERSHIP LOG TABLE
-- ============================================================================
-- Audit trail for ownership changes
CREATE TABLE IF NOT EXISTS investigation_ownership_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,

    -- Change details
    previous_owner VARCHAR(100),
    new_owner VARCHAR(100),
    previous_owner_type VARCHAR(20),
    new_owner_type VARCHAR(20),

    change_type VARCHAR(30) NOT NULL CHECK (change_type IN (
        'assigned', 'reassigned', 'claimed', 'released',
        'escalated', 'auto_assigned', 'system'
    )),

    reason TEXT,
    changed_by VARCHAR(100),  -- who made the change (or 'system')

    -- Metadata
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ownership_log_investigation ON investigation_ownership_log(investigation_id);
CREATE INDEX IF NOT EXISTS idx_ownership_log_created ON investigation_ownership_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ownership_log_change_type ON investigation_ownership_log(change_type);

-- ============================================================================
-- ESCALATION CONFIGURATION TABLE
-- ============================================================================
-- Defines escalation timer thresholds
CREATE TABLE IF NOT EXISTS escalation_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    name VARCHAR(100) NOT NULL,
    description TEXT,

    -- Trigger conditions
    trigger_type VARCHAR(50) NOT NULL CHECK (trigger_type IN (
        'unassigned_timeout', 'no_activity_timeout',
        'sla_approaching', 'sla_breach', 'manual'
    )),

    -- Timing (in minutes)
    threshold_minutes INTEGER NOT NULL,

    -- Applicable to which priorities
    applies_to_priorities TEXT[] DEFAULT ARRAY['P1', 'P2', 'P3', 'P4'],

    -- Actions on trigger
    escalation_level INTEGER DEFAULT 1,  -- 1=T2, 2=manager, 3=critical
    notify_roles TEXT[] DEFAULT ARRAY['escalation_team'],
    auto_escalate BOOLEAN DEFAULT true,

    enabled BOOLEAN DEFAULT true,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Seed default escalation rules
INSERT INTO escalation_config (name, description, trigger_type, threshold_minutes, applies_to_priorities, escalation_level, notify_roles)
VALUES
    ('P1 Unassigned 15min',
     'Escalate P1 investigations unassigned for more than 15 minutes',
     'unassigned_timeout',
     15,
     ARRAY['P1'],
     1,
     ARRAY['tier2_analysts', 'soc_lead']),
    ('P1 No Activity 1hr',
     'Escalate P1 investigations with no activity for more than 1 hour',
     'no_activity_timeout',
     60,
     ARRAY['P1'],
     2,
     ARRAY['soc_manager']),
    ('P2 Unassigned 30min',
     'Escalate P2 investigations unassigned for more than 30 minutes',
     'unassigned_timeout',
     30,
     ARRAY['P2'],
     1,
     ARRAY['tier2_analysts']),
    ('P2 No Activity 2hr',
     'Escalate P2 investigations with no activity for more than 2 hours',
     'no_activity_timeout',
     120,
     ARRAY['P2'],
     1,
     ARRAY['soc_lead']),
    ('All SLA Approaching',
     'Alert when SLA breach is approaching (80% of time elapsed)',
     'sla_approaching',
     0,  -- calculated dynamically based on priority
     ARRAY['P1', 'P2', 'P3'],
     0,  -- warning only, no escalation
     ARRAY['assigned_user'])
ON CONFLICT DO NOTHING;

-- ============================================================================
-- SLA CONFIGURATION TABLE
-- ============================================================================
-- Defines SLA targets by priority
CREATE TABLE IF NOT EXISTS sla_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    priority VARCHAR(10) UNIQUE NOT NULL CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),

    -- Response time targets (in minutes)
    response_time_minutes INTEGER NOT NULL,      -- Time to first assignment
    acknowledge_time_minutes INTEGER NOT NULL,   -- Time to first action
    resolution_time_minutes INTEGER NOT NULL,    -- Time to resolution

    -- Business hours only (for P3/P4)
    business_hours_only BOOLEAN DEFAULT false,

    enabled BOOLEAN DEFAULT true,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Seed default SLA targets
INSERT INTO sla_config (priority, response_time_minutes, acknowledge_time_minutes, resolution_time_minutes, business_hours_only)
VALUES
    ('P1', 15, 30, 240, false),       -- Critical: 15min response, 30min ack, 4hr resolution, 24/7
    ('P2', 60, 120, 480, false),      -- High: 1hr response, 2hr ack, 8hr resolution, 24/7
    ('P3', 240, 480, 1440, true),     -- Medium: 4hr response, 8hr ack, 24hr resolution, business hours
    ('P4', 480, 1440, 4320, true)     -- Low: 8hr response, 24hr ack, 72hr resolution, business hours
ON CONFLICT (priority) DO NOTHING;

-- ============================================================================
-- TEAM DEFINITIONS TABLE
-- ============================================================================
-- Defines analyst teams for assignment
CREATE TABLE IF NOT EXISTS teams (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    team_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(200) NOT NULL,
    description TEXT,

    -- Team members (user IDs)
    members TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Lead/manager
    lead_user_id VARCHAR(100),

    -- Capacity settings for load balancing
    max_concurrent_investigations INTEGER DEFAULT 10,
    current_load INTEGER DEFAULT 0,

    -- Specializations (for smart routing)
    specializations TEXT[] DEFAULT ARRAY[]::TEXT[],
    -- Example: ['phishing', 'malware', 'insider_threat']

    enabled BOOLEAN DEFAULT true,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_teams_team_id ON teams(team_id);
CREATE INDEX IF NOT EXISTS idx_teams_specializations ON teams USING GIN (specializations);

-- Seed default teams
INSERT INTO teams (team_id, name, description, specializations)
VALUES
    ('tier1_analysts', 'Tier 1 Analysts', 'First-line SOC analysts handling initial triage', ARRAY['general']),
    ('tier2_analysts', 'Tier 2 Analysts', 'Senior analysts for escalated investigations', ARRAY['advanced', 'forensics']),
    ('senior_analysts', 'Senior Analyst Team', 'Senior analysts for critical incidents', ARRAY['critical', 'apt']),
    ('phishing_analysts', 'Phishing Team', 'Specialists in phishing and social engineering', ARRAY['phishing', 'social_engineering']),
    ('malware_analysts', 'Malware Analysis Team', 'Specialists in malware analysis and reverse engineering', ARRAY['malware', 'ransomware'])
ON CONFLICT (team_id) DO NOTHING;

-- ============================================================================
-- INVESTIGATION CHAT TABLE (Phase 6)
-- ============================================================================
-- Real-time chat messages between analysts and AI agents within investigations
CREATE TABLE IF NOT EXISTS investigation_chat (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,

    -- Sender information
    sender_type VARCHAR(30) NOT NULL CHECK (sender_type IN (
        'human', 'agent_t1', 'agent_t2', 'agent_t3', 'system', 'integration'
    )),
    sender_id VARCHAR(100),                  -- username or agent_id
    sender_name VARCHAR(200),                -- display name

    -- Message content
    message TEXT NOT NULL,
    message_type VARCHAR(30) DEFAULT 'text' CHECK (message_type IN (
        'text',              -- Regular chat message
        'action_request',    -- Agent requesting an action
        'action_result',     -- Result of an action
        'field_update',      -- Investigation field was updated
        'status_change',     -- Status changed
        'enrichment',        -- Enrichment data received
        'finding',           -- Agent finding/observation
        'recommendation',    -- Agent recommendation
        'question',          -- Agent asking for input
        'system',            -- System notification
        'error'              -- Error message
    )),

    -- Additional metadata for rich messages
    metadata JSONB DEFAULT '{}'::jsonb,
    -- Examples:
    -- action_request: {"action_type": "contain_host", "target": "HOST-123", "confidence": 0.95}
    -- field_update: {"field": "severity", "old_value": "medium", "new_value": "high"}
    -- enrichment: {"ioc": "8.8.8.8", "source": "VirusTotal", "verdict": "clean"}

    -- For threading/context
    parent_message_id UUID REFERENCES investigation_chat(id) ON DELETE SET NULL,

    -- Read/seen tracking (for UI indicators)
    read_by TEXT[] DEFAULT ARRAY[]::TEXT[],

    -- Streaming indicator (for typing/processing)
    is_streaming BOOLEAN DEFAULT false,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for chat
CREATE INDEX IF NOT EXISTS idx_chat_investigation ON investigation_chat(investigation_id, created_at);
CREATE INDEX IF NOT EXISTS idx_chat_sender ON investigation_chat(sender_type, sender_id);
CREATE INDEX IF NOT EXISTS idx_chat_type ON investigation_chat(message_type);
CREATE INDEX IF NOT EXISTS idx_chat_parent ON investigation_chat(parent_message_id);
CREATE INDEX IF NOT EXISTS idx_chat_created ON investigation_chat(created_at DESC);

-- ============================================================================
-- CHAT TYPING INDICATORS TABLE (Ephemeral)
-- ============================================================================
-- Tracks who is currently typing in a chat
CREATE TABLE IF NOT EXISTS chat_typing_status (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    user_id VARCHAR(100) NOT NULL,
    user_name VARCHAR(200),
    is_agent BOOLEAN DEFAULT false,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE DEFAULT (CURRENT_TIMESTAMP + INTERVAL '10 seconds'),
    UNIQUE(investigation_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_typing_investigation ON chat_typing_status(investigation_id);
CREATE INDEX IF NOT EXISTS idx_typing_expires ON chat_typing_status(expires_at);

-- ============================================================================
-- CHAT SUBSCRIPTIONS TABLE
-- ============================================================================
-- Tracks WebSocket subscriptions for chat rooms
CREATE TABLE IF NOT EXISTS chat_subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    user_id VARCHAR(100) NOT NULL,
    connection_id VARCHAR(100) NOT NULL,
    subscribed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(investigation_id, user_id, connection_id)
);

CREATE INDEX IF NOT EXISTS idx_chat_sub_investigation ON chat_subscriptions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_chat_sub_user ON chat_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_chat_sub_heartbeat ON chat_subscriptions(last_heartbeat);

-- ============================================================================
-- CHAT USAGE ANALYTICS TABLE
-- ============================================================================
-- Tracks user chat activity for auditing and analytics
CREATE TABLE IF NOT EXISTS chat_usage_analytics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- User info
    user_id VARCHAR(100) NOT NULL,
    username VARCHAR(200),

    -- Session tracking
    session_id VARCHAR(100),
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,

    -- Event type
    event_type VARCHAR(50) NOT NULL CHECK (event_type IN (
        'session_start',         -- User opened chat
        'session_end',           -- User closed chat
        'message_sent',          -- User sent a message
        'quick_action_used',     -- User used a quick action shortcut
        'action_requested',      -- User requested an agent action
        'agent_response',        -- Agent responded to user
        'connection_error',      -- WebSocket connection error
        'reconnection'           -- User reconnected
    )),

    -- Event details
    message_type VARCHAR(30),    -- text, action_request, etc.
    quick_action_category VARCHAR(50),  -- Analysis, Enrichment, Response, Documentation
    quick_action_label VARCHAR(100),
    action_type VARCHAR(100),    -- For action requests: contain_host, block_ip, etc.
    action_target VARCHAR(500),  -- Target of the action

    -- Metrics
    message_length INTEGER,
    response_time_ms INTEGER,    -- Time between request and agent response

    -- Metadata
    user_agent TEXT,
    ip_address VARCHAR(50),
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_chat_analytics_user ON chat_usage_analytics(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_analytics_event ON chat_usage_analytics(event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_analytics_investigation ON chat_usage_analytics(investigation_id);
CREATE INDEX IF NOT EXISTS idx_chat_analytics_date ON chat_usage_analytics(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_analytics_actions ON chat_usage_analytics(action_type) WHERE action_type IS NOT NULL;

-- ============================================================================
-- CHAT ACTION AUDIT LOG TABLE
-- ============================================================================
-- Detailed audit trail for action requests made through chat
CREATE TABLE IF NOT EXISTS chat_action_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Link to chat message
    chat_message_id UUID REFERENCES investigation_chat(id) ON DELETE SET NULL,
    investigation_id UUID REFERENCES investigations(id) ON DELETE SET NULL,

    -- User who initiated
    user_id VARCHAR(100) NOT NULL,
    username VARCHAR(200),

    -- Action details
    action_type VARCHAR(100) NOT NULL,
    action_target_type VARCHAR(50),
    action_target_value TEXT,
    action_parameters JSONB,

    -- Agent that would execute
    agent_tier INTEGER,
    agent_id VARCHAR(100),

    -- Original user message
    user_prompt TEXT,

    -- Status tracking
    status VARCHAR(30) DEFAULT 'requested' CHECK (status IN (
        'requested',      -- User asked for action
        'parsed',         -- Agent understood the request
        'pending_approval',  -- Awaiting human approval
        'approved',
        'denied',
        'executed',
        'failed',
        'cancelled'
    )),

    -- Approval info
    action_request_id VARCHAR(50),  -- Links to action_requests table
    approved_by VARCHAR(100),
    approved_at TIMESTAMP WITH TIME ZONE,
    denial_reason TEXT,

    -- Execution result
    execution_result JSONB,
    executed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_chat_action_audit_user ON chat_action_audit(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_chat_action_audit_investigation ON chat_action_audit(investigation_id);
CREATE INDEX IF NOT EXISTS idx_chat_action_audit_action ON chat_action_audit(action_type);
CREATE INDEX IF NOT EXISTS idx_chat_action_audit_status ON chat_action_audit(status);
CREATE INDEX IF NOT EXISTS idx_chat_action_audit_request ON chat_action_audit(action_request_id);

-- ============================================================================
-- USER CHAT STATISTICS VIEW
-- ============================================================================
-- Aggregated view of user chat activity
CREATE OR REPLACE VIEW user_chat_statistics AS
SELECT
    user_id,
    username,
    COUNT(*) FILTER (WHERE event_type = 'message_sent') as total_messages,
    COUNT(*) FILTER (WHERE event_type = 'quick_action_used') as quick_actions_used,
    COUNT(*) FILTER (WHERE event_type = 'action_requested') as actions_requested,
    COUNT(DISTINCT investigation_id) as investigations_participated,
    COUNT(DISTINCT session_id) as total_sessions,
    MIN(created_at) as first_activity,
    MAX(created_at) as last_activity,
    AVG(message_length) FILTER (WHERE message_length IS NOT NULL) as avg_message_length
FROM chat_usage_analytics
GROUP BY user_id, username;

-- ============================================================================
-- AGENT TELEMETRY TABLES - Phase 8
-- Tracks agent accuracy, paths, and performance for observability
-- ============================================================================

-- 1. Agent Verdict Outcomes - tracks accuracy per verdict
CREATE TABLE IF NOT EXISTS agent_verdict_outcomes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    agent_execution_id UUID,  -- References agent_executions if exists
    agent_id UUID,  -- References agent_definitions if exists
    agent_tier INTEGER NOT NULL,
    agent_name VARCHAR(255),

    -- Agent's verdict at time of analysis
    agent_verdict VARCHAR(50),  -- MALICIOUS, BENIGN, SUSPICIOUS, etc.
    agent_confidence DECIMAL(5,2),

    -- Final outcome (populated when investigation is resolved)
    final_verdict VARCHAR(50),  -- TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, etc.
    final_disposition VARCHAR(50),
    resolved_by VARCHAR(100),  -- 'agent_tier1', 'agent_tier2', 'human:username'

    -- Accuracy assessment
    was_correct BOOLEAN,  -- NULL until resolved, then TRUE/FALSE
    was_overridden BOOLEAN DEFAULT FALSE,
    override_reason TEXT,

    -- Timing
    agent_verdict_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    final_verdict_at TIMESTAMP WITH TIME ZONE,
    time_to_resolution_ms INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_verdict_outcomes_investigation ON agent_verdict_outcomes(investigation_id);
CREATE INDEX IF NOT EXISTS idx_verdict_outcomes_agent ON agent_verdict_outcomes(agent_id);
CREATE INDEX IF NOT EXISTS idx_verdict_outcomes_tier ON agent_verdict_outcomes(agent_tier);
CREATE INDEX IF NOT EXISTS idx_verdict_outcomes_correct ON agent_verdict_outcomes(was_correct) WHERE was_correct IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_verdict_outcomes_date ON agent_verdict_outcomes(agent_verdict_at DESC);

-- 2. Investigation Agent Paths - tracks the full journey through tiers
CREATE TABLE IF NOT EXISTS investigation_agent_paths (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE UNIQUE,

    -- Path tracking as JSON array
    -- Each step: {tier, agent_id, agent_name, started_at, completed_at, verdict, confidence, escalated}
    path_json JSONB DEFAULT '[]'::jsonb,

    -- Summary metrics
    total_agents_involved INTEGER DEFAULT 0,
    escalation_count INTEGER DEFAULT 0,
    human_involved BOOLEAN DEFAULT FALSE,

    -- Key timestamps
    first_agent_at TIMESTAMP WITH TIME ZONE,
    last_agent_at TIMESTAMP WITH TIME ZONE,
    human_takeover_at TIMESTAMP WITH TIME ZONE,
    resolved_at TIMESTAMP WITH TIME ZONE,

    -- Final outcome
    final_resolver VARCHAR(50),  -- 'tier1', 'tier2', 'tier3', 'human'
    automation_success BOOLEAN,  -- TRUE if resolved without human intervention

    -- Alert context for analytics
    alert_severity VARCHAR(20),
    alert_source VARCHAR(255),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_agent_paths_investigation ON investigation_agent_paths(investigation_id);
CREATE INDEX IF NOT EXISTS idx_agent_paths_resolver ON investigation_agent_paths(final_resolver);
CREATE INDEX IF NOT EXISTS idx_agent_paths_automation ON investigation_agent_paths(automation_success);
CREATE INDEX IF NOT EXISTS idx_agent_paths_created ON investigation_agent_paths(created_at DESC);

-- 3. Model Performance Daily - aggregated metrics per model per day
CREATE TABLE IF NOT EXISTS model_performance_daily (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_date DATE NOT NULL,
    provider VARCHAR(50) NOT NULL,
    model VARCHAR(255) NOT NULL,

    -- Volume metrics
    total_calls INTEGER DEFAULT 0,
    successful_calls INTEGER DEFAULT 0,
    failed_calls INTEGER DEFAULT 0,
    timeout_calls INTEGER DEFAULT 0,

    -- Token metrics
    total_prompt_tokens BIGINT DEFAULT 0,
    total_completion_tokens BIGINT DEFAULT 0,

    -- Cost metrics
    total_cost_cents DECIMAL(12,4) DEFAULT 0,
    avg_cost_per_call_cents DECIMAL(10,4),

    -- Latency metrics
    avg_response_time_ms INTEGER,
    p50_response_time_ms INTEGER,
    p95_response_time_ms INTEGER,
    p99_response_time_ms INTEGER,
    max_response_time_ms INTEGER,

    -- Accuracy metrics (computed from verdict outcomes)
    investigations_involved INTEGER DEFAULT 0,
    correct_verdicts INTEGER DEFAULT 0,
    incorrect_verdicts INTEGER DEFAULT 0,
    accuracy_rate DECIMAL(5,2),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(metric_date, provider, model)
);

CREATE INDEX IF NOT EXISTS idx_model_perf_date ON model_performance_daily(metric_date DESC);
CREATE INDEX IF NOT EXISTS idx_model_perf_provider ON model_performance_daily(provider);

-- 4. Agent Performance Daily - aggregated metrics per agent per day
CREATE TABLE IF NOT EXISTS agent_performance_daily (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_date DATE NOT NULL,
    agent_id UUID,
    agent_name VARCHAR(255),
    agent_tier INTEGER,

    -- Execution volume
    executions_total INTEGER DEFAULT 0,
    executions_completed INTEGER DEFAULT 0,
    executions_failed INTEGER DEFAULT 0,

    -- Accuracy metrics
    verdicts_issued INTEGER DEFAULT 0,
    verdicts_correct INTEGER DEFAULT 0,
    verdicts_overridden INTEGER DEFAULT 0,
    accuracy_rate DECIMAL(5,2),
    override_rate DECIMAL(5,2),

    -- Escalation metrics
    escalations_received INTEGER DEFAULT 0,  -- Incoming from lower tier
    escalations_sent INTEGER DEFAULT 0,      -- Outgoing to higher tier/human
    escalation_rate DECIMAL(5,2),

    -- Confidence metrics
    avg_confidence DECIMAL(5,2),
    confidence_when_correct DECIMAL(5,2),
    confidence_when_wrong DECIMAL(5,2),

    -- Cost metrics
    total_tokens_used BIGINT DEFAULT 0,
    total_cost_cents DECIMAL(12,4) DEFAULT 0,
    avg_cost_per_execution_cents DECIMAL(10,4),

    -- Timing metrics
    avg_execution_time_ms INTEGER,
    avg_time_to_verdict_ms INTEGER,
    min_execution_time_ms INTEGER,
    max_execution_time_ms INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(metric_date, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_agent_perf_date ON agent_performance_daily(metric_date DESC);
CREATE INDEX IF NOT EXISTS idx_agent_perf_agent ON agent_performance_daily(agent_id);
CREATE INDEX IF NOT EXISTS idx_agent_perf_tier ON agent_performance_daily(agent_tier);

-- 5. Telemetry Snapshots - hourly system health snapshots
CREATE TABLE IF NOT EXISTS telemetry_snapshots (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    snapshot_time TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Investigation pipeline metrics
    open_investigations INTEGER DEFAULT 0,
    investigations_last_hour INTEGER DEFAULT 0,
    investigations_auto_resolved_last_hour INTEGER DEFAULT 0,
    investigations_human_resolved_last_hour INTEGER DEFAULT 0,

    -- Agent execution metrics
    agent_executions_last_hour INTEGER DEFAULT 0,
    agent_failures_last_hour INTEGER DEFAULT 0,
    avg_execution_time_ms INTEGER,

    -- Token and cost metrics
    tokens_used_last_hour BIGINT DEFAULT 0,
    cost_cents_last_hour DECIMAL(10,4) DEFAULT 0,

    -- Rolling 24-hour metrics (for trends)
    accuracy_rate_24h DECIMAL(5,2),
    override_rate_24h DECIMAL(5,2),
    escalation_rate_24h DECIMAL(5,2),
    automation_rate_24h DECIMAL(5,2),

    -- Queue health
    pending_investigations INTEGER DEFAULT 0,
    pending_enrichments INTEGER DEFAULT 0,
    pending_actions INTEGER DEFAULT 0,

    -- System health
    active_agents INTEGER DEFAULT 0,
    circuit_breakers_open INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_telemetry_time ON telemetry_snapshots(snapshot_time DESC);

-- 5b. LLM Mesh Snapshots table removed (vLLM replaced by Claude API)

-- 6. View for agent accuracy summary (for quick dashboard queries)
CREATE OR REPLACE VIEW agent_accuracy_summary AS
SELECT
    agent_id,
    agent_name,
    agent_tier,
    COUNT(*) as total_verdicts,
    COUNT(*) FILTER (WHERE was_correct = true) as correct_verdicts,
    COUNT(*) FILTER (WHERE was_correct = false) as incorrect_verdicts,
    COUNT(*) FILTER (WHERE was_overridden = true) as overridden_verdicts,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE was_correct = true) / NULLIF(COUNT(*) FILTER (WHERE was_correct IS NOT NULL), 0),
        2
    ) as accuracy_percent,
    ROUND(AVG(agent_confidence), 2) as avg_confidence,
    ROUND(AVG(agent_confidence) FILTER (WHERE was_correct = true), 2) as confidence_when_correct,
    ROUND(AVG(agent_confidence) FILTER (WHERE was_correct = false), 2) as confidence_when_wrong
FROM agent_verdict_outcomes
WHERE agent_verdict_at > CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY agent_id, agent_name, agent_tier;

-- 7. View for escalation funnel (T1 -> T2 -> Human flow)
CREATE OR REPLACE VIEW escalation_funnel AS
SELECT
    COUNT(*) as total_investigations,
    COUNT(*) FILTER (WHERE total_agents_involved >= 1) as reached_tier1,
    COUNT(*) FILTER (WHERE total_agents_involved >= 2 OR escalation_count >= 1) as reached_tier2,
    COUNT(*) FILTER (WHERE human_involved = true) as reached_human,
    COUNT(*) FILTER (WHERE automation_success = true) as auto_resolved,
    ROUND(100.0 * COUNT(*) FILTER (WHERE automation_success = true) / NULLIF(COUNT(*), 0), 2) as automation_rate,
    ROUND(100.0 * COUNT(*) FILTER (WHERE escalation_count >= 1) / NULLIF(COUNT(*), 0), 2) as escalation_rate
FROM investigation_agent_paths
WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '30 days';

-- ============================================================================
-- CMDB & ASSET DISCOVERY - Phase 9
-- Configuration Management Database for asset-aware security operations
-- ============================================================================

-- 1. Assets - Core asset inventory
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Asset type classification
    asset_type VARCHAR(50) NOT NULL DEFAULT 'unknown' CHECK (asset_type IN (
        'server', 'workstation', 'laptop', 'network_device', 'cloud_instance',
        'container', 'virtual_machine', 'mobile', 'iot', 'database', 'application', 'unknown'
    )),

    -- Primary identifiers
    hostname VARCHAR(255),
    fqdn VARCHAR(500),
    display_name VARCHAR(255),

    -- Network identifiers (arrays for multi-homed systems)
    ip_addresses JSONB DEFAULT '[]'::jsonb,  -- ["10.0.1.50", "192.168.1.100"]
    mac_addresses JSONB DEFAULT '[]'::jsonb, -- ["AA:BB:CC:DD:EE:FF"]

    -- Operating system info
    os_family VARCHAR(50),  -- windows, linux, macos, ios, android, network_os
    os_name VARCHAR(255),   -- Windows Server 2019, Ubuntu 22.04, etc.
    os_version VARCHAR(100),

    -- Criticality and business context
    criticality VARCHAR(20) DEFAULT 'tier4' CHECK (criticality IN ('tier1', 'tier2', 'tier3', 'tier4', 'unknown')),
    status VARCHAR(30) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'decommissioned', 'maintenance', 'unknown')),
    environment VARCHAR(30) DEFAULT 'unknown' CHECK (environment IN ('production', 'staging', 'development', 'test', 'dr', 'unknown')),

    -- Ownership and organization
    owner VARCHAR(255),           -- Primary owner (username or email)
    owner_team VARCHAR(255),      -- Team/group responsible
    department VARCHAR(255),      -- Business department
    cost_center VARCHAR(100),     -- For billing/tracking
    location VARCHAR(255),        -- Physical or logical location

    -- Tags and compliance
    compliance_tags JSONB DEFAULT '[]'::jsonb,  -- ["pci", "hipaa", "sox", "gdpr"]
    custom_tags JSONB DEFAULT '[]'::jsonb,      -- Customer-defined tags

    -- Discovery tracking
    discovery_sources JSONB DEFAULT '{}'::jsonb,  -- {"crowdstrike": "2025-12-23T...", "active_directory": "..."}
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Extended metadata (source-specific details)
    metadata JSONB DEFAULT '{}'::jsonb,

    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    updated_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_fqdn ON assets(fqdn);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_environment ON assets(environment);
CREATE INDEX IF NOT EXISTS idx_assets_owner ON assets(owner);
CREATE INDEX IF NOT EXISTS idx_assets_department ON assets(department);
CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_assets_ip_addresses ON assets USING GIN (ip_addresses);
CREATE INDEX IF NOT EXISTS idx_assets_mac_addresses ON assets USING GIN (mac_addresses);
CREATE INDEX IF NOT EXISTS idx_assets_compliance_tags ON assets USING GIN (compliance_tags);
CREATE INDEX IF NOT EXISTS idx_assets_custom_tags ON assets USING GIN (custom_tags);
CREATE INDEX IF NOT EXISTS idx_assets_metadata ON assets USING GIN (metadata);

-- Full-text search on asset fields
CREATE INDEX IF NOT EXISTS idx_assets_search ON assets USING GIN (
    to_tsvector('english', COALESCE(hostname, '') || ' ' || COALESCE(fqdn, '') || ' ' ||
    COALESCE(display_name, '') || ' ' || COALESCE(owner, '') || ' ' || COALESCE(department, ''))
);

-- 2. Asset Identifiers - Multiple identifiers per asset for matching
CREATE TABLE IF NOT EXISTS asset_identifiers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    -- Identifier details
    identifier_type VARCHAR(50) NOT NULL,  -- hostname, ip, mac, serial, cloud_id, ad_dn, edr_agent_id, vmware_uuid
    identifier_value VARCHAR(500) NOT NULL,

    -- Metadata
    source VARCHAR(100),          -- Discovery source that provided this
    is_primary BOOLEAN DEFAULT FALSE,
    confidence INTEGER DEFAULT 100,  -- 0-100 confidence score
    last_verified TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(identifier_type, identifier_value)
);

CREATE INDEX IF NOT EXISTS idx_asset_identifiers_asset ON asset_identifiers(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_identifiers_type_value ON asset_identifiers(identifier_type, identifier_value);
CREATE INDEX IF NOT EXISTS idx_asset_identifiers_source ON asset_identifiers(source);

-- 3. Asset Relationships - Connections between assets
CREATE TABLE IF NOT EXISTS asset_relationships (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    -- Relationship details
    relationship_type VARCHAR(50) NOT NULL CHECK (relationship_type IN (
        'runs_on', 'connects_to', 'depends_on', 'managed_by', 'hosts',
        'member_of', 'backs_up_to', 'replicates_to', 'load_balances', 'proxies'
    )),

    -- Metadata
    discovered_by VARCHAR(100),   -- Discovery source
    confidence INTEGER DEFAULT 100,
    bidirectional BOOLEAN DEFAULT FALSE,
    metadata JSONB DEFAULT '{}'::jsonb,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(source_asset_id, target_asset_id, relationship_type)
);

CREATE INDEX IF NOT EXISTS idx_asset_rel_source ON asset_relationships(source_asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_rel_target ON asset_relationships(target_asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_rel_type ON asset_relationships(relationship_type);

-- 4. Asset History - Audit trail for asset changes
CREATE TABLE IF NOT EXISTS asset_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    -- Change details
    change_type VARCHAR(30) NOT NULL CHECK (change_type IN (
        'created', 'updated', 'merged', 'split', 'decommissioned', 'reactivated', 'deleted'
    )),
    changed_fields JSONB,         -- List of field names that changed
    old_values JSONB,             -- Previous values
    new_values JSONB,             -- New values

    -- Attribution
    changed_by VARCHAR(255),      -- User or system that made change
    change_source VARCHAR(100),   -- 'manual', 'discovery:crowdstrike', etc.
    change_reason TEXT,           -- Optional explanation

    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_asset_history_asset ON asset_history(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_history_type ON asset_history(change_type);
CREATE INDEX IF NOT EXISTS idx_asset_history_timestamp ON asset_history(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_asset_history_source ON asset_history(change_source);

-- 5. Discovery Sources - Configuration for asset discovery
CREATE TABLE IF NOT EXISTS discovery_sources (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Source identification
    name VARCHAR(255) NOT NULL UNIQUE,
    source_type VARCHAR(50) NOT NULL CHECK (source_type IN (
        'active_directory', 'crowdstrike', 'sentinelone', 'defender_atp',
        'aws', 'azure', 'gcp', 'vmware', 'kubernetes', 'servicenow',
        'network_scan', 'csv_import', 'api', 'manual'
    )),

    -- Connection to integration system
    integration_id UUID,          -- FK to integration_configs if using integration system
    credential_id VARCHAR(255),   -- FK to credential_vault

    -- Configuration
    config JSONB DEFAULT '{}'::jsonb,  -- Source-specific settings
    field_mappings JSONB DEFAULT '{}'::jsonb,  -- Map source fields to asset fields

    -- Scheduling
    sync_enabled BOOLEAN DEFAULT TRUE,
    sync_interval_minutes INTEGER DEFAULT 60,
    sync_cron VARCHAR(100),       -- Optional cron expression for complex schedules

    -- Status tracking
    last_sync_at TIMESTAMP WITH TIME ZONE,
    last_sync_status VARCHAR(30) DEFAULT 'never_run' CHECK (last_sync_status IN (
        'never_run', 'running', 'success', 'partial', 'failed'
    )),
    last_sync_message TEXT,
    last_sync_assets_found INTEGER DEFAULT 0,
    last_sync_assets_created INTEGER DEFAULT 0,
    last_sync_assets_updated INTEGER DEFAULT 0,
    last_sync_duration_seconds INTEGER,

    -- Priority for conflict resolution (higher = preferred)
    source_priority INTEGER DEFAULT 50,

    -- Audit fields
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_discovery_sources_type ON discovery_sources(source_type);
CREATE INDEX IF NOT EXISTS idx_discovery_sources_enabled ON discovery_sources(enabled);
CREATE INDEX IF NOT EXISTS idx_discovery_sources_next_sync ON discovery_sources(last_sync_at, sync_interval_minutes)
    WHERE enabled = TRUE AND sync_enabled = TRUE;

-- 6. Discovery Queue - Pending discovery tasks
CREATE TABLE IF NOT EXISTS discovery_queue (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_id UUID NOT NULL REFERENCES discovery_sources(id) ON DELETE CASCADE,

    -- Job status
    status VARCHAR(30) DEFAULT 'pending' CHECK (status IN (
        'pending', 'running', 'completed', 'failed', 'cancelled'
    )),
    priority INTEGER DEFAULT 5,

    -- Execution tracking
    scheduled_for TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,

    -- Results
    assets_found INTEGER,
    assets_created INTEGER,
    assets_updated INTEGER,
    assets_unchanged INTEGER,
    conflicts_detected INTEGER,
    error_message TEXT,
    execution_log JSONB DEFAULT '[]'::jsonb,

    -- Worker assignment
    locked_by VARCHAR(100),
    locked_until TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_discovery_queue_pending ON discovery_queue(status, priority, scheduled_for)
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_discovery_queue_source ON discovery_queue(source_id);

-- 7. Asset Conflicts - Detected conflicts during reconciliation
CREATE TABLE IF NOT EXISTS asset_conflicts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Affected assets
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    conflicting_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,

    -- Conflict details
    conflict_type VARCHAR(50) NOT NULL CHECK (conflict_type IN (
        'duplicate_identifier', 'conflicting_attributes', 'merge_required',
        'ownership_conflict', 'stale_data', 'orphaned_relationship'
    )),
    conflict_field VARCHAR(100),
    source_a VARCHAR(100),
    source_b VARCHAR(100),
    value_a JSONB,
    value_b JSONB,

    -- Resolution
    status VARCHAR(30) DEFAULT 'pending' CHECK (status IN ('pending', 'resolved', 'ignored')),
    resolution VARCHAR(50),       -- 'keep_a', 'keep_b', 'merge', 'manual'
    resolved_by VARCHAR(255),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_notes TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    discovery_job_id UUID REFERENCES discovery_queue(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_asset_conflicts_status ON asset_conflicts(status) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_asset_conflicts_asset ON asset_conflicts(asset_id);
CREATE INDEX IF NOT EXISTS idx_asset_conflicts_type ON asset_conflicts(conflict_type);

-- 8. Criticality Rules - Configurable rules for auto-assigning criticality
CREATE TABLE IF NOT EXISTS criticality_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Rule definition
    target_criticality VARCHAR(20) NOT NULL CHECK (target_criticality IN ('tier1', 'tier2', 'tier3', 'tier4')),
    rule_priority INTEGER DEFAULT 50,  -- Higher = evaluated first

    -- Conditions (evaluated as AND within, OR across rules)
    conditions JSONB NOT NULL,  -- {"field": "hostname", "operator": "matches", "value": "^dc-.*"}

    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_criticality_rules_enabled ON criticality_rules(enabled, rule_priority DESC);

-- 9. Views for common queries

-- View: Asset summary with identifier count
CREATE OR REPLACE VIEW asset_summary AS
SELECT
    a.id,
    a.hostname,
    a.fqdn,
    a.asset_type,
    a.os_family,
    a.criticality,
    a.status,
    a.environment,
    a.owner,
    a.department,
    a.first_seen,
    a.last_seen,
    COALESCE(i.identifier_count, 0) as identifier_count,
    COALESCE(r.relationship_count, 0) as relationship_count,
    a.ip_addresses,
    a.compliance_tags
FROM assets a
LEFT JOIN (
    SELECT asset_id, COUNT(*) as identifier_count
    FROM asset_identifiers
    GROUP BY asset_id
) i ON i.asset_id = a.id
LEFT JOIN (
    SELECT source_asset_id, COUNT(*) as relationship_count
    FROM asset_relationships
    GROUP BY source_asset_id
) r ON r.source_asset_id = a.id;

-- View: Stale assets (not seen in 7 days)
CREATE OR REPLACE VIEW stale_assets AS
SELECT *
FROM assets
WHERE last_seen < CURRENT_TIMESTAMP - INTERVAL '7 days'
  AND status = 'active';

-- View: Discovery source health
CREATE OR REPLACE VIEW discovery_source_health AS
SELECT
    ds.id,
    ds.name,
    ds.source_type,
    ds.enabled,
    ds.sync_enabled,
    ds.last_sync_at,
    ds.last_sync_status,
    ds.last_sync_assets_found,
    ds.last_sync_duration_seconds,
    CASE
        WHEN ds.last_sync_at IS NULL THEN 'never_synced'
        WHEN ds.last_sync_at < CURRENT_TIMESTAMP - (ds.sync_interval_minutes * 2 || ' minutes')::INTERVAL THEN 'overdue'
        WHEN ds.last_sync_status = 'failed' THEN 'error'
        ELSE 'healthy'
    END as health_status
FROM discovery_sources ds;

-- Function: Find asset by any identifier
CREATE OR REPLACE FUNCTION find_asset_by_identifier(
    p_identifier_type VARCHAR,
    p_identifier_value VARCHAR
) RETURNS UUID AS $$
DECLARE
    v_asset_id UUID;
BEGIN
    SELECT asset_id INTO v_asset_id
    FROM asset_identifiers
    WHERE identifier_type = p_identifier_type
      AND identifier_value = p_identifier_value
    LIMIT 1;

    RETURN v_asset_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Find asset by IP address
CREATE OR REPLACE FUNCTION find_asset_by_ip(p_ip VARCHAR) RETURNS UUID AS $$
DECLARE
    v_asset_id UUID;
BEGIN
    SELECT id INTO v_asset_id
    FROM assets
    WHERE ip_addresses @> to_jsonb(p_ip::text)
    LIMIT 1;

    RETURN v_asset_id;
END;
$$ LANGUAGE plpgsql;

-- Function: Find asset by hostname (case-insensitive)
CREATE OR REPLACE FUNCTION find_asset_by_hostname(p_hostname VARCHAR) RETURNS UUID AS $$
DECLARE
    v_asset_id UUID;
BEGIN
    SELECT id INTO v_asset_id
    FROM assets
    WHERE LOWER(hostname) = LOWER(p_hostname)
       OR LOWER(fqdn) = LOWER(p_hostname)
    LIMIT 1;

    RETURN v_asset_id;
END;
$$ LANGUAGE plpgsql;

-- Trigger: Update updated_at on assets
CREATE OR REPLACE FUNCTION update_asset_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS assets_updated_at ON assets;
CREATE TRIGGER assets_updated_at
    BEFORE UPDATE ON assets
    FOR EACH ROW
    EXECUTE FUNCTION update_asset_timestamp();

-- Trigger: Record asset history on changes
CREATE OR REPLACE FUNCTION record_asset_history()
RETURNS TRIGGER AS $$
DECLARE
    v_changed_fields JSONB := '[]'::jsonb;
    v_old_values JSONB := '{}'::jsonb;
    v_new_values JSONB := '{}'::jsonb;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- Compare fields and record changes
        IF OLD.hostname IS DISTINCT FROM NEW.hostname THEN
            v_changed_fields = v_changed_fields || '"hostname"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('hostname', OLD.hostname);
            v_new_values = v_new_values || jsonb_build_object('hostname', NEW.hostname);
        END IF;
        IF OLD.criticality IS DISTINCT FROM NEW.criticality THEN
            v_changed_fields = v_changed_fields || '"criticality"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('criticality', OLD.criticality);
            v_new_values = v_new_values || jsonb_build_object('criticality', NEW.criticality);
        END IF;
        IF OLD.status IS DISTINCT FROM NEW.status THEN
            v_changed_fields = v_changed_fields || '"status"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('status', OLD.status);
            v_new_values = v_new_values || jsonb_build_object('status', NEW.status);
        END IF;
        IF OLD.owner IS DISTINCT FROM NEW.owner THEN
            v_changed_fields = v_changed_fields || '"owner"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('owner', OLD.owner);
            v_new_values = v_new_values || jsonb_build_object('owner', NEW.owner);
        END IF;
        IF OLD.ip_addresses::text IS DISTINCT FROM NEW.ip_addresses::text THEN
            v_changed_fields = v_changed_fields || '"ip_addresses"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('ip_addresses', OLD.ip_addresses);
            v_new_values = v_new_values || jsonb_build_object('ip_addresses', NEW.ip_addresses);
        END IF;

        -- Only insert if something actually changed
        IF jsonb_array_length(v_changed_fields) > 0 THEN
            INSERT INTO asset_history (
                asset_id, change_type, changed_fields, old_values, new_values,
                changed_by, change_source
            ) VALUES (
                NEW.id, 'updated', v_changed_fields, v_old_values, v_new_values,
                NEW.updated_by, 'trigger'
            );
        END IF;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO asset_history (
            asset_id, change_type, new_values, changed_by, change_source
        ) VALUES (
            NEW.id, 'created', to_jsonb(NEW), NEW.created_by, 'trigger'
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS assets_history_trigger ON assets;
CREATE TRIGGER assets_history_trigger
    AFTER INSERT OR UPDATE ON assets
    FOR EACH ROW
    EXECUTE FUNCTION record_asset_history();

-- 6. Human Overrides Log - tracks when humans correct agent decisions
CREATE TABLE IF NOT EXISTS human_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
    verdict_outcome_id UUID REFERENCES agent_verdict_outcomes(id) ON DELETE SET NULL,

    -- What was overridden
    agent_id UUID REFERENCES agent_definitions(id) ON DELETE SET NULL,
    agent_tier INTEGER,
    original_verdict VARCHAR(50),
    original_confidence DECIMAL(5,2),

    -- The override
    new_verdict VARCHAR(50),
    override_reason TEXT,
    overridden_by VARCHAR(100),  -- username

    -- Categorization
    override_category VARCHAR(50) CHECK (override_category IN (
        'false_positive', 'false_negative', 'severity_adjustment',
        'additional_context', 'policy_exception', 'other'
    )),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_overrides_investigation ON human_overrides(investigation_id);
CREATE INDEX IF NOT EXISTS idx_overrides_agent ON human_overrides(agent_id);
CREATE INDEX IF NOT EXISTS idx_overrides_category ON human_overrides(override_category);
CREATE INDEX IF NOT EXISTS idx_overrides_created ON human_overrides(created_at DESC);

-- ============================================================================
-- PHASE 12: EMAIL INTEGRATION TABLES
-- ============================================================================
-- Complete email infrastructure for notifications, templates, and inbound processing

-- 1. Email Configuration - SMTP settings
CREATE TABLE IF NOT EXISTS email_config (
    id VARCHAR(50) PRIMARY KEY DEFAULT 'smtp',
    smtp_host VARCHAR(255),
    smtp_port INTEGER DEFAULT 587,
    smtp_username VARCHAR(255),
    smtp_password VARCHAR(500),  -- Encrypted in application
    use_tls BOOLEAN DEFAULT TRUE,
    use_ssl BOOLEAN DEFAULT FALSE,
    from_email VARCHAR(255),
    from_name VARCHAR(255) DEFAULT 'T1 Agentics SOC',
    enabled BOOLEAN DEFAULT FALSE,

    -- Rate limiting
    max_emails_per_hour INTEGER DEFAULT 100,
    max_emails_per_day INTEGER DEFAULT 1000,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- 2. Notification Rules - When to send emails
CREATE TABLE IF NOT EXISTS notification_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    enabled BOOLEAN DEFAULT TRUE,

    -- Trigger conditions
    event_types TEXT[] DEFAULT '{}',  -- alert_created, investigation_closed, etc.
    severity_filter TEXT[] DEFAULT '{}',  -- critical, high, medium, low
    source_filter TEXT[] DEFAULT '{}',  -- crowdstrike, sentinel, etc.

    -- Recipients
    recipients TEXT[] DEFAULT '{}',  -- Email addresses
    recipient_roles TEXT[] DEFAULT '{}',  -- Roles to notify

    -- Template reference
    template_id UUID,
    subject_template VARCHAR(500) DEFAULT '[T1 Agentics] {event_type}: {title}',
    body_template TEXT,

    -- Approval integration
    include_approval_links BOOLEAN DEFAULT FALSE,
    approval_ttl_minutes INTEGER DEFAULT 60,
    approval_require_auth BOOLEAN DEFAULT FALSE,

    -- Schedule (for digests)
    is_digest BOOLEAN DEFAULT FALSE,
    digest_cron VARCHAR(100),  -- e.g., '0 8 * * *' for daily at 8am
    last_digest_sent TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_notification_rules_enabled ON notification_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_notification_rules_event ON notification_rules USING GIN(event_types);

-- 3. Email Templates - Reusable HTML templates
CREATE TABLE IF NOT EXISTS email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(50) DEFAULT 'general',  -- alert, escalation, approval, digest, phishing

    -- Template content
    subject_template VARCHAR(500) NOT NULL,
    html_template TEXT NOT NULL,
    text_template TEXT,  -- Plain text fallback

    -- Variables available in this template
    available_variables JSONB DEFAULT '[]'::jsonb,

    -- Preview data for testing
    preview_data JSONB DEFAULT '{}'::jsonb,

    -- Flags
    is_system BOOLEAN DEFAULT FALSE,  -- Cannot be deleted
    is_default BOOLEAN DEFAULT FALSE,  -- Default for category

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_email_templates_category ON email_templates(category);

-- 4. Email Log - Sent email history
CREATE TABLE IF NOT EXISTS email_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(100),
    template_id UUID REFERENCES email_templates(id) ON DELETE SET NULL,

    -- Email details
    event_type VARCHAR(100),
    recipients TEXT[] NOT NULL,
    subject VARCHAR(500),
    body_preview VARCHAR(500),  -- First 500 chars of body

    -- Status
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'bounced')),
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,

    -- Related entities
    alert_id UUID,
    investigation_id UUID,

    -- Timestamps
    queued_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_email_log_status ON email_log(status);
CREATE INDEX IF NOT EXISTS idx_email_log_sent ON email_log(sent_at DESC);
CREATE INDEX IF NOT EXISTS idx_email_log_rule ON email_log(rule_id);

-- 5. Webhook Channels - Slack, Teams, etc.
CREATE TABLE IF NOT EXISTS webhook_channels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Channel type and config
    channel_type VARCHAR(50) NOT NULL CHECK (channel_type IN ('slack', 'teams', 'webex', 'discord', 'generic')),
    webhook_url TEXT NOT NULL,

    -- Optional: additional headers or config
    config JSONB DEFAULT '{}'::jsonb,

    enabled BOOLEAN DEFAULT TRUE,

    -- Stats
    last_used_at TIMESTAMP WITH TIME ZONE,
    success_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_webhook_channels_type ON webhook_channels(channel_type);
CREATE INDEX IF NOT EXISTS idx_webhook_channels_enabled ON webhook_channels(enabled);

-- 6. Inbound Email Mailboxes - For phishing reports and approvals
CREATE TABLE IF NOT EXISTS inbound_mailboxes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mailbox_id VARCHAR(100) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Mailbox type
    mailbox_type VARCHAR(50) NOT NULL CHECK (mailbox_type IN (
        'phishing_reports', 'alert_inbox', 'approval_responses', 'support_requests', 'general'
    )),

    -- Connection settings
    protocol VARCHAR(20) DEFAULT 'imap' CHECK (protocol IN ('imap', 'pop3', 'graph_api', 'gmail_api')),
    server VARCHAR(255),
    port INTEGER,
    use_ssl BOOLEAN DEFAULT TRUE,
    username VARCHAR(255),
    password VARCHAR(500),  -- Encrypted in application
    folder VARCHAR(100) DEFAULT 'INBOX',

    -- OAuth settings (for Graph API / Gmail API)
    oauth_client_id VARCHAR(255),
    oauth_tenant_id VARCHAR(255),
    oauth_refresh_token TEXT,

    -- Polling settings
    poll_interval_seconds INTEGER DEFAULT 300,  -- 5 minutes
    enabled BOOLEAN DEFAULT TRUE,

    -- Processing rules
    auto_create_alerts BOOLEAN DEFAULT TRUE,
    auto_acknowledge BOOLEAN DEFAULT TRUE,
    auto_ai_analysis BOOLEAN DEFAULT TRUE,  -- Auto-queue for AI agent analysis
    assign_to_queue VARCHAR(100),
    default_severity VARCHAR(20) DEFAULT 'medium',

    -- Stats
    last_poll_at TIMESTAMP WITH TIME ZONE,
    last_poll_status VARCHAR(50),
    emails_processed_total INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_inbound_mailboxes_type ON inbound_mailboxes(mailbox_type);
CREATE INDEX IF NOT EXISTS idx_inbound_mailboxes_enabled ON inbound_mailboxes(enabled);

-- 7. Inbound Email Queue - Emails awaiting processing
CREATE TABLE IF NOT EXISTS inbound_email_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    mailbox_id UUID REFERENCES inbound_mailboxes(id) ON DELETE CASCADE,

    -- Email details
    message_id VARCHAR(500) UNIQUE,  -- Email Message-ID header
    from_address VARCHAR(255),
    from_name VARCHAR(255),
    to_addresses TEXT[],
    cc_addresses TEXT[],
    subject VARCHAR(500),
    body_text TEXT,
    body_html TEXT,

    -- Attachments stored as JSON array
    attachments JSONB DEFAULT '[]'::jsonb,
    -- Format: [{filename, content_type, size_bytes, storage_path}]

    -- Headers for threading and analysis
    headers JSONB DEFAULT '{}'::jsonb,
    in_reply_to VARCHAR(500),
    references_header TEXT,

    -- Processing
    status VARCHAR(30) DEFAULT 'pending' CHECK (status IN (
        'pending', 'processing', 'processed', 'failed', 'ignored', 'spam'
    )),
    processing_result JSONB,  -- What was created (alert_id, etc.)
    error_message TEXT,

    -- Classification
    email_type VARCHAR(50),  -- phishing_report, approval_response, etc.
    spam_score DECIMAL(5,2),

    -- Timestamps
    received_at TIMESTAMP WITH TIME ZONE,
    processed_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_inbound_email_status ON inbound_email_queue(status);
CREATE INDEX IF NOT EXISTS idx_inbound_email_mailbox ON inbound_email_queue(mailbox_id);
CREATE INDEX IF NOT EXISTS idx_inbound_email_received ON inbound_email_queue(received_at DESC);
CREATE INDEX IF NOT EXISTS idx_inbound_email_from ON inbound_email_queue(from_address);

-- 8. Phishing Reports - User-submitted suspicious emails
CREATE TABLE IF NOT EXISTS phishing_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    report_id VARCHAR(100) UNIQUE NOT NULL DEFAULT ('PHR-' || UPPER(SUBSTRING(gen_random_uuid()::text, 1, 8))),

    -- Source email
    inbound_email_id UUID REFERENCES inbound_email_queue(id) ON DELETE SET NULL,
    message_id VARCHAR(500),  -- Email Message-ID header for tracking/threading

    -- Campaign linking (for identifying coordinated phishing)
    campaign_id UUID,  -- Links related phishing emails
    similarity_hash VARCHAR(64),  -- Hash for quick similarity matching

    -- Reporter info
    reporter_email VARCHAR(255) NOT NULL,
    reporter_name VARCHAR(255),
    reporter_department VARCHAR(255),

    -- Reported email details
    reported_subject VARCHAR(500),
    reported_from VARCHAR(255),
    reported_body_preview TEXT,
    reported_received_at TIMESTAMP WITH TIME ZONE,

    -- Extracted IOCs
    extracted_urls TEXT[] DEFAULT '{}',
    extracted_domains TEXT[] DEFAULT '{}',
    extracted_ips TEXT[] DEFAULT '{}',
    extracted_emails TEXT[] DEFAULT '{}',
    extracted_hashes TEXT[] DEFAULT '{}',

    -- Attachments
    attachment_count INTEGER DEFAULT 0,
    attachment_hashes TEXT[] DEFAULT '{}',

    -- Analysis
    status VARCHAR(30) DEFAULT 'new' CHECK (status IN (
        'new', 'analyzing', 'confirmed_phishing', 'confirmed_safe',
        'suspicious', 'closed', 'false_positive'
    )),
    severity VARCHAR(20) DEFAULT 'medium',
    verdict VARCHAR(50),
    analysis_notes TEXT,

    -- Related entities
    alert_id UUID,
    investigation_id UUID,

    -- Timestamps
    analyzed_at TIMESTAMP WITH TIME ZONE,
    analyzed_by VARCHAR(100),

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_phishing_reports_status ON phishing_reports(status);
CREATE INDEX IF NOT EXISTS idx_phishing_reports_reporter ON phishing_reports(reporter_email);
CREATE INDEX IF NOT EXISTS idx_phishing_reports_created ON phishing_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_phishing_reports_message_id ON phishing_reports(message_id);
CREATE INDEX IF NOT EXISTS idx_phishing_reports_campaign ON phishing_reports(campaign_id);
CREATE INDEX IF NOT EXISTS idx_phishing_reports_similarity ON phishing_reports(similarity_hash);

-- Phishing Campaigns - Groups related phishing emails
CREATE TABLE IF NOT EXISTS phishing_campaigns (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id VARCHAR(100) UNIQUE NOT NULL DEFAULT ('CAMP-' || UPPER(SUBSTRING(gen_random_uuid()::text, 1, 8))),

    -- Campaign details
    name VARCHAR(255),
    description TEXT,

    -- Indicators used to link emails
    common_sender_domain VARCHAR(255),
    common_subject_pattern VARCHAR(500),
    common_urls TEXT[],
    common_domains TEXT[],
    common_ips TEXT[],

    -- Statistics
    report_count INTEGER DEFAULT 1,
    unique_targets INTEGER DEFAULT 0,  -- Number of unique reporter emails
    first_seen TIMESTAMP WITH TIME ZONE,
    last_seen TIMESTAMP WITH TIME ZONE,

    -- Verdict
    status VARCHAR(30) DEFAULT 'active' CHECK (status IN (
        'active', 'contained', 'resolved', 'false_positive'
    )),
    severity VARCHAR(20) DEFAULT 'medium',
    threat_actor VARCHAR(255),
    attack_type VARCHAR(100),  -- credential_phishing, malware, bec, etc.

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_phishing_campaigns_status ON phishing_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_phishing_campaigns_sender ON phishing_campaigns(common_sender_domain);
CREATE INDEX IF NOT EXISTS idx_phishing_campaigns_created ON phishing_campaigns(created_at DESC);

-- 9. Email Digest Queue - For scheduled digest emails
CREATE TABLE IF NOT EXISTS email_digest_queue (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(100) REFERENCES notification_rules(rule_id) ON DELETE CASCADE,

    -- Digest window
    period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    period_end TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Collected items
    items JSONB DEFAULT '[]'::jsonb,  -- Array of events to include
    item_count INTEGER DEFAULT 0,

    -- Status
    status VARCHAR(20) DEFAULT 'collecting' CHECK (status IN ('collecting', 'pending', 'sent', 'failed')),

    -- Timestamps
    scheduled_send_at TIMESTAMP WITH TIME ZONE,
    sent_at TIMESTAMP WITH TIME ZONE,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_digest_queue_status ON email_digest_queue(status);
CREATE INDEX IF NOT EXISTS idx_digest_queue_scheduled ON email_digest_queue(scheduled_send_at);

-- Insert default email templates
INSERT INTO email_templates (template_id, name, description, category, subject_template, html_template, text_template, is_system, is_default, available_variables) VALUES
-- Alert Notification Template
('alert_notification', 'Alert Notification', 'Default template for alert notifications', 'alert',
 '[T1 Agentics] {severity} Alert: {title}',
 '<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1f2937; margin: 0; padding: 0; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #7c4dff 0%, #b388ff 100%); color: white; padding: 24px; }
        .header h1 { margin: 0; font-size: 20px; }
        .content { padding: 24px; background: #f9fafb; }
        .severity-badge { display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; color: white; }
        .severity-critical { background: #dc2626; }
        .severity-high { background: #f97316; }
        .severity-medium { background: #eab308; }
        .severity-low { background: #3b82f6; }
        .detail-box { background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; margin: 16px 0; }
        .detail-label { color: #6b7280; font-size: 12px; text-transform: uppercase; margin-bottom: 4px; }
        .detail-value { color: #1f2937; font-weight: 500; }
        .button { display: inline-block; padding: 12px 24px; background: #7c4dff; color: white; text-decoration: none; border-radius: 6px; font-weight: 500; }
        .footer { padding: 16px 24px; text-align: center; color: #6b7280; font-size: 12px; background: #f3f4f6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Alert</h1>
            <p style="margin: 8px 0 0 0; opacity: 0.9;">New alert requires attention</p>
        </div>
        <div class="content">
            <span class="severity-badge severity-{severity_lower}">{severity}</span>
            <h2 style="margin: 16px 0 8px 0;">{title}</h2>

            <div class="detail-box">
                <div class="detail-label">Alert ID</div>
                <div class="detail-value">{alert_id}</div>
            </div>

            <div class="detail-box">
                <div class="detail-label">Source</div>
                <div class="detail-value">{source}</div>
            </div>

            <div class="detail-box">
                <div class="detail-label">Description</div>
                <div class="detail-value">{description}</div>
            </div>

            <div class="detail-box">
                <div class="detail-label">Detected At</div>
                <div class="detail-value">{timestamp}</div>
            </div>

            <div style="text-align: center; margin-top: 24px;">
                <a href="{view_url}" class="button">View in T1 Agentics</a>
            </div>
        </div>
        <div class="footer">
            This is an automated notification from T1 Agentics SOC Platform.
        </div>
    </div>
</body>
</html>',
 'SECURITY ALERT: {severity}

Title: {title}
Alert ID: {alert_id}
Source: {source}
Detected: {timestamp}

{description}

View in T1 Agentics: {view_url}',
 TRUE, TRUE,
 '["title", "alert_id", "severity", "severity_lower", "source", "description", "timestamp", "view_url"]'::jsonb),

-- Escalation Template
('escalation', 'Escalation Notice', 'Template for escalated alerts and SLA breaches', 'escalation',
 '[T1 Agentics] Escalation: {title}',
 '<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1f2937; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #dc2626 0%, #f97316 100%); color: white; padding: 24px; }
        .content { padding: 24px; background: #fef2f2; }
        .warning-box { background: white; border: 2px solid #dc2626; border-radius: 8px; padding: 16px; margin: 16px 0; }
        .button { display: inline-block; padding: 12px 24px; background: #dc2626; color: white; text-decoration: none; border-radius: 6px; font-weight: 500; }
        .footer { padding: 16px 24px; text-align: center; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Escalation Notice</h1>
            <p style="margin: 8px 0 0 0;">Immediate attention required</p>
        </div>
        <div class="content">
            <div class="warning-box">
                <strong>Reason:</strong> {escalation_reason}<br>
                <strong>Time Elapsed:</strong> {time_elapsed}<br>
                <strong>Original Assignee:</strong> {original_assignee}
            </div>

            <h2>{title}</h2>
            <p><strong>Alert ID:</strong> {alert_id}</p>
            <p><strong>Severity:</strong> {severity}</p>
            <p>{description}</p>

            <div style="text-align: center; margin-top: 24px;">
                <a href="{view_url}" class="button">Take Action Now</a>
            </div>
        </div>
        <div class="footer">
            This escalation was triggered automatically by T1 Agentics SOC.
        </div>
    </div>
</body>
</html>',
 NULL, TRUE, TRUE,
 '["title", "alert_id", "severity", "description", "escalation_reason", "time_elapsed", "original_assignee", "view_url"]'::jsonb),

-- Approval Request Template
('approval_request', 'Approval Request', 'Template for action approval requests', 'approval',
 '[T1 Agentics] Approval Required: {action_type}',
 '<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1f2937; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #7c4dff 0%, #b388ff 100%); color: white; padding: 24px; }
        .content { padding: 24px; background: #f9fafb; }
        .action-box { background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 20px; margin: 16px 0; }
        .action-title { font-size: 18px; font-weight: 600; color: #1f2937; margin-bottom: 12px; }
        .button-group { text-align: center; margin-top: 24px; }
        .btn-approve { display: inline-block; padding: 14px 32px; background: #22c55e; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 0 8px; }
        .btn-reject { display: inline-block; padding: 14px 32px; background: #ef4444; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 0 8px; }
        .expires { color: #6b7280; font-size: 12px; margin-top: 16px; }
        .footer { padding: 16px 24px; text-align: center; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Approval Required</h1>
            <p style="margin: 8px 0 0 0;">A high-impact action needs your approval</p>
        </div>
        <div class="content">
            <div class="action-box">
                <div class="action-title">{action_type}</div>
                <p><strong>Target:</strong> {target}</p>
                <p><strong>Requested By:</strong> {requested_by}</p>
                <p><strong>Reason:</strong> {reason}</p>
                <p><strong>Related Alert:</strong> {alert_id}</p>
            </div>

            <p><strong>Impact Assessment:</strong></p>
            <p>{impact_description}</p>

            <div class="button-group">
                <a href="{approve_url}" class="btn-approve">Approve</a>
                <a href="{reject_url}" class="btn-reject">Reject</a>
            </div>
            <p class="expires" style="text-align: center;">
                This request expires at {expires_at}. Links are one-time use only.
            </p>
        </div>
        <div class="footer">
            T1 Agentics SOC Platform - Security Operations Center
        </div>
    </div>
</body>
</html>',
 NULL, TRUE, TRUE,
 '["action_type", "target", "requested_by", "reason", "alert_id", "impact_description", "approve_url", "reject_url", "expires_at"]'::jsonb),

-- Daily Digest Template
('daily_digest', 'Daily Digest', 'Template for daily summary emails', 'digest',
 '[T1 Agentics] Daily Security Digest - {date}',
 '<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1f2937; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #0ea5e9 0%, #38bdf8 100%); color: white; padding: 24px; }
        .content { padding: 24px; background: #f9fafb; }
        .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin: 16px 0; }
        .stat-box { background: white; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; text-align: center; }
        .stat-value { font-size: 32px; font-weight: 700; color: #7c4dff; }
        .stat-label { font-size: 12px; color: #6b7280; text-transform: uppercase; }
        .section { margin: 24px 0; }
        .section-title { font-size: 16px; font-weight: 600; margin-bottom: 12px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; }
        .alert-row { background: white; border: 1px solid #e5e7eb; border-radius: 6px; padding: 12px; margin: 8px 0; }
        .footer { padding: 16px 24px; text-align: center; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Daily Security Digest</h1>
            <p style="margin: 8px 0 0 0;">{date}</p>
        </div>
        <div class="content">
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{total_alerts}</div>
                    <div class="stat-label">Total Alerts</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{critical_alerts}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{resolved_count}</div>
                    <div class="stat-label">Resolved</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{avg_resolution_time}</div>
                    <div class="stat-label">Avg Resolution</div>
                </div>
            </div>

            <div class="section">
                <div class="section-title">Open Critical Alerts</div>
                {critical_alerts_list}
            </div>

            <div class="section">
                <div class="section-title">Top Alert Sources</div>
                {top_sources_list}
            </div>

            <div class="section">
                <div class="section-title">AI Agent Performance</div>
                <p>Automation Rate: {automation_rate}%</p>
                <p>Agent Accuracy: {agent_accuracy}%</p>
            </div>
        </div>
        <div class="footer">
            Generated by T1 Agentics SOC Platform
        </div>
    </div>
</body>
</html>',
 NULL, TRUE, TRUE,
 '["date", "total_alerts", "critical_alerts", "resolved_count", "avg_resolution_time", "critical_alerts_list", "top_sources_list", "automation_rate", "agent_accuracy"]'::jsonb),

-- Phishing Report Confirmation Template
('phishing_confirmation', 'Phishing Report Confirmation', 'Sent to users who report phishing emails', 'phishing',
 '[T1 Agentics] Phishing Report Received - {report_id}',
 '<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; color: #1f2937; }
        .container { max-width: 600px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #22c55e 0%, #4ade80 100%); color: white; padding: 24px; }
        .content { padding: 24px; background: #f0fdf4; }
        .check-icon { font-size: 48px; text-align: center; margin-bottom: 16px; }
        .detail-box { background: white; border: 1px solid #bbf7d0; border-radius: 8px; padding: 16px; margin: 16px 0; }
        .footer { padding: 16px 24px; text-align: center; color: #6b7280; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Report Received</h1>
            <p style="margin: 8px 0 0 0;">Thank you for reporting suspicious email</p>
        </div>
        <div class="content">
            <div class="check-icon">[OK]</div>
            <h2 style="text-align: center; margin: 0 0 16px 0;">Your report has been submitted</h2>

            <div class="detail-box">
                <p><strong>Report ID:</strong> {report_id}</p>
                <p><strong>Submitted:</strong> {submitted_at}</p>
                <p><strong>Status:</strong> Under Review</p>
            </div>

            <p>Our security team will analyze the reported email and take appropriate action. You may receive a follow-up if additional information is needed.</p>

            <p><strong>What happens next?</strong></p>
            <ul>
                <li>The email will be analyzed for malicious content</li>
                <li>URLs and attachments will be scanned</li>
                <li>If confirmed malicious, protective measures will be taken</li>
            </ul>
        </div>
        <div class="footer">
            Thank you for helping keep our organization secure!<br>
            - T1 Agentics Security Team
        </div>
    </div>
</body>
</html>',
 NULL, TRUE, TRUE,
 '["report_id", "submitted_at", "reporter_email"]'::jsonb)

ON CONFLICT (template_id) DO NOTHING;

-- ============================================================================
-- PHASE 14: POST-RESOLUTION WORKFLOW TABLES
-- ============================================================================

-- ============================================================================
-- CASE_SUMMARIES TABLE
-- Store generated case summaries for investigations
-- ============================================================================
CREATE TABLE IF NOT EXISTS case_summaries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Investigation reference
    investigation_id VARCHAR(255) UNIQUE NOT NULL,

    -- Summary content
    summary_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    format VARCHAR(50) DEFAULT 'detailed',

    -- Metadata
    generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    generated_by VARCHAR(100) DEFAULT 'system',

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_case_summaries_investigation ON case_summaries(investigation_id);
CREATE INDEX idx_case_summaries_generated ON case_summaries(generated_at DESC);

-- ============================================================================
-- POST_RESOLUTION_TASKS TABLE
-- Tasks created for post-resolution workflow (email, ITSM, CMDB, blocklist)
-- ============================================================================
CREATE TABLE IF NOT EXISTS post_resolution_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Task identification
    investigation_id VARCHAR(255) NOT NULL,
    task_type VARCHAR(50) NOT NULL CHECK (task_type IN (
        'email_summary', 'itsm_export', 'cmdb_update', 'create_blocklist', 'custom'
    )),

    -- Configuration
    task_config JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Status tracking
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'running', 'completed', 'failed', 'cancelled'
    )),

    -- Results
    result_data JSONB DEFAULT '{}'::jsonb,
    error_message TEXT,

    -- Audit
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_post_resolution_tasks_investigation ON post_resolution_tasks(investigation_id);
CREATE INDEX idx_post_resolution_tasks_status ON post_resolution_tasks(status);
CREATE INDEX idx_post_resolution_tasks_type ON post_resolution_tasks(task_type);
CREATE INDEX idx_post_resolution_tasks_created ON post_resolution_tasks(created_at DESC);

-- ============================================================================
-- POST_RESOLUTION_RULES TABLE
-- Automation rules for post-resolution tasks
-- ============================================================================
CREATE TABLE IF NOT EXISTS post_resolution_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Rule identification
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Rule logic
    conditions JSONB NOT NULL DEFAULT '{}'::jsonb,  -- Conditions to match investigations
    actions JSONB NOT NULL DEFAULT '[]'::jsonb,      -- Actions to execute when matched

    -- Configuration
    enabled BOOLEAN DEFAULT true,
    priority INTEGER DEFAULT 10,  -- Lower = higher priority

    -- Audit
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_post_resolution_rules_enabled ON post_resolution_rules(enabled, priority);
CREATE INDEX idx_post_resolution_rules_name ON post_resolution_rules(name);

-- ============================================================================
-- IOC_BLOCKLIST TABLE
-- Blocked IOCs from investigations (for prevention)
-- ============================================================================
CREATE TABLE IF NOT EXISTS ioc_blocklist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- IOC identification
    ioc_type VARCHAR(50) NOT NULL,
    ioc_value VARCHAR(500) NOT NULL,

    -- Source tracking
    source VARCHAR(255),  -- e.g., "Investigation: INV-12345678"
    reason TEXT,

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Metadata
    added_by VARCHAR(100),
    added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    UNIQUE(ioc_type, ioc_value)
);

CREATE INDEX idx_ioc_blocklist_type ON ioc_blocklist(ioc_type);
CREATE INDEX idx_ioc_blocklist_active ON ioc_blocklist(is_active) WHERE is_active = true;
CREATE INDEX idx_ioc_blocklist_value ON ioc_blocklist(ioc_value);

-- ============================================================================
-- ITSM_CONFIGURATIONS TABLE
-- Configuration for ServiceNow, Jira, and custom webhook integrations
-- ============================================================================
CREATE TABLE IF NOT EXISTS itsm_configurations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Basic info
    name VARCHAR(255) NOT NULL UNIQUE,
    system_type VARCHAR(50) NOT NULL,  -- servicenow, jira, webhook

    -- Connection
    base_url VARCHAR(500) NOT NULL,
    instance_name VARCHAR(255),  -- For ServiceNow instances

    -- Authentication (references credentials vault)
    credential_id VARCHAR(255),

    -- Defaults
    default_project VARCHAR(100),      -- For Jira project key
    default_ticket_type VARCHAR(100) DEFAULT 'incident',

    -- Field mappings (system-specific customization)
    field_mappings JSONB DEFAULT '{}',

    -- Status
    enabled BOOLEAN DEFAULT true,

    -- Audit
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_itsm_config_enabled ON itsm_configurations(enabled) WHERE enabled = true;
CREATE INDEX idx_itsm_config_type ON itsm_configurations(system_type);

-- ============================================================================
-- ITSM_EXPORTS TABLE
-- Log of all investigation exports to ITSM systems
-- ============================================================================
CREATE TABLE IF NOT EXISTS itsm_exports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- References
    investigation_id VARCHAR(255) NOT NULL,
    itsm_config_id VARCHAR(255) NOT NULL,

    -- Ticket details
    ticket_id VARCHAR(255),
    ticket_url VARCHAR(500),
    ticket_type VARCHAR(100),

    -- Export data (for audit)
    export_data JSONB DEFAULT '{}',

    -- Status
    status VARCHAR(50) DEFAULT 'success',
    error_message TEXT,

    -- Audit
    created_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_itsm_exports_investigation ON itsm_exports(investigation_id);
CREATE INDEX idx_itsm_exports_created ON itsm_exports(created_at DESC);

-- ============================================================================
-- SEED DEFAULT POST-RESOLUTION RULES
-- ============================================================================
INSERT INTO post_resolution_rules (name, description, conditions, actions, enabled, priority, created_by) VALUES
    ('Critical True Positive - Full Workflow',
     'Execute full post-resolution workflow for confirmed critical threats',
     '{"severity": ["critical", "high"], "disposition": ["MALICIOUS", "TRUE_POSITIVE"]}'::jsonb,
     '[{"type": "email_summary", "config": {"template": "executive"}}, {"type": "itsm_export", "config": {"system": "servicenow", "ticket_type": "problem"}}, {"type": "cmdb_update", "config": {"action": "mark_remediated"}}, {"type": "create_blocklist", "config": {}}]'::jsonb,
     true, 1, 'system'),

    ('Medium Severity - Summary Only',
     'Generate case summary for medium severity confirmed threats',
     '{"severity": ["medium"], "disposition": ["MALICIOUS", "TRUE_POSITIVE"]}'::jsonb,
     '[{"type": "email_summary", "config": {"template": "standard"}}]'::jsonb,
     true, 10, 'system'),

    ('Resolved Investigation - Archive',
     'Archive summaries for all resolved investigations',
     '{"state": ["RESOLVED", "CLOSED"]}'::jsonb,
     '[{"type": "email_summary", "config": {"template": "standard"}}]'::jsonb,
     true, 100, 'system')

ON CONFLICT DO NOTHING;

-- END OF SCHEMA
-- ============================================================================

-- ============================================================================
-- ALERT ATTACHMENTS TABLE
-- ============================================================================
CREATE TABLE IF NOT EXISTS alert_attachments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attachment_id VARCHAR(100) UNIQUE NOT NULL DEFAULT ('ATT-' || UPPER(SUBSTRING(gen_random_uuid()::text, 1, 8))),
    alert_id VARCHAR(255) NOT NULL,  -- References alerts(alert_id)

    -- File info
    filename VARCHAR(255) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    mime_type VARCHAR(100),

    -- Storage info
    storage_path TEXT NOT NULL,
    storage_type VARCHAR(20) DEFAULT 'local' CHECK (storage_type IN ('local', 's3', 'azure', 'gcs')),

    -- Hashes
    md5_hash VARCHAR(32),
    sha1_hash VARCHAR(40),
    sha256_hash VARCHAR(64),

    -- Metadata
    description TEXT,
    uploaded_by VARCHAR(100),

    -- Analysis status
    analysis_status VARCHAR(30) DEFAULT 'pending' CHECK (analysis_status IN (
        'pending', 'analyzing', 'clean', 'suspicious', 'malicious', 'error'
    )),
    is_malicious BOOLEAN,
    threat_score INTEGER CHECK (threat_score >= 0 AND threat_score <= 100),
    analysis_results JSONB DEFAULT '{}',

    -- Timestamps
    uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    analyzed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_alert_attachments_alert_id ON alert_attachments(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_attachments_sha256 ON alert_attachments(sha256_hash);
CREATE INDEX IF NOT EXISTS idx_alert_attachments_status ON alert_attachments(analysis_status);
CREATE INDEX IF NOT EXISTS idx_alert_attachments_uploaded ON alert_attachments(uploaded_at DESC);

-- ============================================================================
-- KNOWLEDGE BASE TABLES (Company Best Practices / SOPs)
-- ============================================================================
CREATE TABLE IF NOT EXISTS knowledge_base (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kb_id VARCHAR(20) UNIQUE NOT NULL,  -- Human-readable ID like KB-A1B2C3D4

    -- Core content
    title VARCHAR(500) NOT NULL,
    content TEXT NOT NULL,
    content_type VARCHAR(50) DEFAULT 'sop' CHECK (content_type IN (
        'sop', 'playbook', 'escalation', 'compliance', 'permission',
        'approval_rule', 'handling_rule', 'runbook', 'policy', 'procedure',
        'guide', 'checklist'
    )),

    -- Categorization
    category VARCHAR(100),
    subcategory VARCHAR(100),
    tags TEXT[] DEFAULT '{}',

    -- Applicability filters
    severity_filter TEXT[] DEFAULT '{}',  -- Which severities this applies to
    incident_types TEXT[] DEFAULT '{}',   -- Which incident types this applies to
    ioc_types TEXT[] DEFAULT '{}',        -- IOC types this is relevant for
    mitre_techniques TEXT[] DEFAULT '{}', -- MITRE ATT&CK techniques
    compliance_frameworks TEXT[] DEFAULT '{}', -- NIST, SOC2, ISO27001, etc.

    -- Ordering and status
    priority INTEGER DEFAULT 100,  -- Lower = higher priority
    is_active BOOLEAN DEFAULT TRUE,
    version INTEGER DEFAULT 1,

    -- AI processing
    ai_processed BOOLEAN DEFAULT FALSE,
    ai_summary TEXT,
    ai_extracted_rules JSONB DEFAULT '[]',
    -- Note: embedding column for vector search requires pgvector extension
    -- Can be added later with: ALTER TABLE knowledge_base ADD COLUMN embedding VECTOR(1536);

    -- Source tracking
    source_document_name VARCHAR(500),
    source_document_type VARCHAR(50),

    -- Approval workflow
    created_by VARCHAR(100),
    approved_by VARCHAR(100),
    approved_at TIMESTAMP WITH TIME ZONE,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for knowledge base
CREATE INDEX IF NOT EXISTS idx_kb_kb_id ON knowledge_base(kb_id);
CREATE INDEX IF NOT EXISTS idx_kb_content_type ON knowledge_base(content_type);
CREATE INDEX IF NOT EXISTS idx_kb_category ON knowledge_base(category);
CREATE INDEX IF NOT EXISTS idx_kb_tags ON knowledge_base USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_kb_severity_filter ON knowledge_base USING GIN(severity_filter);
CREATE INDEX IF NOT EXISTS idx_kb_incident_types ON knowledge_base USING GIN(incident_types);
CREATE INDEX IF NOT EXISTS idx_kb_ioc_types ON knowledge_base USING GIN(ioc_types);
CREATE INDEX IF NOT EXISTS idx_kb_mitre ON knowledge_base USING GIN(mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_kb_priority ON knowledge_base(priority);
CREATE INDEX IF NOT EXISTS idx_kb_is_active ON knowledge_base(is_active);
CREATE INDEX IF NOT EXISTS idx_kb_approved_at ON knowledge_base(approved_at);
CREATE INDEX IF NOT EXISTS idx_kb_created_at ON knowledge_base(created_at DESC);

-- Full-text search index
CREATE INDEX IF NOT EXISTS idx_kb_fts ON knowledge_base
    USING GIN(to_tsvector('english', title || ' ' || content));

-- Version history for knowledge base entries
CREATE TABLE IF NOT EXISTS knowledge_base_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kb_id VARCHAR(20) NOT NULL REFERENCES knowledge_base(kb_id) ON DELETE CASCADE,
    version INTEGER NOT NULL,

    -- Snapshot of content at this version
    title VARCHAR(500) NOT NULL,
    content TEXT NOT NULL,

    -- Change tracking
    changed_by VARCHAR(100),
    change_reason TEXT,

    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_kb_versions_kb_id ON knowledge_base_versions(kb_id);
CREATE INDEX IF NOT EXISTS idx_kb_versions_version ON knowledge_base_versions(version);

-- Document uploads for AI processing
CREATE TABLE IF NOT EXISTS kb_document_uploads (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    upload_id VARCHAR(50) UNIQUE NOT NULL,

    -- File info
    filename VARCHAR(500) NOT NULL,
    file_type VARCHAR(20) NOT NULL,
    file_size INTEGER,

    -- Processing status
    status VARCHAR(30) DEFAULT 'pending' CHECK (status IN (
        'pending', 'processing', 'completed', 'failed'
    )),
    error_message TEXT,

    -- Results
    resulting_kb_ids TEXT[] DEFAULT '{}',

    -- Metadata
    uploaded_by VARCHAR(100),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_kb_uploads_upload_id ON kb_document_uploads(upload_id);
CREATE INDEX IF NOT EXISTS idx_kb_uploads_status ON kb_document_uploads(status);
CREATE INDEX IF NOT EXISTS idx_kb_uploads_created_at ON kb_document_uploads(created_at DESC);

-- SOP Effectiveness Tracking for recommendation improvements
CREATE TABLE IF NOT EXISTS sop_effectiveness_tracking (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kb_id VARCHAR(20) NOT NULL REFERENCES knowledge_base(kb_id) ON DELETE CASCADE,
    investigation_id VARCHAR(100) NOT NULL,

    -- Feedback
    was_helpful BOOLEAN NOT NULL,
    resolution_time_minutes INTEGER,

    -- Metadata
    tracked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Prevent duplicate feedback per KB/investigation pair
    UNIQUE(kb_id, investigation_id)
);

CREATE INDEX IF NOT EXISTS idx_sop_effectiveness_kb_id ON sop_effectiveness_tracking(kb_id);
CREATE INDEX IF NOT EXISTS idx_sop_effectiveness_investigation ON sop_effectiveness_tracking(investigation_id);
CREATE INDEX IF NOT EXISTS idx_sop_effectiveness_helpful ON sop_effectiveness_tracking(was_helpful);

-- ============================================================================
-- ML CLASSIFIER TABLES
-- Training is batch-triggered, not continuous
-- ============================================================================

-- Track ML training runs
CREATE TABLE IF NOT EXISTS ml_training_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    trained_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) NOT NULL CHECK (status IN ('success', 'failed', 'skipped')),
    samples_used INTEGER DEFAULT 0,
    accuracy FLOAT,
    trigger_reason VARCHAR(50),  -- 'bucket_full', 'time_window', 'drift', 'manual'
    error_message TEXT,
    model_version VARCHAR(50),
    training_duration_ms INTEGER,
    config JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_ml_training_status ON ml_training_runs(status);
CREATE INDEX IF NOT EXISTS idx_ml_training_trained_at ON ml_training_runs(trained_at DESC);

-- Track ML predictions for drift detection and feedback loop
CREATE TABLE IF NOT EXISTS ml_predictions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE,
    predicted_disposition VARCHAR(50) NOT NULL,
    confidence FLOAT NOT NULL,
    model_version VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    -- Feedback columns for ML learning loop
    actual_disposition VARCHAR(50),           -- Analyst's final verdict
    resolved_by VARCHAR(255),                 -- Who resolved it
    resolved_at TIMESTAMP WITH TIME ZONE,     -- When it was resolved
    investigation_id VARCHAR(100),            -- Link to investigation if any
    UNIQUE(alert_id)  -- One prediction per alert
);

CREATE INDEX IF NOT EXISTS idx_ml_predictions_alert ON ml_predictions(alert_id);
CREATE INDEX IF NOT EXISTS idx_ml_predictions_created ON ml_predictions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ml_predictions_confidence ON ml_predictions(confidence);
CREATE INDEX IF NOT EXISTS idx_ml_predictions_actual ON ml_predictions(actual_disposition) WHERE actual_disposition IS NOT NULL;

-- Add columns if they don't exist (for upgrades)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ml_predictions' AND column_name = 'actual_disposition') THEN
        ALTER TABLE ml_predictions ADD COLUMN actual_disposition VARCHAR(50);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ml_predictions' AND column_name = 'resolved_by') THEN
        ALTER TABLE ml_predictions ADD COLUMN resolved_by VARCHAR(255);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ml_predictions' AND column_name = 'resolved_at') THEN
        ALTER TABLE ml_predictions ADD COLUMN resolved_at TIMESTAMP WITH TIME ZONE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'ml_predictions' AND column_name = 'investigation_id') THEN
        ALTER TABLE ml_predictions ADD COLUMN investigation_id VARCHAR(100);
    END IF;
END $$;

-- ============================================================================
-- LOG COLLECTION & DETECTION ENGINE TABLES
-- For SOC2 Type 2 and PCI-DSS compliance
-- ============================================================================

-- Log Collection Agents (persistent registration)
CREATE TABLE IF NOT EXISTS log_agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id VARCHAR(255) UNIQUE NOT NULL,          -- Agent's self-reported ID
    hostname VARCHAR(255) NOT NULL,
    os_type VARCHAR(50) NOT NULL CHECK (os_type IN ('windows', 'linux', 'macos', 'other')),
    os_version VARCHAR(100),
    ip_address INET,
    agent_version VARCHAR(50),

    -- Status tracking
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'maintenance', 'decommissioned')),
    last_heartbeat TIMESTAMP WITH TIME ZONE,
    last_event_received TIMESTAMP WITH TIME ZONE,
    events_received_total BIGINT DEFAULT 0,

    -- Configuration
    config JSONB DEFAULT '{}',                       -- Agent-specific config (log sources, filters)
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],            -- For grouping/filtering agents

    -- Audit trail (SOC2 requirement)
    registered_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    registered_by VARCHAR(255),                     -- User who registered/approved
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    metadata JSONB DEFAULT '{}'                     -- Flexible metadata (location, department, etc.)
);

CREATE INDEX IF NOT EXISTS idx_log_agents_hostname ON log_agents(hostname);
CREATE INDEX IF NOT EXISTS idx_log_agents_os_type ON log_agents(os_type);
CREATE INDEX IF NOT EXISTS idx_log_agents_status ON log_agents(status);
CREATE INDEX IF NOT EXISTS idx_log_agents_last_heartbeat ON log_agents(last_heartbeat);
CREATE INDEX IF NOT EXISTS idx_log_agents_tags ON log_agents USING GIN(tags);

-- Detection Rules (Sigma-compatible schema)
CREATE TABLE IF NOT EXISTS detection_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id VARCHAR(100) UNIQUE NOT NULL,           -- Human-readable rule ID (e.g., 'AUTH-001')
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Rule classification
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('informational', 'low', 'medium', 'high', 'critical')),
    status VARCHAR(20) DEFAULT 'enabled' CHECK (status IN ('enabled', 'disabled', 'testing', 'deprecated')),
    rule_type VARCHAR(50) DEFAULT 'detection' CHECK (rule_type IN ('detection', 'hunting', 'correlation', 'threshold')),

    -- Sigma-compatible fields
    logsource JSONB NOT NULL,                       -- {"category": "process_creation", "product": "windows", "service": "sysmon"}
    detection JSONB NOT NULL,                       -- Sigma detection logic
    condition VARCHAR(1000),                        -- Sigma condition string

    -- MITRE ATT&CK mapping (compliance requirement)
    mitre_attack JSONB DEFAULT '[]',               -- [{"tactic": "TA0001", "technique": "T1078", "subtechnique": "T1078.001"}]

    -- Compliance tags
    compliance_frameworks TEXT[] DEFAULT ARRAY[]::TEXT[],  -- ['SOC2', 'PCI-DSS', 'HIPAA', 'NIST']

    -- Rule metadata
    author VARCHAR(255),
    "references" TEXT[] DEFAULT ARRAY[]::TEXT[],     -- URLs to documentation
    tags TEXT[] DEFAULT ARRAY[]::TEXT[],           -- Arbitrary tags for filtering
    false_positive_notes TEXT,                      -- Known FP scenarios

    -- Response actions (what Riggs should do)
    auto_create_alert BOOLEAN DEFAULT true,
    alert_priority VARCHAR(20) DEFAULT 'medium',
    response_actions JSONB DEFAULT '[]',           -- [{"action": "enrich_ioc", "params": {...}}]

    -- Audit trail
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255),

    -- Version control (for rule changes)
    version INTEGER DEFAULT 1,
    previous_versions JSONB DEFAULT '[]'           -- History of rule changes
);

CREATE INDEX IF NOT EXISTS idx_detection_rules_rule_id ON detection_rules(rule_id);
CREATE INDEX IF NOT EXISTS idx_detection_rules_severity ON detection_rules(severity);
CREATE INDEX IF NOT EXISTS idx_detection_rules_status ON detection_rules(status);
CREATE INDEX IF NOT EXISTS idx_detection_rules_rule_type ON detection_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_detection_rules_logsource ON detection_rules USING GIN(logsource);
CREATE INDEX IF NOT EXISTS idx_detection_rules_mitre ON detection_rules USING GIN(mitre_attack);
CREATE INDEX IF NOT EXISTS idx_detection_rules_compliance ON detection_rules USING GIN(compliance_frameworks);
CREATE INDEX IF NOT EXISTS idx_detection_rules_tags ON detection_rules USING GIN(tags);

-- Detection Rule Hits (track when rules fire)
CREATE TABLE IF NOT EXISTS detection_hits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID REFERENCES detection_rules(id) ON DELETE SET NULL,
    rule_name VARCHAR(255) NOT NULL,                -- Denormalized for fast display

    -- Event reference (OpenSearch document)
    event_id VARCHAR(255) NOT NULL,                 -- OpenSearch _id
    event_index VARCHAR(255) NOT NULL,              -- OpenSearch index name
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,

    -- Detection context
    matched_fields JSONB NOT NULL,                  -- Fields that matched the rule
    severity VARCHAR(20) NOT NULL,

    -- Source information
    agent_id UUID REFERENCES log_agents(id) ON DELETE SET NULL,
    hostname VARCHAR(255),
    source_ip INET,

    -- Alert linkage
    alert_created BOOLEAN DEFAULT false,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,

    -- Analyst feedback (for tuning)
    disposition VARCHAR(50) CHECK (disposition IN ('true_positive', 'false_positive', 'benign', 'inconclusive', NULL)),
    disposition_by VARCHAR(255),
    disposition_at TIMESTAMP WITH TIME ZONE,
    disposition_notes TEXT,

    -- Audit
    detected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_detection_hits_rule ON detection_hits(rule_id);
CREATE INDEX IF NOT EXISTS idx_detection_hits_event ON detection_hits(event_id);
CREATE INDEX IF NOT EXISTS idx_detection_hits_timestamp ON detection_hits(event_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_detection_hits_severity ON detection_hits(severity);
CREATE INDEX IF NOT EXISTS idx_detection_hits_agent ON detection_hits(agent_id);
CREATE INDEX IF NOT EXISTS idx_detection_hits_hostname ON detection_hits(hostname);
CREATE INDEX IF NOT EXISTS idx_detection_hits_alert ON detection_hits(alert_id);
CREATE INDEX IF NOT EXISTS idx_detection_hits_disposition ON detection_hits(disposition);
CREATE INDEX IF NOT EXISTS idx_detection_hits_detected ON detection_hits(detected_at DESC);

-- Retention Policies (SOC2/PCI compliance - data retention requirements)
CREATE TABLE IF NOT EXISTS retention_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,

    -- What this policy applies to
    data_type VARCHAR(50) NOT NULL CHECK (data_type IN ('logs', 'alerts', 'investigations', 'audit_logs', 'detection_hits')),
    index_pattern VARCHAR(255),                     -- For OpenSearch: 'security-events-*'

    -- Retention settings
    hot_days INTEGER DEFAULT 7,                     -- Days in hot storage (fast SSD)
    warm_days INTEGER DEFAULT 30,                   -- Days in warm storage
    cold_days INTEGER DEFAULT 365,                  -- Days in cold storage
    delete_after_days INTEGER DEFAULT 2555,         -- 7 years for PCI-DSS

    -- Compliance mapping
    compliance_requirement VARCHAR(255),            -- 'PCI-DSS 10.7', 'SOC2 CC7.2'

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(255),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_by VARCHAR(255)
);

CREATE INDEX IF NOT EXISTS idx_retention_policies_data_type ON retention_policies(data_type);
CREATE INDEX IF NOT EXISTS idx_retention_policies_active ON retention_policies(is_active);

-- Insert default retention policies for compliance
INSERT INTO retention_policies (name, description, data_type, index_pattern, hot_days, warm_days, cold_days, delete_after_days, compliance_requirement, created_by)
VALUES
    ('Security Events - PCI', 'Security event logs per PCI-DSS 10.7', 'logs', 'security-events-*', 7, 30, 365, 2555, 'PCI-DSS 10.7 - Retain audit trail history for at least one year', 'system'),
    ('Audit Logs - SOC2', 'System audit logs per SOC2 CC7.2', 'audit_logs', NULL, 30, 90, 365, 2555, 'SOC2 CC7.2 - System monitoring and anomaly detection', 'system'),
    ('Alerts', 'Security alerts retention', 'alerts', NULL, 30, 90, 365, 2555, 'SOC2/PCI - Security incident records', 'system'),
    ('Investigations', 'Investigation case files', 'investigations', NULL, 90, 180, 730, 2555, 'Legal hold and compliance review', 'system'),
    ('Detection Hits', 'Detection rule matches', 'detection_hits', NULL, 30, 90, 365, 2555, 'Detection tuning and metrics', 'system')
ON CONFLICT (name) DO NOTHING;

-- Log Source Configuration (what log types we accept)
CREATE TABLE IF NOT EXISTS log_source_configs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_type VARCHAR(100) UNIQUE NOT NULL,       -- 'windows_security', 'linux_syslog', 'network_firewall'
    display_name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Parsing configuration
    parser_type VARCHAR(50) DEFAULT 'json' CHECK (parser_type IN ('json', 'syslog', 'cef', 'leef', 'csv', 'regex', 'xml')),
    parser_config JSONB DEFAULT '{}',               -- Parser-specific settings

    -- Normalization mapping to ECS
    field_mappings JSONB DEFAULT '{}',              -- {"source_field": "ecs.field.path"}

    -- Enrichment settings
    auto_enrichments JSONB DEFAULT '[]',            -- [{"type": "geoip", "field": "source.ip"}]

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_log_source_configs_type ON log_source_configs(source_type);
CREATE INDEX IF NOT EXISTS idx_log_source_configs_active ON log_source_configs(is_active);

-- Insert default log source configs
INSERT INTO log_source_configs (source_type, display_name, description, parser_type, parser_config)
VALUES
    ('windows_security', 'Windows Security Events', 'Windows Security Event Log (Event IDs 4624, 4625, 4688, etc.)', 'json', '{"event_id_field": "EventID", "timestamp_field": "TimeCreated"}'),
    ('windows_sysmon', 'Windows Sysmon', 'Sysmon process and network monitoring', 'json', '{"event_id_field": "EventID", "timestamp_field": "UtcTime"}'),
    ('linux_syslog', 'Linux Syslog', 'Standard Linux syslog messages', 'syslog', '{"facility_field": "facility", "severity_field": "severity"}'),
    ('linux_auditd', 'Linux Auditd', 'Linux Audit Daemon logs', 'json', '{"type_field": "type", "timestamp_field": "timestamp"}'),
    ('network_firewall', 'Firewall Logs', 'Generic firewall connection logs', 'json', '{}'),
    ('cloud_audit', 'Cloud Audit Logs', 'AWS CloudTrail, Azure Activity, GCP Audit', 'json', '{}')
ON CONFLICT (source_type) DO NOTHING;

-- ============================================================================
-- LOG INDEXES (Splunk-style) - Role-based log access control
-- ============================================================================

-- Log Indexes - Similar to Splunk indexes, defines logical groupings of logs
CREATE TABLE IF NOT EXISTS log_indexes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,              -- 'security', 'network', 'endpoint', 'admin'
    display_name VARCHAR(255) NOT NULL,             -- 'Security Events'
    description TEXT,

    -- OpenSearch index pattern mapping
    index_pattern VARCHAR(255) NOT NULL,            -- 'logs-security-*'

    -- Data classification
    data_classification VARCHAR(50) DEFAULT 'internal' CHECK (data_classification IN (
        'public', 'internal', 'confidential', 'restricted'
    )),

    -- Retention settings (days)
    retention_days INTEGER DEFAULT 90,

    -- Status
    is_active BOOLEAN DEFAULT true,
    is_default BOOLEAN DEFAULT false,               -- Default index for new logs without explicit routing

    -- Metadata
    source_types TEXT[],                            -- ['edr_process', 'edr_network', 'edr_file']
    tags TEXT[],                                    -- ['endpoint', 'detection', 'edr']

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_log_indexes_name ON log_indexes(name);
CREATE INDEX IF NOT EXISTS idx_log_indexes_pattern ON log_indexes(index_pattern);
CREATE INDEX IF NOT EXISTS idx_log_indexes_active ON log_indexes(is_active);
CREATE INDEX IF NOT EXISTS idx_log_indexes_classification ON log_indexes(data_classification);

-- Role-Index Permissions - Which roles can access which indexes
CREATE TABLE IF NOT EXISTS role_index_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    role VARCHAR(50) NOT NULL,                      -- 'admin', 'analyst', 'read_only', or custom role
    index_id UUID REFERENCES log_indexes(id) ON DELETE CASCADE,
    index_name VARCHAR(100) NOT NULL,               -- Denormalized for faster lookups

    -- Permission levels
    can_read BOOLEAN DEFAULT false,
    can_write BOOLEAN DEFAULT false,
    can_delete BOOLEAN DEFAULT false,
    can_admin BOOLEAN DEFAULT false,                -- Can modify index settings

    -- Field-level restrictions (optional, JSONB array of allowed/denied fields)
    allowed_fields JSONB DEFAULT NULL,              -- NULL = all fields, ['host.*', 'process.*'] = only these
    denied_fields JSONB DEFAULT NULL,               -- ['user.password', 'credentials.*'] = hide these

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),

    UNIQUE(role, index_id)
);

CREATE INDEX IF NOT EXISTS idx_role_index_perms_role ON role_index_permissions(role);
CREATE INDEX IF NOT EXISTS idx_role_index_perms_index ON role_index_permissions(index_id);
CREATE INDEX IF NOT EXISTS idx_role_index_perms_name ON role_index_permissions(index_name);

-- User-specific Index Overrides (for exceptions to role-based access)
CREATE TABLE IF NOT EXISTS user_index_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(100) NOT NULL,                 -- Denormalized
    index_id UUID REFERENCES log_indexes(id) ON DELETE CASCADE,
    index_name VARCHAR(100) NOT NULL,               -- Denormalized

    -- Permission override (true = grant, false = deny, NULL = inherit from role)
    can_read BOOLEAN DEFAULT NULL,
    can_write BOOLEAN DEFAULT NULL,
    can_delete BOOLEAN DEFAULT NULL,

    -- Reason for override
    reason TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,            -- Optional expiration

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),

    UNIQUE(user_id, index_id)
);

CREATE INDEX IF NOT EXISTS idx_user_index_perms_user ON user_index_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_index_perms_username ON user_index_permissions(username);
CREATE INDEX IF NOT EXISTS idx_user_index_perms_index ON user_index_permissions(index_id);

-- Log Search Audit - Track who searches what (SOC2 compliance)
CREATE TABLE IF NOT EXISTS log_search_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(100) NOT NULL,
    user_role VARCHAR(50),

    -- Search details
    search_query TEXT,
    index_names TEXT[],                             -- Which indexes were searched
    time_range VARCHAR(50),                         -- '24h', '7d', etc.

    -- Telemetry search fields (three-class model)
    search_type VARCHAR(20) DEFAULT 'log',          -- 'log' or 'telemetry'
    event_classes TEXT[],                           -- ['observation', 'assertion', 'decision']

    -- Results
    results_count INTEGER,
    execution_time_ms INTEGER,

    -- Request info
    ip_address INET,
    user_agent TEXT,

    -- Status
    success BOOLEAN DEFAULT true,
    error_message TEXT,

    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_log_search_audit_user ON log_search_audit(username, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_log_search_audit_time ON log_search_audit(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_log_search_audit_indexes ON log_search_audit USING GIN(index_names);

-- Insert default log indexes (Splunk-style)
INSERT INTO log_indexes (name, display_name, description, index_pattern, data_classification, source_types, tags, is_default) VALUES
    ('main', 'Main', 'Default index for general logs', 'logs-main-*', 'internal', ARRAY['generic'], ARRAY['default'], true),
    ('security', 'Security Events', 'Security-related events from all sources', 'logs-security-*', 'confidential', ARRAY['edr_process', 'edr_network', 'edr_file', 'windows_security', 'linux_auditd'], ARRAY['security', 'siem', 'detection']),
    ('endpoint', 'Endpoint Telemetry', 'EDR and endpoint monitoring data', 'logs-endpoint-*', 'confidential', ARRAY['edr_process', 'edr_network', 'edr_file'], ARRAY['edr', 'endpoint', 'telemetry']),
    ('network', 'Network Traffic', 'Firewall, proxy, and network flow data', 'logs-network-*', 'internal', ARRAY['firewall', 'proxy', 'netflow', 'dns'], ARRAY['network', 'traffic', 'firewall']),
    ('auth', 'Authentication', 'Login and authentication events', 'logs-auth-*', 'confidential', ARRAY['windows_security', 'linux_auth', 'sso', 'mfa'], ARRAY['auth', 'login', 'identity']),
    ('admin', 'Administrative', 'Privileged operations and admin actions', 'logs-admin-*', 'restricted', ARRAY['admin_audit', 'privileged'], ARRAY['admin', 'privileged', 'sensitive']),
    ('application', 'Application Logs', 'Application-level events and errors', 'logs-app-*', 'internal', ARRAY['app_error', 'app_access', 'app_audit'], ARRAY['application', 'errors']),
    ('threat_intel', 'Threat Intelligence', 'IOC matches and threat feed hits', 'logs-threat-*', 'confidential', ARRAY['ioc_match', 'threat_feed'], ARRAY['threat', 'intel', 'ioc'])
ON CONFLICT (name) DO NOTHING;

-- Insert default role-index permissions
-- Admin: Full access to everything
INSERT INTO role_index_permissions (role, index_id, index_name, can_read, can_write, can_delete, can_admin)
SELECT 'admin', id, name, true, true, true, true FROM log_indexes
ON CONFLICT (role, index_id) DO NOTHING;

-- Analyst: Read/write to most indexes, no admin or restricted data
INSERT INTO role_index_permissions (role, index_id, index_name, can_read, can_write, can_delete, can_admin)
SELECT 'analyst', id, name, true, true, false, false
FROM log_indexes
WHERE name NOT IN ('admin')
ON CONFLICT (role, index_id) DO NOTHING;

-- Analyst: Limited access to admin index (read-only, no sensitive fields)
INSERT INTO role_index_permissions (role, index_id, index_name, can_read, can_write, can_delete, can_admin, denied_fields)
SELECT 'analyst', id, name, true, false, false, false, '["credentials.*", "api_key.*", "secret.*"]'::jsonb
FROM log_indexes
WHERE name = 'admin'
ON CONFLICT (role, index_id) DO NOTHING;

-- Read-only: Can only read from auth and application indexes
INSERT INTO role_index_permissions (role, index_id, index_name, can_read, can_write, can_delete, can_admin)
SELECT 'read_only', id, name, true, false, false, false
FROM log_indexes
WHERE name IN ('main', 'auth', 'application')
ON CONFLICT (role, index_id) DO NOTHING;

-- ============================================================================
-- LOG SOURCE MANAGEMENT
-- Defines available log sources and their routing to indexes
-- Enables scalable collector configuration via UI
-- ============================================================================

-- Log Source Types - Catalog of all available log source types
CREATE TABLE IF NOT EXISTS log_source_types (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source_type VARCHAR(100) UNIQUE NOT NULL,         -- 'windows_security', 'linux_auditd', 'firewall_palo_alto'
    display_name VARCHAR(255) NOT NULL,               -- 'Windows Security Events'
    description TEXT,

    -- Category for organization
    category VARCHAR(50) NOT NULL CHECK (category IN (
        'endpoint', 'network', 'cloud', 'application', 'identity', 'email', 'database', 'custom'
    )),

    -- Platform compatibility
    supported_platforms TEXT[] DEFAULT ARRAY['windows', 'linux', 'macos']::TEXT[],

    -- Default target index for auto-routing
    default_index_id UUID REFERENCES log_indexes(id) ON DELETE SET NULL,
    default_index_name VARCHAR(100),                  -- Denormalized for faster lookups

    -- Collection settings
    default_config JSONB DEFAULT '{}',                -- Default collection configuration
    schema_definition JSONB DEFAULT '{}',             -- Expected fields/schema for validation

    -- Parser/transform info
    parser_type VARCHAR(50) DEFAULT 'json' CHECK (parser_type IN ('json', 'syslog', 'cef', 'leef', 'csv', 'regex', 'xml', 'custom')),
    parser_config JSONB DEFAULT '{}',                 -- Parser-specific settings

    -- Status
    is_builtin BOOLEAN DEFAULT false,                 -- System-provided vs user-created
    is_enabled BOOLEAN DEFAULT true,

    -- Metadata
    vendor VARCHAR(100),                              -- 'Microsoft', 'CrowdStrike', 'Palo Alto'
    product VARCHAR(100),                             -- 'Windows', 'Falcon', 'PAN-OS'
    icon_name VARCHAR(50),                            -- Frontend icon identifier

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_log_source_types_category ON log_source_types(category);
CREATE INDEX IF NOT EXISTS idx_log_source_types_enabled ON log_source_types(is_enabled);
CREATE INDEX IF NOT EXISTS idx_log_source_types_platforms ON log_source_types USING GIN(supported_platforms);

-- Collector Source Assignments - Which collectors monitor which sources
CREATE TABLE IF NOT EXISTS collector_source_assignments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Collector (agent) reference
    agent_id UUID REFERENCES log_agents(id) ON DELETE CASCADE,
    agent_hostname VARCHAR(255) NOT NULL,             -- Denormalized for display

    -- Source type reference
    source_type_id UUID REFERENCES log_source_types(id) ON DELETE CASCADE,
    source_type VARCHAR(100) NOT NULL,                -- Denormalized for faster lookups

    -- Override target index (NULL = use source type default)
    target_index_id UUID REFERENCES log_indexes(id) ON DELETE SET NULL,
    target_index_name VARCHAR(100),                   -- Denormalized

    -- Collection configuration (overrides source type defaults)
    config_overrides JSONB DEFAULT '{}',              -- Agent-specific settings for this source

    -- Filtering
    include_filters JSONB DEFAULT '[]',               -- Only collect events matching these
    exclude_filters JSONB DEFAULT '[]',               -- Exclude events matching these

    -- Status
    is_enabled BOOLEAN DEFAULT true,
    status VARCHAR(30) DEFAULT 'active' CHECK (status IN ('active', 'paused', 'error', 'configuring')),
    last_event_at TIMESTAMP WITH TIME ZONE,
    events_collected BIGINT DEFAULT 0,
    error_message TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),

    UNIQUE(agent_id, source_type_id)
);

CREATE INDEX IF NOT EXISTS idx_collector_assignments_agent ON collector_source_assignments(agent_id);
CREATE INDEX IF NOT EXISTS idx_collector_assignments_source ON collector_source_assignments(source_type_id);
CREATE INDEX IF NOT EXISTS idx_collector_assignments_status ON collector_source_assignments(status);
CREATE INDEX IF NOT EXISTS idx_collector_assignments_enabled ON collector_source_assignments(is_enabled);

-- Collector Groups - For managing collectors at scale
CREATE TABLE IF NOT EXISTS collector_groups (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,                -- 'dc_controllers', 'web_servers', 'dmz'
    display_name VARCHAR(255) NOT NULL,               -- 'Domain Controllers'
    description TEXT,

    -- Group criteria (auto-membership based on agent attributes)
    auto_membership_rules JSONB DEFAULT NULL,         -- {"tags": ["dc"], "os_type": "windows"}

    -- Status
    is_enabled BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_collector_groups_name ON collector_groups(name);
CREATE INDEX IF NOT EXISTS idx_collector_groups_enabled ON collector_groups(is_enabled);

-- Collector Group Membership - Manual group assignments
CREATE TABLE IF NOT EXISTS collector_group_membership (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    group_id UUID REFERENCES collector_groups(id) ON DELETE CASCADE,
    agent_id UUID REFERENCES log_agents(id) ON DELETE CASCADE,

    -- Manual vs auto assignment
    is_manual BOOLEAN DEFAULT true,                   -- false = auto-assigned via rules

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(group_id, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_collector_membership_group ON collector_group_membership(group_id);
CREATE INDEX IF NOT EXISTS idx_collector_membership_agent ON collector_group_membership(agent_id);

-- Group Source Assignments - Apply source configs to entire groups
CREATE TABLE IF NOT EXISTS group_source_assignments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    group_id UUID REFERENCES collector_groups(id) ON DELETE CASCADE,
    group_name VARCHAR(100) NOT NULL,                 -- Denormalized

    source_type_id UUID REFERENCES log_source_types(id) ON DELETE CASCADE,
    source_type VARCHAR(100) NOT NULL,                -- Denormalized

    -- Override target index
    target_index_id UUID REFERENCES log_indexes(id) ON DELETE SET NULL,
    target_index_name VARCHAR(100),

    -- Collection configuration
    config_overrides JSONB DEFAULT '{}',
    include_filters JSONB DEFAULT '[]',
    exclude_filters JSONB DEFAULT '[]',

    -- Priority (higher = takes precedence over lower)
    priority INTEGER DEFAULT 0,

    -- Status
    is_enabled BOOLEAN DEFAULT true,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100),

    UNIQUE(group_id, source_type_id)
);

CREATE INDEX IF NOT EXISTS idx_group_assignments_group ON group_source_assignments(group_id);
CREATE INDEX IF NOT EXISTS idx_group_assignments_source ON group_source_assignments(source_type_id);
CREATE INDEX IF NOT EXISTS idx_group_assignments_priority ON group_source_assignments(priority DESC);

-- Insert default log source types
INSERT INTO log_source_types (source_type, display_name, description, category, supported_platforms, default_index_name, parser_type, vendor, product, is_builtin) VALUES
    -- Endpoint sources
    ('windows_security', 'Windows Security Events', 'Windows Security Event Log (4624, 4625, 4688, etc.)', 'endpoint', ARRAY['windows'], 'security', 'json', 'Microsoft', 'Windows', true),
    ('windows_sysmon', 'Windows Sysmon', 'System Monitor events (process, network, file operations)', 'endpoint', ARRAY['windows'], 'endpoint', 'json', 'Microsoft', 'Sysmon', true),
    ('windows_powershell', 'Windows PowerShell', 'PowerShell script block and module logging', 'endpoint', ARRAY['windows'], 'endpoint', 'json', 'Microsoft', 'PowerShell', true),
    ('windows_defender', 'Windows Defender', 'Microsoft Defender antivirus events', 'endpoint', ARRAY['windows'], 'security', 'json', 'Microsoft', 'Defender', true),
    ('linux_auditd', 'Linux Audit', 'Linux auditd security events', 'endpoint', ARRAY['linux'], 'security', 'syslog', 'Linux', 'auditd', true),
    ('linux_syslog', 'Linux Syslog', 'Standard Linux system logs', 'endpoint', ARRAY['linux'], 'main', 'syslog', 'Linux', 'syslog', true),
    ('macos_unified', 'macOS Unified Logs', 'macOS unified logging system', 'endpoint', ARRAY['macos'], 'endpoint', 'json', 'Apple', 'macOS', true),

    -- Network sources
    ('firewall_generic', 'Generic Firewall', 'Generic firewall logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', NULL, NULL, true),
    ('firewall_palo_alto', 'Palo Alto Firewall', 'Palo Alto Networks firewall traffic and threat logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', 'Palo Alto Networks', 'PAN-OS', true),
    ('firewall_fortinet', 'FortiGate Firewall', 'Fortinet FortiGate firewall logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', 'Fortinet', 'FortiOS', true),
    ('proxy_squid', 'Squid Proxy', 'Squid web proxy access logs', 'network', ARRAY['linux'], 'network', 'regex', 'Squid', 'Squid', true),
    ('dns_logs', 'DNS Query Logs', 'DNS server query and response logs', 'network', ARRAY['windows', 'linux'], 'network', 'syslog', NULL, NULL, true),
    ('netflow', 'NetFlow/IPFIX', 'Network flow data (NetFlow v5/v9, IPFIX)', 'network', ARRAY['windows', 'linux'], 'network', 'json', NULL, NULL, true),

    -- Identity sources
    ('azure_ad', 'Azure AD Sign-ins', 'Azure Active Directory sign-in and audit logs', 'identity', ARRAY['windows', 'linux', 'macos'], 'auth', 'json', 'Microsoft', 'Azure AD', true),
    ('okta', 'Okta Logs', 'Okta system and authentication logs', 'identity', ARRAY['windows', 'linux', 'macos'], 'auth', 'json', 'Okta', 'Okta', true),
    ('ldap_audit', 'LDAP/AD Audit', 'Active Directory and LDAP authentication events', 'identity', ARRAY['windows'], 'auth', 'json', 'Microsoft', 'Active Directory', true),

    -- Cloud sources
    ('aws_cloudtrail', 'AWS CloudTrail', 'AWS API activity and management events', 'cloud', ARRAY['windows', 'linux', 'macos'], 'security', 'json', 'Amazon', 'AWS', true),
    ('aws_guardduty', 'AWS GuardDuty', 'AWS threat detection findings', 'cloud', ARRAY['windows', 'linux', 'macos'], 'security', 'json', 'Amazon', 'AWS', true),
    ('azure_activity', 'Azure Activity Log', 'Azure subscription-level events', 'cloud', ARRAY['windows', 'linux', 'macos'], 'security', 'json', 'Microsoft', 'Azure', true),
    ('gcp_audit', 'GCP Audit Logs', 'Google Cloud Platform audit logs', 'cloud', ARRAY['windows', 'linux', 'macos'], 'security', 'json', 'Google', 'GCP', true),
    ('o365_audit', 'Microsoft 365 Audit', 'Office 365 unified audit log', 'cloud', ARRAY['windows', 'linux', 'macos'], 'security', 'json', 'Microsoft', 'Microsoft 365', true),

    -- Application sources
    ('web_access', 'Web Server Access', 'Apache/Nginx access logs', 'application', ARRAY['linux'], 'application', 'regex', NULL, NULL, true),
    ('app_error', 'Application Errors', 'Application error and exception logs', 'application', ARRAY['windows', 'linux', 'macos'], 'application', 'json', NULL, NULL, true),
    ('database_audit', 'Database Audit', 'Database query and access audit logs', 'database', ARRAY['windows', 'linux'], 'admin', 'json', NULL, NULL, true),

    -- Email sources
    ('email_gateway', 'Email Gateway', 'Email security gateway logs', 'email', ARRAY['windows', 'linux'], 'security', 'syslog', NULL, NULL, true),
    ('exchange_tracking', 'Exchange Tracking', 'Microsoft Exchange message tracking logs', 'email', ARRAY['windows'], 'application', 'csv', 'Microsoft', 'Exchange', true)
ON CONFLICT (source_type) DO NOTHING;

-- Update log_source_types with default_index_id from log_indexes
UPDATE log_source_types lst
SET default_index_id = li.id
FROM log_indexes li
WHERE lst.default_index_name = li.name
  AND lst.default_index_id IS NULL;

-- Insert sample log collectors for demonstration
INSERT INTO log_agents (agent_id, hostname, os_type, os_version, ip_address, agent_version, status, tags, metadata, last_heartbeat, events_received_total) VALUES
    ('agent-dc01-prod', 'DC01.corp.local', 'windows', 'Windows Server 2022', '10.0.1.10', '1.2.0', 'active', ARRAY['domain-controller', 'production', 'tier0'], '{"location": "HQ", "department": "IT"}', NOW() - INTERVAL '2 minutes', 1523847),
    ('agent-dc02-prod', 'DC02.corp.local', 'windows', 'Windows Server 2022', '10.0.1.11', '1.2.0', 'active', ARRAY['domain-controller', 'production', 'tier0'], '{"location": "HQ", "department": "IT"}', NOW() - INTERVAL '1 minute', 1489234),
    ('agent-web01-prod', 'web01.corp.local', 'linux', 'Ubuntu 22.04 LTS', '10.0.2.20', '1.2.0', 'active', ARRAY['web-server', 'production', 'dmz'], '{"location": "HQ", "department": "Engineering"}', NOW() - INTERVAL '30 seconds', 8234567),
    ('agent-web02-prod', 'web02.corp.local', 'linux', 'Ubuntu 22.04 LTS', '10.0.2.21', '1.2.0', 'active', ARRAY['web-server', 'production', 'dmz'], '{"location": "HQ", "department": "Engineering"}', NOW() - INTERVAL '45 seconds', 7891234),
    ('agent-db01-prod', 'db01.corp.local', 'linux', 'RHEL 8.8', '10.0.3.30', '1.1.5', 'active', ARRAY['database', 'production', 'tier1'], '{"location": "HQ", "department": "DBA"}', NOW() - INTERVAL '1 minute', 2345678),
    ('agent-mail01-prod', 'mail01.corp.local', 'windows', 'Windows Server 2019', '10.0.4.40', '1.2.0', 'active', ARRAY['email', 'production'], '{"location": "HQ", "department": "IT"}', NOW() - INTERVAL '2 minutes', 456789),
    ('agent-fw01-prod', 'fw01.corp.local', 'linux', 'PAN-OS 11.0', '10.0.0.1', '1.2.0', 'active', ARRAY['firewall', 'production', 'perimeter'], '{"location": "HQ", "department": "Security"}', NOW() - INTERVAL '15 seconds', 45678901),
    ('agent-siem01-prod', 'siem01.corp.local', 'linux', 'Ubuntu 20.04 LTS', '10.0.5.50', '1.2.0', 'maintenance', ARRAY['siem', 'production'], '{"location": "HQ", "department": "Security"}', NOW() - INTERVAL '1 hour', 12345678),
    ('agent-laptop001', 'LAPTOP-JSmith', 'windows', 'Windows 11 Pro', '192.168.1.101', '1.2.0', 'active', ARRAY['endpoint', 'workstation'], '{"location": "Remote", "department": "Sales", "user": "jsmith"}', NOW() - INTERVAL '5 minutes', 234567),
    ('agent-laptop002', 'LAPTOP-AJones', 'macos', 'macOS Sonoma 14.2', '192.168.1.102', '1.2.0', 'inactive', ARRAY['endpoint', 'workstation'], '{"location": "Remote", "department": "Marketing", "user": "ajones"}', NOW() - INTERVAL '2 days', 123456)
ON CONFLICT (agent_id) DO NOTHING;

-- Assign some sources to the sample collectors
-- DC01 - Windows Security and AD events
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 500000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-dc01-prod' AND lst.source_type IN ('windows_security', 'ldap_audit')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

-- Web servers - Linux audit and web access
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 2000000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-web01-prod' AND lst.source_type IN ('linux_auditd', 'web_access', 'linux_syslog')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

-- Firewall - Network traffic
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 15000000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-fw01-prod' AND lst.source_type IN ('firewall_palo_alto', 'dns_logs', 'netflow')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

-- Database server
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 800000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-db01-prod' AND lst.source_type IN ('linux_auditd', 'database_audit')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

-- Laptop with Sysmon
INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 100000
FROM log_agents la, log_source_types lst
WHERE la.agent_id = 'agent-laptop001' AND lst.source_type IN ('windows_sysmon', 'windows_defender', 'windows_powershell')
ON CONFLICT (agent_id, source_type_id) DO NOTHING;

-- ============================================================================

-- ============================================================================
-- RIGGS_FEEDBACK TABLE
-- ML feedback for Riggs analysis - tracks outcomes for continuous learning
-- ============================================================================
CREATE TABLE IF NOT EXISTS riggs_feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Investigation context
    investigation_id VARCHAR(100) NOT NULL UNIQUE,
    alert_id VARCHAR(100),

    -- T1 analysis
    t1_verdict VARCHAR(50),
    t1_confidence INTEGER CHECK (t1_confidence >= 0 AND t1_confidence <= 100),

    -- Riggs analysis
    riggs_verdict VARCHAR(50) NOT NULL,
    riggs_confidence INTEGER CHECK (riggs_confidence >= 0 AND riggs_confidence <= 100),
    riggs_mode VARCHAR(10) NOT NULL CHECK (riggs_mode IN ('FAST', 'DEEP')),

    -- Escalation tracking
    was_escalated BOOLEAN DEFAULT FALSE,
    escalation_reason TEXT,

    -- Human feedback (filled in later when analyst reviews)
    human_verdict VARCHAR(50),
    human_feedback TEXT,
    human_reviewed_at TIMESTAMP WITH TIME ZONE,
    reviewed_by VARCHAR(100),

    -- Performance metrics
    processing_time_ms INTEGER,
    token_count INTEGER,

    -- Features for ML
    ioc_count INTEGER DEFAULT 0,
    entity_count INTEGER DEFAULT 0,
    has_encoded_content BOOLEAN DEFAULT FALSE,
    severity VARCHAR(20),
    source VARCHAR(100),
    threat_type VARCHAR(50),
    mitre_techniques TEXT[],

    -- Derived metrics (computed after human review)
    verdict_match BOOLEAN GENERATED ALWAYS AS (
        CASE
            WHEN human_verdict IS NULL THEN NULL
            ELSE LOWER(riggs_verdict) = LOWER(human_verdict)
        END
    ) STORED,
    t1_match BOOLEAN GENERATED ALWAYS AS (
        LOWER(t1_verdict) = LOWER(riggs_verdict)
    ) STORED,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for analytics queries
CREATE INDEX idx_riggs_feedback_created ON riggs_feedback(created_at DESC);
CREATE INDEX idx_riggs_feedback_mode ON riggs_feedback(riggs_mode);
CREATE INDEX idx_riggs_feedback_verdict ON riggs_feedback(riggs_verdict);
CREATE INDEX idx_riggs_feedback_human ON riggs_feedback(human_verdict) WHERE human_verdict IS NOT NULL;
CREATE INDEX idx_riggs_feedback_match ON riggs_feedback(verdict_match) WHERE verdict_match IS NOT NULL;
CREATE INDEX idx_riggs_feedback_source ON riggs_feedback(source);
CREATE INDEX idx_riggs_feedback_severity ON riggs_feedback(severity);

-- View for Riggs accuracy dashboard
CREATE OR REPLACE VIEW riggs_accuracy_stats AS
SELECT
    DATE(created_at) as analysis_date,
    riggs_mode,
    COUNT(*) as total_analyses,
    COUNT(*) FILTER (WHERE t1_match) as t1_agreement_count,
    COUNT(*) FILTER (WHERE verdict_match) as human_agreement_count,
    COUNT(*) FILTER (WHERE was_escalated) as escalation_count,
    ROUND(AVG(processing_time_ms)) as avg_processing_ms,
    ROUND(AVG(token_count)) as avg_tokens,
    ROUND(AVG(riggs_confidence)) as avg_confidence
FROM riggs_feedback
GROUP BY DATE(created_at), riggs_mode
ORDER BY analysis_date DESC, riggs_mode;

-- ============================================================================

-- ============================================================================
-- FRONTEND ERROR TRACKING
-- Stores error reports sent from the frontend ErrorBoundary component
-- ============================================================================
CREATE TABLE IF NOT EXISTS frontend_errors (
    id SERIAL PRIMARY KEY,
    error TEXT NOT NULL,
    component_stack TEXT,
    url VARCHAR(500),
    user_agent VARCHAR(500),
    client_ip VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_frontend_errors_created_at ON frontend_errors(created_at DESC);

-- ============================================================================
-- USER PREFERENCES
-- Stores per-user preferences (theme, layout, notifications, etc.)
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_preferences (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(100) UNIQUE NOT NULL,
    preferences JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_preferences_username ON user_preferences(username);
CREATE INDEX IF NOT EXISTS idx_user_preferences_user_id ON user_preferences(user_id);

-- ============================================================================

-- Vacuum and analyze for optimal performance
VACUUM ANALYZE;

-- Success message
DO $$
BEGIN
    RAISE NOTICE 'T1 Agentics PostgreSQL schema created successfully!';
    RAISE NOTICE '  - Tables: alerts, investigations, users, iocs, investigation_notes, audit_log';
    RAISE NOTICE '  - Log Indexes: log_indexes, role_index_permissions, user_index_permissions, log_search_audit';
    RAISE NOTICE '  - Collector Management: log_source_types, collector_source_assignments, collector_groups, group_source_assignments';
    RAISE NOTICE '  - Indexes: GIN indexes on JSONB, full-text search, foreign keys';
    RAISE NOTICE '  - Views: alerts_with_investigation, investigation_summary';
    RAISE NOTICE '  - Functions: search_alerts, get_alert_with_investigation';
    RAISE NOTICE '  Ready for application startup!';
END $$;
