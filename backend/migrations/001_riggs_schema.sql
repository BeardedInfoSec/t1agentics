-- ============================================================================
-- RIGGS ARCHITECTURE SCHEMA MIGRATION
-- Adds Knowledge Base enhancements, Integration Permissions, and Action Approvals
-- ============================================================================

-- Add Riggs-specific columns to knowledge_base
ALTER TABLE knowledge_base
ADD COLUMN IF NOT EXISTS author_type VARCHAR(20) DEFAULT 'user' CHECK (author_type IN ('user', 'riggs')),
ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'published' CHECK (status IN ('draft', 'published', 'archived')),
ADD COLUMN IF NOT EXISTS usage_count INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS related_alerts TEXT[] DEFAULT '{}',
ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMP WITH TIME ZONE;

-- Add index for author_type and status
CREATE INDEX IF NOT EXISTS idx_kb_author_type ON knowledge_base(author_type);
CREATE INDEX IF NOT EXISTS idx_kb_status ON knowledge_base(status);
CREATE INDEX IF NOT EXISTS idx_kb_usage_count ON knowledge_base(usage_count DESC);

-- ============================================================================
-- INTEGRATION CAPABILITIES & PERMISSIONS
-- Controls what actions Riggs can take with each integration
-- ============================================================================

CREATE TABLE IF NOT EXISTS integration_capabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    integration_id UUID NOT NULL,

    -- Capability definition
    capability_name VARCHAR(100) NOT NULL,
    capability_type VARCHAR(30) DEFAULT 'query' CHECK (capability_type IN (
        'query',      -- Read-only data retrieval
        'enrich',     -- IOC/entity enrichment
        'action',     -- Response action (isolate, block, etc.)
        'notify'      -- Send notifications
    )),
    description TEXT,

    -- Permission level
    permission_level VARCHAR(30) DEFAULT 'disabled' CHECK (permission_level IN (
        'auto',              -- Riggs can use without asking
        'approval_required', -- Requires human approval
        'disabled'           -- Riggs cannot use
    )),

    -- Risk assessment
    risk_level VARCHAR(20) DEFAULT 'low' CHECK (risk_level IN (
        'low', 'medium', 'high', 'critical'
    )),

    -- Usage tracking
    usage_count INTEGER DEFAULT 0,
    last_used_at TIMESTAMP WITH TIME ZONE,

    -- Config
    requires_target BOOLEAN DEFAULT TRUE,  -- Does this need a target (host, user, etc)?
    target_type VARCHAR(50),               -- host, user, ip, hash, etc.

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(integration_id, capability_name)
);

CREATE INDEX IF NOT EXISTS idx_int_cap_integration ON integration_capabilities(integration_id);
CREATE INDEX IF NOT EXISTS idx_int_cap_permission ON integration_capabilities(permission_level);
CREATE INDEX IF NOT EXISTS idx_int_cap_type ON integration_capabilities(capability_type);

-- ============================================================================
-- ACTION APPROVAL QUEUE
-- Tracks actions Riggs wants to take that require human approval
-- ============================================================================

CREATE TABLE IF NOT EXISTS action_approvals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    approval_id VARCHAR(30) UNIQUE NOT NULL, -- Human-readable ID like APR-A1B2C3

    -- What action is requested
    action_name VARCHAR(100) NOT NULL,
    capability_id UUID REFERENCES integration_capabilities(id),
    integration_name VARCHAR(100),

    -- Target of the action
    target_type VARCHAR(50),               -- host, user, ip, hash, email
    target_identifier VARCHAR(500),        -- The actual target value
    target_context JSONB DEFAULT '{}',     -- Additional context about target

    -- Why Riggs wants to do this
    reason TEXT NOT NULL,
    evidence JSONB DEFAULT '{}',           -- Supporting evidence
    riggs_confidence FLOAT,                -- 0.0 - 1.0

    -- Links to alerts/investigations
    alert_id UUID,
    investigation_id UUID,

    -- Approval status
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN (
        'pending', 'approved', 'rejected', 'expired', 'executed', 'failed'
    )),
    priority VARCHAR(20) DEFAULT 'medium' CHECK (priority IN (
        'low', 'medium', 'high', 'critical'
    )),

    -- Timing
    requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,

    -- Review
    reviewed_by UUID,
    reviewed_at TIMESTAMP WITH TIME ZONE,
    review_notes TEXT,

    -- Execution
    executed_at TIMESTAMP WITH TIME ZONE,
    execution_result JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_approvals_id ON action_approvals(approval_id);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON action_approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_priority ON action_approvals(priority);
CREATE INDEX IF NOT EXISTS idx_approvals_requested ON action_approvals(requested_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_alert ON action_approvals(alert_id);
CREATE INDEX IF NOT EXISTS idx_approvals_investigation ON action_approvals(investigation_id);

-- ============================================================================
-- RIGGS DECISION LOG
-- Tracks all decisions Riggs makes for audit and learning
-- ============================================================================

CREATE TABLE IF NOT EXISTS riggs_decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    decision_id VARCHAR(30) UNIQUE NOT NULL, -- DEC-A1B2C3

    -- What was analyzed
    alert_id UUID,
    investigation_id UUID,

    -- The decision
    decision_type VARCHAR(30) NOT NULL CHECK (decision_type IN (
        'auto_resolve',    -- Resolved automatically (benign)
        'escalate',        -- Needs human review
        'investigate',     -- Created/updated investigation
        'enrich',          -- Requested enrichment
        'action_request',  -- Requested response action
        'kb_reference',    -- Referenced KB article
        'kb_draft',        -- Drafted new KB article
        'correlate'        -- Correlated with other alerts
    )),

    -- Decision details
    decision_summary TEXT NOT NULL,
    reasoning TEXT,                    -- Riggs's reasoning
    confidence FLOAT,                  -- 0.0 - 1.0

    -- What influenced the decision
    ml_scores JSONB DEFAULT '{}',      -- ML layer outputs
    kb_articles_used TEXT[] DEFAULT '{}', -- KB articles referenced
    similar_alerts TEXT[] DEFAULT '{}',   -- Similar alert IDs

    -- Outcome tracking
    human_feedback VARCHAR(20) CHECK (human_feedback IN (
        'correct', 'incorrect', 'partially_correct', NULL
    )),
    feedback_notes TEXT,
    feedback_by UUID,
    feedback_at TIMESTAMP WITH TIME ZONE,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_riggs_dec_id ON riggs_decisions(decision_id);
CREATE INDEX IF NOT EXISTS idx_riggs_dec_type ON riggs_decisions(decision_type);
CREATE INDEX IF NOT EXISTS idx_riggs_dec_alert ON riggs_decisions(alert_id);
CREATE INDEX IF NOT EXISTS idx_riggs_dec_investigation ON riggs_decisions(investigation_id);
CREATE INDEX IF NOT EXISTS idx_riggs_dec_feedback ON riggs_decisions(human_feedback);
CREATE INDEX IF NOT EXISTS idx_riggs_dec_created ON riggs_decisions(created_at DESC);

-- ============================================================================
-- MITRE COVERAGE TRACKING
-- Tracks which MITRE techniques we have detection/response coverage for
-- ============================================================================

CREATE TABLE IF NOT EXISTS mitre_coverage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    technique_id VARCHAR(20) PRIMARY KEY,  -- T1059.001
    technique_name VARCHAR(200) NOT NULL,
    tactic VARCHAR(100),                   -- Execution, Persistence, etc.

    -- Coverage status
    has_detection BOOLEAN DEFAULT FALSE,
    detection_sources TEXT[] DEFAULT '{}', -- Which detection rules cover this
    has_response BOOLEAN DEFAULT FALSE,
    response_playbooks TEXT[] DEFAULT '{}', -- KB articles for response

    -- Activity tracking
    alerts_last_30d INTEGER DEFAULT 0,
    alerts_last_90d INTEGER DEFAULT 0,
    last_seen_at TIMESTAMP WITH TIME ZONE,

    -- Priority and notes
    priority VARCHAR(20) DEFAULT 'medium',
    notes TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mitre_tactic ON mitre_coverage(tactic);
CREATE INDEX IF NOT EXISTS idx_mitre_has_detection ON mitre_coverage(has_detection);
CREATE INDEX IF NOT EXISTS idx_mitre_priority ON mitre_coverage(priority);

-- ============================================================================
-- SEED SOME INITIAL DATA
-- ============================================================================

-- Common integration capabilities (will be populated when integrations are configured)
-- This is a template that can be customized per deployment

INSERT INTO integration_capabilities (id, integration_id, capability_name, capability_type, permission_level, risk_level, description)
VALUES
    -- VirusTotal-style enrichment
    (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001'::UUID, 'hash_lookup', 'enrich', 'auto', 'low', 'Look up file hashes for reputation'),
    (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001'::UUID, 'url_scan', 'enrich', 'auto', 'low', 'Scan URLs for malicious content'),
    (uuid_generate_v4(), '00000000-0000-0000-0000-000000000001'::UUID, 'ip_lookup', 'enrich', 'auto', 'low', 'Look up IP reputation'),

    -- EDR-style actions
    (uuid_generate_v4(), '00000000-0000-0000-0000-000000000002'::UUID, 'get_device_info', 'query', 'auto', 'low', 'Get device details and status'),
    (uuid_generate_v4(), '00000000-0000-0000-0000-000000000002'::UUID, 'isolate_host', 'action', 'approval_required', 'high', 'Network isolate a host'),
    (uuid_generate_v4(), '00000000-0000-0000-0000-000000000002'::UUID, 'kill_process', 'action', 'approval_required', 'medium', 'Terminate a running process'),

    -- Identity-style actions
    (uuid_generate_v4(), '00000000-0000-0000-0000-000000000003'::UUID, 'get_user', 'query', 'auto', 'low', 'Get user account details'),
    (uuid_generate_v4(), '00000000-0000-0000-0000-000000000003'::UUID, 'suspend_user', 'action', 'approval_required', 'high', 'Suspend a user account'),
    (uuid_generate_v4(), '00000000-0000-0000-0000-000000000003'::UUID, 'reset_password', 'action', 'approval_required', 'medium', 'Force password reset')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- Success message
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Riggs schema migration completed!';
    RAISE NOTICE '  - Added Riggs columns to knowledge_base';
    RAISE NOTICE '  - Created integration_capabilities table';
    RAISE NOTICE '  - Created action_approvals table';
    RAISE NOTICE '  - Created riggs_decisions table';
    RAISE NOTICE '  - Created mitre_coverage table';
END $$;
