-- =============================================================================
-- Unified Reasoning Engine Database Migrations
-- =============================================================================
-- Run these migrations to add the tables for the unified reasoning engine.
-- These support: heuristics, checkpoints, confidence tracking, tool execution logs

-- =============================================================================
-- HEURISTICS TABLE
-- =============================================================================
-- Stores guidance patterns that inform reasoning (NOT procedures)

CREATE TABLE IF NOT EXISTS heuristics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,  -- 'triage', 'analysis', 'response', 'general'
    trigger_conditions JSONB NOT NULL DEFAULT '{}',  -- When to load this heuristic
    guidance_text TEXT NOT NULL,  -- The actual heuristic content
    weight FLOAT DEFAULT 1.0,  -- Relative importance
    version INT DEFAULT 1,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_heuristics_category ON heuristics(category);
CREATE INDEX IF NOT EXISTS idx_heuristics_active ON heuristics(is_active);
CREATE INDEX IF NOT EXISTS idx_heuristics_trigger ON heuristics USING GIN (trigger_conditions);

-- =============================================================================
-- HEURISTIC OUTCOMES TABLE
-- =============================================================================
-- Tracks heuristic effectiveness for auto-deprecation

CREATE TABLE IF NOT EXISTS heuristic_outcomes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    heuristic_id UUID REFERENCES heuristics(id) ON DELETE CASCADE,
    investigation_id UUID NOT NULL,
    was_helpful BOOLEAN NOT NULL,
    confidence_delta FLOAT DEFAULT 0,  -- How much it affected confidence
    analyst_feedback TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_heuristic_outcomes_heuristic ON heuristic_outcomes(heuristic_id);
CREATE INDEX IF NOT EXISTS idx_heuristic_outcomes_investigation ON heuristic_outcomes(investigation_id);

-- =============================================================================
-- INVESTIGATION CHECKPOINTS TABLE
-- =============================================================================
-- Tracks checkpoint progression for investigations

CREATE TABLE IF NOT EXISTS investigation_checkpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL UNIQUE,
    current_checkpoint VARCHAR(50) NOT NULL DEFAULT 'triage',
    authority_level VARCHAR(50) NOT NULL DEFAULT 'OBSERVE',
    confidence INT DEFAULT 0,
    iterations_at_checkpoint INT DEFAULT 0,
    total_iterations INT DEFAULT 0,
    evidence_collected TEXT[] DEFAULT '{}',
    established_facts TEXT[] DEFAULT '{}',
    confidence_history INT[] DEFAULT '{}',
    checkpoint_history JSONB DEFAULT '[]',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_investigation_checkpoints_inv ON investigation_checkpoints(investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigation_checkpoints_checkpoint ON investigation_checkpoints(current_checkpoint);

-- =============================================================================
-- REASONING HISTORY TABLE
-- =============================================================================
-- Stores reasoning outputs for audit and analysis

CREATE TABLE IF NOT EXISTS reasoning_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL,
    iteration INT NOT NULL,
    checkpoint VARCHAR(50) NOT NULL,
    authority_level VARCHAR(50) NOT NULL,

    -- Reasoning output
    assessment TEXT,
    confidence INT,
    confidence_justification TEXT,
    gaps TEXT[] DEFAULT '{}',
    next_action JSONB,
    rationale TEXT,

    -- Metadata
    prompt_tokens_est INT,
    heuristics_used TEXT[] DEFAULT '{}',
    sop_reference_used BOOLEAN DEFAULT false,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_reasoning_history_inv ON reasoning_history(investigation_id);
CREATE INDEX IF NOT EXISTS idx_reasoning_history_checkpoint ON reasoning_history(checkpoint);
CREATE INDEX IF NOT EXISTS idx_reasoning_history_created ON reasoning_history(created_at DESC);

-- =============================================================================
-- TOOL EXECUTION LOG TABLE
-- =============================================================================
-- Audit trail for tool executions through the broker

CREATE TABLE IF NOT EXISTS tool_execution_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL,
    tool_id VARCHAR(100) NOT NULL,

    -- Execution details
    parameters JSONB DEFAULT '{}',
    authority_level VARCHAR(50) NOT NULL,
    confidence_at_execution INT,

    -- Result
    success BOOLEAN NOT NULL,
    result_data JSONB,
    error TEXT,
    blocked_reason TEXT,

    -- Timing
    execution_time_ms INT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_tool_exec_log_inv ON tool_execution_log(investigation_id);
CREATE INDEX IF NOT EXISTS idx_tool_exec_log_tool ON tool_execution_log(tool_id);
CREATE INDEX IF NOT EXISTS idx_tool_exec_log_success ON tool_execution_log(success);
CREATE INDEX IF NOT EXISTS idx_tool_exec_log_created ON tool_execution_log(created_at DESC);

-- =============================================================================
-- CONFIDENCE TRACKING TABLE
-- =============================================================================
-- Tracks confidence over time for analysis and stall detection

CREATE TABLE IF NOT EXISTS confidence_tracking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    investigation_id UUID NOT NULL,
    checkpoint VARCHAR(50) NOT NULL,
    iteration INT NOT NULL,
    confidence INT NOT NULL,
    previous_confidence INT,
    delta INT,
    is_stalled BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_confidence_tracking_inv ON confidence_tracking(investigation_id);
CREATE INDEX IF NOT EXISTS idx_confidence_tracking_stalled ON confidence_tracking(is_stalled);

-- =============================================================================
-- SOP REFERENCES TABLE
-- =============================================================================
-- Stores SOP reference content (NOT procedures)

CREATE TABLE IF NOT EXISTS sop_references (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    alert_types TEXT[] NOT NULL,  -- Alert types this SOP relates to

    -- ALLOWED content (contextual, not procedural)
    common_pitfalls TEXT,
    environmental_notes TEXT,
    edge_cases TEXT,
    context_hints JSONB DEFAULT '{}',  -- gap -> hint mapping

    -- Metadata
    version INT DEFAULT 1,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sop_references_types ON sop_references USING GIN (alert_types);
CREATE INDEX IF NOT EXISTS idx_sop_references_active ON sop_references(is_active);

-- =============================================================================
-- SEED DATA: Initial Heuristics
-- =============================================================================

INSERT INTO heuristics (id, name, category, trigger_conditions, guidance_text, weight) VALUES
(
    gen_random_uuid(),
    'Internal IP Context',
    'triage',
    '{"has_internal_ip": true}',
    'Internal IPs communicating with external threats warrant immediate attention. Consider: Is this a server or workstation? What''s the normal traffic pattern? High confidence indicators: Known C2 domains, beaconing patterns, data exfil volumes.',
    1.0
),
(
    gen_random_uuid(),
    'Phishing Domain Age',
    'analysis',
    '{"alert_type": "phishing", "has_domain": true}',
    'Recently registered domains (< 30 days) in phishing contexts are highly suspicious. However, legitimate services do use new domains. Cross-reference with: domain registrar reputation, SSL certificate details, similar domain patterns (typosquatting).',
    1.2
),
(
    gen_random_uuid(),
    'Credential Exposure Urgency',
    'response',
    '{"involves_credentials": true}',
    'Credential exposure requires rapid assessment of blast radius. Priority factors: privilege level, service accounts vs user accounts, evidence of actual use vs potential exposure. Time-sensitivity: Credentials may already be in use elsewhere.',
    1.5
),
(
    gen_random_uuid(),
    'EDR High Confidence Alert',
    'triage',
    '{"source_type": "edr", "source_confidence": "high"}',
    'EDR alerts with high source confidence have already passed vendor detection logic. Focus on scope and impact rather than re-validating the detection. Key questions: What else did this host do? Are there related alerts?',
    1.3
),
(
    gen_random_uuid(),
    'Lateral Movement Indicators',
    'analysis',
    '{"has_multiple_hosts": true}',
    'Multiple hosts in an alert chain suggest lateral movement. Map the progression: initial access -> privilege escalation -> lateral spread. Check for: shared credentials, admin tool abuse, unusual service account activity.',
    1.4
)
ON CONFLICT DO NOTHING;

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Function to update heuristic timestamp on modification
CREATE OR REPLACE FUNCTION update_heuristic_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger for heuristics
DROP TRIGGER IF EXISTS trigger_heuristic_timestamp ON heuristics;
CREATE TRIGGER trigger_heuristic_timestamp
    BEFORE UPDATE ON heuristics
    FOR EACH ROW
    EXECUTE FUNCTION update_heuristic_timestamp();

-- Function to calculate heuristic accuracy
CREATE OR REPLACE FUNCTION get_heuristic_accuracy(heuristic_uuid UUID)
RETURNS FLOAT AS $$
DECLARE
    total_count INT;
    helpful_count INT;
BEGIN
    SELECT COUNT(*), COUNT(*) FILTER (WHERE was_helpful = true)
    INTO total_count, helpful_count
    FROM heuristic_outcomes
    WHERE heuristic_id = heuristic_uuid;

    IF total_count = 0 THEN
        RETURN 0;
    END IF;

    RETURN helpful_count::FLOAT / total_count::FLOAT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- VIEWS
-- =============================================================================

-- View for heuristic performance
CREATE OR REPLACE VIEW heuristic_performance AS
SELECT
    h.id,
    h.name,
    h.category,
    h.is_active,
    h.weight,
    COUNT(ho.id) as total_uses,
    COUNT(ho.id) FILTER (WHERE ho.was_helpful = true) as helpful_count,
    CASE
        WHEN COUNT(ho.id) > 0
        THEN ROUND((COUNT(ho.id) FILTER (WHERE ho.was_helpful = true)::FLOAT / COUNT(ho.id)::FLOAT) * 100, 1)
        ELSE 0
    END as accuracy_percent,
    AVG(ho.confidence_delta) as avg_confidence_delta
FROM heuristics h
LEFT JOIN heuristic_outcomes ho ON h.id = ho.heuristic_id
GROUP BY h.id, h.name, h.category, h.is_active, h.weight;

-- View for investigation progress
CREATE OR REPLACE VIEW investigation_progress AS
SELECT
    ic.investigation_id,
    ic.current_checkpoint,
    ic.authority_level,
    ic.confidence,
    ic.total_iterations,
    ic.iterations_at_checkpoint,
    array_length(ic.evidence_collected, 1) as evidence_count,
    array_length(ic.established_facts, 1) as facts_count,
    ic.started_at,
    ic.last_updated,
    EXTRACT(EPOCH FROM (ic.last_updated - ic.started_at)) / 60 as duration_minutes
FROM investigation_checkpoints ic;

COMMENT ON TABLE heuristics IS 'Guidance patterns that inform reasoning - NOT procedures';
COMMENT ON TABLE heuristic_outcomes IS 'Tracks heuristic effectiveness for auto-deprecation';
COMMENT ON TABLE investigation_checkpoints IS 'Checkpoint progression state for investigations';
COMMENT ON TABLE reasoning_history IS 'Audit trail of reasoning outputs';
COMMENT ON TABLE tool_execution_log IS 'Audit trail of tool executions through the broker';
COMMENT ON TABLE sop_references IS 'SOP reference content - contextual only, never procedural';
