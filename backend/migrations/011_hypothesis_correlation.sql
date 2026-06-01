-- Migration: Hypothesis-Driven Correlation System
-- Date: 2026-01-29
-- Description: Adds hypothesis fields to investigations and creates correlation_links table
--              for soft-join/hard-join workflow

-- ============================================================================
-- STEP 1: Add hypothesis fields to investigations table
-- ============================================================================

-- Add hypothesis field (the investigation's guiding hypothesis)
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS hypothesis TEXT;

-- Add hypothesis category for filtering
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS hypothesis_category VARCHAR(50);

-- Add threat_domain for cross-domain isolation
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS threat_domain VARCHAR(30);

-- Add seed_alert_time for time window enforcement
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS seed_alert_time TIMESTAMP WITH TIME ZONE;

-- Create constraint for valid hypothesis categories
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_investigations_hypothesis_category'
    ) THEN
        ALTER TABLE investigations ADD CONSTRAINT ck_investigations_hypothesis_category
        CHECK (hypothesis_category IS NULL OR hypothesis_category IN (
            'MALWARE_INFECTION',
            'CREDENTIAL_THEFT',
            'DATA_EXFIL',
            'LATERAL_MOVEMENT',
            'PERSISTENCE',
            'PHISHING_CAMPAIGN',
            'INSIDER_THREAT',
            'POLICY_VIOLATION',
            'C2_COMMUNICATION',
            'RECONNAISSANCE'
        ));
    END IF;
END $$;

-- Create constraint for valid threat domains
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ck_investigations_threat_domain'
    ) THEN
        ALTER TABLE investigations ADD CONSTRAINT ck_investigations_threat_domain
        CHECK (threat_domain IS NULL OR threat_domain IN (
            'EMAIL',
            'ENDPOINT',
            'IDENTITY',
            'NETWORK',
            'CLOUD'
        ));
    END IF;
END $$;

-- Index for hypothesis-based queries
CREATE INDEX IF NOT EXISTS ix_investigations_hypothesis_category
ON investigations(hypothesis_category) WHERE hypothesis_category IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_investigations_threat_domain
ON investigations(threat_domain) WHERE threat_domain IS NOT NULL;


-- ============================================================================
-- STEP 2: Create correlation_links table for soft-join/hard-join workflow
-- ============================================================================

CREATE TABLE IF NOT EXISTS correlation_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,

    -- Link state progression: SUGGESTED -> CONFIRMED/REJECTED
    link_state VARCHAR(20) NOT NULL DEFAULT 'SUGGESTED',

    -- Relationship type within investigation
    relationship_type VARCHAR(20) NOT NULL DEFAULT 'SUPPORTING',

    -- Correlation evidence
    correlation_score INTEGER NOT NULL DEFAULT 0,
    why_correlated TEXT NOT NULL DEFAULT '',
    evidence_json JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Gates that were passed/failed
    gates_passed JSONB DEFAULT '[]'::jsonb,
    gates_failed JSONB DEFAULT '[]'::jsonb,
    hypothesis_support VARCHAR(20) DEFAULT 'COMPATIBLE',

    -- Timestamps
    suggested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    confirmed_at TIMESTAMP WITH TIME ZONE,
    rejected_at TIMESTAMP WITH TIME ZONE,

    -- Who confirmed/rejected
    confirmed_by VARCHAR(100),
    reject_reason TEXT,

    -- Ensure unique link per alert-investigation pair
    UNIQUE(alert_id, investigation_id)
);

-- Constraints for valid states
ALTER TABLE correlation_links ADD CONSTRAINT IF NOT EXISTS ck_correlation_links_state
CHECK (link_state IN ('SUGGESTED', 'CONFIRMED', 'REJECTED'));

ALTER TABLE correlation_links ADD CONSTRAINT IF NOT EXISTS ck_correlation_links_relationship
CHECK (relationship_type IN ('ROOT_CAUSE', 'SUPPORTING', 'CONSEQUENCE', 'CONTEXT_ONLY'));

ALTER TABLE correlation_links ADD CONSTRAINT IF NOT EXISTS ck_correlation_links_hypothesis_support
CHECK (hypothesis_support IS NULL OR hypothesis_support IN ('SUPPORTS', 'COMPATIBLE', 'CONTRADICTS', 'UNRELATED'));

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS ix_correlation_links_alert_id ON correlation_links(alert_id);
CREATE INDEX IF NOT EXISTS ix_correlation_links_investigation_id ON correlation_links(investigation_id);
CREATE INDEX IF NOT EXISTS ix_correlation_links_state ON correlation_links(link_state);
CREATE INDEX IF NOT EXISTS ix_correlation_links_suggested_at ON correlation_links(suggested_at);

-- Index for finding pending suggestions
CREATE INDEX IF NOT EXISTS ix_correlation_links_pending
ON correlation_links(investigation_id, suggested_at)
WHERE link_state = 'SUGGESTED';


-- ============================================================================
-- STEP 3: Create correlation_audit table for decision tracking
-- ============================================================================

CREATE TABLE IF NOT EXISTS correlation_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID NOT NULL,

    -- Decision made
    decision VARCHAR(20) NOT NULL,
    investigation_id UUID,
    investigation_number VARCHAR(50),

    -- Scoring details
    score INTEGER DEFAULT 0,
    threshold_used INTEGER DEFAULT 40,

    -- Gate results
    gates_passed JSONB DEFAULT '[]'::jsonb,
    gates_failed JSONB DEFAULT '[]'::jsonb,

    -- Evidence used
    evidence JSONB DEFAULT '[]'::jsonb,

    -- Hypothesis evaluation
    hypothesis_support VARCHAR(20),
    hypothesis_category VARCHAR(50),

    -- Human-readable reason
    reason TEXT,

    -- Processing metrics
    processing_time_ms INTEGER,

    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Constraint for valid decisions
ALTER TABLE correlation_audit ADD CONSTRAINT IF NOT EXISTS ck_correlation_audit_decision
CHECK (decision IN ('SUGGESTED', 'CONFIRMED', 'REJECTED', 'BLOCKED', 'CREATE_NEW', 'STANDALONE'));

-- Indexes for audit queries
CREATE INDEX IF NOT EXISTS ix_correlation_audit_alert_id ON correlation_audit(alert_id);
CREATE INDEX IF NOT EXISTS ix_correlation_audit_investigation_id ON correlation_audit(investigation_id) WHERE investigation_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_correlation_audit_created_at ON correlation_audit(created_at);
CREATE INDEX IF NOT EXISTS ix_correlation_audit_decision ON correlation_audit(decision);


-- ============================================================================
-- STEP 4: Create view for pending correlation suggestions
-- ============================================================================

CREATE OR REPLACE VIEW v_pending_correlations AS
SELECT
    cl.id AS link_id,
    cl.alert_id,
    a.alert_id AS alert_number,
    a.title AS alert_title,
    a.severity AS alert_severity,
    a.created_at AS alert_created_at,
    cl.investigation_id,
    i.investigation_id AS investigation_number,
    i.state AS investigation_state,
    i.hypothesis,
    i.hypothesis_category,
    cl.correlation_score,
    cl.why_correlated,
    cl.relationship_type,
    cl.hypothesis_support,
    cl.suggested_at,
    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - cl.suggested_at))/3600 AS hours_pending
FROM correlation_links cl
JOIN alerts a ON cl.alert_id = a.id
JOIN investigations i ON cl.investigation_id = i.id
WHERE cl.link_state = 'SUGGESTED'
ORDER BY cl.correlation_score DESC, cl.suggested_at ASC;


-- ============================================================================
-- STEP 5: Function to auto-populate hypothesis on investigation creation
-- ============================================================================

CREATE OR REPLACE FUNCTION set_investigation_defaults()
RETURNS TRIGGER AS $$
BEGIN
    -- Set seed_alert_time from the first linked alert
    IF NEW.seed_alert_time IS NULL THEN
        NEW.seed_alert_time := COALESCE(NEW.created_at, CURRENT_TIMESTAMP);
    END IF;

    -- Infer threat domain from first alert if not set
    -- This would be populated by the correlation service

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_investigation_defaults ON investigations;
CREATE TRIGGER trg_investigation_defaults
    BEFORE INSERT ON investigations
    FOR EACH ROW
    EXECUTE FUNCTION set_investigation_defaults();


-- ============================================================================
-- STEP 6: Function to track correlation decisions
-- ============================================================================

CREATE OR REPLACE FUNCTION record_correlation_decision(
    p_alert_id UUID,
    p_decision VARCHAR(20),
    p_investigation_id UUID DEFAULT NULL,
    p_score INTEGER DEFAULT 0,
    p_threshold INTEGER DEFAULT 40,
    p_gates_passed JSONB DEFAULT '[]'::jsonb,
    p_gates_failed JSONB DEFAULT '[]'::jsonb,
    p_evidence JSONB DEFAULT '[]'::jsonb,
    p_hypothesis_support VARCHAR(20) DEFAULT NULL,
    p_reason TEXT DEFAULT NULL,
    p_processing_time_ms INTEGER DEFAULT NULL
) RETURNS UUID AS $$
DECLARE
    v_audit_id UUID;
    v_inv_number VARCHAR(50);
BEGIN
    -- Get investigation number if provided
    IF p_investigation_id IS NOT NULL THEN
        SELECT investigation_id INTO v_inv_number
        FROM investigations WHERE id = p_investigation_id;
    END IF;

    INSERT INTO correlation_audit (
        alert_id, decision, investigation_id, investigation_number,
        score, threshold_used, gates_passed, gates_failed, evidence,
        hypothesis_support, reason, processing_time_ms
    ) VALUES (
        p_alert_id, p_decision, p_investigation_id, v_inv_number,
        p_score, p_threshold, p_gates_passed, p_gates_failed, p_evidence,
        p_hypothesis_support, p_reason, p_processing_time_ms
    ) RETURNING id INTO v_audit_id;

    RETURN v_audit_id;
END;
$$ LANGUAGE plpgsql;


-- ============================================================================
-- STEP 7: Add alert_count and entity tracking to investigations
-- ============================================================================

-- Track entity counts on investigation
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS alert_count INTEGER DEFAULT 0;
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS unique_users_count INTEGER DEFAULT 0;
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS unique_hosts_count INTEGER DEFAULT 0;

-- Update alert_count trigger
CREATE OR REPLACE FUNCTION update_investigation_alert_count()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' AND NEW.investigation_id IS NOT NULL THEN
        UPDATE investigations
        SET alert_count = alert_count + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = NEW.investigation_id;
    ELSIF TG_OP = 'UPDATE' THEN
        -- Alert moved from one investigation to another
        IF OLD.investigation_id IS DISTINCT FROM NEW.investigation_id THEN
            IF OLD.investigation_id IS NOT NULL THEN
                UPDATE investigations
                SET alert_count = GREATEST(alert_count - 1, 0),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = OLD.investigation_id;
            END IF;
            IF NEW.investigation_id IS NOT NULL THEN
                UPDATE investigations
                SET alert_count = alert_count + 1,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = NEW.investigation_id;
            END IF;
        END IF;
    ELSIF TG_OP = 'DELETE' AND OLD.investigation_id IS NOT NULL THEN
        UPDATE investigations
        SET alert_count = GREATEST(alert_count - 1, 0),
            updated_at = CURRENT_TIMESTAMP
        WHERE id = OLD.investigation_id;
    END IF;

    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_update_investigation_alert_count ON alerts;
CREATE TRIGGER trg_update_investigation_alert_count
    AFTER INSERT OR UPDATE OF investigation_id OR DELETE ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION update_investigation_alert_count();


-- ============================================================================
-- Migration complete
-- ============================================================================

COMMENT ON TABLE correlation_links IS
'Tracks soft-join and hard-join relationships between alerts and investigations.
Supports the hypothesis-driven correlation model where correlations start as SUGGESTED
and require evidence or analyst confirmation to become CONFIRMED.';

COMMENT ON TABLE correlation_audit IS
'Audit trail for all correlation decisions, including blocked correlations and standalone alert decisions.';
