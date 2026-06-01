-- ============================================================================
-- Migration: Two-Track Triage System
-- Adds provisional/confirmed verdict tracking and merge audit
-- ============================================================================

-- Add new triage state enum values to investigations
ALTER TABLE investigations DROP CONSTRAINT IF EXISTS investigations_state_check;
ALTER TABLE investigations ADD CONSTRAINT investigations_state_check CHECK (state IN (
    'NEW',
    'TRIAGE_RUNNING',      -- Track A: Immediate triage in progress
    'TRIAGE_PROVISIONAL',  -- Track A complete: verdict shown, flagged provisional
    'ENRICHMENT_RUNNING',  -- Track B: Enrichment in progress (parallel)
    'MERGE_PENDING',       -- Both tracks done, merge needed
    'ANALYZING',           -- Legacy/DEEP analysis running
    'CONFIRMED',           -- Final verdict after merge
    'NEEDS_REVIEW',        -- Conflict or low confidence - human required
    'IN_PROGRESS',         -- Human working on it
    'CLOSED'
));

-- Add two-track triage columns to investigations
ALTER TABLE investigations
    ADD COLUMN IF NOT EXISTS triage_status VARCHAR(30) DEFAULT 'not_started' CHECK (triage_status IN (
        'not_started',
        'provisional',      -- FAST triage done, enrichment pending
        'enriching',        -- Enrichment running
        'merge_pending',    -- Ready for merge
        'confirmed',        -- Final verdict
        'needs_review'      -- Conflict detected
    )),
    ADD COLUMN IF NOT EXISTS provisional_verdict VARCHAR(50),
    ADD COLUMN IF NOT EXISTS provisional_confidence DECIMAL(5,2),
    ADD COLUMN IF NOT EXISTS provisional_reasoning TEXT,
    ADD COLUMN IF NOT EXISTS provisional_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS final_verdict VARCHAR(50),
    ADD COLUMN IF NOT EXISTS final_confidence DECIMAL(5,2),
    ADD COLUMN IF NOT EXISTS final_reasoning TEXT,
    ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS enrichment_progress INTEGER DEFAULT 0,  -- 0-100
    ADD COLUMN IF NOT EXISTS enrichment_total_iocs INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS enrichment_completed_iocs INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS enrichment_high_risk_hits INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS merge_version INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_merge_at TIMESTAMP WITH TIME ZONE,
    ADD COLUMN IF NOT EXISTS verdict_delta JSONB DEFAULT '[]'::jsonb;  -- Audit trail of changes

-- Create index for triage status queries
CREATE INDEX IF NOT EXISTS idx_investigations_triage_status ON investigations(triage_status);
CREATE INDEX IF NOT EXISTS idx_investigations_provisional_verdict ON investigations(provisional_verdict);
CREATE INDEX IF NOT EXISTS idx_investigations_enrichment_progress ON investigations(enrichment_progress) WHERE enrichment_progress < 100;

-- ============================================================================
-- IOC Enrichment Table (per-IOC tracking)
-- ============================================================================
CREATE TABLE IF NOT EXISTS ioc_enrichments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- IOC identity
    ioc_value VARCHAR(2000) NOT NULL,
    ioc_type VARCHAR(50) NOT NULL CHECK (ioc_type IN (
        'ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256', 'email', 'file_path'
    )),

    -- Normalization (for deduplication)
    ioc_value_normalized VARCHAR(2000) NOT NULL,  -- lowercase, trimmed

    -- Status tracking
    status VARCHAR(30) NOT NULL DEFAULT 'unenriched' CHECK (status IN (
        'unenriched',
        'enriching',
        'enriched',
        'failed',
        'stale'       -- TTL expired but data still usable
    )),

    -- Enrichment results
    result_json JSONB DEFAULT '{}'::jsonb,
    score INTEGER CHECK (score >= 0 AND score <= 100),  -- Aggregate threat score
    verdict VARCHAR(30),  -- benign/suspicious/malicious/unknown

    -- Source tracking
    sources_checked TEXT[] DEFAULT '{}',
    sources_flagged TEXT[] DEFAULT '{}',  -- Sources that flagged as malicious

    -- Caching
    cached_until TIMESTAMP WITH TIME ZONE,
    cache_ttl_seconds INTEGER DEFAULT 86400,  -- 24 hours default

    -- Error tracking
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    last_error_at TIMESTAMP WITH TIME ZONE,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    enriched_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    -- Constraints
    UNIQUE(ioc_value_normalized, ioc_type)
);

CREATE INDEX IF NOT EXISTS idx_ioc_enrichments_value ON ioc_enrichments(ioc_value_normalized);
CREATE INDEX IF NOT EXISTS idx_ioc_enrichments_type ON ioc_enrichments(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_enrichments_status ON ioc_enrichments(status);
CREATE INDEX IF NOT EXISTS idx_ioc_enrichments_verdict ON ioc_enrichments(verdict);
CREATE INDEX IF NOT EXISTS idx_ioc_enrichments_cached ON ioc_enrichments(cached_until) WHERE cached_until > NOW();
CREATE INDEX IF NOT EXISTS idx_ioc_enrichments_score ON ioc_enrichments(score) WHERE score >= 70;  -- High-risk IOCs

-- ============================================================================
-- Investigation-IOC Mapping (links IOCs to investigations)
-- ============================================================================
CREATE TABLE IF NOT EXISTS investigation_iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    ioc_enrichment_id UUID NOT NULL REFERENCES ioc_enrichments(id) ON DELETE CASCADE,

    -- Context
    found_in VARCHAR(100),  -- Where in the alert this IOC was found (e.g., 'raw_event.dest_ip')
    is_primary BOOLEAN DEFAULT FALSE,  -- Is this a key IOC for the investigation?

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(investigation_id, ioc_enrichment_id)
);

CREATE INDEX IF NOT EXISTS idx_investigation_iocs_inv ON investigation_iocs(investigation_id);
CREATE INDEX IF NOT EXISTS idx_investigation_iocs_ioc ON investigation_iocs(ioc_enrichment_id);

-- ============================================================================
-- Verdict Change Audit Log (immutable audit trail)
-- ============================================================================
CREATE TABLE IF NOT EXISTS verdict_audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Target
    investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,

    -- Change details
    change_type VARCHAR(50) NOT NULL CHECK (change_type IN (
        'provisional_set',      -- Initial FAST verdict
        'enrichment_update',    -- Enrichment data arrived
        'merge_executed',       -- Merge completed
        'upgrade',              -- Verdict upgraded (e.g., suspicious → malicious)
        'downgrade',            -- Verdict downgraded (requires strong evidence)
        'confidence_change',    -- Confidence changed significantly
        'needs_review',         -- Flagged for human review
        'human_override',       -- Human analyst overrode verdict
        'confirmed'             -- Final confirmation
    )),

    -- Before/After
    previous_verdict VARCHAR(50),
    previous_confidence DECIMAL(5,2),
    new_verdict VARCHAR(50),
    new_confidence DECIMAL(5,2),

    -- Evidence for the change
    reason TEXT NOT NULL,
    evidence_summary JSONB DEFAULT '{}'::jsonb,

    -- Attribution
    triggered_by VARCHAR(50) NOT NULL CHECK (triggered_by IN (
        'fast_triage',
        'enrichment',
        'merge_engine',
        'deep_analysis',
        'human',
        'system'
    )),
    triggered_by_user VARCHAR(100),

    -- Mode tracking
    analysis_mode VARCHAR(20),  -- FAST or DEEP
    merge_version INTEGER,

    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_verdict_audit_investigation ON verdict_audit_log(investigation_id);
CREATE INDEX IF NOT EXISTS idx_verdict_audit_type ON verdict_audit_log(change_type);
CREATE INDEX IF NOT EXISTS idx_verdict_audit_created ON verdict_audit_log(created_at DESC);

-- ============================================================================
-- Helper function: Check if downgrade is allowed
-- ============================================================================
CREATE OR REPLACE FUNCTION can_downgrade_verdict(
    p_provisional_verdict VARCHAR,
    p_new_verdict VARCHAR,
    p_new_confidence DECIMAL,
    p_enrichment_complete BOOLEAN
) RETURNS BOOLEAN AS $$
BEGIN
    -- Rule: Never downgrade MALICIOUS before enrichment completes
    IF p_provisional_verdict = 'MALICIOUS' AND NOT p_enrichment_complete THEN
        RETURN FALSE;
    END IF;

    -- Rule: MALICIOUS can only go to NEEDS_REVIEW or stay MALICIOUS until enrichment
    IF p_provisional_verdict = 'MALICIOUS' AND p_new_verdict NOT IN ('MALICIOUS', 'NEEDS_REVIEW', 'TRUE_POSITIVE') THEN
        -- Only allow downgrade with very high confidence
        IF p_new_confidence < 95 THEN
            RETURN FALSE;
        END IF;
    END IF;

    -- Rule: Auto-downgrade to BENIGN only if confidence >= 95
    IF p_new_verdict IN ('BENIGN', 'FALSE_POSITIVE') AND p_new_confidence < 95 THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Trigger: Audit verdict changes automatically
-- ============================================================================
CREATE OR REPLACE FUNCTION audit_verdict_change()
RETURNS TRIGGER AS $$
BEGIN
    -- Only log if verdict or confidence changed
    IF (OLD.disposition IS DISTINCT FROM NEW.disposition) OR
       (OLD.confidence IS DISTINCT FROM NEW.confidence AND ABS(COALESCE(OLD.confidence, 0) - COALESCE(NEW.confidence, 0)) >= 5) THEN

        INSERT INTO verdict_audit_log (
            investigation_id,
            change_type,
            previous_verdict,
            previous_confidence,
            new_verdict,
            new_confidence,
            reason,
            triggered_by,
            tenant_id
        ) VALUES (
            NEW.id,
            CASE
                WHEN NEW.triage_status = 'provisional' THEN 'provisional_set'
                WHEN NEW.triage_status = 'confirmed' THEN 'confirmed'
                WHEN NEW.triage_status = 'needs_review' THEN 'needs_review'
                ELSE 'confidence_change'
            END,
            OLD.disposition,
            OLD.confidence,
            NEW.disposition,
            NEW.confidence,
            'Automatic audit log',
            CASE
                WHEN NEW.triage_status IN ('provisional', 'enriching') THEN 'fast_triage'
                WHEN NEW.triage_status = 'confirmed' THEN 'merge_engine'
                ELSE 'system'
            END,
            NEW.tenant_id
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS verdict_change_audit ON investigations;
CREATE TRIGGER verdict_change_audit
    AFTER UPDATE ON investigations
    FOR EACH ROW
    EXECUTE FUNCTION audit_verdict_change();

-- ============================================================================
-- View: Investigations with enrichment status
-- ============================================================================
CREATE OR REPLACE VIEW v_investigations_triage_status AS
SELECT
    i.id,
    i.investigation_id,
    i.state,
    i.triage_status,
    i.provisional_verdict,
    i.provisional_confidence,
    i.final_verdict,
    i.final_confidence,
    i.disposition,
    i.confidence,
    i.enrichment_progress,
    i.enrichment_total_iocs,
    i.enrichment_completed_iocs,
    i.enrichment_high_risk_hits,
    i.merge_version,
    i.created_at,
    i.updated_at,
    CASE
        WHEN i.triage_status = 'provisional' THEN 'PROVISIONAL'
        WHEN i.triage_status = 'confirmed' THEN 'CONFIRMED'
        WHEN i.triage_status = 'needs_review' THEN 'NEEDS_REVIEW'
        ELSE 'PROCESSING'
    END as verdict_status,
    CASE
        WHEN i.enrichment_progress >= 100 THEN 'complete'
        WHEN i.enrichment_progress > 0 THEN 'in_progress'
        ELSE 'pending'
    END as enrichment_status
FROM investigations i;
