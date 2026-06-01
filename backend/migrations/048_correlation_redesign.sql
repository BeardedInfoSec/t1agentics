-- Migration 048: Correlation Redesign
-- Entity risk accumulation table + per-tenant correlation settings
-- Part of v3.0 hypothesis-driven correlation redesign

-- Entity risk accumulation table
CREATE TABLE IF NOT EXISTS entity_risk (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    entity_type VARCHAR(50) NOT NULL,
    entity_value VARCHAR(500) NOT NULL,
    risk_score DECIMAL(8,2) DEFAULT 0,
    alert_count INTEGER DEFAULT 0,
    contributing_alerts JSONB DEFAULT '[]',
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    threshold_breached BOOLEAN DEFAULT false,
    threshold_breached_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, entity_type, entity_value)
);

CREATE INDEX IF NOT EXISTS idx_entity_risk_tenant ON entity_risk(tenant_id);
CREATE INDEX IF NOT EXISTS idx_entity_risk_score ON entity_risk(tenant_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_entity_risk_breached ON entity_risk(tenant_id, threshold_breached) WHERE threshold_breached = true;

ALTER TABLE entity_risk ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS entity_risk_tenant_isolation ON entity_risk;
CREATE POLICY entity_risk_tenant_isolation ON entity_risk
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Per-tenant correlation settings
CREATE TABLE IF NOT EXISTS correlation_settings (
    tenant_id UUID PRIMARY KEY REFERENCES tenants(id),
    -- Engine toggles
    correlation_enabled BOOLEAN DEFAULT true,
    ai_hypothesis_enabled BOOLEAN DEFAULT true,
    entity_risk_enabled BOOLEAN DEFAULT true,
    allow_cross_domain BOOLEAN DEFAULT false,
    -- Thresholds
    time_window_hours INTEGER DEFAULT 24,
    min_evidence_score INTEGER DEFAULT 40,
    auto_confirm_threshold INTEGER DEFAULT 100,
    max_alerts_per_investigation INTEGER DEFAULT 25,
    -- Entity risk
    entity_risk_threshold INTEGER DEFAULT 75,
    entity_risk_decay_hours INTEGER DEFAULT 72,
    -- Entity weights
    user_weight INTEGER DEFAULT 30,
    host_weight INTEGER DEFAULT 25,
    ip_weight INTEGER DEFAULT 15,
    ioc_weight INTEGER DEFAULT 20,
    -- Timestamps
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by VARCHAR(255)
);

ALTER TABLE correlation_settings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS correlation_settings_tenant_isolation ON correlation_settings;
CREATE POLICY correlation_settings_tenant_isolation ON correlation_settings
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));
