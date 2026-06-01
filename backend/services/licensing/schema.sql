-- ============================================================================
-- LICENSING SYSTEM DATABASE SCHEMA
-- ============================================================================
-- Run this in PostgreSQL to set up the licensing tables.
-- This can be added to init-db.sql or run separately.

-- ----------------------------------------------------------------------------
-- TENANTS TABLE
-- ----------------------------------------------------------------------------
-- Represents a customer/organization in multi-tenant mode.
-- In single-tenant mode, there's one default tenant.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(64) UNIQUE,

    -- Contact info
    contact_email VARCHAR(255),
    contact_name VARCHAR(255),

    -- Status
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    metadata JSONB DEFAULT '{}'
);

-- Default tenant for single-tenant mode
INSERT INTO tenants (tenant_id, name, slug, is_active)
VALUES ('default', 'Default Tenant', 'default', true)
ON CONFLICT (tenant_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- PLANS TABLE
-- ----------------------------------------------------------------------------
-- Defines available license plans/tiers.

CREATE TABLE IF NOT EXISTS plans (
    plan_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    tier VARCHAR(32) NOT NULL,  -- 'free', 'core', 'pro', 'enterprise', 'custom'

    -- Pricing (for reference, actual billing handled externally)
    price_monthly_cents INTEGER DEFAULT 0,
    price_yearly_cents INTEGER DEFAULT 0,

    -- Default entitlements for this plan
    entitlements JSONB NOT NULL,

    -- Status
    is_active BOOLEAN DEFAULT true,
    is_public BOOLEAN DEFAULT true,  -- Show in plan selection

    -- Metadata
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index on tier
CREATE INDEX IF NOT EXISTS idx_plans_tier ON plans(tier);

-- ----------------------------------------------------------------------------
-- LICENSES TABLE
-- ----------------------------------------------------------------------------
-- Actual licenses issued to tenants.

CREATE TABLE IF NOT EXISTS licenses (
    license_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id),
    plan_id VARCHAR(64) REFERENCES plans(plan_id),

    -- License key (hashed)
    license_key_hash VARCHAR(64) UNIQUE,

    -- Tier (denormalized for quick access)
    tier VARCHAR(32) NOT NULL,

    -- Entitlements (plan defaults + overrides merged)
    entitlements JSONB NOT NULL,

    -- Tenant-specific overrides
    overrides JSONB DEFAULT '{}',

    -- Validity
    issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    valid_from TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP,  -- NULL = no expiration

    -- Status
    is_active BOOLEAN DEFAULT true,
    is_trial BOOLEAN DEFAULT false,
    trial_ends_at TIMESTAMP,

    -- Audit
    created_by VARCHAR(255),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_licenses_tenant ON licenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_licenses_active ON licenses(is_active, tenant_id);

-- ----------------------------------------------------------------------------
-- USAGE COUNTERS TABLE
-- ----------------------------------------------------------------------------
-- Monthly usage counters per tenant per metric.

CREATE TABLE IF NOT EXISTS usage_counters (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id),
    metric VARCHAR(64) NOT NULL,  -- 'investigations_created', 'automation_runs', etc.
    period VARCHAR(7) NOT NULL,   -- 'YYYY-MM'
    value BIGINT DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Unique constraint
    UNIQUE(tenant_id, metric, period)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_usage_tenant_period ON usage_counters(tenant_id, period);
CREATE INDEX IF NOT EXISTS idx_usage_metric ON usage_counters(metric, period);

-- ----------------------------------------------------------------------------
-- BILLING EVENTS TABLE
-- ----------------------------------------------------------------------------
-- Records threshold crossings and overage events for billing.

CREATE TABLE IF NOT EXISTS billing_events (
    event_id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id),

    -- Event details
    event_type VARCHAR(64) NOT NULL,  -- 'threshold_crossed', 'overage_recorded', 'hard_stop_hit'
    metric VARCHAR(64) NOT NULL,
    threshold_type VARCHAR(32) NOT NULL,  -- 'soft_limit', 'overage_max', 'hard_stop'

    -- Values at time of event
    threshold_value BIGINT NOT NULL,
    current_value BIGINT NOT NULL,
    overage_amount BIGINT DEFAULT 0,

    -- Billing period
    period VARCHAR(7) NOT NULL,

    -- Status
    acknowledged BOOLEAN DEFAULT false,
    acknowledged_at TIMESTAMP,
    acknowledged_by VARCHAR(255),

    -- Metadata
    metadata JSONB DEFAULT '{}',

    -- Timestamps
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_billing_tenant_period ON billing_events(tenant_id, period);
CREATE INDEX IF NOT EXISTS idx_billing_unacked ON billing_events(tenant_id, acknowledged) WHERE NOT acknowledged;

-- ----------------------------------------------------------------------------
-- AGENT DEFINITIONS TABLE
-- ----------------------------------------------------------------------------
-- Defines agents and their tiers.

CREATE TABLE IF NOT EXISTS agent_definitions (
    agent_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,

    -- Tier classification
    tier INTEGER NOT NULL DEFAULT 1,  -- 1, 2, or 3

    -- Capabilities
    is_destructive BOOLEAN DEFAULT false,
    requires_approval BOOLEAN DEFAULT false,

    -- Status
    is_active BOOLEAN DEFAULT true,

    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index on tier
CREATE INDEX IF NOT EXISTS idx_agents_tier ON agent_definitions(tier);

-- ----------------------------------------------------------------------------
-- IDEMPOTENCY KEYS TABLE
-- ----------------------------------------------------------------------------
-- Tracks processed idempotency keys to prevent double-counting.

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key_hash VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    metric VARCHAR(64) NOT NULL,
    amount INTEGER NOT NULL,
    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Auto-expire old keys (use with pg_cron or similar)
    expires_at TIMESTAMP DEFAULT (CURRENT_TIMESTAMP + INTERVAL '7 days')
);

-- Index for cleanup
CREATE INDEX IF NOT EXISTS idx_idempotency_expires ON idempotency_keys(expires_at);

-- ----------------------------------------------------------------------------
-- FUNCTIONS
-- ----------------------------------------------------------------------------

-- Function to safely increment usage counter
CREATE OR REPLACE FUNCTION increment_usage_counter(
    p_tenant_id VARCHAR(64),
    p_metric VARCHAR(64),
    p_period VARCHAR(7),
    p_amount INTEGER,
    p_idempotency_key VARCHAR(64) DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
    v_new_value BIGINT;
    v_key_hash VARCHAR(64);
BEGIN
    -- Check idempotency key if provided
    IF p_idempotency_key IS NOT NULL THEN
        v_key_hash := encode(sha256(p_idempotency_key::bytea), 'hex');

        -- Try to insert idempotency key
        BEGIN
            INSERT INTO idempotency_keys (key_hash, tenant_id, metric, amount)
            VALUES (v_key_hash, p_tenant_id, p_metric, p_amount);
        EXCEPTION WHEN unique_violation THEN
            -- Key already processed, return current value
            SELECT value INTO v_new_value
            FROM usage_counters
            WHERE tenant_id = p_tenant_id AND metric = p_metric AND period = p_period;
            RETURN COALESCE(v_new_value, 0);
        END;
    END IF;

    -- Upsert counter
    INSERT INTO usage_counters (tenant_id, metric, period, value)
    VALUES (p_tenant_id, p_metric, p_period, p_amount)
    ON CONFLICT (tenant_id, metric, period)
    DO UPDATE SET value = usage_counters.value + p_amount, updated_at = CURRENT_TIMESTAMP
    RETURNING value INTO v_new_value;

    RETURN v_new_value;
END;
$$ LANGUAGE plpgsql;

-- Function to get current usage
CREATE OR REPLACE FUNCTION get_usage(
    p_tenant_id VARCHAR(64),
    p_metric VARCHAR(64),
    p_period VARCHAR(7) DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
    v_period VARCHAR(7);
    v_value BIGINT;
BEGIN
    v_period := COALESCE(p_period, to_char(CURRENT_TIMESTAMP, 'YYYY-MM'));

    SELECT value INTO v_value
    FROM usage_counters
    WHERE tenant_id = p_tenant_id AND metric = p_metric AND period = v_period;

    RETURN COALESCE(v_value, 0);
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup expired idempotency keys
CREATE OR REPLACE FUNCTION cleanup_idempotency_keys() RETURNS INTEGER AS $$
DECLARE
    v_deleted INTEGER;
BEGIN
    DELETE FROM idempotency_keys WHERE expires_at < CURRENT_TIMESTAMP;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------------------
-- SEED DEFAULT PLANS
-- ----------------------------------------------------------------------------

INSERT INTO plans (plan_id, name, tier, price_monthly_cents, price_yearly_cents, entitlements, description)
VALUES
    ('plan_free', 'Free', 'free', 0, 0,
     '{"investigations_per_month": 50, "automation_runs_per_month": 100, "overage_allowed": false}',
     'Free tier for evaluation'),
    ('plan_core', 'Core', 'core', 9900, 99900,
     '{"investigations_per_month": 500, "automation_runs_per_month": 2500, "overage_allowed": true, "overage_max_percent": 10}',
     'Entry-level paid plan'),
    ('plan_pro', 'Pro', 'pro', 29900, 299900,
     '{"investigations_per_month": 2500, "automation_runs_per_month": 15000, "overage_allowed": true, "overage_max_percent": 20}',
     'Professional plan for growing teams'),
    ('plan_enterprise', 'Enterprise', 'enterprise', 99900, 999900,
     '{"investigations_per_month": 25000, "automation_runs_per_month": 150000, "overage_allowed": true, "overage_max_percent": 50}',
     'Enterprise plan with full features')
ON CONFLICT (plan_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- VIEWS
-- ----------------------------------------------------------------------------

-- View for current month usage summary
CREATE OR REPLACE VIEW current_usage_summary AS
SELECT
    t.tenant_id,
    t.name as tenant_name,
    l.tier,
    uc.metric,
    uc.value as current_usage,
    CASE
        WHEN uc.metric = 'investigations_created' THEN (l.entitlements->>'investigations_per_month')::int
        WHEN uc.metric = 'automation_runs' THEN (l.entitlements->>'automation_runs_per_month')::int
        ELSE 0
    END as limit_value,
    CASE
        WHEN uc.metric = 'investigations_created' THEN
            ROUND((uc.value::numeric / NULLIF((l.entitlements->>'investigations_per_month')::int, 0)) * 100, 1)
        WHEN uc.metric = 'automation_runs' THEN
            ROUND((uc.value::numeric / NULLIF((l.entitlements->>'automation_runs_per_month')::int, 0)) * 100, 1)
        ELSE 0
    END as percent_used
FROM tenants t
JOIN licenses l ON t.tenant_id = l.tenant_id AND l.is_active = true
LEFT JOIN usage_counters uc ON t.tenant_id = uc.tenant_id AND uc.period = to_char(CURRENT_TIMESTAMP, 'YYYY-MM')
WHERE t.is_active = true;

-- View for billing events needing attention
CREATE OR REPLACE VIEW billing_events_pending AS
SELECT
    be.*,
    t.name as tenant_name,
    l.tier
FROM billing_events be
JOIN tenants t ON be.tenant_id = t.tenant_id
JOIN licenses l ON be.tenant_id = l.tenant_id AND l.is_active = true
WHERE be.acknowledged = false
ORDER BY be.timestamp DESC;
