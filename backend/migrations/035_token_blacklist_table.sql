-- Migration 035: Database-backed token blacklist and usage counters
-- Replaces in-memory token blacklist (tokens survive server restarts)
-- Adds usage_counters table for persistent quota tracking

-- Token blacklist: stores revoked JWT token IDs
CREATE TABLE IF NOT EXISTS token_blacklist (
    jti VARCHAR(64) PRIMARY KEY,
    token_type VARCHAR(20) NOT NULL DEFAULT 'token',  -- 'token' or 'user'
    username VARCHAR(255),  -- For user-level revocations
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    reason VARCHAR(100)  -- 'logout', 'password_change', 'admin_revoke'
);

CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires ON token_blacklist(expires_at);
CREATE INDEX IF NOT EXISTS idx_token_blacklist_username ON token_blacklist(username)
    WHERE token_type = 'user';

-- Usage counters: persistent quota tracking
CREATE TABLE IF NOT EXISTS usage_counters (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    metric VARCHAR(100) NOT NULL,
    period VARCHAR(7) NOT NULL,  -- YYYY-MM
    value BIGINT DEFAULT 0 NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (tenant_id, metric, period)
);

CREATE INDEX IF NOT EXISTS idx_usage_counters_tenant ON usage_counters(tenant_id);
CREATE INDEX IF NOT EXISTS idx_usage_counters_period ON usage_counters(period);
