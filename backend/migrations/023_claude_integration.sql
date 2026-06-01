-- Migration 023: Claude API Integration
-- Adds per-tenant token tracking and monthly usage cache for quota enforcement.

-- 1. Add tenant_id to ai_token_usage for per-tenant tracking
ALTER TABLE ai_token_usage ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_ai_token_usage_tenant_month
    ON ai_token_usage (tenant_id, created_at);

-- 2. Monthly usage cache for fast quota lookups (avoids scanning ai_token_usage)
CREATE TABLE IF NOT EXISTS tenant_claude_usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    month_start DATE NOT NULL,
    total_input_tokens BIGINT DEFAULT 0,
    total_output_tokens BIGINT DEFAULT 0,
    total_tokens BIGINT DEFAULT 0,
    total_cost_cents DECIMAL(12,4) DEFAULT 0,
    overage_tokens BIGINT DEFAULT 0,
    overage_reported_to_stripe BOOLEAN DEFAULT FALSE,
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(tenant_id, month_start)
);

-- 3. Add stripe_metered_item_id to tenants for overage billing
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_metered_item_id VARCHAR(255);
