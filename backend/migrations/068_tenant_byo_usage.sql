-- 068: Per-tenant BYO usage tracking
--
-- Mirrors tenant_claude_usage so BYO tenants can see what their own key
-- has spent. Platform daily-cap and per-tenant quota queries read from
-- tenant_claude_usage / ai_token_usage and intentionally ignore this
-- table — BYO calls are billed to the tenant, not T1.

CREATE TABLE IF NOT EXISTS tenant_byo_usage (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                UUID NOT NULL,
    period                   TEXT NOT NULL,                  -- "2026-05" (YYYY-MM, matches tenant_claude_usage)
    provider                 TEXT NOT NULL,                  -- 'anthropic' | 'openai' | 'self_hosted'
    request_count            BIGINT NOT NULL DEFAULT 0,
    prompt_tokens            BIGINT NOT NULL DEFAULT 0,
    completion_tokens        BIGINT NOT NULL DEFAULT 0,
    total_tokens             BIGINT NOT NULL DEFAULT 0,
    last_request_at          TIMESTAMPTZ,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, period, provider)
);

CREATE INDEX IF NOT EXISTS idx_tenant_byo_usage_tenant
    ON tenant_byo_usage(tenant_id, period);

ALTER TABLE tenant_byo_usage ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_byo_usage_isolation ON tenant_byo_usage;
CREATE POLICY tenant_byo_usage_isolation ON tenant_byo_usage
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS tenant_byo_usage_platform_admin_bypass ON tenant_byo_usage;
CREATE POLICY tenant_byo_usage_platform_admin_bypass ON tenant_byo_usage
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
