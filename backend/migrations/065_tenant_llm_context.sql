-- 065: Per-tenant LLM context overrides
--
-- We already have a hardcoded RIGGS_EXCLUDED_FIELDS list and a substring
-- redactor in agents/riggs.py that strip noisy / sensitive fields before
-- the alert hits Claude. The symmetric direction was missing: tenants had
-- no way to *add* context they want Riggs to consider on every alert
-- (e.g. "we run a managed PSA from Datto, SSO is Okta, the CFO email is
-- cfo@example.com — escalate impersonation hard").
--
-- This table stores three pieces of per-tenant config:
--   * extra_context           free-form prose appended to the prompt
--   * include_field_keys      raw_event keys to keep even when the default
--                             redactor / EXCLUDED_FIELDS list would strip
--                             them (e.g. tenant wants 'cookie' visible)
--   * exclude_field_keys      extra keys to drop on top of the defaults
--
-- One row per tenant. Created on first PUT.

CREATE TABLE IF NOT EXISTS tenant_llm_context (
    tenant_id           UUID PRIMARY KEY,
    extra_context       TEXT,                                    -- free-form prose, capped at 4KB in the API layer
    include_field_keys  JSONB NOT NULL DEFAULT '[]'::jsonb,      -- array of strings
    exclude_field_keys  JSONB NOT NULL DEFAULT '[]'::jsonb,      -- array of strings
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by          UUID
);

ALTER TABLE tenant_llm_context ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_llm_context_isolation ON tenant_llm_context;
CREATE POLICY tenant_llm_context_isolation ON tenant_llm_context
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS tenant_llm_context_platform_admin_bypass ON tenant_llm_context;
CREATE POLICY tenant_llm_context_platform_admin_bypass ON tenant_llm_context
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
