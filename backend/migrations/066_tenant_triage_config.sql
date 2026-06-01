-- 066: Per-tenant triage thresholds
--
-- Until now the auto-close gate in ai_triage_service was hardcoded:
-- 0.90 minimum confidence for BENIGN/FALSE_POSITIVE, fp_likelihood off
-- the gate entirely. Tenants couldn't tune how aggressive auto-close
-- was, which mattered most for free tenants (where auto-close runs)
-- and for the paid-tier "strong benign" shortcut.
--
-- This table holds per-tenant overrides. Both columns default to the
-- historical values so existing tenants behave identically until they
-- opt in.

CREATE TABLE IF NOT EXISTS tenant_triage_config (
    tenant_id                       UUID PRIMARY KEY,
    auto_close_min_confidence       NUMERIC(4,3) NOT NULL DEFAULT 0.900   -- 0.000-1.000
                                    CHECK (auto_close_min_confidence BETWEEN 0 AND 1),
    auto_close_min_fp_likelihood    NUMERIC(4,3) NOT NULL DEFAULT 0.000   -- 0 = off the gate
                                    CHECK (auto_close_min_fp_likelihood BETWEEN 0 AND 1),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by                      UUID
);

ALTER TABLE tenant_triage_config ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_triage_config_isolation ON tenant_triage_config;
CREATE POLICY tenant_triage_config_isolation ON tenant_triage_config
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS tenant_triage_config_platform_admin_bypass ON tenant_triage_config;
CREATE POLICY tenant_triage_config_platform_admin_bypass ON tenant_triage_config
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
