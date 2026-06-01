-- 071: Tenant-defined PII patterns
--
-- The built-in PII detector (services/pii_obfuscation.py) ships with
-- patterns for credit cards, SSNs, emails, phones, etc. Tenants often
-- have their own identifier formats that should be treated the same
-- way — customer numbers, internal employee IDs, account formats that
-- look generic but identify someone.
--
-- This table lets a tenant admin define regex patterns + a redaction
-- mode. Patterns get applied alongside the built-ins during
-- obfuscate_text / obfuscate_event. One row per pattern so the UI can
-- enable/disable individually.

CREATE TABLE IF NOT EXISTS tenant_pii_patterns (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID NOT NULL,
    label        TEXT NOT NULL,                                    -- "Customer ID", "Internal employee number"
    pattern      TEXT NOT NULL,                                    -- regex (caller validates compilable on save)
    mode         TEXT NOT NULL DEFAULT 'mask'
                 CHECK (mode IN ('mask', 'redact', 'hash')),
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   UUID,
    UNIQUE (tenant_id, label)
);

CREATE INDEX IF NOT EXISTS idx_tenant_pii_patterns_tenant
    ON tenant_pii_patterns(tenant_id) WHERE enabled = TRUE;

ALTER TABLE tenant_pii_patterns ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_pii_patterns_isolation ON tenant_pii_patterns;
CREATE POLICY tenant_pii_patterns_isolation ON tenant_pii_patterns
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS tenant_pii_patterns_platform_admin_bypass ON tenant_pii_patterns;
CREATE POLICY tenant_pii_patterns_platform_admin_bypass ON tenant_pii_patterns
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
