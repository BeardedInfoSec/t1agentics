-- 074: Tenant-scope dedupe_config
--
-- dedupe_config has been a global table since it was created — no
-- tenant_id, no RLS, and a global UNIQUE on name. That means tenant A's
-- "Network Scan Dedup" prevented tenant B from creating one with the
-- same name, and tenant A's rule applied to tenant B's alerts. Both
-- wrong for a multi-tenant platform.
--
-- This migration:
--   1. Adds tenant_id (nullable initially so the ALTER doesn't fail
--      with NOT NULL on existing rows)
--   2. Drops the global UNIQUE(name) and replaces it with UNIQUE(tenant_id, name)
--   3. Deletes orphan rows that have no owner. The 3 existing rows on
--      the droplet were created during development with no tenant
--      attached; the new tenants can re-create them via Quick Add.
--   4. Enables RLS with the standard isolation + platform-admin bypass
--      policy pair we use across alert-processing tables

ALTER TABLE dedupe_config
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

-- Drop the legacy global UNIQUE
ALTER TABLE dedupe_config DROP CONSTRAINT IF EXISTS dedupe_config_name_key;

-- Delete orphan rows BEFORE adding the per-tenant unique so the new
-- constraint doesn't get tripped by tenant_id=NULL duplicates.
DELETE FROM dedupe_config WHERE tenant_id IS NULL;

-- New per-tenant unique
ALTER TABLE dedupe_config
    ADD CONSTRAINT dedupe_config_tenant_name_key UNIQUE (tenant_id, name);

CREATE INDEX IF NOT EXISTS idx_dedupe_config_tenant
    ON dedupe_config(tenant_id) WHERE enabled = TRUE;

ALTER TABLE dedupe_config ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS dedupe_config_isolation ON dedupe_config;
CREATE POLICY dedupe_config_isolation ON dedupe_config
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS dedupe_config_platform_admin_bypass ON dedupe_config;
CREATE POLICY dedupe_config_platform_admin_bypass ON dedupe_config
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
