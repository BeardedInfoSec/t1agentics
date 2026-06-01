-- Migration 030: Allow all tenants to read builtin KB articles
--
-- Previously, tenant_isolation policy on knowledge_base only allowed access
-- to articles matching the tenant's own tenant_id. This prevented tenants
-- from seeing platform-level builtin articles (integration guides, SOPs, etc).
--
-- Fix: Split into granular policies:
--   - SELECT: own articles + builtin articles (source = 'builtin')
--   - INSERT/UPDATE/DELETE: own tenant's articles only

DROP POLICY IF EXISTS tenant_isolation ON knowledge_base;

-- Read: own articles + platform builtin articles
CREATE POLICY tenant_read ON knowledge_base FOR SELECT
    USING (
        tenant_id::text = current_setting('app.current_tenant_id', true)
        OR source = 'builtin'
    );

-- Insert: only into own tenant
CREATE POLICY tenant_write ON knowledge_base FOR INSERT
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Update: only own tenant's articles
CREATE POLICY tenant_modify ON knowledge_base FOR UPDATE
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Delete: only own tenant's articles
CREATE POLICY tenant_remove ON knowledge_base FOR DELETE
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));
