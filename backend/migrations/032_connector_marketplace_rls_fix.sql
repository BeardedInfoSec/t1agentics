-- Migration 032: Fix RLS on connector_definitions and playbook_templates
--
-- The rls_hardening migration (Feb 18) added tenant_isolation policies that
-- block regular tenants from reading builtin/community content where
-- tenant_id IS NULL. This broke the T1 Connect marketplace and playbook
-- marketplace for all non-platform tenants.
--
-- Fix: Replace overly restrictive tenant_isolation with granular policies:
--   - SELECT: own rows + builtin/community rows (tenant_id IS NULL)
--   - INSERT/UPDATE/DELETE: own tenant's rows only

-- ═══════════════════════════════════════════════════════
-- connector_definitions
-- ═══════════════════════════════════════════════════════

DROP POLICY IF EXISTS tenant_isolation ON connector_definitions;
DROP POLICY IF EXISTS builtin_connectors_read ON connector_definitions;

-- Read: own connectors + builtin/community connectors
CREATE POLICY connector_read ON connector_definitions FOR SELECT
    USING (
        tenant_id::text = current_setting('app.current_tenant_id', true)
        OR tenant_id IS NULL
    );

-- Insert: only into own tenant
CREATE POLICY connector_write ON connector_definitions FOR INSERT
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Update: only own tenant's connectors
CREATE POLICY connector_modify ON connector_definitions FOR UPDATE
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Delete: only own tenant's connectors
CREATE POLICY connector_remove ON connector_definitions FOR DELETE
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

-- ═══════════════════════════════════════════════════════
-- playbook_templates
-- ═══════════════════════════════════════════════════════

DROP POLICY IF EXISTS tenant_isolation ON playbook_templates;
DROP POLICY IF EXISTS builtin_templates_read ON playbook_templates;

-- Read: own templates + builtin/community templates
CREATE POLICY template_read ON playbook_templates FOR SELECT
    USING (
        tenant_id::text = current_setting('app.current_tenant_id', true)
        OR tenant_id IS NULL
    );

-- Insert: only into own tenant
CREATE POLICY template_write ON playbook_templates FOR INSERT
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Update: only own tenant's templates
CREATE POLICY template_modify ON playbook_templates FOR UPDATE
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));

-- Delete: only own tenant's templates
CREATE POLICY template_remove ON playbook_templates FOR DELETE
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));
