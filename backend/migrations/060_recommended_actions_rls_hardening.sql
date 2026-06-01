-- 060: Harden RLS on recommended_actions to match the intake_forms pattern
--
-- Background: migration 050 created recommended_actions with a single
-- USING-only tenant-isolation policy. That covers SELECT/UPDATE/DELETE
-- visibility but NOT row contents on INSERT/UPDATE — without a
-- WITH CHECK, a tenant could in principle insert a row whose tenant_id
-- column doesn't match their current_tenant_id setting.
--
-- The newer intake_forms (migration 057) uses USING + WITH CHECK and
-- a dedicated platform_admin_bypass policy. Bringing recommended_actions
-- to the same level so background workers (which run as platform-admin)
-- and tenant users have consistent, auditable RLS semantics across the
-- newer tables.

-- Replace the existing policy with one that includes WITH CHECK
DROP POLICY IF EXISTS recommended_actions_tenant_isolation ON recommended_actions;

CREATE POLICY recommended_actions_tenant_isolation ON recommended_actions
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- Platform-admin bypass for background workers / housekeeping
DROP POLICY IF EXISTS recommended_actions_platform_admin_bypass ON recommended_actions;

CREATE POLICY recommended_actions_platform_admin_bypass ON recommended_actions
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
