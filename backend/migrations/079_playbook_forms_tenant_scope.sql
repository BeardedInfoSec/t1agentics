-- 079: Tenant-scope playbook_forms
--
-- playbook_forms has been a global table since 004 — no tenant_id, no
-- RLS — so a tenant's forms were visible (and prefill-resolvable)
-- against any other tenant's running playbook execution. The 2026-05-13
-- prefill feature made the impact concrete: a malicious form authored
-- in tenant A with prefill_mapping = {"x": "$.alert.subject"} would
-- resolve against any tenant's execution_context when their playbook
-- attached that form.
--
-- Migration pattern matches 074_dedupe_tenant_scope.sql:
--   1. Add tenant_id (nullable initially)
--   2. Delete orphan rows so the NOT NULL upgrade is safe
--   3. Replace global UNIQUE(name) with per-tenant UNIQUE(tenant_id, name)
--      — the original schema only had a (non-unique) INDEX on name, so
--      no constraint to drop; we add the per-tenant uniqueness here
--   4. NOT NULL + index
--   5. RLS isolation + platform-admin bypass

ALTER TABLE playbook_forms
    ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;

-- Production currently holds zero playbook_forms rows; this DELETE is a
-- safety net for any future re-application against a non-empty
-- environment where rows were created before the column existed.
DELETE FROM playbook_forms WHERE tenant_id IS NULL;

ALTER TABLE playbook_forms
    ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE playbook_forms
    ADD CONSTRAINT playbook_forms_tenant_name_key UNIQUE (tenant_id, name);

CREATE INDEX IF NOT EXISTS idx_pb_form_tenant ON playbook_forms(tenant_id);

ALTER TABLE playbook_forms ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS playbook_forms_isolation ON playbook_forms;
CREATE POLICY playbook_forms_isolation ON playbook_forms
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS playbook_forms_platform_admin_bypass ON playbook_forms;
CREATE POLICY playbook_forms_platform_admin_bypass ON playbook_forms
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
