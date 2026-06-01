-- Allow any authenticated tenant to READ builtin playbook templates (tenant_id IS NULL)
-- Without this, RLS blocks marketplace templates because tenant_isolation requires
-- tenant_id = app.current_tenant_id, but builtins have tenant_id IS NULL.
DROP POLICY IF EXISTS builtin_templates_read ON playbook_templates;
CREATE POLICY builtin_templates_read ON playbook_templates
  FOR SELECT
  USING (
    tenant_id IS NULL
    AND current_setting('app.current_tenant_id', true) IS NOT NULL
    AND current_setting('app.current_tenant_id', true) != ''
  );
