-- Migration 025: Expanded RBAC Permissions for Integrations and Playbooks
-- Adds granular permissions: integration:view/install/configure/manage
-- Adds playbook permissions: playbook:view/create/edit/execute/delete
-- Copyright (c) 2024-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

-- ============================================================================
-- 1. Insert new permissions (idempotent — skip if already exists)
-- ============================================================================

INSERT INTO permissions (id, key, description, category, is_system)
VALUES
    -- Integration permissions (granular)
    (gen_random_uuid(), 'integration:view',      'View integrations and marketplace',                           'integrations', true),
    (gen_random_uuid(), 'integration:install',    'Install or uninstall integrations',                           'integrations', true),
    (gen_random_uuid(), 'integration:configure',  'Configure integrations, credentials, and test connections',   'integrations', true),
    -- integration:manage already exists

    -- Playbook permissions
    (gen_random_uuid(), 'playbook:view',    'View playbooks and templates',    'playbooks', true),
    (gen_random_uuid(), 'playbook:create',  'Create new playbooks',            'playbooks', true),
    (gen_random_uuid(), 'playbook:edit',    'Edit and update playbooks',       'playbooks', true),
    (gen_random_uuid(), 'playbook:execute', 'Execute playbooks manually',      'playbooks', true),
    (gen_random_uuid(), 'playbook:delete',  'Delete playbooks',                'playbooks', true)
ON CONFLICT (key) DO NOTHING;


-- ============================================================================
-- 2. Grant permissions to default roles (for all existing tenants)
-- ============================================================================

-- Helper: grant a permission to a role across all tenants where that role exists
-- We use a CTE approach to avoid procedural code.

-- Analyst gets: integration:view, playbook:view, playbook:execute
INSERT INTO role_permissions (tenant_id, role_id, permission_id, granted_at)
SELECT r.tenant_id, r.id, p.id, NOW()
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'Analyst'
  AND p.key IN ('integration:view', 'playbook:view', 'playbook:execute')
ON CONFLICT ON CONSTRAINT uq_role_permissions DO NOTHING;

-- ReadOnly gets: integration:view, playbook:view
INSERT INTO role_permissions (tenant_id, role_id, permission_id, granted_at)
SELECT r.tenant_id, r.id, p.id, NOW()
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'ReadOnly'
  AND p.key IN ('integration:view', 'playbook:view')
ON CONFLICT ON CONSTRAINT uq_role_permissions DO NOTHING;

-- Automation gets: playbook:execute, integration:view
INSERT INTO role_permissions (tenant_id, role_id, permission_id, granted_at)
SELECT r.tenant_id, r.id, p.id, NOW()
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'Automation'
  AND p.key IN ('playbook:execute', 'integration:view')
ON CONFLICT ON CONSTRAINT uq_role_permissions DO NOTHING;

-- Admin already has '*' wildcard — no explicit grants needed.
-- But for completeness, grant all new permissions to Admin as well.
INSERT INTO role_permissions (tenant_id, role_id, permission_id, granted_at)
SELECT r.tenant_id, r.id, p.id, NOW()
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'Admin'
  AND p.key IN (
    'integration:view', 'integration:install', 'integration:configure',
    'playbook:view', 'playbook:create', 'playbook:edit', 'playbook:execute', 'playbook:delete'
  )
ON CONFLICT ON CONSTRAINT uq_role_permissions DO NOTHING;
