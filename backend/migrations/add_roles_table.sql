-- Migration: Add roles table for persistent role storage
-- This enables custom roles with index permissions

-- ============================================================================
-- ROLES TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100),
    description TEXT,

    -- Functional permissions (actions the role can perform)
    permissions JSONB DEFAULT '[]'::jsonb,

    -- System vs custom
    is_system BOOLEAN DEFAULT false,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_system ON roles(is_system);

-- Insert default system roles
INSERT INTO roles (name, display_name, description, permissions, is_system) VALUES
    ('admin', 'Administrator', 'Full administrative access to all features', '["*"]'::jsonb, true),
    ('analyst', 'Security Analyst', 'Security analyst with investigation capabilities',
     '["tenant:read", "investigation:read", "investigation:create", "investigation:update", "alert:read", "alert:update", "alert:link", "note:read", "note:create", "note:update", "file:upload", "file:read", "file:download", "action:read", "action:execute"]'::jsonb,
     true),
    ('read_only', 'Read Only', 'Read-only access to investigations and alerts',
     '["tenant:read", "investigation:read", "alert:read", "note:read", "file:read", "action:read"]'::jsonb,
     true),
    ('automation', 'Automation', 'Service account for automation and integrations',
     '["action:execute"]'::jsonb,
     true)
ON CONFLICT (name) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    description = EXCLUDED.description,
    permissions = EXCLUDED.permissions;

-- ============================================================================
-- INDEX PERMISSION TEMPLATES
-- Template for creating default index permissions for new roles
-- ============================================================================

CREATE TABLE IF NOT EXISTS index_permission_templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,

    -- Default permissions to apply
    default_can_read BOOLEAN DEFAULT true,
    default_can_write BOOLEAN DEFAULT false,
    default_can_delete BOOLEAN DEFAULT false,
    default_can_admin BOOLEAN DEFAULT false,

    -- Which indexes to include (NULL = all, or array of index names)
    included_indexes TEXT[],
    excluded_indexes TEXT[],

    -- Default field restrictions
    default_denied_fields JSONB DEFAULT NULL,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Insert permission templates
INSERT INTO index_permission_templates (name, description, default_can_read, default_can_write, default_can_delete, default_can_admin, excluded_indexes, default_denied_fields) VALUES
    ('full_access', 'Full access to all indexes', true, true, true, true, NULL, NULL),
    ('analyst_access', 'Analyst access - read/write, no admin index', true, true, false, false, ARRAY['admin'], NULL),
    ('read_only_access', 'Read-only access to safe indexes', true, false, false, false, ARRAY['admin', 'threat_intel'], '["credentials.*", "api_key.*", "secret.*"]'::jsonb),
    ('minimal_access', 'Minimal access - main and application only', true, false, false, false, ARRAY['admin', 'security', 'endpoint', 'network', 'auth', 'threat_intel'], NULL)
ON CONFLICT (name) DO NOTHING;

SELECT 'Roles table and permission templates created successfully!' as result;
