-- Migration: Add Multi-Tenancy Support
-- Copyright (c) 2024-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
--
-- This migration adds tenant isolation to the T1 Agentics database.
-- Run with: psql -d t1agentics -f 002_multitenancy.sql

-- =============================================================================
-- 1. CREATE TENANTS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(50) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,

    -- Plan & Limits
    plan VARCHAR(50) NOT NULL DEFAULT 'community',
    license_key VARCHAR(255),

    -- Custom limits (NULL = use plan defaults)
    alerts_per_day_limit INTEGER,
    playbooks_limit INTEGER,
    integrations_limit INTEGER,
    users_limit INTEGER,
    retention_days INTEGER,

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    suspended_at TIMESTAMP WITH TIME ZONE,
    suspended_reason TEXT,

    -- Billing
    stripe_customer_id VARCHAR(255),
    billing_email VARCHAR(255),

    -- Metadata
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    -- Constraints
    CONSTRAINT valid_plan CHECK (plan IN ('community', 'professional', 'enterprise')),
    CONSTRAINT valid_status CHECK (status IN ('active', 'suspended', 'cancelled', 'pending')),
    CONSTRAINT valid_slug CHECK (slug ~ '^[a-z0-9][a-z0-9-]*[a-z0-9]$' AND length(slug) >= 3)
);

CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);
CREATE INDEX IF NOT EXISTS idx_tenants_plan ON tenants(plan);

-- =============================================================================
-- 2. CREATE DEFAULT TENANT FOR EXISTING DATA
-- =============================================================================

INSERT INTO tenants (id, slug, name, plan, status)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'default',
    'Default Tenant',
    'enterprise',
    'active'
) ON CONFLICT (slug) DO NOTHING;

-- =============================================================================
-- 3. CREATE API KEYS TABLE (for tenant resolution)
-- =============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA256 hash
    key_prefix VARCHAR(8) NOT NULL,  -- First 8 chars for identification

    -- Permissions
    scopes JSONB DEFAULT '["read", "write"]',

    -- Lifecycle
    created_by UUID,  -- user who created it
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked BOOLEAN DEFAULT false,
    revoked_at TIMESTAMP WITH TIME ZONE,

    CONSTRAINT valid_key_prefix CHECK (length(key_prefix) = 8)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);

-- =============================================================================
-- 4. ADD TENANT_ID TO EXISTING TABLES
-- =============================================================================

-- Function to add tenant_id column if it doesn't exist
CREATE OR REPLACE FUNCTION add_tenant_id_column(table_name TEXT) RETURNS VOID AS $$
BEGIN
    EXECUTE format('
        ALTER TABLE %I
        ADD COLUMN IF NOT EXISTS tenant_id UUID
        REFERENCES tenants(id) ON DELETE CASCADE
    ', table_name);

    -- Set default for existing rows
    EXECUTE format('
        UPDATE %I
        SET tenant_id = ''00000000-0000-0000-0000-000000000001''
        WHERE tenant_id IS NULL
    ', table_name);

    -- Make NOT NULL after backfill
    EXECUTE format('
        ALTER TABLE %I
        ALTER COLUMN tenant_id SET NOT NULL
    ', table_name);

    -- Add index
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%I_tenant_id ON %I(tenant_id)
    ', table_name, table_name);
END;
$$ LANGUAGE plpgsql;

-- Apply to all tenant-scoped tables
DO $$
DECLARE
    tables TEXT[] := ARRAY[
        'alerts',
        'investigations',
        'playbooks',
        'playbook_executions',
        'playbook_node_results',
        'users',
        'integration_instances',
        'credentials',
        'iocs',
        'audit_logs',
        'chat_sessions',
        'chat_messages',
        'attachments',
        'webhooks',
        'webhook_deliveries',
        'edl_lists',
        'threat_feeds',
        'approval_requests',
        'notification_settings'
    ];
    t TEXT;
BEGIN
    FOREACH t IN ARRAY tables
    LOOP
        -- Check if table exists before adding column
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = t) THEN
            PERFORM add_tenant_id_column(t);
            RAISE NOTICE 'Added tenant_id to %', t;
        ELSE
            RAISE NOTICE 'Table % does not exist, skipping', t;
        END IF;
    END LOOP;
END $$;

-- =============================================================================
-- 5. ENABLE ROW-LEVEL SECURITY
-- =============================================================================

-- Function to enable RLS on a table
CREATE OR REPLACE FUNCTION enable_tenant_rls(table_name TEXT) RETURNS VOID AS $$
BEGIN
    -- Enable RLS
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);

    -- Force RLS for table owner too (important for testing)
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);

    -- Drop existing policies if any
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
    EXECUTE format('DROP POLICY IF EXISTS platform_admin_bypass ON %I', table_name);

    -- Create tenant isolation policy
    EXECUTE format('
        CREATE POLICY tenant_isolation ON %I
        FOR ALL
        USING (
            tenant_id = COALESCE(
                NULLIF(current_setting(''app.current_tenant_id'', true), ''''),
                ''00000000-0000-0000-0000-000000000000''
            )::uuid
        )
        WITH CHECK (
            tenant_id = COALESCE(
                NULLIF(current_setting(''app.current_tenant_id'', true), ''''),
                ''00000000-0000-0000-0000-000000000000''
            )::uuid
        )
    ', table_name);

    -- Create platform admin bypass policy
    EXECUTE format('
        CREATE POLICY platform_admin_bypass ON %I
        FOR ALL
        USING (
            COALESCE(current_setting(''app.is_platform_admin'', true), ''false'')::boolean = true
        )
    ', table_name);
END;
$$ LANGUAGE plpgsql;

-- Apply RLS to all tenant-scoped tables
DO $$
DECLARE
    tables TEXT[] := ARRAY[
        'alerts',
        'investigations',
        'playbooks',
        'playbook_executions',
        'playbook_node_results',
        'users',
        'integration_instances',
        'credentials',
        'iocs',
        'audit_logs',
        'chat_sessions',
        'chat_messages',
        'attachments',
        'webhooks',
        'webhook_deliveries',
        'edl_lists',
        'threat_feeds',
        'approval_requests',
        'notification_settings'
    ];
    t TEXT;
BEGIN
    FOREACH t IN ARRAY tables
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = t) THEN
            PERFORM enable_tenant_rls(t);
            RAISE NOTICE 'Enabled RLS on %', t;
        END IF;
    END LOOP;
END $$;

-- =============================================================================
-- 6. USAGE TRACKING TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS usage_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    quantity INTEGER NOT NULL DEFAULT 1,
    metadata JSONB,
    recorded_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_usage_events_tenant_type
    ON usage_events(tenant_id, event_type, recorded_at);
CREATE INDEX IF NOT EXISTS idx_usage_events_recorded
    ON usage_events(recorded_at);

-- =============================================================================
-- 7. TENANT AUDIT LOG
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenant_audit_log (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    actor_id UUID,
    actor_type VARCHAR(20) NOT NULL,  -- 'user', 'api_key', 'system', 'platform_admin'
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenant_audit_tenant ON tenant_audit_log(tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_tenant_audit_action ON tenant_audit_log(action, created_at);

-- =============================================================================
-- 8. UPDATE USERS TABLE FOR MULTI-TENANCY
-- =============================================================================

-- Add tenant-specific role (admin within their tenant)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'tenant_role'
    ) THEN
        ALTER TABLE users ADD COLUMN tenant_role VARCHAR(20) DEFAULT 'analyst';
    END IF;
END $$;

-- =============================================================================
-- 9. HELPER VIEWS
-- =============================================================================

-- View for tenant usage summary
CREATE OR REPLACE VIEW tenant_usage_summary AS
SELECT
    t.id AS tenant_id,
    t.slug,
    t.name,
    t.plan,
    t.status,
    (SELECT COUNT(*) FROM alerts a WHERE a.tenant_id = t.id) AS alert_count,
    (SELECT COUNT(*) FROM playbooks p WHERE p.tenant_id = t.id) AS playbook_count,
    (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id) AS user_count,
    (SELECT COUNT(*) FROM integration_instances i WHERE i.tenant_id = t.id AND i.enabled = true) AS integration_count,
    t.created_at
FROM tenants t;

-- =============================================================================
-- 10. CLEANUP
-- =============================================================================

DROP FUNCTION IF EXISTS add_tenant_id_column(TEXT);
-- Keep enable_tenant_rls for future use

-- =============================================================================
-- VERIFICATION QUERIES (run manually to verify migration)
-- =============================================================================

-- Check all tables have tenant_id
-- SELECT table_name, column_name
-- FROM information_schema.columns
-- WHERE column_name = 'tenant_id'
-- ORDER BY table_name;

-- Check RLS is enabled
-- SELECT tablename, rowsecurity
-- FROM pg_tables
-- WHERE schemaname = 'public' AND rowsecurity = true;

-- Verify policies exist
-- SELECT tablename, policyname, cmd, qual
-- FROM pg_policies
-- WHERE schemaname = 'public';

COMMIT;
