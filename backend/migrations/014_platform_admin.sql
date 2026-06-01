-- Migration: Platform Admin Support
-- Copyright (c) 2024-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
--
-- Adds platform-level administration for T1 Agentics master tenant.
-- Run with: psql -d agentcore -f 004_platform_admin.sql

BEGIN;

-- =============================================================================
-- 1. CREATE T1 AGENTICS MASTER TENANT
-- =============================================================================

-- Insert T1 Agentics as the platform owner tenant
INSERT INTO tenants (id, slug, name, plan, status, settings)
VALUES (
    '00000000-0000-0000-0000-000000000000',
    't1-agentics',
    'T1 Agentics',
    'enterprise',
    'active',
    '{"is_platform_owner": true}'::jsonb
) ON CONFLICT (slug) DO UPDATE SET
    settings = tenants.settings || '{"is_platform_owner": true}'::jsonb;

-- =============================================================================
-- 2. PLATFORM ADMINS TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS platform_admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,

    -- Permissions
    permissions JSONB DEFAULT '["read", "write", "manage_tenants", "manage_licenses"]',

    -- Status
    is_active BOOLEAN DEFAULT true,
    last_login_at TIMESTAMP WITH TIME ZONE,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by UUID
);

CREATE INDEX IF NOT EXISTS idx_platform_admins_email ON platform_admins(email);
CREATE INDEX IF NOT EXISTS idx_platform_admins_active ON platform_admins(is_active);

-- =============================================================================
-- 3. TENANT LICENSES TABLE
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenant_licenses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- License Details
    license_key VARCHAR(64) NOT NULL UNIQUE,
    tier VARCHAR(50) NOT NULL DEFAULT 'community',

    -- Validity
    issued_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,

    -- Custom Limits (override tier defaults)
    custom_limits JSONB,

    -- Billing
    stripe_subscription_id VARCHAR(255),
    billing_cycle VARCHAR(20), -- 'monthly', 'yearly'

    -- Audit
    issued_by UUID REFERENCES platform_admins(id),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by UUID REFERENCES platform_admins(id),
    revoke_reason TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT valid_tier CHECK (tier IN ('community', 'professional', 'enterprise', 'trial'))
);

CREATE INDEX IF NOT EXISTS idx_tenant_licenses_tenant ON tenant_licenses(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_licenses_key ON tenant_licenses(license_key);
CREATE INDEX IF NOT EXISTS idx_tenant_licenses_active ON tenant_licenses(is_active, expires_at);

-- =============================================================================
-- 4. PLATFORM AUDIT LOG
-- =============================================================================

CREATE TABLE IF NOT EXISTS platform_audit_log (
    id BIGSERIAL PRIMARY KEY,
    admin_id UUID REFERENCES platform_admins(id),
    action VARCHAR(100) NOT NULL,
    target_type VARCHAR(50), -- 'tenant', 'license', 'platform_admin'
    target_id UUID,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_platform_audit_admin ON platform_audit_log(admin_id, created_at);
CREATE INDEX IF NOT EXISTS idx_platform_audit_action ON platform_audit_log(action, created_at);
CREATE INDEX IF NOT EXISTS idx_platform_audit_target ON platform_audit_log(target_type, target_id);

-- =============================================================================
-- 5. TENANT USAGE SNAPSHOTS (for billing/reporting)
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenant_usage_snapshots (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    snapshot_date DATE NOT NULL,

    -- Usage Metrics
    alerts_count INTEGER DEFAULT 0,
    investigations_count INTEGER DEFAULT 0,
    playbooks_count INTEGER DEFAULT 0,
    playbook_executions_count INTEGER DEFAULT 0,
    users_count INTEGER DEFAULT 0,
    integrations_count INTEGER DEFAULT 0,
    ai_queries_count INTEGER DEFAULT 0,
    storage_bytes BIGINT DEFAULT 0,

    -- Computed
    alerts_today INTEGER DEFAULT 0,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE(tenant_id, snapshot_date)
);

CREATE INDEX IF NOT EXISTS idx_usage_snapshots_tenant_date ON tenant_usage_snapshots(tenant_id, snapshot_date);

-- =============================================================================
-- 6. UPDATE TENANTS TABLE FOR LICENSE TRACKING
-- =============================================================================

-- Add license reference to tenants
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tenants' AND column_name = 'active_license_id'
    ) THEN
        ALTER TABLE tenants ADD COLUMN active_license_id UUID REFERENCES tenant_licenses(id);
    END IF;
END $$;

-- =============================================================================
-- 7. HELPER FUNCTIONS
-- =============================================================================

-- Function to check if current session is platform admin
CREATE OR REPLACE FUNCTION is_platform_admin() RETURNS BOOLEAN AS $$
BEGIN
    RETURN COALESCE(current_setting('app.is_platform_admin', true), 'false')::boolean;
END;
$$ LANGUAGE plpgsql STABLE;

-- Function to get tenant's current license tier
CREATE OR REPLACE FUNCTION get_tenant_license_tier(p_tenant_id UUID) RETURNS VARCHAR AS $$
DECLARE
    v_tier VARCHAR;
BEGIN
    SELECT tl.tier INTO v_tier
    FROM tenant_licenses tl
    WHERE tl.tenant_id = p_tenant_id
      AND tl.is_active = true
      AND (tl.expires_at IS NULL OR tl.expires_at > NOW())
    ORDER BY tl.created_at DESC
    LIMIT 1;

    RETURN COALESCE(v_tier, 'community');
END;
$$ LANGUAGE plpgsql STABLE;

-- =============================================================================
-- 8. PLATFORM ADMIN VIEWS
-- =============================================================================

-- Comprehensive tenant overview for platform admins
CREATE OR REPLACE VIEW platform_tenant_overview AS
SELECT
    t.id AS tenant_id,
    t.slug,
    t.name,
    t.plan,
    t.status,
    t.created_at,
    t.settings->>'is_platform_owner' AS is_platform_owner,

    -- License Info
    tl.license_key,
    tl.tier AS license_tier,
    tl.expires_at AS license_expires,
    tl.is_active AS license_active,

    -- Usage Counts (latest snapshot or live)
    COALESCE(us.alerts_count, (SELECT COUNT(*) FROM alerts a WHERE a.tenant_id = t.id)) AS alerts_count,
    COALESCE(us.users_count, (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id)) AS users_count,
    COALESCE(us.playbooks_count, (SELECT COUNT(*) FROM playbooks p WHERE p.tenant_id = t.id)) AS playbooks_count,

    -- Limits
    t.alerts_per_day_limit,
    t.users_limit,
    t.playbooks_limit
FROM tenants t
LEFT JOIN tenant_licenses tl ON tl.id = t.active_license_id
LEFT JOIN LATERAL (
    SELECT * FROM tenant_usage_snapshots
    WHERE tenant_id = t.id
    ORDER BY snapshot_date DESC
    LIMIT 1
) us ON true;

COMMIT;
