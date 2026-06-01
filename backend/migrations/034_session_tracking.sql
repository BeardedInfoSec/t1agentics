-- Migration 034: Session tracking table for multi-device management
-- Enables: listing active sessions, remote logout, session limits per plan

CREATE TABLE IF NOT EXISTS user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Session identity
    jti VARCHAR(64) NOT NULL UNIQUE,  -- JWT token ID (maps to issued token)

    -- Device/client info
    ip_address INET,
    user_agent TEXT,
    device_type VARCHAR(30),  -- 'desktop', 'mobile', 'tablet', 'api'

    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_active_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoke_reason VARCHAR(100),  -- 'logout', 'password_change', 'admin_revoke', 'session_limit'

    -- Status
    is_active BOOLEAN DEFAULT true NOT NULL
);

-- Indexes for common lookups
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id ON user_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_jti ON user_sessions(jti);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(user_id, is_active) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON user_sessions(expires_at) WHERE is_active = true;

-- RLS for tenant isolation
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;

CREATE POLICY session_tenant_isolation ON user_sessions
    USING (tenant_id::text = current_setting('app.current_tenant_id', true));

CREATE POLICY session_platform_admin_bypass ON user_sessions
    USING (current_setting('app.is_platform_admin', true) = 'true');

-- IP-based login rate limiting table
CREATE TABLE IF NOT EXISTS login_attempts_by_ip (
    ip_address INET NOT NULL,
    attempt_count INTEGER DEFAULT 1 NOT NULL,
    first_attempt_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    locked_until TIMESTAMP WITH TIME ZONE,
    PRIMARY KEY (ip_address)
);

CREATE INDEX IF NOT EXISTS idx_login_ip_locked ON login_attempts_by_ip(locked_until)
    WHERE locked_until IS NOT NULL;
