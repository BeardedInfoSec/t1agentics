-- Migration 020: Self-Service Registration & Public Website Support
-- Copyright (c) 2024-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

-- 1. Registration requests table (pending email verification)
CREATE TABLE IF NOT EXISTS registration_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) NOT NULL,
    email_hash VARCHAR(64) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    tenant_name VARCHAR(100) NOT NULL,
    tenant_slug VARCHAR(50) NOT NULL,
    full_name VARCHAR(255),

    -- Verification
    verification_token VARCHAR(128) NOT NULL UNIQUE,
    verification_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    verified_at TIMESTAMP WITH TIME ZONE,

    -- Abuse tracking
    ip_address INET,
    ip_hash VARCHAR(64),
    user_agent TEXT,

    -- Status
    status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'verified', 'provisioned', 'expired', 'rejected')),
    provisioned_tenant_id UUID REFERENCES tenants(id),
    rejection_reason TEXT,

    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reg_requests_token ON registration_requests(verification_token);
CREATE INDEX IF NOT EXISTS idx_reg_requests_email_hash ON registration_requests(email_hash);
CREATE INDEX IF NOT EXISTS idx_reg_requests_ip_hash ON registration_requests(ip_hash);
CREATE INDEX IF NOT EXISTS idx_reg_requests_status ON registration_requests(status);
CREATE INDEX IF NOT EXISTS idx_reg_requests_created ON registration_requests(created_at);
CREATE INDEX IF NOT EXISTS idx_reg_requests_slug ON registration_requests(tenant_slug);

-- 2. POC abuse tracking table
CREATE TABLE IF NOT EXISTS poc_tracking (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_hash VARCHAR(64) NOT NULL,
    ip_hash VARCHAR(64),
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    poc_started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    poc_expires_at TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_poc_tracking_email ON poc_tracking(email_hash);
CREATE INDEX IF NOT EXISTS idx_poc_tracking_ip ON poc_tracking(ip_hash);
CREATE INDEX IF NOT EXISTS idx_poc_tracking_active ON poc_tracking(is_active);

-- 3. Contact submissions table (enterprise inquiries)
CREATE TABLE IF NOT EXISTS contact_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    company VARCHAR(255),
    phone VARCHAR(50),
    message TEXT,
    submission_type VARCHAR(50) NOT NULL DEFAULT 'enterprise_inquiry',
    status VARCHAR(20) DEFAULT 'new'
        CHECK (status IN ('new', 'contacted', 'qualified', 'closed')),
    notes TEXT,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_contact_submissions_status ON contact_submissions(status);
CREATE INDEX IF NOT EXISTS idx_contact_submissions_created ON contact_submissions(created_at);

-- 4. Website analytics events table
CREATE TABLE IF NOT EXISTS website_analytics (
    id BIGSERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    page_path VARCHAR(255),
    referrer VARCHAR(500),
    ip_hash VARCHAR(64),
    user_agent TEXT,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_analytics_event ON website_analytics(event_type, created_at);
CREATE INDEX IF NOT EXISTS idx_analytics_page ON website_analytics(page_path, created_at);

-- 5. Rate limiting table for registration endpoints
CREATE TABLE IF NOT EXISTS registration_rate_limits (
    id BIGSERIAL PRIMARY KEY,
    ip_hash VARCHAR(64) NOT NULL,
    endpoint VARCHAR(100) NOT NULL,
    request_count INTEGER DEFAULT 1,
    window_start TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(ip_hash, endpoint, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_lookup ON registration_rate_limits(ip_hash, endpoint, window_start);
