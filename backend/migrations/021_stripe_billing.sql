-- Copyright (c) 2024-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
-- Migration 021: Stripe Billing Support

-- Add requested_plan to registration_requests (stores the plan user selected at registration)
ALTER TABLE registration_requests
    ADD COLUMN IF NOT EXISTS requested_plan VARCHAR(50) DEFAULT 'community';

-- Add billing_status to tenants for payment state tracking
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS billing_status VARCHAR(30) DEFAULT 'none';

-- Stripe checkout sessions tracking table
-- Links to either tenant_id (upgrade) or registration_request_id (new signup)
CREATE TABLE IF NOT EXISTS stripe_checkout_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stripe_session_id VARCHAR(255) NOT NULL UNIQUE,
    tenant_id UUID REFERENCES tenants(id),
    registration_request_id UUID REFERENCES registration_requests(id),
    tier VARCHAR(50) NOT NULL,
    billing_cycle VARCHAR(20) NOT NULL DEFAULT 'monthly',
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    stripe_customer_id VARCHAR(255),
    stripe_subscription_id VARCHAR(255),
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_checkout_sessions_stripe ON stripe_checkout_sessions(stripe_session_id);
CREATE INDEX IF NOT EXISTS idx_checkout_sessions_tenant ON stripe_checkout_sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_checkout_sessions_reg ON stripe_checkout_sessions(registration_request_id);
