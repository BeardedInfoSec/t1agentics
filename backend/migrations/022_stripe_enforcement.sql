-- Copyright (c) 2024-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
-- Migration 022: Stripe Enforcement Support

-- Fix valid_plan constraint to include enterprise_plus and poc
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS valid_plan;
ALTER TABLE tenants ADD CONSTRAINT valid_plan CHECK (
    plan IN ('community', 'poc', 'professional', 'enterprise', 'enterprise_plus', 'platform')
);

-- Fix valid_tier constraint on tenant_licenses to include enterprise_plus and poc
ALTER TABLE tenant_licenses DROP CONSTRAINT IF EXISTS valid_tier;
ALTER TABLE tenant_licenses ADD CONSTRAINT valid_tier CHECK (
    tier IN ('community', 'poc', 'professional', 'enterprise', 'enterprise_plus', 'platform', 'trial')
);

-- Add stripe_subscription_id to tenants for quick lookup by background sync
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS stripe_subscription_id VARCHAR(255);

-- Add billing_grace_deadline for tracking when past_due tenants lose access
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS billing_grace_deadline TIMESTAMP WITH TIME ZONE;

-- Index for billing sync queries
CREATE INDEX IF NOT EXISTS idx_tenants_billing_status ON tenants(billing_status)
    WHERE billing_status != 'none';
CREATE INDEX IF NOT EXISTS idx_tenants_stripe_sub ON tenants(stripe_subscription_id)
    WHERE stripe_subscription_id IS NOT NULL;
