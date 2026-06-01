-- Migration 080: Add "starter" to the valid_plan + valid_tier CHECK constraints
--
-- Backstory: the marketing PricingPage already advertises Starter at $399/mo and
-- registers users with /register?plan=starter, but the backend silently downgrades
-- "starter" to "community" because the registration validator's allowed-set
-- (and the DB CHECK constraints below) never knew about it. A real Stripe
-- product for Starter now exists (prod_UVhFSCCNPApbx2), so we wire the tier
-- in for real: this migration adds the DB row-level acceptance and the
-- companion Python changes add it to the licensing + checkout paths.
--
-- Pattern matches migration 022_stripe_enforcement.sql which set up these
-- same constraints originally.

ALTER TABLE tenants DROP CONSTRAINT IF EXISTS valid_plan;
ALTER TABLE tenants ADD CONSTRAINT valid_plan CHECK (
    plan IN ('community', 'poc', 'starter', 'professional', 'enterprise', 'enterprise_plus', 'platform')
);

ALTER TABLE tenant_licenses DROP CONSTRAINT IF EXISTS valid_tier;
ALTER TABLE tenant_licenses ADD CONSTRAINT valid_tier CHECK (
    tier IN ('community', 'poc', 'starter', 'professional', 'enterprise', 'enterprise_plus', 'platform', 'trial')
);
