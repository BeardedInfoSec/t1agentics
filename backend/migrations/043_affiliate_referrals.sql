-- Migration 043: Affiliate Referral Program
-- Creates affiliate_codes and referrals tables.
-- Adds referral_code to registration_requests.
-- Adds discount tracking columns to tenants.

-- One referral code per tenant, auto-generated on first request
CREATE TABLE IF NOT EXISTS affiliate_codes (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code                VARCHAR(10) NOT NULL UNIQUE,  -- e.g. "T1-ABC123"
    is_active           BOOLEAN NOT NULL DEFAULT true,
    total_referrals     INT NOT NULL DEFAULT 0,
    total_conversions   INT NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_affiliate_codes_tenant ON affiliate_codes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_affiliate_codes_code   ON affiliate_codes(code);

-- One row per use of a referral code
CREATE TABLE IF NOT EXISTS referrals (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    referral_code       VARCHAR(10) NOT NULL,
    referrer_tenant_id  UUID NOT NULL REFERENCES tenants(id),
    referred_email      TEXT,
    referred_tenant_id  UUID REFERENCES tenants(id),   -- populated after tenant provisioning
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    -- pending:   signed up but has not yet paid
    -- converted: first invoice paid; discounts applied
    -- expired:   never converted to paid
    created_at          TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    converted_at        TIMESTAMPTZ,
    CONSTRAINT referrals_status_check CHECK (status IN ('pending', 'converted', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_referrals_code              ON referrals(referral_code);
CREATE INDEX IF NOT EXISTS idx_referrals_referrer          ON referrals(referrer_tenant_id);
CREATE INDEX IF NOT EXISTS idx_referrals_referred_tenant   ON referrals(referred_tenant_id);

-- Track which registration request came via a referral
ALTER TABLE registration_requests
    ADD COLUMN IF NOT EXISTS referral_code VARCHAR(10);

-- Track referrer discount state on the tenant row
-- applied:         Stripe coupon already applied to their subscription
-- pending:         Referral converted but referrer has no subscription yet; apply at next upgrade
-- pending_expires: Banked discount expires 6 months after the referral converted
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS referrer_discount_applied         BOOLEAN     DEFAULT false,
    ADD COLUMN IF NOT EXISTS referrer_discount_expires_at      TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS referrer_discount_pending         BOOLEAN     DEFAULT false,
    ADD COLUMN IF NOT EXISTS referrer_discount_pending_expires_at TIMESTAMPTZ;
