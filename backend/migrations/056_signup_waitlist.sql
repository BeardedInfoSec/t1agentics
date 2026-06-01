-- 056_signup_waitlist.sql
-- Adds 'waitlisted' as a valid status for self-service registration_requests so
-- the platform can cap Free-tier signups via MAX_FREE_TENANTS without rejecting
-- the row outright.

ALTER TABLE registration_requests
    DROP CONSTRAINT IF EXISTS registration_requests_status_check;

ALTER TABLE registration_requests
    ADD CONSTRAINT registration_requests_status_check
    CHECK (status IN ('pending', 'verified', 'provisioned', 'expired', 'rejected', 'waitlisted'));

CREATE INDEX IF NOT EXISTS idx_reg_requests_waitlisted
    ON registration_requests(created_at)
    WHERE status = 'waitlisted';
