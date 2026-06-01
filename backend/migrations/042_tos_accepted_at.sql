-- Migration 042: Add tos_accepted_at to users table
-- Records the timestamp when a user agreed to the Terms of Service,
-- Acceptable Use Policy, Privacy Policy, and AI Governance Policy at registration.
-- Required for legal defensibility of acceptance records.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS tos_accepted_at TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN users.tos_accepted_at IS
    'Timestamp when the user accepted the TOS, AUP, Privacy Policy, and AI Governance Policy. NULL for pre-existing accounts created before this migration.';
