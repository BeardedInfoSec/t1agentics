-- ============================================================================
-- Migration 050: Create password_reset_tokens table
-- ============================================================================
-- Implements persistent storage for password reset tokens.
-- Previously these functions were stubs that returned hardcoded values.
-- ============================================================================

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          SERIAL PRIMARY KEY,
    token       TEXT NOT NULL UNIQUE,
    username    TEXT NOT NULL,
    email       TEXT NOT NULL,
    expiry      TIMESTAMP NOT NULL,
    used        BOOLEAN DEFAULT FALSE,
    created_at  TIMESTAMP DEFAULT NOW()
);

-- Index for fast token lookups
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_token
    ON password_reset_tokens (token);

-- Index for cleanup of expired tokens
CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expiry
    ON password_reset_tokens (expiry);

-- No RLS on this table - tokens are looked up cross-tenant by the
-- password reset flow (unauthenticated endpoint, uses platform_admin bypass).
