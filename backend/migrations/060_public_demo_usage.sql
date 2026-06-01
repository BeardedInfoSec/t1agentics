-- Migration: 060_public_demo_usage.sql
-- Public demo usage tracking for the unauthenticated alert-triage tool
-- exposed at /tools/triage. Supports:
--   - Per-IP rate limiting (5/hour, 20/day)
--   - Daily platform-wide spend kill-switch (defense in depth against abuse)
--   - Counters only. No alert payloads, no model outputs, no user-supplied
--     data of any kind is written to this table.
--
-- Why a dedicated table instead of reusing existing rate limiting:
--   - Public endpoint, no tenant_id, so RLS-bound tables don't fit.
--   - We need both per-IP and global daily aggregates for the kill-switch.
--   - Postgres-only; Redis is not deployed on the droplet.

CREATE TABLE IF NOT EXISTS public_demo_usage (
    id BIGSERIAL PRIMARY KEY,
    ip_hash CHAR(64) NOT NULL,           -- SHA-256 of client IP + daily salt
    bucket_day DATE NOT NULL,            -- UTC day (for daily rate limit + spend)
    bucket_hour TIMESTAMPTZ NOT NULL,    -- Truncated to the hour (for hourly rate limit)
    request_count INTEGER NOT NULL DEFAULT 0,
    estimated_cost_usd NUMERIC(10, 6) NOT NULL DEFAULT 0,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    tool_name VARCHAR(50) NOT NULL DEFAULT 'triage',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per (ip, hour, tool) — increments via UPSERT
CREATE UNIQUE INDEX IF NOT EXISTS idx_public_demo_usage_unique
    ON public_demo_usage (ip_hash, bucket_hour, tool_name);

CREATE INDEX IF NOT EXISTS idx_public_demo_usage_day
    ON public_demo_usage (bucket_day, tool_name);

CREATE INDEX IF NOT EXISTS idx_public_demo_usage_ip_day
    ON public_demo_usage (ip_hash, bucket_day, tool_name);

-- Auto-cleanup old rows so this table never grows unbounded.
-- 30-day retention is plenty for forensic analysis if we ever need to
-- investigate an abuse pattern.
COMMENT ON TABLE public_demo_usage IS
    'Per-IP rate limiting + daily spend tracking for unauthenticated public demo tools. '
    'Contains only counters and SHA-256 IP hashes; no user-submitted content. '
    'Rows older than 30 days should be purged by a periodic job.';
