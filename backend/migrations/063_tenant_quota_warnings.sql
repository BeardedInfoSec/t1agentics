-- 063: Track quota-warning notifications so we send each threshold once per period
--
-- Background: claude_service was attaching an 80% quota warning to the
-- *response* of the call that crossed the threshold. By then the tenant
-- has already paid for the call that took them past 80%, and the warning
-- only fires if they happen to look at that response.
--
-- New model: a periodic sweep checks every tenant's MTD usage. When a
-- tenant crosses 80% (warning) or 100% (block) for the first time this
-- billing period, we email the admin and record the notification here.
-- One row per (tenant, period, threshold) prevents alert spam if the
-- tenant hovers around the threshold for the rest of the period.
--
-- Periods are YYYY-MM strings to match the existing usage period
-- semantics in tenant_claude_usage.

CREATE TABLE IF NOT EXISTS tenant_quota_warnings (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id     UUID NOT NULL,
    period        TEXT NOT NULL,       -- "2026-05"
    threshold     TEXT NOT NULL,       -- "warning" (80%) | "block" (100%)
    sent_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (tenant_id, period, threshold)
);

CREATE INDEX IF NOT EXISTS idx_tenant_quota_warnings_tenant
    ON tenant_quota_warnings(tenant_id);
