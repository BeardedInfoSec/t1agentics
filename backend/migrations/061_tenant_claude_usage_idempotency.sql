-- 061: Idempotency for tenant_claude_usage aggregate updates
--
-- Background: _update_monthly_cache UPSERTs into tenant_claude_usage
-- with ON CONFLICT DO UPDATE incrementing the totals. If the same
-- Claude API call's response gets processed twice (manual retry,
-- upstream retry path, deploy-during-inflight, etc.) the same tokens
-- get added to the tenant's monthly aggregate twice. Free-tier hard
-- stops then fire earlier than they should and paid-tier metered
-- overage gets inflated.
--
-- Fix: track each Anthropic message_id we've already counted. Update
-- the aggregate only when we successfully claim a new message_id —
-- duplicate processing of the same response becomes a no-op.

CREATE TABLE IF NOT EXISTS tenant_claude_usage_applied_events (
    message_id    TEXT PRIMARY KEY,
    tenant_id     UUID NOT NULL,
    applied_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tcu_applied_events_tenant
    ON tenant_claude_usage_applied_events(tenant_id);

-- Used by a periodic cleanup to prune old ids. We only need recent
-- ones to de-dupe retries; nothing in product logic queries this for
-- historical reporting (that's what ai_token_usage is for).
CREATE INDEX IF NOT EXISTS idx_tcu_applied_events_applied_at
    ON tenant_claude_usage_applied_events(applied_at);
