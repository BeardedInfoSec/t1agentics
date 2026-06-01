-- 062: Persistent Stripe webhook event de-duplication
--
-- Background: routes/billing.py was tracking processed webhook event ids
-- in an in-process OrderedDict capped at 10,000 entries. That works for
-- one steady-state replica but loses every dedup ever recorded on
-- restart, and gets reset on every deploy. Stripe retries failed
-- webhooks aggressively (5xx triggers exponential backoff over 3 days),
-- so a backend restart during inflight retry windows can re-process
-- the same event and double-apply tier changes / payment-failed counts.
--
-- Persistent table; INSERT ON CONFLICT DO NOTHING gates processing.
-- Records the event_type alongside the id for audit + the timestamp
-- so a future cleanup job can prune older-than-30-days entries
-- (Stripe's retry window is 3 days, so 30 days is plenty of buffer).

CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    event_id      TEXT PRIMARY KEY,
    event_type    TEXT NOT NULL,
    processed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_processed_at
    ON stripe_webhook_events(processed_at);
