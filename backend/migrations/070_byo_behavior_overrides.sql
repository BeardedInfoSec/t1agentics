-- 070: BYO-gated behavior overrides
--
-- Two small per-tenant knobs that only make sense for tenants on their
-- own LLM bill (BYO) — they raise cost or output volume, so the platform
-- key path keeps the historical defaults.
--
--   tenant_ai_config.chat_max_tokens   override the max output tokens per
--                                       call. Defaults to None (caller
--                                       picks). Only honored when BYO is
--                                       effective.
--
--   tenant_triage_config.force_all_to_investigation
--                                       when TRUE, no alert auto-closes
--                                       — every triage result opens an
--                                       investigation. Useful for "I want
--                                       to see everything for a week"
--                                       evaluation periods. Equivalent
--                                       to the RIGGS_ALL_ALERTS env var
--                                       but scoped to one tenant.

ALTER TABLE tenant_ai_config
    ADD COLUMN IF NOT EXISTS chat_max_tokens INT
        CHECK (chat_max_tokens IS NULL OR chat_max_tokens BETWEEN 100 AND 16000);

ALTER TABLE tenant_triage_config
    ADD COLUMN IF NOT EXISTS force_all_to_investigation BOOLEAN NOT NULL DEFAULT FALSE;
