-- 075: Link entity_risk rows to the investigation auto-created on threshold breach
--
-- When an entity crosses the configured risk threshold, the entity_risk_service
-- now spawns an investigation grouping its contributing alerts. Storing the
-- investigation_id on the entity_risk row gives us two things:
--   1. Idempotency — if accumulate_risk somehow re-triggers a breach for an
--      entity that already has an investigation, we skip creating a duplicate.
--   2. UI link — the High Risk Entities table can deep-link straight into the
--      investigation, instead of forcing analysts to search for it.

ALTER TABLE entity_risk
    ADD COLUMN IF NOT EXISTS investigation_id TEXT;

CREATE INDEX IF NOT EXISTS idx_entity_risk_investigation
    ON entity_risk(investigation_id) WHERE investigation_id IS NOT NULL;
