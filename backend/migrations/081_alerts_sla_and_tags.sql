-- 081_alerts_sla_and_tags.sql
-- Provisions the two columns the VPE "utility" block's set_sla / add_tag /
-- remove_tag operations write to. Without these the dispatcher returns a
-- "not yet supported" error.

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS sla_minutes INTEGER;

ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

-- GIN index so tag membership and array overlap queries stay cheap as the
-- alerts table grows.
CREATE INDEX IF NOT EXISTS idx_alerts_tags ON alerts USING GIN (tags);
