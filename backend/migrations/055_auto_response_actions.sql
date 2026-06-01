-- Per-action auto-response settings for connect instances
-- Allows granular control: enable auto-response for enrichment but not blocking, etc.
-- Falls back to connect_instances.auto_response_enabled if no per-action setting exists.

CREATE TABLE IF NOT EXISTS auto_response_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id UUID NOT NULL REFERENCES connect_instances(id) ON DELETE CASCADE,
    action_type VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(instance_id, action_type)
);

CREATE INDEX IF NOT EXISTS idx_auto_response_instance ON auto_response_settings(instance_id);
