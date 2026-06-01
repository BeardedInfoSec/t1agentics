-- 085_connector_setup_docs.sql
-- Add per-connector setup instructions + external docs URL so the
-- Connect setup wizard can render vendor-specific guidance instead of
-- a generic auth_type blurb. Backing both as nullable so existing
-- connector_definitions rows stay valid until the catalog re-loader
-- backfills them.

ALTER TABLE connector_definitions
    ADD COLUMN IF NOT EXISTS documentation_url VARCHAR(500);

ALTER TABLE connector_definitions
    ADD COLUMN IF NOT EXISTS setup_instructions TEXT;
