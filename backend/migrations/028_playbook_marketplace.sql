-- ============================================================================
-- PLAYBOOK MARKETPLACE MIGRATION
-- Adds marketplace columns to playbook_templates for browse/install/filter
-- Date: 2026-02-14
-- ============================================================================

-- Add marketplace-specific columns to playbook_templates
ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    required_integrations JSONB DEFAULT '[]'::jsonb;

ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    difficulty VARCHAR(20) DEFAULT 'intermediate';

ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    estimated_time VARCHAR(50);

ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    author VARCHAR(100) DEFAULT 'T1 Agentics';

ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    subcategory VARCHAR(100);

ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    severity_filter TEXT[] DEFAULT '{}';

ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    version VARCHAR(20) DEFAULT '1.0.0';

ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    install_count INTEGER DEFAULT 0;

ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    slug VARCHAR(200);

-- Tenant_id for marketplace templates: NULL = global (visible to all tenants)
ALTER TABLE playbook_templates ADD COLUMN IF NOT EXISTS
    tenant_id UUID REFERENCES tenants(id);

-- Indexes for marketplace queries
CREATE INDEX IF NOT EXISTS idx_pb_tmpl_difficulty ON playbook_templates(difficulty);
CREATE INDEX IF NOT EXISTS idx_pb_tmpl_required_integrations ON playbook_templates USING GIN (required_integrations);
CREATE INDEX IF NOT EXISTS idx_pb_tmpl_subcategory ON playbook_templates(subcategory);
CREATE INDEX IF NOT EXISTS idx_pb_tmpl_slug ON playbook_templates(slug);
CREATE INDEX IF NOT EXISTS idx_pb_tmpl_install_count ON playbook_templates(install_count DESC);
CREATE INDEX IF NOT EXISTS idx_pb_tmpl_tenant_id ON playbook_templates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_pb_tmpl_severity ON playbook_templates USING GIN (severity_filter);

-- Add unique constraint on slug for upsert support
-- (only for global templates where tenant_id IS NULL)
CREATE UNIQUE INDEX IF NOT EXISTS idx_pb_tmpl_slug_unique
    ON playbook_templates(slug) WHERE tenant_id IS NULL;

-- ============================================================================
-- SUCCESS MESSAGE
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Playbook marketplace migration completed!';
    RAISE NOTICE '  - Added required_integrations, difficulty, estimated_time columns';
    RAISE NOTICE '  - Added author, subcategory, version, install_count, slug columns';
    RAISE NOTICE '  - Added tenant_id for scoped templates';
    RAISE NOTICE '  - Created marketplace indexes';
END $$;
