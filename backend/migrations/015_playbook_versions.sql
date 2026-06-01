-- ============================================================================
-- PLAYBOOK VERSION HISTORY MIGRATION
-- Stores revision snapshots for reverting to previous versions
-- Date: 2026-02-05
-- ============================================================================

-- ============================================================================
-- PLAYBOOK VERSIONS TABLE
-- Stores snapshot of canvas_data at each save
-- ============================================================================

CREATE TABLE IF NOT EXISTS playbook_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Links
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    version_number INTEGER NOT NULL,

    -- Snapshot data
    canvas_data JSONB NOT NULL,                 -- Full canvas state at this version
    metadata JSONB DEFAULT '{}',                -- Additional version metadata

    -- Change tracking
    change_summary VARCHAR(500),                -- Brief description of changes

    -- Author
    created_by UUID,
    created_by_email VARCHAR(255),

    -- Timing
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

    UNIQUE(playbook_id, version_number)
);

-- Indexes for efficient lookups
CREATE INDEX IF NOT EXISTS idx_pb_versions_playbook ON playbook_versions(playbook_id);
CREATE INDEX IF NOT EXISTS idx_pb_versions_number ON playbook_versions(playbook_id, version_number DESC);
CREATE INDEX IF NOT EXISTS idx_pb_versions_created ON playbook_versions(created_at DESC);

-- ============================================================================
-- FUNCTION: Auto-create version on playbook update
-- ============================================================================

CREATE OR REPLACE FUNCTION create_playbook_version()
RETURNS TRIGGER AS $$
DECLARE
    next_version INTEGER;
BEGIN
    -- Only create version if canvas_data changed
    IF OLD.canvas_data IS DISTINCT FROM NEW.canvas_data THEN
        -- Get next version number
        SELECT COALESCE(MAX(version_number), 0) + 1 INTO next_version
        FROM playbook_versions
        WHERE playbook_id = OLD.id;

        -- Insert the OLD state as a version (before the update)
        INSERT INTO playbook_versions (
            playbook_id,
            version_number,
            canvas_data,
            metadata,
            change_summary,
            created_at,
            tenant_id
        ) VALUES (
            OLD.id,
            next_version,
            OLD.canvas_data,
            jsonb_build_object(
                'name', OLD.name,
                'description', OLD.description,
                'is_enabled', OLD.is_enabled,
                'node_count', jsonb_array_length(COALESCE(OLD.canvas_data->'nodes', '[]'::jsonb))
            ),
            'Auto-saved before update',
            OLD.updated_at,
            OLD.tenant_id
        );

        -- Update the version column on the playbook
        NEW.version = next_version + 1;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply trigger (before update to capture OLD values)
DROP TRIGGER IF EXISTS playbook_version_trigger ON playbooks;
CREATE TRIGGER playbook_version_trigger
    BEFORE UPDATE ON playbooks
    FOR EACH ROW
    EXECUTE FUNCTION create_playbook_version();

-- ============================================================================
-- MIGRATE EXISTING PLAYBOOKS
-- Create initial version for any existing playbooks
-- ============================================================================

INSERT INTO playbook_versions (playbook_id, version_number, canvas_data, metadata, change_summary, created_at, tenant_id)
SELECT
    id,
    1,
    canvas_data,
    jsonb_build_object(
        'name', name,
        'description', description,
        'is_enabled', is_enabled,
        'node_count', jsonb_array_length(COALESCE(canvas_data->'nodes', '[]'::jsonb))
    ),
    'Initial version (migration)',
    created_at,
    tenant_id
FROM playbooks
WHERE NOT EXISTS (
    SELECT 1 FROM playbook_versions pv WHERE pv.playbook_id = playbooks.id
)
ON CONFLICT (playbook_id, version_number) DO NOTHING;

-- ============================================================================
-- SUCCESS MESSAGE
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Playbook version history migration completed!';
    RAISE NOTICE '  - Created playbook_versions table';
    RAISE NOTICE '  - Added auto-versioning trigger';
    RAISE NOTICE '  - Migrated existing playbooks to v1';
END $$;
