-- Migration: Convert tenant IDs to UUIDs
-- Copyright (c) 2024-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0
--
-- This migration:
-- 1. Adds UUID column to tenants table
-- 2. Generates UUIDs for existing tenants
-- 3. Updates all foreign keys
-- 4. Makes UUID the primary identifier
--
-- IMPORTANT: Backup your database before running!
-- Run with: psql -d t1agentics -f 003_tenant_uuid_migration.sql

BEGIN;

-- =============================================================================
-- 1. ENSURE UUID EXTENSION IS AVAILABLE
-- =============================================================================
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- 2. ADD UUID COLUMN IF NOT EXISTS
-- =============================================================================

-- Check if we need to migrate (if id is not already UUID)
DO $$
BEGIN
    -- Add uuid column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'tenants' AND column_name = 'uuid'
    ) THEN
        ALTER TABLE tenants ADD COLUMN uuid UUID DEFAULT gen_random_uuid();

        -- Generate UUIDs for existing rows
        UPDATE tenants SET uuid = gen_random_uuid() WHERE uuid IS NULL;

        -- Make NOT NULL
        ALTER TABLE tenants ALTER COLUMN uuid SET NOT NULL;

        -- Add unique constraint
        ALTER TABLE tenants ADD CONSTRAINT tenants_uuid_unique UNIQUE (uuid);

        RAISE NOTICE 'Added UUID column to tenants table';
    ELSE
        RAISE NOTICE 'UUID column already exists';
    END IF;
END $$;

-- =============================================================================
-- 3. CREATE LOOKUP TABLE FOR OLD ID -> NEW UUID MAPPING
-- =============================================================================

CREATE TEMPORARY TABLE tenant_id_mapping AS
SELECT
    CASE
        WHEN pg_typeof(id)::text = 'uuid' THEN id::text
        ELSE id::text
    END as old_id,
    COALESCE(uuid::text, id::text) as new_uuid
FROM tenants;

-- =============================================================================
-- 4. UPDATE ALL FOREIGN KEY REFERENCES
-- =============================================================================

-- Function to update tenant_id references in a table
CREATE OR REPLACE FUNCTION migrate_tenant_id_to_uuid(table_name TEXT) RETURNS VOID AS $$
DECLARE
    col_type TEXT;
BEGIN
    -- Check if table has tenant_id column
    SELECT data_type INTO col_type
    FROM information_schema.columns
    WHERE table_name = migrate_tenant_id_to_uuid.table_name
      AND column_name = 'tenant_id';

    IF col_type IS NULL THEN
        RAISE NOTICE 'Table % does not have tenant_id column, skipping', table_name;
        RETURN;
    END IF;

    -- If already UUID, skip
    IF col_type = 'uuid' THEN
        RAISE NOTICE 'Table % already has UUID tenant_id, skipping', table_name;
        RETURN;
    END IF;

    -- Add new UUID column
    EXECUTE format('ALTER TABLE %I ADD COLUMN tenant_uuid UUID', table_name);

    -- Copy values using mapping
    EXECUTE format('
        UPDATE %I t
        SET tenant_uuid = m.new_uuid::uuid
        FROM tenant_id_mapping m
        WHERE t.tenant_id::text = m.old_id
    ', table_name);

    -- Drop old column and rename new
    EXECUTE format('ALTER TABLE %I DROP COLUMN tenant_id', table_name);
    EXECUTE format('ALTER TABLE %I RENAME COLUMN tenant_uuid TO tenant_id', table_name);

    -- Add NOT NULL constraint
    EXECUTE format('ALTER TABLE %I ALTER COLUMN tenant_id SET NOT NULL', table_name);

    -- Add foreign key
    BEGIN
        EXECUTE format('
            ALTER TABLE %I
            ADD CONSTRAINT %I_tenant_id_fkey
            FOREIGN KEY (tenant_id) REFERENCES tenants(uuid)
        ', table_name, table_name);
    EXCEPTION WHEN duplicate_object THEN
        RAISE NOTICE 'Foreign key already exists for %', table_name;
    END;

    -- Add index
    EXECUTE format('CREATE INDEX IF NOT EXISTS idx_%I_tenant_id ON %I(tenant_id)', table_name, table_name);

    RAISE NOTICE 'Migrated % to UUID tenant_id', table_name;

EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Error migrating %: %', table_name, SQLERRM;
END;
$$ LANGUAGE plpgsql;

-- Apply to all tables that need tenant_id
DO $$
DECLARE
    tables TEXT[] := ARRAY[
        'alerts',
        'investigations',
        'playbooks',
        'playbook_executions',
        'playbook_node_results',
        'users',
        'integration_instances',
        'credentials',
        'iocs',
        'audit_logs',
        'chat_sessions',
        'chat_messages',
        'attachments',
        'webhooks',
        'edl_lists',
        'threat_feeds',
        'approval_requests',
        'api_keys',
        'usage_events'
    ];
    t TEXT;
BEGIN
    FOREACH t IN ARRAY tables
    LOOP
        IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = t) THEN
            PERFORM migrate_tenant_id_to_uuid(t);
        END IF;
    END LOOP;
END $$;

-- =============================================================================
-- 5. UPDATE TENANTS TABLE PRIMARY KEY
-- =============================================================================

-- If id is not UUID, make uuid the primary key
DO $$
DECLARE
    id_type TEXT;
BEGIN
    SELECT data_type INTO id_type
    FROM information_schema.columns
    WHERE table_name = 'tenants' AND column_name = 'id';

    IF id_type != 'uuid' THEN
        -- Drop old primary key
        ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_pkey;

        -- Rename old id to old_id
        ALTER TABLE tenants RENAME COLUMN id TO legacy_id;

        -- Rename uuid to id
        ALTER TABLE tenants RENAME COLUMN uuid TO id;

        -- Make id the primary key
        ALTER TABLE tenants ADD PRIMARY KEY (id);

        RAISE NOTICE 'Converted tenants primary key to UUID';
    ELSE
        RAISE NOTICE 'Tenants already uses UUID primary key';
    END IF;
END $$;

-- =============================================================================
-- 6. CLEANUP
-- =============================================================================

DROP FUNCTION IF EXISTS migrate_tenant_id_to_uuid(TEXT);

-- =============================================================================
-- 7. VERIFY
-- =============================================================================

-- Show results
DO $$
DECLARE
    tenant_count INTEGER;
    sample_id TEXT;
BEGIN
    SELECT COUNT(*) INTO tenant_count FROM tenants;
    SELECT id::text INTO sample_id FROM tenants LIMIT 1;

    RAISE NOTICE '===========================================';
    RAISE NOTICE 'Migration complete!';
    RAISE NOTICE 'Total tenants: %', tenant_count;
    RAISE NOTICE 'Sample tenant ID: %', sample_id;
    RAISE NOTICE '===========================================';
END $$;

COMMIT;
