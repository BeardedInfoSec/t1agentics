-- Migration 030: Replace placeholder platform owner tenant UUID
-- Old: 00000000-0000-0000-0000-000000000000
-- New: 00000000-0000-0000-0000-000000000001
--
-- This migration dynamically discovers all FK constraints referencing tenants(id),
-- drops them, updates all tenant_id columns, updates the tenants PK, then recreates
-- the FK constraints with their original ON DELETE rules.

BEGIN;

-- Bypass Row-Level Security for this migration
SET app.is_platform_admin = 'true';

DO $$
DECLARE
    old_id UUID := '00000000-0000-0000-0000-000000000000';
    new_id UUID := '00000000-0000-0000-0000-000000000001';
    fk RECORD;
    fk_list JSONB := '[]'::jsonb;
BEGIN
    -- ================================================================
    -- Step 1: Collect all FK constraints pointing at tenants(id)
    -- ================================================================
    FOR fk IN
        SELECT
            tc.constraint_name,
            tc.table_schema,
            tc.table_name,
            kcu.column_name,
            rc.delete_rule
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
        JOIN information_schema.referential_constraints rc
            ON tc.constraint_name = rc.constraint_name
            AND tc.table_schema = rc.constraint_schema
        JOIN information_schema.constraint_column_usage ccu
            ON rc.unique_constraint_name = ccu.constraint_name
        WHERE tc.constraint_type = 'FOREIGN KEY'
          AND ccu.table_name = 'tenants'
          AND ccu.column_name = 'id'
          AND tc.table_schema = 'public'
    LOOP
        -- Save FK info for recreation
        fk_list := fk_list || jsonb_build_object(
            'constraint_name', fk.constraint_name,
            'table_schema',    fk.table_schema,
            'table_name',      fk.table_name,
            'column_name',     fk.column_name,
            'delete_rule',     fk.delete_rule
        );

        -- Drop the FK constraint
        EXECUTE format(
            'ALTER TABLE %I.%I DROP CONSTRAINT %I',
            fk.table_schema, fk.table_name, fk.constraint_name
        );
        RAISE NOTICE 'Dropped FK: %.% (%)', fk.table_name, fk.column_name, fk.constraint_name;
    END LOOP;

    -- ================================================================
    -- Step 2: Update child tables (tenant_id columns)
    -- ================================================================
    FOR fk IN
        SELECT DISTINCT elem->>'table_schema' AS table_schema,
                        elem->>'table_name'   AS table_name,
                        elem->>'column_name'  AS column_name
        FROM jsonb_array_elements(fk_list) AS elem
    LOOP
        EXECUTE format(
            'UPDATE %I.%I SET %I = $1 WHERE %I = $2',
            fk.table_schema, fk.table_name, fk.column_name, fk.column_name
        ) USING new_id, old_id;
        RAISE NOTICE 'Updated %.% rows', fk.table_name, fk.column_name;
    END LOOP;

    -- ================================================================
    -- Step 3: Update the tenants table PK itself
    -- ================================================================
    UPDATE tenants SET id = new_id WHERE id = old_id;
    RAISE NOTICE 'Updated tenants.id from % to %', old_id, new_id;

    -- ================================================================
    -- Step 4: Recreate all FK constraints with original ON DELETE rules
    -- ================================================================
    FOR fk IN
        SELECT elem->>'constraint_name' AS constraint_name,
               elem->>'table_schema'    AS table_schema,
               elem->>'table_name'      AS table_name,
               elem->>'column_name'     AS column_name,
               elem->>'delete_rule'     AS delete_rule
        FROM jsonb_array_elements(fk_list) AS elem
    LOOP
        EXECUTE format(
            'ALTER TABLE %I.%I ADD CONSTRAINT %I FOREIGN KEY (%I) REFERENCES tenants(id) ON DELETE %s',
            fk.table_schema, fk.table_name, fk.constraint_name, fk.column_name,
            CASE fk.delete_rule
                WHEN 'CASCADE'    THEN 'CASCADE'
                WHEN 'SET NULL'   THEN 'SET NULL'
                WHEN 'SET DEFAULT' THEN 'SET DEFAULT'
                WHEN 'RESTRICT'   THEN 'RESTRICT'
                ELSE 'NO ACTION'
            END
        );
        RAISE NOTICE 'Recreated FK: %.% (%)', fk.table_name, fk.column_name, fk.constraint_name;
    END LOOP;
END $$;

COMMIT;
