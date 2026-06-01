-- ============================================================================
-- Migration 052: Add PRIMARY KEY to connector_definitions
-- ============================================================================
-- Problem: connector_definitions has no PRIMARY KEY. The `id` column (VARCHAR)
-- is NOT unique by itself because the same connector id can exist for multiple
-- tenants (builtin with tenant_id NULL + private with a specific tenant_id).
-- A unique index on (id, COALESCE(tenant_id, sentinel_uuid)) enforces
-- uniqueness, but PK constraints cannot use expressions.
--
-- Fix: Add a surrogate `row_id` UUID column as the PRIMARY KEY.
-- This gives the table a proper PK for ORM tooling, pg_dump, replication,
-- and any future FK references, without altering existing query patterns.
--
-- Idempotent: checks for existing PK and column before making changes.
-- ============================================================================

DO $$ BEGIN
  -- Only proceed if the table has no primary key yet
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'connector_definitions'::regclass
      AND contype = 'p'
  ) THEN

    -- Add the surrogate column if it doesn't already exist
    IF NOT EXISTS (
      SELECT 1 FROM information_schema.columns
      WHERE table_name = 'connector_definitions'
        AND column_name = 'row_id'
    ) THEN
      ALTER TABLE connector_definitions
        ADD COLUMN row_id UUID NOT NULL DEFAULT gen_random_uuid();
    END IF;

    -- Add the primary key constraint
    ALTER TABLE connector_definitions
      ADD CONSTRAINT connector_definitions_pkey PRIMARY KEY (row_id);

  END IF;
END $$;
