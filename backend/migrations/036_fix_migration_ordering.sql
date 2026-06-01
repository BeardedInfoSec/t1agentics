-- Migration 036: Fix duplicate migration file prefixes
-- History: Files 001-004 have duplicate numeric prefixes (two files each).
-- Python sorted() alphabetical ordering happens to work, but this is fragile.
-- This migration renames the schema_migrations records to match the new file names.
--
-- File renames (must be done on disk alongside this migration):
--   001_hypothesis_correlation.sql → 011_hypothesis_correlation.sql
--   002_multitenancy.sql           → 012_multitenancy.sql
--   003_tenant_uuid_migration.sql  → 013_tenant_uuid_migration.sql
--   004_platform_admin.sql         → 014_platform_admin.sql
--
-- The "older" files keep their original prefixes:
--   001_riggs_schema.sql           (Jan 7 — stays as 001)
--   002_riggs_review_state.sql     (Jan 7 — stays as 002)
--   003_simplified_states.sql      (Jan 11 — stays as 003)
--   004_playbooks.sql              (Jan 22 — stays as 004)

UPDATE schema_migrations SET filename = '011_hypothesis_correlation.sql'
    WHERE filename = '001_hypothesis_correlation.sql';

UPDATE schema_migrations SET filename = '012_multitenancy.sql'
    WHERE filename = '002_multitenancy.sql';

UPDATE schema_migrations SET filename = '013_tenant_uuid_migration.sql'
    WHERE filename = '003_tenant_uuid_migration.sql';

UPDATE schema_migrations SET filename = '014_platform_admin.sql'
    WHERE filename = '004_platform_admin.sql';
