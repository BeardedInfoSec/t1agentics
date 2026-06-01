-- Migration 041: Fix enrichment_cache unique constraint to include tenant_id
-- The old constraint (ioc_type, ioc_value, provider) causes cross-tenant collisions.
-- The new constraint (ioc_type, ioc_value, provider, tenant_id) ensures tenant isolation.

-- Drop the old unique index
DROP INDEX IF EXISTS idx_enrichment_cache_unique;

-- Create new unique index that includes tenant_id
CREATE UNIQUE INDEX idx_enrichment_cache_unique
    ON enrichment_cache(ioc_type, ioc_value, provider, tenant_id);
