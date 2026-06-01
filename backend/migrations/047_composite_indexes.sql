-- ============================================================================
-- Migration 047: Add composite indexes for common query patterns
-- ============================================================================
-- Migration 044 added single-column tenant_id indexes and a few composite
-- indexes. This migration adds additional composite indexes for common
-- dashboard, queue, and API query patterns that filter on tenant_id
-- plus one or more additional columns.
-- ============================================================================
-- Uses CONCURRENTLY to avoid blocking writes during index creation.
-- IF NOT EXISTS makes this idempotent.
-- ============================================================================

-- Investigation queries: filter by state + priority (SecurityQueue sorting)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_investigations_tenant_state_priority
    ON investigations(tenant_id, state, priority);

-- Investigation queries: filter by state + created_at (SecurityQueue time sorting)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_investigations_tenant_state_created
    ON investigations(tenant_id, state, created_at DESC);

-- IOC queries: filter by type (IOC Center, threat intel lookups)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_iocs_tenant_type
    ON iocs(tenant_id, ioc_type);
