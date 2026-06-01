-- Migration: 008_integration_storage
-- Description: Create tables for integration definitions and instances (declarative framework)
-- Date: 2025-01-XX
--
-- Purpose: Move integration storage from in-memory dicts to PostgreSQL for persistence and scalability

-- ============================================================================
-- INTEGRATION DEFINITIONS TABLE
-- Stores the YAML/JSON integration definitions
-- ============================================================================

CREATE TABLE IF NOT EXISTS integration_definitions (
    -- Primary key
    id VARCHAR(64) PRIMARY KEY,

    -- Version tracking
    version VARCHAR(32) NOT NULL,

    -- Metadata
    name VARCHAR(100) NOT NULL,
    vendor VARCHAR(100),
    category VARCHAR(50) NOT NULL,
    description TEXT,
    icon TEXT,
    documentation_url TEXT,
    tags JSONB DEFAULT '[]'::jsonb,

    -- The full definition as JSONB (for flexible querying)
    definition JSONB NOT NULL,

    -- Source tracking
    source VARCHAR(20) DEFAULT 'custom' CHECK (source IN ('builtin', 'custom', 'marketplace')),
    source_file TEXT,

    -- Status
    enabled BOOLEAN DEFAULT true,
    deprecated BOOLEAN DEFAULT false,
    deprecation_message TEXT,

    -- Audit fields
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100),
    updated_by VARCHAR(100),

    -- Constraints
    CONSTRAINT valid_category CHECK (category IN (
        'threat_intel', 'edr', 'siem', 'soar', 'ticketing',
        'communication', 'cloud_security', 'vulnerability',
        'identity', 'network', 'email_security', 'sandbox',
        'asset_management', 'custom'
    ))
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_integration_definitions_category ON integration_definitions(category);
CREATE INDEX IF NOT EXISTS idx_integration_definitions_enabled ON integration_definitions(enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_integration_definitions_source ON integration_definitions(source);
CREATE INDEX IF NOT EXISTS idx_integration_definitions_tags ON integration_definitions USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_integration_definitions_name_search ON integration_definitions USING GIN(to_tsvector('english', name || ' ' || COALESCE(description, '')));

-- ============================================================================
-- INTEGRATION INSTANCES TABLE
-- Stores per-tenant integration instances with credentials
-- ============================================================================

CREATE TABLE IF NOT EXISTS integration_instances (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Tenant isolation
    tenant_id VARCHAR(100) NOT NULL DEFAULT 'default',

    -- Reference to definition
    definition_id VARCHAR(64) NOT NULL REFERENCES integration_definitions(id) ON DELETE CASCADE,
    definition_version VARCHAR(32) NOT NULL,

    -- Instance metadata
    name VARCHAR(255),
    enabled BOOLEAN DEFAULT true,

    -- Credential reference
    credential_id UUID,

    -- Configuration overrides (merges with definition defaults)
    config_overrides JSONB DEFAULT '{}'::jsonb,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100),
    updated_by VARCHAR(100),

    -- Unique constraint: one instance per definition per tenant
    CONSTRAINT unique_tenant_definition UNIQUE (tenant_id, definition_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_integration_instances_tenant ON integration_instances(tenant_id);
CREATE INDEX IF NOT EXISTS idx_integration_instances_definition ON integration_instances(definition_id);
CREATE INDEX IF NOT EXISTS idx_integration_instances_enabled ON integration_instances(enabled) WHERE enabled = true;

-- ============================================================================
-- INTEGRATION DEFINITION VERSIONS TABLE
-- Stores historical versions of integration definitions
-- ============================================================================

CREATE TABLE IF NOT EXISTS integration_definition_versions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- Reference to main definition
    definition_id VARCHAR(64) NOT NULL REFERENCES integration_definitions(id) ON DELETE CASCADE,

    -- Version info
    version VARCHAR(32) NOT NULL,

    -- The full definition snapshot
    definition JSONB NOT NULL,

    -- Change tracking
    change_summary TEXT,

    -- Audit
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_by VARCHAR(100),

    -- Unique constraint on definition + version
    CONSTRAINT unique_definition_version UNIQUE (definition_id, version)
);

CREATE INDEX IF NOT EXISTS idx_definition_versions_definition ON integration_definition_versions(definition_id);
CREATE INDEX IF NOT EXISTS idx_definition_versions_created ON integration_definition_versions(created_at DESC);
