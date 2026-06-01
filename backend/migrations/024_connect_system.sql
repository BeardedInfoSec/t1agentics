-- Migration 024: T1 Connect Integration System
-- Replaces legacy integration_config, integration_state, integration_credentials tables
-- New unified system: connector_definitions, connect_instances, connect_credentials
-- Copyright (c) 2024-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

-- ============================================================================
-- 1. connector_definitions — Connector blueprints (builtin, community, private)
-- ============================================================================
CREATE TABLE IF NOT EXISTS connector_definitions (
    id              VARCHAR(64) NOT NULL,
    tenant_id       UUID,                           -- NULL = builtin/community visible to all, SET = private to that tenant
    source          VARCHAR(20) NOT NULL DEFAULT 'builtin',
    name            VARCHAR(100) NOT NULL,
    vendor          VARCHAR(100),
    category        VARCHAR(50) NOT NULL,           -- threat_intel, siem, edr, ticketing, communication, etc.
    description     TEXT DEFAULT '',
    logo_url        VARCHAR(500),
    auth_type       VARCHAR(30) NOT NULL DEFAULT 'api_key',
    auth_config     JSONB NOT NULL DEFAULT '{}',    -- e.g. {"header_name": "x-apikey", "location": "header"}
    base_url        VARCHAR(500),
    actions         JSONB NOT NULL DEFAULT '[]',    -- array of action objects
    version         VARCHAR(20) DEFAULT '1.0.0',
    enabled         BOOLEAN DEFAULT true,
    deprecated      BOOLEAN DEFAULT false,
    created_by      VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Source must be one of the allowed values
    CONSTRAINT chk_connector_source CHECK (source IN ('builtin', 'community', 'private')),

    -- Private connectors MUST have a tenant_id
    CONSTRAINT chk_private_requires_tenant CHECK (
        source != 'private' OR tenant_id IS NOT NULL
    ),

    -- Builtin/community connectors MUST NOT have a tenant_id
    CONSTRAINT chk_shared_no_tenant CHECK (
        source NOT IN ('builtin', 'community') OR tenant_id IS NULL
    )
);

-- Unique constraint: same id can exist for different tenants (NULL coalesced to sentinel UUID)
CREATE UNIQUE INDEX IF NOT EXISTS idx_connector_defs_id_scope
    ON connector_definitions(id, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));

CREATE INDEX IF NOT EXISTS idx_connector_defs_tenant ON connector_definitions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_connector_defs_source ON connector_definitions(source);
CREATE INDEX IF NOT EXISTS idx_connector_defs_category ON connector_definitions(category);
CREATE INDEX IF NOT EXISTS idx_connector_defs_name ON connector_definitions(name);

-- ============================================================================
-- 2. connect_credentials — Encrypted credential vault (per-tenant)
-- ============================================================================
CREATE TABLE IF NOT EXISTS connect_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    name                VARCHAR(100) NOT NULL,
    auth_type           VARCHAR(30) NOT NULL,       -- api_key, bearer, basic, oauth2_client, oauth2_token, aws, custom_header
    encrypted_data      TEXT NOT NULL,               -- Fernet-encrypted JSON blob
    metadata            JSONB NOT NULL DEFAULT '{}', -- non-secret config like header_name, api_key_location
    linked_instance_id  UUID,                        -- FK to connect_instances.id (set after instance creation)
    tags                TEXT[] DEFAULT '{}',
    created_by          VARCHAR(100),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at        TIMESTAMPTZ,

    UNIQUE(tenant_id, name)
);

CREATE INDEX IF NOT EXISTS idx_connect_creds_tenant ON connect_credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_connect_creds_auth_type ON connect_credentials(auth_type);
CREATE INDEX IF NOT EXISTS idx_connect_creds_linked_instance ON connect_credentials(linked_instance_id);

-- ============================================================================
-- 3. connect_instances — Per-tenant installed connectors
-- ============================================================================
CREATE TABLE IF NOT EXISTS connect_instances (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    connector_id        VARCHAR(64) NOT NULL,       -- references connector_definitions.id
    credential_id       UUID REFERENCES connect_credentials(id) ON DELETE SET NULL,
    display_name        VARCHAR(100),               -- user's custom label, defaults to connector name
    config              JSONB NOT NULL DEFAULT '{}', -- base_url override, custom settings
    enabled             BOOLEAN NOT NULL DEFAULT false,
    health_status       VARCHAR(20) NOT NULL DEFAULT 'unknown',
    health_checked      TIMESTAMPTZ,
    total_requests      INTEGER NOT NULL DEFAULT 0,
    success_requests    INTEGER NOT NULL DEFAULT 0,
    failed_requests     INTEGER NOT NULL DEFAULT 0,
    created_by          VARCHAR(100),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, connector_id),

    CONSTRAINT chk_health_status CHECK (
        health_status IN ('healthy', 'degraded', 'down', 'unknown')
    )
);

CREATE INDEX IF NOT EXISTS idx_connect_inst_tenant ON connect_instances(tenant_id);
CREATE INDEX IF NOT EXISTS idx_connect_inst_connector ON connect_instances(connector_id);
CREATE INDEX IF NOT EXISTS idx_connect_inst_enabled ON connect_instances(enabled);
CREATE INDEX IF NOT EXISTS idx_connect_inst_health ON connect_instances(health_status);

-- Now that connect_instances exists, add the FK from connect_credentials.linked_instance_id
ALTER TABLE connect_credentials
    DROP CONSTRAINT IF EXISTS fk_connect_creds_linked_instance;
ALTER TABLE connect_credentials
    ADD CONSTRAINT fk_connect_creds_linked_instance
    FOREIGN KEY (linked_instance_id) REFERENCES connect_instances(id) ON DELETE SET NULL;

-- ============================================================================
-- 4. connect_execution_log — Audit trail for all API calls through Connect
-- ============================================================================
CREATE TABLE IF NOT EXISTS connect_execution_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    instance_id     UUID NOT NULL,
    connector_id    VARCHAR(64) NOT NULL,
    action_id       VARCHAR(64),
    success         BOOLEAN,
    status_code     INTEGER,
    duration_ms     INTEGER,
    error_message   TEXT,
    executed_by     VARCHAR(100),
    executed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_connect_exec_tenant_time ON connect_execution_log(tenant_id, executed_at DESC);
CREATE INDEX IF NOT EXISTS idx_connect_exec_instance ON connect_execution_log(instance_id);
CREATE INDEX IF NOT EXISTS idx_connect_exec_connector ON connect_execution_log(connector_id);

-- ============================================================================
-- 5. connector_submissions — Community submission review queue
-- ============================================================================
CREATE TABLE IF NOT EXISTS connector_submissions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    connector_id    VARCHAR(64) NOT NULL,           -- the private connector being submitted
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
    submitted_by    VARCHAR(100),
    submitted_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_by     VARCHAR(100),
    reviewed_at     TIMESTAMPTZ,
    review_notes    TEXT,

    CONSTRAINT chk_submission_status CHECK (
        status IN ('pending', 'approved', 'rejected')
    )
);

CREATE INDEX IF NOT EXISTS idx_connector_subs_status ON connector_submissions(status);
CREATE INDEX IF NOT EXISTS idx_connector_subs_tenant ON connector_submissions(tenant_id);

-- Legacy tables (integration_state, integration_credentials, integrations) will be dropped in a future migration after data is migrated
