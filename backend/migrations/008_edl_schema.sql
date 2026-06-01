-- ============================================================================
-- EDL (External Dynamic List) Schema
-- Production-ready EDL system for SOC platform
-- Supports type-restricted lists (IP, domain, URL) consumed by firewalls
-- ============================================================================

-- Enable UUID generation if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- EDL LISTS - List definitions with type restrictions
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_lists') THEN
        CREATE TABLE edl_lists (
            list_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

            -- Identity
            name VARCHAR(200) NOT NULL,
            slug VARCHAR(200) NOT NULL UNIQUE,
            description TEXT,

            -- Type (strictly enforced - no mixed)
            ioc_type VARCHAR(20) NOT NULL,

            -- List behavior
            list_type VARCHAR(20) NOT NULL DEFAULT 'static',
            refresh_interval_seconds INT DEFAULT 300,

            -- Limits
            max_items INT DEFAULT 150000,
            ttl_default_seconds INT DEFAULT 86400,

            -- Delivery
            include_comments BOOLEAN DEFAULT TRUE,

            -- State
            enabled BOOLEAN DEFAULT TRUE,
            item_count INT DEFAULT 0,
            last_generated_at TIMESTAMP WITH TIME ZONE,
            content_hash VARCHAR(64),

            -- Ownership
            tenant_id VARCHAR(100) DEFAULT 'default',
            created_by VARCHAR(100),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

            CONSTRAINT edl_valid_ioc_type CHECK (ioc_type IN ('ip', 'domain', 'url')),
            CONSTRAINT edl_valid_list_type CHECK (list_type IN ('static', 'dynamic', 'hybrid')),
            CONSTRAINT edl_max_items_positive CHECK (max_items > 0 AND max_items <= 1000000),
            CONSTRAINT edl_unique_name_tenant UNIQUE (name, tenant_id)
        );

        CREATE INDEX idx_edl_lists_slug ON edl_lists(slug);
        CREATE INDEX idx_edl_lists_enabled ON edl_lists(enabled) WHERE enabled = TRUE;
        CREATE INDEX idx_edl_lists_tenant ON edl_lists(tenant_id);
        CREATE INDEX idx_edl_lists_type ON edl_lists(ioc_type);

        RAISE NOTICE '✓ Created edl_lists table';
    END IF;
END $$;


-- ============================================================================
-- EDL ITEMS - Materialized list entries (one IOC per row)
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_items') THEN
        CREATE TABLE edl_items (
            id BIGSERIAL PRIMARY KEY,
            list_id UUID NOT NULL REFERENCES edl_lists(list_id) ON DELETE CASCADE,

            -- IOC data
            ioc_value VARCHAR(2000) NOT NULL,
            ioc_type VARCHAR(20) NOT NULL,
            ioc_normalized VARCHAR(2000) NOT NULL,

            -- Metadata
            confidence DECIMAL(3,2),
            severity VARCHAR(20),
            source_label VARCHAR(200),
            comment TEXT,

            -- Provenance
            source_type VARCHAR(50) NOT NULL DEFAULT 'manual',
            source_id VARCHAR(200),
            added_by VARCHAR(100),

            -- Expiration
            expires_at TIMESTAMP WITH TIME ZONE,

            -- Audit
            added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

            CONSTRAINT edl_items_valid_ioc_type CHECK (ioc_type IN ('ip', 'domain', 'url')),
            CONSTRAINT edl_items_valid_source CHECK (source_type IN (
                'manual', 'playbook', 'investigation', 'threat_feed', 'api'
            )),
            CONSTRAINT edl_items_unique_per_list UNIQUE (list_id, ioc_normalized)
        );

        CREATE INDEX idx_edl_items_list_active ON edl_items(list_id)
            WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP;
        CREATE INDEX idx_edl_items_expires ON edl_items(expires_at)
            WHERE expires_at IS NOT NULL;
        CREATE INDEX idx_edl_items_source ON edl_items(source_type, source_id);
        CREATE INDEX idx_edl_items_added_by ON edl_items(added_by);

        RAISE NOTICE '✓ Created edl_items table';
    END IF;
END $$;


-- ============================================================================
-- EDL CREDENTIALS - Multi-credential auth per list
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_credentials') THEN
        CREATE TABLE edl_credentials (
            credential_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            list_id UUID NOT NULL REFERENCES edl_lists(list_id) ON DELETE CASCADE,

            -- Auth method
            auth_type VARCHAR(20) NOT NULL,

            -- Token auth (Bearer or X-EDL-Token header)
            token_hash VARCHAR(256),
            token_prefix VARCHAR(20),

            -- Basic auth
            basic_username VARCHAR(100),
            basic_password_hash VARCHAR(256),

            -- IP allowlist
            ip_allowlist JSONB,

            -- Identity
            name VARCHAR(200) NOT NULL,
            description TEXT,
            enabled BOOLEAN DEFAULT TRUE,

            -- Lifecycle
            expires_at TIMESTAMP WITH TIME ZONE,
            last_used_at TIMESTAMP WITH TIME ZONE,
            use_count BIGINT DEFAULT 0,

            -- Audit
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            created_by VARCHAR(100),

            CONSTRAINT edl_cred_valid_auth CHECK (auth_type IN (
                'none', 'token', 'basic', 'ip_allowlist', 'header'
            ))
        );

        CREATE INDEX idx_edl_creds_list ON edl_credentials(list_id);
        CREATE INDEX idx_edl_creds_prefix ON edl_credentials(token_prefix, list_id, enabled);
        CREATE INDEX idx_edl_creds_enabled ON edl_credentials(list_id, enabled) WHERE enabled = TRUE;

        RAISE NOTICE '✓ Created edl_credentials table';
    END IF;
END $$;


-- ============================================================================
-- EDL ACCESS LOG - Request audit trail
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_access_log') THEN
        CREATE TABLE edl_access_log (
            id BIGSERIAL PRIMARY KEY,
            list_id UUID NOT NULL REFERENCES edl_lists(list_id) ON DELETE CASCADE,
            credential_id UUID REFERENCES edl_credentials(credential_id) ON DELETE SET NULL,

            -- Request
            client_ip VARCHAR(45) NOT NULL,
            user_agent TEXT,
            request_path VARCHAR(500),

            -- Response
            status_code INT,
            items_returned INT,
            response_time_ms INT,
            cache_hit BOOLEAN DEFAULT FALSE,

            -- Auth
            auth_method VARCHAR(20),
            auth_success BOOLEAN DEFAULT TRUE,

            accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX idx_edl_access_list_time ON edl_access_log(list_id, accessed_at DESC);
        CREATE INDEX idx_edl_access_ip ON edl_access_log(client_ip, accessed_at DESC);
        CREATE INDEX idx_edl_access_failed ON edl_access_log(auth_success)
            WHERE auth_success = FALSE;

        RAISE NOTICE '✓ Created edl_access_log table';
    END IF;
END $$;


-- ============================================================================
-- EDL CHANGE LOG - Track add/remove operations for audit
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_change_log') THEN
        CREATE TABLE edl_change_log (
            id BIGSERIAL PRIMARY KEY,
            list_id UUID NOT NULL REFERENCES edl_lists(list_id) ON DELETE CASCADE,

            -- What changed
            operation VARCHAR(20) NOT NULL,
            ioc_value VARCHAR(2000) NOT NULL,
            ioc_type VARCHAR(20) NOT NULL,

            -- Who/how
            changed_by VARCHAR(100),
            source_type VARCHAR(50),
            source_id VARCHAR(200),
            reason TEXT,

            -- Approval tracking
            approval_required BOOLEAN DEFAULT FALSE,
            approval_id VARCHAR(200),
            approved_by VARCHAR(100),

            changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,

            CONSTRAINT edl_change_valid_op CHECK (operation IN ('add', 'remove', 'expire', 'bulk_add', 'bulk_remove'))
        );

        CREATE INDEX idx_edl_changelog_list ON edl_change_log(list_id, changed_at DESC);
        CREATE INDEX idx_edl_changelog_source ON edl_change_log(source_type, source_id);

        RAISE NOTICE '✓ Created edl_change_log table';
    END IF;
END $$;


-- ============================================================================
-- EDL CONTENT CACHE - Pre-generated list content for fast delivery
-- ============================================================================
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_content_cache') THEN
        CREATE TABLE edl_content_cache (
            list_id UUID PRIMARY KEY REFERENCES edl_lists(list_id) ON DELETE CASCADE,

            -- Cached content
            content_text TEXT,
            content_json JSONB,

            -- Cache metadata
            item_count INT DEFAULT 0,
            content_hash VARCHAR(64),
            generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP WITH TIME ZONE
        );

        RAISE NOTICE '✓ Created edl_content_cache table';
    END IF;
END $$;


-- ============================================================================
-- VERIFICATION
-- ============================================================================
DO $$
DECLARE
    missing_count INTEGER := 0;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_lists') THEN
        missing_count := missing_count + 1;
        RAISE WARNING '✗ Missing table: edl_lists';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_items') THEN
        missing_count := missing_count + 1;
        RAISE WARNING '✗ Missing table: edl_items';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_credentials') THEN
        missing_count := missing_count + 1;
        RAISE WARNING '✗ Missing table: edl_credentials';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_access_log') THEN
        missing_count := missing_count + 1;
        RAISE WARNING '✗ Missing table: edl_access_log';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_change_log') THEN
        missing_count := missing_count + 1;
        RAISE WARNING '✗ Missing table: edl_change_log';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'edl_content_cache') THEN
        missing_count := missing_count + 1;
        RAISE WARNING '✗ Missing table: edl_content_cache';
    END IF;

    IF missing_count = 0 THEN
        RAISE NOTICE '✓ EDL schema migration completed successfully (6 tables created)';
    ELSE
        RAISE WARNING '✗ EDL migration incomplete: % tables missing', missing_count;
    END IF;
END $$;
