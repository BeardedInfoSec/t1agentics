-- Migration: Add Correlation Decisions and Investigation Entities Tables
-- Date: 2026-02-14
-- Purpose: Create tables referenced by investigation-details endpoints
--          that are causing 500 errors in production

-- ===========================================================================
-- TABLE: entity_types (lookup table for entity classifications)
-- ===========================================================================
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = 'entity_types'
    ) THEN
        CREATE TABLE entity_types (
            type_code VARCHAR(50) PRIMARY KEY,
            display_name VARCHAR(100) NOT NULL,
            priority INTEGER DEFAULT 100,
            description TEXT
        );

        INSERT INTO entity_types (type_code, display_name, priority, description) VALUES
            ('user', 'User', 1, 'User accounts'),
            ('host', 'Host', 2, 'Computer/server hostname'),
            ('mitre_technique', 'MITRE Technique', 3, 'MITRE ATT&CK technique'),
            ('threat_object', 'Threat Object', 4, 'Generic threat indicator'),
            ('internal_ip', 'Internal IP', 5, 'Internal IP address'),
            ('external_ioc', 'External IOC', 6, 'External indicator of compromise'),
            ('domain', 'Domain', 7, 'Domain name'),
            ('email', 'Email Address', 8, 'Email address'),
            ('file_hash', 'File Hash', 9, 'SHA256/MD5/SHA1 file hash'),
            ('url', 'URL', 10, 'Uniform Resource Locator');

        RAISE NOTICE 'Created entity_types table with seed data';
    ELSE
        RAISE NOTICE 'entity_types table already exists';
    END IF;
END $$;


-- ===========================================================================
-- TABLE: correlation_decisions
-- ===========================================================================
-- Stores the WHY behind each alert-to-investigation correlation
-- Referenced in: routes/investigations.py (alerts endpoint, correlation-history)

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = 'correlation_decisions'
    ) THEN
        CREATE TABLE correlation_decisions (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            tenant_id UUID REFERENCES tenants(id),
            decision_type VARCHAR(50) NOT NULL DEFAULT 'legacy',
            score INTEGER,
            threshold INTEGER,
            reasons JSONB DEFAULT '[]'::jsonb,
            matched_entities JSONB DEFAULT '[]'::jsonb,
            guardrails_applied JSONB DEFAULT '[]'::jsonb,
            processing_time_ms INTEGER,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(alert_id, investigation_id)
        );

        CREATE INDEX idx_correlation_decisions_alert_id ON correlation_decisions(alert_id);
        CREATE INDEX idx_correlation_decisions_investigation_id ON correlation_decisions(investigation_id);
        CREATE INDEX idx_correlation_decisions_tenant_id ON correlation_decisions(tenant_id);
        CREATE INDEX idx_correlation_decisions_decision_type ON correlation_decisions(decision_type);
        CREATE INDEX idx_correlation_decisions_created_at ON correlation_decisions(created_at);

        -- RLS policy for tenant isolation
        ALTER TABLE correlation_decisions ENABLE ROW LEVEL SECURITY;

        CREATE POLICY tenant_isolation ON correlation_decisions
            USING (
                tenant_id::text = COALESCE(
                    current_setting('app.current_tenant_id', true),
                    '00000000-0000-0000-0000-000000000000'
                )
            );

        CREATE POLICY platform_admin_bypass ON correlation_decisions
            USING (
                current_setting('app.is_platform_admin', true) = 'true'
            );

        RAISE NOTICE 'Created correlation_decisions table with RLS';
    ELSE
        RAISE NOTICE 'correlation_decisions table already exists';
    END IF;
END $$;


-- ===========================================================================
-- TABLE: investigation_entities
-- ===========================================================================
-- Stores extracted entities for each investigation (users, hosts, IOCs, etc.)
-- Referenced in: routes/investigations.py (entities endpoint, summary)

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = 'investigation_entities'
    ) THEN
        CREATE TABLE investigation_entities (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
            tenant_id UUID REFERENCES tenants(id),
            entity_type VARCHAR(50) NOT NULL REFERENCES entity_types(type_code),
            entity_value VARCHAR(500) NOT NULL,
            confidence DECIMAL(5,2) DEFAULT 0,
            alert_count INTEGER DEFAULT 0,
            first_seen TIMESTAMP WITH TIME ZONE,
            last_seen TIMESTAMP WITH TIME ZONE,
            metadata JSONB DEFAULT '{}'::jsonb,
            UNIQUE(investigation_id, entity_type, entity_value)
        );

        CREATE INDEX idx_investigation_entities_investigation_id ON investigation_entities(investigation_id);
        CREATE INDEX idx_investigation_entities_tenant_id ON investigation_entities(tenant_id);
        CREATE INDEX idx_investigation_entities_entity_type ON investigation_entities(entity_type);
        CREATE INDEX idx_investigation_entities_confidence ON investigation_entities(confidence DESC);
        CREATE INDEX idx_investigation_entities_alert_count ON investigation_entities(alert_count DESC);

        -- RLS policy for tenant isolation
        ALTER TABLE investigation_entities ENABLE ROW LEVEL SECURITY;

        CREATE POLICY tenant_isolation ON investigation_entities
            USING (
                tenant_id::text = COALESCE(
                    current_setting('app.current_tenant_id', true),
                    '00000000-0000-0000-0000-000000000000'
                )
            );

        CREATE POLICY platform_admin_bypass ON investigation_entities
            USING (
                current_setting('app.is_platform_admin', true) = 'true'
            );

        RAISE NOTICE 'Created investigation_entities table with RLS';
    ELSE
        RAISE NOTICE 'investigation_entities table already exists';
    END IF;
END $$;


-- ===========================================================================
-- ADD MISSING COLUMNS to alerts table
-- ===========================================================================
-- These columns are referenced in investigation-details queries

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS extracted_entities JSONB DEFAULT '{}'::jsonb;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlation_score INTEGER;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlation_decision VARCHAR(50);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS correlation_reasons JSONB DEFAULT '[]'::jsonb;

-- Indexes for the new columns
CREATE INDEX IF NOT EXISTS idx_alerts_extracted_entities ON alerts USING GIN (extracted_entities);
CREATE INDEX IF NOT EXISTS idx_alerts_correlation_score ON alerts(correlation_score);
CREATE INDEX IF NOT EXISTS idx_alerts_correlation_decision ON alerts(correlation_decision);
