-- Migration: Add Missing Tables for Approval Workflow and Riggs Decisions
-- Date: 2026-02-04
-- Purpose: Create approval_requests and riggs_decisions tables that are referenced in code but missing from schema

-- ===========================================================================
-- TABLE: approval_requests
-- ===========================================================================
-- Stores approval requests for response actions requiring human approval
-- Referenced in: backend/agents/riggs_playbook.py line 1268

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = 'approval_requests'
    ) THEN
        CREATE TABLE approval_requests (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
            action_type VARCHAR(50) NOT NULL,
            action_details JSONB DEFAULT '{}'::jsonb,
            requested_by VARCHAR(100) NOT NULL,
            requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
            approved_by VARCHAR(100),
            approved_at TIMESTAMP WITH TIME ZONE,
            denial_reason TEXT,
            expires_at TIMESTAMP WITH TIME ZONE,
            priority VARCHAR(10) DEFAULT 'P3' CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
            risk_level VARCHAR(20) DEFAULT 'medium' CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );

        -- Indexes for performance
        CREATE INDEX idx_approval_requests_investigation_id ON approval_requests(investigation_id);
        CREATE INDEX idx_approval_requests_status ON approval_requests(status);
        CREATE INDEX idx_approval_requests_requested_by ON approval_requests(requested_by);
        CREATE INDEX idx_approval_requests_created_at ON approval_requests(created_at DESC);
        CREATE INDEX idx_approval_requests_expires_at ON approval_requests(expires_at) WHERE status = 'pending';

        RAISE NOTICE 'Created approval_requests table';
    ELSE
        RAISE NOTICE 'approval_requests table already exists';
    END IF;
END $$;

-- ===========================================================================
-- TABLE: riggs_decisions
-- ===========================================================================
-- Stores Riggs AI agent decisions for investigations
-- Referenced in: backend/agents/riggs_playbook.py line 1287

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public'
        AND table_name = 'riggs_decisions'
    ) THEN
        CREATE TABLE riggs_decisions (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
            decision_type VARCHAR(50) NOT NULL,
            decision_value VARCHAR(100),
            reasoning TEXT,
            confidence DECIMAL(5,2) CHECK (confidence >= 0 AND confidence <= 100),
            evidence JSONB DEFAULT '{}'::jsonb,
            recommendations JSONB DEFAULT '[]'::jsonb,
            model_used VARCHAR(100),
            tokens_used INTEGER,
            processing_time_ms INTEGER,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            created_by VARCHAR(100) DEFAULT 'riggs_agent'
        );

        -- Indexes for performance
        CREATE INDEX idx_riggs_decisions_investigation_id ON riggs_decisions(investigation_id);
        CREATE INDEX idx_riggs_decisions_decision_type ON riggs_decisions(decision_type);
        CREATE INDEX idx_riggs_decisions_created_at ON riggs_decisions(created_at DESC);
        CREATE INDEX idx_riggs_decisions_confidence ON riggs_decisions(confidence);

        RAISE NOTICE 'Created riggs_decisions table';
    ELSE
        RAISE NOTICE 'riggs_decisions table already exists';
    END IF;
END $$;

-- ===========================================================================
-- VERIFICATION
-- ===========================================================================
DO $$
DECLARE
    missing_count INTEGER := 0;
BEGIN
    -- Check approval_requests
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'approval_requests'
    ) THEN
        missing_count := missing_count + 1;
        RAISE WARNING 'Failed to create approval_requests table';
    END IF;

    -- Check riggs_decisions
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'riggs_decisions'
    ) THEN
        missing_count := missing_count + 1;
        RAISE WARNING 'Failed to create riggs_decisions table';
    END IF;

    IF missing_count = 0 THEN
        RAISE NOTICE '✓ Migration 007 completed successfully - all tables created';
    ELSE
        RAISE WARNING '⚠ Migration 007 completed with % missing tables', missing_count;
    END IF;
END $$;
