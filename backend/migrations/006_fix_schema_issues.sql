-- Migration: Fix Missing Database Columns
-- Date: 2026-02-03
-- Purpose: Add missing columns that are referenced in the application code

-- 1. Add triage_enrichment_hash to alerts table
-- Stores hash of enrichment data used during triage to detect when re-triage is needed
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'alerts'
        AND column_name = 'triage_enrichment_hash'
    ) THEN
        ALTER TABLE alerts
        ADD COLUMN triage_enrichment_hash VARCHAR(64);

        CREATE INDEX idx_alerts_triage_hash ON alerts(triage_enrichment_hash);

        RAISE NOTICE 'Added triage_enrichment_hash column to alerts table';
    END IF;
END $$;

-- 2. Add triage_status to investigations table
-- Tracks the triage status that triggered this investigation
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'investigations'
        AND column_name = 'triage_status'
    ) THEN
        ALTER TABLE investigations
        ADD COLUMN triage_status VARCHAR(50);

        CREATE INDEX idx_investigations_triage_status ON investigations(triage_status);

        RAISE NOTICE 'Added triage_status column to investigations table';
    END IF;
END $$;

-- 3. Add model_load_time_ms to ai_token_usage table
-- Tracks model loading time for performance monitoring
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'ai_token_usage'
        AND column_name = 'model_load_time_ms'
    ) THEN
        ALTER TABLE ai_token_usage
        ADD COLUMN model_load_time_ms INTEGER;

        COMMENT ON COLUMN ai_token_usage.model_load_time_ms IS 'Model loading time in milliseconds';

        RAISE NOTICE 'Added model_load_time_ms column to ai_token_usage table';
    END IF;
END $$;

-- 4. Verify all columns were added successfully
DO $$
DECLARE
    missing_count INTEGER := 0;
BEGIN
    -- Check triage_enrichment_hash
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'alerts' AND column_name = 'triage_enrichment_hash'
    ) THEN
        missing_count := missing_count + 1;
        RAISE WARNING 'Failed to add triage_enrichment_hash to alerts';
    END IF;

    -- Check triage_status
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'investigations' AND column_name = 'triage_status'
    ) THEN
        missing_count := missing_count + 1;
        RAISE WARNING 'Failed to add triage_status to investigations';
    END IF;

    -- Check model_load_time_ms
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'ai_token_usage' AND column_name = 'model_load_time_ms'
    ) THEN
        missing_count := missing_count + 1;
        RAISE WARNING 'Failed to add model_load_time_ms to ai_token_usage';
    END IF;

    IF missing_count = 0 THEN
        RAISE NOTICE 'Migration completed successfully - all columns added';
    ELSE
        RAISE WARNING 'Migration completed with % missing columns', missing_count;
    END IF;
END $$;
