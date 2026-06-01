-- Migration: 005_canonical_verdicts.sql
-- Purpose: Update disposition/verdict constraints to include all canonical verdicts
-- Reference: backend/models/verdict.py (single source of truth)
--
-- Canonical Verdicts (9 total):
--   Security: MALICIOUS, SUSPICIOUS, BENIGN
--   Disposition: TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_POSITIVE
--   Process: NEEDS_INVESTIGATION, INCONCLUSIVE, UNKNOWN

-- ============================================================================
-- Update investigations table disposition constraint
-- ============================================================================
DO $$
BEGIN
    -- Drop the existing constraint if it exists
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'investigations_disposition_check'
        AND conrelid = 'investigations'::regclass
    ) THEN
        ALTER TABLE investigations DROP CONSTRAINT investigations_disposition_check;
    END IF;

    -- Add the updated constraint with all canonical verdicts
    ALTER TABLE investigations ADD CONSTRAINT investigations_disposition_check
    CHECK (disposition IN (
        'MALICIOUS', 'SUSPICIOUS', 'BENIGN',
        'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN_POSITIVE',
        'NEEDS_INVESTIGATION', 'INCONCLUSIVE', 'UNKNOWN'
    ));

    RAISE NOTICE 'Updated investigations.disposition constraint with canonical verdicts';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not update investigations.disposition constraint: %', SQLERRM;
END $$;

-- ============================================================================
-- Update detection_hits table disposition constraint
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'detection_hits_disposition_check'
        AND conrelid = 'detection_hits'::regclass
    ) THEN
        ALTER TABLE detection_hits DROP CONSTRAINT detection_hits_disposition_check;
    END IF;

    ALTER TABLE detection_hits ADD CONSTRAINT detection_hits_disposition_check
    CHECK (disposition IN (
        'true_positive', 'false_positive', 'benign', 'inconclusive',
        'MALICIOUS', 'SUSPICIOUS', 'BENIGN',
        'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN_POSITIVE',
        'NEEDS_INVESTIGATION', 'INCONCLUSIVE', 'UNKNOWN',
        NULL
    ));

    RAISE NOTICE 'Updated detection_hits.disposition constraint with canonical verdicts';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not update detection_hits.disposition constraint: %', SQLERRM;
END $$;

-- ============================================================================
-- Create index on riggs_feedback for verdict analysis
-- ============================================================================
CREATE INDEX IF NOT EXISTS idx_riggs_feedback_verdict_canonical
ON riggs_feedback(UPPER(riggs_verdict));

-- ============================================================================
-- Add comment documenting canonical verdicts reference
-- ============================================================================
COMMENT ON COLUMN investigations.disposition IS
'Canonical verdicts from models/verdict.py: MALICIOUS, SUSPICIOUS, BENIGN, TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_POSITIVE, NEEDS_INVESTIGATION, INCONCLUSIVE, UNKNOWN';

-- ============================================================================
-- View for verdict consistency check (useful for debugging)
-- ============================================================================
CREATE OR REPLACE VIEW v_verdict_consistency AS
SELECT
    'investigations' as table_name,
    disposition as verdict,
    COUNT(*) as count
FROM investigations
WHERE disposition IS NOT NULL
GROUP BY disposition

UNION ALL

SELECT
    'riggs_feedback' as table_name,
    riggs_verdict as verdict,
    COUNT(*) as count
FROM riggs_feedback
WHERE riggs_verdict IS NOT NULL
GROUP BY riggs_verdict

UNION ALL

SELECT
    'alerts' as table_name,
    ai_verdict as verdict,
    COUNT(*) as count
FROM alerts
WHERE ai_verdict IS NOT NULL
GROUP BY ai_verdict

ORDER BY table_name, verdict;

COMMENT ON VIEW v_verdict_consistency IS
'Diagnostic view to check verdict consistency across tables. All verdicts should match canonical values from models/verdict.py';
