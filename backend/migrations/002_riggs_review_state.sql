-- ============================================================================
-- RIGGS_REVIEW STATE MIGRATION
-- Adds RIGGS_REVIEW state to investigation workflow
-- T2 agents now escalate to RIGGS_REVIEW instead of T3/AWAITING_HUMAN
-- ============================================================================

-- Step 1: Drop the existing constraint
ALTER TABLE investigations DROP CONSTRAINT IF EXISTS investigations_state_check;

-- Step 2: Add new constraint with RIGGS_REVIEW state
ALTER TABLE investigations ADD CONSTRAINT investigations_state_check CHECK (state IN (
    'NEW', 'ENRICHING', 'AI_TRIAGE_L1', 'AI_TRIAGE_L2',
    'RIGGS_REVIEW', 'AWAITING_HUMAN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'
));

-- Step 3: Optionally migrate existing AWAITING_HUMAN to RIGGS_REVIEW
-- Uncomment if you want to convert existing cases
-- UPDATE investigations SET state = 'RIGGS_REVIEW' WHERE state = 'AWAITING_HUMAN';

-- Step 4: Add riggs_override column if not exists (for Riggs override analysis)
ALTER TABLE investigations ADD COLUMN IF NOT EXISTS riggs_override JSONB DEFAULT NULL;

-- Step 5: Create index for new state
CREATE INDEX IF NOT EXISTS idx_investigations_riggs_review ON investigations(state) WHERE state = 'RIGGS_REVIEW';

-- ============================================================================
-- Success message
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'RIGGS_REVIEW state migration completed!';
    RAISE NOTICE '  - Added RIGGS_REVIEW to investigation state enum';
    RAISE NOTICE '  - Added riggs_override JSONB column';
    RAISE NOTICE '  - T2 now escalates to RIGGS_REVIEW (Riggs = T3)';
END $$;
