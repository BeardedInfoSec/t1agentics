-- Migration: Simplify investigation states to 5-state workflow
-- Date: 2026-01-11
--
-- Old states: NEW, ENRICHING, AI_TRIAGE_L1, AI_TRIAGE_L2, RIGGS_REVIEW,
--             AWAITING_HUMAN, IN_PROGRESS, RESOLVED, CLOSED
--
-- New states: NEW, ANALYZING, NEEDS_REVIEW, IN_PROGRESS, CLOSED
--
-- Mapping:
--   NEW           -> NEW
--   ENRICHING     -> ANALYZING
--   AI_TRIAGE_L1  -> ANALYZING
--   AI_TRIAGE_L2  -> ANALYZING
--   RIGGS_REVIEW  -> NEEDS_REVIEW (AI done, human decision needed)
--   RIGGS_ANALYZED -> NEEDS_REVIEW
--   AWAITING_HUMAN -> NEEDS_REVIEW
--   IN_PROGRESS   -> IN_PROGRESS
--   RESOLVED      -> CLOSED (disposition contains the verdict)
--   CLOSED        -> CLOSED

BEGIN;

-- Step 1: Migrate existing data to new states
UPDATE investigations SET state = 'ANALYZING' WHERE state IN ('ENRICHING', 'AI_TRIAGE_L1', 'AI_TRIAGE_L2');
UPDATE investigations SET state = 'NEEDS_REVIEW' WHERE state IN ('RIGGS_REVIEW', 'RIGGS_ANALYZED', 'AWAITING_HUMAN');
UPDATE investigations SET state = 'CLOSED' WHERE state = 'RESOLVED';

-- Step 2: Drop old constraint
ALTER TABLE investigations DROP CONSTRAINT IF EXISTS investigations_state_check;

-- Step 3: Add new constraint with simplified states
ALTER TABLE investigations ADD CONSTRAINT investigations_state_check CHECK (state IN (
    'NEW',           -- Just arrived, not yet processed
    'ANALYZING',     -- AI working (enriching, triaging, Riggs analysis)
    'NEEDS_REVIEW',  -- AI done, needs human decision
    'IN_PROGRESS',   -- Analyst actively working
    'CLOSED'         -- Terminal state (disposition has the verdict)
));

COMMIT;

-- Verification query (run after migration):
-- SELECT state, COUNT(*) FROM investigations GROUP BY state ORDER BY state;
