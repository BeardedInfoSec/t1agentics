-- ============================================================================
-- PLAYBOOK SCHEDULED DELAYS MIGRATION
-- Adds support for long delays with scheduled resumption
-- Date: 2026-02-04
-- ============================================================================

-- Add resume_at column for scheduled delay resumption
ALTER TABLE playbook_executions
ADD COLUMN IF NOT EXISTS resume_at TIMESTAMP WITH TIME ZONE;

-- Add waiting_delay status to the status check constraint
-- First drop the existing constraint, then recreate with new value
ALTER TABLE playbook_executions
DROP CONSTRAINT IF EXISTS playbook_executions_status_check;

ALTER TABLE playbook_executions
ADD CONSTRAINT playbook_executions_status_check CHECK (status IN (
    'pending',           -- Not yet started
    'running',           -- Currently executing
    'waiting_approval',  -- Paused at approval gate
    'waiting_input',     -- Paused waiting for user input/form
    'waiting_file',      -- Paused waiting for file upload
    'waiting_delay',     -- Paused waiting for scheduled delay
    'completed',         -- Finished successfully
    'failed',            -- Finished with error
    'cancelled',         -- Manually cancelled
    'timeout'            -- Execution timed out
));

-- Index for efficiently finding delayed executions ready to resume
CREATE INDEX IF NOT EXISTS idx_pb_exec_resume_at
ON playbook_executions (resume_at)
WHERE status = 'waiting_delay' AND resume_at IS NOT NULL;

-- Comment on column
COMMENT ON COLUMN playbook_executions.resume_at IS 'Timestamp when a delayed execution should be resumed';
