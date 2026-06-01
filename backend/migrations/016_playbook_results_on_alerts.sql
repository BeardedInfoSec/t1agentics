-- ============================================================================
-- PLAYBOOK RESULTS ON ALERTS MIGRATION
-- Stores playbook execution results directly on alerts so T1/T2 can see them
-- Date: 2026-02-06
-- ============================================================================

-- ============================================================================
-- ADD PLAYBOOK_RESULTS COLUMN TO ALERTS
-- Stores summary of playbook executions for this alert
-- ============================================================================

ALTER TABLE alerts
ADD COLUMN IF NOT EXISTS playbook_results JSONB DEFAULT '[]';

-- Add index for querying alerts with playbook results
CREATE INDEX IF NOT EXISTS idx_alerts_playbook_results
ON alerts USING GIN (playbook_results);

-- Add index for finding alerts where playbooks failed
CREATE INDEX IF NOT EXISTS idx_alerts_playbook_failed
ON alerts ((playbook_results @> '[{"status": "failed"}]'))
WHERE playbook_results IS NOT NULL AND playbook_results != '[]'::jsonb;

-- ============================================================================
-- ADD TRIGGER TIMING COLUMN TO PLAYBOOKS
-- Controls when playbook runs: pre_triage, post_triage, manual
-- ============================================================================

ALTER TABLE playbooks
ADD COLUMN IF NOT EXISTS trigger_timing VARCHAR(50) DEFAULT 'post_triage';

-- Add comment explaining the column
COMMENT ON COLUMN playbooks.trigger_timing IS
'When playbook runs relative to triage:
  - pre_triage: After enrichment, before T1 (results visible to T1)
  - post_triage: After T1/Riggs completes (current behavior)
  - on_demand: Only manual execution or Riggs recommendation
  - parallel: Runs alongside triage (does not block T1)';

-- ============================================================================
-- ADD PLAYBOOK EXECUTION TRACKING ON ALERTS
-- Track which playbooks have run for deduplication
-- ============================================================================

ALTER TABLE alerts
ADD COLUMN IF NOT EXISTS playbook_executions_run TEXT[] DEFAULT '{}';

-- Index for deduplication lookups
CREATE INDEX IF NOT EXISTS idx_alerts_playbook_executions_run
ON alerts USING GIN (playbook_executions_run);

-- ============================================================================
-- UPDATE EXISTING PLAYBOOKS TO DEFAULT TIMING
-- ============================================================================

UPDATE playbooks
SET trigger_timing = 'post_triage'
WHERE trigger_timing IS NULL;

-- ============================================================================
-- SAMPLE PLAYBOOK_RESULTS STRUCTURE (for documentation)
-- ============================================================================
/*
playbook_results JSONB structure:
[
    {
        "playbook_id": "uuid",
        "playbook_name": "Block Malicious IPs",
        "execution_id": "PBX-A1B2C3",
        "trigger_timing": "pre_triage",
        "status": "completed",  -- completed, failed, partial, running, skipped
        "started_at": "2026-02-06T10:00:00Z",
        "completed_at": "2026-02-06T10:00:05Z",
        "duration_ms": 5000,
        "summary": "Blocked 2/3 malicious IPs",
        "actions_taken": [
            {
                "node_id": "node-123",
                "action_type": "block_ip",
                "target": "1.2.3.4",
                "success": true,
                "message": "IP blocked in firewall"
            },
            {
                "node_id": "node-456",
                "action_type": "block_ip",
                "target": "5.6.7.8",
                "success": false,
                "error": "Rate limited by firewall API"
            }
        ],
        "error": null  -- or error message if status is failed
    }
]
*/

-- ============================================================================
-- SUCCESS MESSAGE
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Playbook results on alerts migration completed!';
    RAISE NOTICE '  - Added playbook_results JSONB column to alerts';
    RAISE NOTICE '  - Added trigger_timing column to playbooks';
    RAISE NOTICE '  - Added playbook_executions_run for deduplication';
    RAISE NOTICE '  - Added indexes for efficient querying';
END $$;
