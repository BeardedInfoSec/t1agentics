--
-- Riggs-Playbook Integration Tables
--
-- Tracks playbook executions triggered by Riggs and their outcomes
--

-- Table: Riggs playbook executions
CREATE TABLE IF NOT EXISTS riggs_playbook_executions (
    id SERIAL PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    playbook_id UUID NOT NULL,
    execution_id TEXT NOT NULL,
    triggered_by TEXT NOT NULL DEFAULT 'riggs_auto',
    riggs_verdict TEXT,
    riggs_confidence INTEGER,
    outcome TEXT,  -- success, failed, cancelled
    effectiveness_score INTEGER CHECK (effectiveness_score >= 0 AND effectiveness_score <= 100),
    analyst_notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    feedback_recorded_at TIMESTAMP,
    UNIQUE(investigation_id, execution_id)
);

CREATE INDEX IF NOT EXISTS idx_riggs_playbook_executions_investigation
    ON riggs_playbook_executions(investigation_id);

CREATE INDEX IF NOT EXISTS idx_riggs_playbook_executions_playbook
    ON riggs_playbook_executions(playbook_id);

CREATE INDEX IF NOT EXISTS idx_riggs_playbook_executions_created
    ON riggs_playbook_executions(created_at DESC);


-- Table: Playbook execution approvals
CREATE TABLE IF NOT EXISTS playbook_execution_approvals (
    id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    playbook_id UUID NOT NULL,
    playbook_name TEXT NOT NULL,
    riggs_verdict TEXT,
    riggs_confidence INTEGER,
    riggs_reasoning TEXT,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, approved, rejected, expired
    approved_by TEXT,
    approval_notes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    responded_at TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (playbook_id) REFERENCES playbooks(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_playbook_approvals_investigation
    ON playbook_execution_approvals(investigation_id);

CREATE INDEX IF NOT EXISTS idx_playbook_approvals_status
    ON playbook_execution_approvals(status) WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_playbook_approvals_created
    ON playbook_execution_approvals(created_at DESC);


-- Add columns to playbooks table if not exists
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS riggs_allowed BOOLEAN DEFAULT FALSE;
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS riggs_confidence FLOAT;
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS riggs_suggestions JSONB DEFAULT '[]'::jsonb;
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS last_riggs_review TIMESTAMP;

-- Index for Riggs-allowed playbooks
CREATE INDEX IF NOT EXISTS idx_playbooks_riggs_allowed
    ON playbooks(riggs_allowed) WHERE riggs_allowed = TRUE;


-- View: Playbook effectiveness analytics
CREATE OR REPLACE VIEW riggs_playbook_effectiveness AS
SELECT
    p.id as playbook_id,
    p.name as playbook_name,
    COUNT(*) as total_executions,
    COUNT(*) FILTER (WHERE rpe.outcome = 'success') as successful_executions,
    AVG(rpe.effectiveness_score) as avg_effectiveness,
    COUNT(*) FILTER (WHERE rpe.triggered_by = 'riggs_auto') as auto_executions,
    COUNT(*) FILTER (WHERE rpe.riggs_verdict = 'MALICIOUS') as malicious_verdicts,
    MAX(rpe.created_at) as last_executed
FROM playbooks p
LEFT JOIN riggs_playbook_executions rpe ON p.id = rpe.playbook_id
GROUP BY p.id, p.name;


-- Function: Auto-expire old approval requests
CREATE OR REPLACE FUNCTION expire_old_playbook_approvals()
RETURNS void AS $$
BEGIN
    UPDATE playbook_execution_approvals
    SET status = 'expired'
    WHERE status = 'pending'
    AND created_at < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- Could be run via cron or scheduled task
-- SELECT expire_old_playbook_approvals();
