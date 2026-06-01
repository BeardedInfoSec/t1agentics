-- 084_playbook_community_submissions.sql
-- Community submission workflow for playbooks. Mirrors KB community
-- submissions (migration 031): a tenant submits one of their own
-- playbooks; platform admin reviews; on approval the playbook is cloned
-- into playbook_templates (source='community') for all tenants to install.

CREATE TABLE IF NOT EXISTS playbook_community_submissions (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    playbook_id  UUID NOT NULL,                -- references playbooks.id (no FK so a deleted playbook still surfaces in the audit trail)
    tenant_id    UUID NOT NULL,
    submitted_by VARCHAR(100) NOT NULL,        -- username
    submitter_email VARCHAR(320),              -- captured at submit time for the notification email
    submission_notes TEXT,                      -- optional message from submitter
    status       VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewer_notes TEXT,
    reviewed_by  VARCHAR(100),
    reviewed_at  TIMESTAMPTZ,
    -- When approved, this points at the resulting playbook_templates row
    template_id  UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbook_submissions_status
    ON playbook_community_submissions (status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_playbook_submissions_pending
    ON playbook_community_submissions (created_at DESC)
    WHERE status = 'pending';

CREATE INDEX IF NOT EXISTS idx_playbook_submissions_tenant
    ON playbook_community_submissions (tenant_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_playbook_submissions_playbook
    ON playbook_community_submissions (playbook_id);
