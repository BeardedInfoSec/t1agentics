-- Migration 031: Community submission workflow for Knowledge Base
--
-- Tenants can submit their organization articles for community review.
-- Platform admin reviews and approves/rejects submissions.
-- On approval, the article is cloned as source='builtin' (visible to all tenants).

CREATE TABLE IF NOT EXISTS kb_community_submissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    kb_id VARCHAR(100) NOT NULL,
    tenant_id UUID NOT NULL,
    submitted_by VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending'
        CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewer_notes TEXT,
    reviewed_by VARCHAR(100),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_kb_submissions_status ON kb_community_submissions(status);
CREATE INDEX IF NOT EXISTS idx_kb_submissions_tenant ON kb_community_submissions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_kb_submissions_kb_id ON kb_community_submissions(kb_id);
