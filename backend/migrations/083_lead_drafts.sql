-- 083_lead_drafts.sql
-- Inbound signup-to-conversation marketing agent.
-- Stores AI-generated lead classification + draft follow-up emails for
-- founder review. Drafts surface in the daily summary email with HMAC-signed
-- approve/reject links so the founder can triage from inbox.

CREATE TABLE IF NOT EXISTS lead_drafts (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    source_type     VARCHAR(32)  NOT NULL CHECK (source_type IN ('signup', 'contact', 'triage_demo')),
    source_id       VARCHAR(128) NOT NULL,         -- references registration_requests.id, contact_submissions.id, etc.
    lead_email      VARCHAR(320) NOT NULL,
    lead_name       VARCHAR(255),
    lead_company    VARCHAR(255),

    -- Classification produced by the LLM:
    --   real_prospect  — looks like a real buyer
    --   partner        — looks like a partner / channel
    --   competitor     — works at a competitor; do not engage
    --   noise          — disposable email, .test address, obvious junk
    --   unknown        — agent isn't confident
    classification          VARCHAR(32)  NOT NULL DEFAULT 'unknown'
        CHECK (classification IN ('real_prospect', 'partner', 'competitor', 'noise', 'unknown')),
    classification_confidence NUMERIC(3,2)  -- 0.00 - 1.00
        CHECK (classification_confidence IS NULL OR (classification_confidence >= 0 AND classification_confidence <= 1)),
    classification_reason   TEXT,

    -- The drafted follow-up email.
    draft_subject   VARCHAR(300),
    draft_body      TEXT,

    -- Lifecycle. pending_review -> approved/rejected. approved -> sent.
    status          VARCHAR(20) NOT NULL DEFAULT 'pending_review'
        CHECK (status IN ('pending_review', 'approved', 'rejected', 'sent', 'failed')),
    reviewed_at     TIMESTAMPTZ,
    reviewed_by     VARCHAR(320),    -- email of the platform admin who approved/rejected
    sent_at         TIMESTAMPTZ,
    send_error      TEXT,

    -- HMAC token embedded in the inbox approve/reject link. We compare a hash
    -- in the URL against this on the server, so a leaked stale daily-summary
    -- email cannot replay an approval that has already been processed.
    approval_token  VARCHAR(128) NOT NULL,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lead_drafts_status_created
    ON lead_drafts(status, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_lead_drafts_source
    ON lead_drafts(source_type, source_id);

CREATE INDEX IF NOT EXISTS idx_lead_drafts_pending
    ON lead_drafts(created_at DESC)
    WHERE status = 'pending_review';
