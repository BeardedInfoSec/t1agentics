-- Migration: 057_intake_forms.sql
-- Intake Forms: Tenant-scoped, authenticated web forms whose submissions
-- become alerts that flow through the existing alert pipeline (Riggs triage,
-- enrichment, recommended actions, case creation).
--
-- Scope decisions (2026-05-05):
--   - Internal-only, forced authentication. No anonymous submissions.
--   - Six v1 field types: text, textarea, email, url, select, multiselect,
--     file, datetime. Field schema is JSONB so additions don't need migrations.
--   - Submissions create alerts via the existing alert pipeline; Riggs and
--     triggers run as they already do for any other source.
--   - Anti-enumeration: forms have a random slug (not sequential int);
--     all routes are tenant-scoped via RLS so cross-tenant access 404s.
--
-- Naming: tables are prefixed `intake_` to avoid colliding with the
-- pre-existing `form_submissions` table used by the playbook-forms feature
-- (different schema, different domain).

-- ─────────────────────────────────────────────────────────────────────────────
-- intake_forms: definitions authored by tenant admins
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS intake_forms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Identity
    slug VARCHAR(64) NOT NULL,           -- random, non-guessable; used in URL
    name VARCHAR(255) NOT NULL,          -- admin-facing internal name
    description TEXT,                    -- admin notes (not shown to submitters)

    -- Submitter-facing copy
    title VARCHAR(255) NOT NULL,         -- shown above the form
    intro TEXT,                          -- markdown blurb shown above fields
    submit_message TEXT,                 -- confirmation shown after submit

    -- Field schema. Array of:
    --   { key, label, type, required, help, options[], validation{}, default, placeholder }
    -- where type ∈ text | textarea | email | url | select | multiselect | file | datetime
    fields JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- How a submission maps onto an Alert payload.
    -- Supports simple template strings referencing field keys with {{field_key}}.
    -- Example: { "title": "Phishing report from {{reporter_email}}",
    --            "severity": "medium", "source": "intake_form", "category": "phishing" }
    alert_template JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Lifecycle
    status VARCHAR(16) NOT NULL DEFAULT 'draft'
        CHECK (status IN ('draft', 'active', 'archived')),

    -- Audit
    created_by UUID,                     -- users.id (no FK to avoid cascade surprises)
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT intake_forms_tenant_slug_unique UNIQUE (tenant_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_intake_forms_tenant ON intake_forms(tenant_id);
CREATE INDEX IF NOT EXISTS idx_intake_forms_tenant_status ON intake_forms(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_intake_forms_slug ON intake_forms(slug);

ALTER TABLE intake_forms ENABLE ROW LEVEL SECURITY;

CREATE POLICY intake_forms_tenant_isolation ON intake_forms
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY intake_forms_platform_admin_bypass ON intake_forms
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- ─────────────────────────────────────────────────────────────────────────────
-- intake_form_submissions: a single user's submission; source-of-truth payload
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS intake_form_submissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    form_id UUID NOT NULL REFERENCES intake_forms(id) ON DELETE CASCADE,

    -- Who submitted (forced auth — never null)
    submitted_by UUID NOT NULL,

    -- Submitted field values: { field_key: value, ... }
    -- File uploads store an attachment_id reference here, not raw bytes.
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Pipeline handoff
    -- alert_id is the string id returned by the alert ingestion path; left
    -- as VARCHAR to match the Alert.id type (Optional[str]) in models/__init__.py.
    alert_id VARCHAR(255),
    investigation_id UUID,               -- set later if triage produces a case

    -- Lifecycle
    status VARCHAR(16) NOT NULL DEFAULT 'submitted'
        CHECK (status IN ('submitted', 'processing', 'completed', 'failed')),
    error_message TEXT,                  -- populated on status='failed'

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_intake_form_submissions_tenant ON intake_form_submissions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_intake_form_submissions_form ON intake_form_submissions(form_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_intake_form_submissions_status ON intake_form_submissions(status);
CREATE INDEX IF NOT EXISTS idx_intake_form_submissions_alert ON intake_form_submissions(alert_id) WHERE alert_id IS NOT NULL;

ALTER TABLE intake_form_submissions ENABLE ROW LEVEL SECURITY;

CREATE POLICY intake_form_submissions_tenant_isolation ON intake_form_submissions
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY intake_form_submissions_platform_admin_bypass ON intake_form_submissions
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
