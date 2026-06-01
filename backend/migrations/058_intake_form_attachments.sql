-- 058: Intake form attachments
--
-- File uploads attached to intake-form submissions. End users upload via
-- POST /api/v1/intake-forms/by-slug/{slug}/upload, receive an attachment id,
-- include that id in the form submission payload for the matching file field.
-- Files are stored on local disk (INTAKE_UPLOAD_DIR) and tracked here for
-- metadata, RLS, and TTL cleanup.
--
-- TTL behavior:
-- - Each row gets expires_at = created_at + 14 days at insert time.
-- - A scheduled task (agent_scheduler) periodically deletes rows where
--   expires_at < NOW() and deleted_at IS NULL, removing the disk file and
--   marking deleted_at. Submissions that referenced the file keep working
--   (they have the metadata) but the file itself becomes 410 Gone.

CREATE TABLE IF NOT EXISTS intake_form_attachments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    form_id         UUID NOT NULL REFERENCES intake_forms(id) ON DELETE CASCADE,
    submission_id   UUID NULL REFERENCES intake_form_submissions(id) ON DELETE CASCADE,
    field_key       TEXT NOT NULL,
    filename        TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    size_bytes      BIGINT NOT NULL,
    storage_path    TEXT NOT NULL,
    uploaded_by     UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '14 days'),
    deleted_at      TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_intake_attachments_tenant       ON intake_form_attachments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_intake_attachments_form         ON intake_form_attachments(form_id);
CREATE INDEX IF NOT EXISTS idx_intake_attachments_submission   ON intake_form_attachments(submission_id) WHERE submission_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_intake_attachments_expires      ON intake_form_attachments(expires_at) WHERE deleted_at IS NULL;

ALTER TABLE intake_form_attachments ENABLE ROW LEVEL SECURITY;

CREATE POLICY intake_form_attachments_tenant_isolation ON intake_form_attachments
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

CREATE POLICY intake_form_attachments_platform_admin_bypass ON intake_form_attachments
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
