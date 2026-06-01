-- 073: Create the missing phishing_test_list table.
--
-- services/sender_trust_service.py has always referenced phishing_test_list
-- (pattern-based: sender_pattern + subject_pattern + match_type) but no
-- migration ever created it. There IS a phishing_tests table created by
-- postgres_db.py for a different feature (campaign-based) — different
-- schema entirely, not what the service expects. Net result: adding a
-- phishing test pattern through the UI has never worked. The list always
-- looked empty because the SELECT queried a non-existent table.
--
-- This migration creates the table with the schema the service code
-- expects, plus tenant_id + RLS to match the rest of the per-tenant
-- alert-processing tables (trusted_senders, tenant_pii_patterns, etc.).

CREATE TABLE IF NOT EXISTS phishing_test_list (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_pattern    TEXT NOT NULL,
    subject_pattern   TEXT NOT NULL,
    match_type        TEXT NOT NULL DEFAULT 'contains'
                      CHECK (match_type IN ('exact', 'contains', 'regex')),
    test_name         TEXT,
    vendor            TEXT,
    auto_close        BOOLEAN NOT NULL DEFAULT TRUE,
    skip_enrichment   BOOLEAN NOT NULL DEFAULT TRUE,
    disposition       TEXT NOT NULL DEFAULT 'BENIGN_POSITIVE',
    valid_from        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    valid_until       TIMESTAMPTZ,
    added_by          TEXT,
    is_active         BOOLEAN NOT NULL DEFAULT TRUE,
    hit_count         INTEGER NOT NULL DEFAULT 0,
    last_hit_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id         UUID REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_phishing_test_list_tenant
    ON phishing_test_list(tenant_id) WHERE is_active = TRUE;

ALTER TABLE phishing_test_list ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS phishing_test_list_isolation ON phishing_test_list;
CREATE POLICY phishing_test_list_isolation ON phishing_test_list
    USING      (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

DROP POLICY IF EXISTS phishing_test_list_platform_admin_bypass ON phishing_test_list;
CREATE POLICY phishing_test_list_platform_admin_bypass ON phishing_test_list
    USING      (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');
