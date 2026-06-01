-- ============================================================================
-- Add tenant_id to 41 high-risk tables + enable RLS
-- ============================================================================
-- This migration:
--   1. Adds tenant_id UUID column (nullable) to each table
--   2. Backfills existing rows from parent FK or default tenant
--   3. Sets NOT NULL constraint
--   4. Enables RLS + FORCE + standard policies
--
-- Default tenant: 00000000-0000-0000-0000-000000000001 (t1-agentics)
-- ============================================================================

BEGIN;

-- ============================================================================
-- PHASE 1: Add tenant_id column to all 41 tables (nullable first)
-- ============================================================================

-- Group A: Tables with investigation_id FK
ALTER TABLE investigation_chat ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE investigation_iocs ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE investigation_ownership_log ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE riggs_decisions ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE approval_requests ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE chat_action_audit ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE chat_usage_analytics ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE verdict_audit_log ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE escalation_history ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE case_summaries ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE riggs_feedback ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE riggs_playbook_executions ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE playbook_execution_approvals ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Group B: Tables with alert_id FK
ALTER TABLE alert_attachments ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE alert_ioc_links ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE detection_hits ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Group C: Tables with campaign_id FK
ALTER TABLE campaign_iocs ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE campaign_members ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Group D: Tables with playbook/execution FK
ALTER TABLE playbook_versions ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE playbook_node_approvals ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE playbook_files ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Group E: Tables with user_id FK
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE credentials_vault ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE approval_tokens ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Group F: EDL FK
ALTER TABLE edl_credentials ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Group G: Inbound email FK
ALTER TABLE inbound_email_queue ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Group H: Integration FK
ALTER TABLE integration_credentials ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Group I: Assets (standalone, then children)
ALTER TABLE assets ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE asset_history ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE asset_identifiers ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE asset_relationships ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE asset_conflicts ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Group J: Independent tables
ALTER TABLE exclusion_list ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE ioc_blocklist ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE ioc_whitelist ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE ioc_enrichments ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE notification_rules ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE escalation_config ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE playbook_functions ADD COLUMN IF NOT EXISTS tenant_id UUID;
ALTER TABLE playbook_lists ADD COLUMN IF NOT EXISTS tenant_id UUID;


-- ============================================================================
-- PHASE 2: Backfill existing data
-- ============================================================================

-- ---- Group A: From investigations.tenant_id ----

-- investigation_chat (investigation_id uuid NOT NULL FK)
UPDATE investigation_chat ic
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id = ic.investigation_id
AND ic.tenant_id IS NULL;

-- investigation_iocs (investigation_id uuid NOT NULL FK)
UPDATE investigation_iocs ii
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id = ii.investigation_id
AND ii.tenant_id IS NULL;

-- investigation_ownership_log (investigation_id uuid NOT NULL FK)
UPDATE investigation_ownership_log iol
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id = iol.investigation_id
AND iol.tenant_id IS NULL;

-- riggs_decisions (investigation_id uuid NULLABLE FK)
UPDATE riggs_decisions rd
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id = rd.investigation_id
AND rd.tenant_id IS NULL;

-- approval_requests (investigation_id uuid NULLABLE FK)
UPDATE approval_requests ar
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id = ar.investigation_id
AND ar.tenant_id IS NULL;

-- chat_action_audit (investigation_id uuid NULLABLE FK)
UPDATE chat_action_audit caa
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id = caa.investigation_id
AND caa.tenant_id IS NULL;

-- chat_usage_analytics (investigation_id uuid NULLABLE FK)
UPDATE chat_usage_analytics cua
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id = cua.investigation_id
AND cua.tenant_id IS NULL;

-- verdict_audit_log (investigation_id uuid NOT NULL FK)
UPDATE verdict_audit_log val
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id = val.investigation_id
AND val.tenant_id IS NULL;

-- escalation_history (investigation_id uuid NULLABLE FK, also has alert_id)
UPDATE escalation_history eh
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id = eh.investigation_id
AND eh.tenant_id IS NULL;
-- Fallback: try alert_id for rows without investigation_id
UPDATE escalation_history eh
SET tenant_id = a.tenant_id
FROM alerts a
WHERE a.id = eh.alert_id
AND eh.tenant_id IS NULL;

-- case_summaries (investigation_id varchar → need text join)
UPDATE case_summaries cs
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id::text = cs.investigation_id
AND cs.tenant_id IS NULL;

-- riggs_feedback (investigation_id varchar → need text join)
UPDATE riggs_feedback rf
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id::text = rf.investigation_id
AND rf.tenant_id IS NULL;

-- riggs_playbook_executions (investigation_id text → need text join)
UPDATE riggs_playbook_executions rpe
SET tenant_id = inv.tenant_id
FROM investigations inv
WHERE inv.id::text = rpe.investigation_id
AND rpe.tenant_id IS NULL;

-- playbook_execution_approvals (investigation_id text, playbook_id uuid FK)
UPDATE playbook_execution_approvals pea
SET tenant_id = p.tenant_id
FROM playbooks p
WHERE p.id = pea.playbook_id
AND pea.tenant_id IS NULL;

-- ---- Group B: From alerts.tenant_id ----

-- alert_attachments (alert_id varchar → text join)
UPDATE alert_attachments aa
SET tenant_id = a.tenant_id
FROM alerts a
WHERE a.id::text = aa.alert_id
AND aa.tenant_id IS NULL;

-- alert_ioc_links (alert_id varchar → text join)
UPDATE alert_ioc_links ail
SET tenant_id = a.tenant_id
FROM alerts a
WHERE a.id::text = ail.alert_id
AND ail.tenant_id IS NULL;

-- alert_groups (primary_alert_id uuid)
UPDATE alert_groups ag
SET tenant_id = a.tenant_id
FROM alerts a
WHERE a.id = ag.primary_alert_id
AND ag.tenant_id IS NULL;

-- detection_hits (alert_id uuid NULLABLE FK)
UPDATE detection_hits dh
SET tenant_id = a.tenant_id
FROM alerts a
WHERE a.id = dh.alert_id
AND dh.tenant_id IS NULL;

-- ---- Group C: From campaigns.tenant_id ----

-- campaign_iocs (campaign_id uuid NULLABLE FK)
UPDATE campaign_iocs ci
SET tenant_id = c.tenant_id
FROM campaigns c
WHERE c.id = ci.campaign_id
AND ci.tenant_id IS NULL;

-- campaign_members (campaign_id uuid NULLABLE FK)
UPDATE campaign_members cm
SET tenant_id = c.tenant_id
FROM campaigns c
WHERE c.id = cm.campaign_id
AND cm.tenant_id IS NULL;

-- ---- Group D: From playbooks/playbook_executions ----

-- playbook_versions (playbook_id uuid NOT NULL FK → playbooks.id)
UPDATE playbook_versions pv
SET tenant_id = p.tenant_id
FROM playbooks p
WHERE p.id = pv.playbook_id
AND pv.tenant_id IS NULL;

-- playbook_node_approvals (execution_id uuid NOT NULL FK → playbook_executions.id)
UPDATE playbook_node_approvals pna
SET tenant_id = pe.tenant_id
FROM playbook_executions pe
WHERE pe.id = pna.execution_id
AND pna.tenant_id IS NULL;

-- playbook_files (execution_id uuid NULLABLE FK → playbook_executions.id)
UPDATE playbook_files pf
SET tenant_id = pe.tenant_id
FROM playbook_executions pe
WHERE pe.id = pf.execution_id
AND pf.tenant_id IS NULL;

-- ---- Group E: From users.tenant_id ----

-- audit_log (user_id uuid NULLABLE FK → users.id) — 62 rows
UPDATE audit_log al
SET tenant_id = u.tenant_id
FROM users u
WHERE u.id = al.user_id
AND al.tenant_id IS NULL;

-- credentials_vault (created_by varchar — join to users.username)
UPDATE credentials_vault cv
SET tenant_id = u.tenant_id
FROM users u
WHERE u.username = cv.created_by
AND cv.tenant_id IS NULL;

-- approval_tokens (created_by varchar — join to users.username)
UPDATE approval_tokens at2
SET tenant_id = u.tenant_id
FROM users u
WHERE u.username = at2.created_by
AND at2.tenant_id IS NULL;

-- ---- Group F: From edl_lists.tenant_id ----

-- edl_credentials (list_id uuid NOT NULL FK → edl_lists.list_id)
UPDATE edl_credentials ec
SET tenant_id = el.tenant_id::uuid
FROM edl_lists el
WHERE el.list_id = ec.list_id
AND ec.tenant_id IS NULL;

-- ---- Group G: From inbound_mailboxes.tenant_id ----

-- inbound_email_queue (mailbox_id uuid) — 38 rows
UPDATE inbound_email_queue ieq
SET tenant_id = im.tenant_id
FROM inbound_mailboxes im
WHERE im.id = ieq.mailbox_id
AND ieq.tenant_id IS NULL;

-- ---- Group H: From integrations.tenant_id ----

-- integration_credentials (integration_id uuid)
UPDATE integration_credentials icr
SET tenant_id = i.tenant_id
FROM integrations i
WHERE i.id = icr.integration_id
AND icr.tenant_id IS NULL;


-- ============================================================================
-- PHASE 2b: Default-tenant backfill for remaining NULLs
-- Any rows that couldn't be backfilled via FK get the default tenant
-- ============================================================================

DO $$
DECLARE
    default_tid UUID := '00000000-0000-0000-0000-000000000001';
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[
        -- Group A leftovers (rows with NULL investigation_id)
        'investigation_chat', 'investigation_iocs', 'investigation_ownership_log',
        'riggs_decisions', 'approval_requests', 'chat_action_audit',
        'chat_usage_analytics', 'verdict_audit_log', 'escalation_history',
        'case_summaries', 'riggs_feedback', 'riggs_playbook_executions',
        'playbook_execution_approvals',
        -- Group B leftovers
        'alert_attachments', 'alert_ioc_links', 'alert_groups', 'detection_hits',
        -- Group C leftovers
        'campaign_iocs', 'campaign_members',
        -- Group D leftovers
        'playbook_versions', 'playbook_node_approvals', 'playbook_files',
        -- Group E leftovers
        'audit_log', 'credentials_vault', 'approval_tokens',
        -- Group F-H leftovers
        'edl_credentials', 'inbound_email_queue', 'integration_credentials',
        -- Group I: Assets
        'assets', 'asset_history', 'asset_identifiers',
        'asset_relationships', 'asset_conflicts',
        -- Group J: Independent tables
        'exclusion_list', 'ioc_blocklist', 'ioc_whitelist', 'ioc_enrichments',
        'notification_rules', 'escalation_config',
        'playbook_functions', 'playbook_lists'
    ]
    LOOP
        EXECUTE format(
            'UPDATE %I SET tenant_id = $1 WHERE tenant_id IS NULL',
            tbl
        ) USING default_tid;
    END LOOP;
END $$;


-- ============================================================================
-- PHASE 3: Set NOT NULL constraints
-- ============================================================================

ALTER TABLE investigation_chat ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE investigation_iocs ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE investigation_ownership_log ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE riggs_decisions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE approval_requests ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE chat_action_audit ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE chat_usage_analytics ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE verdict_audit_log ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE escalation_history ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE case_summaries ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE riggs_feedback ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE riggs_playbook_executions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE playbook_execution_approvals ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE alert_attachments ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE alert_ioc_links ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE alert_groups ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE detection_hits ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE campaign_iocs ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE campaign_members ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE playbook_versions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE playbook_node_approvals ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE playbook_files ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE audit_log ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE credentials_vault ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE approval_tokens ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE edl_credentials ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE inbound_email_queue ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE integration_credentials ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE assets ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE asset_history ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE asset_identifiers ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE asset_relationships ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE asset_conflicts ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE exclusion_list ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE ioc_blocklist ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE ioc_whitelist ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE ioc_enrichments ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE notification_rules ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE escalation_config ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE playbook_functions ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE playbook_lists ALTER COLUMN tenant_id SET NOT NULL;


-- ============================================================================
-- PHASE 4: Set DEFAULT for future INSERTs (prevents NOT NULL errors
--          for code that hasn't been updated yet)
-- ============================================================================

ALTER TABLE investigation_chat ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE investigation_iocs ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE investigation_ownership_log ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE riggs_decisions ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE approval_requests ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE chat_action_audit ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE chat_usage_analytics ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE verdict_audit_log ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE escalation_history ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE case_summaries ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE riggs_feedback ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE riggs_playbook_executions ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE playbook_execution_approvals ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE alert_attachments ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE alert_ioc_links ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE alert_groups ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE detection_hits ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE campaign_iocs ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE campaign_members ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE playbook_versions ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE playbook_node_approvals ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE playbook_files ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE audit_log ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE credentials_vault ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE approval_tokens ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE edl_credentials ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE inbound_email_queue ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE integration_credentials ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE assets ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE asset_history ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE asset_identifiers ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE asset_relationships ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE asset_conflicts ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE exclusion_list ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE ioc_blocklist ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE ioc_whitelist ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE ioc_enrichments ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE notification_rules ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE escalation_config ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE playbook_functions ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE playbook_lists ALTER COLUMN tenant_id SET DEFAULT '00000000-0000-0000-0000-000000000001';


-- ============================================================================
-- PHASE 5: Enable RLS + FORCE + policies on all 41 tables
-- ============================================================================

DO $$
DECLARE
    tbl TEXT;
BEGIN
    FOREACH tbl IN ARRAY ARRAY[
        'investigation_chat', 'investigation_iocs', 'investigation_ownership_log',
        'riggs_decisions', 'approval_requests', 'chat_action_audit',
        'chat_usage_analytics', 'verdict_audit_log', 'escalation_history',
        'case_summaries', 'riggs_feedback', 'riggs_playbook_executions',
        'playbook_execution_approvals',
        'alert_attachments', 'alert_ioc_links', 'alert_groups', 'detection_hits',
        'campaign_iocs', 'campaign_members',
        'playbook_versions', 'playbook_node_approvals', 'playbook_files',
        'audit_log', 'credentials_vault', 'approval_tokens',
        'edl_credentials', 'inbound_email_queue', 'integration_credentials',
        'assets', 'asset_history', 'asset_identifiers',
        'asset_relationships', 'asset_conflicts',
        'exclusion_list', 'ioc_blocklist', 'ioc_whitelist', 'ioc_enrichments',
        'notification_rules', 'escalation_config',
        'playbook_functions', 'playbook_lists'
    ]
    LOOP
        -- Enable RLS
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tbl);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tbl);

        -- Drop any existing policies (safe idempotency)
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', tbl);
        EXECUTE format('DROP POLICY IF EXISTS platform_admin_bypass ON %I', tbl);

        -- Create tenant isolation policy
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I FOR ALL
             USING (tenant_id::text = current_setting(''app.current_tenant_id'', true))
             WITH CHECK (tenant_id::text = current_setting(''app.current_tenant_id'', true))',
            tbl
        );

        -- Create platform admin bypass policy
        EXECUTE format(
            'CREATE POLICY platform_admin_bypass ON %I FOR ALL
             USING (current_setting(''app.is_platform_admin'', true) = ''true'')
             WITH CHECK (current_setting(''app.is_platform_admin'', true) = ''true'')',
            tbl
        );
    END LOOP;
END $$;


COMMIT;
