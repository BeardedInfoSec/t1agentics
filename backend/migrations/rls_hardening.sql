-- ============================================================================
-- RLS Hardening Migration
-- Fixes all database-level RLS gaps across 50 tenant-scoped tables
-- ============================================================================
-- Run as: psql -U agentcore -d agentcore -f rls_hardening.sql
-- ============================================================================

BEGIN;

-- ============================================================================
-- PHASE 1: Add RLS to 12 tables that have tenant_id but NO RLS policies
-- ============================================================================

-- 1. connect_credentials (tenant_id NOT NULL, uuid)
ALTER TABLE connect_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE connect_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON connect_credentials FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON connect_credentials FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 2. connect_execution_log (tenant_id NOT NULL, uuid)
ALTER TABLE connect_execution_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE connect_execution_log FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON connect_execution_log FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON connect_execution_log FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 3. connect_instances (tenant_id NOT NULL, uuid)
ALTER TABLE connect_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE connect_instances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON connect_instances FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON connect_instances FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 4. connector_definitions (tenant_id nullable, uuid)
ALTER TABLE connector_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_definitions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON connector_definitions FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON connector_definitions FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 5. connector_submissions (tenant_id NOT NULL, uuid)
ALTER TABLE connector_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE connector_submissions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON connector_submissions FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON connector_submissions FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 6. inbound_mailboxes (tenant_id NOT NULL, uuid)
ALTER TABLE inbound_mailboxes ENABLE ROW LEVEL SECURITY;
ALTER TABLE inbound_mailboxes FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON inbound_mailboxes FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON inbound_mailboxes FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 7. notifications (tenant_id NOT NULL, uuid)
ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notifications FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON notifications FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 8. playbook_templates (tenant_id nullable, uuid)
ALTER TABLE playbook_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbook_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON playbook_templates FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON playbook_templates FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 9. soar_executions (tenant_id nullable, uuid)
ALTER TABLE soar_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_executions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON soar_executions FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON soar_executions FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 10. soar_playbooks (tenant_id nullable, uuid)
ALTER TABLE soar_playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE soar_playbooks FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON soar_playbooks FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON soar_playbooks FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 11. trusted_senders (tenant_id nullable, uuid)
ALTER TABLE trusted_senders ENABLE ROW LEVEL SECURITY;
ALTER TABLE trusted_senders FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON trusted_senders FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON trusted_senders FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 12. usage_counters (tenant_id NOT NULL, uuid)
ALTER TABLE usage_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_counters FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON usage_counters FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON usage_counters FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');


-- ============================================================================
-- PHASE 2: Upgrade 19 tables — add FORCE, drop old policies, create new
--          with standardized names and WITH CHECK
-- ============================================================================

-- 1. action_requests (nullable tenant_id)
ALTER TABLE action_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS action_requests_tenant_isolation ON action_requests;
DROP POLICY IF EXISTS action_requests_platform_admin_bypass ON action_requests;
CREATE POLICY tenant_isolation ON action_requests FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON action_requests FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 2. agent_action_log (nullable tenant_id)
ALTER TABLE agent_action_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_action_log_tenant_isolation ON agent_action_log;
DROP POLICY IF EXISTS agent_action_log_platform_admin_bypass ON agent_action_log;
CREATE POLICY tenant_isolation ON agent_action_log FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON agent_action_log FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 3. agent_approval_requests (nullable tenant_id)
ALTER TABLE agent_approval_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_approval_requests_tenant_isolation ON agent_approval_requests;
DROP POLICY IF EXISTS agent_approval_requests_platform_admin_bypass ON agent_approval_requests;
CREATE POLICY tenant_isolation ON agent_approval_requests FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON agent_approval_requests FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 4. agent_definitions (nullable tenant_id)
ALTER TABLE agent_definitions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_definitions_tenant_isolation ON agent_definitions;
DROP POLICY IF EXISTS agent_definitions_platform_admin_bypass ON agent_definitions;
CREATE POLICY tenant_isolation ON agent_definitions FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON agent_definitions FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 5. agent_executions (nullable tenant_id)
ALTER TABLE agent_executions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS agent_executions_tenant_isolation ON agent_executions;
DROP POLICY IF EXISTS agent_executions_platform_admin_bypass ON agent_executions;
CREATE POLICY tenant_isolation ON agent_executions FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON agent_executions FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 6. ai_action_log (nullable tenant_id)
ALTER TABLE ai_action_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ai_action_log_tenant_isolation ON ai_action_log;
DROP POLICY IF EXISTS ai_action_log_platform_admin_bypass ON ai_action_log;
CREATE POLICY tenant_isolation ON ai_action_log FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON ai_action_log FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 7. ai_agents (nullable tenant_id)
ALTER TABLE ai_agents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS ai_agents_tenant_isolation ON ai_agents;
DROP POLICY IF EXISTS ai_agents_platform_admin_bypass ON ai_agents;
CREATE POLICY tenant_isolation ON ai_agents FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON ai_agents FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 8. api_keys (NOT NULL tenant_id) — was also missing platform_admin_bypass
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS api_keys_tenant_isolation ON api_keys;
CREATE POLICY tenant_isolation ON api_keys FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON api_keys FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 9. campaigns (nullable tenant_id)
ALTER TABLE campaigns FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS campaigns_tenant_isolation ON campaigns;
DROP POLICY IF EXISTS campaigns_platform_admin_bypass ON campaigns;
CREATE POLICY tenant_isolation ON campaigns FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON campaigns FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 10. correlation_decisions (nullable tenant_id) — already has new-style names
ALTER TABLE correlation_decisions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON correlation_decisions;
DROP POLICY IF EXISTS platform_admin_bypass ON correlation_decisions;
CREATE POLICY tenant_isolation ON correlation_decisions FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON correlation_decisions FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 11. enrichment_cache (nullable tenant_id)
ALTER TABLE enrichment_cache FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS enrichment_cache_tenant_isolation ON enrichment_cache;
DROP POLICY IF EXISTS enrichment_cache_platform_admin_bypass ON enrichment_cache;
CREATE POLICY tenant_isolation ON enrichment_cache FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON enrichment_cache FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 12. enrichment_jobs (nullable tenant_id)
ALTER TABLE enrichment_jobs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS enrichment_jobs_tenant_isolation ON enrichment_jobs;
DROP POLICY IF EXISTS enrichment_jobs_platform_admin_bypass ON enrichment_jobs;
CREATE POLICY tenant_isolation ON enrichment_jobs FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON enrichment_jobs FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 13. integrations (nullable tenant_id)
ALTER TABLE integrations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS integrations_tenant_isolation ON integrations;
DROP POLICY IF EXISTS integrations_platform_admin_bypass ON integrations;
CREATE POLICY tenant_isolation ON integrations FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON integrations FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 14. investigation_audit_log (nullable tenant_id)
ALTER TABLE investigation_audit_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS investigation_audit_log_tenant_isolation ON investigation_audit_log;
DROP POLICY IF EXISTS investigation_audit_log_platform_admin_bypass ON investigation_audit_log;
CREATE POLICY tenant_isolation ON investigation_audit_log FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON investigation_audit_log FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 15. investigation_entities (nullable tenant_id) — already has new-style names
ALTER TABLE investigation_entities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON investigation_entities;
DROP POLICY IF EXISTS platform_admin_bypass ON investigation_entities;
CREATE POLICY tenant_isolation ON investigation_entities FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON investigation_entities FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 16. investigation_notes (nullable tenant_id)
ALTER TABLE investigation_notes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS investigation_notes_tenant_isolation ON investigation_notes;
DROP POLICY IF EXISTS investigation_notes_platform_admin_bypass ON investigation_notes;
CREATE POLICY tenant_isolation ON investigation_notes FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON investigation_notes FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 17. knowledge_base (nullable tenant_id)
ALTER TABLE knowledge_base FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS knowledge_base_tenant_isolation ON knowledge_base;
DROP POLICY IF EXISTS knowledge_base_platform_admin_bypass ON knowledge_base;
CREATE POLICY tenant_isolation ON knowledge_base FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON knowledge_base FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 18. teams (nullable tenant_id)
ALTER TABLE teams FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS teams_tenant_isolation ON teams;
DROP POLICY IF EXISTS teams_platform_admin_bypass ON teams;
CREATE POLICY tenant_isolation ON teams FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON teams FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- 19. user_sessions (NOT NULL tenant_id)
ALTER TABLE user_sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS session_tenant_isolation ON user_sessions;
DROP POLICY IF EXISTS session_platform_admin_bypass ON user_sessions;
CREATE POLICY tenant_isolation ON user_sessions FOR ALL
    USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    WITH CHECK (tenant_id::text = current_setting('app.current_tenant_id', true));
CREATE POLICY platform_admin_bypass ON user_sessions FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');


-- ============================================================================
-- PHASE 3: Remove duplicate old-style policies from 7 tables
--          (keep new-style tenant_isolation + platform_admin_bypass)
-- ============================================================================

DROP POLICY IF EXISTS alerts_tenant_isolation ON alerts;
DROP POLICY IF EXISTS alerts_platform_admin_bypass ON alerts;

DROP POLICY IF EXISTS credentials_tenant_isolation ON credentials;
DROP POLICY IF EXISTS credentials_platform_admin_bypass ON credentials;

DROP POLICY IF EXISTS investigations_tenant_isolation ON investigations;
DROP POLICY IF EXISTS investigations_platform_admin_bypass ON investigations;

DROP POLICY IF EXISTS iocs_tenant_isolation ON iocs;
DROP POLICY IF EXISTS iocs_platform_admin_bypass ON iocs;

DROP POLICY IF EXISTS threat_feeds_tenant_isolation ON threat_feeds;
DROP POLICY IF EXISTS threat_feeds_platform_admin_bypass ON threat_feeds;

DROP POLICY IF EXISTS users_tenant_isolation ON users;
DROP POLICY IF EXISTS users_platform_admin_bypass ON users;

DROP POLICY IF EXISTS webhooks_tenant_isolation ON webhooks;
DROP POLICY IF EXISTS webhooks_platform_admin_bypass ON webhooks;


-- ============================================================================
-- PHASE 4: Fix platform_admin_bypass WITH CHECK on all FORCE-enabled tables
--          All existing platform_admin_bypass policies lack WITH CHECK,
--          which blocks INSERT/UPDATE for platform admins on FORCE tables.
-- ============================================================================

-- ai_token_usage
DROP POLICY IF EXISTS platform_admin_bypass ON ai_token_usage;
CREATE POLICY platform_admin_bypass ON ai_token_usage FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- alerts
DROP POLICY IF EXISTS platform_admin_bypass ON alerts;
CREATE POLICY platform_admin_bypass ON alerts FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- credentials
DROP POLICY IF EXISTS platform_admin_bypass ON credentials;
CREATE POLICY platform_admin_bypass ON credentials FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- edl_lists
DROP POLICY IF EXISTS platform_admin_bypass ON edl_lists;
CREATE POLICY platform_admin_bypass ON edl_lists FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- investigations
DROP POLICY IF EXISTS platform_admin_bypass ON investigations;
CREATE POLICY platform_admin_bypass ON investigations FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- iocs
DROP POLICY IF EXISTS platform_admin_bypass ON iocs;
CREATE POLICY platform_admin_bypass ON iocs FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- phishing_tests
DROP POLICY IF EXISTS platform_admin_bypass ON phishing_tests;
CREATE POLICY platform_admin_bypass ON phishing_tests FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- playbook_executions
DROP POLICY IF EXISTS platform_admin_bypass ON playbook_executions;
CREATE POLICY platform_admin_bypass ON playbook_executions FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- playbooks
DROP POLICY IF EXISTS platform_admin_bypass ON playbooks;
CREATE POLICY platform_admin_bypass ON playbooks FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- poc_tracking
DROP POLICY IF EXISTS platform_admin_bypass ON poc_tracking;
CREATE POLICY platform_admin_bypass ON poc_tracking FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- stripe_checkout_sessions
DROP POLICY IF EXISTS platform_admin_bypass ON stripe_checkout_sessions;
CREATE POLICY platform_admin_bypass ON stripe_checkout_sessions FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- tenant_audit_log
DROP POLICY IF EXISTS platform_admin_bypass ON tenant_audit_log;
CREATE POLICY platform_admin_bypass ON tenant_audit_log FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- tenant_claude_usage
DROP POLICY IF EXISTS platform_admin_bypass ON tenant_claude_usage;
CREATE POLICY platform_admin_bypass ON tenant_claude_usage FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- tenant_licenses
DROP POLICY IF EXISTS platform_admin_bypass ON tenant_licenses;
CREATE POLICY platform_admin_bypass ON tenant_licenses FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- tenant_usage_snapshots
DROP POLICY IF EXISTS platform_admin_bypass ON tenant_usage_snapshots;
CREATE POLICY platform_admin_bypass ON tenant_usage_snapshots FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- threat_feeds
DROP POLICY IF EXISTS platform_admin_bypass ON threat_feeds;
CREATE POLICY platform_admin_bypass ON threat_feeds FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- usage_events
DROP POLICY IF EXISTS platform_admin_bypass ON usage_events;
CREATE POLICY platform_admin_bypass ON usage_events FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- users
DROP POLICY IF EXISTS platform_admin_bypass ON users;
CREATE POLICY platform_admin_bypass ON users FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

-- webhooks
DROP POLICY IF EXISTS platform_admin_bypass ON webhooks;
CREATE POLICY platform_admin_bypass ON webhooks FOR ALL
    USING (current_setting('app.is_platform_admin', true) = 'true')
    WITH CHECK (current_setting('app.is_platform_admin', true) = 'true');

COMMIT;
