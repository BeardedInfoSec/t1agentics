-- ============================================================================
-- Migration 045: Fix RLS type comparisons for index usage
-- ============================================================================
-- Problem: All RLS policies use tenant_id::text = current_setting(...)
-- which forces UUID->TEXT conversion on every row, preventing index usage.
-- Fix: Cast the setting to UUID instead: tenant_id = current_setting(...)::uuid
-- This allows PostgreSQL to use existing tenant_id indexes.
-- ============================================================================
-- Idempotent: uses DROP POLICY IF EXISTS before CREATE POLICY.
-- Merges tenant_isolation + platform_admin_bypass into a single policy
-- per table for efficiency (fewer policy evaluations per query).
-- ============================================================================

-- ============================================================================
-- PHASE 1: Tables with standard tenant_isolation + platform_admin_bypass
-- (from rls_hardening.sql Phases 1 & 2, and add_tenant_id_to_tables.sql)
-- ============================================================================

-- Helper: Drop both old policies then create one combined policy
-- For each table: tenant_id = setting::uuid OR platform_admin = true

-- 1. connect_credentials
DROP POLICY IF EXISTS tenant_isolation ON connect_credentials;
DROP POLICY IF EXISTS platform_admin_bypass ON connect_credentials;
CREATE POLICY tenant_isolation_policy ON connect_credentials FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 2. connect_execution_log
DROP POLICY IF EXISTS tenant_isolation ON connect_execution_log;
DROP POLICY IF EXISTS platform_admin_bypass ON connect_execution_log;
CREATE POLICY tenant_isolation_policy ON connect_execution_log FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 3. connect_instances
DROP POLICY IF EXISTS tenant_isolation ON connect_instances;
DROP POLICY IF EXISTS platform_admin_bypass ON connect_instances;
CREATE POLICY tenant_isolation_policy ON connect_instances FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 4. connector_submissions
DROP POLICY IF EXISTS tenant_isolation ON connector_submissions;
DROP POLICY IF EXISTS platform_admin_bypass ON connector_submissions;
CREATE POLICY tenant_isolation_policy ON connector_submissions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 5. inbound_mailboxes
DROP POLICY IF EXISTS tenant_isolation ON inbound_mailboxes;
DROP POLICY IF EXISTS platform_admin_bypass ON inbound_mailboxes;
CREATE POLICY tenant_isolation_policy ON inbound_mailboxes FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 6. notifications
DROP POLICY IF EXISTS tenant_isolation ON notifications;
DROP POLICY IF EXISTS platform_admin_bypass ON notifications;
CREATE POLICY tenant_isolation_policy ON notifications FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 7. soar_executions
DROP POLICY IF EXISTS tenant_isolation ON soar_executions;
DROP POLICY IF EXISTS platform_admin_bypass ON soar_executions;
CREATE POLICY tenant_isolation_policy ON soar_executions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 8. soar_playbooks
DROP POLICY IF EXISTS tenant_isolation ON soar_playbooks;
DROP POLICY IF EXISTS platform_admin_bypass ON soar_playbooks;
CREATE POLICY tenant_isolation_policy ON soar_playbooks FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 9. trusted_senders
DROP POLICY IF EXISTS tenant_isolation ON trusted_senders;
DROP POLICY IF EXISTS platform_admin_bypass ON trusted_senders;
CREATE POLICY tenant_isolation_policy ON trusted_senders FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 10. usage_counters
DROP POLICY IF EXISTS tenant_isolation ON usage_counters;
DROP POLICY IF EXISTS platform_admin_bypass ON usage_counters;
CREATE POLICY tenant_isolation_policy ON usage_counters FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 11. action_requests
DROP POLICY IF EXISTS tenant_isolation ON action_requests;
DROP POLICY IF EXISTS platform_admin_bypass ON action_requests;
CREATE POLICY tenant_isolation_policy ON action_requests FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 12. agent_action_log
DROP POLICY IF EXISTS tenant_isolation ON agent_action_log;
DROP POLICY IF EXISTS platform_admin_bypass ON agent_action_log;
CREATE POLICY tenant_isolation_policy ON agent_action_log FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 13. agent_approval_requests
DROP POLICY IF EXISTS tenant_isolation ON agent_approval_requests;
DROP POLICY IF EXISTS platform_admin_bypass ON agent_approval_requests;
CREATE POLICY tenant_isolation_policy ON agent_approval_requests FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 14. agent_definitions
DROP POLICY IF EXISTS tenant_isolation ON agent_definitions;
DROP POLICY IF EXISTS platform_admin_bypass ON agent_definitions;
CREATE POLICY tenant_isolation_policy ON agent_definitions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 15. agent_executions
DROP POLICY IF EXISTS tenant_isolation ON agent_executions;
DROP POLICY IF EXISTS platform_admin_bypass ON agent_executions;
CREATE POLICY tenant_isolation_policy ON agent_executions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 16. ai_action_log
DROP POLICY IF EXISTS tenant_isolation ON ai_action_log;
DROP POLICY IF EXISTS platform_admin_bypass ON ai_action_log;
CREATE POLICY tenant_isolation_policy ON ai_action_log FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 17. ai_agents
DROP POLICY IF EXISTS tenant_isolation ON ai_agents;
DROP POLICY IF EXISTS platform_admin_bypass ON ai_agents;
CREATE POLICY tenant_isolation_policy ON ai_agents FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 18. api_keys
DROP POLICY IF EXISTS tenant_isolation ON api_keys;
DROP POLICY IF EXISTS platform_admin_bypass ON api_keys;
CREATE POLICY tenant_isolation_policy ON api_keys FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 19. campaigns
DROP POLICY IF EXISTS tenant_isolation ON campaigns;
DROP POLICY IF EXISTS platform_admin_bypass ON campaigns;
CREATE POLICY tenant_isolation_policy ON campaigns FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 20. correlation_decisions
DROP POLICY IF EXISTS tenant_isolation ON correlation_decisions;
DROP POLICY IF EXISTS platform_admin_bypass ON correlation_decisions;
CREATE POLICY tenant_isolation_policy ON correlation_decisions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 21. enrichment_cache
DROP POLICY IF EXISTS tenant_isolation ON enrichment_cache;
DROP POLICY IF EXISTS platform_admin_bypass ON enrichment_cache;
CREATE POLICY tenant_isolation_policy ON enrichment_cache FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 22. enrichment_jobs
DROP POLICY IF EXISTS tenant_isolation ON enrichment_jobs;
DROP POLICY IF EXISTS platform_admin_bypass ON enrichment_jobs;
CREATE POLICY tenant_isolation_policy ON enrichment_jobs FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 23. integrations
DROP POLICY IF EXISTS tenant_isolation ON integrations;
DROP POLICY IF EXISTS platform_admin_bypass ON integrations;
CREATE POLICY tenant_isolation_policy ON integrations FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 24. investigation_audit_log
DROP POLICY IF EXISTS tenant_isolation ON investigation_audit_log;
DROP POLICY IF EXISTS platform_admin_bypass ON investigation_audit_log;
CREATE POLICY tenant_isolation_policy ON investigation_audit_log FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 25. investigation_entities
DROP POLICY IF EXISTS tenant_isolation ON investigation_entities;
DROP POLICY IF EXISTS platform_admin_bypass ON investigation_entities;
CREATE POLICY tenant_isolation_policy ON investigation_entities FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 26. investigation_notes
DROP POLICY IF EXISTS tenant_isolation ON investigation_notes;
DROP POLICY IF EXISTS platform_admin_bypass ON investigation_notes;
CREATE POLICY tenant_isolation_policy ON investigation_notes FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 27. teams
DROP POLICY IF EXISTS tenant_isolation ON teams;
DROP POLICY IF EXISTS platform_admin_bypass ON teams;
CREATE POLICY tenant_isolation_policy ON teams FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 28. user_sessions
DROP POLICY IF EXISTS tenant_isolation ON user_sessions;
DROP POLICY IF EXISTS platform_admin_bypass ON user_sessions;
CREATE POLICY tenant_isolation_policy ON user_sessions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- ============================================================================
-- PHASE 2: Tables from rls_hardening.sql Phase 4
-- These only had platform_admin_bypass recreated; their tenant_isolation
-- came from add_tenant_id_to_tables.sql or 012_multitenancy.sql.
-- Fix both policies in one combined policy.
-- ============================================================================

-- 29. ai_token_usage
DROP POLICY IF EXISTS tenant_isolation ON ai_token_usage;
DROP POLICY IF EXISTS platform_admin_bypass ON ai_token_usage;
CREATE POLICY tenant_isolation_policy ON ai_token_usage FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 30. alerts
DROP POLICY IF EXISTS tenant_isolation ON alerts;
DROP POLICY IF EXISTS platform_admin_bypass ON alerts;
CREATE POLICY tenant_isolation_policy ON alerts FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 31. credentials
DROP POLICY IF EXISTS tenant_isolation ON credentials;
DROP POLICY IF EXISTS platform_admin_bypass ON credentials;
CREATE POLICY tenant_isolation_policy ON credentials FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 32. edl_lists (tenant_id is VARCHAR, not UUID -- use text comparison)
DROP POLICY IF EXISTS tenant_isolation ON edl_lists;
DROP POLICY IF EXISTS platform_admin_bypass ON edl_lists;
CREATE POLICY tenant_isolation_policy ON edl_lists FOR ALL
    USING (
        tenant_id::text = current_setting('app.current_tenant_id', true)
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id::text = current_setting('app.current_tenant_id', true)
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 33. investigations
DROP POLICY IF EXISTS tenant_isolation ON investigations;
DROP POLICY IF EXISTS platform_admin_bypass ON investigations;
CREATE POLICY tenant_isolation_policy ON investigations FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 34. iocs
DROP POLICY IF EXISTS tenant_isolation ON iocs;
DROP POLICY IF EXISTS platform_admin_bypass ON iocs;
CREATE POLICY tenant_isolation_policy ON iocs FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 35. phishing_tests
DROP POLICY IF EXISTS tenant_isolation ON phishing_tests;
DROP POLICY IF EXISTS platform_admin_bypass ON phishing_tests;
CREATE POLICY tenant_isolation_policy ON phishing_tests FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 36. playbook_executions
DROP POLICY IF EXISTS tenant_isolation ON playbook_executions;
DROP POLICY IF EXISTS platform_admin_bypass ON playbook_executions;
CREATE POLICY tenant_isolation_policy ON playbook_executions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 37. playbooks
DROP POLICY IF EXISTS tenant_isolation ON playbooks;
DROP POLICY IF EXISTS platform_admin_bypass ON playbooks;
CREATE POLICY tenant_isolation_policy ON playbooks FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 38. poc_tracking
DROP POLICY IF EXISTS tenant_isolation ON poc_tracking;
DROP POLICY IF EXISTS platform_admin_bypass ON poc_tracking;
CREATE POLICY tenant_isolation_policy ON poc_tracking FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 39. stripe_checkout_sessions
DROP POLICY IF EXISTS tenant_isolation ON stripe_checkout_sessions;
DROP POLICY IF EXISTS platform_admin_bypass ON stripe_checkout_sessions;
CREATE POLICY tenant_isolation_policy ON stripe_checkout_sessions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 40. tenant_audit_log
DROP POLICY IF EXISTS tenant_isolation ON tenant_audit_log;
DROP POLICY IF EXISTS platform_admin_bypass ON tenant_audit_log;
CREATE POLICY tenant_isolation_policy ON tenant_audit_log FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 41. tenant_claude_usage
DROP POLICY IF EXISTS tenant_isolation ON tenant_claude_usage;
DROP POLICY IF EXISTS platform_admin_bypass ON tenant_claude_usage;
CREATE POLICY tenant_isolation_policy ON tenant_claude_usage FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 42. tenant_licenses
DROP POLICY IF EXISTS tenant_isolation ON tenant_licenses;
DROP POLICY IF EXISTS platform_admin_bypass ON tenant_licenses;
CREATE POLICY tenant_isolation_policy ON tenant_licenses FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 43. tenant_usage_snapshots
DROP POLICY IF EXISTS tenant_isolation ON tenant_usage_snapshots;
DROP POLICY IF EXISTS platform_admin_bypass ON tenant_usage_snapshots;
CREATE POLICY tenant_isolation_policy ON tenant_usage_snapshots FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 44. threat_feeds
DROP POLICY IF EXISTS tenant_isolation ON threat_feeds;
DROP POLICY IF EXISTS platform_admin_bypass ON threat_feeds;
CREATE POLICY tenant_isolation_policy ON threat_feeds FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 45. usage_events
DROP POLICY IF EXISTS tenant_isolation ON usage_events;
DROP POLICY IF EXISTS platform_admin_bypass ON usage_events;
CREATE POLICY tenant_isolation_policy ON usage_events FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 46. users
DROP POLICY IF EXISTS tenant_isolation ON users;
DROP POLICY IF EXISTS platform_admin_bypass ON users;
CREATE POLICY tenant_isolation_policy ON users FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 47. webhooks
DROP POLICY IF EXISTS tenant_isolation ON webhooks;
DROP POLICY IF EXISTS platform_admin_bypass ON webhooks;
CREATE POLICY tenant_isolation_policy ON webhooks FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- ============================================================================
-- PHASE 3: Tables from add_tenant_id_to_tables.sql (41 tables)
-- These all have tenant_isolation + platform_admin_bypass with ::text
-- ============================================================================

-- 48. investigation_chat
DROP POLICY IF EXISTS tenant_isolation ON investigation_chat;
DROP POLICY IF EXISTS platform_admin_bypass ON investigation_chat;
CREATE POLICY tenant_isolation_policy ON investigation_chat FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 49. investigation_iocs
DROP POLICY IF EXISTS tenant_isolation ON investigation_iocs;
DROP POLICY IF EXISTS platform_admin_bypass ON investigation_iocs;
CREATE POLICY tenant_isolation_policy ON investigation_iocs FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 50. investigation_ownership_log
DROP POLICY IF EXISTS tenant_isolation ON investigation_ownership_log;
DROP POLICY IF EXISTS platform_admin_bypass ON investigation_ownership_log;
CREATE POLICY tenant_isolation_policy ON investigation_ownership_log FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 51. riggs_decisions
DROP POLICY IF EXISTS tenant_isolation ON riggs_decisions;
DROP POLICY IF EXISTS platform_admin_bypass ON riggs_decisions;
CREATE POLICY tenant_isolation_policy ON riggs_decisions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 52. approval_requests
DROP POLICY IF EXISTS tenant_isolation ON approval_requests;
DROP POLICY IF EXISTS platform_admin_bypass ON approval_requests;
CREATE POLICY tenant_isolation_policy ON approval_requests FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 53. chat_action_audit
DROP POLICY IF EXISTS tenant_isolation ON chat_action_audit;
DROP POLICY IF EXISTS platform_admin_bypass ON chat_action_audit;
CREATE POLICY tenant_isolation_policy ON chat_action_audit FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 54. chat_usage_analytics
DROP POLICY IF EXISTS tenant_isolation ON chat_usage_analytics;
DROP POLICY IF EXISTS platform_admin_bypass ON chat_usage_analytics;
CREATE POLICY tenant_isolation_policy ON chat_usage_analytics FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 55. verdict_audit_log
DROP POLICY IF EXISTS tenant_isolation ON verdict_audit_log;
DROP POLICY IF EXISTS platform_admin_bypass ON verdict_audit_log;
CREATE POLICY tenant_isolation_policy ON verdict_audit_log FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 56. escalation_history
DROP POLICY IF EXISTS tenant_isolation ON escalation_history;
DROP POLICY IF EXISTS platform_admin_bypass ON escalation_history;
CREATE POLICY tenant_isolation_policy ON escalation_history FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 57. case_summaries
DROP POLICY IF EXISTS tenant_isolation ON case_summaries;
DROP POLICY IF EXISTS platform_admin_bypass ON case_summaries;
CREATE POLICY tenant_isolation_policy ON case_summaries FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 58. riggs_feedback
DROP POLICY IF EXISTS tenant_isolation ON riggs_feedback;
DROP POLICY IF EXISTS platform_admin_bypass ON riggs_feedback;
CREATE POLICY tenant_isolation_policy ON riggs_feedback FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 59. riggs_playbook_executions
DROP POLICY IF EXISTS tenant_isolation ON riggs_playbook_executions;
DROP POLICY IF EXISTS platform_admin_bypass ON riggs_playbook_executions;
CREATE POLICY tenant_isolation_policy ON riggs_playbook_executions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 60. playbook_execution_approvals
DROP POLICY IF EXISTS tenant_isolation ON playbook_execution_approvals;
DROP POLICY IF EXISTS platform_admin_bypass ON playbook_execution_approvals;
CREATE POLICY tenant_isolation_policy ON playbook_execution_approvals FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 61. alert_attachments
DROP POLICY IF EXISTS tenant_isolation ON alert_attachments;
DROP POLICY IF EXISTS platform_admin_bypass ON alert_attachments;
CREATE POLICY tenant_isolation_policy ON alert_attachments FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 62. alert_ioc_links
DROP POLICY IF EXISTS tenant_isolation ON alert_ioc_links;
DROP POLICY IF EXISTS platform_admin_bypass ON alert_ioc_links;
CREATE POLICY tenant_isolation_policy ON alert_ioc_links FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 63. alert_groups
DROP POLICY IF EXISTS tenant_isolation ON alert_groups;
DROP POLICY IF EXISTS platform_admin_bypass ON alert_groups;
CREATE POLICY tenant_isolation_policy ON alert_groups FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 64. detection_hits
DROP POLICY IF EXISTS tenant_isolation ON detection_hits;
DROP POLICY IF EXISTS platform_admin_bypass ON detection_hits;
CREATE POLICY tenant_isolation_policy ON detection_hits FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 65. campaign_iocs
DROP POLICY IF EXISTS tenant_isolation ON campaign_iocs;
DROP POLICY IF EXISTS platform_admin_bypass ON campaign_iocs;
CREATE POLICY tenant_isolation_policy ON campaign_iocs FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 66. campaign_members
DROP POLICY IF EXISTS tenant_isolation ON campaign_members;
DROP POLICY IF EXISTS platform_admin_bypass ON campaign_members;
CREATE POLICY tenant_isolation_policy ON campaign_members FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 67. playbook_versions
DROP POLICY IF EXISTS tenant_isolation ON playbook_versions;
DROP POLICY IF EXISTS platform_admin_bypass ON playbook_versions;
CREATE POLICY tenant_isolation_policy ON playbook_versions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 68. playbook_node_approvals
DROP POLICY IF EXISTS tenant_isolation ON playbook_node_approvals;
DROP POLICY IF EXISTS platform_admin_bypass ON playbook_node_approvals;
CREATE POLICY tenant_isolation_policy ON playbook_node_approvals FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 69. playbook_files
DROP POLICY IF EXISTS tenant_isolation ON playbook_files;
DROP POLICY IF EXISTS platform_admin_bypass ON playbook_files;
CREATE POLICY tenant_isolation_policy ON playbook_files FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 70. audit_log
DROP POLICY IF EXISTS tenant_isolation ON audit_log;
DROP POLICY IF EXISTS platform_admin_bypass ON audit_log;
CREATE POLICY tenant_isolation_policy ON audit_log FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 71. credentials_vault
DROP POLICY IF EXISTS tenant_isolation ON credentials_vault;
DROP POLICY IF EXISTS platform_admin_bypass ON credentials_vault;
CREATE POLICY tenant_isolation_policy ON credentials_vault FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 72. approval_tokens
DROP POLICY IF EXISTS tenant_isolation ON approval_tokens;
DROP POLICY IF EXISTS platform_admin_bypass ON approval_tokens;
CREATE POLICY tenant_isolation_policy ON approval_tokens FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 73. edl_credentials
DROP POLICY IF EXISTS tenant_isolation ON edl_credentials;
DROP POLICY IF EXISTS platform_admin_bypass ON edl_credentials;
CREATE POLICY tenant_isolation_policy ON edl_credentials FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 74. inbound_email_queue
DROP POLICY IF EXISTS tenant_isolation ON inbound_email_queue;
DROP POLICY IF EXISTS platform_admin_bypass ON inbound_email_queue;
CREATE POLICY tenant_isolation_policy ON inbound_email_queue FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 75. integration_credentials
DROP POLICY IF EXISTS tenant_isolation ON integration_credentials;
DROP POLICY IF EXISTS platform_admin_bypass ON integration_credentials;
CREATE POLICY tenant_isolation_policy ON integration_credentials FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 76. assets
DROP POLICY IF EXISTS tenant_isolation ON assets;
DROP POLICY IF EXISTS platform_admin_bypass ON assets;
CREATE POLICY tenant_isolation_policy ON assets FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 77. asset_history
DROP POLICY IF EXISTS tenant_isolation ON asset_history;
DROP POLICY IF EXISTS platform_admin_bypass ON asset_history;
CREATE POLICY tenant_isolation_policy ON asset_history FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 78. asset_identifiers
DROP POLICY IF EXISTS tenant_isolation ON asset_identifiers;
DROP POLICY IF EXISTS platform_admin_bypass ON asset_identifiers;
CREATE POLICY tenant_isolation_policy ON asset_identifiers FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 79. asset_relationships
DROP POLICY IF EXISTS tenant_isolation ON asset_relationships;
DROP POLICY IF EXISTS platform_admin_bypass ON asset_relationships;
CREATE POLICY tenant_isolation_policy ON asset_relationships FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 80. asset_conflicts
DROP POLICY IF EXISTS tenant_isolation ON asset_conflicts;
DROP POLICY IF EXISTS platform_admin_bypass ON asset_conflicts;
CREATE POLICY tenant_isolation_policy ON asset_conflicts FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 81. exclusion_list
DROP POLICY IF EXISTS tenant_isolation ON exclusion_list;
DROP POLICY IF EXISTS platform_admin_bypass ON exclusion_list;
CREATE POLICY tenant_isolation_policy ON exclusion_list FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 82. ioc_blocklist
DROP POLICY IF EXISTS tenant_isolation ON ioc_blocklist;
DROP POLICY IF EXISTS platform_admin_bypass ON ioc_blocklist;
CREATE POLICY tenant_isolation_policy ON ioc_blocklist FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 83. ioc_whitelist
DROP POLICY IF EXISTS tenant_isolation ON ioc_whitelist;
DROP POLICY IF EXISTS platform_admin_bypass ON ioc_whitelist;
CREATE POLICY tenant_isolation_policy ON ioc_whitelist FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 84. ioc_enrichments
DROP POLICY IF EXISTS tenant_isolation ON ioc_enrichments;
DROP POLICY IF EXISTS platform_admin_bypass ON ioc_enrichments;
CREATE POLICY tenant_isolation_policy ON ioc_enrichments FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 85. notification_rules
DROP POLICY IF EXISTS tenant_isolation ON notification_rules;
DROP POLICY IF EXISTS platform_admin_bypass ON notification_rules;
CREATE POLICY tenant_isolation_policy ON notification_rules FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 86. escalation_config
DROP POLICY IF EXISTS tenant_isolation ON escalation_config;
DROP POLICY IF EXISTS platform_admin_bypass ON escalation_config;
CREATE POLICY tenant_isolation_policy ON escalation_config FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 87. playbook_functions
DROP POLICY IF EXISTS tenant_isolation ON playbook_functions;
DROP POLICY IF EXISTS platform_admin_bypass ON playbook_functions;
CREATE POLICY tenant_isolation_policy ON playbook_functions FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 88. playbook_lists
DROP POLICY IF EXISTS tenant_isolation ON playbook_lists;
DROP POLICY IF EXISTS platform_admin_bypass ON playbook_lists;
CREATE POLICY tenant_isolation_policy ON playbook_lists FOR ALL
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- ============================================================================
-- PHASE 4: Tables with granular per-operation policies (special handling)
-- These have split SELECT/INSERT/UPDATE/DELETE policies instead of FOR ALL.
-- Fix each individual policy to use ::uuid instead of ::text.
-- ============================================================================

-- 89. knowledge_base (from migration 030_kb_rls_builtin_read.sql)
DROP POLICY IF EXISTS tenant_read ON knowledge_base;
DROP POLICY IF EXISTS tenant_write ON knowledge_base;
DROP POLICY IF EXISTS tenant_modify ON knowledge_base;
DROP POLICY IF EXISTS tenant_remove ON knowledge_base;

CREATE POLICY tenant_read ON knowledge_base FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR source = 'builtin'
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

CREATE POLICY tenant_write ON knowledge_base FOR INSERT
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

CREATE POLICY tenant_modify ON knowledge_base FOR UPDATE
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

CREATE POLICY tenant_remove ON knowledge_base FOR DELETE
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 90. connector_definitions (from migration 032_connector_marketplace_rls_fix.sql)
DROP POLICY IF EXISTS connector_read ON connector_definitions;
DROP POLICY IF EXISTS connector_write ON connector_definitions;
DROP POLICY IF EXISTS connector_modify ON connector_definitions;
DROP POLICY IF EXISTS connector_remove ON connector_definitions;

CREATE POLICY connector_read ON connector_definitions FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR tenant_id IS NULL
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

CREATE POLICY connector_write ON connector_definitions FOR INSERT
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

CREATE POLICY connector_modify ON connector_definitions FOR UPDATE
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

CREATE POLICY connector_remove ON connector_definitions FOR DELETE
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- 91. playbook_templates (from migration 032_connector_marketplace_rls_fix.sql)
DROP POLICY IF EXISTS template_read ON playbook_templates;
DROP POLICY IF EXISTS template_write ON playbook_templates;
DROP POLICY IF EXISTS template_modify ON playbook_templates;
DROP POLICY IF EXISTS template_remove ON playbook_templates;

CREATE POLICY template_read ON playbook_templates FOR SELECT
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR tenant_id IS NULL
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

CREATE POLICY template_write ON playbook_templates FOR INSERT
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

CREATE POLICY template_modify ON playbook_templates FOR UPDATE
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    )
    WITH CHECK (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

CREATE POLICY template_remove ON playbook_templates FOR DELETE
    USING (
        tenant_id = current_setting('app.current_tenant_id', true)::uuid
        OR current_setting('app.is_platform_admin', true) = 'true'
    );

-- Done.
