-- Migration 044: Add missing indexes on tenant_id columns
-- Fixes CRITICAL performance issue: RLS policies were doing full table scans
-- on 41 tables that have tenant_id but no index.

-- Group A: Investigation/chat related
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_investigation_chat_tenant_id ON investigation_chat(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_investigation_iocs_tenant_id ON investigation_iocs(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_investigation_ownership_log_tenant_id ON investigation_ownership_log(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_riggs_decisions_tenant_id ON riggs_decisions(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_approval_requests_tenant_id ON approval_requests(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_chat_action_audit_tenant_id ON chat_action_audit(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_chat_usage_analytics_tenant_id ON chat_usage_analytics(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_verdict_audit_log_tenant_id ON verdict_audit_log(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_escalation_history_tenant_id ON escalation_history(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_case_summaries_tenant_id ON case_summaries(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_riggs_feedback_tenant_id ON riggs_feedback(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_riggs_playbook_executions_tenant_id ON riggs_playbook_executions(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_playbook_execution_approvals_tenant_id ON playbook_execution_approvals(tenant_id);

-- Group B: Alert related
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alert_attachments_tenant_id ON alert_attachments(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alert_ioc_links_tenant_id ON alert_ioc_links(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alert_groups_tenant_id ON alert_groups(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_detection_hits_tenant_id ON detection_hits(tenant_id);

-- Group C: Campaign related
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_campaign_iocs_tenant_id ON campaign_iocs(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_campaign_members_tenant_id ON campaign_members(tenant_id);

-- Group D: Playbook related
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_playbook_versions_tenant_id ON playbook_versions(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_playbook_node_approvals_tenant_id ON playbook_node_approvals(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_playbook_files_tenant_id ON playbook_files(tenant_id);

-- Group E: Audit/credentials
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_tenant_id ON audit_log(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_credentials_vault_tenant_id ON credentials_vault(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_approval_tokens_tenant_id ON approval_tokens(tenant_id);

-- Group F: EDL
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_edl_credentials_tenant_id ON edl_credentials(tenant_id);

-- Group G: Email
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_inbound_email_queue_tenant_id ON inbound_email_queue(tenant_id);

-- Group H: Integration credentials
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_integration_credentials_tenant_id ON integration_credentials(tenant_id);

-- Group I: Assets
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_assets_tenant_id ON assets(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_history_tenant_id ON asset_history(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_identifiers_tenant_id ON asset_identifiers(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_relationships_tenant_id ON asset_relationships(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_asset_conflicts_tenant_id ON asset_conflicts(tenant_id);

-- Group J: IOC/Config
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_exclusion_list_tenant_id ON exclusion_list(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_blocklist_tenant_id ON ioc_blocklist(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_whitelist_tenant_id ON ioc_whitelist(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_ioc_enrichments_tenant_id ON ioc_enrichments(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_notification_rules_tenant_id ON notification_rules(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_escalation_config_tenant_id ON escalation_config(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_playbook_functions_tenant_id ON playbook_functions(tenant_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_playbook_lists_tenant_id ON playbook_lists(tenant_id);

-- Composite indexes for common RLS + filter patterns
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_tenant_status ON alerts(tenant_id, status);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_tenant_severity_created ON alerts(tenant_id, severity, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_investigations_tenant_state ON investigations(tenant_id, state);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_playbooks_tenant_enabled ON playbooks(tenant_id, is_enabled);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_log_tenant_created ON audit_log(tenant_id, created_at DESC);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_users_tenant_role ON users(tenant_id, role);
