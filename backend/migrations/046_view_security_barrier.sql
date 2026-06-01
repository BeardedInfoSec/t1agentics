-- ============================================================================
-- Migration 046: Add security_barrier to views that join RLS-protected tables
-- ============================================================================
-- Problem: Views bypass RLS by default. A malicious query against a view
-- can use leaky-function attacks to extract rows the caller should not see.
-- Fix: Recreate views WITH (security_barrier) so PostgreSQL enforces
-- the view's WHERE/JOIN conditions before evaluating user-supplied predicates.
-- ============================================================================
-- Idempotent: CREATE OR REPLACE VIEW is safe to re-run.
-- ============================================================================

BEGIN;

-- 1. alerts_with_investigation
-- Joins: alerts (RLS) + investigations (RLS)
CREATE OR REPLACE VIEW alerts_with_investigation WITH (security_barrier) AS
SELECT
    a.id,
    a.alert_id,
    a.title,
    a.description,
    a.severity,
    a.status,
    a.source,
    a.created_at,
    a.updated_at,
    CASE
        WHEN i.id IS NOT NULL THEN TRUE
        ELSE FALSE
    END as has_investigation,
    i.investigation_id,
    i.state as investigation_state,
    i.disposition as investigation_disposition,
    i.owner as investigation_owner,
    i.priority as investigation_priority
FROM alerts a
LEFT JOIN investigations i ON a.investigation_id = i.id;

-- 2. investigation_summary
-- Joins: investigations (RLS) + alerts (RLS) + investigation_notes (RLS)
CREATE OR REPLACE VIEW investigation_summary WITH (security_barrier) AS
SELECT
    i.id,
    i.investigation_id,
    i.state,
    i.disposition,
    i.priority,
    i.owner,
    i.alert_title,
    i.created_at,
    i.updated_at,
    a.alert_id,
    a.severity as alert_severity,
    a.status as alert_status,
    COUNT(n.id) as note_count
FROM investigations i
LEFT JOIN alerts a ON i.alert_id = a.id
LEFT JOIN investigation_notes n ON i.investigation_id = n.investigation_id
GROUP BY i.id, i.investigation_id, i.state, i.disposition, i.priority,
         i.owner, i.alert_title, i.created_at, i.updated_at,
         a.alert_id, a.severity, a.status;

-- 3. ai_token_usage_daily
-- Reads: ai_token_usage (RLS)
CREATE OR REPLACE VIEW ai_token_usage_daily WITH (security_barrier) AS
SELECT
    DATE(created_at) as usage_date,
    provider,
    model,
    COUNT(*) as request_count,
    SUM(prompt_tokens) as total_prompt_tokens,
    SUM(completion_tokens) as total_completion_tokens,
    SUM(total_tokens) as total_tokens,
    SUM(estimated_cost_cents) as total_cost_cents,
    AVG(response_time_ms) as avg_response_time_ms,
    COUNT(CASE WHEN status = 'success' THEN 1 END) as successful_requests,
    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_requests
FROM ai_token_usage
GROUP BY DATE(created_at), provider, model
ORDER BY usage_date DESC, provider, model;

-- 4. ai_token_usage_monthly
-- Reads: ai_token_usage (RLS)
CREATE OR REPLACE VIEW ai_token_usage_monthly WITH (security_barrier) AS
SELECT
    DATE_TRUNC('month', created_at) as usage_month,
    provider,
    model,
    COUNT(*) as request_count,
    SUM(prompt_tokens) as total_prompt_tokens,
    SUM(completion_tokens) as total_completion_tokens,
    SUM(total_tokens) as total_tokens,
    SUM(estimated_cost_cents) as total_cost_cents,
    AVG(response_time_ms) as avg_response_time_ms
FROM ai_token_usage
GROUP BY DATE_TRUNC('month', created_at), provider, model
ORDER BY usage_month DESC, provider, model;

-- 5. user_chat_statistics
-- Reads: chat_usage_analytics (RLS)
CREATE OR REPLACE VIEW user_chat_statistics WITH (security_barrier) AS
SELECT
    user_id,
    username,
    COUNT(*) FILTER (WHERE event_type = 'message_sent') as total_messages,
    COUNT(*) FILTER (WHERE event_type = 'quick_action_used') as quick_actions_used,
    COUNT(*) FILTER (WHERE event_type = 'action_requested') as actions_requested,
    COUNT(DISTINCT investigation_id) as investigations_participated,
    COUNT(DISTINCT session_id) as total_sessions,
    MIN(created_at) as first_activity,
    MAX(created_at) as last_activity,
    AVG(message_length) FILTER (WHERE message_length IS NOT NULL) as avg_message_length
FROM chat_usage_analytics
GROUP BY user_id, username;

-- 6. agent_accuracy_summary
-- Reads: agent_verdict_outcomes (no tenant_id, but references investigations which has RLS)
CREATE OR REPLACE VIEW agent_accuracy_summary WITH (security_barrier) AS
SELECT
    agent_id,
    agent_name,
    agent_tier,
    COUNT(*) as total_verdicts,
    COUNT(*) FILTER (WHERE was_correct = true) as correct_verdicts,
    COUNT(*) FILTER (WHERE was_correct = false) as incorrect_verdicts,
    COUNT(*) FILTER (WHERE was_overridden = true) as overridden_verdicts,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE was_correct = true) / NULLIF(COUNT(*) FILTER (WHERE was_correct IS NOT NULL), 0),
        2
    ) as accuracy_percent,
    ROUND(AVG(agent_confidence), 2) as avg_confidence,
    ROUND(AVG(agent_confidence) FILTER (WHERE was_correct = true), 2) as confidence_when_correct,
    ROUND(AVG(agent_confidence) FILTER (WHERE was_correct = false), 2) as confidence_when_wrong
FROM agent_verdict_outcomes
WHERE agent_verdict_at > CURRENT_TIMESTAMP - INTERVAL '30 days'
GROUP BY agent_id, agent_name, agent_tier;

-- 7. escalation_funnel
-- Reads: investigation_agent_paths (references investigations which has RLS)
CREATE OR REPLACE VIEW escalation_funnel WITH (security_barrier) AS
SELECT
    COUNT(*) as total_investigations,
    COUNT(*) FILTER (WHERE total_agents_involved >= 1) as reached_tier1,
    COUNT(*) FILTER (WHERE total_agents_involved >= 2 OR escalation_count >= 1) as reached_tier2,
    COUNT(*) FILTER (WHERE human_involved = true) as reached_human,
    COUNT(*) FILTER (WHERE automation_success = true) as auto_resolved,
    ROUND(100.0 * COUNT(*) FILTER (WHERE automation_success = true) / NULLIF(COUNT(*), 0), 2) as automation_rate,
    ROUND(100.0 * COUNT(*) FILTER (WHERE escalation_count >= 1) / NULLIF(COUNT(*), 0), 2) as escalation_rate
FROM investigation_agent_paths
WHERE created_at > CURRENT_TIMESTAMP - INTERVAL '30 days';

-- 8. asset_summary
-- Joins: assets (RLS) + asset_identifiers (RLS) + asset_relationships (RLS)
CREATE OR REPLACE VIEW asset_summary WITH (security_barrier) AS
SELECT
    a.id,
    a.hostname,
    a.fqdn,
    a.asset_type,
    a.os_family,
    a.criticality,
    a.status,
    a.environment,
    a.owner,
    a.department,
    a.first_seen,
    a.last_seen,
    COALESCE(i.identifier_count, 0) as identifier_count,
    COALESCE(r.relationship_count, 0) as relationship_count,
    a.ip_addresses,
    a.compliance_tags
FROM assets a
LEFT JOIN (
    SELECT asset_id, COUNT(*) as identifier_count
    FROM asset_identifiers
    GROUP BY asset_id
) i ON i.asset_id = a.id
LEFT JOIN (
    SELECT source_asset_id, COUNT(*) as relationship_count
    FROM asset_relationships
    GROUP BY source_asset_id
) r ON r.source_asset_id = a.id;

-- 9. stale_assets
-- Reads: assets (RLS)
CREATE OR REPLACE VIEW stale_assets WITH (security_barrier) AS
SELECT *
FROM assets
WHERE last_seen < CURRENT_TIMESTAMP - INTERVAL '7 days'
  AND status = 'active';

-- 10. discovery_source_health
-- Reads: discovery_sources (may have tenant_id)
CREATE OR REPLACE VIEW discovery_source_health WITH (security_barrier) AS
SELECT
    ds.id,
    ds.name,
    ds.source_type,
    ds.enabled,
    ds.sync_enabled,
    ds.last_sync_at,
    ds.last_sync_status,
    ds.last_sync_assets_found,
    ds.last_sync_duration_seconds,
    CASE
        WHEN ds.last_sync_at IS NULL THEN 'never_synced'
        WHEN ds.last_sync_at < CURRENT_TIMESTAMP - (ds.sync_interval_minutes * 2 || ' minutes')::INTERVAL THEN 'overdue'
        WHEN ds.last_sync_status = 'failed' THEN 'error'
        ELSE 'healthy'
    END as health_status
FROM discovery_sources ds;

-- 11. riggs_accuracy_stats
-- Reads: riggs_feedback (RLS)
CREATE OR REPLACE VIEW riggs_accuracy_stats WITH (security_barrier) AS
SELECT
    DATE(created_at) as analysis_date,
    riggs_mode,
    COUNT(*) as total_analyses,
    COUNT(*) FILTER (WHERE t1_match) as t1_agreement_count,
    COUNT(*) FILTER (WHERE verdict_match) as human_agreement_count,
    COUNT(*) FILTER (WHERE was_escalated) as escalation_count,
    ROUND(AVG(processing_time_ms)) as avg_processing_ms,
    ROUND(AVG(token_count)) as avg_tokens,
    ROUND(AVG(riggs_confidence)) as avg_confidence
FROM riggs_feedback
GROUP BY DATE(created_at), riggs_mode
ORDER BY analysis_date DESC, riggs_mode;

COMMIT;
