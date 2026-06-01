-- Reset alerts, investigations, and token usage
-- Run with: psql -U postgres -d T1 Agentics -f reset_data.sql

BEGIN;

-- Delete in order of dependencies
DELETE FROM chat_messages;
DELETE FROM agent_executions;
DELETE FROM investigation_actions;
DELETE FROM investigation_events;
DELETE FROM alert_attachments;
DELETE FROM alert_iocs;
DELETE FROM phishing_reports;
DELETE FROM investigations;
DELETE FROM alerts;
DELETE FROM ai_token_usage;

COMMIT;

SELECT 'Reset complete' as status;
