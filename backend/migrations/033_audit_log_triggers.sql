-- Migration 033: Replace RULE-based immutable audit logs with TRIGGER-based
-- PostgreSQL RULEs silently discard UPDATE/DELETE (hiding bugs).
-- TRIGGERs raise explicit errors, making violations visible.

-- ============================================================================
-- 1. ai_action_log
-- ============================================================================
DROP RULE IF EXISTS ai_action_log_no_update ON ai_action_log;
DROP RULE IF EXISTS ai_action_log_no_delete ON ai_action_log;

CREATE OR REPLACE FUNCTION prevent_ai_action_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'ai_action_log is immutable: % operations are not allowed', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_ai_action_log_no_update
    BEFORE UPDATE ON ai_action_log
    FOR EACH ROW EXECUTE FUNCTION prevent_ai_action_log_mutation();

CREATE TRIGGER trg_ai_action_log_no_delete
    BEFORE DELETE ON ai_action_log
    FOR EACH ROW EXECUTE FUNCTION prevent_ai_action_log_mutation();

-- ============================================================================
-- 2. investigation_audit_log
-- ============================================================================
DROP RULE IF EXISTS investigation_audit_no_update ON investigation_audit_log;
DROP RULE IF EXISTS investigation_audit_no_delete ON investigation_audit_log;

CREATE OR REPLACE FUNCTION prevent_investigation_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'investigation_audit_log is immutable: % operations are not allowed', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_investigation_audit_no_update
    BEFORE UPDATE ON investigation_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_investigation_audit_mutation();

CREATE TRIGGER trg_investigation_audit_no_delete
    BEFORE DELETE ON investigation_audit_log
    FOR EACH ROW EXECUTE FUNCTION prevent_investigation_audit_mutation();

-- ============================================================================
-- 3. agent_action_log
-- ============================================================================
DROP RULE IF EXISTS agent_action_log_no_update ON agent_action_log;
DROP RULE IF EXISTS agent_action_log_no_delete ON agent_action_log;

CREATE OR REPLACE FUNCTION prevent_agent_action_log_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'agent_action_log is immutable: % operations are not allowed', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_agent_action_log_no_update
    BEFORE UPDATE ON agent_action_log
    FOR EACH ROW EXECUTE FUNCTION prevent_agent_action_log_mutation();

CREATE TRIGGER trg_agent_action_log_no_delete
    BEFORE DELETE ON agent_action_log
    FOR EACH ROW EXECUTE FUNCTION prevent_agent_action_log_mutation();
