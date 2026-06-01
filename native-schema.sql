--
-- PostgreSQL database dump
--

\restrict M559rbxaLV38Dss3md1uCcqTaRODIbtFP0GniFm0KSQeIwDTkNxB2zmW86xpJ3g

-- Dumped from database version 15.17 (Debian 15.17-1.pgdg12+1)
-- Dumped by pg_dump version 15.17 (Debian 15.17-1.pgdg12+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

-- uuid-ossp is unavailable on the bundled (pgserver) Postgres; shim its
-- uuid_generate_v4() over the built-in gen_random_uuid().
CREATE OR REPLACE FUNCTION public.uuid_generate_v4() RETURNS uuid LANGUAGE sql AS 'SELECT gen_random_uuid()';


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: -
--



--
-- Name: acquire_lock(character varying, character varying, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.acquire_lock(p_lock_name character varying, p_node_id character varying, p_ttl_seconds integer DEFAULT 60) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_acquired BOOLEAN := FALSE;
BEGIN
    -- Try to insert new lock or update expired lock
    INSERT INTO distributed_locks (lock_name, holder_node_id, expires_at)
    VALUES (p_lock_name, p_node_id, CURRENT_TIMESTAMP + (p_ttl_seconds || ' seconds')::INTERVAL)
    ON CONFLICT (lock_name) DO UPDATE
    SET holder_node_id = p_node_id,
        acquired_at = CURRENT_TIMESTAMP,
        expires_at = CURRENT_TIMESTAMP + (p_ttl_seconds || ' seconds')::INTERVAL
    WHERE distributed_locks.expires_at < CURRENT_TIMESTAMP
       OR distributed_locks.holder_node_id = p_node_id;

    -- Check if we got the lock
    SELECT holder_node_id = p_node_id INTO v_acquired
    FROM distributed_locks
    WHERE lock_name = p_lock_name;

    RETURN COALESCE(v_acquired, FALSE);
END;
$$;


--
-- Name: audit_verdict_change(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.audit_verdict_change() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF (OLD.disposition IS DISTINCT FROM NEW.disposition) OR
       (OLD.confidence IS DISTINCT FROM NEW.confidence AND ABS(COALESCE(OLD.confidence, 0) - COALESCE(NEW.confidence, 0)) >= 5) THEN

        INSERT INTO verdict_audit_log (
            investigation_id, change_type, previous_verdict, previous_confidence,
            new_verdict, new_confidence, reason, triggered_by, tenant_id
        ) VALUES (
            NEW.id,
            CASE
                WHEN NEW.triage_status = 'provisional' THEN 'provisional_set'
                WHEN NEW.triage_status = 'confirmed' THEN 'confirmed'
                WHEN NEW.triage_status = 'needs_review' THEN 'needs_review'
                ELSE 'confidence_change'
            END,
            OLD.disposition, OLD.confidence, NEW.disposition, NEW.confidence,
            'Automatic audit log',
            CASE
                WHEN NEW.triage_status IN ('provisional', 'enriching') THEN 'fast_triage'
                WHEN NEW.triage_status = 'confirmed' THEN 'merge_engine'
                ELSE 'system'
            END,
            NEW.tenant_id
        );
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: claim_job(character varying, character varying, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.claim_job(p_queue_name character varying, p_node_id character varying, p_lock_seconds integer DEFAULT 300) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_job_id UUID;
BEGIN
    -- Find and lock an available job
    -- Order by: priority (lowest number = highest priority), then created_at (FIFO within same priority)
    UPDATE job_queue
    SET status = 'processing',
        locked_by = p_node_id,
        locked_until = CURRENT_TIMESTAMP + (p_lock_seconds || ' seconds')::INTERVAL,
        started_at = CURRENT_TIMESTAMP,
        attempts = attempts + 1
    WHERE id = (
        SELECT id FROM job_queue
        WHERE queue_name = p_queue_name
          AND status = 'pending'
          AND scheduled_for <= CURRENT_TIMESTAMP
        ORDER BY priority ASC, created_at ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
    )
    RETURNING id INTO v_job_id;

    RETURN v_job_id;
END;
$$;


--
-- Name: cleanup_cluster_state(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.cleanup_cluster_state() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Mark nodes with stale heartbeats as unhealthy
    UPDATE cluster_nodes
    SET status = 'unhealthy'
    WHERE last_heartbeat < CURRENT_TIMESTAMP - INTERVAL '2 minutes'
      AND status = 'healthy';

    -- Remove very old stopped nodes
    DELETE FROM cluster_nodes
    WHERE status = 'stopped'
      AND last_heartbeat < CURRENT_TIMESTAMP - INTERVAL '1 day';

    -- Release expired locks
    DELETE FROM distributed_locks
    WHERE expires_at < CURRENT_TIMESTAMP;

    -- Reset stuck jobs (processing but lock expired)
    UPDATE job_queue
    SET status = 'pending',
        locked_by = NULL,
        locked_until = NULL
    WHERE status = 'processing'
      AND locked_until < CURRENT_TIMESTAMP;
END;
$$;


--
-- Name: complete_job(uuid, jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.complete_job(p_job_id uuid, p_result jsonb DEFAULT NULL::jsonb) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE job_queue
    SET status = 'completed',
        completed_at = CURRENT_TIMESTAMP,
        result = p_result,
        locked_by = NULL,
        locked_until = NULL
    WHERE id = p_job_id;

    RETURN FOUND;
END;
$$;


--
-- Name: create_playbook_version(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.create_playbook_version() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    next_version INTEGER;
BEGIN
    IF OLD.canvas_data IS DISTINCT FROM NEW.canvas_data THEN
        SELECT COALESCE(MAX(version_number), 0) + 1 INTO next_version
        FROM playbook_versions
        WHERE playbook_id = OLD.id;

        INSERT INTO playbook_versions (
            playbook_id, version_number, canvas_data, metadata,
            change_summary, created_at, tenant_id
        ) VALUES (
            OLD.id, next_version, OLD.canvas_data,
            jsonb_build_object(
                'name', OLD.name,
                'description', OLD.description,
                'is_enabled', OLD.is_enabled,
                'node_count', jsonb_array_length(COALESCE(OLD.canvas_data->'nodes', '[]'::jsonb))
            ),
            'Auto-saved before update', OLD.updated_at, OLD.tenant_id
        );

        NEW.version = next_version + 1;
    END IF;
    RETURN NEW;
END;
$$;


--
-- Name: enable_tenant_rls(text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.enable_tenant_rls(table_name text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
    EXECUTE format('DROP POLICY IF EXISTS platform_admin_bypass ON %I', table_name);
    EXECUTE format('
        CREATE POLICY tenant_isolation ON %I
        FOR ALL
        USING (
            tenant_id = COALESCE(
                NULLIF(current_setting(''app.current_tenant_id'', true), ''''),
                ''00000000-0000-0000-0000-ffffffffffff''
            )::uuid
        )
        WITH CHECK (
            tenant_id = COALESCE(
                NULLIF(current_setting(''app.current_tenant_id'', true), ''''),
                ''00000000-0000-0000-0000-ffffffffffff''
            )::uuid
        )
    ', table_name);
    EXECUTE format('
        CREATE POLICY platform_admin_bypass ON %I
        FOR ALL
        USING (
            COALESCE(current_setting(''app.is_platform_admin'', true), ''false'')::boolean = true
        )
    ', table_name);
END;
$$;


--
-- Name: expire_old_playbook_approvals(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.expire_old_playbook_approvals() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    UPDATE playbook_execution_approvals
    SET status = 'expired'
    WHERE status = 'pending'
    AND created_at < NOW() - INTERVAL '24 hours';
END;
$$;


--
-- Name: fail_job(uuid, text); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.fail_job(p_job_id uuid, p_error_message text) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_attempts INTEGER;
    v_max_attempts INTEGER;
BEGIN
    SELECT attempts, max_attempts INTO v_attempts, v_max_attempts
    FROM job_queue WHERE id = p_job_id;

    IF v_attempts >= v_max_attempts THEN
        -- Move to dead letter
        UPDATE job_queue
        SET status = 'dead',
            error_message = p_error_message,
            completed_at = CURRENT_TIMESTAMP,
            locked_by = NULL,
            locked_until = NULL
        WHERE id = p_job_id;
    ELSE
        -- Retry with exponential backoff
        UPDATE job_queue
        SET status = 'pending',
            error_message = p_error_message,
            scheduled_for = CURRENT_TIMESTAMP + ((2 ^ v_attempts) || ' minutes')::INTERVAL,
            locked_by = NULL,
            locked_until = NULL
        WHERE id = p_job_id;
    END IF;

    RETURN FOUND;
END;
$$;


--
-- Name: find_asset_by_hostname(character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.find_asset_by_hostname(p_hostname character varying) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_asset_id UUID;
BEGIN
    SELECT id INTO v_asset_id
    FROM assets
    WHERE LOWER(hostname) = LOWER(p_hostname)
       OR LOWER(fqdn) = LOWER(p_hostname)
    LIMIT 1;

    RETURN v_asset_id;
END;
$$;


--
-- Name: find_asset_by_identifier(character varying, character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.find_asset_by_identifier(p_identifier_type character varying, p_identifier_value character varying) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_asset_id UUID;
BEGIN
    SELECT asset_id INTO v_asset_id
    FROM asset_identifiers
    WHERE identifier_type = p_identifier_type
      AND identifier_value = p_identifier_value
    LIMIT 1;

    RETURN v_asset_id;
END;
$$;


--
-- Name: find_asset_by_ip(character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.find_asset_by_ip(p_ip character varying) RETURNS uuid
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_asset_id UUID;
BEGIN
    SELECT id INTO v_asset_id
    FROM assets
    WHERE ip_addresses @> to_jsonb(p_ip::text)
    LIMIT 1;

    RETURN v_asset_id;
END;
$$;


--
-- Name: generate_agent_system_name(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.generate_agent_system_name() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.system_name := 'Tier ' || NEW.tier || ' ' || NEW.focus || ' ' || NEW.role || ' Agent';
    RETURN NEW;
END;
$$;


--
-- Name: get_alert_with_investigation(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_alert_with_investigation(alert_uuid uuid) RETURNS TABLE(alert_id character varying, title character varying, severity character varying, status character varying, created_at timestamp with time zone, investigation_state character varying, investigation_owner character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT 
        a.alert_id,
        a.title,
        a.severity,
        a.status,
        a.created_at,
        i.state as investigation_state,
        i.owner as investigation_owner
    FROM alerts a
    LEFT JOIN investigations i ON a.investigation_id = i.id
    WHERE a.id = alert_uuid;
END;
$$;


--
-- Name: get_tenant_license_tier(uuid); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.get_tenant_license_tier(p_tenant_id uuid) RETURNS character varying
    LANGUAGE plpgsql STABLE
    AS $$
DECLARE
    v_tier VARCHAR;
BEGIN
    SELECT tl.tier INTO v_tier
    FROM tenant_licenses tl
    WHERE tl.tenant_id = p_tenant_id
      AND tl.is_active = true
      AND (tl.expires_at IS NULL OR tl.expires_at > NOW())
    ORDER BY tl.created_at DESC
    LIMIT 1;

    RETURN COALESCE(v_tier, 'community');
END;
$$;


--
-- Name: is_platform_admin(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.is_platform_admin() RETURNS boolean
    LANGUAGE plpgsql STABLE
    AS $$
BEGIN
    RETURN COALESCE(current_setting('app.is_platform_admin', true), 'false')::boolean;
END;
$$;


--
-- Name: prevent_agent_action_log_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_agent_action_log_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'agent_action_log is immutable: % operations are not allowed', TG_OP;
    RETURN NULL;
END;
$$;


--
-- Name: prevent_ai_action_log_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_ai_action_log_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'ai_action_log is immutable: % operations are not allowed', TG_OP;
    RETURN NULL;
END;
$$;


--
-- Name: prevent_investigation_audit_mutation(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.prevent_investigation_audit_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    RAISE EXCEPTION 'investigation_audit_log is immutable: % operations are not allowed', TG_OP;
    RETURN NULL;
END;
$$;


--
-- Name: record_asset_history(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.record_asset_history() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_changed_fields JSONB := '[]'::jsonb;
    v_old_values JSONB := '{}'::jsonb;
    v_new_values JSONB := '{}'::jsonb;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        -- Compare fields and record changes
        IF OLD.hostname IS DISTINCT FROM NEW.hostname THEN
            v_changed_fields = v_changed_fields || '"hostname"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('hostname', OLD.hostname);
            v_new_values = v_new_values || jsonb_build_object('hostname', NEW.hostname);
        END IF;
        IF OLD.criticality IS DISTINCT FROM NEW.criticality THEN
            v_changed_fields = v_changed_fields || '"criticality"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('criticality', OLD.criticality);
            v_new_values = v_new_values || jsonb_build_object('criticality', NEW.criticality);
        END IF;
        IF OLD.status IS DISTINCT FROM NEW.status THEN
            v_changed_fields = v_changed_fields || '"status"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('status', OLD.status);
            v_new_values = v_new_values || jsonb_build_object('status', NEW.status);
        END IF;
        IF OLD.owner IS DISTINCT FROM NEW.owner THEN
            v_changed_fields = v_changed_fields || '"owner"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('owner', OLD.owner);
            v_new_values = v_new_values || jsonb_build_object('owner', NEW.owner);
        END IF;
        IF OLD.ip_addresses::text IS DISTINCT FROM NEW.ip_addresses::text THEN
            v_changed_fields = v_changed_fields || '"ip_addresses"'::jsonb;
            v_old_values = v_old_values || jsonb_build_object('ip_addresses', OLD.ip_addresses);
            v_new_values = v_new_values || jsonb_build_object('ip_addresses', NEW.ip_addresses);
        END IF;

        -- Only insert if something actually changed
        IF jsonb_array_length(v_changed_fields) > 0 THEN
            INSERT INTO asset_history (
                asset_id, change_type, changed_fields, old_values, new_values,
                changed_by, change_source
            ) VALUES (
                NEW.id, 'updated', v_changed_fields, v_old_values, v_new_values,
                NEW.updated_by, 'trigger'
            );
        END IF;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO asset_history (
            asset_id, change_type, new_values, changed_by, change_source
        ) VALUES (
            NEW.id, 'created', to_jsonb(NEW), NEW.created_by, 'trigger'
        );
    END IF;

    RETURN NEW;
END;
$$;


--
-- Name: release_lock(character varying, character varying); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.release_lock(p_lock_name character varying, p_node_id character varying) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_released BOOLEAN := FALSE;
BEGIN
    DELETE FROM distributed_locks
    WHERE lock_name = p_lock_name
      AND holder_node_id = p_node_id;

    GET DIAGNOSTICS v_released = ROW_COUNT;
    RETURN v_released > 0;
END;
$$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: alerts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alerts (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    alert_id character varying(255) NOT NULL,
    external_id character varying(255),
    title character varying(500) NOT NULL,
    description text,
    severity character varying(20) DEFAULT 'medium'::character varying NOT NULL,
    status character varying(20) DEFAULT 'open'::character varying NOT NULL,
    source character varying(100),
    source_type character varying(50),
    category character varying(100),
    subcategory character varying(100),
    confidence numeric(5,2),
    event_class character varying(20) DEFAULT 'assertion'::character varying NOT NULL,
    vendor character varying(100),
    vendor_confidence numeric(5,4),
    vendor_reputation numeric(5,4),
    false_positive_rate numeric(5,4),
    linked_observation_ids uuid[] DEFAULT '{}'::uuid[],
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    raw_event jsonb DEFAULT '{}'::jsonb NOT NULL,
    search_vector tsvector,
    investigation_id uuid,
    fingerprint character varying(64),
    fingerprint_fields text[],
    alert_group_id uuid,
    is_primary boolean DEFAULT true,
    duplicate_count integer DEFAULT 0,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    ai_verdict character varying(50),
    ai_confidence numeric(5,2),
    ai_reasoning text,
    enrichment_status character varying(20) DEFAULT 'pending'::character varying,
    enrichment_summary jsonb DEFAULT '{}'::jsonb,
    ai_summary text,
    resolved_at timestamp with time zone,
    resolution character varying(255),
    disposition character varying(50),
    closed_by character varying(255),
    closed_at timestamp with time zone,
    ai_triage_queued boolean DEFAULT false,
    ai_triage_queued_at timestamp with time zone,
    display_id integer NOT NULL,
    tenant_id uuid NOT NULL,
    assigned_to character varying(255),
    assigned_at timestamp without time zone,
    triage_enrichment_hash character varying(128),
    triage_status character varying(50) DEFAULT 'pending'::character varying,
    triage_blocked_reason text,
    extracted_entities jsonb DEFAULT '{}'::jsonb,
    correlation_score integer,
    correlation_decision character varying(50),
    correlation_reasons jsonb DEFAULT '[]'::jsonb,
    playbook_results jsonb DEFAULT '[]'::jsonb,
    playbook_executions_run text[] DEFAULT '{}'::text[],
    sensitivity character varying(20) DEFAULT 'internal'::character varying NOT NULL,
    sla_minutes integer,
    tags text[] DEFAULT '{}'::text[] NOT NULL,
    CONSTRAINT alerts_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (100)::numeric))),
    CONSTRAINT alerts_enrichment_status_check CHECK (((enrichment_status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying, 'complete'::character varying, 'failed'::character varying, 'skipped'::character varying])::text[]))),
    CONSTRAINT alerts_event_class_check CHECK (((event_class)::text = ANY ((ARRAY['observation'::character varying, 'assertion'::character varying, 'decision'::character varying])::text[]))),
    CONSTRAINT alerts_false_positive_rate_check CHECK (((false_positive_rate >= (0)::numeric) AND (false_positive_rate <= (1)::numeric))),
    CONSTRAINT alerts_severity_check CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT alerts_status_check CHECK (((status)::text = ANY ((ARRAY['open'::character varying, 'investigating'::character varying, 'resolved'::character varying, 'closed'::character varying, 'triaged'::character varying, 'enriched'::character varying])::text[]))),
    CONSTRAINT alerts_vendor_confidence_check CHECK (((vendor_confidence >= (0)::numeric) AND (vendor_confidence <= (1)::numeric))),
    CONSTRAINT alerts_vendor_reputation_check CHECK (((vendor_reputation >= (0)::numeric) AND (vendor_reputation <= (1)::numeric)))
);

ALTER TABLE ONLY public.alerts FORCE ROW LEVEL SECURITY;


--
-- Name: TABLE alerts; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.alerts IS 'Primary alert storage with JSONB raw_event for AI reasoning';


--
-- Name: search_alerts(text, character varying, character varying, integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.search_alerts(search_query text DEFAULT NULL::text, filter_status character varying DEFAULT NULL::character varying, filter_severity character varying DEFAULT NULL::character varying, limit_count integer DEFAULT 100) RETURNS SETOF public.alerts
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN QUERY
    SELECT a.*
    FROM alerts a
    WHERE 
        (search_query IS NULL OR search_vector @@ plainto_tsquery('english', search_query))
        AND (filter_status IS NULL OR a.status = filter_status)
        AND (filter_severity IS NULL OR a.severity = filter_severity)
    ORDER BY a.created_at DESC
    LIMIT limit_count;
END;
$$;


--
-- Name: update_asset_timestamp(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_asset_timestamp() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


--
-- Name: update_discovered_apis_search_vector(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_discovered_apis_search_vector() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.search_vector := to_tsvector('english',
        COALESCE(NEW.name, '') || ' ' ||
        COALESCE(NEW.description, '') || ' ' ||
        COALESCE(NEW.provider, '') || ' ' ||
        COALESCE(NEW.category, '')
    );
    RETURN NEW;
END;
$$;


--
-- Name: update_updated_at_column(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;


--
-- Name: action_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.action_requests (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    request_id character varying(100) DEFAULT ('ACT-'::text || upper(SUBSTRING((gen_random_uuid())::text FROM 1 FOR 8))) NOT NULL,
    action_type character varying(50) NOT NULL,
    target_type character varying(50) NOT NULL,
    target_value text NOT NULL,
    target_metadata jsonb DEFAULT '{}'::jsonb,
    integration_id uuid,
    integration_name character varying(100),
    integration_action_id character varying(100),
    parameters jsonb DEFAULT '{}'::jsonb,
    investigation_id uuid,
    alert_id uuid,
    requested_by_agent uuid,
    requested_by_human character varying(100),
    status character varying(30) DEFAULT 'pending'::character varying NOT NULL,
    priority character varying(20) DEFAULT 'medium'::character varying,
    expires_at timestamp with time zone,
    approved_by character varying(100),
    approved_at timestamp with time zone,
    denied_by character varying(100),
    denied_at timestamp with time zone,
    denial_reason text,
    executed_at timestamp with time zone,
    execution_result jsonb,
    error_message text,
    is_reversible boolean DEFAULT false,
    rollback_action_type character varying(50),
    rolled_back_at timestamp with time zone,
    rolled_back_by character varying(100),
    reasoning text,
    confidence numeric(3,2),
    evidence jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid,
    CONSTRAINT action_requests_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric))),
    CONSTRAINT action_requests_priority_check CHECK (((priority)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying])::text[]))),
    CONSTRAINT action_requests_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'denied'::character varying, 'executing'::character varying, 'completed'::character varying, 'failed'::character varying, 'expired'::character varying, 'cancelled'::character varying])::text[])))
);

ALTER TABLE ONLY public.action_requests FORCE ROW LEVEL SECURITY;


--
-- Name: action_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.action_types (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    action_type character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    description text,
    category character varying(50) NOT NULL,
    target_type character varying(50) NOT NULL,
    risk_level character varying(20) DEFAULT 'high'::character varying,
    requires_approval boolean DEFAULT true,
    approval_timeout_minutes integer DEFAULT 240,
    is_reversible boolean DEFAULT false,
    reverse_action_type character varying(50),
    integration_mappings jsonb DEFAULT '{}'::jsonb,
    min_agent_tier integer DEFAULT 2,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT action_types_risk_level_check CHECK (((risk_level)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[])))
);


--
-- Name: affiliate_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.affiliate_codes (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_id uuid NOT NULL,
    code character varying(10) NOT NULL,
    is_active boolean DEFAULT true NOT NULL,
    total_referrals integer DEFAULT 0 NOT NULL,
    total_conversions integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

ALTER TABLE ONLY public.affiliate_codes FORCE ROW LEVEL SECURITY;


--
-- Name: agent_verdict_outcomes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_verdict_outcomes (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid,
    agent_execution_id uuid,
    agent_id uuid,
    agent_tier integer NOT NULL,
    agent_name character varying(255),
    agent_verdict character varying(50),
    agent_confidence numeric(5,2),
    final_verdict character varying(50),
    final_disposition character varying(50),
    resolved_by character varying(100),
    was_correct boolean,
    was_overridden boolean DEFAULT false,
    override_reason text,
    agent_verdict_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    final_verdict_at timestamp with time zone,
    time_to_resolution_ms integer,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: agent_accuracy_summary; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.agent_accuracy_summary WITH (security_barrier='true') AS
 SELECT agent_verdict_outcomes.agent_id,
    agent_verdict_outcomes.agent_name,
    agent_verdict_outcomes.agent_tier,
    count(*) AS total_verdicts,
    count(*) FILTER (WHERE (agent_verdict_outcomes.was_correct = true)) AS correct_verdicts,
    count(*) FILTER (WHERE (agent_verdict_outcomes.was_correct = false)) AS incorrect_verdicts,
    count(*) FILTER (WHERE (agent_verdict_outcomes.was_overridden = true)) AS overridden_verdicts,
    round(((100.0 * (count(*) FILTER (WHERE (agent_verdict_outcomes.was_correct = true)))::numeric) / (NULLIF(count(*) FILTER (WHERE (agent_verdict_outcomes.was_correct IS NOT NULL)), 0))::numeric), 2) AS accuracy_percent,
    round(avg(agent_verdict_outcomes.agent_confidence), 2) AS avg_confidence,
    round(avg(agent_verdict_outcomes.agent_confidence) FILTER (WHERE (agent_verdict_outcomes.was_correct = true)), 2) AS confidence_when_correct,
    round(avg(agent_verdict_outcomes.agent_confidence) FILTER (WHERE (agent_verdict_outcomes.was_correct = false)), 2) AS confidence_when_wrong
   FROM public.agent_verdict_outcomes
  WHERE (agent_verdict_outcomes.agent_verdict_at > (CURRENT_TIMESTAMP - '30 days'::interval))
  GROUP BY agent_verdict_outcomes.agent_id, agent_verdict_outcomes.agent_name, agent_verdict_outcomes.agent_tier;


--
-- Name: agent_action_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_action_log (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    execution_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    action character varying(100) NOT NULL,
    target_type character varying(100),
    target_id character varying(255),
    action_type character varying(50) NOT NULL,
    status character varying(50) NOT NULL,
    required_approval boolean DEFAULT false,
    approved_by character varying(255),
    approved_at timestamp with time zone,
    blocked_by_guardrail character varying(255),
    guardrail_rule text,
    reasoning text,
    confidence numeric(3,2),
    result jsonb,
    error_message text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp with time zone,
    duration_ms integer,
    tenant_id uuid,
    CONSTRAINT agent_action_log_action_type_check CHECK (((action_type)::text = ANY ((ARRAY['read'::character varying, 'write'::character varying, 'destructive'::character varying])::text[]))),
    CONSTRAINT agent_action_log_status_check CHECK (((status)::text = ANY ((ARRAY['attempted'::character varying, 'completed'::character varying, 'blocked'::character varying, 'pending_approval'::character varying, 'approved'::character varying, 'denied'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.agent_action_log FORCE ROW LEVEL SECURITY;


--
-- Name: agent_approval_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_approval_requests (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    request_id character varying(100) NOT NULL,
    execution_id uuid NOT NULL,
    agent_id uuid NOT NULL,
    action_log_id uuid,
    action character varying(100) NOT NULL,
    target_type character varying(100),
    target_id character varying(255),
    action_type character varying(50) NOT NULL,
    reasoning text NOT NULL,
    confidence numeric(3,2),
    evidence jsonb DEFAULT '[]'::jsonb,
    risk_assessment text,
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    responded_by character varying(255),
    responded_at timestamp with time zone,
    response_note text,
    requested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone NOT NULL,
    notified_users jsonb DEFAULT '[]'::jsonb,
    notification_sent_at timestamp with time zone,
    created_at timestamp with time zone,
    tenant_id uuid,
    CONSTRAINT agent_approval_requests_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'denied'::character varying, 'expired'::character varying, 'cancelled'::character varying])::text[])))
);

ALTER TABLE ONLY public.agent_approval_requests FORCE ROW LEVEL SECURITY;


--
-- Name: agent_definitions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_definitions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    tier integer NOT NULL,
    focus character varying(100) NOT NULL,
    role character varying(100) NOT NULL,
    system_name character varying(255) NOT NULL,
    codename character varying(100),
    description text,
    permissions jsonb DEFAULT '{"applications": [], "require_approval": true, "max_actions_per_run": 50, "approval_timeout_minutes": 30}'::jsonb NOT NULL,
    guardrails jsonb DEFAULT '{"never_rules": [], "rate_limits": {"max_enrichments_per_minute": 20, "max_investigations_per_hour": 30, "max_actions_per_investigation": 50, "cooldown_after_destructive_action": 300}, "allowed_hours": {"enabled": false}, "escalation_triggers": [], "confidence_threshold": 0.6}'::jsonb NOT NULL,
    model_config jsonb DEFAULT '{"model": "claude-sonnet-4-20250514", "provider": "anthropic", "temperature": 0.1, "context_window": 64000, "max_cost_per_run": 2.00, "max_tokens_per_task": 8000}'::jsonb NOT NULL,
    audit_config jsonb DEFAULT '{"log_level": "standard", "require_reasoning": true, "evidence_retention_days": 90}'::jsonb NOT NULL,
    enabled boolean DEFAULT true,
    created_by character varying(255),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    version character varying(20) DEFAULT '1.0.0'::character varying,
    tenant_id uuid,
    CONSTRAINT agent_definitions_tier_check CHECK ((tier = ANY (ARRAY[1, 2, 3])))
);

ALTER TABLE ONLY public.agent_definitions FORCE ROW LEVEL SECURITY;


--
-- Name: agent_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_executions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    execution_id character varying(100) NOT NULL,
    agent_id uuid NOT NULL,
    trigger_type character varying(50) NOT NULL,
    trigger_source_id character varying(255),
    trigger_source_type character varying(100),
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    duration_ms integer,
    reasoning jsonb DEFAULT '[]'::jsonb,
    evidence jsonb DEFAULT '[]'::jsonb,
    actions jsonb DEFAULT '[]'::jsonb,
    outcome jsonb DEFAULT '{"summary": null, "verdict": null, "confidence": null, "recommendations": []}'::jsonb,
    compliance jsonb DEFAULT '{"actions_blocked": 0, "actions_attempted": 0, "actions_completed": 0, "approvals_granted": 0, "approvals_requested": 0, "guardrails_triggered": []}'::jsonb,
    tokens_used integer DEFAULT 0,
    cost_usd numeric(10,4) DEFAULT 0,
    error_message text,
    error_details jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    llm_metrics jsonb DEFAULT '{}'::jsonb,
    tenant_id uuid,
    actions_taken integer DEFAULT 0,
    CONSTRAINT agent_executions_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'paused'::character varying, 'awaiting_approval'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying, 'timeout'::character varying])::text[]))),
    CONSTRAINT agent_executions_trigger_type_check CHECK (((trigger_type)::text = ANY ((ARRAY['alert'::character varying, 'scheduled'::character varying, 'manual'::character varying, 'escalation'::character varying, 'webhook'::character varying])::text[])))
);

ALTER TABLE ONLY public.agent_executions FORCE ROW LEVEL SECURITY;


--
-- Name: agent_performance_daily; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_performance_daily (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    metric_date date NOT NULL,
    agent_id uuid,
    agent_name character varying(255),
    agent_tier integer,
    executions_total integer DEFAULT 0,
    executions_completed integer DEFAULT 0,
    executions_failed integer DEFAULT 0,
    verdicts_issued integer DEFAULT 0,
    verdicts_correct integer DEFAULT 0,
    verdicts_overridden integer DEFAULT 0,
    accuracy_rate numeric(5,2),
    override_rate numeric(5,2),
    escalations_received integer DEFAULT 0,
    escalations_sent integer DEFAULT 0,
    escalation_rate numeric(5,2),
    avg_confidence numeric(5,2),
    confidence_when_correct numeric(5,2),
    confidence_when_wrong numeric(5,2),
    total_tokens_used bigint DEFAULT 0,
    total_cost_cents numeric(12,4) DEFAULT 0,
    avg_cost_per_execution_cents numeric(10,4),
    avg_execution_time_ms integer,
    avg_time_to_verdict_ms integer,
    min_execution_time_ms integer,
    max_execution_time_ms integer,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: agent_rollback_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_rollback_actions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    execution_id uuid NOT NULL,
    original_action_id character varying(100) NOT NULL,
    original_action_type character varying(100) NOT NULL,
    target_type character varying(100) NOT NULL,
    target_id character varying(500) NOT NULL,
    rollback_method character varying(100) NOT NULL,
    rollback_params jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone NOT NULL,
    executed_at timestamp with time zone,
    executed_by character varying(255),
    success boolean,
    result jsonb,
    execution_note text
);


--
-- Name: agent_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_templates (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    template_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    category character varying(100),
    tier integer NOT NULL,
    focus character varying(100) NOT NULL,
    role character varying(100) NOT NULL,
    permissions jsonb NOT NULL,
    guardrails jsonb NOT NULL,
    model_config jsonb NOT NULL,
    audit_config jsonb NOT NULL,
    usage_count integer DEFAULT 0,
    is_default boolean DEFAULT false,
    is_public boolean DEFAULT true,
    created_by character varying(255),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT agent_templates_tier_check CHECK ((tier = ANY (ARRAY[1, 2, 3])))
);


--
-- Name: ai_action_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_action_log (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id character varying(255) NOT NULL,
    action_type character varying(100) NOT NULL,
    action_description text NOT NULL,
    agent_name character varying(100) NOT NULL,
    agent_version character varying(50),
    status character varying(50) NOT NULL,
    confidence numeric(5,2),
    input_data jsonb DEFAULT '{}'::jsonb,
    output_data jsonb DEFAULT '{}'::jsonb,
    error_details text,
    started_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp with time zone,
    duration_ms integer,
    metadata jsonb DEFAULT '{}'::jsonb,
    tenant_id uuid,
    CONSTRAINT ai_action_log_status_check CHECK (((status)::text = ANY ((ARRAY['SUCCESS'::character varying, 'FAILED'::character varying, 'PARTIAL'::character varying, 'SKIPPED'::character varying])::text[])))
);

ALTER TABLE ONLY public.ai_action_log FORCE ROW LEVEL SECURITY;


--
-- Name: ai_agent_activity; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_agent_activity (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    agent_id character varying(100) NOT NULL,
    investigation_id character varying(255),
    alert_id character varying(255),
    activity_type character varying(50) NOT NULL,
    result jsonb,
    confidence numeric(3,2),
    duration_seconds integer,
    status character varying(50) NOT NULL,
    error_message text,
    started_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp with time zone,
    CONSTRAINT ai_agent_activity_activity_type_check CHECK (((activity_type)::text = ANY ((ARRAY['l1_triage'::character varying, 'l2_investigation'::character varying, 'enrichment_decision'::character varying, 'response_assessment'::character varying])::text[]))),
    CONSTRAINT ai_agent_activity_status_check CHECK (((status)::text = ANY ((ARRAY['started'::character varying, 'completed'::character varying, 'error'::character varying])::text[])))
);


--
-- Name: ai_agent_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_agent_credentials (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    agent_id uuid NOT NULL,
    api_key text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_rotated_at timestamp with time zone
);


--
-- Name: ai_agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_agents (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    agent_id character varying(100) NOT NULL,
    name character varying(100) NOT NULL,
    user_name character varying(100) NOT NULL,
    level integer NOT NULL,
    display_name character varying(200),
    provider character varying(50) NOT NULL,
    model character varying(200) NOT NULL,
    system_prompt text NOT NULL,
    endpoint_url character varying(500),
    enabled boolean DEFAULT true,
    verified boolean DEFAULT false,
    last_used_at timestamp with time zone,
    usage_count integer DEFAULT 0,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid,
    CONSTRAINT ai_agents_level_check CHECK ((level = ANY (ARRAY[1, 2, 3]))),
    CONSTRAINT ai_agents_provider_check CHECK (((provider)::text = ANY ((ARRAY['claude'::character varying, 'lmstudio'::character varying, 'openai'::character varying, 'custom'::character varying])::text[])))
);

ALTER TABLE ONLY public.ai_agents FORCE ROW LEVEL SECURITY;


--
-- Name: ai_providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_providers (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    provider_type character varying(50) NOT NULL,
    base_url character varying(500) NOT NULL,
    api_key text,
    models jsonb DEFAULT '[]'::jsonb,
    selected_model character varying(255),
    tier1_model character varying(255),
    tier2_model character varying(255),
    tier3_model character varying(255),
    chat_model character varying(255),
    is_default boolean DEFAULT false,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    api_key_encrypted text
);


--
-- Name: ai_token_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ai_token_usage (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    request_id character varying(100) NOT NULL,
    provider character varying(50) NOT NULL,
    model character varying(255) NOT NULL,
    integration_id character varying(100),
    prompt_tokens integer DEFAULT 0 NOT NULL,
    completion_tokens integer DEFAULT 0 NOT NULL,
    total_tokens integer DEFAULT 0 NOT NULL,
    estimated_cost_cents numeric(10,4) DEFAULT 0,
    endpoint character varying(500),
    request_type character varying(50),
    investigation_id character varying(100),
    alert_id character varying(100),
    user_id character varying(100),
    agent_id character varying(100),
    status character varying(20) DEFAULT 'success'::character varying NOT NULL,
    response_time_ms integer,
    error_message text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid,
    model_load_time_ms integer,
    inference_time_ms integer,
    is_cold_start boolean DEFAULT false,
    cache_creation_tokens integer DEFAULT 0 NOT NULL,
    cache_read_tokens integer DEFAULT 0 NOT NULL,
    CONSTRAINT ai_token_usage_status_check CHECK (((status)::text = ANY ((ARRAY['success'::character varying, 'failed'::character varying, 'timeout'::character varying, 'rate_limited'::character varying])::text[])))
);

ALTER TABLE ONLY public.ai_token_usage FORCE ROW LEVEL SECURITY;


--
-- Name: ai_token_usage_daily; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.ai_token_usage_daily WITH (security_barrier='true') AS
 SELECT date(ai_token_usage.created_at) AS usage_date,
    ai_token_usage.provider,
    ai_token_usage.model,
    count(*) AS request_count,
    sum(ai_token_usage.prompt_tokens) AS total_prompt_tokens,
    sum(ai_token_usage.completion_tokens) AS total_completion_tokens,
    sum(ai_token_usage.total_tokens) AS total_tokens,
    sum(ai_token_usage.estimated_cost_cents) AS total_cost_cents,
    avg(ai_token_usage.response_time_ms) AS avg_response_time_ms,
    count(
        CASE
            WHEN ((ai_token_usage.status)::text = 'success'::text) THEN 1
            ELSE NULL::integer
        END) AS successful_requests,
    count(
        CASE
            WHEN ((ai_token_usage.status)::text = 'failed'::text) THEN 1
            ELSE NULL::integer
        END) AS failed_requests
   FROM public.ai_token_usage
  GROUP BY (date(ai_token_usage.created_at)), ai_token_usage.provider, ai_token_usage.model
  ORDER BY (date(ai_token_usage.created_at)) DESC, ai_token_usage.provider, ai_token_usage.model;


--
-- Name: ai_token_usage_monthly; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.ai_token_usage_monthly WITH (security_barrier='true') AS
 SELECT date_trunc('month'::text, ai_token_usage.created_at) AS usage_month,
    ai_token_usage.provider,
    ai_token_usage.model,
    count(*) AS request_count,
    sum(ai_token_usage.prompt_tokens) AS total_prompt_tokens,
    sum(ai_token_usage.completion_tokens) AS total_completion_tokens,
    sum(ai_token_usage.total_tokens) AS total_tokens,
    sum(ai_token_usage.estimated_cost_cents) AS total_cost_cents,
    avg(ai_token_usage.response_time_ms) AS avg_response_time_ms
   FROM public.ai_token_usage
  GROUP BY (date_trunc('month'::text, ai_token_usage.created_at)), ai_token_usage.provider, ai_token_usage.model
  ORDER BY (date_trunc('month'::text, ai_token_usage.created_at)) DESC, ai_token_usage.provider, ai_token_usage.model;


--
-- Name: alert_attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_attachments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    attachment_id character varying(100) DEFAULT ('ATT-'::text || upper("substring"((gen_random_uuid())::text, 1, 8))) NOT NULL,
    alert_id character varying(255),
    filename character varying(255) NOT NULL,
    original_filename character varying(255) NOT NULL,
    file_size bigint NOT NULL,
    mime_type character varying(100),
    storage_path text NOT NULL,
    storage_type character varying(20) DEFAULT 'local'::character varying,
    md5_hash character varying(32),
    sha1_hash character varying(40),
    sha256_hash character varying(64),
    description text,
    uploaded_by character varying(100),
    analysis_status character varying(30) DEFAULT 'pending'::character varying,
    is_malicious boolean,
    threat_score integer,
    analysis_results jsonb DEFAULT '{}'::jsonb,
    uploaded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    analyzed_at timestamp with time zone,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    investigation_id character varying(255),
    CONSTRAINT alert_attachments_analysis_status_check CHECK (((analysis_status)::text = ANY ((ARRAY['pending'::character varying, 'analyzing'::character varying, 'clean'::character varying, 'suspicious'::character varying, 'malicious'::character varying, 'error'::character varying])::text[]))),
    CONSTRAINT alert_attachments_storage_type_check CHECK (((storage_type)::text = ANY ((ARRAY['local'::character varying, 's3'::character varying, 'azure'::character varying, 'gcs'::character varying])::text[]))),
    CONSTRAINT alert_attachments_threat_score_check CHECK (((threat_score >= 0) AND (threat_score <= 100)))
);

ALTER TABLE ONLY public.alert_attachments FORCE ROW LEVEL SECURITY;


--
-- Name: alert_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    fingerprint character varying(64) NOT NULL,
    primary_alert_id uuid,
    dedupe_config_id uuid,
    alert_count integer DEFAULT 1,
    first_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    status character varying(20) DEFAULT 'active'::character varying,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT alert_groups_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'resolved'::character varying, 'expired'::character varying])::text[])))
);

ALTER TABLE ONLY public.alert_groups FORCE ROW LEVEL SECURITY;


--
-- Name: alert_ioc_links; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.alert_ioc_links (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    alert_id character varying(255) NOT NULL,
    ioc_value character varying(500) NOT NULL,
    ioc_type character varying(50) NOT NULL,
    extraction_method character varying(50) DEFAULT 'regex'::character varying,
    extraction_source character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT alert_ioc_links_ioc_type_check CHECK (((ioc_type)::text = ANY ((ARRAY['ip'::character varying, 'domain'::character varying, 'hash_md5'::character varying, 'hash_sha1'::character varying, 'hash_sha256'::character varying, 'url'::character varying, 'email'::character varying, 'cve'::character varying])::text[])))
);

ALTER TABLE ONLY public.alert_ioc_links FORCE ROW LEVEL SECURITY;


--
-- Name: alerts_display_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.alerts_display_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: alerts_display_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.alerts_display_id_seq OWNED BY public.alerts.display_id;


--
-- Name: investigations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigations (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id character varying(255) NOT NULL,
    alert_id uuid,
    state character varying(50) DEFAULT 'NEW'::character varying NOT NULL,
    disposition character varying(50) DEFAULT 'UNKNOWN'::character varying,
    priority character varying(10) DEFAULT 'P3'::character varying,
    owner character varying(100),
    alert_title character varying(500),
    executive_summary text,
    confidence numeric(5,2),
    severity character varying(20),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp with time zone,
    assigned_at timestamp with time zone,
    investigation_data jsonb DEFAULT '{}'::jsonb,
    owner_type character varying(20) DEFAULT 'unassigned'::character varying,
    blocked_reason text,
    blocked_at timestamp with time zone,
    resolution_type character varying(50),
    resolution_notes text,
    closed_by character varying(100),
    sla_breach_at timestamp with time zone,
    last_activity_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    resolved_at timestamp with time zone,
    resolved_by character varying(100),
    escalated_to_tier integer,
    escalated_at timestamp with time zone,
    escalated_by character varying(255),
    escalation_reason text,
    display_id integer NOT NULL,
    tenant_id uuid NOT NULL,
    entity_summary jsonb DEFAULT '{}'::jsonb,
    primary_entity_type character varying(100),
    primary_entity_value character varying(500),
    user_count integer DEFAULT 0,
    host_count integer DEFAULT 0,
    triage_status character varying(50) DEFAULT 'pending'::character varying,
    provisional_verdict character varying(50),
    provisional_confidence numeric(5,2),
    provisional_at timestamp with time zone,
    enrichment_progress integer DEFAULT 0,
    enrichment_total_iocs integer DEFAULT 0,
    provisional_reasoning text,
    final_verdict character varying(50),
    final_confidence numeric(5,2),
    final_reasoning text,
    confirmed_at timestamp with time zone,
    enrichment_completed_iocs integer DEFAULT 0,
    enrichment_high_risk_hits integer DEFAULT 0,
    merge_version integer DEFAULT 0,
    last_merge_at timestamp with time zone,
    verdict_delta jsonb DEFAULT '[]'::jsonb,
    sensitivity character varying(20) DEFAULT 'internal'::character varying NOT NULL,
    acknowledged_at timestamp with time zone,
    CONSTRAINT investigations_disposition_check CHECK (((disposition)::text = ANY ((ARRAY['MALICIOUS'::character varying, 'SUSPICIOUS'::character varying, 'BENIGN'::character varying, 'TRUE_POSITIVE'::character varying, 'FALSE_POSITIVE'::character varying, 'BENIGN_POSITIVE'::character varying, 'NEEDS_INVESTIGATION'::character varying, 'INCONCLUSIVE'::character varying, 'UNKNOWN'::character varying])::text[]))),
    CONSTRAINT investigations_owner_type_check CHECK (((owner_type)::text = ANY ((ARRAY['unassigned'::character varying, 'human'::character varying, 'agent'::character varying, 'team'::character varying])::text[]))),
    CONSTRAINT investigations_priority_check CHECK (((priority)::text = ANY ((ARRAY['P1'::character varying, 'P2'::character varying, 'P3'::character varying, 'P4'::character varying])::text[]))),
    CONSTRAINT investigations_resolution_type_check CHECK (((resolution_type)::text = ANY ((ARRAY['verified_malicious'::character varying, 'false_positive'::character varying, 'benign_activity'::character varying, 'inconclusive'::character varying, 'duplicate'::character varying, 'escalated'::character varying, 'auto_closed'::character varying])::text[]))),
    CONSTRAINT investigations_severity_check CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT investigations_state_check CHECK (((state)::text = ANY ((ARRAY['NEW'::character varying, 'TRIAGE_RUNNING'::character varying, 'TRIAGE_PROVISIONAL'::character varying, 'ENRICHMENT_RUNNING'::character varying, 'MERGE_PENDING'::character varying, 'ANALYZING'::character varying, 'CONFIRMED'::character varying, 'NEEDS_REVIEW'::character varying, 'RIGGS_REVIEW'::character varying, 'ESCALATED'::character varying, 'IN_PROGRESS'::character varying, 'CLOSED'::character varying])::text[])))
);

ALTER TABLE ONLY public.investigations FORCE ROW LEVEL SECURITY;


--
-- Name: TABLE investigations; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.investigations IS 'Investigation workflow with state machine';


--
-- Name: COLUMN investigations.disposition; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.investigations.disposition IS 'Canonical verdicts from models/verdict.py: MALICIOUS, SUSPICIOUS, BENIGN, TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_POSITIVE, NEEDS_INVESTIGATION, INCONCLUSIVE, UNKNOWN';


--
-- Name: alerts_with_investigation; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.alerts_with_investigation WITH (security_barrier='true') AS
 SELECT a.id,
    a.alert_id,
    a.title,
    a.description,
    a.severity,
    a.status,
    a.source,
    a.created_at,
    a.updated_at,
        CASE
            WHEN (i.id IS NOT NULL) THEN true
            ELSE false
        END AS has_investigation,
    i.investigation_id,
    i.state AS investigation_state,
    i.disposition AS investigation_disposition,
    i.owner AS investigation_owner,
    i.priority AS investigation_priority
   FROM (public.alerts a
     LEFT JOIN public.investigations i ON ((a.investigation_id = i.id)));


--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    key_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    key_hash character varying(255) NOT NULL,
    role character varying(20) DEFAULT 'user'::character varying NOT NULL,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone,
    last_used timestamp with time zone,
    enabled boolean DEFAULT true,
    tenant_id uuid NOT NULL,
    CONSTRAINT api_keys_role_check CHECK (((role)::text = ANY ((ARRAY['admin'::character varying, 'analyst'::character varying, 'read_only'::character varying, 'user'::character varying])::text[])))
);

ALTER TABLE ONLY public.api_keys FORCE ROW LEVEL SECURITY;


--
-- Name: approval_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.approval_requests (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid,
    action_type character varying(50) NOT NULL,
    action_details jsonb DEFAULT '{}'::jsonb,
    requested_by character varying(100) NOT NULL,
    requested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    status character varying(20) DEFAULT 'pending'::character varying,
    approved_by character varying(100),
    approved_at timestamp with time zone,
    denial_reason text,
    expires_at timestamp with time zone,
    priority character varying(10) DEFAULT 'P3'::character varying,
    risk_level character varying(20) DEFAULT 'medium'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT approval_requests_priority_check CHECK (((priority)::text = ANY ((ARRAY['P1'::character varying, 'P2'::character varying, 'P3'::character varying, 'P4'::character varying])::text[]))),
    CONSTRAINT approval_requests_risk_level_check CHECK (((risk_level)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT approval_requests_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'denied'::character varying, 'expired'::character varying])::text[])))
);

ALTER TABLE ONLY public.approval_requests FORCE ROW LEVEL SECURITY;


--
-- Name: approval_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.approval_tokens (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    token_id character varying(100) NOT NULL,
    token_secret character varying(100) NOT NULL,
    action_type character varying(100) NOT NULL,
    entity_type character varying(50) NOT NULL,
    entity_id character varying(100) NOT NULL,
    action character varying(20) NOT NULL,
    ttl_minutes integer DEFAULT 60,
    require_auth boolean DEFAULT false,
    used boolean DEFAULT false,
    used_at timestamp with time zone,
    used_by character varying(255),
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(255),
    metadata jsonb DEFAULT '{}'::jsonb,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.approval_tokens FORCE ROW LEVEL SECURITY;


--
-- Name: asset_conflicts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_conflicts (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    asset_id uuid,
    conflicting_asset_id uuid,
    conflict_type character varying(50) NOT NULL,
    conflict_field character varying(100),
    source_a character varying(100),
    source_b character varying(100),
    value_a jsonb,
    value_b jsonb,
    status character varying(30) DEFAULT 'pending'::character varying,
    resolution character varying(50),
    resolved_by character varying(255),
    resolved_at timestamp with time zone,
    resolution_notes text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    discovery_job_id uuid,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT asset_conflicts_conflict_type_check CHECK (((conflict_type)::text = ANY ((ARRAY['duplicate_identifier'::character varying, 'conflicting_attributes'::character varying, 'merge_required'::character varying, 'ownership_conflict'::character varying, 'stale_data'::character varying, 'orphaned_relationship'::character varying])::text[]))),
    CONSTRAINT asset_conflicts_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'resolved'::character varying, 'ignored'::character varying])::text[])))
);

ALTER TABLE ONLY public.asset_conflicts FORCE ROW LEVEL SECURITY;


--
-- Name: asset_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_history (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    asset_id uuid NOT NULL,
    change_type character varying(30) NOT NULL,
    changed_fields jsonb,
    old_values jsonb,
    new_values jsonb,
    changed_by character varying(255),
    change_source character varying(100),
    change_reason text,
    "timestamp" timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT asset_history_change_type_check CHECK (((change_type)::text = ANY ((ARRAY['created'::character varying, 'updated'::character varying, 'merged'::character varying, 'split'::character varying, 'decommissioned'::character varying, 'reactivated'::character varying, 'deleted'::character varying])::text[])))
);

ALTER TABLE ONLY public.asset_history FORCE ROW LEVEL SECURITY;


--
-- Name: asset_identifiers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_identifiers (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    asset_id uuid NOT NULL,
    identifier_type character varying(50) NOT NULL,
    identifier_value character varying(500) NOT NULL,
    source character varying(100),
    is_primary boolean DEFAULT false,
    confidence integer DEFAULT 100,
    last_verified timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.asset_identifiers FORCE ROW LEVEL SECURITY;


--
-- Name: asset_relationships; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.asset_relationships (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    source_asset_id uuid NOT NULL,
    target_asset_id uuid NOT NULL,
    relationship_type character varying(50) NOT NULL,
    discovered_by character varying(100),
    confidence integer DEFAULT 100,
    bidirectional boolean DEFAULT false,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT asset_relationships_relationship_type_check CHECK (((relationship_type)::text = ANY ((ARRAY['runs_on'::character varying, 'connects_to'::character varying, 'depends_on'::character varying, 'managed_by'::character varying, 'hosts'::character varying, 'member_of'::character varying, 'backs_up_to'::character varying, 'replicates_to'::character varying, 'load_balances'::character varying, 'proxies'::character varying])::text[])))
);

ALTER TABLE ONLY public.asset_relationships FORCE ROW LEVEL SECURITY;


--
-- Name: assets; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assets (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    asset_type character varying(50) DEFAULT 'unknown'::character varying NOT NULL,
    hostname character varying(255),
    fqdn character varying(500),
    display_name character varying(255),
    ip_addresses jsonb DEFAULT '[]'::jsonb,
    mac_addresses jsonb DEFAULT '[]'::jsonb,
    os_family character varying(50),
    os_name character varying(255),
    os_version character varying(100),
    criticality character varying(20) DEFAULT 'tier4'::character varying,
    status character varying(30) DEFAULT 'active'::character varying,
    environment character varying(30) DEFAULT 'unknown'::character varying,
    owner character varying(255),
    owner_team character varying(255),
    department character varying(255),
    cost_center character varying(100),
    location character varying(255),
    compliance_tags jsonb DEFAULT '[]'::jsonb,
    custom_tags jsonb DEFAULT '[]'::jsonb,
    discovery_sources jsonb DEFAULT '{}'::jsonb,
    first_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(255),
    updated_by character varying(255),
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT assets_asset_type_check CHECK (((asset_type)::text = ANY ((ARRAY['server'::character varying, 'workstation'::character varying, 'laptop'::character varying, 'network_device'::character varying, 'cloud_instance'::character varying, 'container'::character varying, 'virtual_machine'::character varying, 'mobile'::character varying, 'iot'::character varying, 'database'::character varying, 'application'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT assets_criticality_check CHECK (((criticality)::text = ANY ((ARRAY['tier1'::character varying, 'tier2'::character varying, 'tier3'::character varying, 'tier4'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT assets_environment_check CHECK (((environment)::text = ANY ((ARRAY['production'::character varying, 'staging'::character varying, 'development'::character varying, 'test'::character varying, 'dr'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT assets_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'inactive'::character varying, 'decommissioned'::character varying, 'maintenance'::character varying, 'unknown'::character varying])::text[])))
);

ALTER TABLE ONLY public.assets FORCE ROW LEVEL SECURITY;


--
-- Name: asset_summary; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.asset_summary WITH (security_barrier='true') AS
 SELECT a.id,
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
    COALESCE(i.identifier_count, (0)::bigint) AS identifier_count,
    COALESCE(r.relationship_count, (0)::bigint) AS relationship_count,
    a.ip_addresses,
    a.compliance_tags
   FROM ((public.assets a
     LEFT JOIN ( SELECT asset_identifiers.asset_id,
            count(*) AS identifier_count
           FROM public.asset_identifiers
          GROUP BY asset_identifiers.asset_id) i ON ((i.asset_id = a.id)))
     LEFT JOIN ( SELECT asset_relationships.source_asset_id,
            count(*) AS relationship_count
           FROM public.asset_relationships
          GROUP BY asset_relationships.source_asset_id) r ON ((r.source_asset_id = a.id)));


--
-- Name: assignment_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assignment_rules (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    priority integer DEFAULT 100,
    conditions jsonb DEFAULT '{}'::jsonb NOT NULL,
    assign_to character varying(100),
    assign_to_type character varying(20) NOT NULL,
    round_robin_state jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    trigger_count integer DEFAULT 0,
    last_triggered_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100),
    CONSTRAINT assignment_rules_assign_to_type_check CHECK (((assign_to_type)::text = ANY ((ARRAY['user'::character varying, 'team'::character varying, 'agent'::character varying, 'round_robin'::character varying])::text[])))
);


--
-- Name: audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.audit_log (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid,
    username character varying(100) NOT NULL,
    action character varying(100) NOT NULL,
    resource_type character varying(50) NOT NULL,
    resource_id character varying(255),
    details jsonb DEFAULT '{}'::jsonb,
    ip_address inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.audit_log FORCE ROW LEVEL SECURITY;


--
-- Name: TABLE audit_log; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.audit_log IS 'Audit trail for RBAC and compliance';


--
-- Name: auto_response_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auto_response_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    instance_id uuid NOT NULL,
    action_type character varying(100) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: breach_incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.breach_incidents (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    external_id character varying(500),
    fingerprint character varying(64) NOT NULL,
    title character varying(500) NOT NULL,
    summary text,
    raw_content text,
    incident_type character varying(50) NOT NULL,
    affected_org character varying(500),
    affected_sector character varying(100),
    affected_countries text[],
    records_affected bigint,
    severity character varying(20),
    relevance_score numeric(5,2),
    incident_date date,
    disclosure_date date,
    discovered_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    source_id character varying(100),
    source_url text,
    ai_summary text,
    ai_tags text[],
    ai_iocs jsonb DEFAULT '[]'::jsonb,
    ai_ttps jsonb DEFAULT '[]'::jsonb,
    ai_enriched_at timestamp with time zone,
    related_cves text[],
    related_apt_groups text[],
    related_malware text[],
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT breach_incidents_incident_type_check CHECK (((incident_type)::text = ANY ((ARRAY['data_breach'::character varying, 'ransomware'::character varying, 'vulnerability'::character varying, 'apt_campaign'::character varying, 'supply_chain'::character varying, 'ddos'::character varying, 'insider_threat'::character varying, 'government_alert'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT breach_incidents_relevance_score_check1 CHECK (((relevance_score >= (0)::numeric) AND (relevance_score <= (100)::numeric))),
    CONSTRAINT breach_incidents_severity_check1 CHECK (((severity)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying, 'info'::character varying])::text[])))
);


--
-- Name: breach_intel_incidents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.breach_intel_incidents (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    external_id character varying(500),
    fingerprint character varying(64) NOT NULL,
    title character varying(500) NOT NULL,
    summary text,
    raw_content text,
    incident_type character varying(50) NOT NULL,
    affected_org character varying(500),
    affected_sector character varying(100),
    affected_countries text[],
    records_affected bigint,
    severity character varying(20),
    relevance_score numeric(5,2),
    incident_date date,
    disclosure_date date,
    discovered_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    source_id character varying(100),
    source_url text,
    ai_summary text,
    ai_tags text[],
    ai_iocs jsonb DEFAULT '[]'::jsonb,
    ai_ttps jsonb DEFAULT '[]'::jsonb,
    ai_enriched_at timestamp with time zone,
    related_cves text[],
    related_apt_groups text[],
    related_malware text[],
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    url text,
    published_at timestamp with time zone,
    raw_data jsonb DEFAULT '{}'::jsonb,
    CONSTRAINT breach_incidents_relevance_score_check CHECK (((relevance_score >= (0)::numeric) AND (relevance_score <= (100)::numeric))),
    CONSTRAINT breach_incidents_severity_check CHECK (((severity)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying, 'info'::character varying])::text[])))
);


--
-- Name: breach_intel_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.breach_intel_sources (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    source_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    source_type character varying(50) NOT NULL,
    category character varying(50),
    url text NOT NULL,
    parser_config jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    poll_interval_minutes integer DEFAULT 60,
    last_poll_at timestamp with time zone,
    last_poll_status character varying(20),
    last_poll_error text,
    last_poll_item_count integer DEFAULT 0,
    total_items_ingested integer DEFAULT 0,
    next_poll_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    total_items integer DEFAULT 0,
    default_incident_type character varying(50) DEFAULT 'other'::character varying,
    default_severity character varying(20) DEFAULT 'medium'::character varying,
    last_error text,
    last_success_at timestamp with time zone,
    CONSTRAINT breach_intel_sources_last_poll_status_check CHECK (((last_poll_status)::text = ANY ((ARRAY['success'::character varying, 'failed'::character varying, 'partial'::character varying])::text[])))
);


--
-- Name: campaign_iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campaign_iocs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    campaign_id uuid,
    ioc_value character varying(500) NOT NULL,
    ioc_type character varying(50) NOT NULL,
    occurrence_count integer DEFAULT 1,
    first_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    confidence numeric(5,2) DEFAULT 70.0,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.campaign_iocs FORCE ROW LEVEL SECURITY;


--
-- Name: campaign_members; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campaign_members (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    campaign_id uuid,
    member_type character varying(20) NOT NULL,
    alert_id uuid,
    investigation_id uuid,
    added_by character varying(100),
    correlation_reason text,
    correlation_score numeric(5,2),
    added_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT campaign_members_member_type_check CHECK (((member_type)::text = ANY ((ARRAY['alert'::character varying, 'investigation'::character varying])::text[])))
);

ALTER TABLE ONLY public.campaign_members FORCE ROW LEVEL SECURITY;


--
-- Name: campaigns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.campaigns (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    campaign_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    campaign_type character varying(50) DEFAULT 'unknown'::character varying,
    severity character varying(20) DEFAULT 'medium'::character varying,
    confidence numeric(5,2) DEFAULT 70.0,
    status character varying(20) DEFAULT 'active'::character varying,
    alert_count integer DEFAULT 0,
    ioc_count integer DEFAULT 0,
    mitre_techniques text[],
    created_by character varying(100),
    assigned_to character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_activity timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid,
    CONSTRAINT campaigns_campaign_type_check CHECK (((campaign_type)::text = ANY ((ARRAY['apt'::character varying, 'ransomware'::character varying, 'phishing'::character varying, 'malware'::character varying, 'botnet'::character varying, 'data_exfil'::character varying, 'lateral_movement'::character varying, 'credential_theft'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT campaigns_severity_check CHECK (((severity)::text = ANY ((ARRAY['low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT campaigns_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'investigating'::character varying, 'contained'::character varying, 'resolved'::character varying, 'false_positive'::character varying])::text[])))
);

ALTER TABLE ONLY public.campaigns FORCE ROW LEVEL SECURITY;


--
-- Name: case_summaries; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_summaries (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    investigation_id character varying(255) NOT NULL,
    summary_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    format character varying(50) DEFAULT 'detailed'::character varying,
    generated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    generated_by character varying(100) DEFAULT 'system'::character varying,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.case_summaries FORCE ROW LEVEL SECURITY;


--
-- Name: chat_action_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_action_audit (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    chat_message_id uuid,
    investigation_id uuid,
    user_id character varying(100) NOT NULL,
    username character varying(200),
    action_type character varying(100) NOT NULL,
    action_target_type character varying(50),
    action_target_value text,
    action_parameters jsonb,
    agent_tier integer,
    agent_id character varying(100),
    user_prompt text,
    status character varying(30) DEFAULT 'requested'::character varying,
    action_request_id character varying(50),
    approved_by character varying(100),
    approved_at timestamp with time zone,
    denial_reason text,
    execution_result jsonb,
    executed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT chat_action_audit_status_check CHECK (((status)::text = ANY ((ARRAY['requested'::character varying, 'parsed'::character varying, 'pending_approval'::character varying, 'approved'::character varying, 'denied'::character varying, 'executed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])))
);

ALTER TABLE ONLY public.chat_action_audit FORCE ROW LEVEL SECURITY;


--
-- Name: chat_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_subscriptions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid NOT NULL,
    user_id character varying(100) NOT NULL,
    connection_id character varying(100) NOT NULL,
    subscribed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: chat_typing_status; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_typing_status (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid NOT NULL,
    user_id character varying(100) NOT NULL,
    user_name character varying(200),
    is_agent boolean DEFAULT false,
    started_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP + '00:00:10'::interval)
);


--
-- Name: chat_usage_analytics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.chat_usage_analytics (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id character varying(100) NOT NULL,
    username character varying(200),
    session_id character varying(100),
    investigation_id uuid,
    event_type character varying(50) NOT NULL,
    message_type character varying(30),
    quick_action_category character varying(50),
    quick_action_label character varying(100),
    action_type character varying(100),
    action_target character varying(500),
    message_length integer,
    response_time_ms integer,
    user_agent text,
    ip_address character varying(50),
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT chat_usage_analytics_event_type_check CHECK (((event_type)::text = ANY ((ARRAY['session_start'::character varying, 'session_end'::character varying, 'message_sent'::character varying, 'quick_action_used'::character varying, 'action_requested'::character varying, 'agent_response'::character varying, 'connection_error'::character varying, 'reconnection'::character varying])::text[])))
);

ALTER TABLE ONLY public.chat_usage_analytics FORCE ROW LEVEL SECURITY;


--
-- Name: cluster_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cluster_config (
    key character varying(255) NOT NULL,
    value jsonb NOT NULL,
    description text,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_by character varying(100)
);


--
-- Name: cluster_nodes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cluster_nodes (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    node_id character varying(100) NOT NULL,
    hostname character varying(255),
    ip_address inet,
    port integer DEFAULT 8000,
    node_role character varying(30) DEFAULT 'worker'::character varying,
    status character varying(20) DEFAULT 'starting'::character varying,
    last_heartbeat timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    started_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    version character varying(50),
    metadata jsonb DEFAULT '{}'::jsonb,
    CONSTRAINT cluster_nodes_node_role_check CHECK (((node_role)::text = ANY ((ARRAY['worker'::character varying, 'scheduler'::character varying, 'all'::character varying])::text[]))),
    CONSTRAINT cluster_nodes_status_check CHECK (((status)::text = ANY ((ARRAY['starting'::character varying, 'healthy'::character varying, 'unhealthy'::character varying, 'draining'::character varying, 'stopped'::character varying])::text[])))
);


--
-- Name: collector_group_membership; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collector_group_membership (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    group_id uuid,
    agent_id uuid,
    is_manual boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: collector_groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collector_groups (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    display_name character varying(255) NOT NULL,
    description text,
    auto_membership_rules jsonb,
    is_enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100)
);


--
-- Name: collector_source_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.collector_source_assignments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid,
    source_type_id uuid,
    enabled boolean DEFAULT true,
    status character varying(50) DEFAULT 'active'::character varying,
    events_per_second_limit integer DEFAULT 100000,
    config_overrides jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: connect_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connect_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    name character varying(100) NOT NULL,
    auth_type character varying(30) NOT NULL,
    encrypted_data text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    linked_instance_id uuid,
    tags text[] DEFAULT '{}'::text[],
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);

ALTER TABLE ONLY public.connect_credentials FORCE ROW LEVEL SECURITY;


--
-- Name: connect_execution_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connect_execution_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    instance_id uuid NOT NULL,
    connector_id character varying(64) NOT NULL,
    action_id character varying(64),
    success boolean,
    status_code integer,
    duration_ms integer,
    error_message text,
    executed_by character varying(100),
    executed_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.connect_execution_log FORCE ROW LEVEL SECURITY;


--
-- Name: connect_instances; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connect_instances (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    connector_id character varying(64) NOT NULL,
    credential_id uuid,
    display_name character varying(100),
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    health_status character varying(20) DEFAULT 'unknown'::character varying NOT NULL,
    health_checked timestamp with time zone,
    total_requests integer DEFAULT 0 NOT NULL,
    success_requests integer DEFAULT 0 NOT NULL,
    failed_requests integer DEFAULT 0 NOT NULL,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    auto_response_enabled boolean DEFAULT false NOT NULL,
    CONSTRAINT chk_health_status CHECK (((health_status)::text = ANY ((ARRAY['healthy'::character varying, 'degraded'::character varying, 'down'::character varying, 'unknown'::character varying])::text[])))
);

ALTER TABLE ONLY public.connect_instances FORCE ROW LEVEL SECURITY;


--
-- Name: connector_definitions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connector_definitions (
    id character varying(64) NOT NULL,
    tenant_id uuid,
    source character varying(20) DEFAULT 'builtin'::character varying NOT NULL,
    name character varying(100) NOT NULL,
    vendor character varying(100),
    category character varying(50) NOT NULL,
    description text DEFAULT ''::text,
    logo_url character varying(500),
    auth_type character varying(30) DEFAULT 'api_key'::character varying NOT NULL,
    auth_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    base_url character varying(500),
    actions jsonb DEFAULT '[]'::jsonb NOT NULL,
    version character varying(20) DEFAULT '1.0.0'::character varying,
    enabled boolean DEFAULT true,
    deprecated boolean DEFAULT false,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    row_id uuid DEFAULT gen_random_uuid() NOT NULL,
    documentation_url character varying(500),
    setup_instructions text,
    CONSTRAINT chk_connector_source CHECK (((source)::text = ANY ((ARRAY['builtin'::character varying, 'community'::character varying, 'private'::character varying])::text[]))),
    CONSTRAINT chk_private_requires_tenant CHECK ((((source)::text <> 'private'::text) OR (tenant_id IS NOT NULL))),
    CONSTRAINT chk_shared_no_tenant CHECK ((((source)::text <> ALL ((ARRAY['builtin'::character varying, 'community'::character varying])::text[])) OR (tenant_id IS NULL)))
);

ALTER TABLE ONLY public.connector_definitions FORCE ROW LEVEL SECURITY;


--
-- Name: connector_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connector_submissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    connector_id character varying(64) NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    submitted_by character varying(100),
    submitted_at timestamp with time zone DEFAULT now() NOT NULL,
    reviewed_by character varying(100),
    reviewed_at timestamp with time zone,
    review_notes text,
    CONSTRAINT chk_submission_status CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying])::text[])))
);

ALTER TABLE ONLY public.connector_submissions FORCE ROW LEVEL SECURITY;


--
-- Name: contact_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.contact_submissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    company character varying(255),
    phone character varying(50),
    message text,
    submission_type character varying(50) DEFAULT 'enterprise_inquiry'::character varying NOT NULL,
    status character varying(20) DEFAULT 'new'::character varying,
    notes text,
    ip_address inet,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT contact_submissions_status_check CHECK (((status)::text = ANY ((ARRAY['new'::character varying, 'contacted'::character varying, 'qualified'::character varying, 'closed'::character varying])::text[])))
);


--
-- Name: correlation_decisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.correlation_decisions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    alert_id uuid NOT NULL,
    investigation_id uuid NOT NULL,
    tenant_id uuid,
    decision_type character varying(50) DEFAULT 'legacy'::character varying NOT NULL,
    score integer,
    threshold integer,
    reasons jsonb DEFAULT '[]'::jsonb,
    matched_entities jsonb DEFAULT '[]'::jsonb,
    guardrails_applied jsonb DEFAULT '[]'::jsonb,
    processing_time_ms integer,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE ONLY public.correlation_decisions FORCE ROW LEVEL SECURITY;


--
-- Name: correlation_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.correlation_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id uuid,
    rule_name character varying(255),
    correlation_type character varying(50),
    correlation_score numeric(5,2),
    alert_ids uuid[],
    ioc_values text[],
    campaign_id uuid,
    action_taken character varying(50),
    details jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: correlation_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.correlation_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    rule_type character varying(50) NOT NULL,
    parameters jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    priority integer DEFAULT 100,
    auto_create_campaign boolean DEFAULT false,
    trigger_count integer DEFAULT 0,
    last_triggered_at timestamp with time zone,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT correlation_rules_rule_type_check CHECK (((rule_type)::text = ANY ((ARRAY['ioc_match'::character varying, 'time_window'::character varying, 'host_pattern'::character varying, 'user_pattern'::character varying, 'technique_match'::character varying, 'severity_chain'::character varying, 'custom'::character varying])::text[])))
);


--
-- Name: correlation_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.correlation_settings (
    tenant_id uuid NOT NULL,
    correlation_enabled boolean DEFAULT true,
    ai_hypothesis_enabled boolean DEFAULT true,
    entity_risk_enabled boolean DEFAULT true,
    allow_cross_domain boolean DEFAULT false,
    time_window_hours integer DEFAULT 24,
    min_evidence_score integer DEFAULT 40,
    auto_confirm_threshold integer DEFAULT 100,
    max_alerts_per_investigation integer DEFAULT 25,
    entity_risk_threshold integer DEFAULT 75,
    entity_risk_decay_hours integer DEFAULT 72,
    user_weight integer DEFAULT 30,
    host_weight integer DEFAULT 25,
    ip_weight integer DEFAULT 15,
    ioc_weight integer DEFAULT 20,
    updated_at timestamp with time zone DEFAULT now(),
    updated_by character varying(255)
);

ALTER TABLE ONLY public.correlation_settings FORCE ROW LEVEL SECURITY;


--
-- Name: credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credentials (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    auth_type character varying(50) DEFAULT 'api_key'::character varying NOT NULL,
    encrypted_value text NOT NULL,
    integration_name character varying(100),
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid NOT NULL
);

ALTER TABLE ONLY public.credentials FORCE ROW LEVEL SECURITY;


--
-- Name: credentials_vault; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.credentials_vault (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    credential_id character varying(100) NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    auth_type character varying(50) NOT NULL,
    api_key_header character varying(100),
    api_key_prefix character varying(50),
    api_key_location character varying(20),
    username character varying(255),
    client_id character varying(255),
    token_url text,
    scope text,
    aws_access_key_id character varying(255),
    aws_region character varying(50),
    aws_service character varying(100),
    custom_header_names jsonb,
    encrypted_secrets text NOT NULL,
    tags jsonb DEFAULT '[]'::jsonb,
    integration_ids jsonb DEFAULT '[]'::jsonb,
    created_by character varying(100) NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_used_at timestamp with time zone,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT credentials_vault_auth_type_check CHECK (((auth_type)::text = ANY ((ARRAY['api_key'::character varying, 'bearer'::character varying, 'basic'::character varying, 'oauth2_client'::character varying, 'oauth2_token'::character varying, 'aws'::character varying, 'custom_header'::character varying, 'none'::character varying])::text[])))
);

ALTER TABLE ONLY public.credentials_vault FORCE ROW LEVEL SECURITY;


--
-- Name: criticality_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.criticality_rules (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    target_criticality character varying(20) NOT NULL,
    rule_priority integer DEFAULT 50,
    conditions jsonb NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(255),
    CONSTRAINT criticality_rules_target_criticality_check CHECK (((target_criticality)::text = ANY ((ARRAY['tier1'::character varying, 'tier2'::character varying, 'tier3'::character varying, 'tier4'::character varying])::text[])))
);


--
-- Name: dedupe_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dedupe_config (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    enabled boolean DEFAULT true,
    source_filter character varying(200),
    category_filter character varying(200),
    severity_filter character varying(100)[],
    fingerprint_fields text[] DEFAULT ARRAY['source'::text, 'category'::text, 'title'::text] NOT NULL,
    window_minutes integer DEFAULT 60,
    action character varying(50) DEFAULT 'group'::character varying,
    priority integer DEFAULT 100,
    total_matches integer DEFAULT 0,
    duplicates_suppressed integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100),
    tenant_id uuid,
    CONSTRAINT dedupe_config_action_check CHECK (((action)::text = ANY ((ARRAY['group'::character varying, 'suppress'::character varying, 'merge'::character varying, 'count_only'::character varying])::text[])))
);

ALTER TABLE ONLY public.dedupe_config FORCE ROW LEVEL SECURITY;


--
-- Name: detection_hits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_hits (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    rule_id uuid,
    rule_name character varying(255) NOT NULL,
    event_id character varying(255) NOT NULL,
    event_index character varying(255) NOT NULL,
    event_timestamp timestamp with time zone NOT NULL,
    matched_fields jsonb NOT NULL,
    severity character varying(20) NOT NULL,
    agent_id uuid,
    hostname character varying(255),
    source_ip inet,
    alert_created boolean DEFAULT false,
    alert_id uuid,
    disposition character varying(50),
    disposition_by character varying(255),
    disposition_at timestamp with time zone,
    disposition_notes text,
    detected_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT detection_hits_disposition_check CHECK (((disposition)::text = ANY ((ARRAY['true_positive'::character varying, 'false_positive'::character varying, 'benign'::character varying, 'inconclusive'::character varying, 'MALICIOUS'::character varying, 'SUSPICIOUS'::character varying, 'BENIGN'::character varying, 'TRUE_POSITIVE'::character varying, 'FALSE_POSITIVE'::character varying, 'BENIGN_POSITIVE'::character varying, 'NEEDS_INVESTIGATION'::character varying, 'INCONCLUSIVE'::character varying, 'UNKNOWN'::character varying, NULL::character varying])::text[])))
);

ALTER TABLE ONLY public.detection_hits FORCE ROW LEVEL SECURITY;


--
-- Name: detection_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.detection_rules (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    rule_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    severity character varying(20) NOT NULL,
    status character varying(20) DEFAULT 'enabled'::character varying,
    rule_type character varying(50) DEFAULT 'detection'::character varying,
    logsource jsonb NOT NULL,
    detection jsonb NOT NULL,
    condition character varying(1000),
    mitre_attack jsonb DEFAULT '[]'::jsonb,
    compliance_frameworks text[] DEFAULT ARRAY[]::text[],
    author character varying(255),
    "references" text[] DEFAULT ARRAY[]::text[],
    tags text[] DEFAULT ARRAY[]::text[],
    false_positive_notes text,
    auto_create_alert boolean DEFAULT true,
    alert_priority character varying(20) DEFAULT 'medium'::character varying,
    response_actions jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(255),
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_by character varying(255),
    version integer DEFAULT 1,
    previous_versions jsonb DEFAULT '[]'::jsonb,
    CONSTRAINT detection_rules_rule_type_check CHECK (((rule_type)::text = ANY ((ARRAY['detection'::character varying, 'hunting'::character varying, 'correlation'::character varying, 'threshold'::character varying])::text[]))),
    CONSTRAINT detection_rules_severity_check CHECK (((severity)::text = ANY ((ARRAY['informational'::character varying, 'low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT detection_rules_status_check CHECK (((status)::text = ANY ((ARRAY['enabled'::character varying, 'disabled'::character varying, 'testing'::character varying, 'deprecated'::character varying])::text[])))
);


--
-- Name: discovered_apis; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.discovered_apis (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    api_id character varying(500) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    provider character varying(255) NOT NULL,
    version character varying(100),
    category character varying(100),
    tags jsonb DEFAULT '[]'::jsonb,
    source character varying(50) NOT NULL,
    openapi_url text NOT NULL,
    documentation_url text,
    logo_url text,
    popularity_score integer DEFAULT 0,
    last_updated_upstream timestamp with time zone,
    imported boolean DEFAULT false,
    imported_integration_id character varying(100),
    imported_at timestamp with time zone,
    discovered_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_refreshed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    search_vector tsvector,
    CONSTRAINT discovered_apis_source_check CHECK (((source)::text = ANY ((ARRAY['apis_guru'::character varying, 'swaggerhub'::character varying, 'github'::character varying, 'rapidapi'::character varying, 'direct'::character varying, 'manual'::character varying])::text[])))
);


--
-- Name: discovery_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.discovery_queue (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    source_id uuid NOT NULL,
    status character varying(30) DEFAULT 'pending'::character varying,
    priority integer DEFAULT 5,
    scheduled_for timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    assets_found integer,
    assets_created integer,
    assets_updated integer,
    assets_unchanged integer,
    conflicts_detected integer,
    error_message text,
    execution_log jsonb DEFAULT '[]'::jsonb,
    locked_by character varying(100),
    locked_until timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT discovery_queue_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])))
);


--
-- Name: discovery_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.discovery_sources (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    source_type character varying(50) NOT NULL,
    integration_id uuid,
    credential_id character varying(255),
    config jsonb DEFAULT '{}'::jsonb,
    field_mappings jsonb DEFAULT '{}'::jsonb,
    sync_enabled boolean DEFAULT true,
    sync_interval_minutes integer DEFAULT 60,
    sync_cron character varying(100),
    last_sync_at timestamp with time zone,
    last_sync_status character varying(30) DEFAULT 'never_run'::character varying,
    last_sync_message text,
    last_sync_assets_found integer DEFAULT 0,
    last_sync_assets_created integer DEFAULT 0,
    last_sync_assets_updated integer DEFAULT 0,
    last_sync_duration_seconds integer,
    source_priority integer DEFAULT 50,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(255),
    CONSTRAINT discovery_sources_last_sync_status_check CHECK (((last_sync_status)::text = ANY ((ARRAY['never_run'::character varying, 'running'::character varying, 'success'::character varying, 'partial'::character varying, 'failed'::character varying])::text[]))),
    CONSTRAINT discovery_sources_source_type_check CHECK (((source_type)::text = ANY ((ARRAY['active_directory'::character varying, 'crowdstrike'::character varying, 'sentinelone'::character varying, 'defender_atp'::character varying, 'aws'::character varying, 'azure'::character varying, 'gcp'::character varying, 'vmware'::character varying, 'kubernetes'::character varying, 'servicenow'::character varying, 'network_scan'::character varying, 'csv_import'::character varying, 'api'::character varying, 'manual'::character varying])::text[])))
);


--
-- Name: discovery_source_health; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.discovery_source_health WITH (security_barrier='true') AS
 SELECT ds.id,
    ds.name,
    ds.source_type,
    ds.enabled,
    ds.sync_enabled,
    ds.last_sync_at,
    ds.last_sync_status,
    ds.last_sync_assets_found,
    ds.last_sync_duration_seconds,
        CASE
            WHEN (ds.last_sync_at IS NULL) THEN 'never_synced'::text
            WHEN (ds.last_sync_at < (CURRENT_TIMESTAMP - (((ds.sync_interval_minutes * 2) || ' minutes'::text))::interval)) THEN 'overdue'::text
            WHEN ((ds.last_sync_status)::text = 'failed'::text) THEN 'error'::text
            ELSE 'healthy'::text
        END AS health_status
   FROM public.discovery_sources ds;


--
-- Name: distributed_locks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.distributed_locks (
    lock_name character varying(100) NOT NULL,
    holder_node_id character varying(100) NOT NULL,
    acquired_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb
);


--
-- Name: edl_access_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edl_access_log (
    id bigint NOT NULL,
    list_id uuid NOT NULL,
    credential_id uuid,
    client_ip character varying(45) NOT NULL,
    user_agent text,
    request_path character varying(500),
    status_code integer,
    items_returned integer,
    response_time_ms integer,
    cache_hit boolean DEFAULT false,
    auth_method character varying(20),
    auth_success boolean DEFAULT true,
    accessed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: edl_access_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.edl_access_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: edl_access_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.edl_access_log_id_seq OWNED BY public.edl_access_log.id;


--
-- Name: edl_change_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edl_change_log (
    id bigint NOT NULL,
    list_id uuid NOT NULL,
    operation character varying(20) NOT NULL,
    ioc_value character varying(2000) NOT NULL,
    ioc_type character varying(20) NOT NULL,
    changed_by character varying(100),
    source_type character varying(50),
    source_id character varying(200),
    reason text,
    approval_required boolean DEFAULT false,
    approval_id character varying(200),
    approved_by character varying(100),
    changed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT edl_change_valid_op CHECK (((operation)::text = ANY ((ARRAY['add'::character varying, 'remove'::character varying, 'expire'::character varying, 'bulk_add'::character varying, 'bulk_remove'::character varying])::text[])))
);


--
-- Name: edl_change_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.edl_change_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: edl_change_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.edl_change_log_id_seq OWNED BY public.edl_change_log.id;


--
-- Name: edl_content_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edl_content_cache (
    list_id uuid NOT NULL,
    content_text text,
    content_json jsonb,
    item_count integer DEFAULT 0,
    content_hash character varying(64),
    generated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone
);


--
-- Name: edl_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edl_credentials (
    credential_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    list_id uuid NOT NULL,
    auth_type character varying(20) NOT NULL,
    token_hash character varying(256),
    token_prefix character varying(20),
    basic_username character varying(100),
    basic_password_hash character varying(256),
    ip_allowlist jsonb,
    name character varying(200) NOT NULL,
    description text,
    enabled boolean DEFAULT true,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    use_count bigint DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100),
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT edl_cred_valid_auth CHECK (((auth_type)::text = ANY ((ARRAY['none'::character varying, 'token'::character varying, 'basic'::character varying, 'ip_allowlist'::character varying, 'header'::character varying])::text[])))
);

ALTER TABLE ONLY public.edl_credentials FORCE ROW LEVEL SECURITY;


--
-- Name: edl_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edl_items (
    id bigint NOT NULL,
    list_id uuid NOT NULL,
    ioc_value character varying(2000) NOT NULL,
    ioc_type character varying(20) NOT NULL,
    ioc_normalized character varying(2000) NOT NULL,
    confidence numeric(3,2),
    severity character varying(20),
    source_label character varying(200),
    comment text,
    source_type character varying(50) DEFAULT 'manual'::character varying NOT NULL,
    source_id character varying(200),
    added_by character varying(100),
    expires_at timestamp with time zone,
    added_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: edl_items_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.edl_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: edl_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.edl_items_id_seq OWNED BY public.edl_items.id;


--
-- Name: edl_lists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.edl_lists (
    list_id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(200) NOT NULL,
    slug character varying(200) NOT NULL,
    description text,
    ioc_type character varying(20) NOT NULL,
    list_type character varying(20) DEFAULT 'static'::character varying NOT NULL,
    refresh_interval_seconds integer DEFAULT 300,
    max_items integer DEFAULT 150000,
    ttl_default_seconds integer DEFAULT 0,
    include_comments boolean DEFAULT true,
    enabled boolean DEFAULT true,
    item_count integer DEFAULT 0,
    last_generated_at timestamp with time zone,
    content_hash character varying(64),
    tenant_id character varying(100) DEFAULT 'default'::character varying NOT NULL,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT edl_valid_ioc_type CHECK (((ioc_type)::text = ANY ((ARRAY['ip'::character varying, 'domain'::character varying, 'url'::character varying])::text[]))),
    CONSTRAINT edl_valid_list_type CHECK (((list_type)::text = ANY ((ARRAY['static'::character varying, 'dynamic'::character varying, 'hybrid'::character varying])::text[])))
);

ALTER TABLE ONLY public.edl_lists FORCE ROW LEVEL SECURITY;


--
-- Name: email_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_config (
    id character varying(50) DEFAULT 'smtp'::character varying NOT NULL,
    smtp_host character varying(255),
    smtp_port integer DEFAULT 587,
    smtp_username character varying(255),
    smtp_password character varying(500),
    use_tls boolean DEFAULT true,
    use_ssl boolean DEFAULT false,
    from_email character varying(255),
    from_name character varying(255) DEFAULT 'T1 Agentics SOC'::character varying,
    enabled boolean DEFAULT false,
    max_emails_per_hour integer DEFAULT 100,
    max_emails_per_day integer DEFAULT 1000,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: email_digest_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_digest_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id character varying(100),
    period_start timestamp with time zone NOT NULL,
    period_end timestamp with time zone NOT NULL,
    items jsonb DEFAULT '[]'::jsonb,
    item_count integer DEFAULT 0,
    status character varying(20) DEFAULT 'collecting'::character varying,
    scheduled_send_at timestamp with time zone,
    sent_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT email_digest_queue_status_check CHECK (((status)::text = ANY ((ARRAY['collecting'::character varying, 'pending'::character varying, 'sent'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: email_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_log (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id character varying(100),
    template_id uuid,
    event_type character varying(100),
    recipients text[] NOT NULL,
    subject character varying(500),
    body_preview character varying(500),
    status character varying(20) DEFAULT 'pending'::character varying,
    error_message text,
    retry_count integer DEFAULT 0,
    alert_id uuid,
    investigation_id uuid,
    queued_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    sent_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT email_log_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'sent'::character varying, 'failed'::character varying, 'bounced'::character varying])::text[])))
);


--
-- Name: email_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.email_templates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    template_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    category character varying(50) DEFAULT 'general'::character varying,
    subject_template character varying(500) NOT NULL,
    html_template text NOT NULL,
    text_template text,
    available_variables jsonb DEFAULT '[]'::jsonb,
    preview_data jsonb DEFAULT '{}'::jsonb,
    is_system boolean DEFAULT false,
    is_default boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100)
);


--
-- Name: enrichment_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_cache (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    ioc_type character varying(50) NOT NULL,
    ioc_value character varying(500) NOT NULL,
    provider character varying(100) NOT NULL,
    enrichment_data jsonb NOT NULL,
    is_malicious boolean,
    threat_score integer,
    confidence numeric(3,2),
    cached_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone,
    hit_count integer DEFAULT 0,
    last_accessed_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid,
    CONSTRAINT enrichment_cache_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (1)::numeric))),
    CONSTRAINT enrichment_cache_ioc_type_check CHECK (((ioc_type)::text = ANY ((ARRAY['ip'::character varying, 'domain'::character varying, 'hash'::character varying, 'hash_md5'::character varying, 'hash_sha1'::character varying, 'hash_sha256'::character varying, 'url'::character varying, 'email'::character varying])::text[]))),
    CONSTRAINT enrichment_cache_threat_score_check CHECK (((threat_score >= 0) AND (threat_score <= 100)))
);

ALTER TABLE ONLY public.enrichment_cache FORCE ROW LEVEL SECURITY;


--
-- Name: enrichment_health_metrics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_health_metrics (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider character varying(100) NOT NULL,
    measurement_time timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    avg_response_time_ms numeric(10,2),
    p95_response_time_ms numeric(10,2),
    success_rate numeric(5,2),
    error_count integer DEFAULT 0,
    timeout_count integer DEFAULT 0,
    requests_this_hour integer DEFAULT 0,
    requests_today integer DEFAULT 0,
    quota_remaining_percent numeric(5,2),
    cache_hit_count integer DEFAULT 0,
    cache_miss_count integer DEFAULT 0,
    cache_hit_rate numeric(5,2),
    pending_queue_size integer DEFAULT 0,
    avg_queue_wait_seconds numeric(10,2),
    CONSTRAINT enrichment_health_metrics_success_rate_check CHECK (((success_rate >= (0)::numeric) AND (success_rate <= (100)::numeric)))
);


--
-- Name: enrichment_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_jobs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    job_id character varying(100) NOT NULL,
    job_type character varying(50) NOT NULL,
    resource_id character varying(255),
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    total_iocs integer DEFAULT 0,
    processed_iocs integer DEFAULT 0,
    failed_iocs integer DEFAULT 0,
    results jsonb DEFAULT '{}'::jsonb,
    error_message text,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    tenant_id uuid,
    CONSTRAINT enrichment_jobs_job_type_check CHECK (((job_type)::text = ANY ((ARRAY['alert'::character varying, 'investigation'::character varying, 'bulk'::character varying, 'scheduled'::character varying])::text[]))),
    CONSTRAINT enrichment_jobs_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])))
);

ALTER TABLE ONLY public.enrichment_jobs FORCE ROW LEVEL SECURITY;


--
-- Name: enrichment_priority_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_priority_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_value character varying(500) NOT NULL,
    ioc_type character varying(50) NOT NULL,
    calculated_priority integer DEFAULT 5 NOT NULL,
    priority_factors jsonb DEFAULT '{}'::jsonb,
    trigger_type character varying(50) DEFAULT 'manual'::character varying NOT NULL,
    trigger_source character varying(255),
    status character varying(50) DEFAULT 'pending'::character varying NOT NULL,
    target_providers text[],
    scheduled_for timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    delay_reason character varying(255),
    attempts integer DEFAULT 0,
    max_attempts integer DEFAULT 3,
    last_attempt_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp with time zone,
    CONSTRAINT enrichment_priority_queue_calculated_priority_check CHECK (((calculated_priority >= 1) AND (calculated_priority <= 10)))
);


--
-- Name: enrichment_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.enrichment_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_type character varying(50) NOT NULL,
    ioc_value text NOT NULL,
    priority integer DEFAULT 5,
    status character varying(20) DEFAULT 'pending'::character varying,
    source_event_id uuid,
    source_investigation_id uuid,
    attempts integer DEFAULT 0,
    max_attempts integer DEFAULT 3,
    last_error text,
    skip_reason text,
    result_id uuid,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    next_retry_at timestamp with time zone,
    CONSTRAINT enrichment_queue_ioc_type_check CHECK (((ioc_type)::text = ANY ((ARRAY['ip'::character varying, 'domain'::character varying, 'hash'::character varying, 'url'::character varying, 'email'::character varying])::text[]))),
    CONSTRAINT enrichment_queue_priority_check CHECK (((priority >= 1) AND (priority <= 10))),
    CONSTRAINT enrichment_queue_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying, 'complete'::character varying, 'failed'::character varying, 'skipped'::character varying])::text[])))
);


--
-- Name: entity_risk; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.entity_risk (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    entity_type character varying(50) NOT NULL,
    entity_value character varying(500) NOT NULL,
    risk_score numeric(8,2) DEFAULT 0,
    alert_count integer DEFAULT 0,
    contributing_alerts jsonb DEFAULT '[]'::jsonb,
    first_seen timestamp with time zone DEFAULT now(),
    last_seen timestamp with time zone DEFAULT now(),
    threshold_breached boolean DEFAULT false,
    threshold_breached_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    investigation_id text
);

ALTER TABLE ONLY public.entity_risk FORCE ROW LEVEL SECURITY;


--
-- Name: entity_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.entity_types (
    type_code character varying(50) NOT NULL,
    display_name character varying(100) NOT NULL,
    priority integer DEFAULT 100,
    description text
);


--
-- Name: escalation_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.escalation_config (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    trigger_type character varying(50) NOT NULL,
    threshold_minutes integer NOT NULL,
    applies_to_priorities text[] DEFAULT ARRAY['P1'::text, 'P2'::text, 'P3'::text, 'P4'::text],
    escalation_level integer DEFAULT 1,
    notify_roles text[] DEFAULT ARRAY['escalation_team'::text],
    auto_escalate boolean DEFAULT true,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT escalation_config_trigger_type_check CHECK (((trigger_type)::text = ANY ((ARRAY['unassigned_timeout'::character varying, 'no_activity_timeout'::character varying, 'sla_approaching'::character varying, 'sla_breach'::character varying, 'manual'::character varying])::text[])))
);

ALTER TABLE ONLY public.escalation_config FORCE ROW LEVEL SECURITY;


--
-- Name: investigation_agent_paths; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_agent_paths (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid,
    path_json jsonb DEFAULT '[]'::jsonb,
    total_agents_involved integer DEFAULT 0,
    escalation_count integer DEFAULT 0,
    human_involved boolean DEFAULT false,
    first_agent_at timestamp with time zone,
    last_agent_at timestamp with time zone,
    human_takeover_at timestamp with time zone,
    resolved_at timestamp with time zone,
    final_resolver character varying(50),
    automation_success boolean,
    alert_severity character varying(20),
    alert_source character varying(255),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: escalation_funnel; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.escalation_funnel WITH (security_barrier='true') AS
 SELECT count(*) AS total_investigations,
    count(*) FILTER (WHERE (investigation_agent_paths.total_agents_involved >= 1)) AS reached_tier1,
    count(*) FILTER (WHERE ((investigation_agent_paths.total_agents_involved >= 2) OR (investigation_agent_paths.escalation_count >= 1))) AS reached_tier2,
    count(*) FILTER (WHERE (investigation_agent_paths.human_involved = true)) AS reached_human,
    count(*) FILTER (WHERE (investigation_agent_paths.automation_success = true)) AS auto_resolved,
    round(((100.0 * (count(*) FILTER (WHERE (investigation_agent_paths.automation_success = true)))::numeric) / (NULLIF(count(*), 0))::numeric), 2) AS automation_rate,
    round(((100.0 * (count(*) FILTER (WHERE (investigation_agent_paths.escalation_count >= 1)))::numeric) / (NULLIF(count(*), 0))::numeric), 2) AS escalation_rate
   FROM public.investigation_agent_paths
  WHERE (investigation_agent_paths.created_at > (CURRENT_TIMESTAMP - '30 days'::interval));


--
-- Name: escalation_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.escalation_history (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid,
    alert_id uuid,
    from_tier integer NOT NULL,
    to_tier integer NOT NULL,
    escalated_by character varying(255),
    reason text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.escalation_history FORCE ROW LEVEL SECURITY;


--
-- Name: exclusion_list; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.exclusion_list (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_type character varying(50) NOT NULL,
    ioc_value text NOT NULL,
    match_type character varying(20) DEFAULT 'exact'::character varying,
    reason text,
    category character varying(50) DEFAULT 'internal'::character varying,
    added_by character varying(100),
    expires_at timestamp with time zone,
    is_active boolean DEFAULT true,
    hit_count integer DEFAULT 0,
    last_hit_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT exclusion_list_category_check CHECK (((category)::text = ANY ((ARRAY['internal'::character varying, 'vendor'::character varying, 'false_positive'::character varying, 'whitelist'::character varying, 'custom'::character varying])::text[]))),
    CONSTRAINT exclusion_list_ioc_type_check CHECK (((ioc_type)::text = ANY ((ARRAY['ip'::character varying, 'domain'::character varying, 'email'::character varying, 'hash'::character varying, 'cidr'::character varying, 'regex'::character varying])::text[]))),
    CONSTRAINT exclusion_list_match_type_check CHECK (((match_type)::text = ANY ((ARRAY['exact'::character varying, 'prefix'::character varying, 'suffix'::character varying, 'contains'::character varying, 'cidr'::character varying, 'regex'::character varying])::text[])))
);

ALTER TABLE ONLY public.exclusion_list FORCE ROW LEVEL SECURITY;


--
-- Name: form_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.form_submissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    submission_id character varying(100) NOT NULL,
    form_id character varying(100) NOT NULL,
    form_title character varying(255),
    data jsonb DEFAULT '{}'::jsonb,
    submitted_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    ip_address character varying(45),
    user_agent text,
    status character varying(50) DEFAULT 'pending'::character varying,
    alert_created boolean DEFAULT false,
    alert_id character varying(255),
    webhook_sent boolean DEFAULT false,
    webhook_response jsonb,
    processing_errors jsonb
);

ALTER TABLE ONLY public.form_submissions FORCE ROW LEVEL SECURITY;


--
-- Name: frontend_errors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.frontend_errors (
    id integer NOT NULL,
    error text NOT NULL,
    component_stack text,
    url character varying(500),
    user_agent character varying(500),
    client_ip character varying(45),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: frontend_errors_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.frontend_errors_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: frontend_errors_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.frontend_errors_id_seq OWNED BY public.frontend_errors.id;


--
-- Name: geopolitical_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.geopolitical_events (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    fingerprint character varying(64) NOT NULL,
    title character varying(500) NOT NULL,
    summary text,
    event_type character varying(50) NOT NULL,
    countries_involved text[] NOT NULL,
    region character varying(100),
    cyber_risk_level character varying(20),
    expected_threat_actors text[],
    expected_ttps text[],
    targeted_sectors text[],
    ai_cyber_assessment text,
    ai_recommendations text[],
    ai_enriched_at timestamp with time zone,
    event_start_date date,
    event_end_date date,
    is_ongoing boolean DEFAULT true,
    source_id character varying(100),
    source_url text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT geopolitical_events_cyber_risk_level_check CHECK (((cyber_risk_level)::text = ANY ((ARRAY['critical'::character varying, 'high'::character varying, 'medium'::character varying, 'low'::character varying])::text[]))),
    CONSTRAINT geopolitical_events_event_type_check CHECK (((event_type)::text = ANY ((ARRAY['armed_conflict'::character varying, 'sanctions'::character varying, 'cyber_operation'::character varying, 'election'::character varying, 'treaty'::character varying, 'diplomatic_crisis'::character varying, 'critical_infra'::character varying, 'other'::character varying])::text[])))
);


--
-- Name: group_source_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.group_source_assignments (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    group_id uuid,
    group_name character varying(100) NOT NULL,
    source_type_id uuid,
    source_type character varying(100) NOT NULL,
    target_index_id uuid,
    target_index_name character varying(100),
    config_overrides jsonb DEFAULT '{}'::jsonb,
    include_filters jsonb DEFAULT '[]'::jsonb,
    exclude_filters jsonb DEFAULT '[]'::jsonb,
    priority integer DEFAULT 0,
    is_enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100)
);


--
-- Name: human_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.human_overrides (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    investigation_id uuid,
    verdict_outcome_id uuid,
    agent_id uuid,
    agent_tier integer,
    original_verdict character varying(50),
    original_confidence numeric(5,2),
    new_verdict character varying(50),
    override_reason text,
    overridden_by character varying(100),
    override_category character varying(50),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT human_overrides_override_category_check CHECK (((override_category)::text = ANY ((ARRAY['false_positive'::character varying, 'false_negative'::character varying, 'severity_adjustment'::character varying, 'additional_context'::character varying, 'policy_exception'::character varying, 'other'::character varying])::text[])))
);


--
-- Name: inbound_email_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.inbound_email_queue (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    mailbox_id uuid,
    message_id character varying(500),
    from_address character varying(255),
    from_name character varying(255),
    to_addresses text[],
    cc_addresses text[],
    subject character varying(500),
    body_text text,
    body_html text,
    attachments jsonb DEFAULT '[]'::jsonb,
    headers jsonb DEFAULT '{}'::jsonb,
    in_reply_to character varying(500),
    references_header text,
    status character varying(30) DEFAULT 'pending'::character varying,
    processing_result jsonb,
    error_message text,
    email_type character varying(50),
    spam_score numeric(5,2),
    received_at timestamp with time zone,
    processed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT inbound_email_queue_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying, 'processed'::character varying, 'failed'::character varying, 'ignored'::character varying, 'spam'::character varying])::text[])))
);

ALTER TABLE ONLY public.inbound_email_queue FORCE ROW LEVEL SECURITY;


--
-- Name: inbound_mailboxes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.inbound_mailboxes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    mailbox_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    mailbox_type character varying(50) NOT NULL,
    protocol character varying(20) DEFAULT 'imap'::character varying,
    server character varying(255),
    port integer,
    use_ssl boolean DEFAULT true,
    username character varying(255),
    password character varying(500),
    folder character varying(100) DEFAULT 'INBOX'::character varying,
    oauth_client_id character varying(255),
    oauth_tenant_id character varying(255),
    oauth_refresh_token text,
    poll_interval_seconds integer DEFAULT 300,
    enabled boolean DEFAULT true,
    auto_create_alerts boolean DEFAULT true,
    auto_acknowledge boolean DEFAULT true,
    auto_ai_analysis boolean DEFAULT true,
    assign_to_queue character varying(100),
    default_severity character varying(20) DEFAULT 'medium'::character varying,
    last_poll_at timestamp with time zone,
    last_poll_status character varying(50),
    emails_processed_total integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100),
    tenant_id uuid NOT NULL,
    last_uid_synced bigint DEFAULT 0,
    CONSTRAINT inbound_mailboxes_mailbox_type_check CHECK (((mailbox_type)::text = ANY ((ARRAY['phishing_reports'::character varying, 'alert_inbox'::character varying, 'approval_responses'::character varying, 'support_requests'::character varying, 'general'::character varying])::text[]))),
    CONSTRAINT inbound_mailboxes_protocol_check CHECK (((protocol)::text = ANY ((ARRAY['imap'::character varying, 'pop3'::character varying, 'graph_api'::character varying, 'gmail_api'::character varying])::text[])))
);

ALTER TABLE ONLY public.inbound_mailboxes FORCE ROW LEVEL SECURITY;


--
-- Name: index_permission_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.index_permission_templates (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(50) NOT NULL,
    description text,
    default_can_read boolean DEFAULT true,
    default_can_write boolean DEFAULT false,
    default_can_delete boolean DEFAULT false,
    default_can_admin boolean DEFAULT false,
    included_indexes text[],
    excluded_indexes text[],
    default_denied_fields jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: intake_form_attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.intake_form_attachments (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    form_id uuid NOT NULL,
    submission_id uuid,
    field_key text NOT NULL,
    filename text NOT NULL,
    content_type text NOT NULL,
    size_bytes bigint NOT NULL,
    storage_path text NOT NULL,
    uploaded_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '14 days'::interval) NOT NULL,
    deleted_at timestamp with time zone
);

ALTER TABLE ONLY public.intake_form_attachments FORCE ROW LEVEL SECURITY;


--
-- Name: intake_form_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.intake_form_submissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    form_id uuid NOT NULL,
    submitted_by uuid NOT NULL,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    alert_id character varying(255),
    status character varying(16) DEFAULT 'submitted'::character varying NOT NULL,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT intake_form_submissions_status_check CHECK (((status)::text = ANY ((ARRAY['submitted'::character varying, 'processing'::character varying, 'failed'::character varying])::text[])))
);

ALTER TABLE ONLY public.intake_form_submissions FORCE ROW LEVEL SECURITY;


--
-- Name: intake_forms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.intake_forms (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    slug character varying(64) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    title character varying(255) NOT NULL,
    intro text,
    submit_message text,
    fields jsonb DEFAULT '[]'::jsonb NOT NULL,
    alert_template jsonb DEFAULT '{}'::jsonb NOT NULL,
    status character varying(16) DEFAULT 'draft'::character varying NOT NULL,
    created_by uuid,
    updated_by uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    triage_strategy character varying(16) DEFAULT 'enrich'::character varying NOT NULL,
    auto_trigger_playbook_id uuid,
    CONSTRAINT intake_forms_status_check CHECK (((status)::text = ANY ((ARRAY['draft'::character varying, 'active'::character varying, 'archived'::character varying])::text[]))),
    CONSTRAINT intake_forms_triage_strategy_check CHECK (((triage_strategy)::text = ANY ((ARRAY['direct'::character varying, 'enrich'::character varying, 'playbook'::character varying])::text[])))
);

ALTER TABLE ONLY public.intake_forms FORCE ROW LEVEL SECURITY;


--
-- Name: integration_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_credentials (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    integration_id uuid NOT NULL,
    credential_type character varying(50) NOT NULL,
    api_key text,
    username character varying(255),
    password_encrypted text,
    oauth_token text,
    oauth_refresh_token text,
    oauth_expires_at timestamp with time zone,
    additional_fields jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_rotated_at timestamp with time zone,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.integration_credentials FORCE ROW LEVEL SECURITY;


--
-- Name: integration_rate_limits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_rate_limits (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    integration_id character varying(100) NOT NULL,
    minute_requests integer DEFAULT 0,
    daily_requests integer DEFAULT 0,
    minute_reset_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    day_reset_at timestamp with time zone DEFAULT (CURRENT_TIMESTAMP + '1 day'::interval),
    minute_limit integer DEFAULT 60,
    daily_limit integer DEFAULT 1000,
    last_429_error timestamp with time zone,
    consecutive_429_count integer DEFAULT 0,
    backoff_until timestamp with time zone,
    avg_response_time_ms integer,
    success_count integer DEFAULT 0,
    error_count integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: integration_state; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_state (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    integration_id character varying(100) NOT NULL,
    enabled boolean DEFAULT false,
    credential_id character varying(100),
    base_url character varying(500),
    config jsonb DEFAULT '{}'::jsonb,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: integration_update_history; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_update_history (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    integration_id character varying(100) NOT NULL,
    update_type character varying(50) NOT NULL,
    status character varying(50) NOT NULL,
    spec_url text,
    previous_version character varying(100),
    new_version character varying(100),
    actions_before integer,
    actions_after integer,
    actions_added jsonb DEFAULT '[]'::jsonb,
    actions_removed jsonb DEFAULT '[]'::jsonb,
    actions_modified jsonb DEFAULT '[]'::jsonb,
    error_message text,
    error_details jsonb,
    triggered_by character varying(100),
    started_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp with time zone,
    duration_ms integer,
    CONSTRAINT integration_update_history_status_check CHECK (((status)::text = ANY ((ARRAY['success'::character varying, 'failed'::character varying, 'partial'::character varying, 'no_changes'::character varying])::text[]))),
    CONSTRAINT integration_update_history_update_type_check CHECK (((update_type)::text = ANY ((ARRAY['scheduled'::character varying, 'manual'::character varying, 'initial_import'::character varying])::text[])))
);


--
-- Name: integration_update_schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integration_update_schedules (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    integration_id character varying(100) NOT NULL,
    openapi_spec_url text NOT NULL,
    enabled boolean DEFAULT true,
    update_frequency character varying(50) DEFAULT 'weekly'::character varying,
    day_of_week integer DEFAULT 0,
    time_of_day time without time zone DEFAULT '03:00:00'::time without time zone,
    last_check_at timestamp with time zone,
    last_update_at timestamp with time zone,
    last_update_status character varying(50),
    last_update_error text,
    last_spec_hash character varying(64),
    actions_added integer DEFAULT 0,
    actions_removed integer DEFAULT 0,
    actions_modified integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT integration_update_schedules_day_of_week_check CHECK (((day_of_week >= 0) AND (day_of_week <= 6))),
    CONSTRAINT integration_update_schedules_last_update_status_check CHECK (((last_update_status)::text = ANY ((ARRAY['success'::character varying, 'failed'::character varying, 'no_changes'::character varying, 'pending'::character varying])::text[]))),
    CONSTRAINT integration_update_schedules_update_frequency_check CHECK (((update_frequency)::text = ANY ((ARRAY['daily'::character varying, 'weekly'::character varying, 'monthly'::character varying, 'manual'::character varying])::text[])))
);


--
-- Name: integrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.integrations (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    integration_id character varying(100) NOT NULL,
    provider character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    category character varying(50) NOT NULL,
    base_url character varying(500),
    auth_type character varying(50),
    config jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    verified boolean DEFAULT false,
    last_verified_at timestamp with time zone,
    rate_limit_per_minute integer DEFAULT 4,
    rate_limit_per_day integer DEFAULT 500,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_used_at timestamp with time zone,
    usage_count integer DEFAULT 0,
    tenant_id uuid,
    CONSTRAINT integrations_auth_type_check CHECK (((auth_type)::text = ANY ((ARRAY['api_key'::character varying, 'oauth'::character varying, 'basic_auth'::character varying, 'none'::character varying])::text[]))),
    CONSTRAINT integrations_category_check CHECK (((category)::text = ANY ((ARRAY['threat_intel'::character varying, 'sandbox'::character varying, 'siem'::character varying, 'edr'::character varying, 'ticketing'::character varying, 'communication'::character varying, 'enrichment'::character varying, 'vulnerability'::character varying, 'identity'::character varying, 'network'::character varying, 'case_management'::character varying, 'custom'::character varying])::text[])))
);

ALTER TABLE ONLY public.integrations FORCE ROW LEVEL SECURITY;


--
-- Name: investigation_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_audit_log (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id character varying(255) NOT NULL,
    action character varying(100) NOT NULL,
    action_category character varying(50) DEFAULT 'general'::character varying NOT NULL,
    actor_type character varying(20) NOT NULL,
    actor_id character varying(255),
    actor_name character varying(255) NOT NULL,
    field_changed character varying(100),
    old_value text,
    new_value text,
    reason text,
    summary text NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    tenant_id uuid,
    CONSTRAINT investigation_audit_log_actor_type_check CHECK (((actor_type)::text = ANY ((ARRAY['human'::character varying, 'ai_agent'::character varying, 'system'::character varying])::text[])))
);

ALTER TABLE ONLY public.investigation_audit_log FORCE ROW LEVEL SECURITY;


--
-- Name: TABLE investigation_audit_log; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.investigation_audit_log IS 'Immutable audit trail for investigation actions. Cannot be modified or deleted.';


--
-- Name: investigation_chat; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_chat (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid NOT NULL,
    sender_type character varying(30) NOT NULL,
    sender_id character varying(100),
    sender_name character varying(200),
    message text NOT NULL,
    message_type character varying(30) DEFAULT 'text'::character varying,
    metadata jsonb DEFAULT '{}'::jsonb,
    parent_message_id uuid,
    read_by text[] DEFAULT ARRAY[]::text[],
    is_streaming boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT investigation_chat_message_type_check CHECK (((message_type)::text = ANY ((ARRAY['text'::character varying, 'action_request'::character varying, 'action_result'::character varying, 'field_update'::character varying, 'status_change'::character varying, 'enrichment'::character varying, 'finding'::character varying, 'recommendation'::character varying, 'question'::character varying, 'system'::character varying, 'error'::character varying])::text[]))),
    CONSTRAINT investigation_chat_sender_type_check CHECK (((sender_type)::text = ANY ((ARRAY['human'::character varying, 'agent_t1'::character varying, 'agent_t2'::character varying, 'agent_t3'::character varying, 'system'::character varying, 'integration'::character varying])::text[])))
);

ALTER TABLE ONLY public.investigation_chat FORCE ROW LEVEL SECURITY;


--
-- Name: investigation_entities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_entities (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid NOT NULL,
    tenant_id uuid,
    entity_type character varying(50) NOT NULL,
    entity_value character varying(500) NOT NULL,
    confidence numeric(5,2) DEFAULT 0,
    alert_count integer DEFAULT 0,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb
);

ALTER TABLE ONLY public.investigation_entities FORCE ROW LEVEL SECURITY;


--
-- Name: investigation_iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_iocs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid NOT NULL,
    ioc_enrichment_id uuid NOT NULL,
    found_in character varying(100),
    is_primary boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.investigation_iocs FORCE ROW LEVEL SECURITY;


--
-- Name: investigation_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_notes (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id character varying(255) NOT NULL,
    note_type character varying(50) NOT NULL,
    author character varying(100) NOT NULL,
    author_type character varying(20) NOT NULL,
    title character varying(255),
    content text NOT NULL,
    confidence numeric(5,2),
    severity character varying(20),
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    deleted_at timestamp with time zone,
    deleted_by character varying(100),
    tenant_id uuid,
    CONSTRAINT investigation_notes_author_type_check CHECK (((author_type)::text = ANY ((ARRAY['AI'::character varying, 'HUMAN'::character varying, 'SYSTEM'::character varying])::text[]))),
    CONSTRAINT investigation_notes_note_type_check CHECK (((note_type)::text = ANY ((ARRAY['AI_ANALYSIS'::character varying, 'AI_RECOMMENDATION'::character varying, 'AI_OBSERVATION'::character varying, 'HUMAN_NOTE'::character varying, 'SYSTEM_NOTE'::character varying, 'ESCALATION'::character varying])::text[]))),
    CONSTRAINT investigation_notes_severity_check CHECK (((severity)::text = ANY ((ARRAY['info'::character varying, 'low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[])))
);

ALTER TABLE ONLY public.investigation_notes FORCE ROW LEVEL SECURITY;


--
-- Name: TABLE investigation_notes; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.investigation_notes IS 'Notes added during investigation';


--
-- Name: investigation_ownership_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.investigation_ownership_log (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid NOT NULL,
    previous_owner character varying(100),
    new_owner character varying(100),
    previous_owner_type character varying(20),
    new_owner_type character varying(20),
    change_type character varying(30) NOT NULL,
    reason text,
    changed_by character varying(100),
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT investigation_ownership_log_change_type_check CHECK (((change_type)::text = ANY ((ARRAY['assigned'::character varying, 'reassigned'::character varying, 'claimed'::character varying, 'released'::character varying, 'escalated'::character varying, 'auto_assigned'::character varying, 'system'::character varying])::text[])))
);

ALTER TABLE ONLY public.investigation_ownership_log FORCE ROW LEVEL SECURITY;


--
-- Name: investigation_summary; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.investigation_summary WITH (security_barrier='true') AS
 SELECT i.id,
    i.investigation_id,
    i.state,
    i.disposition,
    i.priority,
    i.owner,
    i.alert_title,
    i.created_at,
    i.updated_at,
    a.alert_id,
    a.severity AS alert_severity,
    a.status AS alert_status,
    count(n.id) AS note_count
   FROM ((public.investigations i
     LEFT JOIN public.alerts a ON ((i.alert_id = a.id)))
     LEFT JOIN public.investigation_notes n ON (((i.investigation_id)::text = (n.investigation_id)::text)))
  GROUP BY i.id, i.investigation_id, i.state, i.disposition, i.priority, i.owner, i.alert_title, i.created_at, i.updated_at, a.alert_id, a.severity, a.status;


--
-- Name: investigations_display_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.investigations_display_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: investigations_display_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.investigations_display_id_seq OWNED BY public.investigations.display_id;


--
-- Name: ioc_blocklist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_blocklist (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ioc_type character varying(50) NOT NULL,
    ioc_value character varying(500) NOT NULL,
    source character varying(255),
    reason text,
    is_active boolean DEFAULT true,
    added_by character varying(100),
    added_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.ioc_blocklist FORCE ROW LEVEL SECURITY;


--
-- Name: ioc_enrichments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_enrichments (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    ioc_value character varying(2000) NOT NULL,
    ioc_type character varying(50) NOT NULL,
    ioc_value_normalized character varying(2000) NOT NULL,
    status character varying(30) DEFAULT 'unenriched'::character varying NOT NULL,
    result_json jsonb DEFAULT '{}'::jsonb,
    score integer,
    verdict character varying(30),
    sources_checked text[] DEFAULT '{}'::text[],
    sources_flagged text[] DEFAULT '{}'::text[],
    cached_until timestamp with time zone,
    cache_ttl_seconds integer DEFAULT 86400,
    error_message text,
    retry_count integer DEFAULT 0,
    last_error_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    enriched_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT ioc_enrichments_score_check CHECK (((score >= 0) AND (score <= 100)))
);

ALTER TABLE ONLY public.ioc_enrichments FORCE ROW LEVEL SECURITY;


--
-- Name: ioc_feed_appearances; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_feed_appearances (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    ioc_value character varying(500) NOT NULL,
    ioc_type character varying(50) NOT NULL,
    feed_id character varying(100) NOT NULL,
    first_seen_in_feed timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen_in_feed timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    times_seen integer DEFAULT 1,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.ioc_feed_appearances FORCE ROW LEVEL SECURITY;


--
-- Name: ioc_whitelist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_whitelist (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    ioc_value character varying(500) NOT NULL,
    ioc_type character varying(50) NOT NULL,
    reason character varying(500),
    category character varying(50),
    is_pattern boolean DEFAULT false,
    pattern_type character varying(20),
    added_by character varying(100),
    notes text,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT ioc_whitelist_category_check CHECK (((category)::text = ANY ((ARRAY['internal'::character varying, 'trusted_vendor'::character varying, 'false_positive'::character varying, 'business_critical'::character varying, 'cdn_provider'::character varying, 'security_tool'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT ioc_whitelist_ioc_type_check CHECK (((ioc_type)::text = ANY ((ARRAY['ip'::character varying, 'domain'::character varying, 'url'::character varying, 'hash'::character varying, 'hash_md5'::character varying, 'hash_sha1'::character varying, 'hash_sha256'::character varying, 'email'::character varying, 'username'::character varying, 'hostname'::character varying, 'file_path'::character varying, 'cve'::character varying, 'mitre_attack'::character varying])::text[]))),
    CONSTRAINT ioc_whitelist_pattern_type_check CHECK (((pattern_type)::text = ANY ((ARRAY['exact'::character varying, 'prefix'::character varying, 'suffix'::character varying, 'contains'::character varying, 'regex'::character varying])::text[])))
);

ALTER TABLE ONLY public.ioc_whitelist FORCE ROW LEVEL SECURITY;


--
-- Name: iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.iocs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    ioc_value character varying(500) NOT NULL,
    ioc_type character varying(50) NOT NULL,
    severity character varying(20),
    confidence numeric(5,2),
    reputation character varying(20),
    first_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_seen timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    occurrences integer DEFAULT 1,
    enrichment_data jsonb DEFAULT '{}'::jsonb,
    source character varying(100),
    tags text[],
    source_type character varying(50),
    source_id character varying(255),
    feed_name character varying(100),
    ingested_at timestamp with time zone,
    last_enriched_at timestamp with time zone,
    enrichment_trigger character varying(50),
    feed_last_seen_at timestamp with time zone,
    feed_occurrences integer DEFAULT 0,
    tenant_id uuid NOT NULL,
    CONSTRAINT iocs_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (100)::numeric))),
    CONSTRAINT iocs_enrichment_trigger_check CHECK (((enrichment_trigger)::text = ANY ((ARRAY['manual'::character varying, 'auto_initial'::character varying, 'feed_reappear'::character varying, 'scheduled'::character varying, 'investigation'::character varying])::text[]))),
    CONSTRAINT iocs_ioc_type_check CHECK (((ioc_type)::text = ANY ((ARRAY['ip'::character varying, 'domain'::character varying, 'url'::character varying, 'hash'::character varying, 'hash_md5'::character varying, 'hash_sha1'::character varying, 'hash_sha256'::character varying, 'email'::character varying, 'username'::character varying, 'hostname'::character varying, 'file_path'::character varying, 'cve'::character varying, 'mitre_attack'::character varying])::text[]))),
    CONSTRAINT iocs_reputation_check CHECK ((((reputation)::text = ANY ((ARRAY['clean'::character varying, 'suspicious'::character varying, 'malicious'::character varying, 'unknown'::character varying])::text[])) OR (reputation IS NULL))),
    CONSTRAINT iocs_severity_check CHECK (((severity)::text = ANY ((ARRAY['unknown'::character varying, 'low'::character varying, 'medium'::character varying, 'high'::character varying, 'critical'::character varying])::text[]))),
    CONSTRAINT iocs_source_type_check CHECK (((source_type)::text = ANY ((ARRAY['manual'::character varying, 'ai_agent'::character varying, 'event'::character varying, 'investigation'::character varying, 'threat_feed'::character varying])::text[])))
);

ALTER TABLE ONLY public.iocs FORCE ROW LEVEL SECURITY;


--
-- Name: TABLE iocs; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.iocs IS 'Indicator of Compromise tracking';


--
-- Name: itsm_configurations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itsm_configurations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    system_type character varying(50) NOT NULL,
    base_url character varying(500) NOT NULL,
    instance_name character varying(255),
    credential_id character varying(255),
    default_project character varying(100),
    default_ticket_type character varying(100) DEFAULT 'incident'::character varying,
    field_mappings jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: itsm_exports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.itsm_exports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    investigation_id character varying(255) NOT NULL,
    itsm_config_id character varying(255) NOT NULL,
    ticket_id character varying(255),
    ticket_url character varying(500),
    ticket_type character varying(100),
    export_data jsonb DEFAULT '{}'::jsonb,
    status character varying(50) DEFAULT 'success'::character varying,
    error_message text,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: job_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.job_queue (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    queue_name character varying(100) NOT NULL,
    job_type character varying(100) NOT NULL,
    payload jsonb NOT NULL,
    priority integer DEFAULT 5,
    status character varying(20) DEFAULT 'pending'::character varying,
    attempts integer DEFAULT 0,
    max_attempts integer DEFAULT 3,
    scheduled_for timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    locked_by character varying(100),
    locked_until timestamp with time zone,
    error_message text,
    result jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT job_queue_priority_check CHECK (((priority >= 1) AND (priority <= 10))),
    CONSTRAINT job_queue_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying, 'completed'::character varying, 'failed'::character varying, 'dead'::character varying])::text[])))
);


--
-- Name: kb_community_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kb_community_submissions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    kb_id character varying(100) NOT NULL,
    tenant_id uuid NOT NULL,
    submitted_by character varying(100) NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying,
    reviewer_notes text,
    reviewed_by character varying(100),
    reviewed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT kb_community_submissions_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying])::text[])))
);

ALTER TABLE ONLY public.kb_community_submissions FORCE ROW LEVEL SECURITY;


--
-- Name: kb_document_uploads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.kb_document_uploads (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    upload_id character varying(50) NOT NULL,
    filename character varying(500) NOT NULL,
    file_type character varying(20) NOT NULL,
    file_size integer,
    status character varying(30) DEFAULT 'pending'::character varying,
    error_message text,
    resulting_kb_ids text[] DEFAULT '{}'::text[],
    uploaded_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp with time zone,
    CONSTRAINT kb_document_uploads_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying, 'completed'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: knowledge_base; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.knowledge_base (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    kb_id character varying(20) NOT NULL,
    title character varying(500) NOT NULL,
    content text NOT NULL,
    content_type character varying(50) DEFAULT 'sop'::character varying,
    category character varying(100),
    subcategory character varying(100),
    tags text[] DEFAULT '{}'::text[],
    severity_filter text[] DEFAULT '{}'::text[],
    incident_types text[] DEFAULT '{}'::text[],
    ioc_types text[] DEFAULT '{}'::text[],
    mitre_techniques text[] DEFAULT '{}'::text[],
    compliance_frameworks text[] DEFAULT '{}'::text[],
    priority integer DEFAULT 100,
    is_active boolean DEFAULT true,
    version integer DEFAULT 1,
    ai_processed boolean DEFAULT false,
    ai_summary text,
    ai_extracted_rules jsonb DEFAULT '[]'::jsonb,
    source_document_name character varying(500),
    source_document_type character varying(50),
    created_by character varying(100),
    approved_by character varying(100),
    approved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    embedding jsonb,
    source character varying(20) DEFAULT 'user'::character varying,
    tenant_id uuid,
    CONSTRAINT knowledge_base_content_type_check CHECK (((content_type)::text = ANY ((ARRAY['sop'::character varying, 'playbook'::character varying, 'escalation'::character varying, 'compliance'::character varying, 'permission'::character varying, 'approval_rule'::character varying, 'handling_rule'::character varying, 'runbook'::character varying, 'policy'::character varying, 'procedure'::character varying])::text[])))
);

ALTER TABLE ONLY public.knowledge_base FORCE ROW LEVEL SECURITY;


--
-- Name: knowledge_base_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.knowledge_base_versions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    kb_id character varying(20) NOT NULL,
    version integer NOT NULL,
    title character varying(500) NOT NULL,
    content text NOT NULL,
    changed_by character varying(100),
    change_reason text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: lead_drafts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.lead_drafts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_type character varying(32) NOT NULL,
    source_id character varying(128) NOT NULL,
    lead_email character varying(320) NOT NULL,
    lead_name character varying(255),
    lead_company character varying(255),
    classification character varying(32) DEFAULT 'unknown'::character varying NOT NULL,
    classification_confidence numeric(3,2),
    classification_reason text,
    draft_subject character varying(300),
    draft_body text,
    status character varying(20) DEFAULT 'pending_review'::character varying NOT NULL,
    reviewed_at timestamp with time zone,
    reviewed_by character varying(320),
    sent_at timestamp with time zone,
    send_error text,
    approval_token character varying(128) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT lead_drafts_classification_check CHECK (((classification)::text = ANY ((ARRAY['real_prospect'::character varying, 'partner'::character varying, 'competitor'::character varying, 'noise'::character varying, 'unknown'::character varying])::text[]))),
    CONSTRAINT lead_drafts_classification_confidence_check CHECK (((classification_confidence IS NULL) OR ((classification_confidence >= (0)::numeric) AND (classification_confidence <= (1)::numeric)))),
    CONSTRAINT lead_drafts_source_type_check CHECK (((source_type)::text = ANY ((ARRAY['signup'::character varying, 'contact'::character varying, 'triage_demo'::character varying])::text[]))),
    CONSTRAINT lead_drafts_status_check CHECK (((status)::text = ANY ((ARRAY['pending_review'::character varying, 'approved'::character varying, 'rejected'::character varying, 'sent'::character varying, 'failed'::character varying])::text[])))
);


--
-- Name: llm_mesh_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_mesh_snapshots (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    snapshot_time timestamp with time zone NOT NULL,
    endpoint_url character varying(500) NOT NULL,
    status character varying(20) DEFAULT 'unknown'::character varying,
    model_name character varying(255),
    weight integer DEFAULT 1,
    active_requests integer DEFAULT 0,
    requests_1min integer DEFAULT 0,
    requests_5min integer DEFAULT 0,
    success_count bigint DEFAULT 0,
    failure_count bigint DEFAULT 0,
    total_tokens_processed bigint DEFAULT 0,
    total_prompt_tokens bigint DEFAULT 0,
    total_completion_tokens bigint DEFAULT 0,
    tokens_per_second numeric(10,2) DEFAULT 0,
    avg_latency_ms numeric(10,1) DEFAULT 0,
    p50_latency_ms numeric(10,1) DEFAULT 0,
    p95_latency_ms numeric(10,1) DEFAULT 0,
    p99_latency_ms numeric(10,1) DEFAULT 0,
    consecutive_failures integer DEFAULT 0,
    last_error character varying(500),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT llm_mesh_snapshots_status_check CHECK (((status)::text = ANY ((ARRAY['healthy'::character varying, 'unhealthy'::character varying, 'unknown'::character varying, 'draining'::character varying])::text[])))
);


--
-- Name: log_agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.log_agents (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    agent_id character varying(255) NOT NULL,
    hostname character varying(255) NOT NULL,
    os_type character varying(50) NOT NULL,
    os_version character varying(100),
    ip_address inet,
    agent_version character varying(50),
    status character varying(20) DEFAULT 'active'::character varying,
    last_heartbeat timestamp with time zone,
    last_event_received timestamp with time zone,
    events_received_total bigint DEFAULT 0,
    config jsonb DEFAULT '{}'::jsonb,
    tags text[] DEFAULT ARRAY[]::text[],
    registered_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    registered_by character varying(255),
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    metadata jsonb DEFAULT '{}'::jsonb,
    CONSTRAINT log_agents_os_type_check CHECK (((os_type)::text = ANY ((ARRAY['windows'::character varying, 'linux'::character varying, 'macos'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT log_agents_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'inactive'::character varying, 'maintenance'::character varying, 'decommissioned'::character varying])::text[])))
);


--
-- Name: log_indexes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.log_indexes (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    display_name character varying(255) NOT NULL,
    description text,
    index_pattern character varying(255) NOT NULL,
    data_classification character varying(50) DEFAULT 'internal'::character varying,
    retention_days integer DEFAULT 90,
    is_active boolean DEFAULT true,
    is_default boolean DEFAULT false,
    source_types text[],
    tags text[],
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100),
    CONSTRAINT log_indexes_data_classification_check CHECK (((data_classification)::text = ANY ((ARRAY['public'::character varying, 'internal'::character varying, 'confidential'::character varying, 'restricted'::character varying])::text[])))
);


--
-- Name: log_search_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.log_search_audit (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid,
    username character varying(100) NOT NULL,
    user_role character varying(50),
    search_query text,
    index_names text[],
    time_range character varying(50),
    search_type character varying(20) DEFAULT 'log'::character varying,
    event_classes text[],
    results_count integer,
    execution_time_ms integer,
    ip_address inet,
    user_agent text,
    success boolean DEFAULT true,
    error_message text,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: log_source_configs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.log_source_configs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    source_type character varying(100) NOT NULL,
    display_name character varying(255) NOT NULL,
    description text,
    parser_type character varying(50) DEFAULT 'json'::character varying,
    parser_config jsonb DEFAULT '{}'::jsonb,
    field_mappings jsonb DEFAULT '{}'::jsonb,
    auto_enrichments jsonb DEFAULT '[]'::jsonb,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT log_source_configs_parser_type_check CHECK (((parser_type)::text = ANY ((ARRAY['json'::character varying, 'syslog'::character varying, 'cef'::character varying, 'leef'::character varying, 'csv'::character varying, 'regex'::character varying, 'xml'::character varying])::text[])))
);


--
-- Name: log_source_types; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.log_source_types (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source_type character varying(100) NOT NULL,
    display_name character varying(255),
    description text,
    category character varying(100),
    parser_type character varying(100),
    default_index_name character varying(255),
    fields_schema jsonb DEFAULT '{}'::jsonb,
    is_builtin boolean DEFAULT false,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: login_attempts_by_ip; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.login_attempts_by_ip (
    ip_address inet NOT NULL,
    attempt_count integer DEFAULT 1 NOT NULL,
    first_attempt_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    locked_until timestamp with time zone
);


--
-- Name: ml_predictions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ml_predictions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    alert_id uuid,
    predicted_disposition character varying(50) NOT NULL,
    confidence double precision NOT NULL,
    model_version character varying(50),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    actual_disposition character varying(50),
    resolved_by character varying(255),
    resolved_at timestamp with time zone,
    investigation_id character varying(100)
);


--
-- Name: ml_training_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ml_training_runs (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    trained_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    status character varying(20) NOT NULL,
    samples_used integer DEFAULT 0,
    accuracy double precision,
    trigger_reason character varying(50),
    error_message text,
    model_version character varying(50),
    training_duration_ms integer,
    config jsonb DEFAULT '{}'::jsonb,
    CONSTRAINT ml_training_runs_status_check CHECK (((status)::text = ANY ((ARRAY['success'::character varying, 'failed'::character varying, 'skipped'::character varying])::text[])))
);


--
-- Name: model_performance_daily; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.model_performance_daily (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    metric_date date NOT NULL,
    provider character varying(50) NOT NULL,
    model character varying(255) NOT NULL,
    total_calls integer DEFAULT 0,
    successful_calls integer DEFAULT 0,
    failed_calls integer DEFAULT 0,
    timeout_calls integer DEFAULT 0,
    total_prompt_tokens bigint DEFAULT 0,
    total_completion_tokens bigint DEFAULT 0,
    total_cost_cents numeric(12,4) DEFAULT 0,
    avg_cost_per_call_cents numeric(10,4),
    avg_response_time_ms integer,
    p50_response_time_ms integer,
    p95_response_time_ms integer,
    p99_response_time_ms integer,
    max_response_time_ms integer,
    investigations_involved integer DEFAULT 0,
    correct_verdicts integer DEFAULT 0,
    incorrect_verdicts integer DEFAULT 0,
    accuracy_rate numeric(5,2),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: notification_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notification_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    enabled boolean DEFAULT true,
    event_types text[] DEFAULT '{}'::text[],
    severity_filter text[] DEFAULT '{}'::text[],
    source_filter text[] DEFAULT '{}'::text[],
    recipients text[] DEFAULT '{}'::text[],
    recipient_roles text[] DEFAULT '{}'::text[],
    template_id uuid,
    subject_template character varying(500) DEFAULT '[T1 Agentics] {event_type}: {title}'::character varying,
    body_template text,
    include_approval_links boolean DEFAULT false,
    approval_ttl_minutes integer DEFAULT 60,
    approval_require_auth boolean DEFAULT false,
    is_digest boolean DEFAULT false,
    digest_cron character varying(100),
    last_digest_sent timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100),
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.notification_rules FORCE ROW LEVEL SECURITY;


--
-- Name: notifications; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.notifications (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    user_id uuid,
    title character varying(255) NOT NULL,
    message text,
    category character varying(50) DEFAULT 'system'::character varying NOT NULL,
    severity character varying(20) DEFAULT 'info'::character varying,
    link character varying(500),
    read boolean DEFAULT false,
    read_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    metadata jsonb DEFAULT '{}'::jsonb
);

ALTER TABLE ONLY public.notifications FORCE ROW LEVEL SECURITY;


--
-- Name: password_reset_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.password_reset_tokens (
    id integer NOT NULL,
    token text NOT NULL,
    username text NOT NULL,
    email text NOT NULL,
    expiry timestamp without time zone NOT NULL,
    used boolean DEFAULT false,
    created_at timestamp without time zone DEFAULT now()
);


--
-- Name: password_reset_tokens_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.password_reset_tokens_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: password_reset_tokens_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.password_reset_tokens_id_seq OWNED BY public.password_reset_tokens.id;


--
-- Name: phishing_campaigns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.phishing_campaigns (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    campaign_id character varying(100) DEFAULT ('CAMP-'::text || upper("substring"((gen_random_uuid())::text, 1, 8))) NOT NULL,
    name character varying(255),
    description text,
    common_sender_domain character varying(255),
    common_subject_pattern character varying(500),
    common_urls text[],
    common_domains text[],
    common_ips text[],
    report_count integer DEFAULT 1,
    unique_targets integer DEFAULT 0,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    status character varying(30) DEFAULT 'active'::character varying,
    severity character varying(20) DEFAULT 'medium'::character varying,
    threat_actor character varying(255),
    attack_type character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT phishing_campaigns_status_check CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'contained'::character varying, 'resolved'::character varying, 'false_positive'::character varying])::text[])))
);


--
-- Name: phishing_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.phishing_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    report_id character varying(100) DEFAULT ('PHR-'::text || upper("substring"((gen_random_uuid())::text, 1, 8))) NOT NULL,
    inbound_email_id uuid,
    message_id character varying(500),
    campaign_id uuid,
    similarity_hash character varying(64),
    reporter_email character varying(255) NOT NULL,
    reporter_name character varying(255),
    reporter_department character varying(255),
    reported_subject character varying(500),
    reported_from character varying(255),
    reported_body_preview text,
    reported_received_at timestamp with time zone,
    extracted_urls text[] DEFAULT '{}'::text[],
    extracted_domains text[] DEFAULT '{}'::text[],
    extracted_ips text[] DEFAULT '{}'::text[],
    extracted_emails text[] DEFAULT '{}'::text[],
    extracted_hashes text[] DEFAULT '{}'::text[],
    attachment_count integer DEFAULT 0,
    attachment_hashes text[] DEFAULT '{}'::text[],
    status character varying(30) DEFAULT 'new'::character varying,
    severity character varying(20) DEFAULT 'medium'::character varying,
    verdict character varying(50),
    analysis_notes text,
    alert_id uuid,
    investigation_id uuid,
    analyzed_at timestamp with time zone,
    analyzed_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT phishing_reports_status_check CHECK (((status)::text = ANY ((ARRAY['new'::character varying, 'analyzing'::character varying, 'confirmed_phishing'::character varying, 'confirmed_safe'::character varying, 'suspicious'::character varying, 'closed'::character varying, 'false_positive'::character varying])::text[])))
);


--
-- Name: phishing_test_list; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.phishing_test_list (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sender_pattern text NOT NULL,
    subject_pattern text NOT NULL,
    match_type text DEFAULT 'contains'::text NOT NULL,
    test_name text,
    vendor text,
    auto_close boolean DEFAULT true NOT NULL,
    skip_enrichment boolean DEFAULT true NOT NULL,
    disposition text DEFAULT 'BENIGN_POSITIVE'::text NOT NULL,
    valid_from timestamp with time zone DEFAULT now() NOT NULL,
    valid_until timestamp with time zone,
    added_by text,
    is_active boolean DEFAULT true NOT NULL,
    hit_count integer DEFAULT 0 NOT NULL,
    last_hit_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    tenant_id uuid,
    CONSTRAINT phishing_test_list_match_type_check CHECK ((match_type = ANY (ARRAY['exact'::text, 'contains'::text, 'regex'::text])))
);

ALTER TABLE ONLY public.phishing_test_list FORCE ROW LEVEL SECURITY;


--
-- Name: phishing_tests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.phishing_tests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    sender_type character varying(50) NOT NULL,
    value character varying(500) NOT NULL,
    campaign_name character varying(255),
    description text,
    added_by character varying(255),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp without time zone,
    tenant_id uuid
);

ALTER TABLE ONLY public.phishing_tests FORCE ROW LEVEL SECURITY;


--
-- Name: platform_admins; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_admins (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    email character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    permissions jsonb DEFAULT '["read", "write", "manage_tenants", "manage_licenses"]'::jsonb,
    is_active boolean DEFAULT true,
    last_login_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    created_by uuid
);


--
-- Name: platform_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_audit_log (
    id bigint NOT NULL,
    admin_id uuid,
    action character varying(100) NOT NULL,
    target_type character varying(50),
    target_id uuid,
    details jsonb,
    ip_address inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: platform_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.platform_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: platform_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.platform_audit_log_id_seq OWNED BY public.platform_audit_log.id;


--
-- Name: playbooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbooks (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    trigger_conditions jsonb DEFAULT '{}'::jsonb,
    canvas_data jsonb DEFAULT '{"edges": [], "nodes": []}'::jsonb NOT NULL,
    is_enabled boolean DEFAULT false,
    riggs_allowed boolean DEFAULT false,
    requires_approval boolean DEFAULT true,
    tags text[] DEFAULT '{}'::text[],
    alert_types text[] DEFAULT '{}'::text[],
    severity_filter text[] DEFAULT '{}'::text[],
    data_sources text[] DEFAULT '{}'::text[],
    priority integer DEFAULT 50,
    version integer DEFAULT 1,
    previous_version_id uuid,
    riggs_suggestions jsonb DEFAULT '[]'::jsonb,
    last_riggs_review timestamp with time zone,
    riggs_confidence double precision,
    imported_from character varying(50),
    import_metadata jsonb DEFAULT '{}'::jsonb,
    created_by uuid,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid NOT NULL,
    trigger_timing character varying(50) DEFAULT 'post_triage'::character varying,
    CONSTRAINT playbooks_priority_check CHECK (((priority >= 1) AND (priority <= 100)))
);

ALTER TABLE ONLY public.playbooks FORCE ROW LEVEL SECURITY;


--
-- Name: COLUMN playbooks.trigger_timing; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.playbooks.trigger_timing IS 'When playbook runs relative to triage:
  - pre_triage: After enrichment, before T1 (results visible to T1)
  - post_triage: After T1/Riggs completes (current behavior)
  - on_demand: Only manual execution or Riggs recommendation
  - parallel: Runs alongside triage (does not block T1)';


--
-- Name: tenant_licenses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_licenses (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    license_key character varying(64) NOT NULL,
    tier character varying(50) DEFAULT 'community'::character varying NOT NULL,
    issued_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone,
    is_active boolean DEFAULT true,
    custom_limits jsonb,
    stripe_subscription_id character varying(255),
    billing_cycle character varying(20),
    issued_by uuid,
    revoked_at timestamp with time zone,
    revoked_by uuid,
    revoke_reason text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT valid_tier CHECK (((tier)::text = ANY ((ARRAY['community'::character varying, 'poc'::character varying, 'starter'::character varying, 'professional'::character varying, 'enterprise'::character varying, 'enterprise_plus'::character varying, 'platform'::character varying, 'trial'::character varying])::text[])))
);

ALTER TABLE ONLY public.tenant_licenses FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_usage_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_usage_snapshots (
    id bigint NOT NULL,
    tenant_id uuid NOT NULL,
    snapshot_date date NOT NULL,
    alerts_count integer DEFAULT 0,
    investigations_count integer DEFAULT 0,
    playbooks_count integer DEFAULT 0,
    playbook_executions_count integer DEFAULT 0,
    users_count integer DEFAULT 0,
    integrations_count integer DEFAULT 0,
    ai_queries_count integer DEFAULT 0,
    storage_bytes bigint DEFAULT 0,
    alerts_today integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE ONLY public.tenant_usage_snapshots FORCE ROW LEVEL SECURITY;


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug character varying(50) NOT NULL,
    name character varying(255) NOT NULL,
    plan character varying(50) DEFAULT 'community'::character varying NOT NULL,
    license_key character varying(255),
    alerts_per_day_limit integer,
    playbooks_limit integer,
    integrations_limit integer,
    users_limit integer,
    retention_days integer,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    suspended_at timestamp with time zone,
    suspended_reason text,
    stripe_customer_id character varying(255),
    billing_email character varying(255),
    settings jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    active_license_id uuid,
    billing_status character varying(30) DEFAULT 'none'::character varying,
    stripe_subscription_id character varying(255),
    billing_grace_deadline timestamp with time zone,
    stripe_metered_item_id character varying(255),
    uuid uuid DEFAULT gen_random_uuid() NOT NULL,
    referrer_discount_applied boolean DEFAULT false,
    referrer_discount_expires_at timestamp with time zone,
    referrer_discount_pending boolean DEFAULT false,
    referrer_discount_pending_expires_at timestamp with time zone,
    CONSTRAINT valid_plan CHECK (((plan)::text = ANY ((ARRAY['community'::character varying, 'poc'::character varying, 'starter'::character varying, 'professional'::character varying, 'enterprise'::character varying, 'enterprise_plus'::character varying, 'platform'::character varying])::text[]))),
    CONSTRAINT valid_slug CHECK ((((slug)::text ~ '^[a-z0-9][a-z0-9-]*[a-z0-9]$'::text) AND (length((slug)::text) >= 3))),
    CONSTRAINT valid_status CHECK (((status)::text = ANY ((ARRAY['active'::character varying, 'suspended'::character varying, 'cancelled'::character varying, 'pending'::character varying])::text[])))
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    username character varying(100) NOT NULL,
    email character varying(255) NOT NULL,
    hashed_password character varying(255) NOT NULL,
    full_name character varying(255),
    role character varying(20) NOT NULL,
    disabled boolean DEFAULT false,
    force_password_reset boolean DEFAULT false,
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp with time zone,
    last_failed_login timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_login timestamp with time zone,
    tenant_id uuid NOT NULL,
    tenant_role character varying(20) DEFAULT 'analyst'::character varying,
    totp_secret character varying(64),
    totp_verified boolean DEFAULT false,
    mfa_enabled boolean DEFAULT false,
    totp_recovery_codes text,
    tos_accepted_at timestamp with time zone,
    CONSTRAINT users_role_check CHECK (((role)::text = ANY ((ARRAY['admin'::character varying, 'analyst'::character varying, 'read_only'::character varying])::text[])))
);

ALTER TABLE ONLY public.users FORCE ROW LEVEL SECURITY;


--
-- Name: TABLE users; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.users IS 'User accounts with RBAC roles';


--
-- Name: COLUMN users.tos_accepted_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.users.tos_accepted_at IS 'Timestamp when the user accepted the TOS, AUP, Privacy Policy, and AI Governance Policy. NULL for pre-existing accounts created before this migration.';


--
-- Name: platform_tenant_overview; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.platform_tenant_overview AS
 SELECT t.id AS tenant_id,
    t.slug,
    t.name,
    t.plan,
    t.status,
    t.created_at,
    (t.settings ->> 'is_platform_owner'::text) AS is_platform_owner,
    tl.license_key,
    tl.tier AS license_tier,
    tl.expires_at AS license_expires,
    tl.is_active AS license_active,
    COALESCE((us.alerts_count)::bigint, ( SELECT count(*) AS count
           FROM public.alerts a
          WHERE (a.tenant_id = t.id))) AS alerts_count,
    COALESCE((us.users_count)::bigint, ( SELECT count(*) AS count
           FROM public.users u
          WHERE (u.tenant_id = t.id))) AS users_count,
    COALESCE((us.playbooks_count)::bigint, ( SELECT count(*) AS count
           FROM public.playbooks p
          WHERE (p.tenant_id = t.id))) AS playbooks_count,
    t.alerts_per_day_limit,
    t.users_limit,
    t.playbooks_limit
   FROM ((public.tenants t
     LEFT JOIN public.tenant_licenses tl ON ((tl.id = t.active_license_id)))
     LEFT JOIN LATERAL ( SELECT tenant_usage_snapshots.id,
            tenant_usage_snapshots.tenant_id,
            tenant_usage_snapshots.snapshot_date,
            tenant_usage_snapshots.alerts_count,
            tenant_usage_snapshots.investigations_count,
            tenant_usage_snapshots.playbooks_count,
            tenant_usage_snapshots.playbook_executions_count,
            tenant_usage_snapshots.users_count,
            tenant_usage_snapshots.integrations_count,
            tenant_usage_snapshots.ai_queries_count,
            tenant_usage_snapshots.storage_bytes,
            tenant_usage_snapshots.alerts_today,
            tenant_usage_snapshots.created_at
           FROM public.tenant_usage_snapshots
          WHERE (tenant_usage_snapshots.tenant_id = t.id)
          ORDER BY tenant_usage_snapshots.snapshot_date DESC
         LIMIT 1) us ON (true));


--
-- Name: playbook_community_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_community_submissions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    playbook_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    submitted_by character varying(100) NOT NULL,
    submitter_email character varying(320),
    submission_notes text,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    reviewer_notes text,
    reviewed_by character varying(100),
    reviewed_at timestamp with time zone,
    template_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT playbook_community_submissions_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'approved'::character varying, 'rejected'::character varying])::text[])))
);


--
-- Name: playbook_execution_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_execution_approvals (
    id text NOT NULL,
    investigation_id text NOT NULL,
    playbook_id uuid NOT NULL,
    playbook_name text NOT NULL,
    riggs_verdict text,
    riggs_confidence integer,
    riggs_reasoning text,
    status text DEFAULT 'pending'::text NOT NULL,
    approved_by text,
    approval_notes text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    responded_at timestamp without time zone,
    expires_at timestamp without time zone,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.playbook_execution_approvals FORCE ROW LEVEL SECURITY;


--
-- Name: playbook_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_executions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    execution_id character varying(30) NOT NULL,
    playbook_id uuid NOT NULL,
    playbook_version integer,
    alert_id uuid,
    investigation_id uuid,
    status character varying(30) DEFAULT 'pending'::character varying,
    current_node_id character varying(100),
    execution_context jsonb DEFAULT '{}'::jsonb,
    node_results jsonb DEFAULT '{}'::jsonb,
    error_message text,
    triggered_by character varying(50) DEFAULT 'manual'::character varying,
    triggered_by_user_id uuid,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    timeout_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid NOT NULL,
    resume_at timestamp with time zone,
    CONSTRAINT playbook_executions_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'waiting_approval'::character varying, 'waiting_input'::character varying, 'waiting_file'::character varying, 'waiting_delay'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying, 'timeout'::character varying])::text[])))
);

ALTER TABLE ONLY public.playbook_executions FORCE ROW LEVEL SECURITY;


--
-- Name: COLUMN playbook_executions.resume_at; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.playbook_executions.resume_at IS 'Timestamp when a delayed execution should be resumed';


--
-- Name: playbook_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_files (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    execution_id uuid,
    form_submission_id uuid,
    filename character varying(255) NOT NULL,
    original_filename character varying(255),
    file_type character varying(100),
    file_size bigint,
    storage_path text NOT NULL,
    storage_type character varying(20) DEFAULT 'local'::character varying,
    checksum character varying(64),
    scanned boolean DEFAULT false,
    scan_result character varying(20),
    uploaded_by character varying(255),
    uploaded_by_user_id uuid,
    uploaded_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.playbook_files FORCE ROW LEVEL SECURITY;


--
-- Name: playbook_form_submissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_form_submissions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    form_id uuid,
    execution_id uuid,
    node_id character varying(100),
    form_data jsonb DEFAULT '{}'::jsonb NOT NULL,
    submitted_by character varying(255),
    submitted_by_user_id uuid,
    submitted_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    files jsonb DEFAULT '[]'::jsonb
);


--
-- Name: playbook_forms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_forms (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    fields jsonb DEFAULT '[]'::jsonb NOT NULL,
    submit_action character varying(50) DEFAULT 'continue'::character varying,
    submit_label character varying(100) DEFAULT 'Submit'::character varying,
    require_auth boolean DEFAULT true,
    allowed_roles text[] DEFAULT '{}'::text[],
    created_by uuid,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    prefill_mapping jsonb DEFAULT '{}'::jsonb NOT NULL,
    tenant_id uuid NOT NULL
);

ALTER TABLE ONLY public.playbook_forms FORCE ROW LEVEL SECURITY;


--
-- Name: playbook_functions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_functions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    code text NOT NULL,
    input_schema jsonb DEFAULT '{}'::jsonb,
    output_schema jsonb DEFAULT '{}'::jsonb,
    is_approved boolean DEFAULT false,
    approved_by uuid,
    approved_at timestamp with time zone,
    security_notes text,
    usage_count integer DEFAULT 0,
    last_used_at timestamp with time zone,
    created_by uuid,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.playbook_functions FORCE ROW LEVEL SECURITY;


--
-- Name: playbook_lists; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_lists (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    list_type character varying(50) NOT NULL,
    items jsonb DEFAULT '[]'::jsonb NOT NULL,
    item_count integer DEFAULT 0,
    created_by uuid,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.playbook_lists FORCE ROW LEVEL SECURITY;


--
-- Name: playbook_node_approvals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_node_approvals (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    execution_id uuid NOT NULL,
    node_id character varying(100) NOT NULL,
    action_type character varying(100),
    action_details jsonb DEFAULT '{}'::jsonb,
    reason text,
    status character varying(20) DEFAULT 'pending'::character varying,
    requested_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    expires_at timestamp with time zone,
    reviewed_by uuid,
    reviewed_at timestamp with time zone,
    review_notes text,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.playbook_node_approvals FORCE ROW LEVEL SECURITY;


--
-- Name: playbook_templates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_templates (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    category character varying(100),
    canvas_data jsonb NOT NULL,
    trigger_conditions jsonb DEFAULT '{}'::jsonb,
    tags text[] DEFAULT '{}'::text[],
    alert_types text[] DEFAULT '{}'::text[],
    source character varying(50) DEFAULT 'builtin'::character varying,
    usage_count integer DEFAULT 0,
    rating double precision,
    created_by uuid,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    required_integrations jsonb DEFAULT '[]'::jsonb,
    difficulty character varying(20) DEFAULT 'intermediate'::character varying,
    estimated_time character varying(50),
    author character varying(100) DEFAULT 'T1 Agentics'::character varying,
    subcategory character varying(100),
    severity_filter text[] DEFAULT '{}'::text[],
    version character varying(20) DEFAULT '1.0.0'::character varying,
    install_count integer DEFAULT 0,
    slug character varying(200),
    tenant_id uuid
);

ALTER TABLE ONLY public.playbook_templates FORCE ROW LEVEL SECURITY;


--
-- Name: playbook_versions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.playbook_versions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    playbook_id uuid NOT NULL,
    version_number integer NOT NULL,
    canvas_data jsonb NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    change_summary character varying(500),
    created_by uuid,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.playbook_versions FORCE ROW LEVEL SECURITY;


--
-- Name: poc_tracking; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.poc_tracking (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email_hash character varying(64) NOT NULL,
    ip_hash character varying(64),
    tenant_id uuid,
    poc_started_at timestamp with time zone DEFAULT now(),
    poc_expires_at timestamp with time zone,
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE ONLY public.poc_tracking FORCE ROW LEVEL SECURITY;


--
-- Name: post_resolution_rules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.post_resolution_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    conditions jsonb DEFAULT '{}'::jsonb NOT NULL,
    actions jsonb DEFAULT '[]'::jsonb NOT NULL,
    enabled boolean DEFAULT true,
    priority integer DEFAULT 10,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: post_resolution_tasks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.post_resolution_tasks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    investigation_id character varying(255) NOT NULL,
    task_type character varying(50) NOT NULL,
    task_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    result_data jsonb DEFAULT '{}'::jsonb,
    error_message text,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    CONSTRAINT post_resolution_tasks_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'running'::character varying, 'completed'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[]))),
    CONSTRAINT post_resolution_tasks_task_type_check CHECK (((task_type)::text = ANY ((ARRAY['email_summary'::character varying, 'itsm_export'::character varying, 'cmdb_update'::character varying, 'create_blocklist'::character varying, 'custom'::character varying])::text[])))
);


--
-- Name: public_demo_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.public_demo_usage (
    id bigint NOT NULL,
    ip_hash character(64) NOT NULL,
    bucket_day date NOT NULL,
    bucket_hour timestamp with time zone NOT NULL,
    request_count integer DEFAULT 0 NOT NULL,
    estimated_cost_usd numeric(10,6) DEFAULT 0 NOT NULL,
    input_tokens integer DEFAULT 0 NOT NULL,
    output_tokens integer DEFAULT 0 NOT NULL,
    tool_name character varying(50) DEFAULT 'triage'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: TABLE public_demo_usage; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.public_demo_usage IS 'Per-IP rate limiting + daily spend tracking for unauthenticated public demo tools. Contains only counters and SHA-256 IP hashes; no user-submitted content. Rows older than 30 days should be purged by a periodic job.';


--
-- Name: public_demo_usage_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.public_demo_usage_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: public_demo_usage_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.public_demo_usage_id_seq OWNED BY public.public_demo_usage.id;


--
-- Name: recommended_actions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.recommended_actions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    investigation_id uuid NOT NULL,
    action_type character varying(50) NOT NULL,
    title character varying(255) NOT NULL,
    description text,
    priority character varying(10) DEFAULT 'medium'::character varying NOT NULL,
    ioc_type character varying(50),
    ioc_value text,
    connector_id uuid,
    instance_id uuid,
    connector_action_id character varying(100),
    connector_name character varying(255),
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    approved_by uuid,
    approved_at timestamp with time zone,
    executed_at timestamp with time zone,
    execution_result jsonb,
    dismissed_by uuid,
    dismissed_at timestamp with time zone,
    dismiss_reason text,
    riggs_analysis_id text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.recommended_actions FORCE ROW LEVEL SECURITY;


--
-- Name: referrals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.referrals (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    referral_code character varying(10) NOT NULL,
    referrer_tenant_id uuid NOT NULL,
    referred_email text,
    referred_tenant_id uuid,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    converted_at timestamp with time zone,
    CONSTRAINT referrals_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'converted'::character varying, 'expired'::character varying])::text[])))
);


--
-- Name: registration_rate_limits; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.registration_rate_limits (
    id bigint NOT NULL,
    ip_hash character varying(64) NOT NULL,
    endpoint character varying(100) NOT NULL,
    request_count integer DEFAULT 1,
    window_start timestamp with time zone DEFAULT now()
);


--
-- Name: registration_rate_limits_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.registration_rate_limits_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: registration_rate_limits_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.registration_rate_limits_id_seq OWNED BY public.registration_rate_limits.id;


--
-- Name: registration_requests; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.registration_requests (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email character varying(255) NOT NULL,
    email_hash character varying(64) NOT NULL,
    password_hash character varying(255) NOT NULL,
    tenant_name character varying(100) NOT NULL,
    tenant_slug character varying(50) NOT NULL,
    full_name character varying(255),
    verification_token character varying(128) NOT NULL,
    verification_expires_at timestamp with time zone NOT NULL,
    verified_at timestamp with time zone,
    ip_address inet,
    ip_hash character varying(64),
    user_agent text,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    provisioned_tenant_id uuid,
    rejection_reason text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    requested_plan character varying(50) DEFAULT 'community'::character varying,
    referral_code character varying(10),
    CONSTRAINT registration_requests_status_check CHECK (((status)::text = ANY ((ARRAY['pending'::character varying, 'verified'::character varying, 'provisioned'::character varying, 'expired'::character varying, 'rejected'::character varying, 'waitlisted'::character varying])::text[])))
);


--
-- Name: retention_policies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.retention_policies (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    data_type character varying(50) NOT NULL,
    index_pattern character varying(255),
    hot_days integer DEFAULT 7,
    warm_days integer DEFAULT 30,
    cold_days integer DEFAULT 365,
    delete_after_days integer DEFAULT 2555,
    compliance_requirement character varying(255),
    is_active boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(255),
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_by character varying(255),
    CONSTRAINT retention_policies_data_type_check CHECK (((data_type)::text = ANY ((ARRAY['logs'::character varying, 'alerts'::character varying, 'investigations'::character varying, 'audit_logs'::character varying, 'detection_hits'::character varying])::text[])))
);


--
-- Name: riggs_feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.riggs_feedback (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id character varying(100) NOT NULL,
    alert_id character varying(100),
    t1_verdict character varying(50),
    t1_confidence integer,
    riggs_verdict character varying(50) NOT NULL,
    riggs_confidence integer,
    riggs_mode character varying(10) NOT NULL,
    was_escalated boolean DEFAULT false,
    escalation_reason text,
    human_verdict character varying(50),
    human_feedback text,
    human_reviewed_at timestamp with time zone,
    reviewed_by character varying(100),
    processing_time_ms integer,
    token_count integer,
    ioc_count integer DEFAULT 0,
    entity_count integer DEFAULT 0,
    has_encoded_content boolean DEFAULT false,
    severity character varying(20),
    source character varying(100),
    threat_type character varying(50),
    mitre_techniques text[],
    verdict_match boolean GENERATED ALWAYS AS (
CASE
    WHEN (human_verdict IS NULL) THEN NULL::boolean
    ELSE (lower((riggs_verdict)::text) = lower((human_verdict)::text))
END) STORED,
    t1_match boolean GENERATED ALWAYS AS ((lower((t1_verdict)::text) = lower((riggs_verdict)::text))) STORED,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT riggs_feedback_riggs_confidence_check CHECK (((riggs_confidence >= 0) AND (riggs_confidence <= 100))),
    CONSTRAINT riggs_feedback_riggs_mode_check CHECK (((riggs_mode)::text = ANY ((ARRAY['FAST'::character varying, 'DEEP'::character varying])::text[]))),
    CONSTRAINT riggs_feedback_t1_confidence_check CHECK (((t1_confidence >= 0) AND (t1_confidence <= 100)))
);

ALTER TABLE ONLY public.riggs_feedback FORCE ROW LEVEL SECURITY;


--
-- Name: riggs_accuracy_stats; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.riggs_accuracy_stats WITH (security_barrier='true') AS
 SELECT date(riggs_feedback.created_at) AS analysis_date,
    riggs_feedback.riggs_mode,
    count(*) AS total_analyses,
    count(*) FILTER (WHERE riggs_feedback.t1_match) AS t1_agreement_count,
    count(*) FILTER (WHERE riggs_feedback.verdict_match) AS human_agreement_count,
    count(*) FILTER (WHERE riggs_feedback.was_escalated) AS escalation_count,
    round(avg(riggs_feedback.processing_time_ms)) AS avg_processing_ms,
    round(avg(riggs_feedback.token_count)) AS avg_tokens,
    round(avg(riggs_feedback.riggs_confidence)) AS avg_confidence
   FROM public.riggs_feedback
  GROUP BY (date(riggs_feedback.created_at)), riggs_feedback.riggs_mode
  ORDER BY (date(riggs_feedback.created_at)) DESC, riggs_feedback.riggs_mode;


--
-- Name: riggs_decisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.riggs_decisions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid,
    decision_type character varying(50) NOT NULL,
    decision_value character varying(100),
    reasoning text,
    confidence numeric(5,2),
    evidence jsonb DEFAULT '{}'::jsonb,
    recommendations jsonb DEFAULT '[]'::jsonb,
    model_used character varying(100),
    tokens_used integer,
    processing_time_ms integer,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100) DEFAULT 'riggs_agent'::character varying,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT riggs_decisions_confidence_check CHECK (((confidence >= (0)::numeric) AND (confidence <= (100)::numeric)))
);

ALTER TABLE ONLY public.riggs_decisions FORCE ROW LEVEL SECURITY;


--
-- Name: riggs_playbook_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.riggs_playbook_executions (
    id integer NOT NULL,
    investigation_id text NOT NULL,
    playbook_id uuid NOT NULL,
    execution_id text NOT NULL,
    triggered_by text DEFAULT 'riggs_auto'::text NOT NULL,
    riggs_verdict text,
    riggs_confidence integer,
    outcome text,
    effectiveness_score integer,
    analyst_notes text,
    created_at timestamp without time zone DEFAULT now() NOT NULL,
    feedback_recorded_at timestamp without time zone,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL,
    CONSTRAINT riggs_playbook_executions_effectiveness_score_check CHECK (((effectiveness_score >= 0) AND (effectiveness_score <= 100)))
);

ALTER TABLE ONLY public.riggs_playbook_executions FORCE ROW LEVEL SECURITY;


--
-- Name: riggs_playbook_effectiveness; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.riggs_playbook_effectiveness AS
 SELECT p.id AS playbook_id,
    p.name AS playbook_name,
    count(*) AS total_executions,
    count(*) FILTER (WHERE (rpe.outcome = 'success'::text)) AS successful_executions,
    avg(rpe.effectiveness_score) AS avg_effectiveness,
    count(*) FILTER (WHERE (rpe.triggered_by = 'riggs_auto'::text)) AS auto_executions,
    count(*) FILTER (WHERE (rpe.riggs_verdict = 'MALICIOUS'::text)) AS malicious_verdicts,
    max(rpe.created_at) AS last_executed
   FROM (public.playbooks p
     LEFT JOIN public.riggs_playbook_executions rpe ON ((p.id = rpe.playbook_id)))
  GROUP BY p.id, p.name;


--
-- Name: riggs_playbook_executions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.riggs_playbook_executions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: riggs_playbook_executions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.riggs_playbook_executions_id_seq OWNED BY public.riggs_playbook_executions.id;


--
-- Name: role_index_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.role_index_permissions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    role character varying(50) NOT NULL,
    index_id uuid,
    index_name character varying(100) NOT NULL,
    can_read boolean DEFAULT false,
    can_write boolean DEFAULT false,
    can_delete boolean DEFAULT false,
    can_admin boolean DEFAULT false,
    allowed_fields jsonb,
    denied_fields jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100)
);


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.roles (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(50) NOT NULL,
    display_name character varying(100),
    description text,
    permissions jsonb DEFAULT '[]'::jsonb,
    is_system boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100)
);


--
-- Name: schema_migrations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.schema_migrations (
    id integer NOT NULL,
    migration_name character varying(255) NOT NULL,
    applied_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: schema_migrations_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.schema_migrations_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: schema_migrations_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.schema_migrations_id_seq OWNED BY public.schema_migrations.id;


--
-- Name: sla_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sla_config (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    priority character varying(10) NOT NULL,
    response_time_minutes integer NOT NULL,
    acknowledge_time_minutes integer NOT NULL,
    resolution_time_minutes integer NOT NULL,
    business_hours_only boolean DEFAULT false,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT sla_config_priority_check CHECK (((priority)::text = ANY ((ARRAY['P1'::character varying, 'P2'::character varying, 'P3'::character varying, 'P4'::character varying])::text[])))
);


--
-- Name: soar_executions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.soar_executions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    execution_id character varying(100) NOT NULL,
    playbook_id character varying(100) NOT NULL,
    playbook_version character varying(50),
    playbook_snapshot_path text,
    state character varying(50) DEFAULT 'pending'::character varying,
    current_step character varying(255),
    pause_reason text,
    context jsonb DEFAULT '{}'::jsonb,
    timeline jsonb DEFAULT '[]'::jsonb,
    triggered_by_webhook character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    tenant_id uuid
);

ALTER TABLE ONLY public.soar_executions FORCE ROW LEVEL SECURITY;


--
-- Name: soar_playbooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.soar_playbooks (
    id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    version character varying(50) DEFAULT '1.0'::character varying,
    steps jsonb DEFAULT '[]'::jsonb,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid
);

ALTER TABLE ONLY public.soar_playbooks FORCE ROW LEVEL SECURITY;


--
-- Name: sop_effectiveness_tracking; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sop_effectiveness_tracking (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    kb_id character varying(20) NOT NULL,
    investigation_id character varying(100) NOT NULL,
    was_helpful boolean NOT NULL,
    resolution_time_minutes integer,
    tracked_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: stale_assets; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.stale_assets WITH (security_barrier='true') AS
 SELECT assets.id,
    assets.asset_type,
    assets.hostname,
    assets.fqdn,
    assets.display_name,
    assets.ip_addresses,
    assets.mac_addresses,
    assets.os_family,
    assets.os_name,
    assets.os_version,
    assets.criticality,
    assets.status,
    assets.environment,
    assets.owner,
    assets.owner_team,
    assets.department,
    assets.cost_center,
    assets.location,
    assets.compliance_tags,
    assets.custom_tags,
    assets.discovery_sources,
    assets.first_seen,
    assets.last_seen,
    assets.metadata,
    assets.created_at,
    assets.updated_at,
    assets.created_by,
    assets.updated_by,
    assets.tenant_id
   FROM public.assets
  WHERE ((assets.last_seen < (CURRENT_TIMESTAMP - '7 days'::interval)) AND ((assets.status)::text = 'active'::text));


--
-- Name: stripe_checkout_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.stripe_checkout_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    stripe_session_id character varying(255) NOT NULL,
    tenant_id uuid,
    registration_request_id uuid,
    tier character varying(50) NOT NULL,
    billing_cycle character varying(20) DEFAULT 'monthly'::character varying NOT NULL,
    status character varying(30) DEFAULT 'pending'::character varying NOT NULL,
    stripe_customer_id character varying(255),
    stripe_subscription_id character varying(255),
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE ONLY public.stripe_checkout_sessions FORCE ROW LEVEL SECURITY;


--
-- Name: stripe_webhook_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.stripe_webhook_events (
    event_id text NOT NULL,
    event_type text NOT NULL,
    processed_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: teams; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.teams (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    team_id character varying(100) NOT NULL,
    name character varying(200) NOT NULL,
    description text,
    members text[] DEFAULT ARRAY[]::text[],
    lead_user_id character varying(100),
    max_concurrent_investigations integer DEFAULT 10,
    current_load integer DEFAULT 0,
    specializations text[] DEFAULT ARRAY[]::text[],
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid
);

ALTER TABLE ONLY public.teams FORCE ROW LEVEL SECURITY;


--
-- Name: telemetry_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.telemetry_snapshots (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    snapshot_time timestamp with time zone NOT NULL,
    open_investigations integer DEFAULT 0,
    investigations_last_hour integer DEFAULT 0,
    investigations_auto_resolved_last_hour integer DEFAULT 0,
    investigations_human_resolved_last_hour integer DEFAULT 0,
    agent_executions_last_hour integer DEFAULT 0,
    agent_failures_last_hour integer DEFAULT 0,
    avg_execution_time_ms integer,
    tokens_used_last_hour bigint DEFAULT 0,
    cost_cents_last_hour numeric(10,4) DEFAULT 0,
    accuracy_rate_24h numeric(5,2),
    override_rate_24h numeric(5,2),
    escalation_rate_24h numeric(5,2),
    automation_rate_24h numeric(5,2),
    pending_investigations integer DEFAULT 0,
    pending_enrichments integer DEFAULT 0,
    pending_actions integer DEFAULT 0,
    active_agents integer DEFAULT 0,
    circuit_breakers_open integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: tenant_ai_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_ai_config (
    tenant_id uuid NOT NULL,
    byo_allowed boolean DEFAULT false NOT NULL,
    byo_enabled boolean DEFAULT false NOT NULL,
    chat_provider text,
    chat_api_key_encrypted text,
    chat_model text,
    chat_base_url text,
    chat_api_style text,
    embed_provider text,
    embed_api_key_encrypted text,
    embed_model text,
    embed_base_url text,
    embed_dimensions integer,
    last_validated_at timestamp with time zone,
    last_validation_error text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by uuid,
    chat_max_tokens integer,
    CONSTRAINT tenant_ai_config_chat_api_style_check CHECK (((chat_api_style IS NULL) OR (chat_api_style = ANY (ARRAY['anthropic'::text, 'openai'::text])))),
    CONSTRAINT tenant_ai_config_chat_max_tokens_check CHECK (((chat_max_tokens IS NULL) OR ((chat_max_tokens >= 100) AND (chat_max_tokens <= 16000)))),
    CONSTRAINT tenant_ai_config_chat_provider_check CHECK (((chat_provider IS NULL) OR (chat_provider = ANY (ARRAY['anthropic'::text, 'openai'::text, 'self_hosted'::text])))),
    CONSTRAINT tenant_ai_config_embed_provider_check CHECK (((embed_provider IS NULL) OR (embed_provider = ANY (ARRAY['openai'::text, 'self_hosted'::text, 'disabled'::text]))))
);

ALTER TABLE ONLY public.tenant_ai_config FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_audit_log (
    id bigint NOT NULL,
    tenant_id uuid,
    actor_id uuid,
    actor_type character varying(20) NOT NULL,
    action character varying(50) NOT NULL,
    resource_type character varying(50),
    resource_id character varying(255),
    details jsonb,
    ip_address inet,
    user_agent text,
    created_at timestamp with time zone DEFAULT now()
);

ALTER TABLE ONLY public.tenant_audit_log FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_audit_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tenant_audit_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tenant_audit_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tenant_audit_log_id_seq OWNED BY public.tenant_audit_log.id;


--
-- Name: tenant_byo_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_byo_usage (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    period text NOT NULL,
    provider text NOT NULL,
    request_count bigint DEFAULT 0 NOT NULL,
    prompt_tokens bigint DEFAULT 0 NOT NULL,
    completion_tokens bigint DEFAULT 0 NOT NULL,
    total_tokens bigint DEFAULT 0 NOT NULL,
    last_request_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.tenant_byo_usage FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_claude_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_claude_usage (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    month_start date NOT NULL,
    total_input_tokens bigint DEFAULT 0,
    total_output_tokens bigint DEFAULT 0,
    total_tokens bigint DEFAULT 0,
    total_cost_cents numeric(12,4) DEFAULT 0,
    overage_tokens bigint DEFAULT 0,
    overage_reported_to_stripe boolean DEFAULT false,
    updated_at timestamp without time zone DEFAULT now()
);

ALTER TABLE ONLY public.tenant_claude_usage FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_claude_usage_applied_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_claude_usage_applied_events (
    message_id text NOT NULL,
    tenant_id uuid NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: tenant_llm_context; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_llm_context (
    tenant_id uuid NOT NULL,
    extra_context text,
    include_field_keys jsonb DEFAULT '[]'::jsonb NOT NULL,
    exclude_field_keys jsonb DEFAULT '[]'::jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by uuid
);

ALTER TABLE ONLY public.tenant_llm_context FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_pii_patterns; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_pii_patterns (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    label text NOT NULL,
    pattern text NOT NULL,
    mode text DEFAULT 'mask'::text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by uuid,
    CONSTRAINT tenant_pii_patterns_mode_check CHECK ((mode = ANY (ARRAY['mask'::text, 'redact'::text, 'hash'::text])))
);

ALTER TABLE ONLY public.tenant_pii_patterns FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_quota_warnings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_quota_warnings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    period text NOT NULL,
    threshold text NOT NULL,
    sent_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: tenant_triage_config; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_triage_config (
    tenant_id uuid NOT NULL,
    auto_close_min_confidence numeric(4,3) DEFAULT 0.900 NOT NULL,
    auto_close_min_fp_likelihood numeric(4,3) DEFAULT 0.000 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_by uuid,
    force_all_to_investigation boolean DEFAULT false NOT NULL,
    CONSTRAINT tenant_triage_config_auto_close_min_confidence_check CHECK (((auto_close_min_confidence >= (0)::numeric) AND (auto_close_min_confidence <= (1)::numeric))),
    CONSTRAINT tenant_triage_config_auto_close_min_fp_likelihood_check CHECK (((auto_close_min_fp_likelihood >= (0)::numeric) AND (auto_close_min_fp_likelihood <= (1)::numeric)))
);

ALTER TABLE ONLY public.tenant_triage_config FORCE ROW LEVEL SECURITY;


--
-- Name: tenant_usage_snapshots_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tenant_usage_snapshots_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tenant_usage_snapshots_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tenant_usage_snapshots_id_seq OWNED BY public.tenant_usage_snapshots.id;


--
-- Name: threat_feed_ingestion_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_feed_ingestion_log (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    feed_id character varying(100) NOT NULL,
    started_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    completed_at timestamp with time zone,
    duration_ms integer,
    status character varying(50) NOT NULL,
    iocs_fetched integer DEFAULT 0,
    iocs_new integer DEFAULT 0,
    iocs_updated integer DEFAULT 0,
    iocs_skipped integer DEFAULT 0,
    error_message text,
    error_details jsonb,
    response_size_bytes integer,
    sample_iocs jsonb DEFAULT '[]'::jsonb,
    CONSTRAINT threat_feed_ingestion_log_status_check CHECK (((status)::text = ANY ((ARRAY['success'::character varying, 'failed'::character varying, 'partial'::character varying])::text[])))
);


--
-- Name: threat_feeds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.threat_feeds (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    feed_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    category character varying(50) NOT NULL,
    url text NOT NULL,
    format character varying(50) NOT NULL,
    parser_config jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    poll_interval_minutes integer DEFAULT 60,
    last_poll_at timestamp with time zone,
    next_poll_at timestamp with time zone,
    max_iocs_per_poll integer DEFAULT 10000,
    last_poll_status character varying(50),
    last_poll_error text,
    last_poll_ioc_count integer DEFAULT 0,
    total_iocs_ingested integer DEFAULT 0,
    drop_private_ips boolean DEFAULT true,
    drop_internal_domains boolean DEFAULT true,
    dedupe_window_hours integer DEFAULT 24,
    tags jsonb DEFAULT '[]'::jsonb,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid NOT NULL,
    CONSTRAINT threat_feeds_category_check CHECK (((category)::text = ANY ((ARRAY['ip_blocklist'::character varying, 'domain_blocklist'::character varying, 'url_blocklist'::character varying, 'hash_list'::character varying, 'mixed'::character varying, 'cve'::character varying, 'other'::character varying])::text[]))),
    CONSTRAINT threat_feeds_format_check CHECK (((format)::text = ANY ((ARRAY['txt_lines'::character varying, 'csv'::character varying, 'json'::character varying, 'json_lines'::character varying, 'stix'::character varying, 'misp'::character varying, 'custom'::character varying])::text[]))),
    CONSTRAINT threat_feeds_last_poll_status_check CHECK (((last_poll_status)::text = ANY ((ARRAY['success'::character varying, 'failed'::character varying, 'partial'::character varying, 'pending'::character varying])::text[])))
);

ALTER TABLE ONLY public.threat_feeds FORCE ROW LEVEL SECURITY;


--
-- Name: token_blacklist; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.token_blacklist (
    jti character varying(64) NOT NULL,
    token_type character varying(20) DEFAULT 'token'::character varying NOT NULL,
    username character varying(255),
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    reason character varying(100)
);


--
-- Name: trusted_senders; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trusted_senders (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain character varying(500) NOT NULL,
    sender_pattern character varying(500),
    trust_level character varying(50) DEFAULT 'trusted'::character varying,
    organization character varying(255),
    category character varying(100),
    reason text,
    requires_whois_match boolean DEFAULT false,
    min_domain_age_days integer DEFAULT 365,
    is_active boolean DEFAULT true,
    added_by character varying(255),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    hit_count integer DEFAULT 0,
    last_hit_at timestamp with time zone,
    tenant_id uuid
);

ALTER TABLE ONLY public.trusted_senders FORCE ROW LEVEL SECURITY;


--
-- Name: usage_counters; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_counters (
    tenant_id uuid NOT NULL,
    metric character varying(100) NOT NULL,
    period character varying(7) NOT NULL,
    value bigint DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL
);

ALTER TABLE ONLY public.usage_counters FORCE ROW LEVEL SECURITY;


--
-- Name: usage_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.usage_events (
    id bigint NOT NULL,
    tenant_id uuid NOT NULL,
    event_type character varying(50) NOT NULL,
    quantity integer DEFAULT 1 NOT NULL,
    metadata jsonb,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.usage_events FORCE ROW LEVEL SECURITY;


--
-- Name: usage_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.usage_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: usage_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.usage_events_id_seq OWNED BY public.usage_events.id;


--
-- Name: user_chat_statistics; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.user_chat_statistics WITH (security_barrier='true') AS
 SELECT chat_usage_analytics.user_id,
    chat_usage_analytics.username,
    count(*) FILTER (WHERE ((chat_usage_analytics.event_type)::text = 'message_sent'::text)) AS total_messages,
    count(*) FILTER (WHERE ((chat_usage_analytics.event_type)::text = 'quick_action_used'::text)) AS quick_actions_used,
    count(*) FILTER (WHERE ((chat_usage_analytics.event_type)::text = 'action_requested'::text)) AS actions_requested,
    count(DISTINCT chat_usage_analytics.investigation_id) AS investigations_participated,
    count(DISTINCT chat_usage_analytics.session_id) AS total_sessions,
    min(chat_usage_analytics.created_at) AS first_activity,
    max(chat_usage_analytics.created_at) AS last_activity,
    avg(chat_usage_analytics.message_length) FILTER (WHERE (chat_usage_analytics.message_length IS NOT NULL)) AS avg_message_length
   FROM public.chat_usage_analytics
  GROUP BY chat_usage_analytics.user_id, chat_usage_analytics.username;


--
-- Name: user_index_permissions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_index_permissions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid,
    username character varying(100) NOT NULL,
    index_id uuid,
    index_name character varying(100) NOT NULL,
    can_read boolean,
    can_write boolean,
    can_delete boolean,
    reason text,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100)
);


--
-- Name: user_preferences; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_preferences (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid,
    username character varying(100) NOT NULL,
    preferences jsonb DEFAULT '{}'::jsonb,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: user_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_sessions (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    user_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    jti character varying(64) NOT NULL,
    ip_address inet,
    user_agent text,
    device_type character varying(30),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_active_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    revoke_reason character varying(100),
    is_active boolean DEFAULT true NOT NULL
);

ALTER TABLE ONLY public.user_sessions FORCE ROW LEVEL SECURITY;


--
-- Name: v_verdict_consistency; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_verdict_consistency AS
 SELECT 'investigations'::text AS table_name,
    investigations.disposition AS verdict,
    count(*) AS count
   FROM public.investigations
  WHERE (investigations.disposition IS NOT NULL)
  GROUP BY investigations.disposition
UNION ALL
 SELECT 'riggs_feedback'::text AS table_name,
    riggs_feedback.riggs_verdict AS verdict,
    count(*) AS count
   FROM public.riggs_feedback
  WHERE (riggs_feedback.riggs_verdict IS NOT NULL)
  GROUP BY riggs_feedback.riggs_verdict
UNION ALL
 SELECT 'alerts'::text AS table_name,
    alerts.ai_verdict AS verdict,
    count(*) AS count
   FROM public.alerts
  WHERE (alerts.ai_verdict IS NOT NULL)
  GROUP BY alerts.ai_verdict
  ORDER BY 1, 2;


--
-- Name: VIEW v_verdict_consistency; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON VIEW public.v_verdict_consistency IS 'Diagnostic view to check verdict consistency across tables. All verdicts should match canonical values from models/verdict.py';


--
-- Name: verdict_audit_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.verdict_audit_log (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    investigation_id uuid NOT NULL,
    alert_id uuid,
    change_type character varying(50) NOT NULL,
    previous_verdict character varying(50),
    previous_confidence numeric(5,2),
    new_verdict character varying(50),
    new_confidence numeric(5,2),
    reason text NOT NULL,
    evidence_summary jsonb DEFAULT '{}'::jsonb,
    triggered_by character varying(50) NOT NULL,
    triggered_by_user character varying(100),
    analysis_mode character varying(20),
    merge_version integer,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    tenant_id uuid DEFAULT 'f47ac10b-58cc-4372-a567-0e02b2c3d479'::uuid NOT NULL
);

ALTER TABLE ONLY public.verdict_audit_log FORCE ROW LEVEL SECURITY;


--
-- Name: web_forms; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.web_forms (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    form_id character varying(100) NOT NULL,
    title character varying(255) NOT NULL,
    description text,
    fields jsonb DEFAULT '[]'::jsonb,
    output_config jsonb DEFAULT '{}'::jsonb,
    is_active boolean DEFAULT true,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: webhook_channels; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_channels (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    channel_id character varying(100) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    channel_type character varying(50) NOT NULL,
    webhook_url text NOT NULL,
    config jsonb DEFAULT '{}'::jsonb,
    enabled boolean DEFAULT true,
    last_used_at timestamp with time zone,
    success_count integer DEFAULT 0,
    failure_count integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    created_by character varying(100),
    CONSTRAINT webhook_channels_channel_type_check CHECK (((channel_type)::text = ANY ((ARRAY['slack'::character varying, 'teams'::character varying, 'webex'::character varying, 'discord'::character varying, 'generic'::character varying])::text[])))
);


--
-- Name: webhooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhooks (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    endpoint_path character varying(255) NOT NULL,
    token character varying(255),
    enabled boolean DEFAULT true,
    rate_limit integer DEFAULT 100,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    last_triggered timestamp with time zone,
    trigger_count integer DEFAULT 0,
    tenant_id uuid NOT NULL
);

ALTER TABLE ONLY public.webhooks FORCE ROW LEVEL SECURITY;


--
-- Name: website_analytics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.website_analytics (
    id bigint NOT NULL,
    event_type character varying(50) NOT NULL,
    page_path character varying(255),
    referrer character varying(500),
    ip_hash character varying(64),
    user_agent text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: website_analytics_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.website_analytics_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: website_analytics_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.website_analytics_id_seq OWNED BY public.website_analytics.id;


--
-- Name: alerts display_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts ALTER COLUMN display_id SET DEFAULT nextval('public.alerts_display_id_seq'::regclass);


--
-- Name: edl_access_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_access_log ALTER COLUMN id SET DEFAULT nextval('public.edl_access_log_id_seq'::regclass);


--
-- Name: edl_change_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_change_log ALTER COLUMN id SET DEFAULT nextval('public.edl_change_log_id_seq'::regclass);


--
-- Name: edl_items id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_items ALTER COLUMN id SET DEFAULT nextval('public.edl_items_id_seq'::regclass);


--
-- Name: frontend_errors id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frontend_errors ALTER COLUMN id SET DEFAULT nextval('public.frontend_errors_id_seq'::regclass);


--
-- Name: investigations display_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigations ALTER COLUMN display_id SET DEFAULT nextval('public.investigations_display_id_seq'::regclass);


--
-- Name: password_reset_tokens id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens ALTER COLUMN id SET DEFAULT nextval('public.password_reset_tokens_id_seq'::regclass);


--
-- Name: platform_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_audit_log ALTER COLUMN id SET DEFAULT nextval('public.platform_audit_log_id_seq'::regclass);


--
-- Name: public_demo_usage id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_demo_usage ALTER COLUMN id SET DEFAULT nextval('public.public_demo_usage_id_seq'::regclass);


--
-- Name: registration_rate_limits id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_rate_limits ALTER COLUMN id SET DEFAULT nextval('public.registration_rate_limits_id_seq'::regclass);


--
-- Name: riggs_playbook_executions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.riggs_playbook_executions ALTER COLUMN id SET DEFAULT nextval('public.riggs_playbook_executions_id_seq'::regclass);


--
-- Name: schema_migrations id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations ALTER COLUMN id SET DEFAULT nextval('public.schema_migrations_id_seq'::regclass);


--
-- Name: tenant_audit_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_audit_log ALTER COLUMN id SET DEFAULT nextval('public.tenant_audit_log_id_seq'::regclass);


--
-- Name: tenant_usage_snapshots id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_usage_snapshots ALTER COLUMN id SET DEFAULT nextval('public.tenant_usage_snapshots_id_seq'::regclass);


--
-- Name: usage_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_events ALTER COLUMN id SET DEFAULT nextval('public.usage_events_id_seq'::regclass);


--
-- Name: website_analytics id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.website_analytics ALTER COLUMN id SET DEFAULT nextval('public.website_analytics_id_seq'::regclass);


--
-- Name: action_requests action_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_requests
    ADD CONSTRAINT action_requests_pkey PRIMARY KEY (id);


--
-- Name: action_requests action_requests_request_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_requests
    ADD CONSTRAINT action_requests_request_id_key UNIQUE (request_id);


--
-- Name: action_types action_types_action_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_types
    ADD CONSTRAINT action_types_action_type_key UNIQUE (action_type);


--
-- Name: action_types action_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_types
    ADD CONSTRAINT action_types_pkey PRIMARY KEY (id);


--
-- Name: affiliate_codes affiliate_codes_code_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affiliate_codes
    ADD CONSTRAINT affiliate_codes_code_key UNIQUE (code);


--
-- Name: affiliate_codes affiliate_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affiliate_codes
    ADD CONSTRAINT affiliate_codes_pkey PRIMARY KEY (id);


--
-- Name: agent_action_log agent_action_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_log
    ADD CONSTRAINT agent_action_log_pkey PRIMARY KEY (id);


--
-- Name: agent_approval_requests agent_approval_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_approval_requests
    ADD CONSTRAINT agent_approval_requests_pkey PRIMARY KEY (id);


--
-- Name: agent_approval_requests agent_approval_requests_request_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_approval_requests
    ADD CONSTRAINT agent_approval_requests_request_id_key UNIQUE (request_id);


--
-- Name: agent_definitions agent_definitions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_definitions
    ADD CONSTRAINT agent_definitions_pkey PRIMARY KEY (id);


--
-- Name: agent_executions agent_executions_execution_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_executions
    ADD CONSTRAINT agent_executions_execution_id_key UNIQUE (execution_id);


--
-- Name: agent_executions agent_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_executions
    ADD CONSTRAINT agent_executions_pkey PRIMARY KEY (id);


--
-- Name: agent_performance_daily agent_performance_daily_metric_date_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_performance_daily
    ADD CONSTRAINT agent_performance_daily_metric_date_agent_id_key UNIQUE (metric_date, agent_id);


--
-- Name: agent_performance_daily agent_performance_daily_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_performance_daily
    ADD CONSTRAINT agent_performance_daily_pkey PRIMARY KEY (id);


--
-- Name: agent_rollback_actions agent_rollback_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_rollback_actions
    ADD CONSTRAINT agent_rollback_actions_pkey PRIMARY KEY (id);


--
-- Name: agent_templates agent_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_templates
    ADD CONSTRAINT agent_templates_pkey PRIMARY KEY (id);


--
-- Name: agent_templates agent_templates_template_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_templates
    ADD CONSTRAINT agent_templates_template_id_key UNIQUE (template_id);


--
-- Name: agent_verdict_outcomes agent_verdict_outcomes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_verdict_outcomes
    ADD CONSTRAINT agent_verdict_outcomes_pkey PRIMARY KEY (id);


--
-- Name: ai_action_log ai_action_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_action_log
    ADD CONSTRAINT ai_action_log_pkey PRIMARY KEY (id);


--
-- Name: ai_agent_activity ai_agent_activity_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_agent_activity
    ADD CONSTRAINT ai_agent_activity_pkey PRIMARY KEY (id);


--
-- Name: ai_agent_credentials ai_agent_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_agent_credentials
    ADD CONSTRAINT ai_agent_credentials_pkey PRIMARY KEY (id);


--
-- Name: ai_agents ai_agents_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_agents
    ADD CONSTRAINT ai_agents_agent_id_key UNIQUE (agent_id);


--
-- Name: ai_agents ai_agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_agents
    ADD CONSTRAINT ai_agents_pkey PRIMARY KEY (id);


--
-- Name: ai_providers ai_providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_providers
    ADD CONSTRAINT ai_providers_pkey PRIMARY KEY (id);


--
-- Name: ai_token_usage ai_token_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_token_usage
    ADD CONSTRAINT ai_token_usage_pkey PRIMARY KEY (id);


--
-- Name: alert_attachments alert_attachments_attachment_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_attachments
    ADD CONSTRAINT alert_attachments_attachment_id_key UNIQUE (attachment_id);


--
-- Name: alert_attachments alert_attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_attachments
    ADD CONSTRAINT alert_attachments_pkey PRIMARY KEY (id);


--
-- Name: alert_groups alert_groups_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_groups
    ADD CONSTRAINT alert_groups_fingerprint_key UNIQUE (fingerprint);


--
-- Name: alert_groups alert_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_groups
    ADD CONSTRAINT alert_groups_pkey PRIMARY KEY (id);


--
-- Name: alert_ioc_links alert_ioc_links_alert_id_ioc_value_ioc_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_ioc_links
    ADD CONSTRAINT alert_ioc_links_alert_id_ioc_value_ioc_type_key UNIQUE (alert_id, ioc_value, ioc_type);


--
-- Name: alert_ioc_links alert_ioc_links_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_ioc_links
    ADD CONSTRAINT alert_ioc_links_pkey PRIMARY KEY (id);


--
-- Name: alerts alerts_alert_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_alert_id_key UNIQUE (alert_id);


--
-- Name: alerts alerts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_pkey PRIMARY KEY (id);


--
-- Name: api_keys api_keys_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_key_id_key UNIQUE (key_id);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: approval_requests approval_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_requests
    ADD CONSTRAINT approval_requests_pkey PRIMARY KEY (id);


--
-- Name: approval_tokens approval_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_tokens
    ADD CONSTRAINT approval_tokens_pkey PRIMARY KEY (id);


--
-- Name: approval_tokens approval_tokens_token_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_tokens
    ADD CONSTRAINT approval_tokens_token_id_key UNIQUE (token_id);


--
-- Name: approval_tokens approval_tokens_token_secret_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_tokens
    ADD CONSTRAINT approval_tokens_token_secret_key UNIQUE (token_secret);


--
-- Name: asset_conflicts asset_conflicts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_conflicts
    ADD CONSTRAINT asset_conflicts_pkey PRIMARY KEY (id);


--
-- Name: asset_history asset_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_history
    ADD CONSTRAINT asset_history_pkey PRIMARY KEY (id);


--
-- Name: asset_identifiers asset_identifiers_identifier_type_identifier_value_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_identifiers
    ADD CONSTRAINT asset_identifiers_identifier_type_identifier_value_key UNIQUE (identifier_type, identifier_value);


--
-- Name: asset_identifiers asset_identifiers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_identifiers
    ADD CONSTRAINT asset_identifiers_pkey PRIMARY KEY (id);


--
-- Name: asset_relationships asset_relationships_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_relationships
    ADD CONSTRAINT asset_relationships_pkey PRIMARY KEY (id);


--
-- Name: asset_relationships asset_relationships_source_asset_id_target_asset_id_relatio_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_relationships
    ADD CONSTRAINT asset_relationships_source_asset_id_target_asset_id_relatio_key UNIQUE (source_asset_id, target_asset_id, relationship_type);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);


--
-- Name: assignment_rules assignment_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assignment_rules
    ADD CONSTRAINT assignment_rules_pkey PRIMARY KEY (id);


--
-- Name: audit_log audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_pkey PRIMARY KEY (id);


--
-- Name: auto_response_settings auto_response_settings_instance_id_action_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auto_response_settings
    ADD CONSTRAINT auto_response_settings_instance_id_action_type_key UNIQUE (instance_id, action_type);


--
-- Name: auto_response_settings auto_response_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auto_response_settings
    ADD CONSTRAINT auto_response_settings_pkey PRIMARY KEY (id);


--
-- Name: breach_intel_incidents breach_incidents_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_intel_incidents
    ADD CONSTRAINT breach_incidents_fingerprint_key UNIQUE (fingerprint);


--
-- Name: breach_incidents breach_incidents_fingerprint_key1; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_incidents
    ADD CONSTRAINT breach_incidents_fingerprint_key1 UNIQUE (fingerprint);


--
-- Name: breach_intel_incidents breach_incidents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_intel_incidents
    ADD CONSTRAINT breach_incidents_pkey PRIMARY KEY (id);


--
-- Name: breach_incidents breach_incidents_pkey1; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_incidents
    ADD CONSTRAINT breach_incidents_pkey1 PRIMARY KEY (id);


--
-- Name: breach_intel_sources breach_intel_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_intel_sources
    ADD CONSTRAINT breach_intel_sources_pkey PRIMARY KEY (id);


--
-- Name: breach_intel_sources breach_intel_sources_source_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_intel_sources
    ADD CONSTRAINT breach_intel_sources_source_id_key UNIQUE (source_id);


--
-- Name: campaign_iocs campaign_iocs_campaign_id_ioc_value_ioc_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_iocs
    ADD CONSTRAINT campaign_iocs_campaign_id_ioc_value_ioc_type_key UNIQUE (campaign_id, ioc_value, ioc_type);


--
-- Name: campaign_iocs campaign_iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_iocs
    ADD CONSTRAINT campaign_iocs_pkey PRIMARY KEY (id);


--
-- Name: campaign_members campaign_members_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_members
    ADD CONSTRAINT campaign_members_pkey PRIMARY KEY (id);


--
-- Name: campaigns campaigns_campaign_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaigns
    ADD CONSTRAINT campaigns_campaign_id_key UNIQUE (campaign_id);


--
-- Name: campaigns campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaigns
    ADD CONSTRAINT campaigns_pkey PRIMARY KEY (id);


--
-- Name: case_summaries case_summaries_investigation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_summaries
    ADD CONSTRAINT case_summaries_investigation_id_key UNIQUE (investigation_id);


--
-- Name: case_summaries case_summaries_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_summaries
    ADD CONSTRAINT case_summaries_pkey PRIMARY KEY (id);


--
-- Name: chat_action_audit chat_action_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_action_audit
    ADD CONSTRAINT chat_action_audit_pkey PRIMARY KEY (id);


--
-- Name: chat_subscriptions chat_subscriptions_investigation_id_user_id_connection_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_subscriptions
    ADD CONSTRAINT chat_subscriptions_investigation_id_user_id_connection_id_key UNIQUE (investigation_id, user_id, connection_id);


--
-- Name: chat_subscriptions chat_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_subscriptions
    ADD CONSTRAINT chat_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: chat_typing_status chat_typing_status_investigation_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_typing_status
    ADD CONSTRAINT chat_typing_status_investigation_id_user_id_key UNIQUE (investigation_id, user_id);


--
-- Name: chat_typing_status chat_typing_status_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_typing_status
    ADD CONSTRAINT chat_typing_status_pkey PRIMARY KEY (id);


--
-- Name: chat_usage_analytics chat_usage_analytics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_usage_analytics
    ADD CONSTRAINT chat_usage_analytics_pkey PRIMARY KEY (id);


--
-- Name: cluster_config cluster_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cluster_config
    ADD CONSTRAINT cluster_config_pkey PRIMARY KEY (key);


--
-- Name: cluster_nodes cluster_nodes_node_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cluster_nodes
    ADD CONSTRAINT cluster_nodes_node_id_key UNIQUE (node_id);


--
-- Name: cluster_nodes cluster_nodes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cluster_nodes
    ADD CONSTRAINT cluster_nodes_pkey PRIMARY KEY (id);


--
-- Name: collector_group_membership collector_group_membership_group_id_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_group_membership
    ADD CONSTRAINT collector_group_membership_group_id_agent_id_key UNIQUE (group_id, agent_id);


--
-- Name: collector_group_membership collector_group_membership_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_group_membership
    ADD CONSTRAINT collector_group_membership_pkey PRIMARY KEY (id);


--
-- Name: collector_groups collector_groups_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_groups
    ADD CONSTRAINT collector_groups_name_key UNIQUE (name);


--
-- Name: collector_groups collector_groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_groups
    ADD CONSTRAINT collector_groups_pkey PRIMARY KEY (id);


--
-- Name: collector_source_assignments collector_source_assignments_agent_id_source_type_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_source_assignments
    ADD CONSTRAINT collector_source_assignments_agent_id_source_type_id_key UNIQUE (agent_id, source_type_id);


--
-- Name: collector_source_assignments collector_source_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_source_assignments
    ADD CONSTRAINT collector_source_assignments_pkey PRIMARY KEY (id);


--
-- Name: connect_credentials connect_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connect_credentials
    ADD CONSTRAINT connect_credentials_pkey PRIMARY KEY (id);


--
-- Name: connect_credentials connect_credentials_tenant_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connect_credentials
    ADD CONSTRAINT connect_credentials_tenant_id_name_key UNIQUE (tenant_id, name);


--
-- Name: connect_execution_log connect_execution_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connect_execution_log
    ADD CONSTRAINT connect_execution_log_pkey PRIMARY KEY (id);


--
-- Name: connect_instances connect_instances_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connect_instances
    ADD CONSTRAINT connect_instances_pkey PRIMARY KEY (id);


--
-- Name: connect_instances connect_instances_tenant_id_connector_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connect_instances
    ADD CONSTRAINT connect_instances_tenant_id_connector_id_key UNIQUE (tenant_id, connector_id);


--
-- Name: connector_definitions connector_definitions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connector_definitions
    ADD CONSTRAINT connector_definitions_pkey PRIMARY KEY (row_id);


--
-- Name: connector_submissions connector_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connector_submissions
    ADD CONSTRAINT connector_submissions_pkey PRIMARY KEY (id);


--
-- Name: contact_submissions contact_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.contact_submissions
    ADD CONSTRAINT contact_submissions_pkey PRIMARY KEY (id);


--
-- Name: correlation_decisions correlation_decisions_alert_id_investigation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_decisions
    ADD CONSTRAINT correlation_decisions_alert_id_investigation_id_key UNIQUE (alert_id, investigation_id);


--
-- Name: correlation_decisions correlation_decisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_decisions
    ADD CONSTRAINT correlation_decisions_pkey PRIMARY KEY (id);


--
-- Name: correlation_events correlation_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_events
    ADD CONSTRAINT correlation_events_pkey PRIMARY KEY (id);


--
-- Name: correlation_rules correlation_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_rules
    ADD CONSTRAINT correlation_rules_pkey PRIMARY KEY (id);


--
-- Name: correlation_rules correlation_rules_rule_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_rules
    ADD CONSTRAINT correlation_rules_rule_id_key UNIQUE (rule_id);


--
-- Name: correlation_settings correlation_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_settings
    ADD CONSTRAINT correlation_settings_pkey PRIMARY KEY (tenant_id);


--
-- Name: credentials credentials_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_name_key UNIQUE (name);


--
-- Name: credentials credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);


--
-- Name: credentials_vault credentials_vault_credential_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials_vault
    ADD CONSTRAINT credentials_vault_credential_id_key UNIQUE (credential_id);


--
-- Name: credentials_vault credentials_vault_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials_vault
    ADD CONSTRAINT credentials_vault_pkey PRIMARY KEY (id);


--
-- Name: criticality_rules criticality_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.criticality_rules
    ADD CONSTRAINT criticality_rules_pkey PRIMARY KEY (id);


--
-- Name: dedupe_config dedupe_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dedupe_config
    ADD CONSTRAINT dedupe_config_pkey PRIMARY KEY (id);


--
-- Name: dedupe_config dedupe_config_tenant_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dedupe_config
    ADD CONSTRAINT dedupe_config_tenant_name_key UNIQUE (tenant_id, name);


--
-- Name: detection_hits detection_hits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_hits
    ADD CONSTRAINT detection_hits_pkey PRIMARY KEY (id);


--
-- Name: detection_rules detection_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_pkey PRIMARY KEY (id);


--
-- Name: detection_rules detection_rules_rule_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_rules
    ADD CONSTRAINT detection_rules_rule_id_key UNIQUE (rule_id);


--
-- Name: discovered_apis discovered_apis_api_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.discovered_apis
    ADD CONSTRAINT discovered_apis_api_id_key UNIQUE (api_id);


--
-- Name: discovered_apis discovered_apis_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.discovered_apis
    ADD CONSTRAINT discovered_apis_pkey PRIMARY KEY (id);


--
-- Name: discovery_queue discovery_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.discovery_queue
    ADD CONSTRAINT discovery_queue_pkey PRIMARY KEY (id);


--
-- Name: discovery_sources discovery_sources_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.discovery_sources
    ADD CONSTRAINT discovery_sources_name_key UNIQUE (name);


--
-- Name: discovery_sources discovery_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.discovery_sources
    ADD CONSTRAINT discovery_sources_pkey PRIMARY KEY (id);


--
-- Name: distributed_locks distributed_locks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.distributed_locks
    ADD CONSTRAINT distributed_locks_pkey PRIMARY KEY (lock_name);


--
-- Name: edl_access_log edl_access_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_access_log
    ADD CONSTRAINT edl_access_log_pkey PRIMARY KEY (id);


--
-- Name: edl_change_log edl_change_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_change_log
    ADD CONSTRAINT edl_change_log_pkey PRIMARY KEY (id);


--
-- Name: edl_content_cache edl_content_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_content_cache
    ADD CONSTRAINT edl_content_cache_pkey PRIMARY KEY (list_id);


--
-- Name: edl_credentials edl_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_credentials
    ADD CONSTRAINT edl_credentials_pkey PRIMARY KEY (credential_id);


--
-- Name: edl_items edl_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_items
    ADD CONSTRAINT edl_items_pkey PRIMARY KEY (id);


--
-- Name: edl_items edl_items_unique_per_list; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_items
    ADD CONSTRAINT edl_items_unique_per_list UNIQUE (list_id, ioc_normalized);


--
-- Name: edl_lists edl_lists_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_lists
    ADD CONSTRAINT edl_lists_pkey PRIMARY KEY (list_id);


--
-- Name: edl_lists edl_lists_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_lists
    ADD CONSTRAINT edl_lists_slug_key UNIQUE (slug);


--
-- Name: email_config email_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_config
    ADD CONSTRAINT email_config_pkey PRIMARY KEY (id);


--
-- Name: email_digest_queue email_digest_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_digest_queue
    ADD CONSTRAINT email_digest_queue_pkey PRIMARY KEY (id);


--
-- Name: email_log email_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_log
    ADD CONSTRAINT email_log_pkey PRIMARY KEY (id);


--
-- Name: email_templates email_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_templates
    ADD CONSTRAINT email_templates_pkey PRIMARY KEY (id);


--
-- Name: email_templates email_templates_template_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_templates
    ADD CONSTRAINT email_templates_template_id_key UNIQUE (template_id);


--
-- Name: enrichment_cache enrichment_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_cache
    ADD CONSTRAINT enrichment_cache_pkey PRIMARY KEY (id);


--
-- Name: enrichment_health_metrics enrichment_health_metrics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_health_metrics
    ADD CONSTRAINT enrichment_health_metrics_pkey PRIMARY KEY (id);


--
-- Name: enrichment_health_metrics enrichment_health_metrics_provider_measurement_time_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_health_metrics
    ADD CONSTRAINT enrichment_health_metrics_provider_measurement_time_key UNIQUE (provider, measurement_time);


--
-- Name: enrichment_jobs enrichment_jobs_job_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_jobs
    ADD CONSTRAINT enrichment_jobs_job_id_key UNIQUE (job_id);


--
-- Name: enrichment_jobs enrichment_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_jobs
    ADD CONSTRAINT enrichment_jobs_pkey PRIMARY KEY (id);


--
-- Name: enrichment_priority_queue enrichment_priority_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_priority_queue
    ADD CONSTRAINT enrichment_priority_queue_pkey PRIMARY KEY (id);


--
-- Name: enrichment_queue enrichment_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_queue
    ADD CONSTRAINT enrichment_queue_pkey PRIMARY KEY (id);


--
-- Name: entity_risk entity_risk_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_risk
    ADD CONSTRAINT entity_risk_pkey PRIMARY KEY (id);


--
-- Name: entity_risk entity_risk_tenant_id_entity_type_entity_value_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_risk
    ADD CONSTRAINT entity_risk_tenant_id_entity_type_entity_value_key UNIQUE (tenant_id, entity_type, entity_value);


--
-- Name: entity_types entity_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_types
    ADD CONSTRAINT entity_types_pkey PRIMARY KEY (type_code);


--
-- Name: escalation_config escalation_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.escalation_config
    ADD CONSTRAINT escalation_config_pkey PRIMARY KEY (id);


--
-- Name: escalation_history escalation_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.escalation_history
    ADD CONSTRAINT escalation_history_pkey PRIMARY KEY (id);


--
-- Name: exclusion_list exclusion_list_ioc_type_ioc_value_match_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.exclusion_list
    ADD CONSTRAINT exclusion_list_ioc_type_ioc_value_match_type_key UNIQUE (ioc_type, ioc_value, match_type);


--
-- Name: exclusion_list exclusion_list_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.exclusion_list
    ADD CONSTRAINT exclusion_list_pkey PRIMARY KEY (id);


--
-- Name: form_submissions form_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.form_submissions
    ADD CONSTRAINT form_submissions_pkey PRIMARY KEY (id);


--
-- Name: form_submissions form_submissions_submission_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.form_submissions
    ADD CONSTRAINT form_submissions_submission_id_key UNIQUE (submission_id);


--
-- Name: frontend_errors frontend_errors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.frontend_errors
    ADD CONSTRAINT frontend_errors_pkey PRIMARY KEY (id);


--
-- Name: geopolitical_events geopolitical_events_fingerprint_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.geopolitical_events
    ADD CONSTRAINT geopolitical_events_fingerprint_key UNIQUE (fingerprint);


--
-- Name: geopolitical_events geopolitical_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.geopolitical_events
    ADD CONSTRAINT geopolitical_events_pkey PRIMARY KEY (id);


--
-- Name: group_source_assignments group_source_assignments_group_id_source_type_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_source_assignments
    ADD CONSTRAINT group_source_assignments_group_id_source_type_id_key UNIQUE (group_id, source_type_id);


--
-- Name: group_source_assignments group_source_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_source_assignments
    ADD CONSTRAINT group_source_assignments_pkey PRIMARY KEY (id);


--
-- Name: human_overrides human_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.human_overrides
    ADD CONSTRAINT human_overrides_pkey PRIMARY KEY (id);


--
-- Name: inbound_email_queue inbound_email_queue_message_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_email_queue
    ADD CONSTRAINT inbound_email_queue_message_id_key UNIQUE (message_id);


--
-- Name: inbound_email_queue inbound_email_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_email_queue
    ADD CONSTRAINT inbound_email_queue_pkey PRIMARY KEY (id);


--
-- Name: inbound_mailboxes inbound_mailboxes_mailbox_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_mailboxes
    ADD CONSTRAINT inbound_mailboxes_mailbox_id_key UNIQUE (mailbox_id);


--
-- Name: inbound_mailboxes inbound_mailboxes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_mailboxes
    ADD CONSTRAINT inbound_mailboxes_pkey PRIMARY KEY (id);


--
-- Name: index_permission_templates index_permission_templates_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.index_permission_templates
    ADD CONSTRAINT index_permission_templates_name_key UNIQUE (name);


--
-- Name: index_permission_templates index_permission_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.index_permission_templates
    ADD CONSTRAINT index_permission_templates_pkey PRIMARY KEY (id);


--
-- Name: intake_form_attachments intake_form_attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_form_attachments
    ADD CONSTRAINT intake_form_attachments_pkey PRIMARY KEY (id);


--
-- Name: intake_form_submissions intake_form_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_form_submissions
    ADD CONSTRAINT intake_form_submissions_pkey PRIMARY KEY (id);


--
-- Name: intake_forms intake_forms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_forms
    ADD CONSTRAINT intake_forms_pkey PRIMARY KEY (id);


--
-- Name: intake_forms intake_forms_tenant_slug_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_forms
    ADD CONSTRAINT intake_forms_tenant_slug_unique UNIQUE (tenant_id, slug);


--
-- Name: integration_credentials integration_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_credentials
    ADD CONSTRAINT integration_credentials_pkey PRIMARY KEY (id);


--
-- Name: integration_rate_limits integration_rate_limits_integration_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_rate_limits
    ADD CONSTRAINT integration_rate_limits_integration_id_key UNIQUE (integration_id);


--
-- Name: integration_rate_limits integration_rate_limits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_rate_limits
    ADD CONSTRAINT integration_rate_limits_pkey PRIMARY KEY (id);


--
-- Name: integration_state integration_state_integration_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_state
    ADD CONSTRAINT integration_state_integration_id_key UNIQUE (integration_id);


--
-- Name: integration_state integration_state_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_state
    ADD CONSTRAINT integration_state_pkey PRIMARY KEY (id);


--
-- Name: integration_update_history integration_update_history_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_update_history
    ADD CONSTRAINT integration_update_history_pkey PRIMARY KEY (id);


--
-- Name: integration_update_schedules integration_update_schedules_integration_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_update_schedules
    ADD CONSTRAINT integration_update_schedules_integration_id_key UNIQUE (integration_id);


--
-- Name: integration_update_schedules integration_update_schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_update_schedules
    ADD CONSTRAINT integration_update_schedules_pkey PRIMARY KEY (id);


--
-- Name: integrations integrations_integration_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_integration_id_key UNIQUE (integration_id);


--
-- Name: integrations integrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT integrations_pkey PRIMARY KEY (id);


--
-- Name: investigation_agent_paths investigation_agent_paths_investigation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_agent_paths
    ADD CONSTRAINT investigation_agent_paths_investigation_id_key UNIQUE (investigation_id);


--
-- Name: investigation_agent_paths investigation_agent_paths_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_agent_paths
    ADD CONSTRAINT investigation_agent_paths_pkey PRIMARY KEY (id);


--
-- Name: investigation_audit_log investigation_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_audit_log
    ADD CONSTRAINT investigation_audit_log_pkey PRIMARY KEY (id);


--
-- Name: investigation_chat investigation_chat_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_chat
    ADD CONSTRAINT investigation_chat_pkey PRIMARY KEY (id);


--
-- Name: investigation_entities investigation_entities_investigation_id_entity_type_entity__key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_entities
    ADD CONSTRAINT investigation_entities_investigation_id_entity_type_entity__key UNIQUE (investigation_id, entity_type, entity_value);


--
-- Name: investigation_entities investigation_entities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_entities
    ADD CONSTRAINT investigation_entities_pkey PRIMARY KEY (id);


--
-- Name: investigation_iocs investigation_iocs_investigation_id_ioc_enrichment_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_iocs
    ADD CONSTRAINT investigation_iocs_investigation_id_ioc_enrichment_id_key UNIQUE (investigation_id, ioc_enrichment_id);


--
-- Name: investigation_iocs investigation_iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_iocs
    ADD CONSTRAINT investigation_iocs_pkey PRIMARY KEY (id);


--
-- Name: investigation_notes investigation_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_notes
    ADD CONSTRAINT investigation_notes_pkey PRIMARY KEY (id);


--
-- Name: investigation_ownership_log investigation_ownership_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_ownership_log
    ADD CONSTRAINT investigation_ownership_log_pkey PRIMARY KEY (id);


--
-- Name: investigations investigations_investigation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigations
    ADD CONSTRAINT investigations_investigation_id_key UNIQUE (investigation_id);


--
-- Name: investigations investigations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigations
    ADD CONSTRAINT investigations_pkey PRIMARY KEY (id);


--
-- Name: ioc_blocklist ioc_blocklist_ioc_type_ioc_value_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_blocklist
    ADD CONSTRAINT ioc_blocklist_ioc_type_ioc_value_key UNIQUE (ioc_type, ioc_value);


--
-- Name: ioc_blocklist ioc_blocklist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_blocklist
    ADD CONSTRAINT ioc_blocklist_pkey PRIMARY KEY (id);


--
-- Name: ioc_enrichments ioc_enrichments_ioc_value_normalized_ioc_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_enrichments
    ADD CONSTRAINT ioc_enrichments_ioc_value_normalized_ioc_type_key UNIQUE (ioc_value_normalized, ioc_type);


--
-- Name: ioc_enrichments ioc_enrichments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_enrichments
    ADD CONSTRAINT ioc_enrichments_pkey PRIMARY KEY (id);


--
-- Name: ioc_feed_appearances ioc_feed_appearances_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_feed_appearances
    ADD CONSTRAINT ioc_feed_appearances_pkey PRIMARY KEY (id);


--
-- Name: ioc_whitelist ioc_whitelist_ioc_value_ioc_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_whitelist
    ADD CONSTRAINT ioc_whitelist_ioc_value_ioc_type_key UNIQUE (ioc_value, ioc_type);


--
-- Name: ioc_whitelist ioc_whitelist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_whitelist
    ADD CONSTRAINT ioc_whitelist_pkey PRIMARY KEY (id);


--
-- Name: iocs iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iocs
    ADD CONSTRAINT iocs_pkey PRIMARY KEY (id);


--
-- Name: itsm_configurations itsm_configurations_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itsm_configurations
    ADD CONSTRAINT itsm_configurations_name_key UNIQUE (name);


--
-- Name: itsm_configurations itsm_configurations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itsm_configurations
    ADD CONSTRAINT itsm_configurations_pkey PRIMARY KEY (id);


--
-- Name: itsm_exports itsm_exports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.itsm_exports
    ADD CONSTRAINT itsm_exports_pkey PRIMARY KEY (id);


--
-- Name: job_queue job_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.job_queue
    ADD CONSTRAINT job_queue_pkey PRIMARY KEY (id);


--
-- Name: kb_community_submissions kb_community_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kb_community_submissions
    ADD CONSTRAINT kb_community_submissions_pkey PRIMARY KEY (id);


--
-- Name: kb_document_uploads kb_document_uploads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kb_document_uploads
    ADD CONSTRAINT kb_document_uploads_pkey PRIMARY KEY (id);


--
-- Name: kb_document_uploads kb_document_uploads_upload_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.kb_document_uploads
    ADD CONSTRAINT kb_document_uploads_upload_id_key UNIQUE (upload_id);


--
-- Name: knowledge_base knowledge_base_kb_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.knowledge_base
    ADD CONSTRAINT knowledge_base_kb_id_key UNIQUE (kb_id);


--
-- Name: knowledge_base knowledge_base_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.knowledge_base
    ADD CONSTRAINT knowledge_base_pkey PRIMARY KEY (id);


--
-- Name: knowledge_base_versions knowledge_base_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.knowledge_base_versions
    ADD CONSTRAINT knowledge_base_versions_pkey PRIMARY KEY (id);


--
-- Name: lead_drafts lead_drafts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.lead_drafts
    ADD CONSTRAINT lead_drafts_pkey PRIMARY KEY (id);


--
-- Name: llm_mesh_snapshots llm_mesh_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_mesh_snapshots
    ADD CONSTRAINT llm_mesh_snapshots_pkey PRIMARY KEY (id);


--
-- Name: log_agents log_agents_agent_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_agents
    ADD CONSTRAINT log_agents_agent_id_key UNIQUE (agent_id);


--
-- Name: log_agents log_agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_agents
    ADD CONSTRAINT log_agents_pkey PRIMARY KEY (id);


--
-- Name: log_indexes log_indexes_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_indexes
    ADD CONSTRAINT log_indexes_name_key UNIQUE (name);


--
-- Name: log_indexes log_indexes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_indexes
    ADD CONSTRAINT log_indexes_pkey PRIMARY KEY (id);


--
-- Name: log_search_audit log_search_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_search_audit
    ADD CONSTRAINT log_search_audit_pkey PRIMARY KEY (id);


--
-- Name: log_source_configs log_source_configs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_source_configs
    ADD CONSTRAINT log_source_configs_pkey PRIMARY KEY (id);


--
-- Name: log_source_configs log_source_configs_source_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_source_configs
    ADD CONSTRAINT log_source_configs_source_type_key UNIQUE (source_type);


--
-- Name: log_source_types log_source_types_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_source_types
    ADD CONSTRAINT log_source_types_pkey PRIMARY KEY (id);


--
-- Name: log_source_types log_source_types_source_type_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_source_types
    ADD CONSTRAINT log_source_types_source_type_key UNIQUE (source_type);


--
-- Name: login_attempts_by_ip login_attempts_by_ip_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.login_attempts_by_ip
    ADD CONSTRAINT login_attempts_by_ip_pkey PRIMARY KEY (ip_address);


--
-- Name: ml_predictions ml_predictions_alert_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_predictions
    ADD CONSTRAINT ml_predictions_alert_id_key UNIQUE (alert_id);


--
-- Name: ml_predictions ml_predictions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_predictions
    ADD CONSTRAINT ml_predictions_pkey PRIMARY KEY (id);


--
-- Name: ml_training_runs ml_training_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_training_runs
    ADD CONSTRAINT ml_training_runs_pkey PRIMARY KEY (id);


--
-- Name: model_performance_daily model_performance_daily_metric_date_provider_model_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_performance_daily
    ADD CONSTRAINT model_performance_daily_metric_date_provider_model_key UNIQUE (metric_date, provider, model);


--
-- Name: model_performance_daily model_performance_daily_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_performance_daily
    ADD CONSTRAINT model_performance_daily_pkey PRIMARY KEY (id);


--
-- Name: notification_rules notification_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_rules
    ADD CONSTRAINT notification_rules_pkey PRIMARY KEY (id);


--
-- Name: notification_rules notification_rules_rule_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notification_rules
    ADD CONSTRAINT notification_rules_rule_id_key UNIQUE (rule_id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: password_reset_tokens password_reset_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_pkey PRIMARY KEY (id);


--
-- Name: password_reset_tokens password_reset_tokens_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.password_reset_tokens
    ADD CONSTRAINT password_reset_tokens_token_key UNIQUE (token);


--
-- Name: phishing_campaigns phishing_campaigns_campaign_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.phishing_campaigns
    ADD CONSTRAINT phishing_campaigns_campaign_id_key UNIQUE (campaign_id);


--
-- Name: phishing_campaigns phishing_campaigns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.phishing_campaigns
    ADD CONSTRAINT phishing_campaigns_pkey PRIMARY KEY (id);


--
-- Name: phishing_reports phishing_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.phishing_reports
    ADD CONSTRAINT phishing_reports_pkey PRIMARY KEY (id);


--
-- Name: phishing_reports phishing_reports_report_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.phishing_reports
    ADD CONSTRAINT phishing_reports_report_id_key UNIQUE (report_id);


--
-- Name: phishing_test_list phishing_test_list_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.phishing_test_list
    ADD CONSTRAINT phishing_test_list_pkey PRIMARY KEY (id);


--
-- Name: phishing_tests phishing_tests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.phishing_tests
    ADD CONSTRAINT phishing_tests_pkey PRIMARY KEY (id);


--
-- Name: platform_admins platform_admins_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_admins
    ADD CONSTRAINT platform_admins_email_key UNIQUE (email);


--
-- Name: platform_admins platform_admins_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_admins
    ADD CONSTRAINT platform_admins_pkey PRIMARY KEY (id);


--
-- Name: platform_audit_log platform_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_audit_log
    ADD CONSTRAINT platform_audit_log_pkey PRIMARY KEY (id);


--
-- Name: playbook_community_submissions playbook_community_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_community_submissions
    ADD CONSTRAINT playbook_community_submissions_pkey PRIMARY KEY (id);


--
-- Name: playbook_execution_approvals playbook_execution_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_execution_approvals
    ADD CONSTRAINT playbook_execution_approvals_pkey PRIMARY KEY (id);


--
-- Name: playbook_executions playbook_executions_execution_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_execution_id_key UNIQUE (execution_id);


--
-- Name: playbook_executions playbook_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_pkey PRIMARY KEY (id);


--
-- Name: playbook_files playbook_files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_files
    ADD CONSTRAINT playbook_files_pkey PRIMARY KEY (id);


--
-- Name: playbook_form_submissions playbook_form_submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_form_submissions
    ADD CONSTRAINT playbook_form_submissions_pkey PRIMARY KEY (id);


--
-- Name: playbook_forms playbook_forms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_forms
    ADD CONSTRAINT playbook_forms_pkey PRIMARY KEY (id);


--
-- Name: playbook_forms playbook_forms_tenant_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_forms
    ADD CONSTRAINT playbook_forms_tenant_name_key UNIQUE (tenant_id, name);


--
-- Name: playbook_functions playbook_functions_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_functions
    ADD CONSTRAINT playbook_functions_name_key UNIQUE (name);


--
-- Name: playbook_functions playbook_functions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_functions
    ADD CONSTRAINT playbook_functions_pkey PRIMARY KEY (id);


--
-- Name: playbook_lists playbook_lists_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_lists
    ADD CONSTRAINT playbook_lists_name_key UNIQUE (name);


--
-- Name: playbook_lists playbook_lists_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_lists
    ADD CONSTRAINT playbook_lists_pkey PRIMARY KEY (id);


--
-- Name: playbook_node_approvals playbook_node_approvals_execution_id_node_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_node_approvals
    ADD CONSTRAINT playbook_node_approvals_execution_id_node_id_key UNIQUE (execution_id, node_id);


--
-- Name: playbook_node_approvals playbook_node_approvals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_node_approvals
    ADD CONSTRAINT playbook_node_approvals_pkey PRIMARY KEY (id);


--
-- Name: playbook_templates playbook_templates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_templates
    ADD CONSTRAINT playbook_templates_pkey PRIMARY KEY (id);


--
-- Name: playbook_versions playbook_versions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_versions
    ADD CONSTRAINT playbook_versions_pkey PRIMARY KEY (id);


--
-- Name: playbooks playbooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbooks
    ADD CONSTRAINT playbooks_pkey PRIMARY KEY (id);


--
-- Name: poc_tracking poc_tracking_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.poc_tracking
    ADD CONSTRAINT poc_tracking_pkey PRIMARY KEY (id);


--
-- Name: post_resolution_rules post_resolution_rules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.post_resolution_rules
    ADD CONSTRAINT post_resolution_rules_pkey PRIMARY KEY (id);


--
-- Name: post_resolution_tasks post_resolution_tasks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.post_resolution_tasks
    ADD CONSTRAINT post_resolution_tasks_pkey PRIMARY KEY (id);


--
-- Name: public_demo_usage public_demo_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.public_demo_usage
    ADD CONSTRAINT public_demo_usage_pkey PRIMARY KEY (id);


--
-- Name: recommended_actions recommended_actions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recommended_actions
    ADD CONSTRAINT recommended_actions_pkey PRIMARY KEY (id);


--
-- Name: referrals referrals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT referrals_pkey PRIMARY KEY (id);


--
-- Name: registration_rate_limits registration_rate_limits_ip_hash_endpoint_window_start_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_rate_limits
    ADD CONSTRAINT registration_rate_limits_ip_hash_endpoint_window_start_key UNIQUE (ip_hash, endpoint, window_start);


--
-- Name: registration_rate_limits registration_rate_limits_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_rate_limits
    ADD CONSTRAINT registration_rate_limits_pkey PRIMARY KEY (id);


--
-- Name: registration_requests registration_requests_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_requests
    ADD CONSTRAINT registration_requests_pkey PRIMARY KEY (id);


--
-- Name: registration_requests registration_requests_verification_token_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_requests
    ADD CONSTRAINT registration_requests_verification_token_key UNIQUE (verification_token);


--
-- Name: retention_policies retention_policies_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.retention_policies
    ADD CONSTRAINT retention_policies_name_key UNIQUE (name);


--
-- Name: retention_policies retention_policies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.retention_policies
    ADD CONSTRAINT retention_policies_pkey PRIMARY KEY (id);


--
-- Name: riggs_decisions riggs_decisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.riggs_decisions
    ADD CONSTRAINT riggs_decisions_pkey PRIMARY KEY (id);


--
-- Name: riggs_feedback riggs_feedback_investigation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.riggs_feedback
    ADD CONSTRAINT riggs_feedback_investigation_id_key UNIQUE (investigation_id);


--
-- Name: riggs_feedback riggs_feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.riggs_feedback
    ADD CONSTRAINT riggs_feedback_pkey PRIMARY KEY (id);


--
-- Name: riggs_playbook_executions riggs_playbook_executions_investigation_id_execution_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.riggs_playbook_executions
    ADD CONSTRAINT riggs_playbook_executions_investigation_id_execution_id_key UNIQUE (investigation_id, execution_id);


--
-- Name: riggs_playbook_executions riggs_playbook_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.riggs_playbook_executions
    ADD CONSTRAINT riggs_playbook_executions_pkey PRIMARY KEY (id);


--
-- Name: role_index_permissions role_index_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_index_permissions
    ADD CONSTRAINT role_index_permissions_pkey PRIMARY KEY (id);


--
-- Name: role_index_permissions role_index_permissions_role_index_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_index_permissions
    ADD CONSTRAINT role_index_permissions_role_index_id_key UNIQUE (role, index_id);


--
-- Name: roles roles_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: schema_migrations schema_migrations_migration_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_migration_name_key UNIQUE (migration_name);


--
-- Name: schema_migrations schema_migrations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (id);


--
-- Name: sla_config sla_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sla_config
    ADD CONSTRAINT sla_config_pkey PRIMARY KEY (id);


--
-- Name: sla_config sla_config_priority_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sla_config
    ADD CONSTRAINT sla_config_priority_key UNIQUE (priority);


--
-- Name: soar_executions soar_executions_execution_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soar_executions
    ADD CONSTRAINT soar_executions_execution_id_key UNIQUE (execution_id);


--
-- Name: soar_executions soar_executions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soar_executions
    ADD CONSTRAINT soar_executions_pkey PRIMARY KEY (id);


--
-- Name: soar_playbooks soar_playbooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soar_playbooks
    ADD CONSTRAINT soar_playbooks_pkey PRIMARY KEY (id);


--
-- Name: sop_effectiveness_tracking sop_effectiveness_tracking_kb_id_investigation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sop_effectiveness_tracking
    ADD CONSTRAINT sop_effectiveness_tracking_kb_id_investigation_id_key UNIQUE (kb_id, investigation_id);


--
-- Name: sop_effectiveness_tracking sop_effectiveness_tracking_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sop_effectiveness_tracking
    ADD CONSTRAINT sop_effectiveness_tracking_pkey PRIMARY KEY (id);


--
-- Name: stripe_checkout_sessions stripe_checkout_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_checkout_sessions
    ADD CONSTRAINT stripe_checkout_sessions_pkey PRIMARY KEY (id);


--
-- Name: stripe_checkout_sessions stripe_checkout_sessions_stripe_session_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_checkout_sessions
    ADD CONSTRAINT stripe_checkout_sessions_stripe_session_id_key UNIQUE (stripe_session_id);


--
-- Name: stripe_webhook_events stripe_webhook_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_webhook_events
    ADD CONSTRAINT stripe_webhook_events_pkey PRIMARY KEY (event_id);


--
-- Name: teams teams_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.teams
    ADD CONSTRAINT teams_pkey PRIMARY KEY (id);


--
-- Name: teams teams_team_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.teams
    ADD CONSTRAINT teams_team_id_key UNIQUE (team_id);


--
-- Name: telemetry_snapshots telemetry_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.telemetry_snapshots
    ADD CONSTRAINT telemetry_snapshots_pkey PRIMARY KEY (id);


--
-- Name: tenant_ai_config tenant_ai_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_ai_config
    ADD CONSTRAINT tenant_ai_config_pkey PRIMARY KEY (tenant_id);


--
-- Name: tenant_audit_log tenant_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_audit_log
    ADD CONSTRAINT tenant_audit_log_pkey PRIMARY KEY (id);


--
-- Name: tenant_byo_usage tenant_byo_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_byo_usage
    ADD CONSTRAINT tenant_byo_usage_pkey PRIMARY KEY (id);


--
-- Name: tenant_byo_usage tenant_byo_usage_tenant_id_period_provider_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_byo_usage
    ADD CONSTRAINT tenant_byo_usage_tenant_id_period_provider_key UNIQUE (tenant_id, period, provider);


--
-- Name: tenant_claude_usage_applied_events tenant_claude_usage_applied_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_claude_usage_applied_events
    ADD CONSTRAINT tenant_claude_usage_applied_events_pkey PRIMARY KEY (message_id);


--
-- Name: tenant_claude_usage tenant_claude_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_claude_usage
    ADD CONSTRAINT tenant_claude_usage_pkey PRIMARY KEY (id);


--
-- Name: tenant_claude_usage tenant_claude_usage_tenant_id_month_start_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_claude_usage
    ADD CONSTRAINT tenant_claude_usage_tenant_id_month_start_key UNIQUE (tenant_id, month_start);


--
-- Name: tenant_licenses tenant_licenses_license_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_licenses
    ADD CONSTRAINT tenant_licenses_license_key_key UNIQUE (license_key);


--
-- Name: tenant_licenses tenant_licenses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_licenses
    ADD CONSTRAINT tenant_licenses_pkey PRIMARY KEY (id);


--
-- Name: tenant_llm_context tenant_llm_context_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_llm_context
    ADD CONSTRAINT tenant_llm_context_pkey PRIMARY KEY (tenant_id);


--
-- Name: tenant_pii_patterns tenant_pii_patterns_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_pii_patterns
    ADD CONSTRAINT tenant_pii_patterns_pkey PRIMARY KEY (id);


--
-- Name: tenant_pii_patterns tenant_pii_patterns_tenant_id_label_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_pii_patterns
    ADD CONSTRAINT tenant_pii_patterns_tenant_id_label_key UNIQUE (tenant_id, label);


--
-- Name: tenant_quota_warnings tenant_quota_warnings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_quota_warnings
    ADD CONSTRAINT tenant_quota_warnings_pkey PRIMARY KEY (id);


--
-- Name: tenant_quota_warnings tenant_quota_warnings_tenant_id_period_threshold_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_quota_warnings
    ADD CONSTRAINT tenant_quota_warnings_tenant_id_period_threshold_key UNIQUE (tenant_id, period, threshold);


--
-- Name: tenant_triage_config tenant_triage_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_triage_config
    ADD CONSTRAINT tenant_triage_config_pkey PRIMARY KEY (tenant_id);


--
-- Name: tenant_usage_snapshots tenant_usage_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_usage_snapshots
    ADD CONSTRAINT tenant_usage_snapshots_pkey PRIMARY KEY (id);


--
-- Name: tenant_usage_snapshots tenant_usage_snapshots_tenant_id_snapshot_date_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_usage_snapshots
    ADD CONSTRAINT tenant_usage_snapshots_tenant_id_snapshot_date_key UNIQUE (tenant_id, snapshot_date);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: tenants tenants_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_slug_key UNIQUE (slug);


--
-- Name: tenants tenants_uuid_unique; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_uuid_unique UNIQUE (uuid);


--
-- Name: threat_feed_ingestion_log threat_feed_ingestion_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feed_ingestion_log
    ADD CONSTRAINT threat_feed_ingestion_log_pkey PRIMARY KEY (id);


--
-- Name: threat_feeds threat_feeds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feeds
    ADD CONSTRAINT threat_feeds_pkey PRIMARY KEY (id);


--
-- Name: token_blacklist token_blacklist_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.token_blacklist
    ADD CONSTRAINT token_blacklist_pkey PRIMARY KEY (jti);


--
-- Name: trusted_senders trusted_senders_domain_sender_pattern_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trusted_senders
    ADD CONSTRAINT trusted_senders_domain_sender_pattern_key UNIQUE (domain, sender_pattern);


--
-- Name: trusted_senders trusted_senders_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trusted_senders
    ADD CONSTRAINT trusted_senders_pkey PRIMARY KEY (id);


--
-- Name: usage_counters usage_counters_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_counters
    ADD CONSTRAINT usage_counters_pkey PRIMARY KEY (tenant_id, metric, period);


--
-- Name: usage_events usage_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_events
    ADD CONSTRAINT usage_events_pkey PRIMARY KEY (id);


--
-- Name: user_index_permissions user_index_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_index_permissions
    ADD CONSTRAINT user_index_permissions_pkey PRIMARY KEY (id);


--
-- Name: user_index_permissions user_index_permissions_user_id_index_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_index_permissions
    ADD CONSTRAINT user_index_permissions_user_id_index_id_key UNIQUE (user_id, index_id);


--
-- Name: user_preferences user_preferences_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_preferences
    ADD CONSTRAINT user_preferences_pkey PRIMARY KEY (id);


--
-- Name: user_preferences user_preferences_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_preferences
    ADD CONSTRAINT user_preferences_username_key UNIQUE (username);


--
-- Name: user_sessions user_sessions_jti_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_jti_key UNIQUE (jti);


--
-- Name: user_sessions user_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_pkey PRIMARY KEY (id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: verdict_audit_log verdict_audit_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verdict_audit_log
    ADD CONSTRAINT verdict_audit_log_pkey PRIMARY KEY (id);


--
-- Name: web_forms web_forms_form_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.web_forms
    ADD CONSTRAINT web_forms_form_id_key UNIQUE (form_id);


--
-- Name: web_forms web_forms_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.web_forms
    ADD CONSTRAINT web_forms_pkey PRIMARY KEY (id);


--
-- Name: webhook_channels webhook_channels_channel_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_channels
    ADD CONSTRAINT webhook_channels_channel_id_key UNIQUE (channel_id);


--
-- Name: webhook_channels webhook_channels_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_channels
    ADD CONSTRAINT webhook_channels_pkey PRIMARY KEY (id);


--
-- Name: webhooks webhooks_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_name_key UNIQUE (name);


--
-- Name: webhooks webhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_pkey PRIMARY KEY (id);


--
-- Name: website_analytics website_analytics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.website_analytics
    ADD CONSTRAINT website_analytics_pkey PRIMARY KEY (id);


--
-- Name: idx_action_requests_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_requests_agent ON public.action_requests USING btree (requested_by_agent);


--
-- Name: idx_action_requests_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_requests_created ON public.action_requests USING btree (created_at);


--
-- Name: idx_action_requests_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_requests_expires ON public.action_requests USING btree (expires_at) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_action_requests_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_requests_investigation ON public.action_requests USING btree (investigation_id);


--
-- Name: idx_action_requests_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_requests_priority ON public.action_requests USING btree (priority, status);


--
-- Name: idx_action_requests_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_requests_status ON public.action_requests USING btree (status);


--
-- Name: idx_action_requests_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_requests_target ON public.action_requests USING btree (target_type, target_value);


--
-- Name: idx_action_requests_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_requests_tenant_id ON public.action_requests USING btree (tenant_id);


--
-- Name: idx_action_types_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_types_category ON public.action_types USING btree (category);


--
-- Name: idx_action_types_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_action_types_target ON public.action_types USING btree (target_type);


--
-- Name: idx_affiliate_codes_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_affiliate_codes_code ON public.affiliate_codes USING btree (code);


--
-- Name: idx_affiliate_codes_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_affiliate_codes_tenant ON public.affiliate_codes USING btree (tenant_id);


--
-- Name: idx_agent_action_log_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_log_action ON public.agent_action_log USING btree (action);


--
-- Name: idx_agent_action_log_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_log_agent ON public.agent_action_log USING btree (agent_id);


--
-- Name: idx_agent_action_log_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_log_created ON public.agent_action_log USING btree (created_at DESC);


--
-- Name: idx_agent_action_log_execution; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_log_execution ON public.agent_action_log USING btree (execution_id);


--
-- Name: idx_agent_action_log_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_log_status ON public.agent_action_log USING btree (status);


--
-- Name: idx_agent_action_log_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_action_log_tenant_id ON public.agent_action_log USING btree (tenant_id);


--
-- Name: idx_agent_approval_requests_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_approval_requests_agent ON public.agent_approval_requests USING btree (agent_id);


--
-- Name: idx_agent_approval_requests_execution; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_approval_requests_execution ON public.agent_approval_requests USING btree (execution_id);


--
-- Name: idx_agent_approval_requests_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_approval_requests_expires ON public.agent_approval_requests USING btree (expires_at) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_agent_approval_requests_request_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_approval_requests_request_id ON public.agent_approval_requests USING btree (request_id);


--
-- Name: idx_agent_approval_requests_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_approval_requests_status ON public.agent_approval_requests USING btree (status);


--
-- Name: idx_agent_approval_requests_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_approval_requests_tenant_id ON public.agent_approval_requests USING btree (tenant_id);


--
-- Name: idx_agent_definitions_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_definitions_enabled ON public.agent_definitions USING btree (enabled);


--
-- Name: idx_agent_definitions_focus; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_definitions_focus ON public.agent_definitions USING btree (focus);


--
-- Name: idx_agent_definitions_guardrails; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_definitions_guardrails ON public.agent_definitions USING gin (guardrails);


--
-- Name: idx_agent_definitions_permissions; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_definitions_permissions ON public.agent_definitions USING gin (permissions);


--
-- Name: idx_agent_definitions_system_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_definitions_system_name ON public.agent_definitions USING btree (system_name);


--
-- Name: idx_agent_definitions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_definitions_tenant_id ON public.agent_definitions USING btree (tenant_id);


--
-- Name: idx_agent_definitions_tier; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_definitions_tier ON public.agent_definitions USING btree (tier);


--
-- Name: idx_agent_executions_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_executions_agent ON public.agent_executions USING btree (agent_id);


--
-- Name: idx_agent_executions_execution_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_executions_execution_id ON public.agent_executions USING btree (execution_id);


--
-- Name: idx_agent_executions_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_executions_started ON public.agent_executions USING btree (started_at DESC);


--
-- Name: idx_agent_executions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_executions_status ON public.agent_executions USING btree (status);


--
-- Name: idx_agent_executions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_executions_tenant_id ON public.agent_executions USING btree (tenant_id);


--
-- Name: idx_agent_executions_trigger; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_executions_trigger ON public.agent_executions USING btree (trigger_type, trigger_source_id);


--
-- Name: idx_agent_paths_automation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_paths_automation ON public.investigation_agent_paths USING btree (automation_success);


--
-- Name: idx_agent_paths_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_paths_created ON public.investigation_agent_paths USING btree (created_at DESC);


--
-- Name: idx_agent_paths_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_paths_investigation ON public.investigation_agent_paths USING btree (investigation_id);


--
-- Name: idx_agent_paths_resolver; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_paths_resolver ON public.investigation_agent_paths USING btree (final_resolver);


--
-- Name: idx_agent_perf_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_perf_agent ON public.agent_performance_daily USING btree (agent_id);


--
-- Name: idx_agent_perf_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_perf_date ON public.agent_performance_daily USING btree (metric_date DESC);


--
-- Name: idx_agent_perf_tier; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_perf_tier ON public.agent_performance_daily USING btree (agent_tier);


--
-- Name: idx_agent_rollback_execution; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_rollback_execution ON public.agent_rollback_actions USING btree (execution_id);


--
-- Name: idx_agent_rollback_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_rollback_expires ON public.agent_rollback_actions USING btree (expires_at) WHERE (executed_at IS NULL);


--
-- Name: idx_agent_rollback_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_rollback_pending ON public.agent_rollback_actions USING btree (created_at DESC) WHERE (executed_at IS NULL);


--
-- Name: idx_agent_rollback_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_rollback_target ON public.agent_rollback_actions USING btree (target_type, target_id);


--
-- Name: idx_agent_templates_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_templates_category ON public.agent_templates USING btree (category);


--
-- Name: idx_agent_templates_is_default; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_templates_is_default ON public.agent_templates USING btree (is_default);


--
-- Name: idx_agent_templates_tier; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_templates_tier ON public.agent_templates USING btree (tier);


--
-- Name: idx_ai_action_log_action_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_action_log_action_type ON public.ai_action_log USING btree (action_type);


--
-- Name: idx_ai_action_log_agent_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_action_log_agent_name ON public.ai_action_log USING btree (agent_name);


--
-- Name: idx_ai_action_log_input; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_action_log_input ON public.ai_action_log USING gin (input_data);


--
-- Name: idx_ai_action_log_investigation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_action_log_investigation_id ON public.ai_action_log USING btree (investigation_id);


--
-- Name: idx_ai_action_log_output; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_action_log_output ON public.ai_action_log USING gin (output_data);


--
-- Name: idx_ai_action_log_started_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_action_log_started_at ON public.ai_action_log USING btree (started_at DESC);


--
-- Name: idx_ai_action_log_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_action_log_status ON public.ai_action_log USING btree (status);


--
-- Name: idx_ai_action_log_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_action_log_tenant_id ON public.ai_action_log USING btree (tenant_id);


--
-- Name: idx_ai_agent_activity_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_agent_activity_agent ON public.ai_agent_activity USING btree (agent_id);


--
-- Name: idx_ai_agent_activity_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_agent_activity_investigation ON public.ai_agent_activity USING btree (investigation_id);


--
-- Name: idx_ai_agent_activity_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_agent_activity_started ON public.ai_agent_activity USING btree (started_at DESC);


--
-- Name: idx_ai_agent_activity_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_agent_activity_type ON public.ai_agent_activity USING btree (activity_type);


--
-- Name: idx_ai_agent_credentials_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_agent_credentials_agent ON public.ai_agent_credentials USING btree (agent_id);


--
-- Name: idx_ai_agents_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_agents_enabled ON public.ai_agents USING btree (enabled);


--
-- Name: idx_ai_agents_level; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_agents_level ON public.ai_agents USING btree (level);


--
-- Name: idx_ai_agents_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_agents_provider ON public.ai_agents USING btree (provider);


--
-- Name: idx_ai_agents_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_agents_tenant_id ON public.ai_agents USING btree (tenant_id);


--
-- Name: idx_ai_token_usage_cache_read; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_token_usage_cache_read ON public.ai_token_usage USING btree (created_at DESC) WHERE (cache_read_tokens > 0);


--
-- Name: idx_ai_token_usage_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_token_usage_created ON public.ai_token_usage USING btree (created_at DESC);


--
-- Name: idx_ai_token_usage_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_token_usage_investigation ON public.ai_token_usage USING btree (investigation_id);


--
-- Name: idx_ai_token_usage_model; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_token_usage_model ON public.ai_token_usage USING btree (model);


--
-- Name: idx_ai_token_usage_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_token_usage_provider ON public.ai_token_usage USING btree (provider);


--
-- Name: idx_ai_token_usage_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_token_usage_status ON public.ai_token_usage USING btree (status);


--
-- Name: idx_ai_token_usage_tenant_month; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_token_usage_tenant_month ON public.ai_token_usage USING btree (tenant_id, created_at);


--
-- Name: idx_ai_token_usage_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ai_token_usage_user ON public.ai_token_usage USING btree (user_id);


--
-- Name: idx_alert_attachments_alert_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_attachments_alert_id ON public.alert_attachments USING btree (alert_id);


--
-- Name: idx_alert_attachments_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_attachments_sha256 ON public.alert_attachments USING btree (sha256_hash);


--
-- Name: idx_alert_attachments_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_attachments_status ON public.alert_attachments USING btree (analysis_status);


--
-- Name: idx_alert_attachments_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_attachments_tenant_id ON public.alert_attachments USING btree (tenant_id);


--
-- Name: idx_alert_attachments_uploaded; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_attachments_uploaded ON public.alert_attachments USING btree (uploaded_at DESC);


--
-- Name: idx_alert_groups_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_groups_fingerprint ON public.alert_groups USING btree (fingerprint);


--
-- Name: idx_alert_groups_primary; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_groups_primary ON public.alert_groups USING btree (primary_alert_id);


--
-- Name: idx_alert_groups_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_groups_status ON public.alert_groups USING btree (status, last_seen DESC);


--
-- Name: idx_alert_groups_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_groups_tenant_id ON public.alert_groups USING btree (tenant_id);


--
-- Name: idx_alert_ioc_links_alert; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_ioc_links_alert ON public.alert_ioc_links USING btree (alert_id);


--
-- Name: idx_alert_ioc_links_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_ioc_links_created ON public.alert_ioc_links USING btree (created_at DESC);


--
-- Name: idx_alert_ioc_links_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_ioc_links_ioc ON public.alert_ioc_links USING btree (ioc_value, ioc_type);


--
-- Name: idx_alert_ioc_links_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alert_ioc_links_tenant_id ON public.alert_ioc_links USING btree (tenant_id);


--
-- Name: idx_alerts_alert_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_alert_id ON public.alerts USING btree (alert_id);


--
-- Name: idx_alerts_correlation_decision; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_correlation_decision ON public.alerts USING btree (correlation_decision);


--
-- Name: idx_alerts_correlation_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_correlation_score ON public.alerts USING btree (correlation_score);


--
-- Name: idx_alerts_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_created_at ON public.alerts USING btree (created_at DESC);


--
-- Name: idx_alerts_display_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_alerts_display_id ON public.alerts USING btree (display_id);


--
-- Name: idx_alerts_enrichment; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_enrichment ON public.alerts USING btree (enrichment_status);


--
-- Name: idx_alerts_event_class; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_event_class ON public.alerts USING btree (event_class);


--
-- Name: idx_alerts_external_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_external_id ON public.alerts USING btree (external_id);


--
-- Name: idx_alerts_extracted_entities; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_extracted_entities ON public.alerts USING gin (extracted_entities);


--
-- Name: idx_alerts_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_fingerprint ON public.alerts USING btree (fingerprint) WHERE (fingerprint IS NOT NULL);


--
-- Name: idx_alerts_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_group ON public.alerts USING btree (alert_group_id) WHERE (alert_group_id IS NOT NULL);


--
-- Name: idx_alerts_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_investigation ON public.alerts USING btree (investigation_id);


--
-- Name: idx_alerts_linked_observations; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_linked_observations ON public.alerts USING gin (linked_observation_ids);


--
-- Name: idx_alerts_playbook_executions_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_playbook_executions_run ON public.alerts USING gin (playbook_executions_run);


--
-- Name: idx_alerts_playbook_failed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_playbook_failed ON public.alerts USING btree (((playbook_results @> '[{"status": "failed"}]'::jsonb))) WHERE ((playbook_results IS NOT NULL) AND (playbook_results <> '[]'::jsonb));


--
-- Name: idx_alerts_playbook_results; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_playbook_results ON public.alerts USING gin (playbook_results);


--
-- Name: idx_alerts_raw_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_raw_event ON public.alerts USING gin (raw_event);


--
-- Name: idx_alerts_search; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_search ON public.alerts USING gin (search_vector);


--
-- Name: idx_alerts_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_severity ON public.alerts USING btree (severity);


--
-- Name: idx_alerts_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_source ON public.alerts USING btree (source);


--
-- Name: idx_alerts_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_status ON public.alerts USING btree (status);


--
-- Name: idx_alerts_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_tags ON public.alerts USING gin (tags);


--
-- Name: idx_alerts_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_tenant_id ON public.alerts USING btree (tenant_id);


--
-- Name: idx_alerts_tenant_severity_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_tenant_severity_created ON public.alerts USING btree (tenant_id, severity, created_at DESC);


--
-- Name: idx_alerts_tenant_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_tenant_status ON public.alerts USING btree (tenant_id, status);


--
-- Name: idx_alerts_vendor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_vendor ON public.alerts USING btree (vendor);


--
-- Name: idx_alerts_vendor_reputation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_alerts_vendor_reputation ON public.alerts USING btree (vendor_reputation);


--
-- Name: idx_analytics_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analytics_event ON public.website_analytics USING btree (event_type, created_at);


--
-- Name: idx_analytics_page; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_analytics_page ON public.website_analytics USING btree (page_path, created_at);


--
-- Name: idx_api_keys_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_enabled ON public.api_keys USING btree (enabled);


--
-- Name: idx_api_keys_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_hash ON public.api_keys USING btree (key_hash);


--
-- Name: idx_api_keys_key_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_key_hash ON public.api_keys USING btree (key_hash);


--
-- Name: idx_api_keys_key_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_key_id ON public.api_keys USING btree (key_id);


--
-- Name: idx_api_keys_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_tenant_id ON public.api_keys USING btree (tenant_id);


--
-- Name: idx_approval_requests_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_requests_created_at ON public.approval_requests USING btree (created_at DESC);


--
-- Name: idx_approval_requests_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_requests_expires_at ON public.approval_requests USING btree (expires_at) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_approval_requests_investigation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_requests_investigation_id ON public.approval_requests USING btree (investigation_id);


--
-- Name: idx_approval_requests_requested_by; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_requests_requested_by ON public.approval_requests USING btree (requested_by);


--
-- Name: idx_approval_requests_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_requests_status ON public.approval_requests USING btree (status);


--
-- Name: idx_approval_requests_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_requests_tenant_id ON public.approval_requests USING btree (tenant_id);


--
-- Name: idx_approval_tokens_entity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_tokens_entity ON public.approval_tokens USING btree (entity_type, entity_id);


--
-- Name: idx_approval_tokens_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_tokens_expires ON public.approval_tokens USING btree (expires_at);


--
-- Name: idx_approval_tokens_secret; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_tokens_secret ON public.approval_tokens USING btree (token_secret);


--
-- Name: idx_approval_tokens_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_approval_tokens_tenant_id ON public.approval_tokens USING btree (tenant_id);


--
-- Name: idx_asset_conflicts_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_conflicts_asset ON public.asset_conflicts USING btree (asset_id);


--
-- Name: idx_asset_conflicts_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_conflicts_status ON public.asset_conflicts USING btree (status) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_asset_conflicts_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_conflicts_tenant_id ON public.asset_conflicts USING btree (tenant_id);


--
-- Name: idx_asset_conflicts_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_conflicts_type ON public.asset_conflicts USING btree (conflict_type);


--
-- Name: idx_asset_history_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_history_asset ON public.asset_history USING btree (asset_id);


--
-- Name: idx_asset_history_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_history_source ON public.asset_history USING btree (change_source);


--
-- Name: idx_asset_history_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_history_tenant_id ON public.asset_history USING btree (tenant_id);


--
-- Name: idx_asset_history_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_history_timestamp ON public.asset_history USING btree ("timestamp" DESC);


--
-- Name: idx_asset_history_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_history_type ON public.asset_history USING btree (change_type);


--
-- Name: idx_asset_identifiers_asset; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_identifiers_asset ON public.asset_identifiers USING btree (asset_id);


--
-- Name: idx_asset_identifiers_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_identifiers_source ON public.asset_identifiers USING btree (source);


--
-- Name: idx_asset_identifiers_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_identifiers_tenant_id ON public.asset_identifiers USING btree (tenant_id);


--
-- Name: idx_asset_identifiers_type_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_identifiers_type_value ON public.asset_identifiers USING btree (identifier_type, identifier_value);


--
-- Name: idx_asset_rel_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_rel_source ON public.asset_relationships USING btree (source_asset_id);


--
-- Name: idx_asset_rel_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_rel_target ON public.asset_relationships USING btree (target_asset_id);


--
-- Name: idx_asset_rel_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_rel_type ON public.asset_relationships USING btree (relationship_type);


--
-- Name: idx_asset_relationships_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_asset_relationships_tenant_id ON public.asset_relationships USING btree (tenant_id);


--
-- Name: idx_assets_compliance_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_compliance_tags ON public.assets USING gin (compliance_tags);


--
-- Name: idx_assets_criticality; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_criticality ON public.assets USING btree (criticality);


--
-- Name: idx_assets_custom_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_custom_tags ON public.assets USING gin (custom_tags);


--
-- Name: idx_assets_department; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_department ON public.assets USING btree (department);


--
-- Name: idx_assets_environment; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_environment ON public.assets USING btree (environment);


--
-- Name: idx_assets_fqdn; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_fqdn ON public.assets USING btree (fqdn);


--
-- Name: idx_assets_hostname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_hostname ON public.assets USING btree (hostname);


--
-- Name: idx_assets_ip_addresses; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_ip_addresses ON public.assets USING gin (ip_addresses);


--
-- Name: idx_assets_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_last_seen ON public.assets USING btree (last_seen DESC);


--
-- Name: idx_assets_mac_addresses; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_mac_addresses ON public.assets USING gin (mac_addresses);


--
-- Name: idx_assets_metadata; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_metadata ON public.assets USING gin (metadata);


--
-- Name: idx_assets_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_owner ON public.assets USING btree (owner);


--
-- Name: idx_assets_search; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_search ON public.assets USING gin (to_tsvector('english'::regconfig, (((((((((COALESCE(hostname, ''::character varying))::text || ' '::text) || (COALESCE(fqdn, ''::character varying))::text) || ' '::text) || (COALESCE(display_name, ''::character varying))::text) || ' '::text) || (COALESCE(owner, ''::character varying))::text) || ' '::text) || (COALESCE(department, ''::character varying))::text)));


--
-- Name: idx_assets_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_status ON public.assets USING btree (status);


--
-- Name: idx_assets_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_tenant_id ON public.assets USING btree (tenant_id);


--
-- Name: idx_assets_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assets_type ON public.assets USING btree (asset_type);


--
-- Name: idx_assignment_rules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assignment_rules_enabled ON public.assignment_rules USING btree (enabled, priority);


--
-- Name: idx_assignment_rules_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assignment_rules_type ON public.assignment_rules USING btree (assign_to_type);


--
-- Name: idx_attachments_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attachments_investigation ON public.alert_attachments USING btree (investigation_id);


--
-- Name: idx_audit_log_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_action ON public.audit_log USING btree (action);


--
-- Name: idx_audit_log_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_created_at ON public.audit_log USING btree (created_at DESC);


--
-- Name: idx_audit_log_resource; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_resource ON public.audit_log USING btree (resource_type, resource_id);


--
-- Name: idx_audit_log_tenant_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_tenant_created ON public.audit_log USING btree (tenant_id, created_at DESC);


--
-- Name: idx_audit_log_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_tenant_id ON public.audit_log USING btree (tenant_id);


--
-- Name: idx_audit_log_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_audit_log_user ON public.audit_log USING btree (user_id);


--
-- Name: idx_auto_response_instance; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auto_response_instance ON public.auto_response_settings USING btree (instance_id);


--
-- Name: idx_breach_incidents_countries; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_countries ON public.breach_intel_incidents USING gin (affected_countries);


--
-- Name: idx_breach_incidents_cves; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_cves ON public.breach_intel_incidents USING gin (related_cves);


--
-- Name: idx_breach_incidents_discovered; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_discovered ON public.breach_intel_incidents USING btree (discovered_at DESC);


--
-- Name: idx_breach_incidents_fingerprint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_fingerprint ON public.breach_intel_incidents USING btree (fingerprint);


--
-- Name: idx_breach_incidents_incident_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_incident_date ON public.breach_intel_incidents USING btree (incident_date DESC);


--
-- Name: idx_breach_incidents_sector; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_sector ON public.breach_intel_incidents USING btree (affected_sector);


--
-- Name: idx_breach_incidents_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_severity ON public.breach_intel_incidents USING btree (severity);


--
-- Name: idx_breach_incidents_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_source ON public.breach_intel_incidents USING btree (source_id);


--
-- Name: idx_breach_incidents_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_tags ON public.breach_intel_incidents USING gin (ai_tags);


--
-- Name: idx_breach_incidents_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_incidents_type ON public.breach_intel_incidents USING btree (incident_type);


--
-- Name: idx_breach_intel_sources_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_intel_sources_enabled ON public.breach_intel_sources USING btree (enabled);


--
-- Name: idx_breach_intel_sources_next_poll; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_breach_intel_sources_next_poll ON public.breach_intel_sources USING btree (next_poll_at);


--
-- Name: idx_campaign_iocs_campaign; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaign_iocs_campaign ON public.campaign_iocs USING btree (campaign_id);


--
-- Name: idx_campaign_iocs_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaign_iocs_ioc ON public.campaign_iocs USING btree (ioc_value, ioc_type);


--
-- Name: idx_campaign_iocs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaign_iocs_tenant_id ON public.campaign_iocs USING btree (tenant_id);


--
-- Name: idx_campaign_members_alert; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaign_members_alert ON public.campaign_members USING btree (alert_id);


--
-- Name: idx_campaign_members_campaign; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaign_members_campaign ON public.campaign_members USING btree (campaign_id);


--
-- Name: idx_campaign_members_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaign_members_tenant_id ON public.campaign_members USING btree (tenant_id);


--
-- Name: idx_campaigns_activity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaigns_activity ON public.campaigns USING btree (last_activity DESC);


--
-- Name: idx_campaigns_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaigns_status ON public.campaigns USING btree (status);


--
-- Name: idx_campaigns_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaigns_tenant_id ON public.campaigns USING btree (tenant_id);


--
-- Name: idx_campaigns_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_campaigns_type ON public.campaigns USING btree (campaign_type);


--
-- Name: idx_case_summaries_generated; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_summaries_generated ON public.case_summaries USING btree (generated_at DESC);


--
-- Name: idx_case_summaries_inv; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_summaries_inv ON public.case_summaries USING btree (investigation_id);


--
-- Name: idx_case_summaries_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_summaries_investigation ON public.case_summaries USING btree (investigation_id);


--
-- Name: idx_case_summaries_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_summaries_tenant_id ON public.case_summaries USING btree (tenant_id);


--
-- Name: idx_chat_action_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_action_audit_action ON public.chat_action_audit USING btree (action_type);


--
-- Name: idx_chat_action_audit_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_action_audit_investigation ON public.chat_action_audit USING btree (investigation_id);


--
-- Name: idx_chat_action_audit_request; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_action_audit_request ON public.chat_action_audit USING btree (action_request_id);


--
-- Name: idx_chat_action_audit_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_action_audit_status ON public.chat_action_audit USING btree (status);


--
-- Name: idx_chat_action_audit_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_action_audit_tenant_id ON public.chat_action_audit USING btree (tenant_id);


--
-- Name: idx_chat_action_audit_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_action_audit_user ON public.chat_action_audit USING btree (user_id, created_at DESC);


--
-- Name: idx_chat_analytics_actions; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_analytics_actions ON public.chat_usage_analytics USING btree (action_type) WHERE (action_type IS NOT NULL);


--
-- Name: idx_chat_analytics_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_analytics_date ON public.chat_usage_analytics USING btree (created_at DESC);


--
-- Name: idx_chat_analytics_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_analytics_event ON public.chat_usage_analytics USING btree (event_type, created_at DESC);


--
-- Name: idx_chat_analytics_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_analytics_investigation ON public.chat_usage_analytics USING btree (investigation_id);


--
-- Name: idx_chat_analytics_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_analytics_user ON public.chat_usage_analytics USING btree (user_id, created_at DESC);


--
-- Name: idx_chat_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_created ON public.investigation_chat USING btree (created_at DESC);


--
-- Name: idx_chat_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_investigation ON public.investigation_chat USING btree (investigation_id, created_at);


--
-- Name: idx_chat_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_parent ON public.investigation_chat USING btree (parent_message_id);


--
-- Name: idx_chat_sender; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_sender ON public.investigation_chat USING btree (sender_type, sender_id);


--
-- Name: idx_chat_sub_heartbeat; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_sub_heartbeat ON public.chat_subscriptions USING btree (last_heartbeat);


--
-- Name: idx_chat_sub_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_sub_investigation ON public.chat_subscriptions USING btree (investigation_id);


--
-- Name: idx_chat_sub_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_sub_user ON public.chat_subscriptions USING btree (user_id);


--
-- Name: idx_chat_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_type ON public.investigation_chat USING btree (message_type);


--
-- Name: idx_chat_usage_analytics_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_chat_usage_analytics_tenant_id ON public.chat_usage_analytics USING btree (tenant_id);


--
-- Name: idx_checkout_sessions_reg; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_checkout_sessions_reg ON public.stripe_checkout_sessions USING btree (registration_request_id);


--
-- Name: idx_checkout_sessions_stripe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_checkout_sessions_stripe ON public.stripe_checkout_sessions USING btree (stripe_session_id);


--
-- Name: idx_checkout_sessions_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_checkout_sessions_tenant ON public.stripe_checkout_sessions USING btree (tenant_id);


--
-- Name: idx_cluster_nodes_heartbeat; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cluster_nodes_heartbeat ON public.cluster_nodes USING btree (last_heartbeat);


--
-- Name: idx_cluster_nodes_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cluster_nodes_status ON public.cluster_nodes USING btree (status);


--
-- Name: idx_collector_assignments_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collector_assignments_agent ON public.collector_source_assignments USING btree (agent_id);


--
-- Name: idx_collector_assignments_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collector_assignments_source ON public.collector_source_assignments USING btree (source_type_id);


--
-- Name: idx_collector_assignments_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collector_assignments_status ON public.collector_source_assignments USING btree (status);


--
-- Name: idx_collector_groups_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collector_groups_enabled ON public.collector_groups USING btree (is_enabled);


--
-- Name: idx_collector_groups_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collector_groups_name ON public.collector_groups USING btree (name);


--
-- Name: idx_collector_membership_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collector_membership_agent ON public.collector_group_membership USING btree (agent_id);


--
-- Name: idx_collector_membership_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_collector_membership_group ON public.collector_group_membership USING btree (group_id);


--
-- Name: idx_connect_creds_auth_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_creds_auth_type ON public.connect_credentials USING btree (auth_type);


--
-- Name: idx_connect_creds_linked_instance; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_creds_linked_instance ON public.connect_credentials USING btree (linked_instance_id);


--
-- Name: idx_connect_creds_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_creds_tenant ON public.connect_credentials USING btree (tenant_id);


--
-- Name: idx_connect_exec_connector; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_exec_connector ON public.connect_execution_log USING btree (connector_id);


--
-- Name: idx_connect_exec_instance; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_exec_instance ON public.connect_execution_log USING btree (instance_id);


--
-- Name: idx_connect_exec_tenant_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_exec_tenant_time ON public.connect_execution_log USING btree (tenant_id, executed_at DESC);


--
-- Name: idx_connect_inst_connector; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_inst_connector ON public.connect_instances USING btree (connector_id);


--
-- Name: idx_connect_inst_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_inst_enabled ON public.connect_instances USING btree (enabled);


--
-- Name: idx_connect_inst_health; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_inst_health ON public.connect_instances USING btree (health_status);


--
-- Name: idx_connect_inst_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connect_inst_tenant ON public.connect_instances USING btree (tenant_id);


--
-- Name: idx_connector_defs_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connector_defs_category ON public.connector_definitions USING btree (category);


--
-- Name: idx_connector_defs_id_scope; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_connector_defs_id_scope ON public.connector_definitions USING btree (id, COALESCE(tenant_id, '00000000-0000-0000-0000-000000000000'::uuid));


--
-- Name: idx_connector_defs_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connector_defs_name ON public.connector_definitions USING btree (name);


--
-- Name: idx_connector_defs_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connector_defs_source ON public.connector_definitions USING btree (source);


--
-- Name: idx_connector_defs_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connector_defs_tenant ON public.connector_definitions USING btree (tenant_id);


--
-- Name: idx_connector_subs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connector_subs_status ON public.connector_submissions USING btree (status);


--
-- Name: idx_connector_subs_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_connector_subs_tenant ON public.connector_submissions USING btree (tenant_id);


--
-- Name: idx_contact_submissions_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contact_submissions_created ON public.contact_submissions USING btree (created_at);


--
-- Name: idx_contact_submissions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_contact_submissions_status ON public.contact_submissions USING btree (status);


--
-- Name: idx_correlation_decisions_alert_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_decisions_alert_id ON public.correlation_decisions USING btree (alert_id);


--
-- Name: idx_correlation_decisions_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_decisions_created_at ON public.correlation_decisions USING btree (created_at);


--
-- Name: idx_correlation_decisions_decision_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_decisions_decision_type ON public.correlation_decisions USING btree (decision_type);


--
-- Name: idx_correlation_decisions_investigation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_decisions_investigation_id ON public.correlation_decisions USING btree (investigation_id);


--
-- Name: idx_correlation_decisions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_decisions_tenant_id ON public.correlation_decisions USING btree (tenant_id);


--
-- Name: idx_correlation_events_campaign; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_events_campaign ON public.correlation_events USING btree (campaign_id);


--
-- Name: idx_correlation_events_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_events_created ON public.correlation_events USING btree (created_at DESC);


--
-- Name: idx_correlation_events_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_events_rule ON public.correlation_events USING btree (rule_id);


--
-- Name: idx_correlation_rules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_rules_enabled ON public.correlation_rules USING btree (enabled, priority);


--
-- Name: idx_correlation_rules_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_correlation_rules_type ON public.correlation_rules USING btree (rule_type);


--
-- Name: idx_credentials_integration; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_integration ON public.credentials USING btree (integration_name);


--
-- Name: idx_credentials_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_name ON public.credentials USING btree (name);


--
-- Name: idx_credentials_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_tenant_id ON public.credentials USING btree (tenant_id);


--
-- Name: idx_credentials_vault_auth_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_vault_auth_type ON public.credentials_vault USING btree (auth_type);


--
-- Name: idx_credentials_vault_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_vault_id ON public.credentials_vault USING btree (credential_id);


--
-- Name: idx_credentials_vault_integrations; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_vault_integrations ON public.credentials_vault USING gin (integration_ids);


--
-- Name: idx_credentials_vault_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_vault_name ON public.credentials_vault USING btree (name);


--
-- Name: idx_credentials_vault_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_vault_tags ON public.credentials_vault USING gin (tags);


--
-- Name: idx_credentials_vault_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_credentials_vault_tenant_id ON public.credentials_vault USING btree (tenant_id);


--
-- Name: idx_criticality_rules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_criticality_rules_enabled ON public.criticality_rules USING btree (enabled, rule_priority DESC);


--
-- Name: idx_dedupe_config_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dedupe_config_enabled ON public.dedupe_config USING btree (enabled, priority);


--
-- Name: idx_dedupe_config_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dedupe_config_tenant ON public.dedupe_config USING btree (tenant_id) WHERE (enabled = true);


--
-- Name: idx_detection_hits_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_agent ON public.detection_hits USING btree (agent_id);


--
-- Name: idx_detection_hits_alert; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_alert ON public.detection_hits USING btree (alert_id);


--
-- Name: idx_detection_hits_detected; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_detected ON public.detection_hits USING btree (detected_at DESC);


--
-- Name: idx_detection_hits_disposition; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_disposition ON public.detection_hits USING btree (disposition);


--
-- Name: idx_detection_hits_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_event ON public.detection_hits USING btree (event_id);


--
-- Name: idx_detection_hits_hostname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_hostname ON public.detection_hits USING btree (hostname);


--
-- Name: idx_detection_hits_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_rule ON public.detection_hits USING btree (rule_id);


--
-- Name: idx_detection_hits_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_severity ON public.detection_hits USING btree (severity);


--
-- Name: idx_detection_hits_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_tenant_id ON public.detection_hits USING btree (tenant_id);


--
-- Name: idx_detection_hits_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_hits_timestamp ON public.detection_hits USING btree (event_timestamp DESC);


--
-- Name: idx_detection_rules_compliance; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_compliance ON public.detection_rules USING gin (compliance_frameworks);


--
-- Name: idx_detection_rules_logsource; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_logsource ON public.detection_rules USING gin (logsource);


--
-- Name: idx_detection_rules_mitre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_mitre ON public.detection_rules USING gin (mitre_attack);


--
-- Name: idx_detection_rules_rule_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_rule_id ON public.detection_rules USING btree (rule_id);


--
-- Name: idx_detection_rules_rule_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_rule_type ON public.detection_rules USING btree (rule_type);


--
-- Name: idx_detection_rules_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_severity ON public.detection_rules USING btree (severity);


--
-- Name: idx_detection_rules_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_status ON public.detection_rules USING btree (status);


--
-- Name: idx_detection_rules_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_detection_rules_tags ON public.detection_rules USING gin (tags);


--
-- Name: idx_digest_queue_scheduled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_digest_queue_scheduled ON public.email_digest_queue USING btree (scheduled_send_at);


--
-- Name: idx_digest_queue_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_digest_queue_status ON public.email_digest_queue USING btree (status);


--
-- Name: idx_discovered_apis_api_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovered_apis_api_id ON public.discovered_apis USING btree (api_id);


--
-- Name: idx_discovered_apis_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovered_apis_category ON public.discovered_apis USING btree (category);


--
-- Name: idx_discovered_apis_imported; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovered_apis_imported ON public.discovered_apis USING btree (imported);


--
-- Name: idx_discovered_apis_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovered_apis_name ON public.discovered_apis USING btree (name);


--
-- Name: idx_discovered_apis_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovered_apis_provider ON public.discovered_apis USING btree (provider);


--
-- Name: idx_discovered_apis_search; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovered_apis_search ON public.discovered_apis USING gin (search_vector);


--
-- Name: idx_discovered_apis_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovered_apis_source ON public.discovered_apis USING btree (source);


--
-- Name: idx_discovered_apis_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovered_apis_tags ON public.discovered_apis USING gin (tags);


--
-- Name: idx_discovery_queue_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovery_queue_pending ON public.discovery_queue USING btree (status, priority, scheduled_for) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_discovery_queue_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovery_queue_source ON public.discovery_queue USING btree (source_id);


--
-- Name: idx_discovery_sources_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovery_sources_enabled ON public.discovery_sources USING btree (enabled);


--
-- Name: idx_discovery_sources_next_sync; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovery_sources_next_sync ON public.discovery_sources USING btree (last_sync_at, sync_interval_minutes) WHERE ((enabled = true) AND (sync_enabled = true));


--
-- Name: idx_discovery_sources_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_discovery_sources_type ON public.discovery_sources USING btree (source_type);


--
-- Name: idx_distributed_locks_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_distributed_locks_expires ON public.distributed_locks USING btree (expires_at);


--
-- Name: idx_edl_access_failed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_access_failed ON public.edl_access_log USING btree (auth_success) WHERE (auth_success = false);


--
-- Name: idx_edl_access_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_access_ip ON public.edl_access_log USING btree (client_ip, accessed_at DESC);


--
-- Name: idx_edl_access_list_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_access_list_time ON public.edl_access_log USING btree (list_id, accessed_at DESC);


--
-- Name: idx_edl_changelog_list; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_changelog_list ON public.edl_change_log USING btree (list_id, changed_at DESC);


--
-- Name: idx_edl_changelog_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_changelog_source ON public.edl_change_log USING btree (source_type, source_id);


--
-- Name: idx_edl_credentials_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_credentials_tenant_id ON public.edl_credentials USING btree (tenant_id);


--
-- Name: idx_edl_creds_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_creds_enabled ON public.edl_credentials USING btree (list_id, enabled) WHERE (enabled = true);


--
-- Name: idx_edl_creds_list; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_creds_list ON public.edl_credentials USING btree (list_id);


--
-- Name: idx_edl_creds_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_creds_prefix ON public.edl_credentials USING btree (token_prefix, list_id, enabled);


--
-- Name: idx_edl_lists_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_lists_enabled ON public.edl_lists USING btree (enabled) WHERE (enabled = true);


--
-- Name: idx_edl_lists_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_lists_slug ON public.edl_lists USING btree (slug);


--
-- Name: idx_edl_lists_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_lists_tenant ON public.edl_lists USING btree (tenant_id);


--
-- Name: idx_edl_lists_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_edl_lists_tenant_id ON public.edl_lists USING btree (tenant_id);


--
-- Name: idx_email_log_rule; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_email_log_rule ON public.email_log USING btree (rule_id);


--
-- Name: idx_email_log_sent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_email_log_sent ON public.email_log USING btree (sent_at DESC);


--
-- Name: idx_email_log_sent_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_email_log_sent_at ON public.email_log USING btree (sent_at);


--
-- Name: idx_email_log_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_email_log_status ON public.email_log USING btree (status);


--
-- Name: idx_email_templates_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_email_templates_category ON public.email_templates USING btree (category);


--
-- Name: idx_enrichment_cache_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_cache_expires ON public.enrichment_cache USING btree (expires_at);


--
-- Name: idx_enrichment_cache_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_cache_ioc ON public.enrichment_cache USING btree (ioc_type, ioc_value);


--
-- Name: idx_enrichment_cache_malicious; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_cache_malicious ON public.enrichment_cache USING btree (is_malicious) WHERE (is_malicious = true);


--
-- Name: idx_enrichment_cache_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_cache_provider ON public.enrichment_cache USING btree (provider);


--
-- Name: idx_enrichment_cache_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_cache_tenant_id ON public.enrichment_cache USING btree (tenant_id);


--
-- Name: idx_enrichment_cache_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_enrichment_cache_unique ON public.enrichment_cache USING btree (ioc_type, ioc_value, provider, tenant_id);


--
-- Name: idx_enrichment_jobs_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_jobs_created ON public.enrichment_jobs USING btree (created_at DESC);


--
-- Name: idx_enrichment_jobs_resource; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_jobs_resource ON public.enrichment_jobs USING btree (resource_id);


--
-- Name: idx_enrichment_jobs_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_jobs_status ON public.enrichment_jobs USING btree (status);


--
-- Name: idx_enrichment_jobs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_jobs_tenant_id ON public.enrichment_jobs USING btree (tenant_id);


--
-- Name: idx_enrichment_q_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_q_pending ON public.enrichment_queue USING btree (status, created_at) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_enrichment_q_retry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_q_retry ON public.enrichment_queue USING btree (next_retry_at) WHERE (((status)::text = 'failed'::text) AND (attempts < max_attempts));


--
-- Name: idx_enrichment_q_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_q_source ON public.enrichment_queue USING btree (source_event_id);


--
-- Name: idx_enrichment_q_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_q_status ON public.enrichment_queue USING btree (status, priority);


--
-- Name: idx_enrichment_queue_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_queue_ioc ON public.enrichment_priority_queue USING btree (ioc_value, ioc_type);


--
-- Name: idx_enrichment_queue_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_queue_priority ON public.enrichment_priority_queue USING btree (calculated_priority, status) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_enrichment_queue_scheduled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_queue_scheduled ON public.enrichment_priority_queue USING btree (scheduled_for) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_enrichment_queue_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_enrichment_queue_status ON public.enrichment_priority_queue USING btree (status);


--
-- Name: idx_enrichment_queue_unique_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_enrichment_queue_unique_pending ON public.enrichment_priority_queue USING btree (ioc_value, ioc_type) WHERE ((status)::text = ANY ((ARRAY['pending'::character varying, 'processing'::character varying])::text[]));


--
-- Name: idx_entity_risk_breached; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_risk_breached ON public.entity_risk USING btree (tenant_id, threshold_breached) WHERE (threshold_breached = true);


--
-- Name: idx_entity_risk_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_risk_investigation ON public.entity_risk USING btree (investigation_id) WHERE (investigation_id IS NOT NULL);


--
-- Name: idx_entity_risk_score; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_risk_score ON public.entity_risk USING btree (tenant_id, risk_score DESC);


--
-- Name: idx_entity_risk_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_entity_risk_tenant ON public.entity_risk USING btree (tenant_id);


--
-- Name: idx_escalation_config_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_escalation_config_tenant_id ON public.escalation_config USING btree (tenant_id);


--
-- Name: idx_escalation_history_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_escalation_history_tenant_id ON public.escalation_history USING btree (tenant_id);


--
-- Name: idx_exclusion_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_exclusion_active ON public.exclusion_list USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_exclusion_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_exclusion_category ON public.exclusion_list USING btree (category);


--
-- Name: idx_exclusion_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_exclusion_expires ON public.exclusion_list USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: idx_exclusion_list_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_exclusion_list_tenant_id ON public.exclusion_list USING btree (tenant_id);


--
-- Name: idx_exclusion_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_exclusion_type ON public.exclusion_list USING btree (ioc_type);


--
-- Name: idx_form_submissions_alert; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_form_submissions_alert ON public.form_submissions USING btree (alert_id) WHERE (alert_id IS NOT NULL);


--
-- Name: idx_form_submissions_form_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_form_submissions_form_id ON public.form_submissions USING btree (form_id);


--
-- Name: idx_form_submissions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_form_submissions_status ON public.form_submissions USING btree (status);


--
-- Name: idx_frontend_errors_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_frontend_errors_created_at ON public.frontend_errors USING btree (created_at DESC);


--
-- Name: idx_geopolitical_events_countries; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_geopolitical_events_countries ON public.geopolitical_events USING gin (countries_involved);


--
-- Name: idx_geopolitical_events_ongoing; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_geopolitical_events_ongoing ON public.geopolitical_events USING btree (is_ongoing) WHERE (is_ongoing = true);


--
-- Name: idx_geopolitical_events_risk; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_geopolitical_events_risk ON public.geopolitical_events USING btree (cyber_risk_level);


--
-- Name: idx_geopolitical_events_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_geopolitical_events_type ON public.geopolitical_events USING btree (event_type);


--
-- Name: idx_group_assignments_group; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_group_assignments_group ON public.group_source_assignments USING btree (group_id);


--
-- Name: idx_group_assignments_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_group_assignments_priority ON public.group_source_assignments USING btree (priority DESC);


--
-- Name: idx_group_assignments_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_group_assignments_source ON public.group_source_assignments USING btree (source_type_id);


--
-- Name: idx_health_metrics_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_health_metrics_provider ON public.enrichment_health_metrics USING btree (provider, measurement_time DESC);


--
-- Name: idx_health_metrics_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_health_metrics_time ON public.enrichment_health_metrics USING btree (measurement_time DESC);


--
-- Name: idx_inbound_email_from; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_email_from ON public.inbound_email_queue USING btree (from_address);


--
-- Name: idx_inbound_email_mailbox; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_email_mailbox ON public.inbound_email_queue USING btree (mailbox_id);


--
-- Name: idx_inbound_email_queue_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_email_queue_tenant_id ON public.inbound_email_queue USING btree (tenant_id);


--
-- Name: idx_inbound_email_received; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_email_received ON public.inbound_email_queue USING btree (received_at DESC);


--
-- Name: idx_inbound_email_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_email_status ON public.inbound_email_queue USING btree (status);


--
-- Name: idx_inbound_mailboxes_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_mailboxes_enabled ON public.inbound_mailboxes USING btree (enabled);


--
-- Name: idx_inbound_mailboxes_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_mailboxes_type ON public.inbound_mailboxes USING btree (mailbox_type);


--
-- Name: idx_intake_attachments_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_attachments_expires ON public.intake_form_attachments USING btree (expires_at) WHERE (deleted_at IS NULL);


--
-- Name: idx_intake_attachments_form; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_attachments_form ON public.intake_form_attachments USING btree (form_id);


--
-- Name: idx_intake_attachments_submission; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_attachments_submission ON public.intake_form_attachments USING btree (submission_id) WHERE (submission_id IS NOT NULL);


--
-- Name: idx_intake_attachments_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_attachments_tenant ON public.intake_form_attachments USING btree (tenant_id);


--
-- Name: idx_intake_form_submissions_alert; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_form_submissions_alert ON public.intake_form_submissions USING btree (alert_id) WHERE (alert_id IS NOT NULL);


--
-- Name: idx_intake_form_submissions_form; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_form_submissions_form ON public.intake_form_submissions USING btree (form_id, created_at DESC);


--
-- Name: idx_intake_form_submissions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_form_submissions_status ON public.intake_form_submissions USING btree (status);


--
-- Name: idx_intake_form_submissions_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_form_submissions_tenant ON public.intake_form_submissions USING btree (tenant_id);


--
-- Name: idx_intake_forms_playbook; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_forms_playbook ON public.intake_forms USING btree (auto_trigger_playbook_id) WHERE (auto_trigger_playbook_id IS NOT NULL);


--
-- Name: idx_intake_forms_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_forms_slug ON public.intake_forms USING btree (slug);


--
-- Name: idx_intake_forms_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_forms_tenant ON public.intake_forms USING btree (tenant_id);


--
-- Name: idx_intake_forms_tenant_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_intake_forms_tenant_status ON public.intake_forms USING btree (tenant_id, status);


--
-- Name: idx_integration_credentials_integration; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_credentials_integration ON public.integration_credentials USING btree (integration_id);


--
-- Name: idx_integration_credentials_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_credentials_tenant_id ON public.integration_credentials USING btree (tenant_id);


--
-- Name: idx_integration_update_history_integration; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_update_history_integration ON public.integration_update_history USING btree (integration_id);


--
-- Name: idx_integration_update_history_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_update_history_started ON public.integration_update_history USING btree (started_at DESC);


--
-- Name: idx_integration_update_history_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_update_history_status ON public.integration_update_history USING btree (status);


--
-- Name: idx_integration_update_history_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_update_history_type ON public.integration_update_history USING btree (update_type);


--
-- Name: idx_integration_update_schedules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_update_schedules_enabled ON public.integration_update_schedules USING btree (enabled);


--
-- Name: idx_integration_update_schedules_frequency; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_update_schedules_frequency ON public.integration_update_schedules USING btree (update_frequency);


--
-- Name: idx_integration_update_schedules_integration; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integration_update_schedules_integration ON public.integration_update_schedules USING btree (integration_id);


--
-- Name: idx_integrations_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integrations_category ON public.integrations USING btree (category);


--
-- Name: idx_integrations_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integrations_enabled ON public.integrations USING btree (enabled);


--
-- Name: idx_integrations_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integrations_provider ON public.integrations USING btree (provider);


--
-- Name: idx_integrations_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_integrations_tenant_id ON public.integrations USING btree (tenant_id);


--
-- Name: idx_inv_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_audit_action ON public.investigation_audit_log USING btree (action);


--
-- Name: idx_inv_audit_actor; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_audit_actor ON public.investigation_audit_log USING btree (actor_id);


--
-- Name: idx_inv_audit_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_audit_category ON public.investigation_audit_log USING btree (action_category);


--
-- Name: idx_inv_audit_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_audit_created_at ON public.investigation_audit_log USING btree (created_at DESC);


--
-- Name: idx_inv_audit_investigation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inv_audit_investigation_id ON public.investigation_audit_log USING btree (investigation_id);


--
-- Name: idx_investigation_audit_log_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_audit_log_tenant_id ON public.investigation_audit_log USING btree (tenant_id);


--
-- Name: idx_investigation_chat_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_chat_tenant_id ON public.investigation_chat USING btree (tenant_id);


--
-- Name: idx_investigation_entities_alert_count; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_entities_alert_count ON public.investigation_entities USING btree (alert_count DESC);


--
-- Name: idx_investigation_entities_confidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_entities_confidence ON public.investigation_entities USING btree (confidence DESC);


--
-- Name: idx_investigation_entities_entity_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_entities_entity_type ON public.investigation_entities USING btree (entity_type);


--
-- Name: idx_investigation_entities_investigation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_entities_investigation_id ON public.investigation_entities USING btree (investigation_id);


--
-- Name: idx_investigation_entities_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_entities_tenant_id ON public.investigation_entities USING btree (tenant_id);


--
-- Name: idx_investigation_iocs_inv; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_iocs_inv ON public.investigation_iocs USING btree (investigation_id);


--
-- Name: idx_investigation_iocs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_iocs_tenant_id ON public.investigation_iocs USING btree (tenant_id);


--
-- Name: idx_investigation_notes_author; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_notes_author ON public.investigation_notes USING btree (author);


--
-- Name: idx_investigation_notes_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_notes_created_at ON public.investigation_notes USING btree (created_at DESC);


--
-- Name: idx_investigation_notes_investigation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_notes_investigation_id ON public.investigation_notes USING btree (investigation_id);


--
-- Name: idx_investigation_notes_metadata; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_notes_metadata ON public.investigation_notes USING gin (metadata);


--
-- Name: idx_investigation_notes_note_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_notes_note_type ON public.investigation_notes USING btree (note_type);


--
-- Name: idx_investigation_notes_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_notes_tenant_id ON public.investigation_notes USING btree (tenant_id);


--
-- Name: idx_investigation_ownership_log_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigation_ownership_log_tenant_id ON public.investigation_ownership_log USING btree (tenant_id);


--
-- Name: idx_investigations_acknowledged_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_acknowledged_at ON public.investigations USING btree (acknowledged_at) WHERE (acknowledged_at IS NOT NULL);


--
-- Name: idx_investigations_alert_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_alert_id ON public.investigations USING btree (alert_id);


--
-- Name: idx_investigations_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_created_at ON public.investigations USING btree (created_at DESC);


--
-- Name: idx_investigations_data; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_data ON public.investigations USING gin (investigation_data);


--
-- Name: idx_investigations_display_id; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_investigations_display_id ON public.investigations USING btree (display_id);


--
-- Name: idx_investigations_disposition; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_disposition ON public.investigations USING btree (disposition);


--
-- Name: idx_investigations_investigation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_investigation_id ON public.investigations USING btree (investigation_id);


--
-- Name: idx_investigations_last_activity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_last_activity ON public.investigations USING btree (last_activity_at);


--
-- Name: idx_investigations_owner; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_owner ON public.investigations USING btree (owner);


--
-- Name: idx_investigations_owner_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_owner_type ON public.investigations USING btree (owner_type);


--
-- Name: idx_investigations_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_priority ON public.investigations USING btree (priority);


--
-- Name: idx_investigations_provisional_verdict; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_provisional_verdict ON public.investigations USING btree (provisional_verdict);


--
-- Name: idx_investigations_resolution_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_resolution_type ON public.investigations USING btree (resolution_type);


--
-- Name: idx_investigations_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_severity ON public.investigations USING btree (severity);


--
-- Name: idx_investigations_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_state ON public.investigations USING btree (state);


--
-- Name: idx_investigations_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_tenant_id ON public.investigations USING btree (tenant_id);


--
-- Name: idx_investigations_tenant_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_tenant_state ON public.investigations USING btree (tenant_id, state);


--
-- Name: idx_investigations_tenant_state_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_tenant_state_created ON public.investigations USING btree (tenant_id, state, created_at DESC);


--
-- Name: idx_investigations_tenant_state_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_tenant_state_priority ON public.investigations USING btree (tenant_id, state, priority);


--
-- Name: idx_investigations_triage_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_investigations_triage_status ON public.investigations USING btree (triage_status);


--
-- Name: idx_ioc_blocklist_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_blocklist_active ON public.ioc_blocklist USING btree (is_active) WHERE (is_active = true);


--
-- Name: idx_ioc_blocklist_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_blocklist_tenant_id ON public.ioc_blocklist USING btree (tenant_id);


--
-- Name: idx_ioc_blocklist_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_blocklist_type ON public.ioc_blocklist USING btree (ioc_type);


--
-- Name: idx_ioc_blocklist_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_blocklist_value ON public.ioc_blocklist USING btree (ioc_value);


--
-- Name: idx_ioc_enrichments_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_enrichments_status ON public.ioc_enrichments USING btree (status);


--
-- Name: idx_ioc_enrichments_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_enrichments_tenant_id ON public.ioc_enrichments USING btree (tenant_id);


--
-- Name: idx_ioc_enrichments_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_enrichments_value ON public.ioc_enrichments USING btree (ioc_value_normalized);


--
-- Name: idx_ioc_feed_appearances_feed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_appearances_feed ON public.ioc_feed_appearances USING btree (feed_id);


--
-- Name: idx_ioc_feed_appearances_ioc; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_appearances_ioc ON public.ioc_feed_appearances USING btree (ioc_value, ioc_type);


--
-- Name: idx_ioc_feed_appearances_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_feed_appearances_last_seen ON public.ioc_feed_appearances USING btree (last_seen_in_feed DESC);


--
-- Name: idx_ioc_whitelist_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_whitelist_category ON public.ioc_whitelist USING btree (category);


--
-- Name: idx_ioc_whitelist_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_whitelist_expires ON public.ioc_whitelist USING btree (expires_at) WHERE (expires_at IS NOT NULL);


--
-- Name: idx_ioc_whitelist_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_whitelist_tenant_id ON public.ioc_whitelist USING btree (tenant_id);


--
-- Name: idx_ioc_whitelist_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_whitelist_type ON public.ioc_whitelist USING btree (ioc_type);


--
-- Name: idx_ioc_whitelist_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_whitelist_value ON public.ioc_whitelist USING btree (ioc_value);


--
-- Name: idx_iocs_enrichment; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_enrichment ON public.iocs USING gin (enrichment_data);


--
-- Name: idx_iocs_feed_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_feed_last_seen ON public.iocs USING btree (feed_last_seen_at DESC);


--
-- Name: idx_iocs_feed_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_feed_name ON public.iocs USING btree (feed_name);


--
-- Name: idx_iocs_last_enriched; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_last_enriched ON public.iocs USING btree (last_enriched_at);


--
-- Name: idx_iocs_last_seen; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_last_seen ON public.iocs USING btree (last_seen DESC);


--
-- Name: idx_iocs_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_severity ON public.iocs USING btree (severity);


--
-- Name: idx_iocs_source_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_source_type ON public.iocs USING btree (source_type);


--
-- Name: idx_iocs_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_tags ON public.iocs USING gin (tags);


--
-- Name: idx_iocs_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_tenant_id ON public.iocs USING btree (tenant_id);


--
-- Name: idx_iocs_tenant_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_tenant_type ON public.iocs USING btree (tenant_id, ioc_type);


--
-- Name: idx_iocs_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_type ON public.iocs USING btree (ioc_type);


--
-- Name: idx_iocs_value; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_iocs_value ON public.iocs USING btree (ioc_value);


--
-- Name: idx_itsm_config_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itsm_config_enabled ON public.itsm_configurations USING btree (enabled) WHERE (enabled = true);


--
-- Name: idx_itsm_config_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itsm_config_type ON public.itsm_configurations USING btree (system_type);


--
-- Name: idx_itsm_exports_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itsm_exports_created ON public.itsm_exports USING btree (created_at DESC);


--
-- Name: idx_itsm_exports_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_itsm_exports_investigation ON public.itsm_exports USING btree (investigation_id);


--
-- Name: idx_job_queue_completed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_job_queue_completed ON public.job_queue USING btree (completed_at DESC) WHERE ((status)::text = ANY ((ARRAY['completed'::character varying, 'failed'::character varying, 'dead'::character varying])::text[]));


--
-- Name: idx_job_queue_locked; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_job_queue_locked ON public.job_queue USING btree (locked_until) WHERE ((status)::text = 'processing'::text);


--
-- Name: idx_job_queue_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_job_queue_pending ON public.job_queue USING btree (queue_name, priority, scheduled_for) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_job_queue_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_job_queue_type ON public.job_queue USING btree (job_type, status);


--
-- Name: idx_kb_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_active ON public.knowledge_base USING btree (is_active);


--
-- Name: idx_kb_approved_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_approved_at ON public.knowledge_base USING btree (approved_at);


--
-- Name: idx_kb_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_category ON public.knowledge_base USING btree (category);


--
-- Name: idx_kb_compliance; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_compliance ON public.knowledge_base USING gin (compliance_frameworks);


--
-- Name: idx_kb_content_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_content_type ON public.knowledge_base USING btree (content_type);


--
-- Name: idx_kb_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_created_at ON public.knowledge_base USING btree (created_at DESC);


--
-- Name: idx_kb_fts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_fts ON public.knowledge_base USING gin (to_tsvector('english'::regconfig, (((title)::text || ' '::text) || content)));


--
-- Name: idx_kb_fulltext; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_fulltext ON public.knowledge_base USING gin (to_tsvector('english'::regconfig, (((title)::text || ' '::text) || content)));


--
-- Name: idx_kb_incident_types; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_incident_types ON public.knowledge_base USING gin (incident_types);


--
-- Name: idx_kb_ioc_types; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_ioc_types ON public.knowledge_base USING gin (ioc_types);


--
-- Name: idx_kb_is_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_is_active ON public.knowledge_base USING btree (is_active);


--
-- Name: idx_kb_kb_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_kb_id ON public.knowledge_base USING btree (kb_id);


--
-- Name: idx_kb_mitre; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_mitre ON public.knowledge_base USING gin (mitre_techniques);


--
-- Name: idx_kb_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_priority ON public.knowledge_base USING btree (priority);


--
-- Name: idx_kb_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_severity ON public.knowledge_base USING gin (severity_filter);


--
-- Name: idx_kb_severity_filter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_severity_filter ON public.knowledge_base USING gin (severity_filter);


--
-- Name: idx_kb_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_source ON public.knowledge_base USING btree (source);


--
-- Name: idx_kb_submissions_kb_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_submissions_kb_id ON public.kb_community_submissions USING btree (kb_id);


--
-- Name: idx_kb_submissions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_submissions_status ON public.kb_community_submissions USING btree (status);


--
-- Name: idx_kb_submissions_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_submissions_tenant ON public.kb_community_submissions USING btree (tenant_id);


--
-- Name: idx_kb_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_tags ON public.knowledge_base USING gin (tags);


--
-- Name: idx_kb_uploads_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_uploads_created_at ON public.kb_document_uploads USING btree (created_at DESC);


--
-- Name: idx_kb_uploads_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_uploads_status ON public.kb_document_uploads USING btree (status);


--
-- Name: idx_kb_uploads_upload_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_uploads_upload_id ON public.kb_document_uploads USING btree (upload_id);


--
-- Name: idx_kb_versions_kb_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_versions_kb_id ON public.knowledge_base_versions USING btree (kb_id);


--
-- Name: idx_kb_versions_version; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_kb_versions_version ON public.knowledge_base_versions USING btree (version);


--
-- Name: idx_knowledge_base_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_knowledge_base_tenant_id ON public.knowledge_base USING btree (tenant_id);


--
-- Name: idx_lead_drafts_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_lead_drafts_pending ON public.lead_drafts USING btree (created_at DESC) WHERE ((status)::text = 'pending_review'::text);


--
-- Name: idx_lead_drafts_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_lead_drafts_source ON public.lead_drafts USING btree (source_type, source_id);


--
-- Name: idx_lead_drafts_status_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_lead_drafts_status_created ON public.lead_drafts USING btree (status, created_at DESC);


--
-- Name: idx_llm_mesh_endpoint; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_mesh_endpoint ON public.llm_mesh_snapshots USING btree (endpoint_url);


--
-- Name: idx_llm_mesh_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_mesh_status ON public.llm_mesh_snapshots USING btree (status);


--
-- Name: idx_llm_mesh_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_mesh_time ON public.llm_mesh_snapshots USING btree (snapshot_time DESC);


--
-- Name: idx_log_agents_hostname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_agents_hostname ON public.log_agents USING btree (hostname);


--
-- Name: idx_log_agents_last_heartbeat; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_agents_last_heartbeat ON public.log_agents USING btree (last_heartbeat);


--
-- Name: idx_log_agents_os_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_agents_os_type ON public.log_agents USING btree (os_type);


--
-- Name: idx_log_agents_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_agents_status ON public.log_agents USING btree (status);


--
-- Name: idx_log_agents_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_agents_tags ON public.log_agents USING gin (tags);


--
-- Name: idx_log_indexes_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_indexes_active ON public.log_indexes USING btree (is_active);


--
-- Name: idx_log_indexes_classification; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_indexes_classification ON public.log_indexes USING btree (data_classification);


--
-- Name: idx_log_indexes_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_indexes_name ON public.log_indexes USING btree (name);


--
-- Name: idx_log_indexes_pattern; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_indexes_pattern ON public.log_indexes USING btree (index_pattern);


--
-- Name: idx_log_search_audit_indexes; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_search_audit_indexes ON public.log_search_audit USING gin (index_names);


--
-- Name: idx_log_search_audit_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_search_audit_time ON public.log_search_audit USING btree (created_at DESC);


--
-- Name: idx_log_search_audit_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_search_audit_user ON public.log_search_audit USING btree (username, created_at DESC);


--
-- Name: idx_log_source_configs_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_source_configs_active ON public.log_source_configs USING btree (is_active);


--
-- Name: idx_log_source_configs_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_source_configs_type ON public.log_source_configs USING btree (source_type);


--
-- Name: idx_log_source_types_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_log_source_types_category ON public.log_source_types USING btree (category);


--
-- Name: idx_login_ip_locked; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_login_ip_locked ON public.login_attempts_by_ip USING btree (locked_until) WHERE (locked_until IS NOT NULL);


--
-- Name: idx_ml_predictions_actual; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ml_predictions_actual ON public.ml_predictions USING btree (actual_disposition) WHERE (actual_disposition IS NOT NULL);


--
-- Name: idx_ml_predictions_alert; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ml_predictions_alert ON public.ml_predictions USING btree (alert_id);


--
-- Name: idx_ml_predictions_confidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ml_predictions_confidence ON public.ml_predictions USING btree (confidence);


--
-- Name: idx_ml_predictions_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ml_predictions_created ON public.ml_predictions USING btree (created_at DESC);


--
-- Name: idx_ml_training_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ml_training_status ON public.ml_training_runs USING btree (status);


--
-- Name: idx_ml_training_trained_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ml_training_trained_at ON public.ml_training_runs USING btree (trained_at DESC);


--
-- Name: idx_model_perf_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_model_perf_date ON public.model_performance_daily USING btree (metric_date DESC);


--
-- Name: idx_model_perf_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_model_perf_provider ON public.model_performance_daily USING btree (provider);


--
-- Name: idx_notification_rules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_rules_enabled ON public.notification_rules USING btree (enabled);


--
-- Name: idx_notification_rules_event; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_rules_event ON public.notification_rules USING gin (event_types);


--
-- Name: idx_notification_rules_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notification_rules_tenant_id ON public.notification_rules USING btree (tenant_id);


--
-- Name: idx_notifications_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_created ON public.notifications USING btree (created_at DESC);


--
-- Name: idx_notifications_tenant_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_tenant_user ON public.notifications USING btree (tenant_id, user_id);


--
-- Name: idx_notifications_unread; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_notifications_unread ON public.notifications USING btree (tenant_id, user_id, read) WHERE (read = false);


--
-- Name: idx_overrides_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_overrides_agent ON public.human_overrides USING btree (agent_id);


--
-- Name: idx_overrides_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_overrides_category ON public.human_overrides USING btree (override_category);


--
-- Name: idx_overrides_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_overrides_created ON public.human_overrides USING btree (created_at DESC);


--
-- Name: idx_overrides_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_overrides_investigation ON public.human_overrides USING btree (investigation_id);


--
-- Name: idx_ownership_log_change_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ownership_log_change_type ON public.investigation_ownership_log USING btree (change_type);


--
-- Name: idx_ownership_log_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ownership_log_created ON public.investigation_ownership_log USING btree (created_at DESC);


--
-- Name: idx_ownership_log_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ownership_log_investigation ON public.investigation_ownership_log USING btree (investigation_id);


--
-- Name: idx_password_reset_tokens_expiry; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_password_reset_tokens_expiry ON public.password_reset_tokens USING btree (expiry);


--
-- Name: idx_password_reset_tokens_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_password_reset_tokens_token ON public.password_reset_tokens USING btree (token);


--
-- Name: idx_pb_approval_exec; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_approval_exec ON public.playbook_node_approvals USING btree (execution_id);


--
-- Name: idx_pb_approval_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_approval_status ON public.playbook_node_approvals USING btree (status);


--
-- Name: idx_pb_exec_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_exec_id ON public.playbook_executions USING btree (execution_id);


--
-- Name: idx_pb_exec_playbook; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_exec_playbook ON public.playbook_executions USING btree (playbook_id);


--
-- Name: idx_pb_exec_resume_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_exec_resume_at ON public.playbook_executions USING btree (resume_at) WHERE (((status)::text = 'waiting_delay'::text) AND (resume_at IS NOT NULL));


--
-- Name: idx_pb_exec_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_exec_status ON public.playbook_executions USING btree (status);


--
-- Name: idx_pb_file_exec; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_file_exec ON public.playbook_files USING btree (execution_id);


--
-- Name: idx_pb_file_form; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_file_form ON public.playbook_files USING btree (form_submission_id);


--
-- Name: idx_pb_form_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_form_name ON public.playbook_forms USING btree (name);


--
-- Name: idx_pb_form_sub_exec; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_form_sub_exec ON public.playbook_form_submissions USING btree (execution_id);


--
-- Name: idx_pb_form_sub_form; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_form_sub_form ON public.playbook_form_submissions USING btree (form_id);


--
-- Name: idx_pb_form_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_form_tenant ON public.playbook_forms USING btree (tenant_id);


--
-- Name: idx_pb_func_approved; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_func_approved ON public.playbook_functions USING btree (is_approved);


--
-- Name: idx_pb_func_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_func_name ON public.playbook_functions USING btree (name);


--
-- Name: idx_pb_list_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_list_name ON public.playbook_lists USING btree (name);


--
-- Name: idx_pb_list_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_list_type ON public.playbook_lists USING btree (list_type);


--
-- Name: idx_pb_template_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_template_category ON public.playbook_templates USING btree (category);


--
-- Name: idx_pb_template_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_template_tags ON public.playbook_templates USING gin (tags);


--
-- Name: idx_pb_tmpl_difficulty; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_tmpl_difficulty ON public.playbook_templates USING btree (difficulty);


--
-- Name: idx_pb_tmpl_install_count; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_tmpl_install_count ON public.playbook_templates USING btree (install_count DESC);


--
-- Name: idx_pb_tmpl_required_integrations; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_tmpl_required_integrations ON public.playbook_templates USING gin (required_integrations);


--
-- Name: idx_pb_tmpl_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_tmpl_severity ON public.playbook_templates USING gin (severity_filter);


--
-- Name: idx_pb_tmpl_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_tmpl_slug ON public.playbook_templates USING btree (slug);


--
-- Name: idx_pb_tmpl_slug_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_pb_tmpl_slug_unique ON public.playbook_templates USING btree (slug) WHERE (tenant_id IS NULL);


--
-- Name: idx_pb_tmpl_subcategory; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_tmpl_subcategory ON public.playbook_templates USING btree (subcategory);


--
-- Name: idx_pb_tmpl_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_tmpl_tenant_id ON public.playbook_templates USING btree (tenant_id);


--
-- Name: idx_pb_versions_playbook; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_versions_playbook ON public.playbook_versions USING btree (playbook_id, version_number DESC);


--
-- Name: idx_phishing_campaigns_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_campaigns_created ON public.phishing_campaigns USING btree (created_at DESC);


--
-- Name: idx_phishing_campaigns_sender; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_campaigns_sender ON public.phishing_campaigns USING btree (common_sender_domain);


--
-- Name: idx_phishing_campaigns_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_campaigns_status ON public.phishing_campaigns USING btree (status);


--
-- Name: idx_phishing_reports_campaign; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_reports_campaign ON public.phishing_reports USING btree (campaign_id);


--
-- Name: idx_phishing_reports_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_reports_created ON public.phishing_reports USING btree (created_at DESC);


--
-- Name: idx_phishing_reports_message_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_reports_message_id ON public.phishing_reports USING btree (message_id);


--
-- Name: idx_phishing_reports_reporter; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_reports_reporter ON public.phishing_reports USING btree (reporter_email);


--
-- Name: idx_phishing_reports_similarity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_reports_similarity ON public.phishing_reports USING btree (similarity_hash);


--
-- Name: idx_phishing_reports_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_reports_status ON public.phishing_reports USING btree (status);


--
-- Name: idx_phishing_test_list_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_phishing_test_list_tenant ON public.phishing_test_list USING btree (tenant_id) WHERE (is_active = true);


--
-- Name: idx_platform_admins_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_platform_admins_active ON public.platform_admins USING btree (is_active);


--
-- Name: idx_platform_admins_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_platform_admins_email ON public.platform_admins USING btree (email);


--
-- Name: idx_platform_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_platform_audit_action ON public.platform_audit_log USING btree (action, created_at);


--
-- Name: idx_platform_audit_admin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_platform_audit_admin ON public.platform_audit_log USING btree (admin_id, created_at);


--
-- Name: idx_platform_audit_target; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_platform_audit_target ON public.platform_audit_log USING btree (target_type, target_id);


--
-- Name: idx_playbook_approvals_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_approvals_created ON public.playbook_execution_approvals USING btree (created_at DESC);


--
-- Name: idx_playbook_approvals_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_approvals_investigation ON public.playbook_execution_approvals USING btree (investigation_id);


--
-- Name: idx_playbook_approvals_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_approvals_status ON public.playbook_execution_approvals USING btree (status) WHERE (status = 'pending'::text);


--
-- Name: idx_playbook_execution_approvals_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_execution_approvals_tenant_id ON public.playbook_execution_approvals USING btree (tenant_id);


--
-- Name: idx_playbook_executions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_executions_tenant_id ON public.playbook_executions USING btree (tenant_id);


--
-- Name: idx_playbook_files_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_files_tenant_id ON public.playbook_files USING btree (tenant_id);


--
-- Name: idx_playbook_functions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_functions_tenant_id ON public.playbook_functions USING btree (tenant_id);


--
-- Name: idx_playbook_lists_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_lists_tenant_id ON public.playbook_lists USING btree (tenant_id);


--
-- Name: idx_playbook_node_approvals_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_node_approvals_tenant_id ON public.playbook_node_approvals USING btree (tenant_id);


--
-- Name: idx_playbook_submissions_pending; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_submissions_pending ON public.playbook_community_submissions USING btree (created_at DESC) WHERE ((status)::text = 'pending'::text);


--
-- Name: idx_playbook_submissions_playbook; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_submissions_playbook ON public.playbook_community_submissions USING btree (playbook_id);


--
-- Name: idx_playbook_submissions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_submissions_status ON public.playbook_community_submissions USING btree (status, created_at DESC);


--
-- Name: idx_playbook_submissions_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_submissions_tenant ON public.playbook_community_submissions USING btree (tenant_id, created_at DESC);


--
-- Name: idx_playbook_versions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_versions_tenant_id ON public.playbook_versions USING btree (tenant_id);


--
-- Name: idx_playbooks_alert_types; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbooks_alert_types ON public.playbooks USING gin (alert_types);


--
-- Name: idx_playbooks_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbooks_enabled ON public.playbooks USING btree (is_enabled, riggs_allowed);


--
-- Name: idx_playbooks_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbooks_name ON public.playbooks USING btree (name);


--
-- Name: idx_playbooks_riggs_allowed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbooks_riggs_allowed ON public.playbooks USING btree (riggs_allowed) WHERE (riggs_allowed = true);


--
-- Name: idx_playbooks_tags; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbooks_tags ON public.playbooks USING gin (tags);


--
-- Name: idx_playbooks_tenant_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbooks_tenant_enabled ON public.playbooks USING btree (tenant_id, is_enabled);


--
-- Name: idx_playbooks_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbooks_tenant_id ON public.playbooks USING btree (tenant_id);


--
-- Name: idx_poc_tracking_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_poc_tracking_active ON public.poc_tracking USING btree (is_active);


--
-- Name: idx_poc_tracking_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_poc_tracking_email ON public.poc_tracking USING btree (email_hash);


--
-- Name: idx_poc_tracking_ip; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_poc_tracking_ip ON public.poc_tracking USING btree (ip_hash);


--
-- Name: idx_post_res_tasks_inv; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_post_res_tasks_inv ON public.post_resolution_tasks USING btree (investigation_id);


--
-- Name: idx_post_res_tasks_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_post_res_tasks_status ON public.post_resolution_tasks USING btree (status);


--
-- Name: idx_post_resolution_rules_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_post_resolution_rules_enabled ON public.post_resolution_rules USING btree (enabled, priority);


--
-- Name: idx_post_resolution_rules_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_post_resolution_rules_name ON public.post_resolution_rules USING btree (name);


--
-- Name: idx_post_resolution_tasks_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_post_resolution_tasks_created ON public.post_resolution_tasks USING btree (created_at DESC);


--
-- Name: idx_post_resolution_tasks_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_post_resolution_tasks_investigation ON public.post_resolution_tasks USING btree (investigation_id);


--
-- Name: idx_post_resolution_tasks_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_post_resolution_tasks_status ON public.post_resolution_tasks USING btree (status);


--
-- Name: idx_post_resolution_tasks_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_post_resolution_tasks_type ON public.post_resolution_tasks USING btree (task_type);


--
-- Name: idx_public_demo_usage_day; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_public_demo_usage_day ON public.public_demo_usage USING btree (bucket_day, tool_name);


--
-- Name: idx_public_demo_usage_ip_day; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_public_demo_usage_ip_day ON public.public_demo_usage USING btree (ip_hash, bucket_day, tool_name);


--
-- Name: idx_public_demo_usage_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_public_demo_usage_unique ON public.public_demo_usage USING btree (ip_hash, bucket_hour, tool_name);


--
-- Name: idx_rate_limits_backoff; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rate_limits_backoff ON public.integration_rate_limits USING btree (backoff_until) WHERE (backoff_until IS NOT NULL);


--
-- Name: idx_rate_limits_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rate_limits_lookup ON public.registration_rate_limits USING btree (ip_hash, endpoint, window_start);


--
-- Name: idx_recommended_actions_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_recommended_actions_investigation ON public.recommended_actions USING btree (investigation_id);


--
-- Name: idx_recommended_actions_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_recommended_actions_status ON public.recommended_actions USING btree (status);


--
-- Name: idx_recommended_actions_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_recommended_actions_tenant ON public.recommended_actions USING btree (tenant_id);


--
-- Name: idx_recommended_actions_tenant_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_recommended_actions_tenant_investigation ON public.recommended_actions USING btree (tenant_id, investigation_id);


--
-- Name: idx_referrals_code; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referrals_code ON public.referrals USING btree (referral_code);


--
-- Name: idx_referrals_referred_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referrals_referred_tenant ON public.referrals USING btree (referred_tenant_id);


--
-- Name: idx_referrals_referrer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_referrals_referrer ON public.referrals USING btree (referrer_tenant_id);


--
-- Name: idx_reg_requests_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reg_requests_created ON public.registration_requests USING btree (created_at);


--
-- Name: idx_reg_requests_email_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reg_requests_email_hash ON public.registration_requests USING btree (email_hash);


--
-- Name: idx_reg_requests_ip_hash; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reg_requests_ip_hash ON public.registration_requests USING btree (ip_hash);


--
-- Name: idx_reg_requests_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reg_requests_slug ON public.registration_requests USING btree (tenant_slug);


--
-- Name: idx_reg_requests_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reg_requests_status ON public.registration_requests USING btree (status);


--
-- Name: idx_reg_requests_token; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reg_requests_token ON public.registration_requests USING btree (verification_token);


--
-- Name: idx_reg_requests_waitlisted; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_reg_requests_waitlisted ON public.registration_requests USING btree (created_at) WHERE ((status)::text = 'waitlisted'::text);


--
-- Name: idx_retention_policies_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_retention_policies_active ON public.retention_policies USING btree (is_active);


--
-- Name: idx_retention_policies_data_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_retention_policies_data_type ON public.retention_policies USING btree (data_type);


--
-- Name: idx_riggs_decisions_confidence; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_decisions_confidence ON public.riggs_decisions USING btree (confidence);


--
-- Name: idx_riggs_decisions_created_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_decisions_created_at ON public.riggs_decisions USING btree (created_at DESC);


--
-- Name: idx_riggs_decisions_decision_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_decisions_decision_type ON public.riggs_decisions USING btree (decision_type);


--
-- Name: idx_riggs_decisions_investigation_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_decisions_investigation_id ON public.riggs_decisions USING btree (investigation_id);


--
-- Name: idx_riggs_decisions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_decisions_tenant_id ON public.riggs_decisions USING btree (tenant_id);


--
-- Name: idx_riggs_feedback_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_feedback_created ON public.riggs_feedback USING btree (created_at DESC);


--
-- Name: idx_riggs_feedback_human; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_feedback_human ON public.riggs_feedback USING btree (human_verdict) WHERE (human_verdict IS NOT NULL);


--
-- Name: idx_riggs_feedback_match; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_feedback_match ON public.riggs_feedback USING btree (verdict_match) WHERE (verdict_match IS NOT NULL);


--
-- Name: idx_riggs_feedback_mode; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_feedback_mode ON public.riggs_feedback USING btree (riggs_mode);


--
-- Name: idx_riggs_feedback_severity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_feedback_severity ON public.riggs_feedback USING btree (severity);


--
-- Name: idx_riggs_feedback_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_feedback_source ON public.riggs_feedback USING btree (source);


--
-- Name: idx_riggs_feedback_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_feedback_tenant_id ON public.riggs_feedback USING btree (tenant_id);


--
-- Name: idx_riggs_feedback_verdict; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_feedback_verdict ON public.riggs_feedback USING btree (riggs_verdict);


--
-- Name: idx_riggs_feedback_verdict_canonical; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_feedback_verdict_canonical ON public.riggs_feedback USING btree (upper((riggs_verdict)::text));


--
-- Name: idx_riggs_playbook_executions_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_playbook_executions_created ON public.riggs_playbook_executions USING btree (created_at DESC);


--
-- Name: idx_riggs_playbook_executions_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_playbook_executions_investigation ON public.riggs_playbook_executions USING btree (investigation_id);


--
-- Name: idx_riggs_playbook_executions_playbook; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_playbook_executions_playbook ON public.riggs_playbook_executions USING btree (playbook_id);


--
-- Name: idx_riggs_playbook_executions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_riggs_playbook_executions_tenant_id ON public.riggs_playbook_executions USING btree (tenant_id);


--
-- Name: idx_role_index_perms_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_index_perms_index ON public.role_index_permissions USING btree (index_id);


--
-- Name: idx_role_index_perms_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_index_perms_name ON public.role_index_permissions USING btree (index_name);


--
-- Name: idx_role_index_perms_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_role_index_perms_role ON public.role_index_permissions USING btree (role);


--
-- Name: idx_roles_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_roles_name ON public.roles USING btree (name);


--
-- Name: idx_roles_system; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_roles_system ON public.roles USING btree (is_system);


--
-- Name: idx_sessions_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sessions_active ON public.user_sessions USING btree (user_id, is_active) WHERE (is_active = true);


--
-- Name: idx_sessions_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sessions_expires ON public.user_sessions USING btree (expires_at) WHERE (is_active = true);


--
-- Name: idx_sessions_jti; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sessions_jti ON public.user_sessions USING btree (jti);


--
-- Name: idx_sessions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sessions_tenant_id ON public.user_sessions USING btree (tenant_id);


--
-- Name: idx_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sessions_user_id ON public.user_sessions USING btree (user_id);


--
-- Name: idx_soar_executions_playbook; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_soar_executions_playbook ON public.soar_executions USING btree (playbook_id);


--
-- Name: idx_soar_executions_state; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_soar_executions_state ON public.soar_executions USING btree (state);


--
-- Name: idx_soar_executions_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_soar_executions_tenant_id ON public.soar_executions USING btree (tenant_id);


--
-- Name: idx_soar_playbooks_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_soar_playbooks_tenant_id ON public.soar_playbooks USING btree (tenant_id);


--
-- Name: idx_sop_effectiveness_helpful; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sop_effectiveness_helpful ON public.sop_effectiveness_tracking USING btree (was_helpful);


--
-- Name: idx_sop_effectiveness_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sop_effectiveness_investigation ON public.sop_effectiveness_tracking USING btree (investigation_id);


--
-- Name: idx_sop_effectiveness_kb_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_sop_effectiveness_kb_id ON public.sop_effectiveness_tracking USING btree (kb_id);


--
-- Name: idx_stripe_webhook_events_processed_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_stripe_webhook_events_processed_at ON public.stripe_webhook_events USING btree (processed_at);


--
-- Name: idx_tcu_applied_events_applied_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tcu_applied_events_applied_at ON public.tenant_claude_usage_applied_events USING btree (applied_at);


--
-- Name: idx_tcu_applied_events_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tcu_applied_events_tenant ON public.tenant_claude_usage_applied_events USING btree (tenant_id);


--
-- Name: idx_teams_specializations; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_teams_specializations ON public.teams USING gin (specializations);


--
-- Name: idx_teams_team_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_teams_team_id ON public.teams USING btree (team_id);


--
-- Name: idx_teams_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_teams_tenant_id ON public.teams USING btree (tenant_id);


--
-- Name: idx_telemetry_time; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_telemetry_time ON public.telemetry_snapshots USING btree (snapshot_time DESC);


--
-- Name: idx_tenant_audit_action; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_audit_action ON public.tenant_audit_log USING btree (action, created_at);


--
-- Name: idx_tenant_audit_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_audit_tenant ON public.tenant_audit_log USING btree (tenant_id, created_at);


--
-- Name: idx_tenant_byo_usage_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_byo_usage_tenant ON public.tenant_byo_usage USING btree (tenant_id, period);


--
-- Name: idx_tenant_licenses_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_licenses_active ON public.tenant_licenses USING btree (is_active, expires_at);


--
-- Name: idx_tenant_licenses_key; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_licenses_key ON public.tenant_licenses USING btree (license_key);


--
-- Name: idx_tenant_licenses_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_licenses_tenant ON public.tenant_licenses USING btree (tenant_id);


--
-- Name: idx_tenant_pii_patterns_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_pii_patterns_tenant ON public.tenant_pii_patterns USING btree (tenant_id) WHERE (enabled = true);


--
-- Name: idx_tenant_quota_warnings_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenant_quota_warnings_tenant ON public.tenant_quota_warnings USING btree (tenant_id);


--
-- Name: idx_tenants_billing_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_billing_status ON public.tenants USING btree (billing_status) WHERE ((billing_status)::text <> 'none'::text);


--
-- Name: idx_tenants_plan; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_plan ON public.tenants USING btree (plan);


--
-- Name: idx_tenants_slug; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_slug ON public.tenants USING btree (slug);


--
-- Name: idx_tenants_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_status ON public.tenants USING btree (status);


--
-- Name: idx_tenants_stripe_sub; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tenants_stripe_sub ON public.tenants USING btree (stripe_subscription_id) WHERE (stripe_subscription_id IS NOT NULL);


--
-- Name: idx_threat_feed_log_feed; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_feed_log_feed ON public.threat_feed_ingestion_log USING btree (feed_id);


--
-- Name: idx_threat_feed_log_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_feed_log_started ON public.threat_feed_ingestion_log USING btree (started_at DESC);


--
-- Name: idx_threat_feed_log_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_feed_log_status ON public.threat_feed_ingestion_log USING btree (status);


--
-- Name: idx_threat_feeds_category; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_feeds_category ON public.threat_feeds USING btree (category);


--
-- Name: idx_threat_feeds_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_feeds_enabled ON public.threat_feeds USING btree (enabled);


--
-- Name: idx_threat_feeds_feed_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_feeds_feed_id ON public.threat_feeds USING btree (feed_id);


--
-- Name: idx_threat_feeds_next_poll; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_feeds_next_poll ON public.threat_feeds USING btree (next_poll_at) WHERE (enabled = true);


--
-- Name: idx_threat_feeds_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_threat_feeds_tenant_id ON public.threat_feeds USING btree (tenant_id);


--
-- Name: idx_token_blacklist_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_token_blacklist_expires ON public.token_blacklist USING btree (expires_at);


--
-- Name: idx_token_blacklist_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_token_blacklist_username ON public.token_blacklist USING btree (username) WHERE ((token_type)::text = 'user'::text);


--
-- Name: idx_token_usage_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_token_usage_agent ON public.ai_token_usage USING btree (agent_id);


--
-- Name: idx_token_usage_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_token_usage_created ON public.ai_token_usage USING btree (created_at);


--
-- Name: idx_token_usage_provider; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_token_usage_provider ON public.ai_token_usage USING btree (provider);


--
-- Name: idx_trusted_senders_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trusted_senders_domain ON public.trusted_senders USING btree (domain);


--
-- Name: idx_trusted_senders_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trusted_senders_tenant_id ON public.trusted_senders USING btree (tenant_id);


--
-- Name: idx_typing_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_typing_expires ON public.chat_typing_status USING btree (expires_at);


--
-- Name: idx_typing_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_typing_investigation ON public.chat_typing_status USING btree (investigation_id);


--
-- Name: idx_usage_counters_period; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_usage_counters_period ON public.usage_counters USING btree (period);


--
-- Name: idx_usage_counters_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_usage_counters_tenant ON public.usage_counters USING btree (tenant_id);


--
-- Name: idx_usage_events_recorded; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_usage_events_recorded ON public.usage_events USING btree (recorded_at);


--
-- Name: idx_usage_events_tenant_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_usage_events_tenant_type ON public.usage_events USING btree (tenant_id, event_type, recorded_at);


--
-- Name: idx_usage_snapshots_tenant_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_usage_snapshots_tenant_date ON public.tenant_usage_snapshots USING btree (tenant_id, snapshot_date);


--
-- Name: idx_user_index_perms_index; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_index_perms_index ON public.user_index_permissions USING btree (index_id);


--
-- Name: idx_user_index_perms_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_index_perms_user ON public.user_index_permissions USING btree (user_id);


--
-- Name: idx_user_index_perms_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_index_perms_username ON public.user_index_permissions USING btree (username);


--
-- Name: idx_user_preferences_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_preferences_user_id ON public.user_preferences USING btree (user_id);


--
-- Name: idx_user_preferences_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_user_preferences_username ON public.user_preferences USING btree (username);


--
-- Name: idx_users_email; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_email ON public.users USING btree (email);


--
-- Name: idx_users_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_role ON public.users USING btree (role);


--
-- Name: idx_users_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_id ON public.users USING btree (tenant_id);


--
-- Name: idx_users_tenant_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_tenant_role ON public.users USING btree (tenant_id, role);


--
-- Name: idx_users_username; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_users_username ON public.users USING btree (username);


--
-- Name: idx_verdict_audit_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verdict_audit_investigation ON public.verdict_audit_log USING btree (investigation_id);


--
-- Name: idx_verdict_audit_log_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verdict_audit_log_tenant_id ON public.verdict_audit_log USING btree (tenant_id);


--
-- Name: idx_verdict_outcomes_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verdict_outcomes_agent ON public.agent_verdict_outcomes USING btree (agent_id);


--
-- Name: idx_verdict_outcomes_correct; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verdict_outcomes_correct ON public.agent_verdict_outcomes USING btree (was_correct) WHERE (was_correct IS NOT NULL);


--
-- Name: idx_verdict_outcomes_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verdict_outcomes_created ON public.agent_verdict_outcomes USING btree (created_at DESC);


--
-- Name: idx_verdict_outcomes_date; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verdict_outcomes_date ON public.agent_verdict_outcomes USING btree (agent_verdict_at DESC);


--
-- Name: idx_verdict_outcomes_investigation; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verdict_outcomes_investigation ON public.agent_verdict_outcomes USING btree (investigation_id);


--
-- Name: idx_verdict_outcomes_tier; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verdict_outcomes_tier ON public.agent_verdict_outcomes USING btree (agent_tier);


--
-- Name: idx_webhook_channels_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_channels_enabled ON public.webhook_channels USING btree (enabled);


--
-- Name: idx_webhook_channels_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_channels_type ON public.webhook_channels USING btree (channel_type);


--
-- Name: idx_webhooks_enabled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhooks_enabled ON public.webhooks USING btree (enabled);


--
-- Name: idx_webhooks_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhooks_name ON public.webhooks USING btree (name);


--
-- Name: idx_webhooks_tenant_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhooks_tenant_id ON public.webhooks USING btree (tenant_id);


--
-- Name: ioc_feed_appearances_value_type_feed_tenant_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ioc_feed_appearances_value_type_feed_tenant_key ON public.ioc_feed_appearances USING btree (ioc_value, ioc_type, feed_id, tenant_id);


--
-- Name: iocs_value_type_tenant_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX iocs_value_type_tenant_key ON public.iocs USING btree (ioc_value, ioc_type, tenant_id);


--
-- Name: ix_alerts_sensitivity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_alerts_sensitivity ON public.alerts USING btree (tenant_id, sensitivity);


--
-- Name: ix_investigations_sensitivity; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_investigations_sensitivity ON public.investigations USING btree (tenant_id, sensitivity);


--
-- Name: threat_feeds_feed_id_tenant_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX threat_feeds_feed_id_tenant_key ON public.threat_feeds USING btree (feed_id, tenant_id);


--
-- Name: agent_definitions agent_definitions_system_name; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER agent_definitions_system_name BEFORE INSERT OR UPDATE ON public.agent_definitions FOR EACH ROW EXECUTE FUNCTION public.generate_agent_system_name();


--
-- Name: alerts alerts_search_vector_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER alerts_search_vector_update BEFORE INSERT OR UPDATE ON public.alerts FOR EACH ROW EXECUTE FUNCTION tsvector_update_trigger('search_vector', 'pg_catalog.english', 'title', 'description');


--
-- Name: assets assets_history_trigger; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER assets_history_trigger AFTER INSERT OR UPDATE ON public.assets FOR EACH ROW EXECUTE FUNCTION public.record_asset_history();


--
-- Name: assets assets_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER assets_updated_at BEFORE UPDATE ON public.assets FOR EACH ROW EXECUTE FUNCTION public.update_asset_timestamp();


--
-- Name: discovered_apis discovered_apis_search_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER discovered_apis_search_update BEFORE INSERT OR UPDATE ON public.discovered_apis FOR EACH ROW EXECUTE FUNCTION public.update_discovered_apis_search_vector();


--
-- Name: agent_action_log trg_agent_action_log_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_agent_action_log_no_delete BEFORE DELETE ON public.agent_action_log FOR EACH ROW EXECUTE FUNCTION public.prevent_agent_action_log_mutation();


--
-- Name: agent_action_log trg_agent_action_log_no_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_agent_action_log_no_update BEFORE UPDATE ON public.agent_action_log FOR EACH ROW EXECUTE FUNCTION public.prevent_agent_action_log_mutation();


--
-- Name: ai_action_log trg_ai_action_log_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_ai_action_log_no_delete BEFORE DELETE ON public.ai_action_log FOR EACH ROW EXECUTE FUNCTION public.prevent_ai_action_log_mutation();


--
-- Name: ai_action_log trg_ai_action_log_no_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_ai_action_log_no_update BEFORE UPDATE ON public.ai_action_log FOR EACH ROW EXECUTE FUNCTION public.prevent_ai_action_log_mutation();


--
-- Name: investigation_audit_log trg_investigation_audit_no_delete; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_investigation_audit_no_delete BEFORE DELETE ON public.investigation_audit_log FOR EACH ROW EXECUTE FUNCTION public.prevent_investigation_audit_mutation();


--
-- Name: investigation_audit_log trg_investigation_audit_no_update; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_investigation_audit_no_update BEFORE UPDATE ON public.investigation_audit_log FOR EACH ROW EXECUTE FUNCTION public.prevent_investigation_audit_mutation();


--
-- Name: alerts update_alerts_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_alerts_updated_at BEFORE UPDATE ON public.alerts FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: investigation_notes update_investigation_notes_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_investigation_notes_updated_at BEFORE UPDATE ON public.investigation_notes FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: investigations update_investigations_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER update_investigations_updated_at BEFORE UPDATE ON public.investigations FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();


--
-- Name: action_requests action_requests_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_requests
    ADD CONSTRAINT action_requests_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE SET NULL;


--
-- Name: action_requests action_requests_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_requests
    ADD CONSTRAINT action_requests_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE SET NULL;


--
-- Name: action_requests action_requests_requested_by_agent_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_requests
    ADD CONSTRAINT action_requests_requested_by_agent_fkey FOREIGN KEY (requested_by_agent) REFERENCES public.agent_definitions(id) ON DELETE SET NULL;


--
-- Name: affiliate_codes affiliate_codes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.affiliate_codes
    ADD CONSTRAINT affiliate_codes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: agent_action_log agent_action_log_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_log
    ADD CONSTRAINT agent_action_log_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agent_definitions(id) ON DELETE CASCADE;


--
-- Name: agent_action_log agent_action_log_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_action_log
    ADD CONSTRAINT agent_action_log_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.agent_executions(id) ON DELETE CASCADE;


--
-- Name: agent_approval_requests agent_approval_requests_action_log_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_approval_requests
    ADD CONSTRAINT agent_approval_requests_action_log_id_fkey FOREIGN KEY (action_log_id) REFERENCES public.agent_action_log(id);


--
-- Name: agent_approval_requests agent_approval_requests_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_approval_requests
    ADD CONSTRAINT agent_approval_requests_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agent_definitions(id) ON DELETE CASCADE;


--
-- Name: agent_approval_requests agent_approval_requests_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_approval_requests
    ADD CONSTRAINT agent_approval_requests_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.agent_executions(id) ON DELETE CASCADE;


--
-- Name: agent_executions agent_executions_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_executions
    ADD CONSTRAINT agent_executions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agent_definitions(id) ON DELETE CASCADE;


--
-- Name: agent_rollback_actions agent_rollback_actions_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_rollback_actions
    ADD CONSTRAINT agent_rollback_actions_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.agent_executions(id) ON DELETE CASCADE;


--
-- Name: agent_verdict_outcomes agent_verdict_outcomes_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_verdict_outcomes
    ADD CONSTRAINT agent_verdict_outcomes_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: ai_action_log ai_action_log_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_action_log
    ADD CONSTRAINT ai_action_log_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(investigation_id) ON DELETE CASCADE;


--
-- Name: ai_agent_credentials ai_agent_credentials_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_agent_credentials
    ADD CONSTRAINT ai_agent_credentials_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.ai_agents(id) ON DELETE CASCADE;


--
-- Name: ai_token_usage ai_token_usage_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_token_usage
    ADD CONSTRAINT ai_token_usage_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: alert_attachments alert_attachments_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_attachments
    ADD CONSTRAINT alert_attachments_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(investigation_id) ON DELETE CASCADE;


--
-- Name: alert_groups alert_groups_dedupe_config_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_groups
    ADD CONSTRAINT alert_groups_dedupe_config_id_fkey FOREIGN KEY (dedupe_config_id) REFERENCES public.dedupe_config(id) ON DELETE SET NULL;


--
-- Name: alert_groups alert_groups_primary_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alert_groups
    ADD CONSTRAINT alert_groups_primary_alert_id_fkey FOREIGN KEY (primary_alert_id) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- Name: alerts alerts_alert_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_alert_group_id_fkey FOREIGN KEY (alert_group_id) REFERENCES public.alert_groups(id) ON DELETE SET NULL;


--
-- Name: alerts alerts_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE SET NULL;


--
-- Name: alerts alerts_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.alerts
    ADD CONSTRAINT alerts_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: approval_requests approval_requests_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.approval_requests
    ADD CONSTRAINT approval_requests_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: asset_conflicts asset_conflicts_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_conflicts
    ADD CONSTRAINT asset_conflicts_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: asset_conflicts asset_conflicts_conflicting_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_conflicts
    ADD CONSTRAINT asset_conflicts_conflicting_asset_id_fkey FOREIGN KEY (conflicting_asset_id) REFERENCES public.assets(id) ON DELETE SET NULL;


--
-- Name: asset_conflicts asset_conflicts_discovery_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_conflicts
    ADD CONSTRAINT asset_conflicts_discovery_job_id_fkey FOREIGN KEY (discovery_job_id) REFERENCES public.discovery_queue(id) ON DELETE SET NULL;


--
-- Name: asset_history asset_history_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_history
    ADD CONSTRAINT asset_history_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: asset_identifiers asset_identifiers_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_identifiers
    ADD CONSTRAINT asset_identifiers_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: asset_relationships asset_relationships_source_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_relationships
    ADD CONSTRAINT asset_relationships_source_asset_id_fkey FOREIGN KEY (source_asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: asset_relationships asset_relationships_target_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.asset_relationships
    ADD CONSTRAINT asset_relationships_target_asset_id_fkey FOREIGN KEY (target_asset_id) REFERENCES public.assets(id) ON DELETE CASCADE;


--
-- Name: audit_log audit_log_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.audit_log
    ADD CONSTRAINT audit_log_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: auto_response_settings auto_response_settings_instance_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auto_response_settings
    ADD CONSTRAINT auto_response_settings_instance_id_fkey FOREIGN KEY (instance_id) REFERENCES public.connect_instances(id) ON DELETE CASCADE;


--
-- Name: breach_intel_incidents breach_incidents_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_intel_incidents
    ADD CONSTRAINT breach_incidents_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.breach_intel_sources(source_id);


--
-- Name: breach_incidents breach_incidents_source_id_fkey1; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.breach_incidents
    ADD CONSTRAINT breach_incidents_source_id_fkey1 FOREIGN KEY (source_id) REFERENCES public.breach_intel_sources(source_id);


--
-- Name: campaign_iocs campaign_iocs_campaign_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_iocs
    ADD CONSTRAINT campaign_iocs_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_members campaign_members_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_members
    ADD CONSTRAINT campaign_members_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- Name: campaign_members campaign_members_campaign_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_members
    ADD CONSTRAINT campaign_members_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES public.campaigns(id) ON DELETE CASCADE;


--
-- Name: campaign_members campaign_members_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaign_members
    ADD CONSTRAINT campaign_members_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: chat_action_audit chat_action_audit_chat_message_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_action_audit
    ADD CONSTRAINT chat_action_audit_chat_message_id_fkey FOREIGN KEY (chat_message_id) REFERENCES public.investigation_chat(id) ON DELETE SET NULL;


--
-- Name: chat_action_audit chat_action_audit_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_action_audit
    ADD CONSTRAINT chat_action_audit_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE SET NULL;


--
-- Name: chat_subscriptions chat_subscriptions_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_subscriptions
    ADD CONSTRAINT chat_subscriptions_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: chat_typing_status chat_typing_status_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_typing_status
    ADD CONSTRAINT chat_typing_status_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: chat_usage_analytics chat_usage_analytics_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.chat_usage_analytics
    ADD CONSTRAINT chat_usage_analytics_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE SET NULL;


--
-- Name: collector_group_membership collector_group_membership_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_group_membership
    ADD CONSTRAINT collector_group_membership_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.log_agents(id) ON DELETE CASCADE;


--
-- Name: collector_group_membership collector_group_membership_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_group_membership
    ADD CONSTRAINT collector_group_membership_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.collector_groups(id) ON DELETE CASCADE;


--
-- Name: collector_source_assignments collector_source_assignments_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_source_assignments
    ADD CONSTRAINT collector_source_assignments_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.log_agents(id);


--
-- Name: collector_source_assignments collector_source_assignments_source_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.collector_source_assignments
    ADD CONSTRAINT collector_source_assignments_source_type_id_fkey FOREIGN KEY (source_type_id) REFERENCES public.log_source_types(id);


--
-- Name: connect_instances connect_instances_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connect_instances
    ADD CONSTRAINT connect_instances_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.connect_credentials(id) ON DELETE SET NULL;


--
-- Name: correlation_decisions correlation_decisions_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_decisions
    ADD CONSTRAINT correlation_decisions_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- Name: correlation_decisions correlation_decisions_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_decisions
    ADD CONSTRAINT correlation_decisions_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: correlation_decisions correlation_decisions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_decisions
    ADD CONSTRAINT correlation_decisions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: correlation_events correlation_events_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_events
    ADD CONSTRAINT correlation_events_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.correlation_rules(id) ON DELETE SET NULL;


--
-- Name: correlation_settings correlation_settings_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.correlation_settings
    ADD CONSTRAINT correlation_settings_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: credentials credentials_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: dedupe_config dedupe_config_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dedupe_config
    ADD CONSTRAINT dedupe_config_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: detection_hits detection_hits_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_hits
    ADD CONSTRAINT detection_hits_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.log_agents(id) ON DELETE SET NULL;


--
-- Name: detection_hits detection_hits_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_hits
    ADD CONSTRAINT detection_hits_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE SET NULL;


--
-- Name: detection_hits detection_hits_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.detection_hits
    ADD CONSTRAINT detection_hits_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.detection_rules(id) ON DELETE SET NULL;


--
-- Name: discovery_queue discovery_queue_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.discovery_queue
    ADD CONSTRAINT discovery_queue_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.discovery_sources(id) ON DELETE CASCADE;


--
-- Name: edl_access_log edl_access_log_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_access_log
    ADD CONSTRAINT edl_access_log_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.edl_credentials(credential_id) ON DELETE SET NULL;


--
-- Name: edl_access_log edl_access_log_list_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_access_log
    ADD CONSTRAINT edl_access_log_list_id_fkey FOREIGN KEY (list_id) REFERENCES public.edl_lists(list_id) ON DELETE CASCADE;


--
-- Name: edl_change_log edl_change_log_list_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_change_log
    ADD CONSTRAINT edl_change_log_list_id_fkey FOREIGN KEY (list_id) REFERENCES public.edl_lists(list_id) ON DELETE CASCADE;


--
-- Name: edl_content_cache edl_content_cache_list_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_content_cache
    ADD CONSTRAINT edl_content_cache_list_id_fkey FOREIGN KEY (list_id) REFERENCES public.edl_lists(list_id) ON DELETE CASCADE;


--
-- Name: edl_credentials edl_credentials_list_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_credentials
    ADD CONSTRAINT edl_credentials_list_id_fkey FOREIGN KEY (list_id) REFERENCES public.edl_lists(list_id) ON DELETE CASCADE;


--
-- Name: edl_items edl_items_list_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.edl_items
    ADD CONSTRAINT edl_items_list_id_fkey FOREIGN KEY (list_id) REFERENCES public.edl_lists(list_id) ON DELETE CASCADE;


--
-- Name: email_digest_queue email_digest_queue_rule_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_digest_queue
    ADD CONSTRAINT email_digest_queue_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.notification_rules(rule_id) ON DELETE CASCADE;


--
-- Name: email_log email_log_template_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.email_log
    ADD CONSTRAINT email_log_template_id_fkey FOREIGN KEY (template_id) REFERENCES public.email_templates(id) ON DELETE SET NULL;


--
-- Name: enrichment_queue enrichment_queue_result_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_queue
    ADD CONSTRAINT enrichment_queue_result_id_fkey FOREIGN KEY (result_id) REFERENCES public.enrichment_cache(id) ON DELETE SET NULL;


--
-- Name: enrichment_queue enrichment_queue_source_event_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_queue
    ADD CONSTRAINT enrichment_queue_source_event_id_fkey FOREIGN KEY (source_event_id) REFERENCES public.alerts(id) ON DELETE SET NULL;


--
-- Name: enrichment_queue enrichment_queue_source_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_queue
    ADD CONSTRAINT enrichment_queue_source_investigation_id_fkey FOREIGN KEY (source_investigation_id) REFERENCES public.investigations(id) ON DELETE SET NULL;


--
-- Name: entity_risk entity_risk_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.entity_risk
    ADD CONSTRAINT entity_risk_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: escalation_history escalation_history_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.escalation_history
    ADD CONSTRAINT escalation_history_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- Name: escalation_history escalation_history_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.escalation_history
    ADD CONSTRAINT escalation_history_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: action_requests fk_action_requests_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.action_requests
    ADD CONSTRAINT fk_action_requests_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: agent_approval_requests fk_agent_approval_requests_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_approval_requests
    ADD CONSTRAINT fk_agent_approval_requests_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: agent_definitions fk_agent_definitions_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_definitions
    ADD CONSTRAINT fk_agent_definitions_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: agent_executions fk_agent_executions_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_executions
    ADD CONSTRAINT fk_agent_executions_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: ai_agents fk_ai_agents_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ai_agents
    ADD CONSTRAINT fk_ai_agents_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: api_keys fk_api_keys_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT fk_api_keys_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: campaigns fk_campaigns_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.campaigns
    ADD CONSTRAINT fk_campaigns_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: connect_credentials fk_connect_creds_linked_instance; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connect_credentials
    ADD CONSTRAINT fk_connect_creds_linked_instance FOREIGN KEY (linked_instance_id) REFERENCES public.connect_instances(id) ON DELETE SET NULL;


--
-- Name: enrichment_cache fk_enrichment_cache_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_cache
    ADD CONSTRAINT fk_enrichment_cache_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: enrichment_jobs fk_enrichment_jobs_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.enrichment_jobs
    ADD CONSTRAINT fk_enrichment_jobs_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: integrations fk_integrations_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integrations
    ADD CONSTRAINT fk_integrations_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: investigation_notes fk_investigation_notes_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_notes
    ADD CONSTRAINT fk_investigation_notes_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: investigations fk_investigations_alert; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigations
    ADD CONSTRAINT fk_investigations_alert FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- Name: knowledge_base fk_knowledge_base_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.knowledge_base
    ADD CONSTRAINT fk_knowledge_base_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: soar_executions fk_soar_executions_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soar_executions
    ADD CONSTRAINT fk_soar_executions_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: soar_playbooks fk_soar_playbooks_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.soar_playbooks
    ADD CONSTRAINT fk_soar_playbooks_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: teams fk_teams_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.teams
    ADD CONSTRAINT fk_teams_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: trusted_senders fk_trusted_senders_tenant; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trusted_senders
    ADD CONSTRAINT fk_trusted_senders_tenant FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: group_source_assignments group_source_assignments_group_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_source_assignments
    ADD CONSTRAINT group_source_assignments_group_id_fkey FOREIGN KEY (group_id) REFERENCES public.collector_groups(id) ON DELETE CASCADE;


--
-- Name: group_source_assignments group_source_assignments_source_type_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_source_assignments
    ADD CONSTRAINT group_source_assignments_source_type_id_fkey FOREIGN KEY (source_type_id) REFERENCES public.log_source_types(id) ON DELETE CASCADE;


--
-- Name: group_source_assignments group_source_assignments_target_index_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.group_source_assignments
    ADD CONSTRAINT group_source_assignments_target_index_id_fkey FOREIGN KEY (target_index_id) REFERENCES public.log_indexes(id) ON DELETE SET NULL;


--
-- Name: human_overrides human_overrides_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.human_overrides
    ADD CONSTRAINT human_overrides_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agent_definitions(id) ON DELETE SET NULL;


--
-- Name: human_overrides human_overrides_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.human_overrides
    ADD CONSTRAINT human_overrides_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: human_overrides human_overrides_verdict_outcome_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.human_overrides
    ADD CONSTRAINT human_overrides_verdict_outcome_id_fkey FOREIGN KEY (verdict_outcome_id) REFERENCES public.agent_verdict_outcomes(id) ON DELETE SET NULL;


--
-- Name: inbound_email_queue inbound_email_queue_mailbox_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_email_queue
    ADD CONSTRAINT inbound_email_queue_mailbox_id_fkey FOREIGN KEY (mailbox_id) REFERENCES public.inbound_mailboxes(id) ON DELETE CASCADE;


--
-- Name: intake_form_attachments intake_form_attachments_form_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_form_attachments
    ADD CONSTRAINT intake_form_attachments_form_id_fkey FOREIGN KEY (form_id) REFERENCES public.intake_forms(id) ON DELETE CASCADE;


--
-- Name: intake_form_attachments intake_form_attachments_submission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_form_attachments
    ADD CONSTRAINT intake_form_attachments_submission_id_fkey FOREIGN KEY (submission_id) REFERENCES public.intake_form_submissions(id) ON DELETE CASCADE;


--
-- Name: intake_form_attachments intake_form_attachments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_form_attachments
    ADD CONSTRAINT intake_form_attachments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: intake_form_attachments intake_form_attachments_uploaded_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_form_attachments
    ADD CONSTRAINT intake_form_attachments_uploaded_by_fkey FOREIGN KEY (uploaded_by) REFERENCES public.users(id);


--
-- Name: intake_form_submissions intake_form_submissions_form_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_form_submissions
    ADD CONSTRAINT intake_form_submissions_form_id_fkey FOREIGN KEY (form_id) REFERENCES public.intake_forms(id) ON DELETE CASCADE;


--
-- Name: intake_form_submissions intake_form_submissions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_form_submissions
    ADD CONSTRAINT intake_form_submissions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: intake_forms intake_forms_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.intake_forms
    ADD CONSTRAINT intake_forms_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: integration_credentials integration_credentials_integration_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.integration_credentials
    ADD CONSTRAINT integration_credentials_integration_id_fkey FOREIGN KEY (integration_id) REFERENCES public.integrations(id) ON DELETE CASCADE;


--
-- Name: investigation_agent_paths investigation_agent_paths_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_agent_paths
    ADD CONSTRAINT investigation_agent_paths_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: investigation_audit_log investigation_audit_log_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_audit_log
    ADD CONSTRAINT investigation_audit_log_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(investigation_id) ON DELETE CASCADE;


--
-- Name: investigation_chat investigation_chat_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_chat
    ADD CONSTRAINT investigation_chat_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: investigation_chat investigation_chat_parent_message_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_chat
    ADD CONSTRAINT investigation_chat_parent_message_id_fkey FOREIGN KEY (parent_message_id) REFERENCES public.investigation_chat(id) ON DELETE SET NULL;


--
-- Name: investigation_entities investigation_entities_entity_type_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_entities
    ADD CONSTRAINT investigation_entities_entity_type_fkey FOREIGN KEY (entity_type) REFERENCES public.entity_types(type_code);


--
-- Name: investigation_entities investigation_entities_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_entities
    ADD CONSTRAINT investigation_entities_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: investigation_entities investigation_entities_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_entities
    ADD CONSTRAINT investigation_entities_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: investigation_iocs investigation_iocs_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_iocs
    ADD CONSTRAINT investigation_iocs_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: investigation_iocs investigation_iocs_ioc_enrichment_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_iocs
    ADD CONSTRAINT investigation_iocs_ioc_enrichment_id_fkey FOREIGN KEY (ioc_enrichment_id) REFERENCES public.ioc_enrichments(id) ON DELETE CASCADE;


--
-- Name: investigation_notes investigation_notes_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_notes
    ADD CONSTRAINT investigation_notes_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(investigation_id) ON DELETE CASCADE;


--
-- Name: investigation_ownership_log investigation_ownership_log_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigation_ownership_log
    ADD CONSTRAINT investigation_ownership_log_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: investigations investigations_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.investigations
    ADD CONSTRAINT investigations_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: iocs iocs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.iocs
    ADD CONSTRAINT iocs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: knowledge_base_versions knowledge_base_versions_kb_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.knowledge_base_versions
    ADD CONSTRAINT knowledge_base_versions_kb_id_fkey FOREIGN KEY (kb_id) REFERENCES public.knowledge_base(kb_id) ON DELETE CASCADE;


--
-- Name: log_search_audit log_search_audit_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.log_search_audit
    ADD CONSTRAINT log_search_audit_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: ml_predictions ml_predictions_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ml_predictions
    ADD CONSTRAINT ml_predictions_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE CASCADE;


--
-- Name: phishing_reports phishing_reports_inbound_email_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.phishing_reports
    ADD CONSTRAINT phishing_reports_inbound_email_id_fkey FOREIGN KEY (inbound_email_id) REFERENCES public.inbound_email_queue(id) ON DELETE SET NULL;


--
-- Name: phishing_test_list phishing_test_list_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.phishing_test_list
    ADD CONSTRAINT phishing_test_list_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: phishing_tests phishing_tests_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.phishing_tests
    ADD CONSTRAINT phishing_tests_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: platform_audit_log platform_audit_log_admin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_audit_log
    ADD CONSTRAINT platform_audit_log_admin_id_fkey FOREIGN KEY (admin_id) REFERENCES public.platform_admins(id);


--
-- Name: playbook_execution_approvals playbook_execution_approvals_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_execution_approvals
    ADD CONSTRAINT playbook_execution_approvals_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.playbooks(id) ON DELETE CASCADE;


--
-- Name: playbook_executions playbook_executions_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.playbooks(id) ON DELETE CASCADE;


--
-- Name: playbook_executions playbook_executions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_executions
    ADD CONSTRAINT playbook_executions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: playbook_files playbook_files_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_files
    ADD CONSTRAINT playbook_files_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.playbook_executions(id) ON DELETE SET NULL;


--
-- Name: playbook_files playbook_files_form_submission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_files
    ADD CONSTRAINT playbook_files_form_submission_id_fkey FOREIGN KEY (form_submission_id) REFERENCES public.playbook_form_submissions(id) ON DELETE SET NULL;


--
-- Name: playbook_form_submissions playbook_form_submissions_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_form_submissions
    ADD CONSTRAINT playbook_form_submissions_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.playbook_executions(id) ON DELETE SET NULL;


--
-- Name: playbook_form_submissions playbook_form_submissions_form_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_form_submissions
    ADD CONSTRAINT playbook_form_submissions_form_id_fkey FOREIGN KEY (form_id) REFERENCES public.playbook_forms(id) ON DELETE CASCADE;


--
-- Name: playbook_forms playbook_forms_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_forms
    ADD CONSTRAINT playbook_forms_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: playbook_node_approvals playbook_node_approvals_execution_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_node_approvals
    ADD CONSTRAINT playbook_node_approvals_execution_id_fkey FOREIGN KEY (execution_id) REFERENCES public.playbook_executions(id) ON DELETE CASCADE;


--
-- Name: playbook_templates playbook_templates_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_templates
    ADD CONSTRAINT playbook_templates_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: playbook_versions playbook_versions_playbook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbook_versions
    ADD CONSTRAINT playbook_versions_playbook_id_fkey FOREIGN KEY (playbook_id) REFERENCES public.playbooks(id) ON DELETE CASCADE;


--
-- Name: playbooks playbooks_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.playbooks
    ADD CONSTRAINT playbooks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: poc_tracking poc_tracking_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.poc_tracking
    ADD CONSTRAINT poc_tracking_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE SET NULL;


--
-- Name: recommended_actions recommended_actions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.recommended_actions
    ADD CONSTRAINT recommended_actions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: referrals referrals_referred_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT referrals_referred_tenant_id_fkey FOREIGN KEY (referred_tenant_id) REFERENCES public.tenants(id);


--
-- Name: referrals referrals_referrer_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.referrals
    ADD CONSTRAINT referrals_referrer_tenant_id_fkey FOREIGN KEY (referrer_tenant_id) REFERENCES public.tenants(id);


--
-- Name: registration_requests registration_requests_provisioned_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.registration_requests
    ADD CONSTRAINT registration_requests_provisioned_tenant_id_fkey FOREIGN KEY (provisioned_tenant_id) REFERENCES public.tenants(id);


--
-- Name: riggs_decisions riggs_decisions_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.riggs_decisions
    ADD CONSTRAINT riggs_decisions_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: role_index_permissions role_index_permissions_index_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.role_index_permissions
    ADD CONSTRAINT role_index_permissions_index_id_fkey FOREIGN KEY (index_id) REFERENCES public.log_indexes(id) ON DELETE CASCADE;


--
-- Name: sop_effectiveness_tracking sop_effectiveness_tracking_kb_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sop_effectiveness_tracking
    ADD CONSTRAINT sop_effectiveness_tracking_kb_id_fkey FOREIGN KEY (kb_id) REFERENCES public.knowledge_base(kb_id) ON DELETE CASCADE;


--
-- Name: stripe_checkout_sessions stripe_checkout_sessions_registration_request_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_checkout_sessions
    ADD CONSTRAINT stripe_checkout_sessions_registration_request_id_fkey FOREIGN KEY (registration_request_id) REFERENCES public.registration_requests(id);


--
-- Name: stripe_checkout_sessions stripe_checkout_sessions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.stripe_checkout_sessions
    ADD CONSTRAINT stripe_checkout_sessions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: tenant_audit_log tenant_audit_log_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_audit_log
    ADD CONSTRAINT tenant_audit_log_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: tenant_claude_usage tenant_claude_usage_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_claude_usage
    ADD CONSTRAINT tenant_claude_usage_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id);


--
-- Name: tenant_licenses tenant_licenses_issued_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_licenses
    ADD CONSTRAINT tenant_licenses_issued_by_fkey FOREIGN KEY (issued_by) REFERENCES public.platform_admins(id);


--
-- Name: tenant_licenses tenant_licenses_revoked_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_licenses
    ADD CONSTRAINT tenant_licenses_revoked_by_fkey FOREIGN KEY (revoked_by) REFERENCES public.platform_admins(id);


--
-- Name: tenant_licenses tenant_licenses_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_licenses
    ADD CONSTRAINT tenant_licenses_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenant_usage_snapshots tenant_usage_snapshots_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_usage_snapshots
    ADD CONSTRAINT tenant_usage_snapshots_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: tenants tenants_active_license_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_active_license_id_fkey FOREIGN KEY (active_license_id) REFERENCES public.tenant_licenses(id);


--
-- Name: threat_feeds threat_feeds_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.threat_feeds
    ADD CONSTRAINT threat_feeds_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: usage_counters usage_counters_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_counters
    ADD CONSTRAINT usage_counters_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: usage_events usage_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.usage_events
    ADD CONSTRAINT usage_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: user_index_permissions user_index_permissions_index_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_index_permissions
    ADD CONSTRAINT user_index_permissions_index_id_fkey FOREIGN KEY (index_id) REFERENCES public.log_indexes(id) ON DELETE CASCADE;


--
-- Name: user_index_permissions user_index_permissions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_index_permissions
    ADD CONSTRAINT user_index_permissions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_preferences user_preferences_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_preferences
    ADD CONSTRAINT user_preferences_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: user_sessions user_sessions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: user_sessions user_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_sessions
    ADD CONSTRAINT user_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: users users_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: verdict_audit_log verdict_audit_log_alert_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verdict_audit_log
    ADD CONSTRAINT verdict_audit_log_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.alerts(id) ON DELETE SET NULL;


--
-- Name: verdict_audit_log verdict_audit_log_investigation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.verdict_audit_log
    ADD CONSTRAINT verdict_audit_log_investigation_id_fkey FOREIGN KEY (investigation_id) REFERENCES public.investigations(id) ON DELETE CASCADE;


--
-- Name: webhooks webhooks_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;


--
-- Name: action_requests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.action_requests ENABLE ROW LEVEL SECURITY;

--
-- Name: affiliate_codes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.affiliate_codes ENABLE ROW LEVEL SECURITY;

--
-- Name: agent_action_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.agent_action_log ENABLE ROW LEVEL SECURITY;

--
-- Name: agent_approval_requests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.agent_approval_requests ENABLE ROW LEVEL SECURITY;

--
-- Name: agent_definitions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.agent_definitions ENABLE ROW LEVEL SECURITY;

--
-- Name: agent_executions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.agent_executions ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_action_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ai_action_log ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_agents; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ai_agents ENABLE ROW LEVEL SECURITY;

--
-- Name: ai_token_usage; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ai_token_usage ENABLE ROW LEVEL SECURITY;

--
-- Name: alert_attachments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.alert_attachments ENABLE ROW LEVEL SECURITY;

--
-- Name: alert_groups; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.alert_groups ENABLE ROW LEVEL SECURITY;

--
-- Name: alert_ioc_links; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.alert_ioc_links ENABLE ROW LEVEL SECURITY;

--
-- Name: alerts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;

--
-- Name: api_keys; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

--
-- Name: approval_requests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.approval_requests ENABLE ROW LEVEL SECURITY;

--
-- Name: approval_tokens; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.approval_tokens ENABLE ROW LEVEL SECURITY;

--
-- Name: asset_conflicts; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.asset_conflicts ENABLE ROW LEVEL SECURITY;

--
-- Name: asset_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.asset_history ENABLE ROW LEVEL SECURITY;

--
-- Name: asset_identifiers; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.asset_identifiers ENABLE ROW LEVEL SECURITY;

--
-- Name: asset_relationships; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.asset_relationships ENABLE ROW LEVEL SECURITY;

--
-- Name: assets; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.assets ENABLE ROW LEVEL SECURITY;

--
-- Name: audit_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_templates builtin_templates_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY builtin_templates_read ON public.playbook_templates FOR SELECT USING (((tenant_id IS NULL) AND (current_setting('app.current_tenant_id'::text, true) IS NOT NULL) AND (current_setting('app.current_tenant_id'::text, true) <> ''::text)));


--
-- Name: campaign_iocs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.campaign_iocs ENABLE ROW LEVEL SECURITY;

--
-- Name: campaign_members; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.campaign_members ENABLE ROW LEVEL SECURITY;

--
-- Name: campaigns; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.campaigns ENABLE ROW LEVEL SECURITY;

--
-- Name: case_summaries; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.case_summaries ENABLE ROW LEVEL SECURITY;

--
-- Name: chat_action_audit; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.chat_action_audit ENABLE ROW LEVEL SECURITY;

--
-- Name: chat_usage_analytics; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.chat_usage_analytics ENABLE ROW LEVEL SECURITY;

--
-- Name: connect_credentials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.connect_credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: connect_execution_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.connect_execution_log ENABLE ROW LEVEL SECURITY;

--
-- Name: connect_instances; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.connect_instances ENABLE ROW LEVEL SECURITY;

--
-- Name: connector_definitions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.connector_definitions ENABLE ROW LEVEL SECURITY;

--
-- Name: connector_definitions connector_modify; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY connector_modify ON public.connector_definitions FOR UPDATE USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: connector_definitions connector_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY connector_read ON public.connector_definitions FOR SELECT USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (tenant_id IS NULL) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: connector_definitions connector_remove; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY connector_remove ON public.connector_definitions FOR DELETE USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: connector_submissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.connector_submissions ENABLE ROW LEVEL SECURITY;

--
-- Name: connector_definitions connector_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY connector_write ON public.connector_definitions FOR INSERT WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: correlation_decisions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.correlation_decisions ENABLE ROW LEVEL SECURITY;

--
-- Name: correlation_settings; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.correlation_settings ENABLE ROW LEVEL SECURITY;

--
-- Name: correlation_settings correlation_settings_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY correlation_settings_tenant_isolation ON public.correlation_settings USING (((tenant_id)::text = current_setting('app.current_tenant_id'::text, true)));


--
-- Name: credentials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: credentials_vault; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.credentials_vault ENABLE ROW LEVEL SECURITY;

--
-- Name: dedupe_config; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.dedupe_config ENABLE ROW LEVEL SECURITY;

--
-- Name: dedupe_config dedupe_config_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY dedupe_config_isolation ON public.dedupe_config USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: dedupe_config dedupe_config_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY dedupe_config_platform_admin_bypass ON public.dedupe_config USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: detection_hits; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.detection_hits ENABLE ROW LEVEL SECURITY;

--
-- Name: edl_credentials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.edl_credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: edl_lists; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.edl_lists ENABLE ROW LEVEL SECURITY;

--
-- Name: enrichment_cache; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.enrichment_cache ENABLE ROW LEVEL SECURITY;

--
-- Name: enrichment_jobs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.enrichment_jobs ENABLE ROW LEVEL SECURITY;

--
-- Name: entity_risk; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.entity_risk ENABLE ROW LEVEL SECURITY;

--
-- Name: entity_risk entity_risk_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY entity_risk_tenant_isolation ON public.entity_risk USING (((tenant_id)::text = current_setting('app.current_tenant_id'::text, true)));


--
-- Name: escalation_config; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.escalation_config ENABLE ROW LEVEL SECURITY;

--
-- Name: escalation_history; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.escalation_history ENABLE ROW LEVEL SECURITY;

--
-- Name: exclusion_list; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.exclusion_list ENABLE ROW LEVEL SECURITY;

--
-- Name: form_submissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.form_submissions ENABLE ROW LEVEL SECURITY;

--
-- Name: form_submissions form_submissions_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY form_submissions_platform_admin_bypass ON public.form_submissions USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: inbound_email_queue; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.inbound_email_queue ENABLE ROW LEVEL SECURITY;

--
-- Name: inbound_mailboxes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.inbound_mailboxes ENABLE ROW LEVEL SECURITY;

--
-- Name: intake_form_attachments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.intake_form_attachments ENABLE ROW LEVEL SECURITY;

--
-- Name: intake_form_attachments intake_form_attachments_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY intake_form_attachments_platform_admin_bypass ON public.intake_form_attachments USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: intake_form_attachments intake_form_attachments_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY intake_form_attachments_tenant_isolation ON public.intake_form_attachments USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: intake_form_submissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.intake_form_submissions ENABLE ROW LEVEL SECURITY;

--
-- Name: intake_form_submissions intake_form_submissions_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY intake_form_submissions_platform_admin_bypass ON public.intake_form_submissions USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: intake_form_submissions intake_form_submissions_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY intake_form_submissions_tenant_isolation ON public.intake_form_submissions USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: intake_forms; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.intake_forms ENABLE ROW LEVEL SECURITY;

--
-- Name: intake_forms intake_forms_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY intake_forms_platform_admin_bypass ON public.intake_forms USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: intake_forms intake_forms_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY intake_forms_tenant_isolation ON public.intake_forms USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: integration_credentials; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integration_credentials ENABLE ROW LEVEL SECURITY;

--
-- Name: integrations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.integrations ENABLE ROW LEVEL SECURITY;

--
-- Name: investigation_audit_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.investigation_audit_log ENABLE ROW LEVEL SECURITY;

--
-- Name: investigation_chat; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.investigation_chat ENABLE ROW LEVEL SECURITY;

--
-- Name: investigation_entities; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.investigation_entities ENABLE ROW LEVEL SECURITY;

--
-- Name: investigation_iocs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.investigation_iocs ENABLE ROW LEVEL SECURITY;

--
-- Name: investigation_notes; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.investigation_notes ENABLE ROW LEVEL SECURITY;

--
-- Name: investigation_ownership_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.investigation_ownership_log ENABLE ROW LEVEL SECURITY;

--
-- Name: investigations; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.investigations ENABLE ROW LEVEL SECURITY;

--
-- Name: ioc_blocklist; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ioc_blocklist ENABLE ROW LEVEL SECURITY;

--
-- Name: ioc_enrichments; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ioc_enrichments ENABLE ROW LEVEL SECURITY;

--
-- Name: ioc_feed_appearances; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ioc_feed_appearances ENABLE ROW LEVEL SECURITY;

--
-- Name: ioc_whitelist; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.ioc_whitelist ENABLE ROW LEVEL SECURITY;

--
-- Name: iocs; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.iocs ENABLE ROW LEVEL SECURITY;

--
-- Name: kb_community_submissions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.kb_community_submissions ENABLE ROW LEVEL SECURITY;

--
-- Name: knowledge_base; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.knowledge_base ENABLE ROW LEVEL SECURITY;

--
-- Name: notification_rules; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notification_rules ENABLE ROW LEVEL SECURITY;

--
-- Name: notifications; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.notifications ENABLE ROW LEVEL SECURITY;

--
-- Name: phishing_test_list; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.phishing_test_list ENABLE ROW LEVEL SECURITY;

--
-- Name: phishing_test_list phishing_test_list_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY phishing_test_list_isolation ON public.phishing_test_list USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: phishing_test_list phishing_test_list_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY phishing_test_list_platform_admin_bypass ON public.phishing_test_list USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: phishing_tests; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.phishing_tests ENABLE ROW LEVEL SECURITY;

--
-- Name: connector_definitions platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY platform_admin_bypass ON public.connector_definitions USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: knowledge_base platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY platform_admin_bypass ON public.knowledge_base USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: playbook_templates platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY platform_admin_bypass ON public.playbook_templates USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: playbook_execution_approvals; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbook_execution_approvals ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_executions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbook_executions ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_files; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbook_files ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_forms; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbook_forms ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_forms playbook_forms_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY playbook_forms_isolation ON public.playbook_forms USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: playbook_forms playbook_forms_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY playbook_forms_platform_admin_bypass ON public.playbook_forms USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: playbook_functions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbook_functions ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_lists; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbook_lists ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_node_approvals; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbook_node_approvals ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_templates; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbook_templates ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_versions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbook_versions ENABLE ROW LEVEL SECURITY;

--
-- Name: playbooks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.playbooks ENABLE ROW LEVEL SECURITY;

--
-- Name: poc_tracking; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.poc_tracking ENABLE ROW LEVEL SECURITY;

--
-- Name: recommended_actions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.recommended_actions ENABLE ROW LEVEL SECURITY;

--
-- Name: recommended_actions recommended_actions_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY recommended_actions_platform_admin_bypass ON public.recommended_actions USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: recommended_actions recommended_actions_tenant_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY recommended_actions_tenant_isolation ON public.recommended_actions USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: riggs_decisions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.riggs_decisions ENABLE ROW LEVEL SECURITY;

--
-- Name: riggs_feedback; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.riggs_feedback ENABLE ROW LEVEL SECURITY;

--
-- Name: riggs_playbook_executions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.riggs_playbook_executions ENABLE ROW LEVEL SECURITY;

--
-- Name: soar_executions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.soar_executions ENABLE ROW LEVEL SECURITY;

--
-- Name: soar_playbooks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.soar_playbooks ENABLE ROW LEVEL SECURITY;

--
-- Name: stripe_checkout_sessions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.stripe_checkout_sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: teams; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.teams ENABLE ROW LEVEL SECURITY;

--
-- Name: playbook_templates template_modify; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY template_modify ON public.playbook_templates FOR UPDATE USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_templates template_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY template_read ON public.playbook_templates FOR SELECT USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (tenant_id IS NULL) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_templates template_remove; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY template_remove ON public.playbook_templates FOR DELETE USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_templates template_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY template_write ON public.playbook_templates FOR INSERT WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: tenant_ai_config; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_ai_config ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant_ai_config tenant_ai_config_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_ai_config_isolation ON public.tenant_ai_config USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: tenant_ai_config tenant_ai_config_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_ai_config_platform_admin_bypass ON public.tenant_ai_config USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: tenant_audit_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_audit_log ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant_byo_usage; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_byo_usage ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant_byo_usage tenant_byo_usage_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_byo_usage_isolation ON public.tenant_byo_usage USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: tenant_byo_usage tenant_byo_usage_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_byo_usage_platform_admin_bypass ON public.tenant_byo_usage USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: tenant_claude_usage; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_claude_usage ENABLE ROW LEVEL SECURITY;

--
-- Name: action_requests tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.action_requests USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: affiliate_codes tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.affiliate_codes USING (((current_setting('app.is_platform_admin'::text, true) = 'true'::text) OR (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK (((current_setting('app.is_platform_admin'::text, true) = 'true'::text) OR (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: agent_action_log tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.agent_action_log USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: agent_approval_requests tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.agent_approval_requests USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: agent_definitions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.agent_definitions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: agent_executions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.agent_executions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: ai_action_log tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.ai_action_log USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: ai_agents tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.ai_agents USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: ai_token_usage tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.ai_token_usage USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: alert_attachments tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.alert_attachments USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: alert_groups tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.alert_groups USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: alert_ioc_links tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.alert_ioc_links USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: alerts tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.alerts USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: api_keys tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.api_keys USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: approval_requests tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.approval_requests USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: approval_tokens tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.approval_tokens USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: asset_conflicts tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.asset_conflicts USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: asset_history tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.asset_history USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: asset_identifiers tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.asset_identifiers USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: asset_relationships tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.asset_relationships USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: assets tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.assets USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: audit_log tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.audit_log USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: campaign_iocs tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.campaign_iocs USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: campaign_members tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.campaign_members USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: campaigns tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.campaigns USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: case_summaries tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.case_summaries USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: chat_action_audit tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.chat_action_audit USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: chat_usage_analytics tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.chat_usage_analytics USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: connect_credentials tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.connect_credentials USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: connect_execution_log tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.connect_execution_log USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: connect_instances tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.connect_instances USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: connector_submissions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.connector_submissions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: correlation_decisions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.correlation_decisions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: credentials tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.credentials USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: credentials_vault tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.credentials_vault USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: detection_hits tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.detection_hits USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: edl_credentials tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.edl_credentials USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: edl_lists tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.edl_lists USING ((((tenant_id)::text = NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text)) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK ((((tenant_id)::text = NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text)) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: enrichment_cache tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.enrichment_cache USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: enrichment_jobs tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.enrichment_jobs USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: escalation_config tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.escalation_config USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: escalation_history tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.escalation_history USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: exclusion_list tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.exclusion_list USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: inbound_email_queue tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.inbound_email_queue USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: inbound_mailboxes tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.inbound_mailboxes USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: integration_credentials tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.integration_credentials USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: integrations tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.integrations USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: investigation_audit_log tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.investigation_audit_log USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: investigation_chat tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.investigation_chat USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: investigation_entities tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.investigation_entities USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: investigation_iocs tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.investigation_iocs USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: investigation_notes tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.investigation_notes USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: investigation_ownership_log tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.investigation_ownership_log USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: investigations tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.investigations USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: ioc_blocklist tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.ioc_blocklist USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: ioc_enrichments tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.ioc_enrichments USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: ioc_feed_appearances tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.ioc_feed_appearances USING (((current_setting('app.is_platform_admin'::text, true) = 'true'::text) OR (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK (((current_setting('app.is_platform_admin'::text, true) = 'true'::text) OR (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: ioc_whitelist tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.ioc_whitelist USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: iocs tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.iocs USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: kb_community_submissions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.kb_community_submissions USING (((current_setting('app.is_platform_admin'::text, true) = 'true'::text) OR (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid))) WITH CHECK (((current_setting('app.is_platform_admin'::text, true) = 'true'::text) OR (tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid)));


--
-- Name: notification_rules tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.notification_rules USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: notifications tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.notifications USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: phishing_tests tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.phishing_tests USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_execution_approvals tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.playbook_execution_approvals USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_executions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.playbook_executions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_files tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.playbook_files USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_functions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.playbook_functions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_lists tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.playbook_lists USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_node_approvals tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.playbook_node_approvals USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbook_versions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.playbook_versions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: playbooks tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.playbooks USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: poc_tracking tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.poc_tracking USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: riggs_decisions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.riggs_decisions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: riggs_feedback tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.riggs_feedback USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: riggs_playbook_executions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.riggs_playbook_executions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: soar_executions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.soar_executions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: soar_playbooks tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.soar_playbooks USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: stripe_checkout_sessions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.stripe_checkout_sessions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: teams tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.teams USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: tenant_audit_log tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.tenant_audit_log USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: tenant_claude_usage tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.tenant_claude_usage USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: tenant_licenses tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.tenant_licenses USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: tenant_usage_snapshots tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.tenant_usage_snapshots USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: threat_feeds tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.threat_feeds USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: trusted_senders tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.trusted_senders USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: usage_counters tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.usage_counters USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: usage_events tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.usage_events USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: user_sessions tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.user_sessions USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: users tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.users USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: verdict_audit_log tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.verdict_audit_log USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: webhooks tenant_isolation_policy; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_isolation_policy ON public.webhooks USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: tenant_licenses; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_licenses ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant_llm_context; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_llm_context ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant_llm_context tenant_llm_context_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_llm_context_isolation ON public.tenant_llm_context USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: tenant_llm_context tenant_llm_context_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_llm_context_platform_admin_bypass ON public.tenant_llm_context USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: knowledge_base tenant_modify; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_modify ON public.knowledge_base FOR UPDATE USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text))) WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: tenant_pii_patterns; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_pii_patterns ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant_pii_patterns tenant_pii_patterns_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_pii_patterns_isolation ON public.tenant_pii_patterns USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: tenant_pii_patterns tenant_pii_patterns_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_pii_patterns_platform_admin_bypass ON public.tenant_pii_patterns USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: knowledge_base tenant_read; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_read ON public.knowledge_base FOR SELECT USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR ((source)::text = 'builtin'::text) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: knowledge_base tenant_remove; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_remove ON public.knowledge_base FOR DELETE USING (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: tenant_triage_config; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_triage_config ENABLE ROW LEVEL SECURITY;

--
-- Name: tenant_triage_config tenant_triage_config_isolation; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_triage_config_isolation ON public.tenant_triage_config USING ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid)) WITH CHECK ((tenant_id = (current_setting('app.current_tenant_id'::text, true))::uuid));


--
-- Name: tenant_triage_config tenant_triage_config_platform_admin_bypass; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_triage_config_platform_admin_bypass ON public.tenant_triage_config USING ((current_setting('app.is_platform_admin'::text, true) = 'true'::text)) WITH CHECK ((current_setting('app.is_platform_admin'::text, true) = 'true'::text));


--
-- Name: tenant_usage_snapshots; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.tenant_usage_snapshots ENABLE ROW LEVEL SECURITY;

--
-- Name: knowledge_base tenant_write; Type: POLICY; Schema: public; Owner: -
--

CREATE POLICY tenant_write ON public.knowledge_base FOR INSERT WITH CHECK (((tenant_id = (NULLIF(current_setting('app.current_tenant_id'::text, true), ''::text))::uuid) OR (current_setting('app.is_platform_admin'::text, true) = 'true'::text)));


--
-- Name: threat_feeds; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.threat_feeds ENABLE ROW LEVEL SECURITY;

--
-- Name: trusted_senders; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.trusted_senders ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_counters; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_counters ENABLE ROW LEVEL SECURITY;

--
-- Name: usage_events; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.usage_events ENABLE ROW LEVEL SECURITY;

--
-- Name: user_sessions; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.user_sessions ENABLE ROW LEVEL SECURITY;

--
-- Name: users; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;

--
-- Name: verdict_audit_log; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.verdict_audit_log ENABLE ROW LEVEL SECURITY;

--
-- Name: webhooks; Type: ROW SECURITY; Schema: public; Owner: -
--

ALTER TABLE public.webhooks ENABLE ROW LEVEL SECURITY;

--
-- PostgreSQL database dump complete
--

\unrestrict M559rbxaLV38Dss3md1uCcqTaRODIbtFP0GniFm0KSQeIwDTkNxB2zmW86xpJ3g

