# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
PostgreSQL Database Service
Production-ready async database service for T1 Agentics SOC platform
"""

import asyncpg
import json
import os
import logging
import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import List, Dict, Any, Optional
from datetime import datetime
from passlib.hash import bcrypt

logger = logging.getLogger(__name__)

# ContextVar for background tasks that need platform admin RLS bypass.
# When set to True, TenantAwarePool.acquire() will automatically set
# app.is_platform_admin = 'true' on the connection, allowing background
# services (scheduler, job queue, agent executor) to bypass tenant RLS.
_platform_admin_mode: ContextVar[bool] = ContextVar('_platform_admin_mode', default=False)


def set_platform_admin_mode(enabled: bool = True):
    """Enable/disable platform admin mode for the current async context."""
    _platform_admin_mode.set(enabled)


def is_platform_admin_mode() -> bool:
    """Check if platform admin mode is active in current context."""
    return _platform_admin_mode.get()


class TenantAwarePool:
    """
    Wraps an asyncpg pool so that every acquire() automatically sets
    the PostgreSQL session variable ``app.current_tenant_id`` when a
    tenant context exists (via the ContextVar set by TenantMiddleware).

    If no tenant context is present (e.g. during startup, background
    jobs, or unauthenticated endpoints), the connection is returned
    without modification — RLS will fall back to the default policy.
    """

    def __init__(self, real_pool):
        self._pool = real_pool

    # -- proxy every attribute to the underlying pool --
    def __getattr__(self, name):
        return getattr(self._pool, name)

    @asynccontextmanager
    async def acquire(self, *, timeout=None):
        kw = {} if timeout is None else {"timeout": timeout}
        async with self._pool.acquire(**kw) as conn:
            # Health check: verify connection is alive before use
            try:
                await conn.fetchval('SELECT 1')
            except Exception:
                logger.warning("Connection health check failed, connection may be stale")
                raise

            context_set = False
            admin_set = False
            try:
                from middleware.tenant_middleware import get_optional_tenant_id
                tenant_id = get_optional_tenant_id()
                if tenant_id:
                    await conn.execute(
                        "SELECT set_config('app.current_tenant_id', $1, false)",
                        str(tenant_id),
                    )
                    context_set = True
                    logger.debug(f"RLS: SET tenant_id={tenant_id}")
                else:
                    # No tenant context (tenant-exempt route, startup task, etc.).
                    # Default current_tenant_id to the nil UUID so RLS policies
                    # that cast current_setting('app.current_tenant_id')::uuid
                    # don't crash on the empty-string default. Tenant-scoped
                    # queries match zero rows (safe); routes that need
                    # cross-tenant access set app.is_platform_admin afterwards.
                    await conn.execute(
                        "SELECT set_config('app.current_tenant_id', "
                        "'00000000-0000-0000-0000-000000000000', false)"
                    )
                    context_set = True

                # Background services (scheduler, job queue, agent executor)
                # set _platform_admin_mode ContextVar to bypass tenant RLS.
                if _platform_admin_mode.get(False):
                    await conn.execute("SET app.is_platform_admin = 'true'")
                    admin_set = True
            except Exception as e:
                logger.warning(f"RLS: Failed to set tenant context: {e}")
                # CRITICAL: If admin mode was set but context failed after,
                # ensure we clean up before yielding the connection.
                if admin_set:
                    try:
                        await conn.execute("RESET app.is_platform_admin")
                        admin_set = False
                    except Exception:
                        logger.error("RLS: Failed to reset admin mode after context error -- connection unsafe")
                        raise
            try:
                yield conn
            finally:
                try:
                    if context_set:
                        await conn.execute("RESET app.current_tenant_id")
                    if admin_set:
                        await conn.execute("RESET app.is_platform_admin")
                except Exception as e:
                    logger.error(f"RLS: Failed to reset connection context: {e} -- connection may leak admin privileges")


class PostgresDB:
    """PostgreSQL database service with connection pooling"""

    def __init__(self):
        self.pool = None
        self.connected = False

    async def connect(self):
        """Create connection pool and bootstrap"""
        try:
            logger.info("Attempting to connect to PostgreSQL...")
            logger.info(f"PostgreSQL connection parameters - Host: {os.getenv('POSTGRES_HOST', 'localhost')}, "
                       f"Port: {os.getenv('POSTGRES_PORT', 5432)}, "
                       f"Database: {os.getenv('POSTGRES_DB', 'agentcore')}, "
                       f"User: {os.getenv('POSTGRES_USER', 'agentcore')}")

            raw_pool = await asyncpg.create_pool(
                host=os.getenv('POSTGRES_HOST', 'localhost'),
                port=int(os.getenv('POSTGRES_PORT', 5432)),
                user=os.getenv('POSTGRES_USER', 'agentcore'),
                password=os.getenv('POSTGRES_PASSWORD', 'agentcore_dev_password'),
                database=os.getenv('POSTGRES_DB', 'agentcore'),
                min_size=int(os.getenv('DB_POOL_MIN_SIZE', '5')),
                max_size=int(os.getenv('DB_POOL_MAX_SIZE', '20')),
                command_timeout=int(os.getenv('DB_COMMAND_TIMEOUT', '60'))
            )
            self.pool = TenantAwarePool(raw_pool)

            # Test connection
            logger.info("Testing PostgreSQL connection...")
            async with self.pool.acquire() as conn:
                result = await conn.fetchval('SELECT 1')
                logger.info(f"Connection test successful (result={result})")

            self.connected = True
            logger.info("Connected to PostgreSQL successfully")

            # Run migrations for new columns/tables
            logger.info("Running schema migrations...")
            await self.run_migrations()

            # Bootstrap default users
            logger.info("Bootstrapping default users...")
            await self.bootstrap_users()
            logger.info("User bootstrap complete")
            
        except Exception as e:
            logger.error(f"PostgreSQL connection failed: {type(e).__name__}: {e}")
            logger.exception("Full traceback:")
            self.connected = False
            raise
    
    async def disconnect(self):
        """Close connection pool"""
        if self.pool:
            await self.pool.close()
            self.connected = False
            logger.info("Disconnected from PostgreSQL")

    @asynccontextmanager
    async def tenant_acquire(self):
        """
        Acquire a connection with automatic tenant context for RLS.

        Reads the current tenant_id from the request ContextVar (set by
        TenantMiddleware) and executes SET app.current_tenant_id so
        PostgreSQL Row-Level Security policies filter correctly.

        Usage:
            async with postgres_db.tenant_acquire() as conn:
                rows = await conn.fetch("SELECT * FROM alerts")
        """
        from middleware.tenant_middleware import get_optional_tenant_id
        tenant_id = get_optional_tenant_id()

        async with self.pool.acquire() as conn:
            if tenant_id:
                await conn.execute(
                    "SELECT set_config('app.current_tenant_id', $1, false)",
                    str(tenant_id)
                )
            else:
                logger.debug("tenant_acquire() called without tenant context — RLS will filter to 0 rows")
            try:
                yield conn
            finally:
                if tenant_id:
                    try:
                        await conn.execute("RESET app.current_tenant_id")
                    except Exception:
                        pass

    async def execute_query(self, query: str, *args) -> List[Dict[str, Any]]:
        """Execute a query and return results as list of dicts"""
        if not self.pool:
            return []
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *args)
            return [dict(row) for row in rows]

    async def execute_one(self, query: str, *args) -> Optional[Dict[str, Any]]:
        """Execute a query and return single row as dict"""
        if not self.pool:
            return None
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(query, *args)
            return dict(row) if row else None

    async def execute(self, query: str, *args) -> str:
        """Execute a query without returning results (INSERT, UPDATE, DELETE)"""
        if not self.pool:
            return "ERROR"
        async with self.pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def fetch(self, query: str, *args):
        """Execute a query and return all rows"""
        if not self.pool:
            return []
        async with self.pool.acquire() as conn:
            return await conn.fetch(query, *args)

    async def fetchrow(self, query: str, *args):
        """Execute a query and return a single row"""
        if not self.pool:
            return None
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def fetchval(self, query: str, *args):
        """Execute a query and return a single value"""
        if not self.pool:
            return None
        async with self.pool.acquire() as conn:
            return await conn.fetchval(query, *args)

    async def run_migrations(self):
        """Run schema migrations for new columns/tables"""
        async with self.pool.acquire() as conn:
            # Create migration tracking table
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        id SERIAL PRIMARY KEY,
                        migration_name VARCHAR(255) UNIQUE NOT NULL,
                        applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
            except Exception as e:
                logger.warning(f"schema_migrations table creation: {e}")

            # Add force_password_reset column if missing
            try:
                await conn.execute('''
                    ALTER TABLE users
                    ADD COLUMN IF NOT EXISTS force_password_reset BOOLEAN DEFAULT FALSE
                ''')
                logger.debug("users.force_password_reset column ensured")
            except Exception as e:
                logger.debug(f"force_password_reset migration: {e}")

            # Add account lockout columns if missing
            try:
                await conn.execute('''
                    ALTER TABLE users
                    ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0
                ''')
                await conn.execute('''
                    ALTER TABLE users
                    ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE
                ''')
                await conn.execute('''
                    ALTER TABLE users
                    ADD COLUMN IF NOT EXISTS last_failed_login TIMESTAMP WITH TIME ZONE
                ''')
                logger.debug("users.lockout columns ensured")
            except Exception as e:
                logger.debug(f"lockout columns migration: {e}")
            
            # Create api_keys table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS api_keys (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        key_id VARCHAR(100) UNIQUE NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        key_hash VARCHAR(255) NOT NULL,
                        role VARCHAR(20) NOT NULL DEFAULT 'user',
                        created_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP WITH TIME ZONE,
                        last_used TIMESTAMP WITH TIME ZONE,
                        enabled BOOLEAN DEFAULT TRUE
                    )
                ''')
                logger.debug("api_keys table ensured")
            except Exception as e:
                logger.debug(f"api_keys table migration: {e}")
            
            # Create integration_credentials table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS integration_credentials (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        credential_id VARCHAR(100) UNIQUE NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        credential_type VARCHAR(50) NOT NULL,
                        encrypted_value TEXT,
                        integration_id VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug("integration_credentials table ensured")
            except Exception as e:
                logger.debug(f"integration_credentials table migration: {e}")
            
            # Create webhooks table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS webhooks (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(100) UNIQUE NOT NULL,
                        description TEXT,
                        endpoint_path VARCHAR(255) NOT NULL,
                        enabled BOOLEAN DEFAULT TRUE,
                        created_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        last_triggered TIMESTAMP WITH TIME ZONE,
                        trigger_count INTEGER DEFAULT 0
                    )
                ''')
                logger.debug(" webhooks table ensured")
            except Exception as e:
                logger.debug(f" webhooks table migration: {e}")
            
            # Create credentials table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS credentials (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(255) UNIQUE NOT NULL,
                        description TEXT,
                        auth_type VARCHAR(50) NOT NULL DEFAULT 'api_key',
                        encrypted_value TEXT NOT NULL,
                        integration_name VARCHAR(100),
                        created_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" credentials table ensured")
            except Exception as e:
                logger.debug(f" credentials table migration: {e}")

            # Create integration_state table for persisting enabled/credential state
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS integration_state (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        integration_id VARCHAR(100) UNIQUE NOT NULL,
                        enabled BOOLEAN DEFAULT FALSE,
                        credential_id VARCHAR(100),
                        base_url VARCHAR(500),
                        config JSONB DEFAULT '{}',
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" integration_state table ensured")
            except Exception as e:
                logger.debug(f" integration_state table migration: {e}")

            # Add AI verdict columns to alerts table
            try:
                await conn.execute('''
                    ALTER TABLE alerts
                    ADD COLUMN IF NOT EXISTS ai_verdict VARCHAR(50),
                    ADD COLUMN IF NOT EXISTS ai_confidence DECIMAL(5,2),
                    ADD COLUMN IF NOT EXISTS ai_summary TEXT,
                    ADD COLUMN IF NOT EXISTS closed_by VARCHAR(255),
                    ADD COLUMN IF NOT EXISTS closed_at TIMESTAMP WITH TIME ZONE
                ''')
                logger.debug(" alerts.ai_verdict columns ensured")
            except Exception as e:
                logger.debug(f" alerts AI columns migration: {e}")

            # Add AI triage queue columns to alerts table (for scheduler)
            try:
                await conn.execute('''
                    ALTER TABLE alerts
                    ADD COLUMN IF NOT EXISTS ai_triage_queued BOOLEAN DEFAULT FALSE,
                    ADD COLUMN IF NOT EXISTS ai_triage_queued_at TIMESTAMP WITH TIME ZONE
                ''')
                logger.debug(" alerts.ai_triage_queued columns ensured")
            except Exception as e:
                logger.debug(f" alerts ai_triage columns migration: {e}")

            # Update enrichment_cache ioc_type constraint to include hash variants
            try:
                await conn.execute('''
                    ALTER TABLE enrichment_cache DROP CONSTRAINT IF EXISTS enrichment_cache_ioc_type_check;
                    ALTER TABLE enrichment_cache
                    ADD CONSTRAINT enrichment_cache_ioc_type_check
                    CHECK (ioc_type IN ('ip', 'domain', 'hash', 'hash_md5', 'hash_sha1', 'hash_sha256', 'url', 'email'));
                ''')
                logger.debug(" enrichment_cache.ioc_type constraint updated")
            except Exception as e:
                logger.debug(f" enrichment_cache ioc_type constraint migration: {e}")

            # Create alert_ioc_links table for correlation (Phase 2.5)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS alert_ioc_links (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        alert_id VARCHAR(255) NOT NULL,
                        ioc_value VARCHAR(500) NOT NULL,
                        ioc_type VARCHAR(50) NOT NULL,
                        extraction_method VARCHAR(50) DEFAULT 'regex',
                        extraction_source VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(alert_id, ioc_value, ioc_type)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_alert_ioc_links_alert ON alert_ioc_links(alert_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_alert_ioc_links_ioc ON alert_ioc_links(ioc_value, ioc_type)')
                logger.debug(" alert_ioc_links table ensured")
            except Exception as e:
                logger.debug(f" alert_ioc_links migration: {e}")

            # Create correlation_rules table (Phase 2.5)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS correlation_rules (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        rule_id VARCHAR(100) UNIQUE NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        rule_type VARCHAR(50) NOT NULL,
                        parameters JSONB DEFAULT '{}'::jsonb,
                        enabled BOOLEAN DEFAULT true,
                        priority INTEGER DEFAULT 100,
                        auto_create_campaign BOOLEAN DEFAULT false,
                        trigger_count INTEGER DEFAULT 0,
                        last_triggered_at TIMESTAMP WITH TIME ZONE,
                        created_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                # Insert default rules
                await conn.execute('''
                    INSERT INTO correlation_rules (rule_id, name, description, rule_type, parameters, enabled, priority, auto_create_campaign)
                    VALUES
                        ('rule-ioc-repeat-3', 'Repeated IOC (3+ alerts)', 'Triggers when the same IOC appears in 3 or more alerts within 24 hours', 'ioc_match',
                         '{"min_occurrences": 3, "ioc_types": ["ip", "domain", "hash_sha256"], "time_window_hours": 24}'::jsonb, true, 100, true)
                    ON CONFLICT (rule_id) DO NOTHING
                ''')
                logger.debug(" correlation_rules table ensured")
            except Exception as e:
                logger.debug(f" correlation_rules migration: {e}")

            # Create campaigns table (Phase 2.5)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS campaigns (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        campaign_id VARCHAR(100) UNIQUE NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        campaign_type VARCHAR(50) DEFAULT 'unknown',
                        severity VARCHAR(20) DEFAULT 'medium',
                        confidence DECIMAL(5,2) DEFAULT 70.0,
                        status VARCHAR(20) DEFAULT 'active',
                        alert_count INTEGER DEFAULT 0,
                        ioc_count INTEGER DEFAULT 0,
                        mitre_techniques TEXT[],
                        created_by VARCHAR(100),
                        assigned_to VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" campaigns table ensured")
            except Exception as e:
                logger.debug(f" campaigns migration: {e}")

            # Add escalation columns to investigations table
            try:
                await conn.execute('''
                    ALTER TABLE investigations
                    ADD COLUMN IF NOT EXISTS escalated_to_tier INTEGER,
                    ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMP WITH TIME ZONE,
                    ADD COLUMN IF NOT EXISTS escalated_by VARCHAR(255),
                    ADD COLUMN IF NOT EXISTS escalation_reason TEXT
                ''')
                logger.debug(" investigations.escalation columns ensured")
            except Exception as e:
                logger.debug(f" investigations escalation columns migration: {e}")

            # Create escalation_history table
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS escalation_history (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        investigation_id UUID REFERENCES investigations(id) ON DELETE CASCADE,
                        alert_id UUID REFERENCES alerts(id) ON DELETE CASCADE,
                        from_tier INTEGER NOT NULL,
                        to_tier INTEGER NOT NULL,
                        escalated_by VARCHAR(255),
                        reason TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" escalation_history table ensured")
            except Exception as e:
                logger.debug(f" escalation_history table migration: {e}")

            # Create ai_token_usage table for tracking AI API calls
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS ai_token_usage (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        request_id VARCHAR(100) NOT NULL,
                        provider VARCHAR(50) NOT NULL,
                        model VARCHAR(255) NOT NULL,
                        integration_id VARCHAR(100),
                        prompt_tokens INTEGER NOT NULL DEFAULT 0,
                        completion_tokens INTEGER NOT NULL DEFAULT 0,
                        total_tokens INTEGER NOT NULL DEFAULT 0,
                        estimated_cost_cents DECIMAL(10, 4) DEFAULT 0,
                        endpoint VARCHAR(500),
                        request_type VARCHAR(50),
                        investigation_id VARCHAR(100),
                        alert_id VARCHAR(100),
                        user_id VARCHAR(100),
                        agent_id VARCHAR(100),
                        status VARCHAR(20) NOT NULL DEFAULT 'success',
                        response_time_ms INTEGER,
                        error_message TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                # Create indexes
                await conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_token_usage_provider ON ai_token_usage(provider);
                    CREATE INDEX IF NOT EXISTS idx_token_usage_agent ON ai_token_usage(agent_id);
                    CREATE INDEX IF NOT EXISTS idx_token_usage_created ON ai_token_usage(created_at);
                ''')
                logger.debug(" ai_token_usage table ensured")
            except Exception as e:
                logger.debug(f" ai_token_usage table migration: {e}")

            # Add llm_metrics column to agent_executions
            try:
                await conn.execute('''
                    ALTER TABLE agent_executions
                    ADD COLUMN IF NOT EXISTS llm_metrics JSONB DEFAULT '{}'::jsonb
                ''')
                logger.debug(" agent_executions.llm_metrics column ensured")
            except Exception as e:
                logger.debug(f" agent_executions llm_metrics migration: {e}")

            # Create ai_providers table for AI provider configuration
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS ai_providers (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(255) NOT NULL,
                        provider_type VARCHAR(50) NOT NULL,
                        base_url VARCHAR(500) NOT NULL,
                        api_key TEXT,
                        models JSONB DEFAULT '[]'::jsonb,
                        selected_model VARCHAR(255),
                        tier1_model VARCHAR(255),
                        tier2_model VARCHAR(255),
                        tier3_model VARCHAR(255),
                        chat_model VARCHAR(255),
                        is_default BOOLEAN DEFAULT FALSE,
                        enabled BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" ai_providers table ensured")
            except Exception as e:
                logger.debug(f" ai_providers table migration: {e}")

            # Add tier model columns if ai_providers table already exists
            try:
                await conn.execute('''
                    ALTER TABLE ai_providers
                    ADD COLUMN IF NOT EXISTS selected_model VARCHAR(255),
                    ADD COLUMN IF NOT EXISTS tier1_model VARCHAR(255),
                    ADD COLUMN IF NOT EXISTS tier2_model VARCHAR(255),
                    ADD COLUMN IF NOT EXISTS tier3_model VARCHAR(255),
                    ADD COLUMN IF NOT EXISTS chat_model VARCHAR(255)
                ''')
                logger.debug(" ai_providers tier model columns ensured")
            except Exception as e:
                logger.debug(f" ai_providers tier model columns migration: {e}")

            # Create user_preferences table for persisting user settings
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS user_preferences (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                        username VARCHAR(100) NOT NULL,
                        preferences JSONB DEFAULT '{}'::jsonb,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(username)
                    )
                ''')
                logger.debug(" user_preferences table ensured")
            except Exception as e:
                logger.debug(f" user_preferences table migration: {e}")

            # Create email_config table for SMTP settings
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS email_config (
                        id VARCHAR(50) PRIMARY KEY,
                        smtp_host VARCHAR(255),
                        smtp_port INTEGER DEFAULT 587,
                        smtp_username VARCHAR(255),
                        smtp_password TEXT,
                        use_tls BOOLEAN DEFAULT TRUE,
                        use_ssl BOOLEAN DEFAULT FALSE,
                        from_email VARCHAR(255),
                        from_name VARCHAR(255) DEFAULT 'T1 Agentics SOC',
                        enabled BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" email_config table ensured")
            except Exception as e:
                logger.debug(f" email_config table migration: {e}")

            # Create notification_rules table for email notification rules
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS notification_rules (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        rule_id VARCHAR(100) UNIQUE NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        enabled BOOLEAN DEFAULT TRUE,
                        event_types TEXT[] DEFAULT '{}',
                        severity_filter TEXT[] DEFAULT '{}',
                        recipients TEXT[] DEFAULT '{}',
                        subject_template TEXT DEFAULT '[T1 Agentics] {event_type}: {title}',
                        body_template TEXT,
                        include_approval_links BOOLEAN DEFAULT FALSE,
                        approval_ttl_minutes INTEGER DEFAULT 60,
                        approval_require_auth BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" notification_rules table ensured")
            except Exception as e:
                logger.debug(f" notification_rules table migration: {e}")

            # Add approval columns to existing notification_rules table if needed
            try:
                await conn.execute('''
                    ALTER TABLE notification_rules
                    ADD COLUMN IF NOT EXISTS include_approval_links BOOLEAN DEFAULT FALSE,
                    ADD COLUMN IF NOT EXISTS approval_ttl_minutes INTEGER DEFAULT 60,
                    ADD COLUMN IF NOT EXISTS approval_require_auth BOOLEAN DEFAULT FALSE
                ''')
            except Exception as e:
                pass  # Columns may already exist

            # Create email_log table for tracking sent emails
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS email_log (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        rule_id VARCHAR(100),
                        event_type VARCHAR(100),
                        recipients TEXT[],
                        subject TEXT,
                        status VARCHAR(20) DEFAULT 'sent',
                        error_message TEXT,
                        sent_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_email_log_sent_at ON email_log(sent_at);
                ''')
                logger.debug(" email_log table ensured")
            except Exception as e:
                logger.debug(f" email_log table migration: {e}")

            # Create webhook_channels table for Slack, Teams, Webex etc.
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS webhook_channels (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        channel_id VARCHAR(100) UNIQUE NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        channel_type VARCHAR(50) NOT NULL,
                        webhook_url TEXT NOT NULL,
                        enabled BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" webhook_channels table ensured")
            except Exception as e:
                logger.debug(f" webhook_channels table migration: {e}")

            # Create approval_tokens table for approval workflow links
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS approval_tokens (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        token_id VARCHAR(100) UNIQUE NOT NULL,
                        token_secret VARCHAR(100) UNIQUE NOT NULL,
                        action_type VARCHAR(100) NOT NULL,
                        entity_type VARCHAR(50) NOT NULL,
                        entity_id VARCHAR(100) NOT NULL,
                        action VARCHAR(20) NOT NULL,
                        ttl_minutes INTEGER DEFAULT 60,
                        require_auth BOOLEAN DEFAULT FALSE,
                        used BOOLEAN DEFAULT FALSE,
                        used_at TIMESTAMP WITH TIME ZONE,
                        used_by VARCHAR(255),
                        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        created_by VARCHAR(255),
                        metadata JSONB DEFAULT '{}'
                    )
                ''')
                await conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_approval_tokens_secret ON approval_tokens(token_secret);
                ''')
                await conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_approval_tokens_entity ON approval_tokens(entity_type, entity_id);
                ''')
                await conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_approval_tokens_expires ON approval_tokens(expires_at);
                ''')
                logger.debug(" approval_tokens table ensured")
            except Exception as e:
                logger.debug(f" approval_tokens table migration: {e}")

            # Create knowledge_base table for Company Best Practices / SOPs
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS knowledge_base (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        kb_id VARCHAR(100) UNIQUE NOT NULL,
                        title VARCHAR(500) NOT NULL,
                        content TEXT NOT NULL,
                        content_type VARCHAR(50) NOT NULL DEFAULT 'sop',
                        category VARCHAR(100),
                        subcategory VARCHAR(100),
                        tags TEXT[] DEFAULT '{}',
                        severity_filter TEXT[] DEFAULT '{}',
                        incident_types TEXT[] DEFAULT '{}',
                        ioc_types TEXT[] DEFAULT '{}',
                        mitre_techniques TEXT[] DEFAULT '{}',
                        compliance_frameworks TEXT[] DEFAULT '{}',
                        priority INTEGER DEFAULT 100,
                        is_active BOOLEAN DEFAULT TRUE,
                        version INTEGER DEFAULT 1,
                        ai_processed BOOLEAN DEFAULT FALSE,
                        ai_summary TEXT,
                        ai_extracted_rules JSONB DEFAULT '[]'::jsonb,
                        source_document_name VARCHAR(500),
                        source_document_type VARCHAR(50),
                        created_by VARCHAR(100),
                        updated_by VARCHAR(100),
                        approved_by VARCHAR(100),
                        approved_at TIMESTAMP WITH TIME ZONE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                # Create indexes for efficient querying
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_category ON knowledge_base(category)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_content_type ON knowledge_base(content_type)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_active ON knowledge_base(is_active)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_tags ON knowledge_base USING GIN(tags)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_severity ON knowledge_base USING GIN(severity_filter)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_incident_types ON knowledge_base USING GIN(incident_types)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_ioc_types ON knowledge_base USING GIN(ioc_types)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_mitre ON knowledge_base USING GIN(mitre_techniques)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_compliance ON knowledge_base USING GIN(compliance_frameworks)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_fulltext ON knowledge_base USING GIN(to_tsvector(\'english\', title || \' \' || content))')
                logger.debug(" knowledge_base table ensured")
            except Exception as e:
                logger.debug(f" knowledge_base table migration: {e}")

            # Create knowledge_base_versions table for version history
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS knowledge_base_versions (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        kb_id VARCHAR(100) NOT NULL,
                        version INTEGER NOT NULL,
                        title VARCHAR(500) NOT NULL,
                        content TEXT NOT NULL,
                        ai_summary TEXT,
                        ai_extracted_rules JSONB DEFAULT '[]'::jsonb,
                        changed_by VARCHAR(100),
                        change_reason TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(kb_id, version)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_versions_kb_id ON knowledge_base_versions(kb_id)')
                logger.debug(" knowledge_base_versions table ensured")
            except Exception as e:
                logger.debug(f" knowledge_base_versions table migration: {e}")

            # Create kb_document_uploads table for tracking uploaded documents
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS kb_document_uploads (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        upload_id VARCHAR(100) UNIQUE NOT NULL,
                        filename VARCHAR(500) NOT NULL,
                        file_type VARCHAR(50) NOT NULL,
                        file_size_bytes INTEGER,
                        status VARCHAR(50) DEFAULT 'pending',
                        processing_started_at TIMESTAMP WITH TIME ZONE,
                        processing_completed_at TIMESTAMP WITH TIME ZONE,
                        extracted_text TEXT,
                        ai_analysis JSONB DEFAULT '{}'::jsonb,
                        resulting_kb_ids TEXT[] DEFAULT '{}',
                        error_message TEXT,
                        uploaded_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_uploads_status ON kb_document_uploads(status)')
                logger.debug(" kb_document_uploads table ensured")
            except Exception as e:
                logger.debug(f" kb_document_uploads table migration: {e}")

            # Create kb_community_submissions table for community submission workflow
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS kb_community_submissions (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        kb_id VARCHAR(100) NOT NULL,
                        tenant_id UUID NOT NULL,
                        submitted_by VARCHAR(100) NOT NULL,
                        status VARCHAR(20) DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'rejected')),
                        reviewer_notes TEXT,
                        reviewed_by VARCHAR(100),
                        reviewed_at TIMESTAMP WITH TIME ZONE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_submissions_status ON kb_community_submissions(status)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_submissions_tenant ON kb_community_submissions(tenant_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_kb_submissions_kb_id ON kb_community_submissions(kb_id)')
                logger.debug(" kb_community_submissions table ensured")
            except Exception as e:
                logger.debug(f" kb_community_submissions table migration: {e}")

            # Create case_summaries table for post-resolution workflow (Phase 14)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS case_summaries (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        investigation_id VARCHAR(255) UNIQUE NOT NULL,
                        summary_data JSONB NOT NULL,
                        format VARCHAR(50) DEFAULT 'detailed',
                        generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        generated_by VARCHAR(100)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_case_summaries_inv ON case_summaries(investigation_id)')
                logger.debug(" case_summaries table ensured")
            except Exception as e:
                logger.debug(f" case_summaries table migration: {e}")

            # Create post_resolution_tasks table (Phase 14)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS post_resolution_tasks (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        investigation_id VARCHAR(255) NOT NULL,
                        task_type VARCHAR(50) NOT NULL,
                        task_config JSONB DEFAULT '{}'::jsonb,
                        status VARCHAR(20) DEFAULT 'pending',
                        result_data JSONB,
                        error_message TEXT,
                        created_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP WITH TIME ZONE
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_post_res_tasks_inv ON post_resolution_tasks(investigation_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_post_res_tasks_status ON post_resolution_tasks(status)')
                logger.debug(" post_resolution_tasks table ensured")
            except Exception as e:
                logger.debug(f" post_resolution_tasks table migration: {e}")

            # Create post_resolution_rules table (Phase 14)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS post_resolution_rules (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        conditions JSONB DEFAULT '{}'::jsonb,
                        actions JSONB DEFAULT '[]'::jsonb,
                        enabled BOOLEAN DEFAULT TRUE,
                        priority INTEGER DEFAULT 10,
                        created_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" post_resolution_rules table ensured")
            except Exception as e:
                logger.debug(f" post_resolution_rules table migration: {e}")

            # Create ioc_blocklist table for auto-blocking (Phase 14)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS ioc_blocklist (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        ioc_type VARCHAR(50) NOT NULL,
                        ioc_value VARCHAR(500) NOT NULL,
                        source VARCHAR(255),
                        reason TEXT,
                        added_by VARCHAR(100),
                        added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP WITH TIME ZONE,
                        UNIQUE(ioc_type, ioc_value)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_ioc_blocklist_value ON ioc_blocklist(ioc_value)')
                logger.debug(" ioc_blocklist table ensured")
            except Exception as e:
                logger.debug(f" ioc_blocklist table migration: {e}")

            # Create credentials_vault table for secure credential storage (Phase 1)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS credentials_vault (
                        credential_id VARCHAR(100) PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        auth_type VARCHAR(50) NOT NULL,
                        api_key_header VARCHAR(255),
                        api_key_prefix VARCHAR(255),
                        api_key_location VARCHAR(50),
                        username VARCHAR(255),
                        client_id VARCHAR(255),
                        token_url VARCHAR(500),
                        scope TEXT,
                        aws_access_key_id VARCHAR(255),
                        aws_region VARCHAR(100),
                        aws_service VARCHAR(100),
                        custom_header_names JSONB,
                        encrypted_secrets TEXT NOT NULL,
                        tags JSONB DEFAULT '[]'::jsonb,
                        integration_ids JSONB DEFAULT '[]'::jsonb,
                        created_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        last_used_at TIMESTAMP WITH TIME ZONE
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_credentials_vault_name ON credentials_vault(name)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_credentials_vault_auth_type ON credentials_vault(auth_type)')
                logger.debug(" credentials_vault table ensured")
            except Exception as e:
                logger.debug(f" credentials_vault table migration: {e}")

            # Add display_id SERIAL column to alerts table for human-friendly IDs
            try:
                await conn.execute('''
                    ALTER TABLE alerts
                    ADD COLUMN IF NOT EXISTS display_id SERIAL
                ''')
                await conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_display_id ON alerts(display_id)')
                logger.debug(" alerts.display_id column ensured")
            except Exception as e:
                logger.debug(f" alerts display_id migration: {e}")

            # Add display_id SERIAL column to investigations table for human-friendly IDs
            try:
                await conn.execute('''
                    ALTER TABLE investigations
                    ADD COLUMN IF NOT EXISTS display_id SERIAL
                ''')
                await conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_investigations_display_id ON investigations(display_id)')
                logger.debug(" investigations.display_id column ensured")
            except Exception as e:
                logger.debug(f" investigations display_id migration: {e}")

            # ========================================================================
            # PLAYBOOK SYSTEM TABLES (VPE - Visual Playbook Editor)
            # ========================================================================

            # Create playbooks table
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbooks (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        trigger_conditions JSONB DEFAULT '{}',
                        canvas_data JSONB NOT NULL DEFAULT '{"nodes": [], "edges": []}',
                        is_enabled BOOLEAN DEFAULT FALSE,
                        riggs_allowed BOOLEAN DEFAULT FALSE,
                        requires_approval BOOLEAN DEFAULT TRUE,
                        tags TEXT[] DEFAULT '{}',
                        alert_types TEXT[] DEFAULT '{}',
                        severity_filter TEXT[] DEFAULT '{}',
                        data_sources TEXT[] DEFAULT '{}',
                        priority INTEGER DEFAULT 50 CHECK (priority >= 1 AND priority <= 100),
                        version INTEGER DEFAULT 1,
                        previous_version_id UUID,
                        riggs_suggestions JSONB DEFAULT '[]',
                        last_riggs_review TIMESTAMP WITH TIME ZONE,
                        riggs_confidence FLOAT,
                        imported_from VARCHAR(50),
                        import_metadata JSONB DEFAULT '{}',
                        created_by UUID,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_playbooks_tags ON playbooks USING GIN (tags)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_playbooks_alert_types ON playbooks USING GIN (alert_types)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON playbooks (is_enabled, riggs_allowed)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_playbooks_name ON playbooks (name)')
                logger.debug(" playbooks table ensured")
            except Exception as e:
                logger.debug(f" playbooks table migration: {e}")

            # Create playbook_executions table
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbook_executions (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        execution_id VARCHAR(30) UNIQUE NOT NULL,
                        playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
                        playbook_version INTEGER,
                        alert_id UUID,
                        investigation_id UUID,
                        status VARCHAR(30) DEFAULT 'pending',
                        current_node_id VARCHAR(100),
                        execution_context JSONB DEFAULT '{}',
                        node_results JSONB DEFAULT '{}',
                        error_message TEXT,
                        triggered_by VARCHAR(50) DEFAULT 'manual',
                        triggered_by_user_id UUID,
                        started_at TIMESTAMP WITH TIME ZONE,
                        completed_at TIMESTAMP WITH TIME ZONE,
                        timeout_at TIMESTAMP WITH TIME ZONE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_exec_id ON playbook_executions(execution_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_exec_playbook ON playbook_executions(playbook_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_exec_status ON playbook_executions(status)')
                logger.debug(" playbook_executions table ensured")
            except Exception as e:
                logger.debug(f" playbook_executions table migration: {e}")

            # Create playbook_functions table (sandboxed Python)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbook_functions (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(100) NOT NULL UNIQUE,
                        description TEXT,
                        code TEXT NOT NULL,
                        input_schema JSONB DEFAULT '{}',
                        output_schema JSONB DEFAULT '{}',
                        is_approved BOOLEAN DEFAULT FALSE,
                        approved_by UUID,
                        approved_at TIMESTAMP WITH TIME ZONE,
                        security_notes TEXT,
                        usage_count INTEGER DEFAULT 0,
                        last_used_at TIMESTAMP WITH TIME ZONE,
                        created_by UUID,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_func_name ON playbook_functions(name)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_func_approved ON playbook_functions(is_approved)')
                logger.debug(" playbook_functions table ensured")
            except Exception as e:
                logger.debug(f" playbook_functions table migration: {e}")

            # Create playbook_lists table (allowlists, blocklists)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbook_lists (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(100) NOT NULL UNIQUE,
                        description TEXT,
                        list_type VARCHAR(50) NOT NULL,
                        items JSONB NOT NULL DEFAULT '[]',
                        item_count INTEGER DEFAULT 0,
                        created_by UUID,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_list_name ON playbook_lists(name)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_list_type ON playbook_lists(list_type)')
                logger.debug(" playbook_lists table ensured")
            except Exception as e:
                logger.debug(f" playbook_lists table migration: {e}")

            # Create playbook_forms table (webforms)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbook_forms (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(100) NOT NULL,
                        description TEXT,
                        fields JSONB NOT NULL DEFAULT '[]',
                        submit_action VARCHAR(50) DEFAULT 'continue',
                        submit_label VARCHAR(100) DEFAULT 'Submit',
                        require_auth BOOLEAN DEFAULT TRUE,
                        allowed_roles TEXT[] DEFAULT '{}',
                        created_by UUID,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_form_name ON playbook_forms(name)')
                logger.debug(" playbook_forms table ensured")
            except Exception as e:
                logger.debug(f" playbook_forms table migration: {e}")

            # Create playbook_form_submissions table
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbook_form_submissions (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        form_id UUID REFERENCES playbook_forms(id) ON DELETE CASCADE,
                        execution_id UUID REFERENCES playbook_executions(id) ON DELETE SET NULL,
                        node_id VARCHAR(100),
                        form_data JSONB NOT NULL DEFAULT '{}',
                        submitted_by VARCHAR(255),
                        submitted_by_user_id UUID,
                        submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        files JSONB DEFAULT '[]'
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_form_sub_form ON playbook_form_submissions(form_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_form_sub_exec ON playbook_form_submissions(execution_id)')
                logger.debug(" playbook_form_submissions table ensured")
            except Exception as e:
                logger.debug(f" playbook_form_submissions table migration: {e}")

            # Create playbook_files table (file uploads)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbook_files (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        execution_id UUID REFERENCES playbook_executions(id) ON DELETE SET NULL,
                        form_submission_id UUID REFERENCES playbook_form_submissions(id) ON DELETE SET NULL,
                        filename VARCHAR(255) NOT NULL,
                        original_filename VARCHAR(255),
                        file_type VARCHAR(100),
                        file_size BIGINT,
                        storage_path TEXT NOT NULL,
                        storage_type VARCHAR(20) DEFAULT 'local',
                        checksum VARCHAR(64),
                        scanned BOOLEAN DEFAULT FALSE,
                        scan_result VARCHAR(20),
                        uploaded_by VARCHAR(255),
                        uploaded_by_user_id UUID,
                        uploaded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_file_exec ON playbook_files(execution_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_file_form ON playbook_files(form_submission_id)')
                logger.debug(" playbook_files table ensured")
            except Exception as e:
                logger.debug(f" playbook_files table migration: {e}")

            # Create playbook_node_approvals table
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbook_node_approvals (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        execution_id UUID NOT NULL REFERENCES playbook_executions(id) ON DELETE CASCADE,
                        node_id VARCHAR(100) NOT NULL,
                        action_type VARCHAR(100),
                        action_details JSONB DEFAULT '{}',
                        reason TEXT,
                        status VARCHAR(20) DEFAULT 'pending',
                        requested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP WITH TIME ZONE,
                        reviewed_by UUID,
                        reviewed_at TIMESTAMP WITH TIME ZONE,
                        review_notes TEXT,
                        UNIQUE(execution_id, node_id)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_approval_exec ON playbook_node_approvals(execution_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_approval_status ON playbook_node_approvals(status)')
                logger.debug(" playbook_node_approvals table ensured")
            except Exception as e:
                logger.debug(f" playbook_node_approvals table migration: {e}")

            # Create playbook_templates table
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbook_templates (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        category VARCHAR(100),
                        canvas_data JSONB NOT NULL,
                        trigger_conditions JSONB DEFAULT '{}',
                        tags TEXT[] DEFAULT '{}',
                        alert_types TEXT[] DEFAULT '{}',
                        source VARCHAR(50) DEFAULT 'builtin',
                        usage_count INTEGER DEFAULT 0,
                        rating FLOAT,
                        created_by UUID,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_template_category ON playbook_templates(category)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_template_tags ON playbook_templates USING GIN (tags)')
                logger.debug(" playbook_templates table ensured")
            except Exception as e:
                logger.debug(f" playbook_templates table migration: {e}")

            # Playbook revision history
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS playbook_versions (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
                        version_number INTEGER NOT NULL,
                        canvas_data JSONB NOT NULL,
                        metadata JSONB DEFAULT '{}',
                        change_summary VARCHAR(500),
                        created_by UUID,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_pb_versions_playbook ON playbook_versions(playbook_id, version_number DESC)')
                logger.debug(" playbook_versions table ensured")
            except Exception as e:
                logger.debug(f" playbook_versions table migration: {e}")

            # EDL (External Dynamic List) tables
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS edl_lists (
                        list_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        name VARCHAR(200) NOT NULL,
                        slug VARCHAR(200) NOT NULL UNIQUE,
                        description TEXT,
                        ioc_type VARCHAR(20) NOT NULL,
                        list_type VARCHAR(20) NOT NULL DEFAULT 'static',
                        refresh_interval_seconds INT DEFAULT 300,
                        max_items INT DEFAULT 150000,
                        ttl_default_seconds INT DEFAULT 0,
                        include_comments BOOLEAN DEFAULT TRUE,
                        enabled BOOLEAN DEFAULT TRUE,
                        item_count INT DEFAULT 0,
                        last_generated_at TIMESTAMP WITH TIME ZONE,
                        content_hash VARCHAR(64),
                        tenant_id VARCHAR(100) DEFAULT 'default',
                        created_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT edl_valid_ioc_type CHECK (ioc_type IN ('ip', 'domain', 'url')),
                        CONSTRAINT edl_valid_list_type CHECK (list_type IN ('static', 'dynamic', 'hybrid'))
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_edl_lists_slug ON edl_lists(slug)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_edl_lists_enabled ON edl_lists(enabled) WHERE enabled = TRUE')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_edl_lists_tenant ON edl_lists(tenant_id)')
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS edl_items (
                        id BIGSERIAL PRIMARY KEY,
                        list_id UUID NOT NULL REFERENCES edl_lists(list_id) ON DELETE CASCADE,
                        ioc_value VARCHAR(2000) NOT NULL,
                        ioc_type VARCHAR(20) NOT NULL,
                        ioc_normalized VARCHAR(2000) NOT NULL,
                        confidence DECIMAL(3,2),
                        severity VARCHAR(20),
                        source_label VARCHAR(200),
                        comment TEXT,
                        source_type VARCHAR(50) NOT NULL DEFAULT 'manual',
                        source_id VARCHAR(200),
                        added_by VARCHAR(100),
                        expires_at TIMESTAMP WITH TIME ZONE,
                        added_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        CONSTRAINT edl_items_unique_per_list UNIQUE (list_id, ioc_normalized)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_edl_items_list_active ON edl_items(list_id) WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_edl_items_expires ON edl_items(expires_at) WHERE expires_at IS NOT NULL')
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS edl_credentials (
                        credential_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        list_id UUID NOT NULL REFERENCES edl_lists(list_id) ON DELETE CASCADE,
                        auth_type VARCHAR(20) NOT NULL,
                        token_hash VARCHAR(256),
                        token_prefix VARCHAR(20),
                        basic_username VARCHAR(100),
                        basic_password_hash VARCHAR(256),
                        ip_allowlist JSONB,
                        name VARCHAR(200) NOT NULL,
                        description TEXT,
                        enabled BOOLEAN DEFAULT TRUE,
                        expires_at TIMESTAMP WITH TIME ZONE,
                        last_used_at TIMESTAMP WITH TIME ZONE,
                        use_count BIGINT DEFAULT 0,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        created_by VARCHAR(100)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_edl_creds_list ON edl_credentials(list_id)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_edl_creds_prefix ON edl_credentials(token_prefix, list_id, enabled)')
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS edl_access_log (
                        id BIGSERIAL PRIMARY KEY,
                        list_id UUID NOT NULL REFERENCES edl_lists(list_id) ON DELETE CASCADE,
                        credential_id UUID REFERENCES edl_credentials(credential_id) ON DELETE SET NULL,
                        client_ip VARCHAR(45) NOT NULL,
                        user_agent TEXT,
                        request_path VARCHAR(500),
                        status_code INT,
                        items_returned INT,
                        response_time_ms INT,
                        cache_hit BOOLEAN DEFAULT FALSE,
                        auth_method VARCHAR(20),
                        auth_success BOOLEAN DEFAULT TRUE,
                        accessed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_edl_access_list_time ON edl_access_log(list_id, accessed_at DESC)')
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS edl_change_log (
                        id BIGSERIAL PRIMARY KEY,
                        list_id UUID NOT NULL REFERENCES edl_lists(list_id) ON DELETE CASCADE,
                        operation VARCHAR(20) NOT NULL,
                        ioc_value VARCHAR(2000) NOT NULL,
                        ioc_type VARCHAR(20) NOT NULL,
                        changed_by VARCHAR(100),
                        source_type VARCHAR(50),
                        source_id VARCHAR(200),
                        reason TEXT,
                        approval_required BOOLEAN DEFAULT FALSE,
                        approval_id VARCHAR(200),
                        approved_by VARCHAR(100),
                        changed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_edl_changelog_list ON edl_change_log(list_id, changed_at DESC)')
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS edl_content_cache (
                        list_id UUID PRIMARY KEY REFERENCES edl_lists(list_id) ON DELETE CASCADE,
                        content_text TEXT,
                        content_json JSONB,
                        item_count INT DEFAULT 0,
                        content_hash VARCHAR(64),
                        generated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP WITH TIME ZONE
                    )
                ''')
                logger.debug(" EDL tables ensured")
            except Exception as e:
                logger.debug(f" EDL tables migration: {e}")

            # Create web_forms table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS web_forms (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        form_id VARCHAR(100) UNIQUE NOT NULL,
                        title VARCHAR(255) NOT NULL,
                        description TEXT,
                        fields JSONB DEFAULT '[]'::jsonb,
                        output_config JSONB DEFAULT '{}'::jsonb,
                        is_active BOOLEAN DEFAULT TRUE,
                        created_by VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" web_forms table ensured")
            except Exception as e:
                logger.debug(f" web_forms table migration: {e}")

            # Create form_submissions table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS form_submissions (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        submission_id VARCHAR(100) UNIQUE NOT NULL,
                        form_id VARCHAR(100) NOT NULL,
                        form_title VARCHAR(255),
                        data JSONB DEFAULT '{}'::jsonb,
                        submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        ip_address VARCHAR(45),
                        user_agent TEXT,
                        status VARCHAR(50) DEFAULT 'pending',
                        alert_created BOOLEAN DEFAULT FALSE,
                        alert_id VARCHAR(255),
                        webhook_sent BOOLEAN DEFAULT FALSE,
                        webhook_response JSONB,
                        processing_errors JSONB
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_form_submissions_form_id ON form_submissions(form_id)')
                logger.debug(" form_submissions table ensured")
            except Exception as e:
                logger.debug(f" form_submissions table migration: {e}")

            # Create soar_executions table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS soar_executions (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        execution_id VARCHAR(100) UNIQUE NOT NULL,
                        playbook_id VARCHAR(100) NOT NULL,
                        playbook_version VARCHAR(50),
                        playbook_snapshot_path TEXT,
                        state VARCHAR(50) DEFAULT 'pending',
                        current_step VARCHAR(255),
                        pause_reason TEXT,
                        context JSONB DEFAULT '{}'::jsonb,
                        timeline JSONB DEFAULT '[]'::jsonb,
                        triggered_by_webhook VARCHAR(100),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        started_at TIMESTAMP WITH TIME ZONE,
                        completed_at TIMESTAMP WITH TIME ZONE
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_soar_executions_state ON soar_executions(state)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_soar_executions_playbook ON soar_executions(playbook_id)')
                logger.debug(" soar_executions table ensured")
            except Exception as e:
                logger.debug(f" soar_executions table migration: {e}")

            # Create soar_playbooks table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS soar_playbooks (
                        id VARCHAR(100) PRIMARY KEY,
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        version VARCHAR(50) DEFAULT '1.0',
                        steps JSONB DEFAULT '[]'::jsonb,
                        enabled BOOLEAN DEFAULT true,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" soar_playbooks table ensured")
            except Exception as e:
                logger.debug(f" soar_playbooks table migration: {e}")

            # Create log_source_types table if missing (for collectors)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS log_source_types (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        source_type VARCHAR(100) UNIQUE NOT NULL,
                        display_name VARCHAR(255),
                        description TEXT,
                        category VARCHAR(100),
                        parser_type VARCHAR(100),
                        default_index_name VARCHAR(255),
                        fields_schema JSONB DEFAULT '{}'::jsonb,
                        is_builtin BOOLEAN DEFAULT false,
                        enabled BOOLEAN DEFAULT true,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" log_source_types table ensured")
            except Exception as e:
                logger.debug(f" log_source_types table migration: {e}")

            # Create collector_source_assignments table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS collector_source_assignments (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        agent_id UUID REFERENCES log_agents(id),
                        source_type_id UUID REFERENCES log_source_types(id),
                        enabled BOOLEAN DEFAULT true,
                        status VARCHAR(50) DEFAULT 'active',
                        events_per_second_limit INTEGER DEFAULT 100000,
                        config_overrides JSONB DEFAULT '{}'::jsonb,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(agent_id, source_type_id)
                    )
                ''')
                logger.debug(" collector_source_assignments table ensured")
            except Exception as e:
                logger.debug(f" collector_source_assignments table migration: {e}")

            # Create/fix trusted_senders table
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS trusted_senders (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        domain VARCHAR(500) NOT NULL,
                        sender_pattern VARCHAR(500),
                        trust_level VARCHAR(50) DEFAULT 'trusted',
                        organization VARCHAR(255),
                        category VARCHAR(100),
                        reason TEXT,
                        requires_whois_match BOOLEAN DEFAULT false,
                        min_domain_age_days INTEGER DEFAULT 365,
                        is_active BOOLEAN DEFAULT true,
                        hit_count INTEGER DEFAULT 0,
                        last_hit_at TIMESTAMP WITH TIME ZONE,
                        added_by VARCHAR(255),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(domain, sender_pattern)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_trusted_senders_domain ON trusted_senders(domain)')
                logger.debug(" trusted_senders table ensured")
            except Exception as e:
                logger.debug(f" trusted_senders table migration: {e}")

            # Create phishing_tests table if missing
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS phishing_tests (
                        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                        test_id VARCHAR(100) UNIQUE NOT NULL,
                        name VARCHAR(255) NOT NULL,
                        description TEXT,
                        status VARCHAR(50) DEFAULT 'draft',
                        created_by VARCHAR(255),
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                logger.debug(" phishing_tests table ensured")
            except Exception as e:
                logger.debug(f" phishing_tests table migration: {e}")

            # Add missing columns to alert_attachments
            try:
                await conn.execute('''
                    ALTER TABLE alert_attachments
                    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP WITH TIME ZONE,
                    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                ''')
                logger.debug(" alert_attachments columns ensured")
            except Exception as e:
                logger.debug(f" alert_attachments columns migration: {e}")

            # Add missing columns to agent_approval_requests
            try:
                await conn.execute('''
                    ALTER TABLE agent_approval_requests
                    ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE
                ''')
                await conn.execute('''
                    UPDATE agent_approval_requests SET created_at = requested_at WHERE created_at IS NULL
                ''')
                logger.debug(" agent_approval_requests.created_at ensured")
            except Exception as e:
                logger.debug(f" agent_approval_requests columns migration: {e}")

            # Add missing columns to alerts (assigned_to, entity_summary etc.)
            try:
                await conn.execute('''
                    ALTER TABLE alerts
                    ADD COLUMN IF NOT EXISTS assigned_to VARCHAR(255),
                    ADD COLUMN IF NOT EXISTS assigned_at TIMESTAMP WITH TIME ZONE
                ''')
                logger.debug(" alerts.assigned_to columns ensured")
            except Exception as e:
                logger.debug(f" alerts assigned columns migration: {e}")

            # Add missing columns to investigations
            try:
                await conn.execute('''
                    ALTER TABLE investigations
                    ADD COLUMN IF NOT EXISTS entity_summary JSONB DEFAULT '{}'::jsonb,
                    ADD COLUMN IF NOT EXISTS primary_entity_type VARCHAR(100),
                    ADD COLUMN IF NOT EXISTS primary_entity_value VARCHAR(500),
                    ADD COLUMN IF NOT EXISTS user_count INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS host_count INTEGER DEFAULT 0
                ''')
                logger.debug(" investigations entity columns ensured")
            except Exception as e:
                logger.debug(f" investigations entity columns migration: {e}")

            # ================================================================
            # TWO-TRACK TRIAGE SYSTEM (investigations + alerts + IOC tables)
            # ================================================================

            # Add two-track triage columns to investigations
            try:
                await conn.execute('''
                    ALTER TABLE investigations
                    ADD COLUMN IF NOT EXISTS triage_status VARCHAR(30) DEFAULT 'not_started',
                    ADD COLUMN IF NOT EXISTS provisional_verdict VARCHAR(50),
                    ADD COLUMN IF NOT EXISTS provisional_confidence DECIMAL(5,2),
                    ADD COLUMN IF NOT EXISTS provisional_reasoning TEXT,
                    ADD COLUMN IF NOT EXISTS provisional_at TIMESTAMP WITH TIME ZONE,
                    ADD COLUMN IF NOT EXISTS final_verdict VARCHAR(50),
                    ADD COLUMN IF NOT EXISTS final_confidence DECIMAL(5,2),
                    ADD COLUMN IF NOT EXISTS final_reasoning TEXT,
                    ADD COLUMN IF NOT EXISTS confirmed_at TIMESTAMP WITH TIME ZONE,
                    ADD COLUMN IF NOT EXISTS enrichment_progress INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS enrichment_total_iocs INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS enrichment_completed_iocs INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS enrichment_high_risk_hits INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS merge_version INTEGER DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS last_merge_at TIMESTAMP WITH TIME ZONE,
                    ADD COLUMN IF NOT EXISTS verdict_delta JSONB DEFAULT '[]'::jsonb
                ''')
                logger.debug(" investigations triage columns ensured")
            except Exception as e:
                logger.debug(f" investigations triage columns migration: {e}")

            # Update investigations state constraint to include triage states
            try:
                await conn.execute('''
                    ALTER TABLE investigations DROP CONSTRAINT IF EXISTS investigations_state_check;
                    ALTER TABLE investigations ADD CONSTRAINT investigations_state_check CHECK (state IN (
                        'NEW',
                        'TRIAGE_RUNNING',
                        'TRIAGE_PROVISIONAL',
                        'ENRICHMENT_RUNNING',
                        'MERGE_PENDING',
                        'ANALYZING',
                        'CONFIRMED',
                        'NEEDS_REVIEW',
                        'RIGGS_REVIEW',
                        'ESCALATED',
                        'IN_PROGRESS',
                        'CLOSED'
                    ))
                ''')
                logger.debug(" investigations state constraint updated")
            except Exception as e:
                logger.debug(f" investigations state constraint migration: {e}")

            # Add triage columns to alerts table
            try:
                await conn.execute('''
                    ALTER TABLE alerts
                    ADD COLUMN IF NOT EXISTS triage_status VARCHAR(50),
                    ADD COLUMN IF NOT EXISTS triage_blocked_reason TEXT,
                    ADD COLUMN IF NOT EXISTS triage_enrichment_hash VARCHAR(64)
                ''')
                logger.debug(" alerts triage columns ensured")
            except Exception as e:
                logger.debug(f" alerts triage columns migration: {e}")

            # Create ioc_enrichments table (per-IOC tracking)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS ioc_enrichments (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        ioc_value VARCHAR(2000) NOT NULL,
                        ioc_type VARCHAR(50) NOT NULL,
                        ioc_value_normalized VARCHAR(2000) NOT NULL,
                        status VARCHAR(30) NOT NULL DEFAULT 'unenriched',
                        result_json JSONB DEFAULT '{}'::jsonb,
                        score INTEGER CHECK (score >= 0 AND score <= 100),
                        verdict VARCHAR(30),
                        sources_checked TEXT[] DEFAULT '{}',
                        sources_flagged TEXT[] DEFAULT '{}',
                        cached_until TIMESTAMP WITH TIME ZONE,
                        cache_ttl_seconds INTEGER DEFAULT 86400,
                        error_message TEXT,
                        retry_count INTEGER DEFAULT 0,
                        last_error_at TIMESTAMP WITH TIME ZONE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        enriched_at TIMESTAMP WITH TIME ZONE,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(ioc_value_normalized, ioc_type)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_ioc_enrichments_value ON ioc_enrichments(ioc_value_normalized)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_ioc_enrichments_status ON ioc_enrichments(status)')
                logger.debug(" ioc_enrichments table ensured")
            except Exception as e:
                logger.debug(f" ioc_enrichments table migration: {e}")

            # Create investigation_iocs table (links IOCs to investigations)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS investigation_iocs (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                        ioc_enrichment_id UUID NOT NULL REFERENCES ioc_enrichments(id) ON DELETE CASCADE,
                        found_in VARCHAR(100),
                        is_primary BOOLEAN DEFAULT FALSE,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(investigation_id, ioc_enrichment_id)
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_investigation_iocs_inv ON investigation_iocs(investigation_id)')
                logger.debug(" investigation_iocs table ensured")
            except Exception as e:
                logger.debug(f" investigation_iocs table migration: {e}")

            # Create verdict_audit_log table (immutable audit trail)
            try:
                await conn.execute('''
                    CREATE TABLE IF NOT EXISTS verdict_audit_log (
                        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                        investigation_id UUID NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
                        alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
                        change_type VARCHAR(50) NOT NULL,
                        previous_verdict VARCHAR(50),
                        previous_confidence DECIMAL(5,2),
                        new_verdict VARCHAR(50),
                        new_confidence DECIMAL(5,2),
                        reason TEXT NOT NULL,
                        evidence_summary JSONB DEFAULT '{}'::jsonb,
                        triggered_by VARCHAR(50) NOT NULL,
                        triggered_by_user VARCHAR(100),
                        analysis_mode VARCHAR(20),
                        merge_version INTEGER,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_verdict_audit_investigation ON verdict_audit_log(investigation_id)')
                logger.debug(" verdict_audit_log table ensured")
            except Exception as e:
                logger.debug(f" verdict_audit_log table migration: {e}")

            # Create triage indexes
            try:
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_investigations_triage_status ON investigations(triage_status)')
                await conn.execute('CREATE INDEX IF NOT EXISTS idx_investigations_provisional_verdict ON investigations(provisional_verdict)')
            except Exception:
                pass

            # Run numbered SQL migration files
            await self._run_sql_migrations(conn)

            # Seed sample log collectors if none exist (for demo/development)
            await self._seed_sample_collectors(conn)

    async def _run_sql_migrations(self, conn):
        """Run numbered SQL migration files from backend/migrations/ that haven't been applied yet."""
        import pathlib
        migrations_dir = pathlib.Path(__file__).parent.parent / "migrations"
        if not migrations_dir.exists():
            return

        # Get already-applied migrations
        try:
            applied = set()
            rows = await conn.fetch("SELECT migration_name FROM schema_migrations")
            for row in rows:
                applied.add(row["migration_name"])
        except Exception:
            return  # table doesn't exist yet

        # Find and sort SQL files (numbered files first, then unnumbered)
        sql_files = sorted(migrations_dir.glob("*.sql"))
        applied_count = 0

        for sql_file in sql_files:
            name = sql_file.name
            if name in applied:
                continue

            try:
                sql = sql_file.read_text(encoding="utf-8")
                # Migrations frequently include data backfills against
                # tenant-scoped tables (alerts, investigations, etc.). The
                # RLS policy on those tables requires either a tenant
                # context or app.is_platform_admin='true'. The migration
                # runner has neither by default, so backfill UPDATEs
                # silently match zero rows.
                #
                # Wrap the apply in an explicit transaction so SET LOCAL
                # actually scopes to it. A handful of migrations use
                # CREATE INDEX CONCURRENTLY which cannot run inside a
                # transaction — for those we fall back to the un-wrapped
                # path so they at least don't break, and accept that they
                # won't have the platform-admin guarantee (they don't
                # need it; they're schema-only).
                if 'CREATE INDEX CONCURRENTLY' in sql.upper():
                    await conn.execute(sql)
                else:
                    async with conn.transaction():
                        await conn.execute("SET LOCAL app.is_platform_admin = 'true'")
                        await conn.execute(sql)
                await conn.execute(
                    "INSERT INTO schema_migrations (migration_name) VALUES ($1) ON CONFLICT DO NOTHING",
                    name,
                )
                applied_count += 1
                logger.info(f"Applied migration: {name}")
            except Exception as e:
                logger.warning(f"Migration {name} failed: {e}")

        if applied_count:
            logger.info(f"Applied {applied_count} new migration(s)")

    async def _seed_sample_collectors(self, conn):
        """Seed sample log collectors and source assignments for demonstration"""
        try:
            # Check if we already have collectors
            count = await conn.fetchval('SELECT COUNT(*) FROM log_agents')
            if count > 0:
                logger.debug(f" log_agents already has {count} collectors, skipping seed")
                return

            logger.info("Seeding sample log collectors for demonstration...")

            # Insert sample collectors
            await conn.execute('''
                INSERT INTO log_agents (agent_id, hostname, os_type, os_version, ip_address, agent_version, status, tags, metadata, last_heartbeat, events_received_total) VALUES
                    ('agent-dc01-prod', 'DC01.corp.local', 'windows', 'Windows Server 2022', '10.0.1.10', '1.2.0', 'active', ARRAY['domain-controller', 'production', 'tier0'], '{"location": "HQ", "department": "IT"}', NOW() - INTERVAL '2 minutes', 1523847),
                    ('agent-dc02-prod', 'DC02.corp.local', 'windows', 'Windows Server 2022', '10.0.1.11', '1.2.0', 'active', ARRAY['domain-controller', 'production', 'tier0'], '{"location": "HQ", "department": "IT"}', NOW() - INTERVAL '1 minute', 1489234),
                    ('agent-web01-prod', 'web01.corp.local', 'linux', 'Ubuntu 22.04 LTS', '10.0.2.20', '1.2.0', 'active', ARRAY['web-server', 'production', 'dmz'], '{"location": "HQ", "department": "Engineering"}', NOW() - INTERVAL '30 seconds', 8234567),
                    ('agent-web02-prod', 'web02.corp.local', 'linux', 'Ubuntu 22.04 LTS', '10.0.2.21', '1.2.0', 'active', ARRAY['web-server', 'production', 'dmz'], '{"location": "HQ", "department": "Engineering"}', NOW() - INTERVAL '45 seconds', 7891234),
                    ('agent-db01-prod', 'db01.corp.local', 'linux', 'RHEL 8.8', '10.0.3.30', '1.1.5', 'active', ARRAY['database', 'production', 'tier1'], '{"location": "HQ", "department": "DBA"}', NOW() - INTERVAL '1 minute', 2345678),
                    ('agent-mail01-prod', 'mail01.corp.local', 'windows', 'Windows Server 2019', '10.0.4.40', '1.2.0', 'active', ARRAY['email', 'production'], '{"location": "HQ", "department": "IT"}', NOW() - INTERVAL '2 minutes', 456789),
                    ('agent-fw01-prod', 'fw01.corp.local', 'linux', 'PAN-OS 11.0', '10.0.0.1', '1.2.0', 'active', ARRAY['firewall', 'production', 'perimeter'], '{"location": "HQ", "department": "Security"}', NOW() - INTERVAL '15 seconds', 45678901),
                    ('agent-siem01-prod', 'siem01.corp.local', 'linux', 'Ubuntu 20.04 LTS', '10.0.5.50', '1.2.0', 'maintenance', ARRAY['siem', 'production'], '{"location": "HQ", "department": "Security"}', NOW() - INTERVAL '1 hour', 12345678),
                    ('agent-laptop001', 'LAPTOP-JSmith', 'windows', 'Windows 11 Pro', '192.168.1.101', '1.2.0', 'active', ARRAY['endpoint', 'workstation'], '{"location": "Remote", "department": "Sales", "user": "jsmith"}', NOW() - INTERVAL '5 minutes', 234567),
                    ('agent-laptop002', 'LAPTOP-AJones', 'macos', 'macOS Sonoma 14.2', '192.168.1.102', '1.2.0', 'inactive', ARRAY['endpoint', 'workstation'], '{"location": "Remote", "department": "Marketing", "user": "ajones"}', NOW() - INTERVAL '2 days', 123456)
                ON CONFLICT (agent_id) DO NOTHING
            ''')
            logger.info(" Seeded 10 sample log collectors")

            # Assign sources to collectors
            # DC01 - Windows Security and AD events
            await conn.execute('''
                INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
                SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 500000
                FROM log_agents la, log_source_types lst
                WHERE la.agent_id = 'agent-dc01-prod' AND lst.source_type IN ('windows_security', 'ldap_audit')
                ON CONFLICT (agent_id, source_type_id) DO NOTHING
            ''')

            # Web servers - Linux audit and web access
            await conn.execute('''
                INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
                SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 2000000
                FROM log_agents la, log_source_types lst
                WHERE la.agent_id = 'agent-web01-prod' AND lst.source_type IN ('linux_auditd', 'web_access', 'linux_syslog')
                ON CONFLICT (agent_id, source_type_id) DO NOTHING
            ''')

            # Firewall - Network traffic
            await conn.execute('''
                INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
                SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 15000000
                FROM log_agents la, log_source_types lst
                WHERE la.agent_id = 'agent-fw01-prod' AND lst.source_type IN ('firewall_palo_alto', 'dns_logs', 'netflow')
                ON CONFLICT (agent_id, source_type_id) DO NOTHING
            ''')

            # Database server
            await conn.execute('''
                INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
                SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 800000
                FROM log_agents la, log_source_types lst
                WHERE la.agent_id = 'agent-db01-prod' AND lst.source_type IN ('linux_auditd', 'database_audit')
                ON CONFLICT (agent_id, source_type_id) DO NOTHING
            ''')

            # Laptop with Sysmon
            await conn.execute('''
                INSERT INTO collector_source_assignments (agent_id, agent_hostname, source_type_id, source_type, target_index_name, is_enabled, status, events_collected)
                SELECT la.id, la.hostname, lst.id, lst.source_type, lst.default_index_name, true, 'active', 100000
                FROM log_agents la, log_source_types lst
                WHERE la.agent_id = 'agent-laptop001' AND lst.source_type IN ('windows_sysmon', 'windows_defender', 'windows_powershell')
                ON CONFLICT (agent_id, source_type_id) DO NOTHING
            ''')

            logger.info(" Seeded collector source assignments")

        except Exception as e:
            logger.warning(f" Sample collectors seed skipped (may already exist): {e}")

    # ========================================================================
    # USERS
    # ========================================================================
    
    async def bootstrap_users(self):
        """Create default users if they don't exist"""
        from config.constants import PLATFORM_OWNER_TENANT_ID

        default_users = [
            {
                'username': 'admin',
                'email': 'admin@T1 Agentics.io',
                'password': 'admin123',
                'full_name': 'Administrator',
                'role': 'admin'
            },
            {
                'username': 'analyst',
                'email': 'analyst@T1 Agentics.io',
                'password': 'analyst123',
                'full_name': 'SOC Analyst',
                'role': 'analyst'
            },
            {
                'username': 'readonly',
                'email': 'readonly@T1 Agentics.io',
                'password': 'readonly123',
                'full_name': 'Read Only User',
                'role': 'read_only'
            }
        ]

        logger.info(f"Checking/creating {len(default_users)} default users...")

        async with self.pool.acquire() as conn:
            # Set RLS context so bootstrap can read/write the users table
            await conn.execute(
                "SELECT set_config('app.current_tenant_id', $1, false)",
                str(PLATFORM_OWNER_TENANT_ID),
            )
            await conn.execute(
                "SELECT set_config('app.is_platform_admin', 'true', false)"
            )

            for user_data in default_users:
                try:
                    # Check if user exists
                    existing = await conn.fetchval(
                        'SELECT 1 FROM users WHERE username = $1',
                        user_data['username']
                    )

                    if existing:
                        logger.debug(f"User '{user_data['username']}' already exists, skipping")
                    else:
                        logger.info(f"Creating user '{user_data['username']}'...")

                        hashed_password = bcrypt.hash(user_data['password'])
                        # New users with default passwords must change on first login
                        await conn.execute('''
                            INSERT INTO users (username, email, hashed_password, full_name, role, tenant_id, force_password_reset)
                            VALUES ($1, $2, $3, $4, $5, $6, true)
                        ''',
                            user_data['username'],
                            user_data['email'],
                            hashed_password,
                            user_data['full_name'],
                            user_data['role'],
                            PLATFORM_OWNER_TENANT_ID
                        )
                        logger.info(f"Created user: {user_data['username']} (password reset required)")
                except Exception as e:
                    logger.error(f"Error creating user {user_data['username']}: {e}")
                    logger.exception("Full traceback:")
    
    async def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all non-disabled users"""
        async with self.tenant_acquire() as conn:
            # First try with force_password_reset, fallback without it
            try:
                rows = await conn.fetch('''
                    SELECT id, username, email, full_name, role, disabled, 
                           force_password_reset,
                           created_at, last_login
                    FROM users 
                    WHERE disabled = FALSE
                    ORDER BY username
                ''')
            except Exception:
                # Column doesn't exist yet, query without it
                rows = await conn.fetch('''
                    SELECT id, username, email, full_name, role, disabled, 
                           FALSE as force_password_reset,
                           created_at, last_login
                    FROM users 
                    WHERE disabled = FALSE
                    ORDER BY username
                ''')
            return [dict(row) for row in rows]
    
    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username.

        Uses admin bypass because this is called during login and auth
        validation where no tenant context may be set yet.
        """
        async with self.pool.acquire() as conn:
            await conn.execute("SET app.is_platform_admin = 'true'")
            row = await conn.fetchrow(
                'SELECT * FROM users WHERE username = $1',
                username
            )
            return dict(row) if row else None

    async def get_user_by_username_or_email(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Get user by username or email.

        Supports login with either username or email address.
        Uses admin bypass because this is called during login.
        """
        async with self.pool.acquire() as conn:
            await conn.execute("SET app.is_platform_admin = 'true'")
            row = await conn.fetchrow(
                'SELECT * FROM users WHERE username = $1 OR email = $1',
                identifier
            )
            return dict(row) if row else None
    
    async def create_log(self, log_entry: dict):
        """Write a log entry. Used by PollingScheduler for operational logging."""
        level = log_entry.get("level", "info")
        message = log_entry.get("message", "")
        getattr(logger, level, logger.info)(f"[SCHEDULER] {message}")

    async def get_polling_integrations(self):
        """Get all enabled integrations that have polling configured.
        Returns list of dicts with integration_id, name, poll_interval_minutes, enabled."""
        if not self.pool:
            return []
        try:
            async with self.pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                rows = await conn.fetch("""
                    SELECT integration_id, name, enabled,
                           COALESCE((config->>'poll_interval_minutes')::int, 60) as poll_interval_minutes,
                           COALESCE((config->>'poll_enabled')::boolean, false) as poll_enabled
                    FROM integrations
                    WHERE enabled = true
                    AND (config->>'poll_enabled')::boolean = true
                """)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.warning(f"get_polling_integrations failed (returning empty): {e}")
            return []

    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get single alert by alert_id"""
        async with self.tenant_acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM alerts WHERE alert_id = $1',
                alert_id
            )
            return dict(row) if row else None

    # ========================================================================
    # ALERTS
    # ========================================================================
    
    async def create_alert(self, alert_data: Dict[str, Any]) -> str:
        """Create new alert with JSONB storage

        Supports three-class telemetry model:
        - observation: Raw log/event data from collectors
        - assertion: Vendor claims (webhook alerts from external SIEM/EDR)
        - decision: Human/AI investigation conclusions
        """
        async with self.tenant_acquire() as conn:
            # Generate alert_id if not provided
            alert_id = alert_data.get('alert_id', f"alert-{datetime.utcnow().timestamp()}")

            # Get group_id as UUID if present (string like "uuid-string")
            group_id = alert_data.get('alert_group_id')

            # Resolve tenant_id: explicit in data > ContextVar > fallback
            tenant_id_str = alert_data.get('tenant_id')
            if not tenant_id_str:
                try:
                    from middleware.tenant_middleware import get_optional_tenant_id
                    tenant_id_str = get_optional_tenant_id()
                except Exception:
                    pass
            if not tenant_id_str:
                from config.constants import PLATFORM_OWNER_TENANT_ID
                tenant_id_str = PLATFORM_OWNER_TENANT_ID

            import uuid as _uuid
            tenant_uuid = _uuid.UUID(str(tenant_id_str))

            row = await conn.fetchrow('''
                INSERT INTO alerts (
                    alert_id, external_id, title, description,
                    severity, status, source, source_type,
                    category, subcategory, confidence, raw_event,
                    fingerprint, alert_group_id, is_primary,
                    event_class, vendor, vendor_confidence,
                    vendor_reputation, false_positive_rate,
                    linked_observation_ids, tenant_id
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                    $16, $17, $18, $19, $20, $21, $22
                )
                RETURNING id, alert_id, display_id, created_at
            ''',
                alert_id,
                alert_data.get('external_id'),
                alert_data['title'],
                alert_data.get('description'),
                alert_data.get('severity', 'medium'),
                alert_data.get('status', 'open'),
                alert_data.get('source'),
                alert_data.get('source_type'),
                alert_data.get('category'),
                alert_data.get('subcategory'),
                alert_data.get('confidence'),
                json.dumps(alert_data.get('raw_event', alert_data)),  # Store full payload
                alert_data.get('fingerprint'),
                group_id,  # UUID or None
                alert_data.get('is_primary', True),
                # Telemetry classification (default to 'assertion' for webhook alerts)
                alert_data.get('event_class', 'assertion'),
                # Vendor trust tracking
                alert_data.get('vendor'),
                alert_data.get('vendor_confidence'),
                alert_data.get('vendor_reputation'),
                alert_data.get('false_positive_rate'),
                # Correlation: linked observation IDs
                alert_data.get('linked_observation_ids', []),
                tenant_uuid,
            )

            logger.info(f"Created alert: #{row['display_id']} ({row['alert_id']}) [event_class={alert_data.get('event_class', 'assertion')}]")
            return row['alert_id']
    
    async def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        source: Optional[str] = None,
        search_query: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        exclude_with_investigation: bool = True
    ) -> List[Dict[str, Any]]:
        """Get alerts with filters

        By default, excludes alerts with investigation_id to avoid duplicates in work queue.
        """
        async with self.tenant_acquire() as conn:
            query_parts = ['SELECT * FROM alerts WHERE 1=1']
            params = []
            param_count = 1

            # Exclude alerts escalated to investigation (avoid duplicates)
            if exclude_with_investigation:
                query_parts.append('AND investigation_id IS NULL')

            if status and status != 'all':
                query_parts.append(f'AND status = ${param_count}')
                params.append(status)
                param_count += 1
            
            if severity and severity != 'all':
                query_parts.append(f'AND severity = ${param_count}')
                params.append(severity)
                param_count += 1
            
            if source:
                query_parts.append(f'AND source = ${param_count}')
                params.append(source)
                param_count += 1
            
            if search_query:
                # SIEM-style deep search: searches in all fields including JSONB raw_event
                query_parts.append(f'''AND (
                    title ILIKE ${param_count} OR 
                    description ILIKE ${param_count} OR
                    alert_id ILIKE ${param_count} OR
                    source ILIKE ${param_count} OR
                    raw_event::text ILIKE ${param_count}
                )''')
                params.append(f'%{search_query}%')
                param_count += 1
            
            query_parts.append(f'ORDER BY created_at DESC LIMIT ${param_count} OFFSET ${param_count+1}')
            params.extend([limit, offset])

            query = ' '.join(query_parts)
            rows = await conn.fetch(query, *params)

            results = []
            for row in rows:
                alert = dict(row)
                # Parse raw_event JSON string to dict for frontend
                if alert.get('raw_event') and isinstance(alert['raw_event'], str):
                    try:
                        alert['raw_event'] = json.loads(alert['raw_event'])
                    except json.JSONDecodeError:
                        pass
                results.append(alert)
            return results

    async def get_alert_by_id(self, alert_id: str, tenant_id: str = None) -> Optional[Dict[str, Any]]:
        """Get alert by alert_id. Pass tenant_id for background tasks without request context."""
        async with self.tenant_acquire() as conn:
            if tenant_id:
                # Explicit tenant_id overrides ContextVar (for background tasks)
                await conn.execute(
                    "SELECT set_config('app.current_tenant_id', $1, true)",
                    str(tenant_id)
                )
            row = await conn.fetchrow(
                'SELECT * FROM alerts WHERE alert_id = $1',
                alert_id
            )
            if row:
                alert = dict(row)
                # Parse raw_event JSON string to dict for frontend
                if alert.get('raw_event') and isinstance(alert['raw_event'], str):
                    try:
                        alert['raw_event'] = json.loads(alert['raw_event'])
                    except json.JSONDecodeError:
                        pass
                return alert
            return None

    async def get_alert_by_external_id(self, external_id: str, source: str) -> Optional[Dict[str, Any]]:
        """Get alert by external_id and source (for duplicate detection)"""
        async with self.tenant_acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM alerts WHERE external_id = $1 AND source = $2',
                external_id, source
            )
            return dict(row) if row else None
    
    async def update_alert_status(self, alert_id: str, status: str) -> bool:
        """Update alert status"""
        async with self.tenant_acquire() as conn:
            result = await conn.execute(
                'UPDATE alerts SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE alert_id = $2',
                status, alert_id
            )
            return result == 'UPDATE 1'
    
    async def update_alert_severity(self, alert_id: str, severity: str) -> bool:
        """Update alert severity"""
        async with self.tenant_acquire() as conn:
            result = await conn.execute(
                'UPDATE alerts SET severity = $1, updated_at = CURRENT_TIMESTAMP WHERE alert_id = $2',
                severity, alert_id
            )
            return result == 'UPDATE 1'
    
    async def update_alert_sensitivity(self, alert_id: str, sensitivity: str) -> bool:
        """Update alert sensitivity"""
        async with self.tenant_acquire() as conn:
            result = await conn.execute(
                'UPDATE alerts SET sensitivity = $1, updated_at = CURRENT_TIMESTAMP WHERE alert_id = $2',
                sensitivity, alert_id
            )
            return result == 'UPDATE 1'

    async def get_alert_investigation(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get investigation linked to alert"""
        async with self.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                SELECT i.*
                FROM investigations i
                JOIN alerts a ON i.id = a.investigation_id
                WHERE a.alert_id = $1
            ''', alert_id)
            return dict(row) if row else None
    
    # ========================================================================
    # INVESTIGATIONS
    # ========================================================================
    
    async def create_investigation(self, inv_data: Dict[str, Any]) -> str:
        """Create investigation linked to alert"""
        async with self.pool.acquire() as conn:
            # Set admin context for background tasks (RLS bypass)
            await conn.execute("SET app.is_platform_admin = 'true'")
            try:
                return await self._create_investigation_impl(conn, inv_data)
            finally:
                try:
                    await conn.execute("RESET app.is_platform_admin")
                except Exception:
                    pass

    async def _create_investigation_impl(self, conn, inv_data: Dict[str, Any]) -> str:
        """Internal: create investigation with an existing connection."""
        # Generate investigation_id if not provided - use INV-XXXXXXXX format
        inv_id = inv_data.get('investigation_id')
        if not inv_id:
            import uuid
            inv_id = f"INV-{uuid.uuid4().hex[:8].upper()}"

        # Get alert UUID and tenant_id if alert_id provided
        alert_uuid = None
        tenant_id = inv_data.get('tenant_id')
        if inv_data.get('alert_id'):
            alert_row = await conn.fetchrow(
                'SELECT id, tenant_id FROM alerts WHERE alert_id = $1',
                inv_data['alert_id']
            )
            if alert_row:
                alert_uuid = alert_row['id']
                if not tenant_id:
                    tenant_id = alert_row['tenant_id']

        if not tenant_id:
            # Fallback: try to get from current tenant context
            try:
                from middleware.tenant_middleware import get_current_tenant_id
                tenant_id = get_current_tenant_id()
            except Exception:
                pass

        if not tenant_id:
            raise ValueError("Cannot create investigation: no tenant_id available")

        # Build investigation_data JSONB - include raw_alert, timeline, enrichment, etc.
        investigation_data = {
            'raw_alert': inv_data.get('raw_alert', {}),
            'timeline': inv_data.get('timeline', []),
            'enrichment_data': inv_data.get('enrichment_data', {}),
            'ai_analysis': inv_data.get('ai_analysis', {}),
            'indicators': inv_data.get('indicators', []),
            'recommended_actions': inv_data.get('recommended_actions', [])
        }
        # Merge with any existing investigation_data
        if inv_data.get('investigation_data'):
            investigation_data.update(inv_data['investigation_data'])

        # Convert confidence to numeric (handle string values like "High", "Medium", "Low")
        confidence_raw = inv_data.get('confidence')
        if isinstance(confidence_raw, str):
            confidence_map = {'low': 0.3, 'medium': 0.6, 'high': 0.85, 'critical': 0.95}
            confidence_val = confidence_map.get(confidence_raw.lower(), 0.5)
        elif isinstance(confidence_raw, (int, float)):
            confidence_val = float(confidence_raw)
        else:
            confidence_val = 0.5

        # Normalize severity to lowercase (database constraint requires: low, medium, high, critical)
        severity_raw = inv_data.get('severity', 'medium')
        if isinstance(severity_raw, str):
            severity_val = severity_raw.lower()
            if severity_val not in ('low', 'medium', 'high', 'critical'):
                severity_val = 'medium'
        else:
            severity_val = 'medium'

        row = await conn.fetchrow('''
            INSERT INTO investigations (
                investigation_id, alert_id, alert_title,
                state, disposition, priority, owner,
                executive_summary, confidence, severity,
                investigation_data, tenant_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            RETURNING id, investigation_id, display_id
        ''',
            inv_id,
            alert_uuid,
            inv_data.get('alert_title'),
            inv_data.get('state', 'NEW'),
            inv_data.get('disposition', 'UNKNOWN'),
            inv_data.get('priority', 'P3'),
            inv_data.get('owner'),
            inv_data.get('executive_summary') or inv_data.get('summary'),
            confidence_val,
            severity_val,
            json.dumps(investigation_data),
            tenant_id
        )

        # Link alert to investigation
        if alert_uuid:
            await conn.execute(
                'UPDATE alerts SET investigation_id = $1 WHERE id = $2',
                row['id'], alert_uuid
            )
            # Update alert status to investigating
            await conn.execute(
                'UPDATE alerts SET status = $1 WHERE id = $2',
                'investigating', alert_uuid
            )

            # Auto-link investigation to campaigns that contain this alert
            try:
                campaign_rows = await conn.fetch(
                    """
                    SELECT DISTINCT cm.campaign_id, c.campaign_id as campaign_code
                    FROM campaign_members cm
                    JOIN campaigns c ON c.id = cm.campaign_id
                    WHERE cm.alert_id = $1 AND cm.member_type = 'alert'
                    """,
                    alert_uuid
                )

                for camp_row in campaign_rows:
                    # Link investigation to same campaign
                    await conn.execute(
                        """
                        INSERT INTO campaign_members (campaign_id, member_type, investigation_id, added_by, correlation_reason, tenant_id)
                        VALUES ($1, 'investigation', $2, 'auto_link', 'Investigation created from campaign-linked alert', $3)
                        ON CONFLICT DO NOTHING
                        """,
                        camp_row['campaign_id'], row['id'], tenant_id
                    )
                    logger.debug(f"Auto-linked investigation {inv_id} to campaign {camp_row['campaign_code']}")
            except Exception as camp_err:
                logger.debug(f"Campaign auto-link check: {camp_err}")

        logger.info(f"Created investigation: INV-{row['display_id']} ({row['investigation_id']})")

        # Trigger playbooks for investigation_created (non-blocking)
        try:
            from services.playbook_trigger_service import trigger_playbooks_for_event

            alert_row = None
            if inv_data.get('alert_id'):
                alert_row = await conn.fetchrow(
                    'SELECT * FROM alerts WHERE alert_id = $1',
                    inv_data['alert_id']
                )
            investigation_row = await conn.fetchrow(
                'SELECT * FROM investigations WHERE investigation_id = $1',
                inv_id
            )

            asyncio.create_task(trigger_playbooks_for_event(
                event_type="investigation_created",
                alert=dict(alert_row) if alert_row else None,
                investigation=dict(investigation_row) if investigation_row else None,
                alert_id=inv_data.get('alert_id'),
                investigation_id=inv_id
            ))
        except Exception as e:
            logger.warning(f"Playbook trigger (investigation_created) failed: {e}")

        return row['investigation_id']
    
    async def get_investigations(
        self,
        state: Optional[str] = None,
        disposition: Optional[str] = None,
        owner: Optional[str] = None,
        priority: Optional[str] = None,
        sort_by: str = 'created_at',
        sort_order: str = 'desc',
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get investigations with filters and sorting"""
        async with self.tenant_acquire() as conn:
            # Use subquery to get alert confidence when investigation confidence is null
            query_parts = ['''
                SELECT i.*,
                    COALESCE(i.confidence, (
                        SELECT a.ai_confidence
                        FROM alerts a
                        WHERE a.investigation_id = i.id
                        LIMIT 1
                    )) as confidence,
                    (
                        SELECT a.source
                        FROM alerts a
                        WHERE a.investigation_id = i.id
                        LIMIT 1
                    ) as alert_source
                FROM investigations i
                WHERE 1=1
            ''']
            params = []
            param_count = 1
            
            # State grouping (frontend provides grouped state)
            if state and state != 'all':
                if state == 'open':
                    query_parts.append(f"AND state IN ('NEW', 'ENRICHING')")
                elif state == 'in_progress':
                    query_parts.append(f"AND state IN ('AI_TRIAGE_L1', 'AI_TRIAGE_L2', 'AWAITING_HUMAN', 'IN_PROGRESS')")
                elif state == 'closed':
                    query_parts.append(f"AND state IN ('RESOLVED', 'CLOSED')")
                else:
                    # Direct state match
                    query_parts.append(f'AND state = ${param_count}')
                    params.append(state.upper())
                    param_count += 1
            
            if disposition:
                query_parts.append(f'AND disposition = ${param_count}')
                params.append(disposition)
                param_count += 1
            
            if owner:
                query_parts.append(f'AND owner = ${param_count}')
                params.append(owner)
                param_count += 1
            
            if priority:
                query_parts.append(f'AND priority = ${param_count}')
                params.append(priority)
                param_count += 1
            
            # Sorting (validate fields to prevent SQL injection)
            valid_sort_fields = ['created_at', 'updated_at', 'priority', 'severity', 'state', 'disposition']
            if sort_by not in valid_sort_fields:
                sort_by = 'created_at'
            
            valid_sort_orders = ['asc', 'desc']
            if sort_order.lower() not in valid_sort_orders:
                sort_order = 'desc'
            
            # Priority custom sorting (P1 > P2 > P3 > P4)
            if sort_by == 'priority':
                query_parts.append(f'''
                    ORDER BY
                        CASE i.priority
                            WHEN 'P1' THEN 1
                            WHEN 'P2' THEN 2
                            WHEN 'P3' THEN 3
                            WHEN 'P4' THEN 4
                            ELSE 5
                        END {sort_order.upper()},
                        i.created_at DESC
                ''')
            else:
                query_parts.append(f'ORDER BY i.{sort_by} {sort_order.upper()}')
            
            query_parts.append(f'LIMIT ${param_count} OFFSET ${param_count+1}')
            params.extend([limit, offset])
            
            query = ' '.join(query_parts)
            rows = await conn.fetch(query, *params)
            
            return [dict(row) for row in rows]
    
    async def get_investigation_by_id(self, investigation_id: str, admin_bypass: bool = False) -> Optional[Dict[str, Any]]:
        """Get investigation by investigation_id or UUID id"""
        async with self.tenant_acquire() as conn:
            # Platform admin can view investigations across all tenants
            if admin_bypass:
                await conn.execute("SELECT set_config('app.is_platform_admin', 'true', false)")
            # First try by investigation_id (e.g., INV-XXXXXXXX)
            row = await conn.fetchrow(
                'SELECT * FROM investigations WHERE investigation_id = $1',
                investigation_id
            )

            # If not found, try by UUID id
            if not row:
                row = await conn.fetchrow(
                    'SELECT * FROM investigations WHERE id::text = $1',
                    investigation_id
                )

            if not row:
                return None

            result = dict(row)

            # Parse investigation_data if it's a string
            if result.get('investigation_data'):
                if isinstance(result['investigation_data'], str):
                    try:
                        result['investigation_data'] = json.loads(result['investigation_data'])
                    except:
                        pass

            # Parse extracted_iocs if it's a string (asyncpg returns JSONB as string)
            if result.get('extracted_iocs'):
                if isinstance(result['extracted_iocs'], str):
                    try:
                        result['extracted_iocs'] = json.loads(result['extracted_iocs'])
                    except:
                        result['extracted_iocs'] = []
            else:
                result['extracted_iocs'] = []

            # ================================================================
            # EXTRACT NESTED FIELDS FOR FRONTEND COMPATIBILITY
            # ================================================================
            inv_data = result.get('investigation_data', {}) or {}

            # Extract ioc_summary from investigation_data to top level
            if inv_data.get('ioc_summary') and not result.get('ioc_summary'):
                result['ioc_summary'] = inv_data['ioc_summary']

            # Extract indicators from investigation_data to top level
            if inv_data.get('indicators') and not result.get('indicators'):
                result['indicators'] = inv_data['indicators']

            # Enrich IOCs with verdict data from the iocs table
            if result.get('alert_id'):
                try:
                    # Get the alert to access IOCs and _extracted data
                    alert_row = await conn.fetchrow(
                        'SELECT raw_event FROM alerts WHERE id = $1',
                        result['alert_id']
                    )
                    if alert_row and alert_row['raw_event']:
                        raw_event = alert_row['raw_event']
                        if isinstance(raw_event, str):
                            raw_event = json.loads(raw_event)

                        # ================================================================
                        # BUILD IOC SUMMARY FROM _EXTRACTED IF NOT ALREADY SET
                        # ================================================================
                        extracted = raw_event.get('_extracted', {})
                        extracted_iocs = extracted.get('iocs', {})
                        enrichment_results = extracted.get('enrichment', {}).get('results', {}) or extracted.get('enrichment', {})
                        ai_triage = extracted.get('ai_triage', {})

                        # Build ioc_summary from extracted IOCs if not already present
                        if not result.get('ioc_summary') and extracted_iocs:
                            result['ioc_summary'] = {
                                'ips': extracted_iocs.get('ips', []),
                                'private_ips': extracted_iocs.get('private_ips', []),  # Internal IPs
                                'domains': extracted_iocs.get('domains', []),
                                'hashes': extracted_iocs.get('hashes', []),
                                'urls': extracted_iocs.get('urls', []),
                                'emails': extracted_iocs.get('emails', []),
                            }

                        # ================================================================
                        # BUILD INDICATORS WITH ENRICHMENT VERDICTS
                        # ================================================================
                        if not result.get('indicators'):
                            indicators = []

                            # Process public IPs (enrichable)
                            for ip in extracted_iocs.get('ips', []):
                                verdict = 'unknown'
                                confidence = None
                                # Check enrichment results for this IP
                                for enr_ip in enrichment_results.get('ips', []):
                                    if enr_ip.get('value') == ip or enr_ip.get('ip') == ip:
                                        verdict = enr_ip.get('verdict', 'unknown')
                                        confidence = enr_ip.get('confidence')
                                        break
                                indicators.append({
                                    'type': 'ip',
                                    'value': ip,
                                    'verdict': verdict,
                                    'confidence': confidence,
                                    'sources': ['extracted']
                                })

                            # Process private/internal IPs (not enrichable but visible)
                            for ip in extracted_iocs.get('private_ips', []):
                                indicators.append({
                                    'type': 'ip',
                                    'value': ip,
                                    'verdict': 'internal',  # Mark as internal, not unknown
                                    'confidence': None,
                                    'sources': ['extracted'],
                                    'internal': True,  # Flag for UI to show differently
                                    'note': 'Private/internal IP - external enrichment not applicable'
                                })

                            # Process domains
                            for domain in extracted_iocs.get('domains', []):
                                verdict = 'unknown'
                                confidence = None
                                for enr_dom in enrichment_results.get('domains', []):
                                    if enr_dom.get('value') == domain or enr_dom.get('domain') == domain:
                                        verdict = enr_dom.get('verdict', 'unknown')
                                        confidence = enr_dom.get('confidence')
                                        break
                                indicators.append({
                                    'type': 'domain',
                                    'value': domain,
                                    'verdict': verdict,
                                    'confidence': confidence,
                                    'sources': ['extracted']
                                })

                            # Process hashes
                            for hash_val in extracted_iocs.get('hashes', []):
                                verdict = 'unknown'
                                confidence = None
                                for enr_hash in enrichment_results.get('hashes', []):
                                    if enr_hash.get('value') == hash_val or enr_hash.get('hash') == hash_val:
                                        verdict = enr_hash.get('verdict', 'unknown')
                                        confidence = enr_hash.get('confidence')
                                        break
                                indicators.append({
                                    'type': 'hash',
                                    'value': hash_val,
                                    'verdict': verdict,
                                    'confidence': confidence,
                                    'sources': ['extracted']
                                })

                            # Process URLs
                            for url in extracted_iocs.get('urls', []):
                                verdict = 'unknown'
                                confidence = None
                                for enr_url in enrichment_results.get('urls', []):
                                    if enr_url.get('value') == url or enr_url.get('url') == url:
                                        verdict = enr_url.get('verdict', 'unknown')
                                        confidence = enr_url.get('confidence')
                                        break
                                indicators.append({
                                    'type': 'url',
                                    'value': url,
                                    'verdict': verdict,
                                    'confidence': confidence,
                                    'sources': ['extracted']
                                })

                            if indicators:
                                result['indicators'] = indicators
                                # ================================================================
                                # BUILD extracted_iocs FOR FRONTEND COMPATIBILITY
                                # Frontend expects 'reputation' field, we use 'verdict'
                                # ================================================================
                                if not result.get('extracted_iocs'):
                                    result['extracted_iocs'] = []
                                    for ind in indicators:
                                        # Map 'verdict' to 'reputation' for frontend
                                        reputation = ind.get('verdict', 'unknown')
                                        # Normalize: 'internal' IPs should show as 'suspicious' in frontend
                                        if reputation == 'internal':
                                            reputation = 'suspicious'
                                        result['extracted_iocs'].append({
                                            'type': ind.get('type'),
                                            'value': ind.get('value'),
                                            'reputation': reputation,  # Frontend expects this field
                                            'confidence': ind.get('confidence'),
                                            'sources': ind.get('sources', []),
                                            'internal': ind.get('internal', False),
                                            'note': ind.get('note')
                                        })

                        # ================================================================
                        # POPULATE AI TRIAGE DATA AT TOP LEVEL
                        # Priority: final > provisional > tier1_analysis > ai_triage
                        # ================================================================
                        if ai_triage:
                            if not result.get('ai_verdict'):
                                # Prefer investigation verdicts (from deeper analysis) over initial triage
                                result['ai_verdict'] = (
                                    result.get('final_verdict')
                                    or result.get('provisional_verdict')
                                    or inv_data.get('tier1_analysis', {}).get('verdict')
                                    or ai_triage.get('verdict')
                                )
                            if not result.get('ai_confidence'):
                                result['ai_confidence'] = (
                                    result.get('final_confidence')
                                    or result.get('provisional_confidence')
                                    or inv_data.get('tier1_analysis', {}).get('confidence')
                                    or result.get('confidence')
                                    or ai_triage.get('confidence')
                                )
                            if not result.get('ai_summary'):
                                result['ai_summary'] = ai_triage.get('summary')
                            if ai_triage.get('key_findings'):
                                result['key_findings'] = ai_triage.get('key_findings')
                            if ai_triage.get('threat_type'):
                                result['threat_type'] = ai_triage.get('threat_type')
                            if ai_triage.get('recommended_actions'):
                                result['recommended_actions'] = ai_triage.get('recommended_actions')
                            # Also include full ai_triage object for frontend access
                            result['ai_triage'] = ai_triage

                            # ================================================================
                            # MERGE DECODED IOCs FROM AI ANALYSIS INTO INDICATORS
                            # These are IOCs the AI decoded from base64/encoded content
                            # ================================================================
                            decoded_iocs = ai_triage.get('decoded_iocs', {})
                            if decoded_iocs:
                                if not result.get('indicators'):
                                    result['indicators'] = []
                                if not result.get('extracted_iocs'):
                                    result['extracted_iocs'] = []

                                # Add decoded IPs
                                for ip in decoded_iocs.get('ips', []):
                                    result['indicators'].append({
                                        'type': 'ip',
                                        'value': ip,
                                        'verdict': 'suspicious',  # AI decoded = suspicious by default
                                        'confidence': 0.8,
                                        'sources': ['ai_decoded']
                                    })
                                    # Also add to extracted_iocs for frontend
                                    result['extracted_iocs'].append({
                                        'type': 'ip',
                                        'value': ip,
                                        'reputation': 'suspicious',  # Frontend expects 'reputation'
                                        'confidence': 0.8,
                                        'sources': ['ai_decoded'],
                                        'decoded': True  # Mark as decoded from encoded content
                                    })

                                # Add decoded URLs
                                for url in decoded_iocs.get('urls', []):
                                    result['indicators'].append({
                                        'type': 'url',
                                        'value': url,
                                        'verdict': 'suspicious',
                                        'confidence': 0.8,
                                        'sources': ['ai_decoded']
                                    })
                                    result['extracted_iocs'].append({
                                        'type': 'url',
                                        'value': url,
                                        'reputation': 'suspicious',
                                        'confidence': 0.8,
                                        'sources': ['ai_decoded'],
                                        'decoded': True
                                    })

                                # Add decoded domains
                                for domain in decoded_iocs.get('domains', []):
                                    result['indicators'].append({
                                        'type': 'domain',
                                        'value': domain,
                                        'verdict': 'suspicious',
                                        'confidence': 0.8,
                                        'sources': ['ai_decoded']
                                    })
                                    result['extracted_iocs'].append({
                                        'type': 'domain',
                                        'value': domain,
                                        'reputation': 'suspicious',
                                        'confidence': 0.8,
                                        'sources': ['ai_decoded'],
                                        'decoded': True
                                    })

                                # Also update ioc_summary with decoded IOCs
                                if decoded_iocs.get('ips') or decoded_iocs.get('urls') or decoded_iocs.get('domains'):
                                    if not result.get('ioc_summary'):
                                        result['ioc_summary'] = {'ips': [], 'domains': [], 'urls': [], 'hashes': [], 'emails': []}
                                    for ip in decoded_iocs.get('ips', []):
                                        if ip not in result['ioc_summary'].get('ips', []):
                                            result['ioc_summary'].setdefault('ips', []).append(ip)
                                    for domain in decoded_iocs.get('domains', []):
                                        if domain not in result['ioc_summary'].get('domains', []):
                                            result['ioc_summary'].setdefault('domains', []).append(domain)
                                    for url in decoded_iocs.get('urls', []):
                                        if url not in result['ioc_summary'].get('urls', []):
                                            result['ioc_summary'].setdefault('urls', []).append(url)

                        # ================================================================
                        # MERGE DECODED IOCs FROM TIER ANALYSIS (T1/T2)
                        # These are IOCs the agent decoded during investigation
                        # ================================================================
                        for tier_key in ['tier1_analysis', 'tier2_analysis']:
                            tier_analysis = inv_data.get(tier_key, {})
                            tier_decoded = tier_analysis.get('decoded_iocs', {})
                            if tier_decoded and any(tier_decoded.values()):
                                if not result.get('indicators'):
                                    result['indicators'] = []
                                if not result.get('extracted_iocs'):
                                    result['extracted_iocs'] = []
                                if not result.get('ioc_summary'):
                                    result['ioc_summary'] = {'ips': [], 'domains': [], 'urls': [], 'hashes': [], 'emails': []}

                                tier_label = 't1_decoded' if tier_key == 'tier1_analysis' else 't2_decoded'

                                # Add decoded IPs from tier analysis
                                for ip in tier_decoded.get('ips', []):
                                    # Skip if already added
                                    if any(ind.get('value') == ip for ind in result['indicators']):
                                        continue
                                    result['indicators'].append({
                                        'type': 'ip',
                                        'value': ip,
                                        'verdict': 'suspicious',
                                        'confidence': 0.85,
                                        'sources': [tier_label],
                                        'decoded': True,
                                        'note': f'Extracted from encoded content by {tier_key.replace("_", " ").title()}'
                                    })
                                    result['extracted_iocs'].append({
                                        'type': 'ip',
                                        'value': ip,
                                        'reputation': 'suspicious',
                                        'confidence': 0.85,
                                        'sources': [tier_label],
                                        'decoded': True
                                    })
                                    if ip not in result['ioc_summary'].get('ips', []):
                                        result['ioc_summary'].setdefault('ips', []).append(ip)

                                # Add decoded URLs from tier analysis
                                for url in tier_decoded.get('urls', []):
                                    if any(ind.get('value') == url for ind in result['indicators']):
                                        continue
                                    result['indicators'].append({
                                        'type': 'url',
                                        'value': url,
                                        'verdict': 'suspicious',
                                        'confidence': 0.85,
                                        'sources': [tier_label],
                                        'decoded': True,
                                        'note': f'Extracted from encoded content by {tier_key.replace("_", " ").title()}'
                                    })
                                    result['extracted_iocs'].append({
                                        'type': 'url',
                                        'value': url,
                                        'reputation': 'suspicious',
                                        'confidence': 0.85,
                                        'sources': [tier_label],
                                        'decoded': True
                                    })
                                    if url not in result['ioc_summary'].get('urls', []):
                                        result['ioc_summary'].setdefault('urls', []).append(url)

                                # Add decoded domains from tier analysis (filter out false positives like "System.Net")
                                for domain in tier_decoded.get('domains', []):
                                    # Skip common false positives
                                    if domain in ['System.Net', 'System', 'Net', 'localhost']:
                                        continue
                                    if any(ind.get('value') == domain for ind in result['indicators']):
                                        continue
                                    result['indicators'].append({
                                        'type': 'domain',
                                        'value': domain,
                                        'verdict': 'suspicious',
                                        'confidence': 0.85,
                                        'sources': [tier_label],
                                        'decoded': True,
                                        'note': f'Extracted from encoded content by {tier_key.replace("_", " ").title()}'
                                    })
                                    result['extracted_iocs'].append({
                                        'type': 'domain',
                                        'value': domain,
                                        'reputation': 'suspicious',
                                        'confidence': 0.85,
                                        'sources': [tier_label],
                                        'decoded': True
                                    })
                                    if domain not in result['ioc_summary'].get('domains', []):
                                        result['ioc_summary'].setdefault('domains', []).append(domain)

                        # Legacy: Process old-style iocs list
                        iocs_list = raw_event.get('iocs', [])
                        if iocs_list:
                            # Get enrichment data for all IOC values
                            ioc_values = [ioc.get('value') for ioc in iocs_list if ioc.get('value')]
                            if ioc_values:
                                enrichment_rows = await conn.fetch('''
                                    SELECT ioc_value, enrichment_data, last_enriched_at
                                    FROM iocs
                                    WHERE ioc_value = ANY($1)
                                ''', ioc_values)

                                # Build lookup map
                                enrichment_map = {}
                                for er in enrichment_rows:
                                    ed = er['enrichment_data'] or {}
                                    if isinstance(ed, str):
                                        try:
                                            ed = json.loads(ed)
                                        except:
                                            ed = {}
                                    enrichment_map[er['ioc_value']] = {
                                        'enrichment_data': ed,
                                        'last_enriched_at': er['last_enriched_at']
                                    }

                                # Merge enrichment into IOCs
                                for ioc in iocs_list:
                                    ioc_value = ioc.get('value')
                                    if ioc_value and ioc_value in enrichment_map:
                                        enrich = enrichment_map[ioc_value]
                                        ioc['enrichment_data'] = enrich['enrichment_data']
                                        ioc['last_enriched_at'] = str(enrich['last_enriched_at']) if enrich['last_enriched_at'] else None

                                        # Extract verdict from enrichment sources
                                        verdict = None
                                        for source, data in enrich['enrichment_data'].items():
                                            if isinstance(data, dict) and data.get('verdict'):
                                                v = data['verdict'].lower()
                                                if v in ['malicious', 'suspicious']:
                                                    verdict = v
                                                    break
                                                elif v == 'clean' and not verdict:
                                                    verdict = 'clean'
                                                elif v not in ['unknown', 'none', ''] and not verdict:
                                                    verdict = v
                                        ioc['verdict'] = verdict

                                # Store enriched IOCs back
                                result['extracted_iocs'] = iocs_list
                except Exception as e:
                    import traceback
                    print(f"Warning: Failed to enrich IOCs: {e}")
                    traceback.print_exc()

            # ================================================================
            # FETCH CORRELATION/CAMPAIGN DATA
            # ================================================================
            try:
                # Get campaigns this investigation is linked to
                campaign_rows = await conn.fetch(
                    """
                    SELECT c.campaign_id, c.name, c.campaign_type, c.severity,
                           c.status, c.alert_count, c.ioc_count, c.confidence,
                           cm.correlation_reason, cm.correlation_score, cm.added_at
                    FROM campaign_members cm
                    JOIN campaigns c ON c.id = cm.campaign_id
                    WHERE cm.investigation_id = $1 AND cm.member_type = 'investigation'
                    ORDER BY cm.added_at DESC
                    """,
                    result['id']
                )

                if campaign_rows:
                    result['campaigns'] = []
                    for camp_row in campaign_rows:
                        result['campaigns'].append({
                            'campaign_id': camp_row['campaign_id'],
                            'name': camp_row['name'],
                            'campaign_type': camp_row['campaign_type'],
                            'severity': camp_row['severity'],
                            'status': camp_row['status'],
                            'alert_count': camp_row['alert_count'],
                            'ioc_count': camp_row['ioc_count'],
                            'confidence': float(camp_row['confidence']) if camp_row['confidence'] else None,
                            'correlation_reason': camp_row['correlation_reason'],
                            'correlation_score': float(camp_row['correlation_score']) if camp_row['correlation_score'] else None,
                            'added_at': str(camp_row['added_at']) if camp_row['added_at'] else None
                        })

                # Get related alerts from same campaigns (for correlation context)
                if result.get('campaigns'):
                    campaign_ids = [c['campaign_id'] for c in result['campaigns']]
                    related_alerts = await conn.fetch(
                        """
                        SELECT DISTINCT a.alert_id, a.title, a.severity, a.status, a.created_at
                        FROM campaign_members cm
                        JOIN campaigns c ON c.id = cm.campaign_id
                        JOIN alerts a ON a.id = cm.alert_id
                        WHERE c.campaign_id = ANY($1)
                          AND cm.member_type = 'alert'
                          AND a.id != $2
                        ORDER BY a.created_at DESC
                        LIMIT 10
                        """,
                        campaign_ids,
                        result.get('alert_id')
                    )

                    if related_alerts:
                        result['related_alerts'] = [
                            {
                                'alert_id': ra['alert_id'],
                                'title': ra['title'],
                                'severity': ra['severity'],
                                'status': ra['status'],
                                'created_at': str(ra['created_at']) if ra['created_at'] else None
                            }
                            for ra in related_alerts
                        ]

                # Get correlation events involving this investigation's alert
                if result.get('alert_id'):
                    corr_events = await conn.fetch(
                        """
                        SELECT ce.rule_name, ce.correlation_type, ce.correlation_score,
                               ce.ioc_values, ce.created_at, c.campaign_id as campaign_code
                        FROM correlation_events ce
                        LEFT JOIN campaigns c ON c.id = ce.campaign_id
                        WHERE $1::uuid = ANY(ce.alert_ids)
                        ORDER BY ce.created_at DESC
                        LIMIT 5
                        """,
                        result['alert_id']
                    )

                    if corr_events:
                        result['correlation_events'] = [
                            {
                                'rule_name': ce['rule_name'],
                                'correlation_type': ce['correlation_type'],
                                'correlation_score': float(ce['correlation_score']) if ce['correlation_score'] else None,
                                'ioc_values': ce['ioc_values'],
                                'campaign_id': ce['campaign_code'],
                                'created_at': str(ce['created_at']) if ce['created_at'] else None
                            }
                            for ce in corr_events
                        ]

            except Exception as corr_err:
                logger.debug(f"Failed to fetch correlation data: {corr_err}")

            return result
    
    async def update_investigation_field(
        self,
        investigation_id: str,
        field: str,
        value: Any
    ) -> bool:
        """Update investigation field (state, disposition, priority, owner, severity)"""
        allowed_fields = ['state', 'disposition', 'priority', 'owner', 'executive_summary', 'severity', 'sensitivity']
        if field not in allowed_fields:
            raise ValueError(f"Field {field} not allowed for update")

        async with self.tenant_acquire() as conn:
            query = f'UPDATE investigations SET {field} = $1 WHERE investigation_id = $2'
            result = await conn.execute(query, value, investigation_id)
            
            # If closing investigation, set completed_at
            if field == 'state' and value in ['RESOLVED', 'CLOSED']:
                await conn.execute(
                    'UPDATE investigations SET completed_at = CURRENT_TIMESTAMP WHERE investigation_id = $1',
                    investigation_id
                )
            
            # If assigning owner, set assigned_at
            if field == 'owner' and value:
                await conn.execute(
                    'UPDATE investigations SET assigned_at = CURRENT_TIMESTAMP WHERE investigation_id = $1',
                    investigation_id
                )
            
            return result == 'UPDATE 1'
    
    # ========================================================================
    # INVESTIGATION NOTES
    # ========================================================================
    
    async def add_investigation_note(
        self,
        investigation_id: str,
        author: str,
        content: str,
        note_type: str = 'HUMAN_NOTE',
        author_type: str = 'HUMAN'
    ) -> str:
        """Add note to investigation"""
        async with self.tenant_acquire() as conn:
            # The table uses investigation_id as VARCHAR, not UUID reference
            row = await conn.fetchrow('''
                INSERT INTO investigation_notes (investigation_id, author, author_type, content, note_type)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id
            ''', investigation_id, author, author_type, content, note_type)
            
            return str(row['id'])
    
    async def get_investigation_notes(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Get all notes for investigation"""
        async with self.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT *
                FROM investigation_notes
                WHERE investigation_id = $1
                ORDER BY created_at DESC
            ''', investigation_id)
            
            return [dict(row) for row in rows]
    
    # ========================================================================
    # IOCS
    # ========================================================================
    
    async def track_ioc(self, ioc_data: Dict[str, Any]) -> str:
        """Track or update IOC"""
        async with self.tenant_acquire() as conn:
            # Check if IOC exists
            existing = await conn.fetchrow(
                'SELECT id, occurrences FROM iocs WHERE ioc_value = $1 AND ioc_type = $2',
                ioc_data['ioc_value'], ioc_data['ioc_type']
            )
            
            if existing:
                # Update existing IOC
                await conn.execute('''
                    UPDATE iocs 
                    SET last_seen = CURRENT_TIMESTAMP,
                        occurrences = occurrences + 1,
                        enrichment_data = $1
                    WHERE id = $2
                ''', 
                    json.dumps(ioc_data.get('enrichment_data', {})),
                    existing['id']
                )
                return str(existing['id'])
            else:
                # Create new IOC — include tenant_id for RLS
                from middleware.tenant_middleware import get_current_tenant_id
                import uuid as uuid_mod
                try:
                    tid = uuid_mod.UUID(get_current_tenant_id())
                except Exception:
                    from config.constants import PLATFORM_OWNER_TENANT_ID
                    tid = uuid_mod.UUID(PLATFORM_OWNER_TENANT_ID)
                row = await conn.fetchrow('''
                    INSERT INTO iocs (
                        ioc_value, ioc_type, severity, confidence,
                        reputation, source, tags, enrichment_data,
                        tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    RETURNING id
                ''',
                    ioc_data['ioc_value'],
                    ioc_data['ioc_type'],
                    ioc_data.get('severity'),
                    ioc_data.get('confidence'),
                    ioc_data.get('reputation'),
                    ioc_data.get('source'),
                    ioc_data.get('tags', []),
                    json.dumps(ioc_data.get('enrichment_data', {})),
                    tid
                )
                return str(row['id'])
    
    async def get_iocs(
        self,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get IOCs with filters"""
        async with self.tenant_acquire() as conn:
            query_parts = ['SELECT * FROM iocs WHERE 1=1']
            params = []
            param_count = 1
            
            if ioc_type:
                query_parts.append(f'AND ioc_type = ${param_count}')
                params.append(ioc_type)
                param_count += 1
            
            if severity:
                query_parts.append(f'AND severity = ${param_count}')
                params.append(severity)
                param_count += 1
            
            query_parts.append(f'ORDER BY last_seen DESC LIMIT ${param_count}')
            params.append(limit)
            
            query = ' '.join(query_parts)
            rows = await conn.fetch(query, *params)
            
            return [dict(row) for row in rows]
    
    # ========================================================================
    # AUDIT LOG
    # ========================================================================
    
    async def log_audit(
        self,
        username: str,
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log audit event"""
        async with self.tenant_acquire() as conn:
            from middleware.tenant_middleware import get_optional_tenant_id
            import uuid as _uuid
            _tenant_id = get_optional_tenant_id()

            # Get user UUID
            user_uuid = await conn.fetchval(
                'SELECT id FROM users WHERE username = $1',
                username
            )

            await conn.execute('''
                INSERT INTO audit_log (
                    user_id, username, action, resource_type, resource_id, details, tenant_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ''',
                user_uuid,
                username,
                action,
                resource_type,
                resource_id,
                json.dumps(details or {}),
                _uuid.UUID(str(_tenant_id)) if _tenant_id else None
            )

    async def get_system_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get system/audit logs"""
        async with self.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT
                    id,
                    username,
                    action,
                    resource_type,
                    resource_id,
                    details,
                    ip_address,
                    user_agent,
                    created_at
                FROM audit_log
                ORDER BY created_at DESC
                LIMIT $1
            ''', limit)

            results = []
            for row in rows:
                record = dict(row)
                # Convert datetime to ISO string
                if record.get('created_at'):
                    record['created_at'] = record['created_at'].isoformat()
                # Convert UUID to string
                if record.get('id'):
                    record['id'] = str(record['id'])
                # Parse JSON details if needed
                if record.get('details'):
                    if isinstance(record['details'], str):
                        try:
                            record['details'] = json.loads(record['details'])
                        except:
                            pass
                # Convert inet to string
                if record.get('ip_address'):
                    record['ip_address'] = str(record['ip_address'])
                results.append(record)

            return results

    # ========================================================================
    # USER PREFERENCES
    # ========================================================================

    async def get_user_preferences(self, username: str) -> Dict[str, Any]:
        """Get user preferences"""
        async with self.tenant_acquire() as conn:
            row = await conn.fetchrow(
                'SELECT preferences FROM user_preferences WHERE username = $1',
                username
            )
            if row and row['preferences']:
                prefs = row['preferences']
                if isinstance(prefs, str):
                    try:
                        return json.loads(prefs)
                    except:
                        return {}
                return prefs
            return {}

    async def save_user_preferences(self, username: str, preferences: Dict[str, Any]) -> bool:
        """Save user preferences (upsert)"""
        async with self.tenant_acquire() as conn:
            try:
                # Get user UUID
                user_uuid = await conn.fetchval(
                    'SELECT id FROM users WHERE username = $1',
                    username
                )

                await conn.execute('''
                    INSERT INTO user_preferences (user_id, username, preferences, updated_at)
                    VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
                    ON CONFLICT (username)
                    DO UPDATE SET
                        preferences = $3,
                        updated_at = CURRENT_TIMESTAMP
                ''',
                    user_uuid,
                    username,
                    json.dumps(preferences)
                )
                return True
            except Exception as e:
                logger.error(f"Failed to save user preferences: {e}")
                return False

    async def update_user_preference(self, username: str, key: str, value: Any) -> bool:
        """Update a single preference key"""
        prefs = await self.get_user_preferences(username)
        prefs[key] = value
        return await self.save_user_preferences(username, prefs)

    # ========================================================================
    # INTEGRATION STATE (for persisting enabled/credential state across restarts)
    # ========================================================================

    async def save_integration_state(
        self,
        integration_id: str,
        enabled: bool,
        credential_id: Optional[str] = None,
        base_url: Optional[str] = None,
        config: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Save integration state to database (upsert)"""
        async with self.tenant_acquire() as conn:
            try:
                await conn.execute('''
                    INSERT INTO integration_state (integration_id, enabled, credential_id, base_url, config, updated_at)
                    VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
                    ON CONFLICT (integration_id)
                    DO UPDATE SET
                        enabled = $2,
                        credential_id = $3,
                        base_url = $4,
                        config = $5,
                        updated_at = CURRENT_TIMESTAMP
                ''',
                    integration_id,
                    enabled,
                    credential_id,
                    base_url,
                    json.dumps(config or {})
                )
                logger.info(f"Saved integration state: {integration_id} enabled={enabled} credential_id={credential_id}")
                return True
            except Exception as e:
                logger.error(f"Failed to save integration state for {integration_id}: {e}")
                return False

    async def get_all_integration_states(self) -> List[Dict[str, Any]]:
        """Get all saved integration states for loading on startup"""
        async with self.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT integration_id, enabled, credential_id, base_url, config
                FROM integration_state
            ''')
            return [dict(row) for row in rows]

    async def get_integration_state(self, integration_id: str) -> Optional[Dict[str, Any]]:
        """Get saved state for a specific integration"""
        async with self.tenant_acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM integration_state WHERE integration_id = $1',
                integration_id
            )
            return dict(row) if row else None

    async def delete_integration_state(self, integration_id: str) -> bool:
        """Delete saved state for an integration (when user removes it)"""
        async with self.tenant_acquire() as conn:
            try:
                result = await conn.execute(
                    'DELETE FROM integration_state WHERE integration_id = $1',
                    integration_id
                )
                deleted = result.split()[-1] != '0'
                if deleted:
                    logger.info(f"Deleted integration state: {integration_id}")
                return deleted
            except Exception as e:
                logger.error(f"Failed to delete integration state for {integration_id}: {e}")
                return False


# Global instance
postgres_db = PostgresDB()


async def get_pool():
    """Get the database connection pool."""
    if postgres_db.connected and postgres_db.pool:
        return postgres_db.pool
    return None


def get_postgres_db() -> PostgresDB:
    """Get the global PostgresDB instance."""
    return postgres_db
