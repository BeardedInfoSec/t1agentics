# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics FastAPI Application
Main entry point for the backend API.
"""

import asyncio
import logging
import sys

# Configure structured logging before anything else
from config.logging_config import setup_logging
setup_logging()

# Set log levels for our modules
logging.getLogger('routes').setLevel(logging.INFO)
logging.getLogger('services').setLevel(logging.INFO)
logging.getLogger('routes.webhooks').setLevel(logging.INFO)
logging.getLogger('services.ioc_correlation_engine').setLevel(logging.INFO)

from fastapi import FastAPI, HTTPException, BackgroundTasks, Body, Header, Depends, Query, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from dependencies.auth import get_current_user as auth_get_current_user
from pydantic import BaseModel
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from typing import Dict, List, Optional, Any
import uuid
import secrets
import os
import re
import socket
import time
from datetime import datetime, timedelta
from collections import defaultdict

from models import (
    Alert, InvestigationResult, SeverityLevel,
    DispositionType, ConfidenceLevel
)
from utils.extractors import IndicatorExtractor, normalize_alert
from agents.planner import AgentPlanner
from routes.webhooks import router as webhooks_router
from routes.admin import router as admin_router
from routes.documentation import router as docs_router
from routes.forms import router as forms_router
from routes.credentials import router as credentials_router
from routes.actions import router as actions_router
from routes.connect import router as connect_router
from routes.token_usage import router as token_usage_router
from routes.threat_intel import router as threat_intel_router
from routes.ioc_management import router as ioc_management_router
from routes.threat_feeds import router as threat_feeds_router
try:
    from routes.breach_intel import router as breach_intel_router
except ImportError:
    breach_intel_router = None
from routes.threat_feed_upload import router as threat_feed_upload_router
from routes.correlation import router as correlation_router
from routes.pii_settings import router as pii_settings_router
from routes.knowledge_base import router as knowledge_base_router
from routes.playbooks import router as playbooks_router
from routes.playbook_forms import router as playbook_forms_router, public_router as playbook_public_forms_router
from routes.intake_forms import router as intake_forms_router
from routes.tenant_llm_context import router as tenant_llm_context_router
from routes.tenant_triage_config import router as tenant_triage_config_router
from routes.tenant_ai_config import router as tenant_ai_config_router
from routes.tenant_pii_patterns import router as tenant_pii_patterns_router
from routes.playbook_converters import router as playbook_converters_router
from routes.mfa import router as mfa_router
from routes.riggs_assist import router as riggs_assist_router
from routes.recommended_actions import router as recommended_actions_router
from routes.investigation_notes import router as investigation_notes_router
from services.postgres_db import postgres_db


# In-memory storage for investigations (use database in production)
investigations_store: Dict[str, InvestigationResult] = {}
alerts_store: Dict[str, Alert] = {}


# ============================================================================
# BULK OPERATION RATE LIMITING
# ============================================================================

class BulkOperationRateLimiter:
    """
    Rate limiter for bulk operations to prevent abuse.
    Per-user limit of 10 bulk requests per minute.
    """

    def __init__(self):
        # Track requests per user: {user_id: [(timestamp, request_count), ...]}
        self.user_requests: Dict[str, List[tuple]] = defaultdict(list)
        self.max_requests_per_minute = 10
        self.window_seconds = 60

    def check_limit(self, user_id: str) -> bool:
        """
        Check if user has exceeded rate limit.
        Returns True if request is allowed, False if rate limited.
        """
        current_time = time.time()
        window_start = current_time - self.window_seconds

        # Clean old requests outside the window
        if user_id in self.user_requests:
            self.user_requests[user_id] = [
                (timestamp, count) for timestamp, count in self.user_requests[user_id]
                if timestamp > window_start
            ]

        # Count requests in current window
        total_requests = sum(count for _, count in self.user_requests[user_id])

        # Check if under limit
        if total_requests >= self.max_requests_per_minute:
            return False

        # Record this request
        if user_id in self.user_requests and self.user_requests[user_id]:
            # Update the last request's count
            self.user_requests[user_id][-1] = (current_time, total_requests + 1)
        else:
            # First request in window
            self.user_requests[user_id].append((current_time, 1))

        return True

    def reset(self, user_id: Optional[str] = None):
        """Reset rate limit tracking for testing"""
        if user_id:
            self.user_requests.pop(user_id, None)
        else:
            self.user_requests.clear()


# Global rate limiter instance
_bulk_rate_limiter = BulkOperationRateLimiter()


def get_bulk_rate_limiter() -> BulkOperationRateLimiter:
    """Get the global bulk operation rate limiter"""
    return _bulk_rate_limiter


def validate_security_config():
    """
    Validate critical security configuration at startup.
    Logs warnings for insecure configurations in production mode.
    """
    environment = os.getenv('ENVIRONMENT', 'development')
    is_production = environment.lower() in ('production', 'prod')
    warnings = []
    critical_errors = []

    # Check JWT_SECRET_KEY
    jwt_secret = os.getenv('JWT_SECRET_KEY', '')
    if not jwt_secret or jwt_secret == 'your-secret-key-change-in-production':
        if is_production:
            critical_errors.append(
                "JWT_SECRET_KEY is not set or uses default value. "
                "Set a strong secret key via environment variable."
            )
        else:
            warnings.append("JWT_SECRET_KEY uses default value (OK for development)")

    # Check POSTGRES_PASSWORD
    db_password = os.getenv('POSTGRES_PASSWORD', '')
    default_db_passwords = ['agentcore_dev_password', 't1agentics_dev_password', 'postgres']
    if not db_password or db_password in default_db_passwords:
        if is_production:
            critical_errors.append(
                "POSTGRES_PASSWORD is not set or uses a default value. "
                "Set a strong password via environment variable."
            )
        else:
            warnings.append("POSTGRES_PASSWORD uses default value (OK for development)")

    # Check CREDENTIALS_ENCRYPTION_KEY
    cred_key = os.getenv('CREDENTIALS_ENCRYPTION_KEY', '')
    if not cred_key:
        if is_production:
            critical_errors.append(
                "CREDENTIALS_ENCRYPTION_KEY is not set. "
                "Set a Fernet key for secure credential storage."
            )
        else:
            warnings.append("CREDENTIALS_ENCRYPTION_KEY not set - will use generated key")

    # Check ADMIN_PASSWORD
    admin_password = os.getenv('ADMIN_PASSWORD', '')
    if not admin_password:
        if is_production:
            critical_errors.append(
                "ADMIN_PASSWORD is not set. "
                "Set an admin password via environment variable."
            )
        else:
            warnings.append("ADMIN_PASSWORD not set (OK for development)")

    # Print results
    logger.info("=" * 60)
    logger.info("SECURITY CONFIGURATION CHECK")
    logger.info("=" * 60)
    logger.info(f"Environment: {environment.upper()}")

    if critical_errors:
        logger.critical("\n[CRITICAL] Security configuration errors:")
        for error in critical_errors:
            logger.info(f"  - {error}")
        if is_production:
            logger.critical("\n*** REFUSING TO START IN PRODUCTION WITH INSECURE CONFIGURATION ***")
            logger.info("Fix the above errors and restart.")
            sys.exit(1)

    if warnings:
        logger.info("\n[WARNING] Development configuration detected:")
        for warning in warnings:
            logger.info(f"  - {warning}")

    if not critical_errors and not warnings:
        logger.info("[OK] All security configurations properly set")

    logger.info("=" * 60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle management for the application"""
    logger.info("T1 Agentics starting up...")

    # Validate security configuration
    validate_security_config()
    
    # Initialize PostgreSQL (PRIMARY DATABASE)
    try:
        from services.postgres_db import postgres_db
        logger.info("=" * 60)
        logger.info("INITIALIZING POSTGRESQL")
        logger.info("=" * 60)
        await postgres_db.connect()
        logger.info("=" * 60)
        logger.info("POSTGRESQL INITIALIZATION COMPLETE")
        logger.info("=" * 60)

        # Load enrichment-relevant integrations (threat_intel, enrichment, sandbox)
        # into the in-memory registry so threat_intel_service can discover providers
        try:
            from services.integration_loader import load_integrations_into_registry
            int_count = load_integrations_into_registry()
            logger.info(f"[OK] Integration registry: {int_count} enrichment integrations loaded")
        except Exception as e:
            logger.warning(f"[WARN] Integration registry load error: {e}")

    except Exception as e:
        logger.info("=" * 60)
        logger.error("POSTGRESQL CONNECTION FAILED!")
        logger.info("=" * 60)
        _startup_logger = logging.getLogger("app.startup")
        _startup_logger.error(f"Startup error ({type(e).__name__}): {e}", exc_info=True)
        environment = os.getenv('ENVIRONMENT', 'development').lower()
        if environment in ('production', 'prod'):
            logger.critical("*** REFUSING TO START WITHOUT DATABASE IN PRODUCTION ***")
            sys.exit(1)
        logger.info("   Continuing without PostgreSQL...")
        logger.info("=" * 60)
    
    # PostgreSQL handles all user creation in bootstrap_users()
    # MongoDB is NO LONGER USED - all data in PostgreSQL
    
    # Initialize postgres-dependent services
    try:
        from services.startup import init_postgres_dependent_services
        from services.postgres_db import postgres_db
        await init_postgres_dependent_services(app, postgres_db)
    except Exception as e:
        logger.info(f"Postgres dependent service init error: {e}")

    # Load token blacklist from database (persist revocations across restarts)
    try:
        from services.token_blacklist import get_token_blacklist
        await get_token_blacklist().load_from_db()
        logger.info("[OK] Token blacklist loaded from database")
    except Exception as e:
        logger.warning(f"[WARN] Token blacklist load error: {e}")

    # T1 Connect: Load builtin connector catalog into database
    try:
        from services.connect_service import get_connect_service
        connect_svc = get_connect_service()
        connect_count = await connect_svc.load_builtin_catalog()
        logger.info(f"[OK] T1 Connect: {connect_count} builtin connectors loaded into marketplace")
    except Exception as e:
        logger.warning(f"[WARN] T1 Connect catalog load error: {e}")

    # Load builtin playbook templates into marketplace
    try:
        from services.playbook_catalog_service import playbook_catalog
        pb_count = await playbook_catalog.load_builtin_catalog()
        logger.info(f"[OK] Playbook Marketplace: {pb_count} builtin templates loaded")
    except Exception as e:
        logger.warning(f"[WARN] Playbook catalog load error: {e}")

    # Initialize ClickHouse telemetry schema
    try:
        from services.telemetry_service import telemetry_service
        if telemetry_service.init_schema():
            logger.info("[OK] ClickHouse UX telemetry schema initialized")
        else:
            logger.warning("[WARN] ClickHouse unavailable, UX telemetry will log to stdout")
    except Exception as e:
        logger.warning(f"[WARN] ClickHouse telemetry init error: {e}")

    # Start polling scheduler (uses PostgreSQL)
    try:
        from services.alert_ingestion import AlertIngestionService
        from services.scheduler import PollingScheduler
        from services.postgres_db import postgres_db
        
        if postgres_db.connected:
            logger.info("Initializing polling scheduler...")
            ingestion_service = AlertIngestionService(postgres_db)
            scheduler = PollingScheduler(postgres_db, ingestion_service)
            await scheduler.start()

            # Store scheduler in app state for access in routes
            app.state.scheduler = scheduler
            app.state.ingestion_service = ingestion_service
        else:
            logger.info("Scheduler not started (database not connected)")

    except Exception as e:
        logger.info(f"Scheduler initialization error: {e}")

    # Start playbook cron scheduler
    try:
        from services.playbook_scheduler import PlaybookScheduler
        from services.postgres_db import postgres_db

        if postgres_db.connected:
            logger.info("Initializing playbook scheduler...")
            playbook_scheduler = PlaybookScheduler(postgres_db)
            await playbook_scheduler.start()
            app.state.playbook_scheduler = playbook_scheduler
        else:
            logger.info("Playbook scheduler not started (database not connected)")
    except Exception as e:
        logger.info(f"Playbook scheduler initialization error: {e}")

    # Start integration update scheduler
    try:
        from services.update_scheduler import start_scheduler
        await start_scheduler()
        logger.info("Integration Update Scheduler started")
    except Exception as e:
        logger.info(f"Integration update scheduler error: {e}")

    # Start daily cost summary scheduler (admin email digest)
    try:
        from services.cost_summary_scheduler import CostSummaryScheduler
        from services.postgres_db import postgres_db

        if postgres_db.connected:
            cost_summary_scheduler = CostSummaryScheduler()
            await cost_summary_scheduler.start()
            app.state.cost_summary_scheduler = cost_summary_scheduler
            logger.info("Daily cost summary scheduler started")
        else:
            logger.info("Cost summary scheduler not started (database not connected)")
    except Exception as e:
        logger.info(f"Cost summary scheduler initialization error: {e}")

    # Start enrichment queue (catches missed enrichments)
    try:
        from services.enrichment_queue import start_enrichment_queue
        await start_enrichment_queue()
        logger.info("Enrichment Queue Service started (catches missed IOC enrichments)")
    except Exception as e:
        logger.info(f"Enrichment queue error: {e}")

    # Initialize job queue for agent processing
    try:
        from services.job_queue import get_job_queue_service, register_agent_handlers, QueueName
        from services.postgres_db import postgres_db

        if postgres_db.connected:
            job_queue = await get_job_queue_service()
            job_queue.set_db(postgres_db)

            # Register agent job handlers
            await register_agent_handlers(job_queue)

            # Start background workers for agent and enrichment queues
            # Workers should match LLM_MAX_CONCURRENT_REQUESTS for optimal throughput
            import os as _os
            workers_per_queue = int(_os.getenv('JOB_QUEUE_WORKERS', _os.getenv('LLM_MAX_CONCURRENT_REQUESTS', '2')))
            await job_queue.start_workers(
                queues=[QueueName.AGENT, QueueName.ENRICHMENT],
                workers_per_queue=workers_per_queue
            )
            logger.info(f"[OK] Job queue workers: {workers_per_queue} per queue (AGENT + ENRICHMENT)")

            app.state.job_queue = job_queue
            logger.info("[OK] Job Queue Service started with agent handlers")

            # Start Agent Scheduler (auto-queues untriaged events)
            from services.agent_scheduler import start_agent_scheduler, get_agent_scheduler
            agent_scheduler = await start_agent_scheduler()
            app.state.agent_scheduler = agent_scheduler
            triage_status = "enabled" if agent_scheduler.config.auto_triage_enabled else "DISABLED (Riggs-only mode)"
            logger.info(f"[OK] Agent Scheduler started (auto-triage: {triage_status})")

            # Seed welcome notifications for tenants that have none
            try:
                from routes.notifications import create_notification
                from services.postgres_db import set_platform_admin_mode
                set_platform_admin_mode(True)
                try:
                    async with postgres_db.pool.acquire() as conn:
                        tenants_without_notifs = await conn.fetch('''
                            SELECT t.id FROM tenants t
                            WHERE NOT EXISTS (
                                SELECT 1 FROM notifications n WHERE n.tenant_id = t.id
                            )
                        ''')
                    for t in tenants_without_notifs:
                        tid = str(t['id'])
                        await create_notification(
                            tenant_id=tid,
                            title="Welcome to T1 Agentics",
                            message="Your SOC platform is ready. Start by configuring integrations in Connect.",
                            category="system",
                            severity="info",
                            link="/connect",
                        )
                        await create_notification(
                            tenant_id=tid,
                            title="274+ Knowledge Base Articles Available",
                            message="Browse SOPs, integration guides, and best practices in the Knowledge Base.",
                            category="system",
                            severity="info",
                            link="/knowledge-base",
                        )
                        await create_notification(
                            tenant_id=tid,
                            title="Explore the Playbook Marketplace",
                            message="Install pre-built playbooks for phishing, malware, threat intel, and more.",
                            category="system",
                            severity="info",
                            link="/playbook-marketplace",
                        )
                    if tenants_without_notifs:
                        logger.info(f"[OK] Welcome notifications seeded for {len(tenants_without_notifs)} tenant(s)")
                finally:
                    set_platform_admin_mode(False)
            except Exception as e:
                logger.warning(f"[WARN] Seed notifications skipped: {e}")

            # Auto-configure Ollama AI Provider if environment variables are set
            try:
                ollama_host = _os.getenv('OLLAMA_HOST')
                ollama_port = _os.getenv('OLLAMA_PORT', '11434')
                ollama_model = _os.getenv('OLLAMA_MODEL', 'llama3.1:8b')

                if ollama_host:
                    ollama_url = f"http://{ollama_host}:{ollama_port}/v1"

                    async with postgres_db.pool.acquire() as conn:
                        # Check if Ollama provider already exists
                        existing = await conn.fetchrow(
                            "SELECT id FROM ai_providers WHERE name = 'Ollama (Local)'"
                        )

                        if not existing:
                            # Create Ollama provider
                            import json as json_mod
                            models_json = json_mod.dumps([{"id": ollama_model, "name": ollama_model}])

                            await conn.execute("""
                                INSERT INTO ai_providers
                                (name, provider_type, base_url, api_key, models, selected_model,
                                 tier1_model, tier2_model, tier3_model, chat_model, is_default, enabled, created_at)
                                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW())
                            """,
                                'Ollama (Local)',
                                'openai_compatible',
                                ollama_url,
                                '',  # No API key needed for local Ollama
                                models_json,
                                ollama_model,
                                ollama_model,  # tier1
                                ollama_model,  # tier2
                                ollama_model,  # tier3
                                ollama_model,  # chat (Riggs)
                                True,  # is_default
                                True   # enabled
                            )
                            logger.info(f"[OK] Ollama AI Provider auto-configured: {ollama_url} (model: {ollama_model})")
                        else:
                            # Update existing Ollama provider URL in case it changed
                            await conn.execute("""
                                UPDATE ai_providers
                                SET base_url = $1, is_default = true, enabled = true
                                WHERE name = 'Ollama (Local)'
                            """, ollama_url)
                            logger.info(f"[OK] Ollama AI Provider updated: {ollama_url}")

                        # Ensure Ollama is set as default (disable other defaults)
                        await conn.execute("""
                            UPDATE ai_providers SET is_default = false
                            WHERE name != 'Ollama (Local)' AND is_default = true
                        """)
            except Exception as ollama_err:
                logger.warning(f"[WARN] Ollama auto-config failed: {ollama_err}")

            # Start Smart Enrichment Scheduler
            from services.smart_enrichment_scheduler import get_smart_enrichment_scheduler
            smart_scheduler = get_smart_enrichment_scheduler()
            await smart_scheduler.start()
            app.state.smart_enrichment_scheduler = smart_scheduler
            logger.info("[OK] Smart Enrichment Scheduler started")

            # Start Threat Feed Polling Scheduler
            from services.threat_feed_service import get_threat_feed_service
            threat_feed_service = get_threat_feed_service()
            await threat_feed_service.start_polling()
            app.state.threat_feed_service = threat_feed_service
            logger.info("[OK] Threat Feed Scheduler started")

            # Start Breach Intel RSS Feed Polling
            try:
                from services.breach_intel_service import get_breach_intel_service
                breach_intel_service = get_breach_intel_service()
                await breach_intel_service.start_polling()
                app.state.breach_intel_service = breach_intel_service
                logger.info("[OK] Breach Intel RSS Feed Scheduler started")
            except Exception as e:
                logger.warning(f"[WARN] Breach Intel RSS Feed failed to start: {e}")

            # Start Inbound Email Polling (phishing mailbox)
            try:
                from services.inbound_email_service import get_inbound_email_service
                inbound_email_service = get_inbound_email_service()
                inbound_email_service.set_db(postgres_db)
                await inbound_email_service.initialize()
                app.state.inbound_email_service = inbound_email_service
                logger.info("[OK] Inbound Email Service started (auto-polling enabled mailboxes)")
            except Exception as e:
                logger.warning(f"[WARN] Inbound Email Service failed to start: {e}")

            # Telemetry service removed (UEBA/event logs disabled)


    except Exception as e:
        logging.getLogger("app.startup").error(f"Job queue initialization error: {e}", exc_info=True)

    # Clean up expired approval tokens on startup
    try:
        from services.approval_service import get_approval_service
        from services.postgres_db import postgres_db

        if postgres_db.connected:
            approval_service = get_approval_service()
            approval_service.set_db(postgres_db)
            cleaned = await approval_service.cleanup_expired_tokens()
            if cleaned > 0:
                logger.info(f"[OK] Cleaned up {cleaned} expired approval tokens")
            else:
                logger.info("[OK] Approval tokens: no expired tokens to clean")
    except Exception as e:
        logger.info(f"Approval token cleanup error: {e}")

    # Initialize Action Request Service
    try:
        from services.action_request_service import init_action_request_service
        from services.postgres_db import postgres_db

        if postgres_db.connected:
            action_request_service = await init_action_request_service(postgres_db)
            app.state.action_request_service = action_request_service
            logger.info("[OK] Action Request Service initialized")

            # Register response action handlers for real integration execution
            try:
                from services.response_action_handlers import register_response_handlers
                await register_response_handlers(action_request_service)
                logger.info("[OK] Response Action Handlers registered")
            except Exception as handler_err:
                logger.warning(f"[WARN] Response handler registration error: {handler_err}")
    except Exception as e:
        logger.info(f"Action Request Service initialization error: {e}")

    # Initialize Chat Service (Phase 6)
    try:
        from services.chat_service import init_chat_service
        from services.postgres_db import postgres_db

        if postgres_db.connected:
            chat_service = await init_chat_service(postgres_db)
            app.state.chat_service = chat_service

            # Register WebSocket broadcast handler
            try:
                from websocket.chat_handler import on_chat_message
                chat_service.register_message_handler(on_chat_message)
            except ImportError:
                pass

            logger.info("[OK] Chat Service initialized")
    except Exception as e:
        logger.info(f"Chat Service initialization error: {e}")

    # Initialize Chat Analytics Service (Phase 6 - Audit)
    try:
        from services.chat_analytics_service import init_chat_analytics_service
        from services.postgres_db import postgres_db

        if postgres_db.connected:
            chat_analytics_service = await init_chat_analytics_service(postgres_db)
            app.state.chat_analytics_service = chat_analytics_service
            logger.info("[OK] Chat Analytics Service initialized")
    except Exception as e:
        logger.info(f"Chat Analytics Service initialization error: {e}")

    # Intake-form attachment TTL sweeper. Hourly tick that removes
    # attachments past their 14-day expiry from disk + marks deleted_at.
    try:
        from services.intake_upload_storage import cleanup_loop as intake_upload_cleanup_loop
        intake_upload_task = asyncio.create_task(intake_upload_cleanup_loop())
        app.state.intake_upload_cleanup_task = intake_upload_task
        logger.info("[OK] Intake-form attachment cleanup loop started")
    except Exception as e:
        logger.warning(f"Intake-form cleanup loop init error: {e}")

    # Proactive Claude-quota warning sweep. Every 30 min, scans tenants
    # who crossed 80% / 100% of their managed-tokens cap this period
    # and emails the admin once per threshold per month. Replaces the
    # old post-hoc warning that fired on the response of the call that
    # crossed the threshold.
    try:
        from services.quota_warning_loop import cleanup_loop as quota_warning_loop
        quota_task = asyncio.create_task(quota_warning_loop())
        app.state.quota_warning_task = quota_task
        logger.info("[OK] Proactive quota warning loop started")
    except Exception as e:
        logger.warning(f"Quota warning loop init error: {e}")

    # Entity risk decay loop — without this, scores only grow and every
    # entity eventually trips the threshold. Hourly cadence; cheap.
    try:
        from services.entity_risk_decay_loop import cleanup_loop as entity_risk_decay_loop
        decay_task = asyncio.create_task(entity_risk_decay_loop())
        app.state.entity_risk_decay_task = decay_task
        logger.info("[OK] Entity risk decay loop started")
    except Exception as e:
        logger.warning(f"Entity risk decay loop init error: {e}")

    # One-shot: encrypt any legacy plaintext ai_providers.api_key values
    # left over from the pre-encryption era (idempotent — skips rows that
    # already have api_key_encrypted set). Safe to call every startup.
    try:
        from routes.ai_providers import backfill_ai_providers_encryption
        encrypted_count = await backfill_ai_providers_encryption()
        if encrypted_count:
            logger.info(f"[OK] Encrypted {encrypted_count} legacy ai_providers key(s)")
    except Exception as e:
        logger.warning(f"[WARN] ai_providers encryption backfill failed: {e}")

    yield

    # Cleanup
    logger.info("Shutting down services...")

    # Stop threat feed scheduler
    try:
        if hasattr(app.state, 'threat_feed_service'):
            await app.state.threat_feed_service.stop_polling()
            logger.info("Threat Feed Scheduler stopped")
    except Exception as e:
        logger.info(f"Threat feed scheduler shutdown error: {e}")

    # Stop smart enrichment scheduler
    try:
        if hasattr(app.state, 'smart_enrichment_scheduler'):
            await app.state.smart_enrichment_scheduler.stop()
            logger.info("Smart Enrichment Scheduler stopped")
    except Exception as e:
        logger.info(f"Smart enrichment scheduler shutdown error: {e}")

    # Stop cost summary scheduler
    try:
        if hasattr(app.state, 'cost_summary_scheduler'):
            await app.state.cost_summary_scheduler.stop()
            logger.info("Cost Summary Scheduler stopped")
    except Exception as e:
        logger.info(f"Cost summary scheduler shutdown error: {e}")

    # Stop agent scheduler
    try:
        if hasattr(app.state, 'agent_scheduler'):
            from services.agent_scheduler import stop_agent_scheduler
            await stop_agent_scheduler()
            logger.info("Agent Scheduler stopped")
    except Exception as e:
        logger.info(f"Agent scheduler shutdown error: {e}")


    # Stop job queue workers
    try:
        if hasattr(app.state, 'job_queue'):
            await app.state.job_queue.stop_workers()
            logger.info("Job Queue workers stopped")
    except Exception as e:
        logger.info(f"Job queue stop error: {e}")

    # Stop enrichment queue
    try:
        from services.enrichment_queue import stop_enrichment_queue
        await stop_enrichment_queue()
        logger.info("Enrichment Queue Service stopped")
    except Exception as e:
        logger.info(f"Enrichment queue stop error: {e}")

    # Stop integration update scheduler
    try:
        from services.update_scheduler import stop_scheduler
        await stop_scheduler()
        logger.info("Integration Update Scheduler stopped")
    except Exception as e:
        logger.info(f"Integration update scheduler stop error: {e}")

    try:
        # Stop scheduler
        if hasattr(app.state, 'scheduler'):
            await app.state.scheduler.stop()
            logger.info("Scheduler stopped")
    except Exception as e:
        logger.info(f"Scheduler stop error: {e}")

    # Stop playbook scheduler
    try:
        if hasattr(app.state, 'playbook_scheduler'):
            await app.state.playbook_scheduler.stop()
            logger.info("Playbook Scheduler stopped")
    except Exception as e:
        logger.info(f"Playbook scheduler stop error: {e}")
    
    try:
        from services.postgres_db import postgres_db
        await postgres_db.disconnect()
        logger.info("PostgreSQL disconnected")
    except Exception as e:
        logger.info(f"PostgreSQL disconnect error: {e}")
    
    try:
        from services.database import db
        await db.disconnect()
        logger.info("Database disconnected")
    except Exception as e:
        logger.info(f"Database disconnect error: {e}")
    
    logger.info("T1 Agentics shutdown complete")


_is_production = os.getenv("ENVIRONMENT", "development").lower() in ("production", "prod")

app = FastAPI(
    title="T1 Agentics API",
    description="Vendor-Neutral Agentic Cybersecurity Worker",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)

# CORS middleware for frontend access
# SECURITY: Restrict origins, methods, and headers in production
# Set ALLOWED_ORIGINS environment variable to restrict access
# Use "*" for development (allows all origins without credentials reflection)
# Use comma-separated list for production: "http://localhost:3000,http://example.com"
_cors_origins_env = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000")

# Build subdomain regex from PUBLIC_URL (e.g. https://t1agentics.ai → *.t1agentics.ai)
_public_url = os.getenv("PUBLIC_URL", "")
ALLOWED_ORIGIN_REGEX = None
if _public_url:
    from urllib.parse import urlparse as _urlparse
    _base_domain = _urlparse(_public_url).hostname or ""
    if _base_domain and _base_domain != "localhost":
        ALLOWED_ORIGIN_REGEX = rf"^https://[\w-]+\.{re.escape(_base_domain)}$"

# Handle wildcard specially - when using *, we must disable credentials
# to prevent cross-site credential leakage.
if _cors_origins_env.strip() == "*":
    if _is_production:
        raise ValueError(
            "SECURITY: ALLOWED_ORIGINS='*' is not allowed in production. "
            "Set ALLOWED_ORIGINS to specific origins (e.g. 'https://yoursite.com')."
        )
    CORS_ALLOW_ALL = True
    ALLOWED_ORIGINS = ["*"]
else:
    CORS_ALLOW_ALL = False
    ALLOWED_ORIGINS = [origin.strip() for origin in _cors_origins_env.split(",") if origin.strip()]


def _is_allowed_origin(origin: str) -> bool:
    """Check if origin is in explicit list or matches subdomain regex."""
    if origin in ALLOWED_ORIGINS:
        return True
    if ALLOWED_ORIGIN_REGEX and re.match(ALLOWED_ORIGIN_REGEX, origin):
        return True
    return False

# Restrict methods and headers for security
ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
ALLOWED_HEADERS = [
    "Authorization",
    "Content-Type",
    "Accept",
    "Origin",
    "X-Requested-With",
    "X-Webhook-Token",
    "X-Request-ID",
    "X-Agent-Token",
    "X-CSRF-Token",
    "X-CSRF"
]

# CORS middleware is added AFTER all other middleware (below) so it runs
# FIRST in the request chain and handles OPTIONS preflight before auth.

# ============================================================================
# GLOBAL EXCEPTION HANDLERS
# ============================================================================
# These handlers ensure all errors return consistent JSON responses

from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError
import traceback as tb

# Security headers for exception responses (bypass middleware)
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Cache-Control": "no-store, no-cache, must-revalidate, private",
}

@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    """Handle HTTP exceptions with consistent JSON response."""
    # Get origin from request headers
    origin = request.headers.get("origin", "")
    request_id = getattr(request.state, "request_id", None)

    # Prepare CORS headers
    # SECURITY: Never allow credentials with wildcard origins
    cors_headers = {}
    if CORS_ALLOW_ALL:
        # Allow any origin in development - but NO credentials with wildcards
        cors_headers["Access-Control-Allow-Origin"] = origin or "*"
        # SECURITY: Credentials are NOT allowed with wildcard origins
    elif _is_allowed_origin(origin):
        # Only allow configured origins in production
        cors_headers["Access-Control-Allow-Origin"] = origin
        cors_headers["Access-Control-Allow-Credentials"] = "true"

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "status_code": exc.status_code,
            "message": str(exc.detail),
            "path": str(request.url.path),
            "request_id": request_id
        },
        headers={**cors_headers, **_SECURITY_HEADERS}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    """Handle request validation errors with helpful messages."""
    # Get origin from request headers
    origin = request.headers.get("origin", "")
    request_id = getattr(request.state, "request_id", None)

    # Prepare CORS headers
    # SECURITY: Never allow credentials with wildcard origins
    cors_headers = {}
    if CORS_ALLOW_ALL:
        cors_headers["Access-Control-Allow-Origin"] = origin or "*"
        # SECURITY: Credentials are NOT allowed with wildcard origins
    elif _is_allowed_origin(origin):
        cors_headers["Access-Control-Allow-Origin"] = origin
        cors_headers["Access-Control-Allow-Credentials"] = "true"

    errors = []
    for error in exc.errors():
        loc = " -> ".join(str(l) for l in error.get("loc", []))
        errors.append({
            "field": loc,
            "message": error.get("msg", "Validation error"),
            "type": error.get("type", "unknown")
        })
    return JSONResponse(
        status_code=422,
        content={
            "error": True,
            "status_code": 422,
            "message": "Request validation failed",
            "path": str(request.url.path),
            "validation_errors": errors,
            "request_id": request_id
        },
        headers={**cors_headers, **_SECURITY_HEADERS}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    Catch-all handler for unhandled exceptions.
    Logs the full traceback but returns a safe error message.
    """
    error_id = secrets.token_hex(8)
    error_type = type(exc).__name__

    # Log the full error details
    logger = logging.getLogger(__name__)
    logger.error(f"[{error_id}] Unhandled {error_type} on {request.method} {request.url.path}")
    logger.error(f"[{error_id}] {str(exc)}")
    logger.error(f"[{error_id}] Traceback:\n{tb.format_exc()}")

    # Get origin from request headers
    origin = request.headers.get("origin", "")

    # Prepare CORS headers
    # SECURITY: Never allow credentials with wildcard origins
    cors_headers = {}
    if CORS_ALLOW_ALL:
        cors_headers["Access-Control-Allow-Origin"] = origin or "*"
        # SECURITY: Credentials are NOT allowed with wildcard origins
    elif _is_allowed_origin(origin):
        cors_headers["Access-Control-Allow-Origin"] = origin
        cors_headers["Access-Control-Allow-Credentials"] = "true"

    # Return safe error response (don't leak internal details)
    return JSONResponse(
        status_code=500,
        content={
            "error": True,
            "status_code": 500,
            "message": "An internal server error occurred",
            "error_id": error_id,
            "path": str(request.url.path),
            "hint": "Check server logs for error_id to debug"
        },
        headers={**cors_headers, **_SECURITY_HEADERS}
    )

# ============================================================================
# SECURITY MIDDLEWARE (Authentication, Rate Limiting, Security Headers)
# ============================================================================
# Import and add security middleware
# Middleware order matters: outermost is executed first
try:
    from middleware.auth_middleware import AuthenticationMiddleware
    from middleware.rate_limiter import AdvancedRateLimitMiddleware
    from middleware.security_headers import SecurityHeadersMiddleware
    from middleware.request_id import RequestIdMiddleware
    from middleware.csrf_middleware import CSRFMiddleware
    from middleware.license_middleware import LicenseMiddleware
    from middleware.tenant_middleware import TenantMiddleware

    # Security headers (outermost - adds headers to all responses)
    app.add_middleware(SecurityHeadersMiddleware)

    # Request ID for traceability
    app.add_middleware(RequestIdMiddleware)

    # Advanced rate limiting (before auth, to block brute force)
    # Features: per-webhook limits, tier-based, trusted source bypass, metrics
    app.add_middleware(AdvancedRateLimitMiddleware)

    # CSRF protection (cookie-auth only, unsafe methods)
    app.add_middleware(CSRFMiddleware)

    # Authentication middleware (validates auth on protected routes)
    app.add_middleware(AuthenticationMiddleware)

    # Tenant isolation (resolves tenant from JWT/API key/subdomain)
    app.add_middleware(TenantMiddleware)

    # License enforcement (checks license validity and usage limits)
    app.add_middleware(LicenseMiddleware)

    # CORS must be the LAST middleware added (= first to run) so it handles
    # OPTIONS preflight requests before auth/tenant middleware reject them.
    if CORS_ALLOW_ALL:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=ALLOWED_ORIGINS,
            allow_credentials=False,
            allow_methods=ALLOWED_METHODS,
            allow_headers=ALLOWED_HEADERS,
            expose_headers=["X-Request-ID"],
            max_age=600,
        )
    else:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=ALLOWED_ORIGINS,
            allow_origin_regex=ALLOWED_ORIGIN_REGEX,
            allow_credentials=True,
            allow_methods=ALLOWED_METHODS,
            allow_headers=ALLOWED_HEADERS,
            expose_headers=["X-Request-ID"],
            max_age=600,
        )

    logger = logging.getLogger(__name__)
    logger.info("Security middleware loaded:")
    logger.info("  - Security headers (OWASP best practices)")
    logger.info("  - Rate limiting: 200/min/IP/webhook (configurable)")
    logger.info("  - Authentication: JWT/API key/cookie")
    logger.info("  - CSRF: Double-submit cookie for unsafe methods")
    logger.info("  - Tenant isolation: multi-tenant data separation")
    logger.info("  - License enforcement: tier-based feature/usage limits")
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.error(f"CRITICAL: Could not load security middleware: {e}")
    logger.error("API endpoints will NOT be protected by authentication!")

# ============================================================================
# HEALTH CHECK ENDPOINTS (Phase 0: HA/Clustering Support)
# ============================================================================

# Track startup time for uptime calculation
APP_START_TIME = time.time()
NODE_ID = os.getenv("NODE_ID", f"node-{socket.gethostname()}-{os.getpid()}")
APP_VERSION = os.getenv("APP_VERSION", "1.0.0")

@app.get("/health", tags=["Health"])
async def health_check():
    """
    Basic health check - returns 200 if the service is running.
    Used by load balancers for basic availability checks.
    """
    return {"status": "healthy", "node_id": NODE_ID}


@app.get("/ready", tags=["Health"])
async def ready_alias():
    """Alias for /health/ready."""
    return await readiness_check()


@app.get("/live", tags=["Health"])
async def live_alias():
    """Alias for /health/live."""
    return await liveness_check()

@app.get("/health/live", tags=["Health"])
async def liveness_check():
    """
    Kubernetes liveness probe - is the process alive?
    Returns 200 if the process is running (even if dependencies are down).
    Failing this probe causes container restart.
    """
    return {"status": "alive", "node_id": NODE_ID, "uptime_seconds": int(time.time() - APP_START_TIME)}

@app.get("/health/ready", tags=["Health"])
async def readiness_check():
    """
    Kubernetes readiness probe - is the service ready to accept traffic?
    Checks database connectivity. Failing this removes the pod from service.
    """
    checks = {
        "database": False,
        "node_id": NODE_ID,
        "version": APP_VERSION
    }

    # Check PostgreSQL
    try:
        from services.postgres_db import postgres_db
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.tenant_acquire() as conn:
                await conn.fetchval("SELECT 1")
            checks["database"] = True
    except Exception as e:
        checks["database_error"] = str(e)

    # Determine overall status
    is_ready = checks["database"]

    if is_ready:
        return {"status": "ready", **checks}
    else:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", **checks}
        )

@app.get("/health/detailed", tags=["Health"])
async def detailed_health_check():
    """
    Detailed health check with all component statuses.
    Used for monitoring dashboards and debugging.
    """
    checks = {
        "node_id": NODE_ID,
        "version": APP_VERSION,
        "uptime_seconds": int(time.time() - APP_START_TIME),
        "components": {
            "database": {"status": "unknown"},
            "scheduler": {"status": "unknown"},
            "integrations": {"status": "unknown"}
        }
    }

    # Check PostgreSQL
    try:
        from services.postgres_db import postgres_db
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.tenant_acquire() as conn:
                result = await conn.fetchval("SELECT COUNT(*) FROM alerts")
            checks["components"]["database"] = {
                "status": "healthy",
                "type": "postgresql",
                "alert_count": result
            }
        else:
            checks["components"]["database"] = {"status": "disconnected"}
    except Exception as e:
        checks["components"]["database"] = {"status": "error", "error": str(e)}

    # Check scheduler
    try:
        if hasattr(app.state, 'scheduler') and app.state.scheduler:
            checks["components"]["scheduler"] = {
                "status": "running" if app.state.scheduler.running else "stopped"
            }
        else:
            checks["components"]["scheduler"] = {"status": "not_initialized"}
    except Exception as e:
        checks["components"]["scheduler"] = {"status": "error", "error": str(e)}

    # Check integrations registry
    try:
        from integrations.registry.integration_registry import get_registry
        registry = get_registry()
        all_integrations = registry.list()
        enabled_integrations = registry.list(enabled_only=True)
        checks["components"]["integrations"] = {
            "status": "healthy",
            "total": len(all_integrations),
            "enabled": len(enabled_integrations)
        }
    except Exception as e:
        checks["components"]["integrations"] = {"status": "error", "error": str(e)}

    # Overall status
    component_statuses = [c.get("status") for c in checks["components"].values()]
    if all(s in ["healthy", "running", "not_initialized"] for s in component_statuses):
        checks["status"] = "healthy"
    elif any(s == "error" for s in component_statuses):
        checks["status"] = "degraded"
    else:
        checks["status"] = "unhealthy"

    return checks

@app.get("/metrics", tags=["Health"])
async def prometheus_metrics():
    """
    Prometheus-compatible metrics endpoint.
    Returns metrics in Prometheus text format for scraping.
    """
    from fastapi.responses import PlainTextResponse

    metrics_lines = []

    # Basic app info
    metrics_lines.append(f'# HELP T1 Agentics_info Application information')
    metrics_lines.append(f'# TYPE T1 Agentics_info gauge')
    metrics_lines.append(f'T1 Agentics_info{{version="{APP_VERSION}",node_id="{NODE_ID}"}} 1')

    # Uptime
    uptime = int(time.time() - APP_START_TIME)
    metrics_lines.append(f'# HELP T1 Agentics_uptime_seconds Time since application started')
    metrics_lines.append(f'# TYPE T1 Agentics_uptime_seconds counter')
    metrics_lines.append(f'T1 Agentics_uptime_seconds {uptime}')

    # Database metrics
    try:
        from services.postgres_db import postgres_db
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.tenant_acquire() as conn:
                # Alert counts by status
                alert_counts = await conn.fetch("""
                    SELECT status, COUNT(*) as count
                    FROM alerts
                    GROUP BY status
                """)

                metrics_lines.append(f'# HELP T1 Agentics_alerts_total Total alerts by status')
                metrics_lines.append(f'# TYPE T1 Agentics_alerts_total gauge')
                for row in alert_counts:
                    metrics_lines.append(f'T1 Agentics_alerts_total{{status="{row["status"]}"}} {row["count"]}')

                # Investigation counts by state
                inv_counts = await conn.fetch("""
                    SELECT state, COUNT(*) as count
                    FROM investigations
                    GROUP BY state
                """)

                metrics_lines.append(f'# HELP T1 Agentics_investigations_total Total investigations by state')
                metrics_lines.append(f'# TYPE T1 Agentics_investigations_total gauge')
                for row in inv_counts:
                    metrics_lines.append(f'T1 Agentics_investigations_total{{state="{row["state"]}"}} {row["count"]}')

                # Job queue metrics
                try:
                    queue_stats = await conn.fetch("""
                        SELECT queue_name, status, COUNT(*) as count
                        FROM job_queue
                        GROUP BY queue_name, status
                    """)

                    metrics_lines.append(f'# HELP T1 Agentics_job_queue_total Jobs in queue by status')
                    metrics_lines.append(f'# TYPE T1 Agentics_job_queue_total gauge')
                    for row in queue_stats:
                        metrics_lines.append(f'T1 Agentics_job_queue_total{{queue="{row["queue_name"]}",status="{row["status"]}"}} {row["count"]}')
                except Exception:
                    pass  # Table might not exist yet

                # Database connection pool stats
                pool_size = postgres_db.pool.get_size()
                pool_free = postgres_db.pool.get_idle_size()
                metrics_lines.append(f'# HELP T1 Agentics_db_pool_size Database connection pool size')
                metrics_lines.append(f'# TYPE T1 Agentics_db_pool_size gauge')
                metrics_lines.append(f'T1 Agentics_db_pool_size {pool_size}')
                metrics_lines.append(f'# HELP T1 Agentics_db_pool_free Free database connections')
                metrics_lines.append(f'# TYPE T1 Agentics_db_pool_free gauge')
                metrics_lines.append(f'T1 Agentics_db_pool_free {pool_free}')

                metrics_lines.append(f'# HELP T1 Agentics_database_up Database connection status')
                metrics_lines.append(f'# TYPE T1 Agentics_database_up gauge')
                metrics_lines.append(f'T1 Agentics_database_up 1')
        else:
            metrics_lines.append(f'# HELP T1 Agentics_database_up Database connection status')
            metrics_lines.append(f'# TYPE T1 Agentics_database_up gauge')
            metrics_lines.append(f'T1 Agentics_database_up 0')
    except Exception as e:
        metrics_lines.append(f'# HELP T1 Agentics_database_up Database connection status')
        metrics_lines.append(f'# TYPE T1 Agentics_database_up gauge')
        metrics_lines.append(f'T1 Agentics_database_up 0')

    # Integration metrics
    try:
        from integrations.registry.integration_registry import get_registry
        registry = get_registry()
        total = len(registry.list())
        enabled = len(registry.list(enabled_only=True))

        metrics_lines.append(f'# HELP T1 Agentics_integrations_total Total integrations registered')
        metrics_lines.append(f'# TYPE T1 Agentics_integrations_total gauge')
        metrics_lines.append(f'T1 Agentics_integrations_total {total}')
        metrics_lines.append(f'# HELP T1 Agentics_integrations_enabled Enabled integrations')
        metrics_lines.append(f'# TYPE T1 Agentics_integrations_enabled gauge')
        metrics_lines.append(f'T1 Agentics_integrations_enabled {enabled}')
    except Exception:
        pass

    return PlainTextResponse(
        content="\n".join(metrics_lines) + "\n",
        media_type="text/plain; charset=utf-8"
    )

# Include routers
app.include_router(webhooks_router)
app.include_router(admin_router)
app.include_router(mfa_router)  # MFA/TOTP authentication routes
app.include_router(docs_router)
app.include_router(forms_router)
app.include_router(playbooks_router)  # Visual Playbook Editor
app.include_router(playbook_forms_router)  # Playbook webform management
app.include_router(intake_forms_router)  # Intake forms (tenant-scoped, auth required) → alert pipeline
app.include_router(tenant_llm_context_router)  # Per-tenant LLM context overrides (extra context + key allow/deny)
app.include_router(tenant_triage_config_router)  # Per-tenant auto-close thresholds
app.include_router(tenant_ai_config_router)  # Per-tenant BYO LLM config
app.include_router(tenant_pii_patterns_router)  # Tenant-defined PII regex patterns
app.include_router(playbook_public_forms_router)  # Public form submission (no auth)
app.include_router(playbook_converters_router)  # Playbook format converters
app.include_router(recommended_actions_router)  # Riggs recommended actions
app.include_router(investigation_notes_router)  # Investigation notes and attachments

# Riggs AI Studio routes
try:
    from routes.riggs_builder import router as riggs_builder_router
    from routes.riggs_playbooks import router as riggs_playbooks_router
    from routes.fast_triage import router as fast_triage_router
    app.include_router(riggs_builder_router)  # Riggs playbook builder
    app.include_router(riggs_playbooks_router)  # Riggs playbook recommendations
    app.include_router(fast_triage_router)  # Fast triage and Riggs analysis
except ImportError as e:
    logging.warning(f"Riggs routes not available: {e}")

app.include_router(riggs_assist_router)  # Riggs Clippy global assistant
app.include_router(credentials_router)
app.include_router(actions_router)

# T1 Connect - New unified integration system
app.include_router(connect_router)

# Include webhook admin routes
from routes.webhooks import admin_router as webhook_admin_router
app.include_router(webhook_admin_router)

# Include config router
from routes.config import router as config_router
app.include_router(config_router)

# Include ingestion router
from routes.ingestion import router as ingestion_router
app.include_router(ingestion_router)

# Include token usage router (AI token tracking)
app.include_router(token_usage_router)

# Include threat intel router (IOC management, enrichment, correlation)
app.include_router(threat_intel_router)

# Include IOC management router (whitelist, submissions, bulk operations)
app.include_router(ioc_management_router)

# Include EDL (External Dynamic List) routes
try:
    from routes.edl import router as edl_router
    from routes.edl_delivery import router as edl_delivery_router
    app.include_router(edl_router)
    app.include_router(edl_delivery_router)
    logger.info("EDL routes loaded (management + firewall delivery)")
except ImportError as e:
    logger.info(f"Warning: Could not load EDL routes: {e}")

# Include threat feeds router (feed management, polling)
app.include_router(threat_feeds_router)

# Include breach intelligence router (breach tracking, threat landscape)
if breach_intel_router:
    app.include_router(breach_intel_router)

# Include threat feed upload router (file uploads)
app.include_router(threat_feed_upload_router)

# Include correlation router (campaigns, correlation rules, IOC correlation)
app.include_router(correlation_router)

# Include PII settings router (PCI compliance configuration)
try:
    from routes.pii_settings import router as pii_settings_router
    app.include_router(pii_settings_router)
    logger.info("PII settings routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load PII settings routes: {e}")

# Include exclusion list router (Phase 2.1 - RFC1918 and IOC exclusions)
try:
    from routes.exclusions import router as exclusions_router
    app.include_router(exclusions_router)
    logger.info("Exclusion list routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load exclusion routes: {e}")

# Include enrichment cache routes (Phase 2.2 - Cache management)
try:
    from routes.enrichment import router as enrichment_router
    app.include_router(enrichment_router)
    logger.info("Enrichment cache routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load enrichment routes: {e}")

# Include deduplication routes (Phase 2.4 - Alert deduplication)
try:
    from routes.deduplication import router as deduplication_router
    app.include_router(deduplication_router)
    logger.info("Deduplication routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load deduplication routes: {e}")

# Include agent routes (agent management, executions, approvals)
try:
    from routes.agents import router as agents_router, executions_router, approvals_router
    app.include_router(agents_router)
    app.include_router(executions_router)
    app.include_router(approvals_router)
    logger.info("Agent routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load agent routes: {e}")

# Include AI provider routes
try:
    from routes.ai_providers import router as ai_providers_router
    app.include_router(ai_providers_router)
    logger.info("AI provider routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load AI provider routes: {e}")


# Include work queue routes
try:
    from routes.work_queue import router as work_queue_router
    app.include_router(work_queue_router)
    logger.info("Work queue routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load work queue routes: {e}")

# Include notification routes (email notifications, SMTP config)
try:
    from routes.notifications import router as notifications_router
    app.include_router(notifications_router)
    logger.info("Notification routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load notification routes: {e}")

# Include approval token routes (TTL links, one-time use approval workflows)
try:
    from routes.approvals import router as approval_tokens_router
    app.include_router(approval_tokens_router)
    logger.info("Approval token routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load approval token routes: {e}")

# Include attachments routes (file upload/download for alerts)
try:
    from routes.attachments import router as attachments_router
    app.include_router(attachments_router)
    logger.info("Attachments routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load attachments routes: {e}")

# Include knowledge base routes (Company Best Practices / SOP database)
try:
    app.include_router(knowledge_base_router)
    logger.info("Knowledge base routes loaded")
except Exception as e:
    logger.info(f"Warning: Could not load knowledge base routes: {e}")

# Include action approvals routes (Riggs response action approvals)
try:
    from routes.action_approvals import router as action_approvals_router
    app.include_router(action_approvals_router)
    logger.info("Action approvals routes loaded (Riggs)")
except ImportError as e:
    logger.info(f"Warning: Could not load action approvals routes: {e}")

# Include license management routes (tier-based licensing with usage limits)
try:
    from routes.license import router as license_router
    app.include_router(license_router)
    logger.info("License management routes loaded (/api/v1/license)")
except ImportError as e:
    logger.info(f"Warning: Could not load license routes: {e}")

# Include data retention routes (cleanup, archival, storage management)
try:
    from routes.data_retention import router as data_retention_router
    app.include_router(data_retention_router)
    logger.info("Data retention routes loaded (/api/v1/admin/retention)")
except ImportError as e:
    logger.info(f"Warning: Could not load data retention routes: {e}")

# Include licensing routes (license management, usage tracking, entitlements)
try:
    from routes.licensing import router as licensing_router
    app.include_router(licensing_router)
    logger.info("Licensing routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load licensing routes: {e}")

# Include Platform Admin routes (T1 Agentics master tenant management)
try:
    from routes.platform_admin import router as platform_admin_router
    app.include_router(platform_admin_router)
    logger.info("Platform Admin routes loaded (/api/v1/platform)")
except ImportError as e:
    logger.info(f"Warning: Could not load platform admin routes: {e}")

# Include Self-Service Registration routes (public website)
try:
    from routes.registration import router as registration_router
    app.include_router(registration_router)
    logger.info("Registration routes loaded (/api/v1/register, /api/v1/contact, /api/v1/public)")
except ImportError as e:
    logger.info(f"Warning: Could not load registration routes: {e}")

# Lead-draft review (HMAC-signed inbox approve/reject from daily summary)
try:
    from routes.lead_drafts import router as lead_drafts_router
    app.include_router(lead_drafts_router)
    logger.info("Lead-draft routes loaded (/api/v1/lead-drafts/approve, /reject)")
except ImportError as e:
    logger.info(f"Warning: Could not load lead-draft routes: {e}")

# Include Frontend Telemetry routes (error reporting, usage metrics)
try:
    from routes.telemetry import router as telemetry_router
    app.include_router(telemetry_router)
    logger.info("Telemetry routes loaded (/api/v1/telemetry)")
except ImportError as e:
    logger.info(f"Warning: Could not load telemetry routes: {e}")

# Include Public Demo routes (unauthenticated lead-magnet tools)
try:
    from routes.public_demo import router as public_demo_router
    app.include_router(public_demo_router)
    logger.info("Public demo routes loaded (/api/v1/public/triage)")
except ImportError as e:
    logger.info(f"Warning: Could not load public demo routes: {e}")

# Include Affiliate / Referral routes
try:
    from routes.affiliate import router as affiliate_router
    app.include_router(affiliate_router, prefix="/api/v1")
    logger.info("Affiliate routes loaded (/api/v1/affiliate)")
except ImportError as e:
    logger.info(f"Warning: Could not load affiliate routes: {e}")

# Include IAM (Identity and Access Management) response action routes
try:
    from routes.iam import router as iam_router
    app.include_router(iam_router)
    logger.info("IAM response action routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load IAM routes: {e}")

# Include Chat routes (Phase 6 - real-time investigation chat)
try:
    from routes.chat import router as chat_router, search_assist_router
    app.include_router(chat_router)
    app.include_router(search_assist_router)  # Riggs search assist at /api/chat/search-assist
    logger.info("Chat routes loaded (including Riggs search assist)")
except ImportError as e:
    logger.info(f"Warning: Could not load chat routes: {e}")

# Telemetry routes removed (Phase 8 disabled)

# Include Asset routes (Phase 9 - CMDB & Asset Discovery)
try:
    from routes.assets import router as assets_router
    app.include_router(assets_router)
    logger.info("Asset routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load asset routes: {e}")

# Include Asset Discovery routes (Phase 9.2 - Discovery Orchestrator)
try:
    from routes.asset_discovery import router as asset_discovery_router
    app.include_router(asset_discovery_router)
    logger.info("Asset discovery routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load asset discovery routes: {e}")

# UEBA routes removed (Phase 10 disabled)

# Phase 12: Inbound Email routes
try:
    from routes.inbound_email import router as inbound_email_router
    app.include_router(inbound_email_router)
    logger.info("Inbound email routes loaded (Phase 12: Email Integration)")
except ImportError as e:
    logger.info(f"Warning: Could not load inbound email routes: {e}")

# Post-Resolution Workflow routes (Phase 14)
try:
    from routes.post_resolution import router as post_resolution_router
    app.include_router(post_resolution_router)
    logger.info("Post-resolution routes loaded (Phase 14: Post-Resolution Workflow)")
except ImportError as e:
    logger.info(f"Warning: Could not load post-resolution routes: {e}")

# Sender Trust routes (Trusted Senders & Phishing Test Lists)
try:
    from routes.sender_trust import router as sender_trust_router
    app.include_router(sender_trust_router)
    logger.info("Sender trust routes loaded (Trusted Senders & Phishing Tests)")
except ImportError as e:
    logger.info(f"Warning: Could not load sender trust routes: {e}")

# Unified Reasoning Engine routes (Phase NEW - Judgment-Preserving Architecture)
try:
    from routes.reasoning import router as reasoning_router
    app.include_router(reasoning_router)
    logger.info("Unified Reasoning Engine routes loaded (ONE engine, ONE prompt)")

    # Initialize tool handlers for the reasoning engine
    from reasoning_engine import initialize_tool_handlers
    initialize_tool_handlers()
    logger.info("Reasoning engine tool handlers initialized")
except ImportError as e:
    logger.info(f"Warning: Could not load reasoning engine routes: {e}")

# ML Classifier routes (ML layer for alert disposition prediction)
try:
    from routes.ml import router as ml_router
    app.include_router(ml_router)
    logger.info("ML Classifier routes loaded (train, predict, status)")
except ImportError as e:
    logger.info(f"Warning: Could not load ML routes: {e}")

# ML Server update distribution (serves files to remote 3090 Ti)
try:
    from routes.ml_server import router as ml_server_router
    app.include_router(ml_server_router)
    logger.info("ML Server update routes loaded (manifest, files, status)")
except ImportError as e:
    logger.info(f"Warning: Could not load ML Server routes: {e}")

# Log Collection, Log Source, and Log Viewer routes removed (event logs disabled)

# Agent-Asset Linking routes (Phase 9 - CMDB integration)
try:
    from routes.agent_assets import router as agent_assets_router
    app.include_router(agent_assets_router)
    logger.info("Agent-Asset Linking routes loaded (Phase 9)")
except ImportError as e:
    logger.info(f"Warning: Could not load Agent-Asset routes: {e}")

# Integration Store routes (Phase 10 - Agent capabilities)
# Agent Capabilities routes (Phase 11 - Tool execution)
try:
    from routes.agent_capabilities import router as agent_capabilities_router
    app.include_router(agent_capabilities_router)
    logger.info("Agent Capabilities routes loaded (Phase 11)")
except ImportError as e:
    logger.info(f"Warning: Could not load Agent Capabilities routes: {e}")

# Collector Management routes (source types, assignments, groups)
try:
    from routes.collectors import router as collectors_router
    app.include_router(collectors_router)
    logger.info("Collector Management routes loaded (source-types, assignments, groups)")
except ImportError as e:
    logger.info(f"Warning: Could not load Collector Management routes: {e}")

# Control Plane routes (collector configuration pull)
try:
    from routes.control_plane import router as control_plane_router
    app.include_router(control_plane_router)
    logger.info("Control Plane routes loaded (config pull, heartbeat, registration)")
except ImportError as e:
    logger.info(f"Warning: Could not load Control Plane routes: {e}")

# EDR (Endpoint Detection & Response) routes
try:
    from routes.edr import router as edr_router
    app.include_router(edr_router)
    logger.info("EDR routes loaded (agents, events, IOCs, inventory, actions)")
except ImportError as e:
    logger.info(f"Warning: Could not load EDR routes: {e}")

# Investigation Detail routes (view correlated alerts with full data)
try:
    from routes.investigations import router as investigations_router
    app.include_router(investigations_router)
    logger.info("Investigation routes loaded (details, alerts, entities, correlation history)")
except ImportError as e:
    logger.info(f"Warning: Could not load Investigation routes: {e}")

# Report generation routes (investigation reports in Markdown/PDF)
try:
    from routes.reports import router as reports_router
    app.include_router(reports_router)
    logger.info("Report generation routes loaded")
except ImportError as e:
    logger.info(f"Warning: Could not load Report routes: {e}")

# WebSocket endpoint for chat
from fastapi import WebSocket, Query as WSQuery

@app.websocket("/ws/chat/{investigation_id}")
async def websocket_chat_endpoint(
    websocket: WebSocket,
    investigation_id: str,
    token: str = WSQuery(None)
):
    """
    WebSocket endpoint for real-time investigation chat.

    Connect with: ws://localhost:8000/ws/chat/{investigation_id}?token={jwt_token}
    """
    try:
        from websocket.chat_handler import chat_websocket
        await chat_websocket.handle_connection(websocket, investigation_id, token)
    except ImportError as e:
        logger.info(f"WebSocket chat handler not available: {e}")
        await websocket.close(code=1011, reason="Chat service unavailable")
    except Exception as e:
        logger.info(f"WebSocket error: {e}")
        await websocket.close(code=1011, reason=str(e))

# User preferences store (in-memory, would be DB in production)
user_preferences_store = {}

@app.post("/api/v1/user/preferences")
async def save_user_preference(data: dict):
    """Save a user preference"""
    username = data.get("username", "admin")
    key = data.get("key")
    value = data.get("value")
    
    if not key:
        raise HTTPException(status_code=400, detail="Key is required")
    
    if username not in user_preferences_store:
        user_preferences_store[username] = {}
    user_preferences_store[username][key] = value
    return {"success": True, "key": key}

@app.get("/api/v1/user/preferences/{username}")
async def get_user_preferences(username: str):
    """Get all preferences for a user"""
    return user_preferences_store.get(username, {})

@app.get("/api/v1/user/preferences/{username}/{key}")
async def get_user_preference(username: str, key: str):
    """Get a specific preference for a user"""
    user_prefs = user_preferences_store.get(username, {})
    if key in user_prefs:
        return {"key": key, "value": user_prefs[key]}
    raise HTTPException(status_code=404, detail="Preference not found")


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "T1 Agentics",
        "version": "1.0.0",
        "status": "operational",
        "description": "Vendor-Neutral Agentic Cybersecurity Worker"
    }


@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    from services.postgres_db import postgres_db

    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "postgres_connected": postgres_db.connected,
        "investigations_count": len(investigations_store),
        "alerts_count": len(alerts_store)
    }


@app.get("/api/v1/riggs/proactive-tips")
async def riggs_proactive_tips(
    route: str = Query(default="/", description="Current frontend pathname so tips can be scoped to context"),
    current_user: dict = Depends(auth_get_current_user),
):
    """
    Returns a short list of proactive, data-driven tips for the Riggs Clippy
    surface. Each tip is grounded in the tenant's actual platform state —
    not a static tip list — so the analyst gets something actionable rather
    than a generic "did you know."

    Tip shape:
        { id, text, action: { label, link } | null, severity }

    Cheap: bounded queries with LIMIT clauses. Best-effort: individual tip
    failures don't break the response.
    """
    from services.postgres_db import postgres_db
    from middleware.tenant_middleware import get_optional_tenant_id

    tips = []
    tenant_id = get_optional_tenant_id()
    if not tenant_id or not postgres_db.connected:
        return {"tips": tips}

    route_lc = (route or '/').lower()

    try:
        async with postgres_db.tenant_acquire() as conn:
            # SLA-pressure tip — top driver of "you should look at this now"
            try:
                breach_row = await conn.fetchrow(
                    """
                    SELECT COUNT(*) AS n
                      FROM investigations
                     WHERE state NOT IN ('CLOSED', 'RESOLVED')
                       AND (
                            (severity = 'critical' AND created_at < NOW() - INTERVAL '60 minutes')
                         OR (severity = 'high'     AND created_at < NOW() - INTERVAL '240 minutes')
                         OR (severity = 'medium'   AND created_at < NOW() - INTERVAL '480 minutes')
                         OR (severity = 'low'      AND created_at < NOW() - INTERVAL '1440 minutes')
                       )
                    """
                )
                if breach_row and breach_row['n']:
                    n = breach_row['n']
                    tips.append({
                        "id": "sla_breach",
                        "text": f"{n} open investigation{'s' if n != 1 else ''} past SLA right now.",
                        # timeRange=all is critical here — the queue's default
                        # is 24h, and breached items are by definition usually
                        # older than that, so without it the analyst lands on
                        # an SLA-exceeded view that only shows the 1–3 recent
                        # breaches and silently hides the rest.
                        # status=active keeps closed/resolved historicals out
                        # of the view — the count is open-only by definition,
                        # so the table should be too. view=investigations
                        # because the SQL only counts the investigations
                        # table; without this the queue shows breached
                        # alerts too and the tip count no longer matches
                        # what the analyst sees.
                        "action": {"label": "View breached", "link": "/queue?sla=exceeded&status=active&timeRange=all&view=investigations"},
                        "severity": "critical",
                    })
            except Exception:
                pass

            # Needs-review backlog — analyst-actionable, not noise
            try:
                review_row = await conn.fetchrow(
                    """
                    SELECT COUNT(*) AS n
                      FROM investigations
                     WHERE state = 'NEEDS_REVIEW'
                       AND owner IS NULL
                    """
                )
                if review_row and review_row['n']:
                    n = review_row['n']
                    tips.append({
                        "id": "needs_review_unassigned",
                        "text": f"{n} investigation{'s' if n != 1 else ''} need review and nobody's picked them up.",
                        # Same reason as the SLA tip: the queue's 24h default
                        # hides anything older. Widen to all-time so the count
                        # in the tip matches what the analyst actually sees.
                        "action": {"label": "Open queue", "link": "/queue?status=needs_review&timeRange=all"},
                        "severity": "high",
                    })
            except Exception:
                pass

            # High-risk entities — a single user blowing up is a campaign signal
            try:
                risk_row = await conn.fetchrow(
                    """
                    SELECT entity_type, entity_value, score, related_alert_count
                      FROM entity_risk
                     WHERE threshold_breached = TRUE
                     ORDER BY score DESC NULLS LAST
                     LIMIT 1
                    """
                )
                if risk_row:
                    val = risk_row['entity_value']
                    cnt = risk_row['related_alert_count'] or 0
                    tips.append({
                        "id": "high_risk_entity",
                        "text": f"{risk_row['entity_type']} {val} is above risk threshold ({cnt} related alerts).",
                        "action": {"label": "Investigate", "link": f"/queue?search={val}"},
                        "severity": "high",
                    })
            except Exception:
                pass

            # Recommended actions awaiting approval — easy analyst wins
            try:
                ra_row = await conn.fetchrow(
                    """
                    SELECT COUNT(*) AS n
                      FROM recommended_actions
                     WHERE status = 'pending'
                    """
                )
                if ra_row and ra_row['n']:
                    n = ra_row['n']
                    tips.append({
                        "id": "recommended_actions_pending",
                        "text": f"Riggs has {n} action{'s' if n != 1 else ''} waiting for your approval.",
                        "action": {"label": "Review actions", "link": "/workbench/approvals"},
                        "severity": "medium",
                    })
            except Exception:
                pass

            # Context-specific tips by route
            if route_lc.startswith('/investigation/'):
                inv_id = route_lc.rsplit('/', 1)[-1]
                # Detect related-by-entity opportunities — if this investigation
                # shares a user with N others, Riggs can save the analyst a
                # correlation query.
                try:
                    rel_row = await conn.fetchrow(
                        """
                        SELECT COUNT(DISTINCT i2.id) AS n
                          FROM investigations i1
                          JOIN alerts a1 ON a1.investigation_id = i1.id
                          JOIN alerts a2 ON a2.tenant_id = a1.tenant_id
                                          AND LOWER(a2.raw_event::text) LIKE '%' || LOWER(SUBSTRING(a1.title FROM 1 FOR 30)) || '%'
                                          AND a2.investigation_id != i1.id
                          JOIN investigations i2 ON i2.id = a2.investigation_id
                         WHERE i1.investigation_id = $1
                           AND i2.created_at > NOW() - INTERVAL '30 days'
                        """,
                        inv_id,
                    )
                    if rel_row and (rel_row['n'] or 0) >= 2:
                        n = rel_row['n']
                        tips.append({
                            "id": "related_investigations",
                            "text": f"{n} other recent investigations share signal with this one. Possible campaign.",
                            "action": None,
                            "severity": "info",
                        })
                except Exception:
                    pass

    except Exception as e:
        logger.warning(f"proactive-tips: outer failure: {e}")

    # Limit + sort: critical > high > medium > info, then preserve order
    sev_order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    tips.sort(key=lambda t: sev_order.get(t.get("severity", "info"), 9))
    return {"tips": tips[:5]}


@app.get("/api/v1/ready")
async def ready_check_api():
    """Readiness alias for API tooling."""
    return await readiness_check()


@app.get("/api/v1/live")
async def live_check_api():
    """Liveness alias for API tooling."""
    return await liveness_check()


# ============================================================================
# TEST ENDPOINT (DEV ONLY - NO AUTH REQUIRED)
# ============================================================================

# SECURITY: Test endpoint only available in development environment
ENVIRONMENT = os.environ.get("ENVIRONMENT", "production").lower()

# ============================================================================
# Demo chat — lightweight Claude endpoint for public demo page
# Capped at 200 tokens, rate-limited per IP, no auth required
# ============================================================================
_demo_chat_counts = {}  # ip -> (count, reset_timestamp)
DEMO_CHAT_RATE_LIMIT = 30  # max requests per IP per hour

@app.post("/api/v1/demo/chat")
async def demo_chat(request: Request):
    """Public demo chat — uses Claude to answer questions about demo investigation scenarios."""
    import time

    # Rate limit by IP
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    count, reset_at = _demo_chat_counts.get(client_ip, (0, now + 3600))
    if now > reset_at:
        count, reset_at = 0, now + 3600
    if count >= DEMO_CHAT_RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Demo chat rate limit reached. Sign up for unlimited access.")
    _demo_chat_counts[client_ip] = (count + 1, reset_at)

    try:
        body = await request.json()
        question = (body.get("question") or "")[:500]  # cap input length
        system_prompt = (body.get("system") or "")[:3000]  # cap system prompt

        if not question:
            raise HTTPException(status_code=400, detail="No question provided")

        from services.claude_service import get_claude_service
        from config.constants import PLATFORM_OWNER_TENANT_ID
        import uuid as _uuid

        claude = await get_claude_service()
        if not claude.is_configured:
            return {"reply": None}

        result = await claude.complete(
            tenant_id=_uuid.UUID(PLATFORM_OWNER_TENANT_ID),
            prompt=f"{system_prompt}\n\nUser question: {question}",
            max_tokens=200,
            temperature=0.5,
            request_type="demo_chat",
        )

        return {"reply": result.text if result else None}

    except HTTPException:
        raise
    except Exception as e:
        logger.warning(f"Demo chat error: {e}")
        return {"reply": None}


@app.post("/api/v1/test/alert")
async def test_ingest_alert(
    alert: Alert,
    background_tasks: BackgroundTasks
):
    """
    Test endpoint to ingest alerts without authentication.
    For development/testing purposes only.

    SECURITY: This endpoint is DISABLED in production environments.
    Set ENVIRONMENT=development to enable.
    """
    # SECURITY: Block in production
    if ENVIRONMENT not in ("development", "dev", "test", "testing"):
        raise HTTPException(
            status_code=403,
            detail="Test endpoints are disabled in production. Set ENVIRONMENT=development to enable."
        )

    try:
        alert_dict = alert.dict()
        alert_dict['id'] = alert_dict.get('id') or f"test-{uuid.uuid4()}"
        alert_dict['alert_id'] = alert_dict['id']
        alert_dict['status'] = 'open'
        alert_dict['created_at'] = datetime.utcnow()

        # Save to in-memory store
        alerts_store[alert_dict['id']] = alert_dict

        # Also try PostgreSQL if connected
        if postgres_db.connected:
            try:
                await postgres_db.create_alert(alert_dict)
            except Exception as e:
                logger.warning(f"PostgreSQL save failed (continuing with in-memory): {e}")

        return {
            "success": True,
            "alert_id": alert_dict['id'],
            "message": "Alert ingested successfully. Use /api/v1/alerts/{alert_id}/ai-triage to trigger AI analysis."
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Test alert ingestion failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# USER MANAGEMENT ENDPOINTS (SECURED)
# ============================================================================

@app.get("/api/v1/users")
async def list_users(current_user: dict = Depends(auth_get_current_user)):
    """
    List all users for owner assignment dropdown.
    Returns username and role for each user.

    SECURITY: Requires authentication (middleware + explicit dependency)
    """
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            # Fallback to default users
            return [
                {"username": "admin", "role": "admin", "full_name": "Administrator"},
                {"username": "analyst", "role": "analyst", "full_name": "SOC Analyst"},
                {"username": "readonly", "role": "read_only", "full_name": "Read Only User"}
            ]

        users = await postgres_db.get_all_users()

        # Return minimal info for dropdown
        return [
            {
                "username": user.get("username"),
                "role": user.get("role"),
                "full_name": user.get("full_name"),
                "disabled": user.get("disabled", False)
            }
            for user in users
            if not user.get("disabled", False)
        ]
    except Exception as e:
        logger.info(f"Error fetching users: {e}")
        # Return defaults on error
        return [
            {"username": "admin", "role": "admin", "full_name": "Administrator"},
            {"username": "analyst", "role": "analyst", "full_name": "SOC Analyst"},
            {"username": "readonly", "role": "read_only", "full_name": "Read Only User"}
        ]


async def get_current_username(authorization: str = Header(None)) -> str:
    """
    Simple auth dependency that extracts username from JWT token.
    Returns the username string for use in workflow endpoints.
    """
    import jwt
    import os

    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    if not JWT_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Server misconfiguration")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.replace("Bearer ", "")

    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/api/v1/users/me")
async def get_current_user_info(current_user: Dict = Depends(auth_get_current_user)):
    """
    Get current user information including permissions and license tier.
    Uses shared auth dependency (supports bearer or cookie auth).
    """
    from services.soc_rbac import get_user_permissions
    from services.postgres_db import postgres_db
    user = current_user

    # Fetch license tier + entitlements for the user's tenant
    license_tier = None
    features = {}
    riggs_limits = {}
    riggs_usage = {}
    deep_dive_usage = {}
    tenant_id = user.get("tenant_id")
    if tenant_id and postgres_db.connected:
        try:
            from dependencies.license_checks import get_tenant_limits
            limits = await get_tenant_limits(str(tenant_id))
            license_tier = limits.get("tier")
            features = limits.get("features", {})
            riggs_limits = limits.get("riggs_limits", {})
            riggs_usage = limits.get("riggs_usage", {})
            deep_dive_usage = limits.get("deep_dive_usage", {})
        except Exception as e:
            logger.warning(f"Failed to fetch license tier for /users/me: {e}")

    return {
        "username": user.get("username"),
        "role": user.get("role"),
        "full_name": user.get("full_name", user.get("username")),
        "email": user.get("email"),
        "permissions": get_user_permissions(user.get("role", "user")),
        "license_tier": license_tier,
        "tenant_id": str(tenant_id) if tenant_id else None,
        "features": features,
        "riggs_limits": riggs_limits,
        "riggs_usage": riggs_usage,
        "deep_dive_usage": deep_dive_usage,
    }


@app.get("/api/v1/users/me/preferences")
async def get_current_user_preferences(current_user: Dict = Depends(auth_get_current_user)):
    """
    Get current user's preferences (theme, layout, notifications, etc.).
    Returns the preferences object or an empty dict if none set.
    """
    username = current_user.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        prefs = await postgres_db.get_user_preferences(username)
        return {"preferences": prefs}
    except Exception as e:
        logger.warning(f"Failed to fetch preferences for {username}: {e}")
        return {"preferences": {}}


@app.post("/api/v1/users/me/preferences")
async def save_current_user_preferences(
    preferences: Dict = Body(...),
    current_user: Dict = Depends(auth_get_current_user)
):
    """
    Save current user's preferences (full replace).
    Accepts the entire preferences object from the frontend.
    """
    username = current_user.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        success = await postgres_db.save_user_preferences(username, preferences)
        if success:
            return {"status": "saved", "preferences": preferences}
        else:
            raise HTTPException(status_code=500, detail="Failed to save preferences")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving preferences for {username}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.put("/api/v1/users/me/preferences")
async def update_current_user_preferences(
    preferences: Dict = Body(...),
    current_user: Dict = Depends(auth_get_current_user)
):
    """
    Update current user's preferences (merge with existing).
    Alias for POST that also works for the frontend.
    """
    username = current_user.get("username")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        success = await postgres_db.save_user_preferences(username, preferences)
        if success:
            return {"status": "saved", "preferences": preferences}
        else:
            raise HTTPException(status_code=500, detail="Failed to save preferences")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error saving preferences for {username}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/api/v1/auth/login")
async def login(credentials: Dict = Body(...), response: Response = None):
    """
    Login endpoint - validates credentials and returns JWT token + user info
    """
    from services.postgres_db import postgres_db
    from passlib.hash import bcrypt
    from routes.admin import create_jwt_token

    username = credentials.get("username")
    password = credentials.get("password")

    if not username or not password:
        raise HTTPException(status_code=400, detail="Username and password required")

    def _set_auth_cookies(token: str):
        try:
            from utils.auth_tokens import (
                ACCESS_TOKEN_COOKIE,
                CSRF_COOKIE,
                build_csrf_token,
                should_use_secure_cookies,
                get_cookie_domain,
            )
            if response is None:
                return
            secure_cookie = should_use_secure_cookies()
            csrf_token = build_csrf_token()
            cookie_domain = get_cookie_domain()
            response.set_cookie(
                ACCESS_TOKEN_COOKIE,
                token,
                httponly=True,
                secure=secure_cookie,
                samesite="lax",
                max_age=24 * 3600,
                path="/",
                domain=cookie_domain,
            )
            response.set_cookie(
                CSRF_COOKIE,
                csrf_token,
                httponly=False,
                secure=secure_cookie,
                samesite="lax",
                max_age=24 * 3600,
                path="/",
                domain=cookie_domain,
            )
        except Exception:
            pass

    # Try PostgreSQL first
    if postgres_db.connected:
        try:
            user = await postgres_db.get_user_by_username(username)
            if user:
                # Verify password
                if bcrypt.verify(password, user.get("hashed_password")):
                    # Success! Generate JWT token
                    from services.soc_rbac import get_user_permissions
                    role = user.get("role", "analyst")
                    access_token = create_jwt_token(username, role)
                    _set_auth_cookies(access_token)
                    return {
                        "success": True,
                        "access_token": access_token,
                        "username": user.get("username"),
                        "role": role,
                        "user": {
                            "username": user.get("username"),
                            "email": user.get("email"),
                            "full_name": user.get("full_name"),
                            "role": role,
                            "permissions": get_user_permissions(role)
                        }
                    }
        except Exception as e:
            logger.info(f"PostgreSQL login error: {e}")
    
    # Legacy fallback
    try:
        from services.database import db
        if db.connected:
            user = await db.get_user(username)
            if user:
                # Verify password
                if bcrypt.verify(password, user.get("hashed_password")):
                    from services.soc_rbac import get_user_permissions
                    role = user.get("role", "analyst")
                    access_token = create_jwt_token(username, role)
                    _set_auth_cookies(access_token)
                    return {
                        "success": True,
                        "access_token": access_token,
                        "username": user.get("username"),
                        "role": role,
                        "user": {
                            "username": user.get("username"),
                            "email": user.get("email", f"{username}@T1 Agentics.io"),
                            "full_name": user.get("full_name", username),
                            "role": role,
                            "permissions": get_user_permissions(role)
                        }
                    }
    except Exception as e:
        logger.info(f"Database login error: {e}")
    
    # Login failed
    raise HTTPException(status_code=401, detail="Invalid username or password")


@app.post("/api/v1/alerts/ingest", response_model=Dict)
async def ingest_alert(
    alert: Alert,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(auth_get_current_user)
):
    """
    Ingest a new alert and trigger investigation.
    Returns immediately with investigation ID while processing continues in background.

    SECURITY: Requires authentication (JWT or API key)
    """
    # Generate alert ID if not provided
    if not alert.id:
        alert.id = f"alert-{uuid.uuid4().hex[:8]}"
    
    # Store alert (in-memory fallback if databases not available)
    alerts_store[alert.id] = alert
    
    # Save to PostgreSQL (PRIMARY DATABASE)
    try:
        from services.postgres_db import postgres_db

        if postgres_db.connected:
            # Convert Pydantic model to dict
            if hasattr(alert, 'model_dump'):
                alert_dict = alert.model_dump(mode='json')
            else:
                alert_dict = alert.dict()

            # PCI Compliance: Obfuscate PII before storing.
            # Tenant-defined custom patterns layer on top of the built-ins.
            try:
                from services.pii_obfuscation import get_pii_service
                from services.tenant_pii_patterns_service import get_compiled_for_tenant
                pii_service = get_pii_service()

                # Resolve tenant_id for tenant-specific PII patterns.
                _tenant_id = None
                try:
                    _tenant_id = (
                        alert_dict.get('tenant_id')
                        or (current_user.get('tenant_id') if isinstance(current_user, dict) else None)
                    )
                    if not _tenant_id:
                        from middleware.tenant_middleware import current_tenant_id as _ctid
                        _tenant_id = _ctid.get()
                except Exception:
                    _tenant_id = None

                extra_patterns = (
                    await get_compiled_for_tenant(str(_tenant_id)) if _tenant_id else []
                )
                alert_dict, pii_report = pii_service.obfuscate_event(
                    alert_dict, extra_patterns=extra_patterns
                )
                if pii_report.get('matches_count', 0) > 0:
                    logger.info(f"Alert {alert.id}: PII obfuscated - {pii_report['matches_count']} items masked for PCI compliance")
                    # Store PII report in metadata for audit
                    if '_metadata' not in alert_dict:
                        alert_dict['_metadata'] = {}
                    alert_dict['_metadata']['pii_obfuscation'] = pii_report
            except Exception as pii_err:
                logger.info(f"Alert {alert.id}: PII obfuscation warning - {pii_err}")

            # Create alert in PostgreSQL
            logger.info(f"Attempting to save alert to PostgreSQL: {alert.id}")
            
            # Map alert fields to PostgreSQL schema
            # Use raw_event from request if provided, otherwise use full alert
            raw_event_data = alert_dict.get('raw_event')
            if isinstance(raw_event_data, str):
                try:
                    import json
                    raw_event_data = json.loads(raw_event_data)
                except:
                    pass
            if not raw_event_data:
                raw_event_data = alert_dict

            pg_alert = {
                'alert_id': alert.id,
                'title': alert_dict.get('title', 'Untitled Alert'),
                'description': alert_dict.get('description', ''),
                'severity': alert_dict.get('severity', 'medium'),
                'status': 'open',
                'source': alert_dict.get('source', 'api'),
                'source_type': alert_dict.get('source_type', 'manual'),
                'raw_event': raw_event_data  # Store raw_event as JSONB
            }

            result = await postgres_db.create_alert(pg_alert)
            logger.info(f"Alert {alert.id} saved to PostgreSQL: {result}")

            # Trigger playbooks configured for alert creation
            try:
                import asyncio
                from services.playbook_trigger_service import trigger_playbooks_for_event
                asyncio.create_task(
                    trigger_playbooks_for_event(
                        event_type="alert_created",
                        alert=alert_dict,
                        alert_id=alert.id
                    )
                )
            except Exception as trigger_err:
                logger.info(f"Alert {alert.id}: Playbook trigger failed - {trigger_err}")

            # Send notification for new alert
            try:
                from services.email_service import get_email_service
                email_service = get_email_service()
                email_service.set_db(postgres_db)

                # Determine event type based on severity
                event_type = 'alert_critical' if pg_alert['severity'] == 'critical' else 'alert_created'

                sent_count = await email_service.notify_event(event_type, {
                    'alert_id': alert.id,
                    'title': pg_alert['title'],
                    'severity': pg_alert['severity'],
                    'source': pg_alert['source'],
                    'description': pg_alert.get('description', '')[:500]
                })
                logger.info(f"Alert {alert.id}: Notification sent to {sent_count} recipients")
            except Exception as notify_err:
                logger.info(f"Alert {alert.id}: Notification failed - {notify_err}")

            # Trigger automatic IOC enrichment in background.
            # The enrichment pipeline chains:
            #   Alert → IOC extraction → IOC enrichment (complete) → ai_triage_service.triage_alert()
            # which creates the investigation with full enrichment data, and auto-triggers
            # Riggs deep analysis for premium tiers / lighter recommendations for free tiers.
            # (We no longer run fast_triage in parallel — it caused race conditions and
            # bypassed enrichment, resulting in investigations missing enrichment_data/malicious_iocs.)
            from services.auto_enrichment import enrich_alert_background
            background_tasks.add_task(
                enrich_alert_background,
                alert_id=alert.id,
                raw_event=alert_dict,
                tenant_id=current_user.get('tenant_id')
            )
            logger.info(f"Alert {alert.id}: Enrichment + triage pipeline queued")

            # Trigger alert correlation (checks for related investigations)
            try:
                from services.alert_correlation_service import get_correlation_service
                correlation_service = get_correlation_service()
                background_tasks.add_task(
                    _correlate_alert_task,
                    alert_id=alert.id,
                    alert_dict=alert_dict
                )
                logger.info(f"Alert {alert.id}: Correlation queued")
            except Exception as corr_err:
                logger.info(f"Alert {alert.id}: Correlation queueing failed - {corr_err}")
        else:
            logger.info(f"PostgreSQL not connected, alert saved to memory only")
    except Exception as e:
        logger.info(f"Error saving alert to PostgreSQL: {e}")
        import traceback
        traceback.print_exc()

    # DISABLED: Old investigation pipeline - now using agent-based system
    # The new pipeline (auto_enrichment -> ai_triage -> agent_executor) handles investigations
    # Keeping the old run_investigation function for backwards compatibility but not calling it
    # investigation_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
    # background_tasks.add_task(run_investigation, investigation_id=investigation_id, alert=alert)

    return {
        "status": "accepted",
        "alert_id": alert.id,
        "investigation_id": None,  # Investigation will be created by agent pipeline if needed
        "message": "Alert ingested. AI triage will determine if investigation is needed.",
        "check_status_url": f"/api/v1/alerts/{alert.id}"
    }


@app.post("/api/v1/investigate", response_model=InvestigationResult)
async def investigate_synchronous(
    alert: Alert,
    current_user: dict = Depends(auth_get_current_user)
):
    """
    Run investigation synchronously with enhanced IOC tracking and correlation.

    SECURITY: Requires authentication (JWT or API key)
    """
    try:
        # Use existing alert_id from metadata if available, otherwise generate new
        if not alert.id and alert.metadata.get('alert_id'):
            alert.id = alert.metadata.get('alert_id')
        elif not alert.id:
            alert.id = f"alert-{uuid.uuid4().hex[:8]}"
        
        logger.info(f"[INVESTIGATE] Investigating alert: {alert.id}")
        
        # Use proper INV-XXXXXXXX format
        investigation_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
        logger.info(f"[INV] Investigation ID: {investigation_id}")
        
        # Extract raw_alert data from metadata (frontend spreads raw_event into metadata)
        raw_alert_from_metadata = dict(alert.metadata) if alert.metadata else {}
        # Remove internal fields that aren't part of the raw alert
        for key in ['alert_id', 'external_id', 'source_type', 'severity']:
            raw_alert_from_metadata.pop(key, None)
        
        logger.info(f"[DATA] Raw alert data from metadata: {len(raw_alert_from_metadata)} fields")
    except Exception as e:
        logger.error(f"[ERROR] Error in investigation setup: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(500, "Investigation setup failed")
    
    # Check if alert already exists, if not save it
    try:
        from services.database import db
        if db.connected:
            # Check if alert already exists by id
            existing_alert = await db.db.alerts.find_one({"alert_id": alert.id})
            
            if existing_alert:
                logger.info(f"[INFO] Using existing alert {alert.id} from database")
            else:
                # Only save if it doesn't exist
                # Convert Pydantic model to dict
                if hasattr(alert, 'model_dump'):
                    alert_dict = alert.model_dump(mode='json')
                else:
                    alert_dict = alert.dict()
                
                alert_dict["alert_id"] = alert.id
                alert_dict["id"] = alert.id
                
                # Convert timestamp if needed
                if "timestamp" in alert_dict and isinstance(alert_dict["timestamp"], str):
                    alert_dict["timestamp"] = datetime.fromisoformat(alert_dict["timestamp"].replace('Z', '+00:00'))
                
                await db.save_alert(alert_dict)
                logger.info(f"[OK] New alert {alert.id} saved to database")
    except Exception as e:
        logger.warning(f"[WARN] Could not check/save alert to database: {e}")
    
    # Extract IOCs for investigation (old format - List[Indicator])
    extractor = IndicatorExtractor()
    text = f"{alert.title} {alert.description or ''} {alert.raw_log or ''}"
    indicators = extractor.extract_all(text, alert.metadata)
    
    # Validate that we got Indicator objects
    logger.debug(f"[DEBUG] indicators type = {type(indicators)}")
    if indicators:
        logger.debug(f"[DEBUG] first indicator type = {type(indicators[0])}")
        logger.debug(f"[DEBUG] first indicator = {indicators[0]}")
    
    # ALSO track IOCs in database using enhanced extractor (dict format)
    try:
        from services.ioc_extractor import ioc_extractor
        from services.database import db
        
        if db.connected:
            # Extract and automatically track (returns dict)
            ioc_dict = await ioc_extractor.extract_and_track(
                text=text,
                metadata=alert.metadata,
                db_service=db,
                alert_id=alert.id,
                investigation_id=investigation_id,
                severity="medium"  # Will be updated based on verdict
            )
            logger.info(f"[OK] Extracted and tracked {sum(len(v) for v in ioc_dict.values())} IOCs")
    except Exception as e:
        logger.warning(f"[WARN] IOC extraction error: {e}")
        import traceback
        traceback.print_exc()
    
    # Get IOC correlations before investigation
    correlations = {}
    try:
        from services.database import db
        if db.connected and indicators:
            # Extract unique values from Indicator objects
            all_ioc_values = list(set(ind.value for ind in indicators))
            
            if all_ioc_values:
                correlations = await db.get_ioc_correlations(all_ioc_values)
                logger.info(f"[OK] Found correlations for {len(correlations)} IOCs")
    except Exception as e:
        logger.warning(f"[WARN] Could not get correlations: {e}")
    
    # Create manual investigation (AI not implemented yet)
    # Instead of calling AI, create a basic investigation object
    from models import (
        InvestigationResult, SeverityLevel, ConfidenceLevel, DispositionType,
        RecommendedAction, IOCSummary, TechnicalFinding, TimelineEvent
    )
    
    # Extract IOC summary from indicators
    ioc_summary = IOCSummary()
    for ind in indicators:
        if ind.type.value == 'ip':
            ioc_summary.ips.append(ind.value)
        elif ind.type.value == 'domain':
            ioc_summary.domains.append(ind.value)
        elif ind.type.value == 'hash':
            ioc_summary.hashes.append(ind.value)
        elif ind.type.value == 'url':
            ioc_summary.urls.append(ind.value)
        elif ind.type.value == 'email':
            ioc_summary.emails.append(ind.value)
        elif ind.type.value == 'hostname':
            ioc_summary.hosts.append(ind.value)
        elif ind.type.value == 'username':
            ioc_summary.users.append(ind.value)
    
    result = InvestigationResult(
        investigation_id=investigation_id,
        alert_id=alert.id,
        executive_summary="Investigation created. Awaiting analyst review.",
        technical_findings=[
            TechnicalFinding(
                title="Initial Triage",
                description=f"Alert '{alert.title}' requires investigation",
                severity=SeverityLevel.MEDIUM,
                indicators=[],
                evidence=[],
                mitre_tactics=[]
            )
        ],
        timeline=[
            TimelineEvent(
                timestamp=datetime.utcnow(),
                event_type="investigation_created",
                description="Manual investigation initiated",
                indicators=[],
                metadata={"source": "system"}
            )
        ],
        severity=SeverityLevel.MEDIUM,
        confidence=ConfidenceLevel.LOW,
        verdict=DispositionType.UNKNOWN,
        recommended_actions=[
            RecommendedAction(
                action="Review alert details",
                description="Examine the alert context and determine if it requires further investigation",
                priority="Medium",
                rationale="Initial triage step",
                automation_possible=False
            ),
            RecommendedAction(
                action="Analyze indicators",
                description="Review any IOCs or indicators associated with this alert",
                priority="Medium",
                rationale="Identify potential threats",
                automation_possible=False
            )
        ],
        ioc_summary=ioc_summary,
        ioc_correlations=correlations if correlations else {}
    )
    
    # Store result in memory
    investigations_store[result.investigation_id] = result
    
    # === SAVE TO POSTGRESQL ===
    try:
        from services.postgres_db import postgres_db
        import json
        
        # Helper to convert datetime to string for JSON serialization
        def serialize_for_json(obj):
            """Convert object to JSON-serializable format"""
            if hasattr(obj, 'dict'):
                return serialize_for_json(obj.dict())
            elif isinstance(obj, dict):
                return {k: serialize_for_json(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [serialize_for_json(i) for i in obj]
            elif isinstance(obj, datetime):
                return obj.isoformat()
            elif hasattr(obj, 'value'):  # Enum
                return obj.value
            else:
                return obj
        
        if postgres_db.connected:
            logger.info(f"[SAVE] Saving investigation {investigation_id} to PostgreSQL...")
            
            # Serialize data properly
            technical_findings_data = serialize_for_json([f.dict() for f in result.technical_findings]) if hasattr(result, 'technical_findings') else []
            timeline_data = serialize_for_json([t.dict() for t in result.timeline]) if hasattr(result, 'timeline') else []
            recommended_actions_data = serialize_for_json([a.dict() for a in result.recommended_actions]) if hasattr(result, 'recommended_actions') else []
            ioc_summary_data = serialize_for_json(result.ioc_summary.dict()) if hasattr(result, 'ioc_summary') else {}
            
            investigation_data = {
                'investigation_id': investigation_id,
                'alert_id': alert.id,
                'alert_title': alert.title,
                'state': 'NEW',  # Manual investigations start as NEW
                'disposition': 'UNKNOWN',  # Will be set by analyst
                'priority': 'P3',  # Default priority
                'owner': None,  # Unassigned initially
                'severity': 'medium',  # Default severity
                'confidence': None,  # No AI confidence yet
                'executive_summary': result.executive_summary,
                'investigation_data': {
                    'technical_findings': technical_findings_data,
                    'timeline': timeline_data,
                    'indicators': [
                        {
                            'type': str(ind.type.value) if hasattr(ind.type, 'value') else str(ind.type),
                            'value': ind.value,
                            'context': ind.context,
                            'first_seen': ind.first_seen.isoformat() if hasattr(ind, 'first_seen') and ind.first_seen else None
                        } for ind in indicators
                    ] if indicators else [],
                    'recommended_actions': recommended_actions_data,
                    'ioc_summary': ioc_summary_data,
                    'correlations': serialize_for_json(correlations) if correlations else {}
                }
            }
            
            # Save to PostgreSQL
            try:
                # First, try to get the raw_event data from the alert in PostgreSQL
                raw_alert_data = {}
                try:
                    alert_row = await postgres_db.pool.fetchrow(
                        'SELECT raw_event FROM alerts WHERE alert_id = $1',
                        alert.id
                    )
                    if alert_row and alert_row['raw_event']:
                        raw_alert_data = alert_row['raw_event'] if isinstance(alert_row['raw_event'], dict) else {}
                        logger.info(f"[OK] Retrieved raw_event from alert {alert.id}: {len(raw_alert_data)} fields")
                except Exception as e:
                    logger.warning(f"[WARN] Could not get raw_event from alert DB: {e}")
                
                # If database didn't have raw_event, use metadata from frontend
                if not raw_alert_data and raw_alert_from_metadata:
                    raw_alert_data = raw_alert_from_metadata
                    logger.info(f"[OK] Using raw_alert from metadata: {len(raw_alert_data)} fields")
                
                # Include raw_alert in investigation_data
                investigation_data['raw_alert'] = raw_alert_data
                investigation_data['investigation_data']['raw_alert'] = raw_alert_data
                
                saved_investigation_id = await postgres_db.create_investigation(investigation_data)
                logger.info(f"[OK] Investigation saved to PostgreSQL: {saved_investigation_id}")
            except Exception as pg_error:
                logger.error(f"[ERROR] FAILED to save investigation to PostgreSQL: {pg_error}")
                import traceback
                traceback.print_exc()
                # Continue anyway - it's saved to database
            
            # Also update alert status to 'investigating' in PostgreSQL
            try:
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute("""
                        UPDATE alerts
                        SET status = 'investigating', updated_at = NOW()
                        WHERE alert_id = $1
                    """, alert.id)
                    logger.info(f"[OK] Alert {alert.id} status updated to 'investigating'")
            except Exception as e:
                logger.warning(f"[WARN] Could not update alert status: {e}")
                
    except Exception as e:
        logger.warning(f"[WARN] Could not save investigation to PostgreSQL: {e}")
        import traceback
        traceback.print_exc()
    
    # Update IOC severities (default to medium for manual investigations)
    try:
        from services.database import db
        
        if db.connected:
            severity = 'medium'  # Default for manual investigations
            
            # Update all IOCs from this investigation with the determined severity
            for indicator in indicators:
                await db.track_or_update_ioc({
                    "ioc_value": indicator.value,
                    "ioc_type": str(indicator.type).lower().replace("indicatortype.", ""),
                    "severity": severity,
                    "investigation_id": investigation_id
                })
            
            logger.info(f"[OK] Tracked {len(indicators)} IOCs with severity: {severity}")
    except Exception as e:
        logger.warning(f"[WARN] Could not update IOC severities: {e}")
    
    # === ADVANCED FEATURES: Generate Framework Matches, Timeline, Correlations ===
    try:
        logger.info("[GEN] Generating advanced investigation features...")
        
        # 1. Framework Mapping
        from services.framework_mapper import get_framework_matches
        
        framework_data = {
            "title": alert.title,
            "description": alert.description or "",
            "severity": "medium",  # Default severity for manual investigations
            "indicators": [{"type": str(ind.type), "value": ind.value} for ind in indicators]
        }
        framework_matches = get_framework_matches(framework_data)
        result.framework_matches = framework_matches
        logger.info(f"[OK] Matched {sum(len(v) for v in framework_matches.values())} framework controls")
        
        # 2. Correlation Engine
        from services.correlation_engine import CorrelationEngine
        from services.database import db
        
        if db.connected:
            correlation_engine = CorrelationEngine(db)
            correlations = await correlation_engine.correlate_investigation(investigation_id)
            result.correlations = correlations
            logger.info(f"[OK] Found correlations (score: {correlations.get('correlation_score', 0)})")
        
        # 3. Timeline Generation
        from services.timeline_generator import TimelineGenerator
        
        if db.connected:
            timeline_generator = TimelineGenerator(db)
            timeline = await timeline_generator.generate_timeline(investigation_id)
            result.timeline_events = [
                {
                    "timestamp": event["timestamp"].isoformat() if isinstance(event["timestamp"], datetime) else event["timestamp"],
                    "type": event["type"],
                    "description": event["description"],
                    "metadata": event.get("metadata", {}),
                    "icon": event.get("icon", "[EVENT]"),
                    "color": event.get("color", "#6b7280")
                }
                for event in timeline
            ]
            logger.info(f"[OK] Generated timeline with {len(timeline)} events")
        
        # 4. Store indicators in new format
        result.indicators = [
            {
                "type": str(ind.type).replace("IndicatorType.", "").lower(),
                "value": ind.value,
                "context": ind.context,
                "confidence": "high"
            }
            for ind in indicators
        ]
        
    except Exception as e:
        logger.warning(f"[WARN] Advanced features generation error: {e}")
        import traceback
        traceback.print_exc()
    
    # Save investigation to database
    try:
        from services.database import db
        if db.connected:
            # Convert Pydantic model to dict
            if hasattr(result, 'model_dump'):
                result_dict = result.model_dump(mode='json')
            else:
                result_dict = result.dict()
            
            result_dict["investigation_id"] = investigation_id
            
            # Remove correlations from saved data (too large, query on demand)
            result_dict.pop("ioc_correlations", None)
            
            # Convert datetime strings back to datetime objects
            for field in ["timestamp", "created_at", "completed_at"]:
                if field in result_dict and isinstance(result_dict[field], str):
                    try:
                        result_dict[field] = datetime.fromisoformat(result_dict[field].replace('Z', '+00:00'))
                    except:
                        pass
            
            await db.save_investigation(result_dict)
            logger.info(f"[OK] Investigation {investigation_id} saved to database")
    except Exception as e:
        logger.warning(f"[WARN] Could not save investigation to database: {e}")

    
    return result


# ================== STATIC INVESTIGATION ROUTES (must come before parameterized routes) ==================

@app.get("/api/v1/investigations/queue/mine")
async def get_my_queue_static(current_user: str = Depends(get_current_username)):
    """
    Get investigations assigned to the current user.
    STATIC ROUTE - must be defined before parameterized route.
    """
    from services.assignment_service import get_assignment_service
    service = get_assignment_service()
    investigations = await service.get_my_queue(current_user)
    return {
        "owner": current_user,
        "count": len(investigations),
        "investigations": investigations
    }


@app.get("/api/v1/investigations/orphaned")
async def get_orphaned_static(
    stale_minutes: int = 60,
    current_user: str = Depends(get_current_username)
):
    """
    Get unassigned investigations that are stale.
    STATIC ROUTE - must be defined before parameterized route.
    """
    from services.assignment_service import get_assignment_service
    service = get_assignment_service()
    investigations = await service.get_orphaned_investigations(stale_minutes)
    return {
        "stale_threshold_minutes": stale_minutes,
        "count": len(investigations),
        "investigations": investigations
    }


@app.patch("/api/v1/investigations/bulk-update")
async def bulk_update_investigations(
    body: Dict = Body(...),
    current_user: dict = Depends(auth_get_current_user)
):
    """
    Bulk update multiple investigations at once.
    IMPORTANT: This route must be defined BEFORE parameterized routes like /{investigation_id}

    Body:
        {
            "investigation_ids": ["INV-ABC123", "INV-DEF456", ...],
            "updates": {
                "state": "CLOSED",           // optional
                "disposition": "BENIGN",     // optional
                "priority": "P2",            // optional
                "owner": "analyst@company.com", // optional
                "severity": "high"           // optional
            }
        }
    """
    from services.postgres_db import postgres_db

    # RBAC check: Only admin and platform_owner roles can perform bulk updates
    if current_user.get("role") not in ("admin", "platform_owner"):
        raise HTTPException(status_code=403, detail="Bulk update requires admin or platform_owner role")

    investigation_ids = body.get('investigation_ids', [])
    updates = body.get('updates', {})

    logger.info(f"[BULK-UPDATE-INV] Handler reached! investigation_ids: {len(investigation_ids)}, updates: {updates}")

    # ========================================================================
    # INPUT VALIDATION
    # ========================================================================

    # Validate that investigation_ids is provided and non-empty
    if not investigation_ids:
        logger.error(f"[BULK-UPDATE-INV] ERROR: investigation_ids is empty")
        raise HTTPException(status_code=400, detail="investigation_ids is required")

    # Validate size limit (maximum 1000 items per request)
    if len(investigation_ids) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 items per request")

    # Validate format: all IDs must be strings with non-zero length
    if not all(isinstance(id, str) and len(id) > 0 for id in investigation_ids):
        raise HTTPException(status_code=400, detail="All IDs must be non-empty strings")

    if not updates:
        logger.error(f"[BULK-UPDATE-INV] ERROR: updates is empty")
        raise HTTPException(status_code=400, detail="updates is required")

    # ========================================================================
    # RATE LIMITING
    # ========================================================================

    # Get rate limiter and check limit (10 requests per minute per user)
    rate_limiter = get_bulk_rate_limiter()
    user_id = current_user.get("id", "system_user")  # Extract from authenticated user
    if not rate_limiter.check_limit(user_id):
        logger.warning(f"Rate limit exceeded for bulk update investigations by user: {user_id}")
        raise HTTPException(
            status_code=429,
            detail="Too many bulk update requests. Maximum 10 per minute allowed."
        )

    # Validate updates (must match database constraint)
    valid_states = ['NEW', 'ANALYZING', 'NEEDS_REVIEW', 'IN_PROGRESS', 'CLOSED']
    valid_dispositions = ['MALICIOUS', 'BENIGN', 'SUSPICIOUS', 'TRUE_POSITIVE',
                          'FALSE_POSITIVE', 'BENIGN_POSITIVE', 'INCONCLUSIVE', 'UNKNOWN']
    valid_priorities = ['P1', 'P2', 'P3', 'P4']
    valid_severities = ['low', 'medium', 'high', 'critical']

    # Normalize state to uppercase and map user-facing states to database states
    if 'state' in updates:
        updates['state'] = updates['state'].upper()
        # Map RESOLVED to CLOSED (database doesn't have RESOLVED state)
        if updates['state'] == 'RESOLVED':
            updates['state'] = 'CLOSED'
        # Map INVESTIGATING to IN_PROGRESS
        if updates['state'] == 'INVESTIGATING':
            updates['state'] = 'IN_PROGRESS'
        # Map OPEN to ANALYZING (closest equivalent)
        if updates['state'] == 'OPEN':
            updates['state'] = 'ANALYZING'

    if 'state' in updates and updates['state'] not in valid_states:
        raise HTTPException(status_code=400, detail="Internal server error")

    if 'disposition' in updates and updates['disposition'] not in valid_dispositions:
        raise HTTPException(status_code=400, detail="Internal server error")

    if 'priority' in updates and updates['priority'] not in valid_priorities:
        raise HTTPException(status_code=400, detail="Internal server error")

    if 'severity' in updates:
        updates['severity'] = updates['severity'].lower()
        if updates['severity'] not in valid_severities:
            raise HTTPException(status_code=400, detail="Internal server error")

    try:
        from middleware.tenant_middleware import get_current_tenant_id
        tenant_id = get_current_tenant_id()
        if not tenant_id:
            raise HTTPException(status_code=400, detail="No tenant context for this request")

        async with postgres_db.tenant_acquire() as conn:
            # Tenant validation: the RLS policy on tenant_acquire() already
            # restricts visibility to the caller's tenant, so we just verify
            # the requested investigation_ids exist for this tenant.
            tenant_check_query = """
                SELECT COUNT(*) as count FROM investigations
                WHERE investigation_id = ANY($1)
            """
            tenant_result = await conn.fetchval(tenant_check_query, investigation_ids)
            if tenant_result != len(investigation_ids):
                raise HTTPException(status_code=403, detail="One or more investigations do not belong to your tenant")

            # Build the SET clause dynamically
            set_clauses = []
            values = []
            param_count = 1

            if 'state' in updates:
                set_clauses.append(f"state = ${param_count}")
                values.append(updates['state'])
                param_count += 1
                # Set completed_at if closing
                if updates['state'] in ['CLOSED']:
                    set_clauses.append(f"completed_at = CURRENT_TIMESTAMP")
                # First move out of NEW counts as acknowledgment (response SLA stop)
                if updates['state'] not in ('NEW',):
                    set_clauses.append("acknowledged_at = COALESCE(acknowledged_at, CURRENT_TIMESTAMP)")

            if 'disposition' in updates:
                set_clauses.append(f"disposition = ${param_count}")
                values.append(updates['disposition'])
                param_count += 1

            if 'priority' in updates:
                set_clauses.append(f"priority = ${param_count}")
                values.append(updates['priority'])
                param_count += 1

            if 'owner' in updates:
                set_clauses.append(f"owner = ${param_count}")
                values.append(updates['owner'])
                param_count += 1
                set_clauses.append("assigned_at = CURRENT_TIMESTAMP")
                # Assigning an owner also acknowledges the investigation
                set_clauses.append("acknowledged_at = COALESCE(acknowledged_at, CURRENT_TIMESTAMP)")

            if 'severity' in updates:
                set_clauses.append(f"severity = ${param_count}")
                values.append(updates['severity'])
                param_count += 1

            set_clauses.append("updated_at = CURRENT_TIMESTAMP")

            if not set_clauses:
                return {"success": True, "updated_count": 0, "message": "No valid updates provided"}

            # Add investigation_ids as final parameter (use ANY() syntax like alerts endpoint)
            values.append(investigation_ids)

            query = f"""
                UPDATE investigations
                SET {', '.join(set_clauses)}
                WHERE investigation_id = ANY(${param_count})
                RETURNING investigation_id
            """

            result_rows = await conn.fetch(query, *values)
            updated_count = len(result_rows)
            logger.info(f"[BULK-UPDATE-INV] Query executed. Updated count: {updated_count}, rows: {result_rows}")

            # If state changed to CLOSED or RESOLVED, also update linked alerts
            new_state = updates.get('state', '').upper()
            if new_state in ['CLOSED', 'RESOLVED'] and updated_count > 0:
                # Determine alert status based on state and disposition
                alert_status = 'closed' if new_state == 'CLOSED' else 'resolved'
                disposition = updates.get('disposition', '').upper()
                if disposition == 'FALSE_POSITIVE':
                    alert_status = 'false_positive'
                elif disposition in ['TRUE_POSITIVE', 'MALICIOUS']:
                    alert_status = 'confirmed'

                # Get the UUIDs of the investigations we just updated
                inv_uuid_placeholders = ', '.join(f"${i}" for i in range(1, 1 + len(investigation_ids)))
                inv_uuids = await conn.fetch(f"""
                    SELECT id FROM investigations WHERE investigation_id IN ({inv_uuid_placeholders})
                """, *investigation_ids)
                inv_uuid_list = [row['id'] for row in inv_uuids]

                if inv_uuid_list:
                    # Update all alerts linked to these investigations via investigation_id
                    uuid_placeholders = ', '.join(f"${i}" for i in range(2, 2 + len(inv_uuid_list)))
                    alert_update_query = f"""
                        UPDATE alerts
                        SET status = $1, updated_at = NOW(), closed_at = NOW()
                        WHERE investigation_id IN ({uuid_placeholders})
                        AND status NOT IN ('resolved', 'closed')
                    """
                    alert_result = await conn.execute(alert_update_query, alert_status, *inv_uuid_list)
                    alert_updated_count = int(alert_result.split()[-1])
                    logger.info(f"[OK] Bulk update: {alert_updated_count} alerts updated to '{alert_status}'")

            # Log the bulk update
            await postgres_db.log_audit(
                username=current_user["username"],
                action="bulk_update_investigations",
                resource_type="investigation",
                resource_id=f"bulk_{updated_count}_investigations",
                details={
                    "investigation_ids": investigation_ids,
                    "updates": updates,
                    "updated_count": updated_count
                }
            )

            return {
                "success": True,
                "updated_count": updated_count,
                "requested_count": len(investigation_ids),
                "updates": updates
            }

    except Exception as e:
        logger.info(f"Bulk update investigations error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error")


# ================== PARAMETERIZED INVESTIGATION ROUTES ==================

@app.get("/api/v1/investigations/{investigation_id}")
async def get_investigation(
    investigation_id: str,
    current_user: dict = Depends(auth_get_current_user)
):
    """
    Get investigation results by ID from PostgreSQL.

    SECURITY: Requires authentication
    """

    # Static routes are defined earlier - if we get here with 'orphaned' or 'queue',
    # redirect to the static handlers
    if investigation_id == "orphaned":
        from services.assignment_service import get_assignment_service
        service = get_assignment_service()
        investigations = await service.get_orphaned_investigations(60)
        return {
            "stale_threshold_minutes": 60,
            "count": len(investigations),
            "investigations": investigations
        }

    investigation = None

    # Try PostgreSQL first (PRIMARY)
    try:
        from services.postgres_db import postgres_db
        if postgres_db.connected:
            is_admin = current_user.get("role") in ("admin", "platform_owner")
            inv_doc = await postgres_db.get_investigation_by_id(investigation_id, admin_bypass=is_admin)
            if inv_doc:
                logger.info(f"[OK] Loaded investigation {investigation_id} from PostgreSQL")
                return inv_doc
    except Exception as e:
        logger.warning(f"[WARN] PostgreSQL query failed: {e}")
    
    # Fall back to in-memory store
    if investigation_id in investigations_store:
        investigation = investigations_store[investigation_id]
        logger.info(f"[LOAD] Loaded investigation {investigation_id} from memory")
        return investigation.dict() if hasattr(investigation, 'dict') else investigation
    
    raise HTTPException(
        status_code=404,
        detail=f"Investigation {investigation_id} not found"
    )


@app.patch("/api/v1/investigations/{investigation_id}")
async def update_investigation(
    investigation_id: str,
    updates: dict,
    request: Request,
    current_user: Dict = Depends(auth_get_current_user),
):
    """
    Update investigation fields.
    Accepts: state, disposition, priority, owner, executive_summary, etc.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(503, "Database not available")

    # Map of allowed fields and their validation
    allowed_fields = {
        'state': ['NEW', 'OPEN', 'IN_PROGRESS', 'AWAITING_HUMAN', 'CLOSED', 'RESOLVED', 'ESCALATED'],
        'disposition': ['UNKNOWN', 'TRUE_POSITIVE', 'FALSE_POSITIVE', 'BENIGN', 'MALICIOUS', 'SUSPICIOUS', 'INCONCLUSIVE'],
        'priority': ['P1', 'P2', 'P3', 'P4'],
        'owner': None,  # Any string
        'executive_summary': None,  # Any string
        'severity': ['critical', 'high', 'medium', 'low', 'info'],
    }

    # Map frontend field names to backend field names
    field_aliases = {
        'verdict': 'disposition',
        'assigned_to': 'owner',
        'assignee': 'owner',
    }

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Build update query dynamically
            set_parts = []
            values = []
            param_idx = 1
            processed_updates = {}  # Track actual field names and values after processing
            seen_fields = set()  # Track fields we've already processed to avoid duplicates

            for field, value in updates.items():
                # Map aliases to actual field names
                actual_field = field_aliases.get(field, field)

                if actual_field not in allowed_fields:
                    continue  # Skip unknown fields

                # Skip if we've already processed this field (handles case where both
                # 'verdict' and 'disposition' are sent - both map to 'disposition')
                if actual_field in seen_fields:
                    continue
                seen_fields.add(actual_field)

                field = actual_field  # Use the actual field name

                # Validate if field has allowed values
                valid_values = allowed_fields[field]
                if valid_values and value not in valid_values:
                    # Try uppercase for state/disposition
                    upper_value = str(value).upper().replace(' ', '_')
                    if upper_value in valid_values:
                        value = upper_value
                    else:
                        raise HTTPException(400, f"Invalid {field}. Must be one of: {valid_values}")

                set_parts.append(f"{field} = ${param_idx}")
                values.append(value)
                processed_updates[field] = value  # Track the processed field and value
                param_idx += 1

            if not set_parts:
                raise HTTPException(400, "No valid fields to update")

            # Add updated_at
            set_parts.append(f"updated_at = ${param_idx}")
            values.append(datetime.utcnow())
            param_idx += 1

            # Add investigation_id for WHERE clause
            values.append(investigation_id)

            query = f"""
                UPDATE investigations
                SET {', '.join(set_parts)}
                WHERE investigation_id = ${param_idx}
                RETURNING *
            """

            row = await conn.fetchrow(query, *values)

            if not row:
                raise HTTPException(404, "Investigation not found")

            # If investigation state changed to CLOSED or RESOLVED, update linked alerts
            # Use processed_updates which has the actual field names and normalized values
            new_state = processed_updates.get('state', '').upper()
            if new_state in ['CLOSED', 'RESOLVED']:
                # Map investigation state to alert status
                alert_status = 'closed' if new_state == 'CLOSED' else 'resolved'

                # Also consider disposition for status (check processed_updates first, then row)
                disposition = processed_updates.get('disposition', row.get('disposition', '') or '').upper()
                if disposition == 'FALSE_POSITIVE':
                    alert_status = 'false_positive'
                elif disposition in ['TRUE_POSITIVE', 'MALICIOUS']:
                    alert_status = 'confirmed'

                investigation_uuid = row.get('id')  # The investigation's UUID
                logger.info(f"[SYNC] Syncing alerts for investigation {investigation_id} (UUID: {investigation_uuid}) to status '{alert_status}'")

                # Update all alerts linked to this investigation via investigation_id
                result = await conn.execute("""
                    UPDATE alerts
                    SET status = $1, updated_at = NOW(), closed_at = NOW()
                    WHERE investigation_id = $2 AND status NOT IN ('resolved', 'closed', 'false_positive', 'confirmed')
                """, alert_status, investigation_uuid)
                updated_count = int(result.split()[-1])
                if updated_count > 0:
                    logger.info(f"[OK] {updated_count} alert(s) status updated to '{alert_status}' (investigation {new_state})")
                else:
                    logger.warning(f"[WARN] No alerts found to update for investigation_id={investigation_uuid}")

                # Trigger playbooks for investigation closed
                try:
                    import asyncio
                    from services.playbook_trigger_service import trigger_playbooks_for_event
                    investigation_dict = dict(row)
                    investigation_dict['id'] = str(investigation_dict.get('id')) if investigation_dict.get('id') else None
                    asyncio.create_task(
                        trigger_playbooks_for_event(
                            event_type="investigation_closed",
                            investigation=investigation_dict,
                            investigation_id=investigation_id
                        )
                    )
                except Exception as trigger_err:
                    logger.info(f"Investigation {investigation_id}: Playbook trigger failed - {trigger_err}")

            # Log audit
            await postgres_db.log_audit(
                username=updates.get('updated_by', 'admin'),
                action="update_investigation",
                resource_type="investigation",
                resource_id=investigation_id,
                details={"updates": updates}
            )

            # Return the updated investigation row so frontend can merge it
            updated_inv = dict(row)
            # Serialize UUID/datetime fields for JSON
            for k, v in updated_inv.items():
                if hasattr(v, 'isoformat'):
                    updated_inv[k] = v.isoformat()
                elif hasattr(v, 'hex') and hasattr(v, 'int'):
                    updated_inv[k] = str(v)
            return updated_inv

    except HTTPException:
        raise
    except Exception as e:
        logger.info(f"Error updating investigation: {e}")
        raise HTTPException(500, str(e))


@app.put("/api/v1/investigations/{investigation_id}")
async def update_investigation_put(
    investigation_id: str,
    updates: dict,
    request: Request,
    current_user: Dict = Depends(auth_get_current_user),
):
    """PUT version of update investigation - forwards to PATCH handler"""
    return await update_investigation(investigation_id, updates, request, current_user)


@app.post("/api/v1/investigations/{investigation_id}/run-script")
async def run_investigation_script(investigation_id: str, script_data: Dict[str, Any] = Body(...)):
    """
    Execute a saved Python script in the context of an investigation.
    
    Body should contain:
    {
      "script_id": "script-123",  // Optional: specific script to run
      "script_code": "logger.info('hello')",  // Optional: ad-hoc code to run
      "timeout": 30  // Optional: execution timeout in seconds
    }
    """
    try:
        # Get the investigation
        investigation = None
        try:
            from services.database import db
            if db.connected:
                inv_doc = await db.get_investigation(investigation_id)
                if inv_doc:
                    investigation = InvestigationResult(**inv_doc)
        except:
            pass
        
        if not investigation and investigation_id in investigations_store:
            investigation = investigations_store[investigation_id]
        
        if not investigation:
            raise HTTPException(status_code=404, detail="Investigation not found")
        
        # Get script code
        script_code = script_data.get("script_code")
        script_id = script_data.get("script_id")
        timeout = script_data.get("timeout", 30)
        
        if script_id:
            # Load script from database
            try:
                from services.database import db
                if db.connected:
                    script_doc = await db.get_script(script_id)
                    if script_doc:
                        script_code = script_doc.get("code")
            except Exception as e:
                raise HTTPException(status_code=404, detail="Internal server error")
        
        if not script_code:
            raise HTTPException(status_code=400, detail="No script code provided")
        
        # Execute script with investigation context
        import subprocess
        import sys
        import tempfile
        import json
        
        # Prepare investigation data as JSON for the script
        inv_data = investigation.dict() if hasattr(investigation, 'dict') else investigation
        
        # Create temporary Python file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            # Inject investigation data
            f.write("import json\n")
            f.write(f"investigation = json.loads('''{json.dumps(inv_data)}''')\n\n")
            f.write(script_code)
            temp_file = f.name
        
        try:
            # Execute script
            result = subprocess.run(
                [sys.executable, temp_file],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            import os
            os.unlink(temp_file)
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "errors": result.stderr,
                "return_code": result.returncode
            }
        
        except subprocess.TimeoutExpired:
            import os
            os.unlink(temp_file)
            raise HTTPException(status_code=408, detail="Script execution timeout")
        
        except Exception as e:
            import os
            try:
                os.unlink(temp_file)
            except:
                pass
            raise HTTPException(status_code=500, detail="Internal server error")
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/alerts", response_model=List[Dict])
async def list_alerts(
    limit: int = Query(default=1000, ge=1, le=10000),  # Max 10K alerts
    offset: int = 0,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    source: Optional[str] = None,
    q: Optional[str] = None,  # Search query
    include_investigated: bool = False,  # Include alerts that already have an investigation_id
):
    """List all alerts with optional filtering.

    By default, alerts that have been promoted to an investigation are excluded
    so callers (NewInvestigation, dashboards) don't see duplicates. The unified
    SecurityQueue dedups alert/investigation pairs itself, so it passes
    include_investigated=true to keep alert-side fields (source, source_type)
    available for the merged row.
    """
    from services.postgres_db import postgres_db

    logger.info(f"GET /api/v1/alerts - PostgreSQL connected: {postgres_db.connected}")

    # Try PostgreSQL first (primary database)
    if postgres_db.connected:
        try:
            alerts = await postgres_db.get_alerts(
                status=status,
                severity=severity,
                source=source,
                search_query=q,
                limit=limit,
                offset=offset,
                exclude_with_investigation=not include_investigated,
            )
            
            logger.info(f"Fetched {len(alerts)} alerts from PostgreSQL")

            # Get investigation states for alerts that have investigation_id
            investigation_ids = [a['investigation_id'] for a in alerts if a.get('investigation_id')]
            investigation_states = {}
            if investigation_ids:
                logger.info(f"[LOOKUP] Looking up {len(investigation_ids)} investigation states")
                async with postgres_db.tenant_acquire() as conn:
                    rows = await conn.fetch("""
                        SELECT id, state, disposition, completed_at FROM investigations
                        WHERE id = ANY($1::uuid[])
                    """, investigation_ids)
                    for row in rows:
                        investigation_states[row['id']] = {
                            'state': row['state'],
                            'disposition': row['disposition'],
                            'completed_at': row['completed_at'],
                        }
                        logger.info(f"  [INV] Investigation {row['id']}: state={row['state']}, disposition={row['disposition']}")

            # Convert datetime objects and JSONB to strings for JSON serialization
            for alert in alerts:
                # Handle timestamps — closed_at is needed downstream so the
                # SecurityQueue can compute "time to close" SLA instead of
                # falling back to updated_at (which keeps drifting).
                for ts_field in ('created_at', 'updated_at', 'closed_at'):
                    if alert.get(ts_field):
                        alert[ts_field] = alert[ts_field].isoformat()

                # Convert UUIDs to strings
                if alert.get('id'):
                    alert['id'] = str(alert['id'])

                # Sync alert status with investigation state if investigation is resolved/closed
                if alert.get('investigation_id'):
                    inv_uuid = alert['investigation_id']
                    inv_info = investigation_states.get(inv_uuid)
                    if inv_info:
                        inv_state = (inv_info.get('state') or '').upper()
                        inv_disposition = (inv_info.get('disposition') or '').upper()

                        # Final dispositions indicate investigation is effectively resolved
                        final_dispositions = ['FALSE_POSITIVE', 'TRUE_POSITIVE', 'MALICIOUS', 'BENIGN']
                        is_resolved = inv_state in ['RESOLVED', 'CLOSED'] or inv_disposition in final_dispositions

                        # If investigation is resolved/closed OR has a final disposition, update alert status
                        if is_resolved:
                            old_status = alert.get('status')
                            if inv_disposition == 'FALSE_POSITIVE':
                                alert['status'] = 'false_positive'
                            elif inv_disposition in ['TRUE_POSITIVE', 'MALICIOUS']:
                                alert['status'] = 'confirmed'
                            elif inv_disposition == 'BENIGN':
                                alert['status'] = 'resolved'
                            elif inv_state == 'CLOSED':
                                alert['status'] = 'closed'
                            else:
                                alert['status'] = 'resolved'
                            # Project the investigation's close time onto the alert when
                            # the alert itself never got closed_at stamped (legacy auto-
                            # resolve paths). Lets the queue SLA reflect the real close
                            # time instead of falling back to updated_at.
                            if not alert.get('closed_at'):
                                inv_completed = inv_info.get('completed_at')
                                if inv_completed:
                                    alert['closed_at'] = inv_completed.isoformat() if hasattr(inv_completed, 'isoformat') else inv_completed
                            logger.info(f"  [OK] Alert {alert.get('alert_id')}: status {old_status} -> {alert['status']} (inv state={inv_state}, disp={inv_disposition})")
                    else:
                        logger.warning(f"  [WARN] Alert {alert.get('alert_id')}: inv_uuid {inv_uuid} not found in investigation_states")

                    alert['investigation_id'] = str(inv_uuid)

                # Handle JSONB raw_event - it's already a dict from asyncpg
                # Just make sure it exists
                if 'raw_event' not in alert or alert['raw_event'] is None:
                    alert['raw_event'] = {}

            return alerts
        except Exception as e:
            logging.getLogger("app.alerts").error(f"Error fetching alerts from PostgreSQL: {e}", exc_info=True)
    
    # Legacy fallback (legacy)
    try:
        from services.database import db
        if db.connected:
            query = {}
            if status and status != 'all':
                query["status"] = status
            if severity:
                query["severity"] = severity.lower()
            if source:
                query["source"] = source
            
            alerts = []
            cursor = db.db.alerts.find(query).sort("created_at", -1).limit(limit)
            async for alert in cursor:
                alert["_id"] = str(alert["_id"])
                alerts.append(alert)
            
            return alerts
    except Exception as e:
        logger.info(f"Error fetching alerts from database: {e}")
    
    return []


@app.get("/api/v1/alerts/{alert_id}/investigation")
async def get_alert_investigation(alert_id: str):
    """Get investigation linked to an alert"""
    from services.postgres_db import postgres_db
    
    if postgres_db.connected:
        try:
            investigation = await postgres_db.get_alert_investigation(alert_id)
            if investigation:
                # Convert datetime to ISO format
                for key in ['created_at', 'updated_at', 'completed_at', 'assigned_at']:
                    if investigation.get(key):
                        investigation[key] = investigation[key].isoformat()
                # Convert UUIDs to strings
                for key in ['id', 'alert_id']:
                    if investigation.get(key):
                        investigation[key] = str(investigation[key])
                return investigation
        except Exception as e:
            logger.info(f"Error fetching investigation: {e}")
    
    return None


@app.patch("/api/v1/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, body: Dict = Body(...)):
    """Update alert status. Optionally accepts `disposition` so callers
    (e.g. the drawer's "Close as Benign / FP / TP" buttons) can set both
    in a single round-trip and have the cascade write the right
    investigation disposition."""
    from services.postgres_db import postgres_db

    new_status = body.get('status')
    if not new_status:
        raise HTTPException(status_code=400, detail="Status is required")
    explicit_disposition = body.get('disposition')
    
    if postgres_db.connected:
        try:
            success = await postgres_db.update_alert_status(alert_id, new_status)
            if success:
                  # Log audit
                  await postgres_db.log_audit(
                      username="admin",  # TODO: Get from auth
                      action="update_alert_status",
                      resource_type="alert",
                      resource_id=alert_id,
                      details={"old_status": "unknown", "new_status": new_status}
                  )

                  # Cascade to the linked investigation so the dashboard /
                  # drawer don't show divergent states. Previously closing an
                  # alert left its investigation stuck in NEEDS_REVIEW, and
                  # the dashboard said "Closed" while the drawer still said
                  # "Needs Review" for the same row.
                  terminal_alert_statuses = ('closed', 'resolved', 'false_positive', 'confirmed')
                  if new_status.lower() in terminal_alert_statuses:
                      try:
                          async with postgres_db.tenant_acquire() as conn:
                              alert_row = await conn.fetchrow(
                                  "SELECT investigation_id, ai_verdict FROM alerts WHERE alert_id = $1",
                                  alert_id,
                              )
                              if alert_row and alert_row['investigation_id']:
                                  # Caller may pass an explicit disposition
                                  # (e.g. "Close as Benign" button) which wins
                                  # over any inference from status / ai_verdict.
                                  inferred_disposition = None
                                  if explicit_disposition:
                                      v = str(explicit_disposition).upper()
                                      if v in ('BENIGN', 'FALSE_POSITIVE', 'TRUE_POSITIVE', 'MALICIOUS'):
                                          inferred_disposition = v
                                  if inferred_disposition is None:
                                      if new_status.lower() == 'false_positive':
                                          inferred_disposition = 'FALSE_POSITIVE'
                                      elif new_status.lower() == 'confirmed':
                                          inferred_disposition = 'TRUE_POSITIVE'
                                      elif alert_row['ai_verdict']:
                                          v = str(alert_row['ai_verdict']).upper()
                                          if v in ('BENIGN', 'FALSE_POSITIVE', 'TRUE_POSITIVE', 'MALICIOUS'):
                                              inferred_disposition = v

                                  # Only close the parent investigation when
                                  # every sibling alert is also in a terminal
                                  # status. If even one child is still open,
                                  # leave the investigation alone (just bump
                                  # its disposition if we have a confident
                                  # call). This prevents one analyst closing
                                  # the first alert of a 20-alert correlation
                                  # group from prematurely closing the case.
                                  open_siblings = await conn.fetchval(
                                      """
                                      SELECT COUNT(*) FROM alerts
                                       WHERE investigation_id = $1
                                         AND LOWER(status) NOT IN ('closed', 'resolved', 'false_positive', 'confirmed')
                                      """,
                                      alert_row['investigation_id'],
                                  )

                                  if open_siblings and open_siblings > 0:
                                      # Children still open — don't close yet.
                                      # Surface a disposition if we have a
                                      # confident one so the case carries the
                                      # latest analyst signal.
                                      if inferred_disposition:
                                          await conn.execute(
                                              """
                                              UPDATE investigations
                                                 SET disposition = COALESCE(NULLIF(disposition, 'NEEDS_INVESTIGATION'), $2, disposition),
                                                     updated_at  = CURRENT_TIMESTAMP
                                               WHERE id = $1
                                                 AND state NOT IN ('CLOSED', 'RESOLVED')
                                              """,
                                              alert_row['investigation_id'],
                                              inferred_disposition,
                                          )
                                      logger.info(
                                          f"Alert {alert_id} closed but investigation "
                                          f"{alert_row['investigation_id']} kept open — "
                                          f"{open_siblings} sibling alert(s) still open"
                                      )
                                  else:
                                      await conn.execute(
                                          """
                                          UPDATE investigations
                                             SET state         = 'CLOSED',
                                                 disposition   = COALESCE(NULLIF(disposition, 'NEEDS_INVESTIGATION'),
                                                                          $2, disposition),
                                                 completed_at  = COALESCE(completed_at, CURRENT_TIMESTAMP),
                                                 updated_at    = CURRENT_TIMESTAMP
                                           WHERE id = $1
                                             AND state NOT IN ('CLOSED', 'RESOLVED')
                                          """,
                                          alert_row['investigation_id'],
                                          inferred_disposition,
                                      )
                                      logger.info(
                                          f"Cascaded alert {alert_id} close to investigation "
                                          f"{alert_row['investigation_id']} (all siblings closed, "
                                          f"disposition={inferred_disposition})"
                                      )
                      except Exception as cascade_err:
                          # Best-effort cascade; alert status update has
                          # already succeeded, so don't fail the request.
                          logger.warning(f"Alert {alert_id}: investigation cascade failed - {cascade_err}")

                  if new_status.lower() in ['closed', 'resolved']:
                      try:
                          import asyncio
                          from services.playbook_trigger_service import trigger_playbooks_for_event
                          asyncio.create_task(
                              trigger_playbooks_for_event(
                                  event_type="alert_closed",
                                  alert={"alert_id": alert_id, "status": new_status},
                                  alert_id=alert_id
                              )
                          )
                      except Exception as trigger_err:
                          logger.info(f"Alert {alert_id}: Playbook trigger failed - {trigger_err}")
                  return {"success": True, "alert_id": alert_id, "status": new_status}
            else:
                raise HTTPException(status_code=404, detail="Alert not found")
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")
    
    raise HTTPException(status_code=503, detail="Database not available")


@app.patch("/api/v1/alerts/{alert_id}/severity")
async def update_alert_severity(alert_id: str, body: Dict = Body(...)):
    """Update alert severity"""
    from services.postgres_db import postgres_db
    
    new_severity = body.get('severity')
    if not new_severity:
        raise HTTPException(status_code=400, detail="Severity is required")
    
    # Validate severity
    valid_severities = ['low', 'medium', 'high', 'critical']
    if new_severity.lower() not in valid_severities:
        raise HTTPException(status_code=400, detail="Internal server error")
    
    if postgres_db.connected:
        try:
            success = await postgres_db.update_alert_severity(alert_id, new_severity.lower())
            if success:
                # Log audit
                await postgres_db.log_audit(
                    username="admin",  # TODO: Get from auth
                    action="update_alert_severity",
                    resource_type="alert",
                    resource_id=alert_id,
                    details={"old_severity": "unknown", "new_severity": new_severity}
                )
                return {"success": True, "alert_id": alert_id, "severity": new_severity}
            else:
                raise HTTPException(status_code=404, detail="Alert not found")
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")
    
    raise HTTPException(status_code=503, detail="Database not available")


@app.post("/api/v1/alerts/{alert_id}/escalate")
async def escalate_alert(alert_id: str, body: Dict = Body(default={}), current_user: dict = Depends(auth_get_current_user)):
    """Escalate an alert.

    Two side effects beyond a normal status/severity edit:
      1. Bump severity to 'critical' (unless already critical)
      2. Drop a tenant-wide notification with a deep-link to the alert,
         so anyone watching the bell sees it without needing email rules

    Body fields (all optional):
      - reason: short free-text shown in the notification body
      - target_severity: override the default 'critical' bump (e.g. 'high')
    """
    from services.postgres_db import postgres_db
    from middleware.tenant_middleware import get_optional_tenant_id

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")

    reason = (body.get('reason') or '').strip()
    target_severity = (body.get('target_severity') or 'critical').lower()
    if target_severity not in ('high', 'critical'):
        target_severity = 'critical'

    try:
        # Fetch alert so we can build a meaningful notification + know what
        # we're actually escalating against.
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT a.id, a.title, a.severity, a.investigation_id, i.investigation_id AS inv_pretty_id
                  FROM alerts a
                  LEFT JOIN investigations i ON i.id = a.investigation_id
                 WHERE a.alert_id = $1
                """,
                alert_id,
            )
            if not row:
                raise HTTPException(status_code=404, detail="Alert not found")
            current_severity = (row['severity'] or 'medium').lower()
            severity_order = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
            # Only bump severity if escalation target is higher than current.
            if severity_order.get(target_severity, 3) > severity_order.get(current_severity, 0):
                await conn.execute(
                    "UPDATE alerts SET severity = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
                    target_severity,
                    row['id'],
                )
                if row['investigation_id']:
                    await conn.execute(
                        "UPDATE investigations SET severity = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
                        target_severity,
                        row['investigation_id'],
                    )
                bumped_to = target_severity
            else:
                bumped_to = current_severity

        tenant_id = get_optional_tenant_id()
        actor = current_user.get('username') or current_user.get('email') or 'analyst'
        title = f"Alert escalated: {row['title'][:80]}" if row['title'] else f"Alert escalated: {alert_id}"
        message_parts = [f"Escalated by {actor}."]
        if reason:
            message_parts.append(reason)
        if bumped_to != current_severity:
            message_parts.append(f"Severity raised {current_severity} -> {bumped_to}.")
        link = (
            f"/investigation/{row['inv_pretty_id']}" if row['inv_pretty_id']
            else f"/queue?view=alerts&search={alert_id}&drawer={alert_id}"
        )

        if tenant_id:
            try:
                from routes.notifications import create_notification
                await create_notification(
                    tenant_id=str(tenant_id),
                    title=title,
                    message=' '.join(message_parts),
                    category="alert",
                    severity="critical",
                    link=link,
                    metadata={
                        "alert_id": alert_id,
                        "investigation_id": row['inv_pretty_id'],
                        "escalated_by": actor,
                        "reason": reason,
                    },
                )
            except Exception as notify_err:
                logger.warning(f"Alert {alert_id}: escalation notification failed - {notify_err}")

        await postgres_db.log_audit(
            username=actor,
            action="escalate_alert",
            resource_type="alert",
            resource_id=alert_id,
            details={"reason": reason, "severity_before": current_severity, "severity_after": bumped_to},
        )

        return {
            "success": True,
            "alert_id": alert_id,
            "severity": bumped_to,
            "previous_severity": current_severity,
            "notified": tenant_id is not None,
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to escalate alert {alert_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to escalate alert")


@app.patch("/api/v1/alerts/{alert_id}/sensitivity")
async def update_alert_sensitivity(alert_id: str, body: Dict = Body(...)):
    """Update alert sensitivity (RBAC: update_sensitivity required)"""
    from services.postgres_db import postgres_db

    new_sensitivity = body.get('sensitivity')
    if not new_sensitivity:
        raise HTTPException(status_code=400, detail="Sensitivity is required")

    valid = ['public', 'internal', 'confidential', 'restricted']
    if new_sensitivity.lower() not in valid:
        raise HTTPException(status_code=400, detail="Internal server error")

    if postgres_db.connected:
        try:
            success = await postgres_db.update_alert_sensitivity(alert_id, new_sensitivity.lower())
            if success:
                await postgres_db.log_audit(
                    username="admin",
                    action="update_alert_sensitivity",
                    resource_type="alert",
                    resource_id=alert_id,
                    details={"new_sensitivity": new_sensitivity}
                )
                return {"success": True, "alert_id": alert_id, "sensitivity": new_sensitivity}
            else:
                raise HTTPException(status_code=404, detail="Alert not found")
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    raise HTTPException(status_code=503, detail="Database not available")


@app.patch("/api/v1/investigations/{investigation_id}/sensitivity")
async def update_investigation_sensitivity(investigation_id: str, body: Dict = Body(...)):
    """Update investigation sensitivity (RBAC: update_sensitivity required)"""
    from services.postgres_db import postgres_db

    new_sensitivity = body.get('sensitivity')
    if not new_sensitivity:
        raise HTTPException(status_code=400, detail="Sensitivity is required")

    valid = ['public', 'internal', 'confidential', 'restricted']
    if new_sensitivity.lower() not in valid:
        raise HTTPException(status_code=400, detail="Internal server error")

    if postgres_db.connected:
        try:
            success = await postgres_db.update_investigation_field(
                investigation_id, 'sensitivity', new_sensitivity.lower()
            )
            if success:
                await postgres_db.log_audit(
                    username="admin",
                    action="update_investigation_sensitivity",
                    resource_type="investigation",
                    resource_id=investigation_id,
                    details={"new_sensitivity": new_sensitivity}
                )
                return {"success": True, "investigation_id": investigation_id, "sensitivity": new_sensitivity}
            else:
                raise HTTPException(status_code=404, detail="Investigation not found")
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error")

    raise HTTPException(status_code=503, detail="Database not available")


@app.get("/api/v1/alerts/ai-verdicts")
async def get_alerts_with_ai_verdicts(
    verdict: Optional[str] = None,
    min_confidence: Optional[float] = None,
    limit: int = 50
):
    """
    Get alerts with AI verdicts.

    Filters:
    - verdict: Filter by specific verdict (MALICIOUS, SUSPICIOUS, BENIGN, etc.)
    - min_confidence: Filter by minimum confidence score
    - limit: Maximum number of alerts to return
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Build query based on filters
            query = '''
                SELECT
                    alert_id,
                    title,
                    severity,
                    status,
                    ai_verdict,
                    ai_confidence,
                    ai_summary,
                    created_at,
                    updated_at
                FROM alerts
                WHERE ai_verdict IS NOT NULL
            '''
            params = []
            param_count = 0

            if verdict:
                param_count += 1
                query += f' AND ai_verdict = ${param_count}'
                params.append(verdict)

            if min_confidence is not None:
                param_count += 1
                query += f' AND ai_confidence >= ${param_count}'
                params.append(min_confidence)

            query += ' ORDER BY updated_at DESC'

            param_count += 1
            query += f' LIMIT ${param_count}'
            params.append(limit)

            rows = await conn.fetch(query, *params)

            return {
                "alerts": [
                    {
                        "alert_id": row['alert_id'],
                        "title": row['title'],
                        "severity": row['severity'],
                        "status": row['status'],
                        "ai_verdict": row['ai_verdict'],
                        "ai_confidence": float(row['ai_confidence']) if row['ai_confidence'] else None,
                        "ai_summary": row['ai_summary'],
                        "created_at": row['created_at'].isoformat() if row['created_at'] else None,
                        "updated_at": row['updated_at'].isoformat() if row['updated_at'] else None
                    }
                    for row in rows
                ],
                "count": len(rows),
                "filters": {
                    "verdict": verdict,
                    "min_confidence": min_confidence,
                    "limit": limit
                }
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.patch("/api/v1/alerts/bulk-update")
async def bulk_update_alerts(
    body: Dict = Body(...),
    current_user: dict = Depends(auth_get_current_user)
):
    """
    Bulk update multiple alerts at once
    
    Body:
        {
            "alert_ids": ["alert_123", "alert_456", ...],
            "updates": {
                "status": "closed",        // optional
                "severity": "high",        // optional
                "category": "malware"      // optional
            }
        }
    """
    from services.postgres_db import postgres_db

    # RBAC check: Only admin and platform_owner roles can perform bulk updates
    if current_user.get("role") not in ("admin", "platform_owner"):
        raise HTTPException(status_code=403, detail="Bulk update requires admin or platform_owner role")

    alert_ids = body.get('alert_ids', [])
    updates = body.get('updates', {})

    # ========================================================================
    # INPUT VALIDATION
    # ========================================================================

    # Validate that alert_ids is provided and non-empty
    if not alert_ids:
        raise HTTPException(status_code=400, detail="alert_ids is required")

    # Validate size limit (maximum 1000 items per request)
    if len(alert_ids) > 1000:
        raise HTTPException(status_code=400, detail="Maximum 1000 items per request")

    # Validate format: all IDs must be strings with non-zero length
    if not all(isinstance(id, str) and len(id) > 0 for id in alert_ids):
        raise HTTPException(status_code=400, detail="All IDs must be non-empty strings")

    if not updates:
        raise HTTPException(status_code=400, detail="updates is required")

    # ========================================================================
    # RATE LIMITING
    # ========================================================================

    # Get rate limiter and check limit (10 requests per minute per user)
    rate_limiter = get_bulk_rate_limiter()
    user_id = current_user.get("id", "system_user")  # Extract from authenticated user
    if not rate_limiter.check_limit(user_id):
        logger.warning(f"Rate limit exceeded for bulk update alerts by user: {user_id}")
        raise HTTPException(
            status_code=429,
            detail="Too many bulk update requests. Maximum 10 per minute allowed."
        )

    # Validate severity if provided
    if 'severity' in updates:
        valid_severities = ['low', 'medium', 'high', 'critical']
        if updates['severity'].lower() not in valid_severities:
            raise HTTPException(status_code=400, detail="Internal server error")
        updates['severity'] = updates['severity'].lower()
    
    # Validate status if provided
    if 'status' in updates:
        valid_statuses = ['open', 'investigating', 'in_progress', 'needs_review', 'resolved', 'closed']
        if updates['status'].lower() not in valid_statuses:
            raise HTTPException(status_code=400, detail="Internal server error")
        updates['status'] = updates['status'].lower()
    
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    try:
        from middleware.tenant_middleware import get_current_tenant_id
        tenant_id = get_current_tenant_id()
        if not tenant_id:
            raise HTTPException(status_code=400, detail="No tenant context for this request")

        async with postgres_db.tenant_acquire() as conn:
            # Tenant validation: Verify all alerts belong to the current tenant.
            # The connection's RLS policy already filters by tenant, so we
            # just need to verify the requested alert_ids actually exist for
            # this tenant before issuing the UPDATE.
            tenant_check_query = """
                SELECT COUNT(*) as count FROM alerts
                WHERE alert_id = ANY($1)
            """
            tenant_result = await conn.fetchval(tenant_check_query, alert_ids)
            if tenant_result != len(alert_ids):
                raise HTTPException(status_code=403, detail="One or more alerts do not belong to your tenant")

            # Build update query dynamically
            set_clauses = []
            params = []
            param_index = 1

            if 'status' in updates:
                set_clauses.append(f"status = ${param_index}")
                params.append(updates['status'])
                param_index += 1

            if 'severity' in updates:
                set_clauses.append(f"severity = ${param_index}")
                params.append(updates['severity'])
                param_index += 1

            if 'category' in updates:
                set_clauses.append(f"category = ${param_index}")
                params.append(updates['category'])
                param_index += 1

            # Always update updated_at
            set_clauses.append(f"updated_at = ${param_index}")
            params.append(datetime.utcnow())
            param_index += 1

            # Add alert_ids as final parameter
            params.append(alert_ids)

            query = f"""
                UPDATE alerts
                SET {', '.join(set_clauses)}
                WHERE alert_id = ANY(${param_index})
                RETURNING alert_id
            """

            updated_rows = await conn.fetch(query, *params)
            updated_count = len(updated_rows)

            # Log audit trail
            await postgres_db.log_audit(
                username=current_user["username"],
                action="bulk_update_alerts",
                resource_type="alert",
                resource_id=f"bulk_{updated_count}_alerts",
                details={
                    "alert_ids": alert_ids,
                    "updates": updates,
                    "updated_count": updated_count
                }
            )

            return {
                "success": True,
                "updated_count": updated_count,
                "requested_count": len(alert_ids),
                "updates": updates
            }

    except Exception as e:
        logger.info(f"Bulk update error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/investigations", response_model=List[Dict])
async def list_investigations(
    limit: int = Query(default=100, ge=1, le=5000),  # Increased from unbounded to 5000 max
    state: Optional[str] = None,
    disposition: Optional[str] = None,
    owner: Optional[str] = None,
    priority: Optional[str] = None,
    sort_by: str = 'created_at',
    sort_order: str = 'desc',
    current_user: dict = Depends(auth_get_current_user)
):
    """
    List all investigations with filtering and sorting.

    SECURITY: Requires authentication

    Query params:
    - state: Filter by state (NEW, COMPLETED, etc.)
    - disposition: Filter by disposition (TRUE_POSITIVE, etc.)
    - owner: Filter by owner username
    - priority: Filter by priority (P1, P2, P3, P4)
    - sort_by: Sort field (created_at, updated_at, priority, severity)
    - sort_order: asc or desc
    - limit: Max results (default 100)
    """
    from services.postgres_db import postgres_db
    
    # Try PostgreSQL first (primary database)
    if postgres_db.connected:
        try:
            investigations = await postgres_db.get_investigations(
                state=state,
                disposition=disposition,
                owner=owner,
                priority=priority,
                sort_by=sort_by,
                sort_order=sort_order,
                limit=limit
            )
            
            # Convert datetime objects to strings
            for inv in investigations:
                for key in ['created_at', 'updated_at', 'completed_at', 'assigned_at', 'acknowledged_at']:
                    if inv.get(key):
                        inv[key] = inv[key].isoformat()
                # Convert UUIDs to strings
                for key in ['id', 'alert_id']:
                    if inv.get(key):
                        inv[key] = str(inv[key])
            
            return investigations
        except Exception as e:
            logger.info(f"Error fetching investigations from PostgreSQL: {e}")
            import traceback
            traceback.print_exc()
    
    # Legacy fallback (legacy)
    investigations_list = []

    # Try database first
    try:
        from services.database import db
        if db.connected:
            inv_docs = await db.get_all_investigations()
            if inv_docs:
                # Convert to InvestigationResult objects
                for doc in inv_docs:
                    try:
                        inv = InvestigationResult(**doc)
                        investigations.append(inv)
                    except Exception as e:
                        logger.warning(f"[WARN] Error parsing investigation {doc.get('investigation_id')}: {e}")
                        continue

                logger.info(f"[OK] Loaded {len(investigations)} investigations from database")
    except Exception as e:
        logger.warning(f"[WARN] database query failed, falling back to in-memory: {e}")

    # Fall back to in-memory store if database failed
    if not investigations:
        investigations = list(investigations_store.values())
        logger.info(f"[MEM] Using in-memory store: {len(investigations)} investigations")
    
    # Apply filters
    if disposition:
        investigations = [inv for inv in investigations if inv.disposition == disposition]
    
    if severity:
        investigations = [inv for inv in investigations if inv.severity == severity]
    
    # Sort by creation time (newest first)
    investigations.sort(key=lambda x: x.created_at, reverse=True)
    
    # Limit results
    investigations = investigations[:limit]
    
    # Return summary view
    return [
        {
            "investigation_id": inv.investigation_id,
            "alert_id": inv.alert_id,
            "severity": inv.severity,
            "disposition": inv.disposition,
            "confidence": inv.confidence,
            "created_at": inv.created_at,
            "completed_at": inv.completed_at,
            "summary": inv.executive_summary[:100] + "..." if len(inv.executive_summary) > 100 else inv.executive_summary
        }
        for inv in investigations
    ]


@app.post("/api/v1/investigations")
async def create_investigation(
    request: Dict[str, Any],
    current_user: dict = Depends(auth_get_current_user)
):
    """
    Manually create an investigation from alert IDs.

    Request body:
    {
        "alert_ids": ["alert-id-1", "alert-id-2"],  // Required: list of alert IDs
        "title": "Investigation Title",  // Optional
        "priority": "P2",  // Optional: P1, P2, P3, P4
        "severity": "high"  // Optional: low, medium, high, critical
    }
    """
    from services.postgres_db import postgres_db
    from middleware.tenant_middleware import get_current_tenant_id
    import uuid as uuid_mod
    from datetime import datetime

    try:
        # Accept both alert_id (singular) and alert_ids (array) from frontend
        alert_ids = request.get('alert_ids', [])
        if not alert_ids and request.get('alert_id'):
            alert_ids = [request.get('alert_id')]
        if not alert_ids:
            raise HTTPException(status_code=400, detail="alert_id or alert_ids required")

        # Get tenant context
        tenant_id = get_current_tenant_id()

        # Get the first alert to base the investigation on
        async with postgres_db.tenant_acquire() as conn:
            alert = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id::text = $1 OR alert_id = $1",
                str(alert_ids[0])
            )

            if not alert:
                raise HTTPException(status_code=404, detail=f"Alert {alert_ids[0]} not found")

            # Create investigation
            investigation_id = f"INV-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid_mod.uuid4())[:8]}"
            title = request.get('title', alert['title'])
            priority = request.get('priority', 'P3')
            severity = request.get('severity', alert['severity'])

            # Insert investigation with tenant_id
            inv_result = await conn.fetchrow('''
                INSERT INTO investigations (
                    investigation_id,
                    tenant_id,
                    alert_id,
                    state,
                    disposition,
                    priority,
                    severity,
                    alert_title,
                    executive_summary,
                    confidence,
                    owner,
                    owner_type,
                    created_at,
                    updated_at,
                    last_activity_at
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, NOW(), NOW(), NOW()
                )
                RETURNING *
            ''',
                investigation_id,
                uuid_mod.UUID(tenant_id),
                alert['id'],
                'NEW',
                'UNKNOWN',
                priority,
                severity,
                title,
                f"Manually created investigation for: {title}",
                0.0,
                current_user.get('username'),
                'human',
            )

            # Link all provided alerts to this investigation (use UUID id, not VARCHAR investigation_id)
            for alert_id in alert_ids:
                await conn.execute('''
                    UPDATE alerts
                    SET investigation_id = $1, updated_at = NOW()
                    WHERE id::text = $2 OR alert_id = $2
                ''', inv_result['id'], str(alert_id))

            logger.info(f"Created investigation {investigation_id} with {len(alert_ids)} alerts by {current_user.get('username')}")

            return {
                "investigation_id": investigation_id,
                "id": str(inv_result['id']),
                "state": inv_result['state'],
                "alert_count": len(alert_ids),
                "created_at": inv_result['created_at'].isoformat()
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create investigation: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/investigations/{investigation_id}/related")
async def get_related_items(investigation_id: str):
    """
    Get related alerts, investigations, and shared IOCs
    Returns correlation data for cross-referencing using PostgreSQL
    """
    import json
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            return {
                "related_alerts": [],
                "related_investigations": [],
                "shared_iocs": [],
                "correlation_score": 0
            }

        async with postgres_db.tenant_acquire() as conn:
            # Get the investigation's UUID and data
            inv = await conn.fetchrow("""
                SELECT i.id, i.investigation_id, i.alert_id, i.investigation_data
                FROM investigations i
                WHERE i.id::text = $1 OR i.investigation_id = $1
            """, investigation_id)

            if not inv:
                return {
                    "related_alerts": [],
                    "related_investigations": [],
                    "shared_iocs": [],
                    "correlation_score": 0
                }

            inv_uuid = inv['id']

            # Extract IOCs from investigation_data JSONB or linked alert
            ioc_values = []
            inv_data = inv['investigation_data'] or {}
            if isinstance(inv_data, str):
                try:
                    inv_data = json.loads(inv_data)
                except:
                    inv_data = {}

            # Try investigation_data.iocs first (set by hypothesis correlation)
            if 'iocs' in inv_data:
                for ioc in inv_data['iocs']:
                    if isinstance(ioc, dict) and ioc.get('value'):
                        ioc_values.append(ioc['value'])
                    elif isinstance(ioc, str):
                        ioc_values.append(ioc)

            # Also try tier1_analysis.iocs (set by AI triage)
            tier1 = inv_data.get('tier1_analysis', {})
            if isinstance(tier1, str):
                try:
                    tier1 = json.loads(tier1)
                except:
                    tier1 = {}
            for ioc in tier1.get('iocs', []):
                if isinstance(ioc, dict) and ioc.get('value'):
                    val = ioc['value']
                    if val not in ioc_values:
                        ioc_values.append(val)

            # Fallback: get IOCs from linked alert's raw_event
            if not ioc_values and inv['alert_id']:
                alert_row = await conn.fetchrow(
                    "SELECT raw_event FROM alerts WHERE id = $1", inv['alert_id']
                )
                if alert_row and alert_row['raw_event']:
                    raw = alert_row['raw_event']
                    if isinstance(raw, str):
                        try:
                            raw = json.loads(raw)
                        except:
                            raw = {}
                    for ioc in (raw.get('iocs') or []):
                        if isinstance(ioc, dict) and ioc.get('value'):
                            ioc_values.append(ioc['value'])

            # Find related alerts (same IOCs in title/description)
            related_alerts = []
            if ioc_values:
                # Build pattern for matching IOCs
                pattern = '|'.join([f"(?i){re.escape(v)}" for v in ioc_values[:20]])  # Limit to 20 IOCs
                alerts = await conn.fetch("""
                    SELECT a.alert_id, a.title, a.severity, a.source, a.status, a.created_at
                    FROM alerts a
                    WHERE a.investigation_id != $1
                      AND (a.title ~* $2 OR a.description ~* $2)
                    ORDER BY a.created_at DESC
                    LIMIT 10
                """, inv_uuid, pattern)

                for alert in alerts:
                    # Count matching IOCs
                    alert_text = (alert['title'] or '').lower()
                    match_count = sum(1 for v in ioc_values if v.lower() in alert_text)
                    related_alerts.append({
                        "alert_id": alert['alert_id'],
                        "title": alert['title'],
                        "severity": alert['severity'],
                        "source": alert['source'],
                        "status": alert['status'],
                        "created_at": alert['created_at'].isoformat() if alert['created_at'] else None,
                        "match_count": match_count
                    })

            # Find related investigations (share IOCs)
            related_investigations = []
            if ioc_values:
                investigations = await conn.fetch("""
                    SELECT i.id, i.investigation_id, i.alert_title, i.severity, i.created_at, i.investigation_data
                    FROM investigations i
                    WHERE i.id != $1
                      AND i.state NOT IN ('CLOSED', 'RESOLVED')
                    ORDER BY i.created_at DESC
                    LIMIT 50
                """, inv_uuid)

                for other_inv in investigations:
                    # Extract IOC values from other investigation's data
                    other_data = other_inv['investigation_data'] or {}
                    if isinstance(other_data, str):
                        try:
                            other_data = json.loads(other_data)
                        except:
                            other_data = {}
                    other_ioc_values = set()
                    for ioc in other_data.get('iocs', []):
                        if isinstance(ioc, dict) and ioc.get('value'):
                            other_ioc_values.add(ioc['value'].lower())
                    for ioc in other_data.get('tier1_analysis', {}).get('iocs', []):
                        if isinstance(ioc, dict) and ioc.get('value'):
                            other_ioc_values.add(ioc['value'].lower())

                    shared = set(v.lower() for v in ioc_values).intersection(other_ioc_values)

                    if shared:
                        related_investigations.append({
                            "investigation_id": other_inv['investigation_id'],
                            "summary": other_inv['alert_title'] or other_inv['investigation_id'],
                            "severity": other_inv['severity'],
                            "created_at": other_inv['created_at'].isoformat() if other_inv['created_at'] else None,
                            "match_count": len(shared)
                        })

                # Sort by match count
                related_investigations.sort(key=lambda x: x['match_count'], reverse=True)
                related_investigations = related_investigations[:10]

            # Get shared IOC details with occurrence counts
            shared_iocs = []
            for ioc_value in ioc_values[:20]:
                # Count in alerts
                alert_count = await conn.fetchval("""
                    SELECT COUNT(*) FROM alerts
                    WHERE title ILIKE $1 OR description ILIKE $1
                """, f"%{ioc_value}%")

                # Count in investigations
                inv_count = await conn.fetchval("""
                    SELECT COUNT(*) FROM investigations
                    WHERE investigation_data::text ILIKE $1
                """, f"%{ioc_value}%")

                if alert_count > 1 or inv_count > 1:
                    shared_iocs.append({
                        "value": ioc_value,
                        "alert_count": alert_count,
                        "investigation_count": inv_count,
                        "risk_score": min((alert_count + inv_count) * 10, 100)
                    })

            # Sort by risk score
            shared_iocs.sort(key=lambda x: x['risk_score'], reverse=True)

            # Calculate correlation score
            score = 0
            score += min(len(related_alerts) * 10, 30)
            score += min(len(related_investigations) * 15, 40)
            score += min(len(shared_iocs) * 5, 30)

            return {
                "related_alerts": related_alerts,
                "related_investigations": related_investigations,
                "shared_iocs": shared_iocs,
                "correlation_score": min(score, 100)
            }

    except Exception as e:
        import traceback
        logger.info(f"Error getting correlations: {e}")
        traceback.print_exc()
        return {
            "related_alerts": [],
            "related_investigations": [],
            "shared_iocs": [],
            "correlation_score": 0
        }


@app.get("/api/v1/investigations/{investigation_id}/linked-alerts")
async def get_linked_alerts(investigation_id: str):
    """
    Get all alerts linked to an investigation.
    Returns alerts that were either:
    - The original alert that created the investigation
    - Auto-correlated to this investigation based on time-window and IOC matching
    """
    try:
        from services.alert_correlation import get_linked_alerts as _get_linked_alerts

        alerts = await _get_linked_alerts(investigation_id)

        # Convert datetime objects to ISO strings
        for alert in alerts:
            for key in ['created_at', 'updated_at']:
                if key in alert and isinstance(alert[key], datetime):
                    alert[key] = alert[key].isoformat()
            if 'id' in alert:
                alert['id'] = str(alert['id'])

        return {
            "investigation_id": investigation_id,
            "linked_alert_count": len(alerts),
            "alerts": alerts
        }

    except Exception as e:
        logger.info(f"Error getting linked alerts: {e}")
        raise HTTPException(500, f"Linked alerts error: {str(e)}")


@app.post("/api/v1/investigations/{investigation_id}/link-alert")
async def link_alert_to_investigation(investigation_id: str, body: Dict = Body(...)):
    """
    Manually link an alert to an investigation.
    Body: {"alert_id": "EDR-251229-0001"}
    """
    try:
        from services.alert_correlation import link_alert_to_investigation as _link_alert

        alert_id = body.get('alert_id')
        if not alert_id:
            raise HTTPException(400, "alert_id is required")

        success = await _link_alert(
            alert_id=alert_id,
            investigation_id=investigation_id,
            match_reasons=["Manual link by analyst"]
        )

        if success:
            return {
                "status": "linked",
                "alert_id": alert_id,
                "investigation_id": investigation_id,
                "message": f"Alert {alert_id} linked to investigation {investigation_id}"
            }
        else:
            raise HTTPException(400, f"Failed to link alert {alert_id} - may already be linked or not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.info(f"Error linking alert: {e}")
        raise HTTPException(500, f"Link error: {str(e)}")


@app.get("/api/v1/investigations/{investigation_id}/timeline")
async def get_investigation_timeline(investigation_id: str):
    """
    Get chronological timeline of investigation events
    Includes alerts, IOCs, enrichment, framework matches, etc.
    """
    try:
        from services.timeline_generator import TimelineGenerator
        from services.database import db
        
        if not db.connected:
            return []
        
        timeline_generator = TimelineGenerator(db)
        timeline = await timeline_generator.generate_timeline(investigation_id)
        
        # Convert datetime objects to ISO strings
        return [
            {
                **event,
                "timestamp": event["timestamp"].isoformat() if isinstance(event["timestamp"], datetime) else event["timestamp"]
            }
            for event in timeline
        ]
        
    except Exception as e:
        logger.info(f"Error generating timeline: {e}")
        raise HTTPException(500, f"Timeline error: {str(e)}")


@app.get("/api/v1/investigations/{investigation_id}/frameworks")
async def get_framework_mappings(investigation_id: str):
    """
    Get matched cybersecurity frameworks and controls
    Returns MITRE ATT&CK, NIST CSF, CIS Controls, etc.
    """
    try:
        from services.database import db
        
        if not db.connected:
            raise HTTPException(503, "Database not connected")
        
        investigation = await db.get_investigation(investigation_id)
        if not investigation:
            raise HTTPException(404, "Investigation not found")
        
        return investigation.get("framework_matches", {})
        
    except HTTPException:
        raise
    except Exception as e:
        logger.info(f"Error getting frameworks: {e}")
        raise HTTPException(500, f"Framework error: {str(e)}")


# ================== NEW: INVESTIGATION MANAGEMENT ENDPOINTS ==================

@app.patch("/api/v1/investigations/{investigation_id}/disposition")
async def update_disposition(investigation_id: str, disposition: dict):
    """Update investigation disposition"""
    from services.postgres_db import postgres_db
    from models import DispositionType
    
    disp_value = disposition.get("disposition")
    if not disp_value:
        raise HTTPException(400, "Disposition is required")
    
    # Validate disposition value
    valid_dispositions = [d.value for d in DispositionType]
    if disp_value not in valid_dispositions:
        raise HTTPException(400, f"Invalid disposition. Must be one of: {valid_dispositions}")
    
    if postgres_db.connected:
        try:
            success = await postgres_db.update_investigation_field(
                investigation_id, 'disposition', disp_value
            )
            
            if success:
                # Log audit
                await postgres_db.log_audit(
                    username="admin",  # TODO: Get from auth
                    action="update_investigation_disposition",
                    resource_type="investigation",
                    resource_id=investigation_id,
                    details={"new_disposition": disp_value}
                )
                return {"success": True, "disposition": disp_value}
            else:
                raise HTTPException(404, "Investigation not found")
        except HTTPException:
            raise
        except Exception as e:
            logger.info(f"Error updating disposition: {e}")
            raise HTTPException(500, str(e))
    
    # Legacy fallback
    try:
        from services.database import db
        if db.connected:
            result = await db.db.investigations.update_one(
                {"investigation_id": investigation_id},
                {"$set": {"disposition": disp_value, "updated_at": datetime.utcnow()}}
            )
            if result.matched_count == 0:
                raise HTTPException(404, "Investigation not found")
            return {"success": True, "disposition": disp_value}
    except Exception as e:
        logger.info(f"Error with database: {e}")
    
    raise HTTPException(503, "Database not available")


@app.patch("/api/v1/investigations/{investigation_id}/priority")
async def update_priority(investigation_id: str, priority_data: dict):
    """Update investigation priority"""
    from services.postgres_db import postgres_db
    
    priority = priority_data.get("priority")
    if not priority:
        raise HTTPException(400, "Priority is required")
    
    # Validate priority
    if priority not in ['P1', 'P2', 'P3', 'P4']:
        raise HTTPException(400, "Priority must be P1, P2, P3, or P4")
    
    if postgres_db.connected:
        try:
            success = await postgres_db.update_investigation_field(
                investigation_id, 'priority', priority
            )
            if success:
                await postgres_db.log_audit(
                    username="admin",
                    action="update_investigation_priority",
                    resource_type="investigation",
                    resource_id=investigation_id,
                    details={"new_priority": priority}
                )
                return {"success": True, "priority": priority}
            else:
                raise HTTPException(404, "Investigation not found")
        except Exception as e:
            logger.info(f"Error: {e}")
            raise HTTPException(500, str(e))
    
    raise HTTPException(503, "Database not available")


@app.patch("/api/v1/investigations/{investigation_id}/owner")
async def update_owner(
    investigation_id: str,
    owner_data: dict,
    current_user: dict = Depends(auth_get_current_user),
):
    """Assign investigation to an analyst. Fires a user-specific notification
    to the new owner so they see the assignment in their bell — previously
    this was silent and analysts had to refresh the queue to discover work."""
    from services.postgres_db import postgres_db
    from middleware.tenant_middleware import get_optional_tenant_id

    owner = owner_data.get("owner")

    if not postgres_db.connected:
        raise HTTPException(503, "Database not available")

    try:
        # Snapshot previous owner + investigation title for the notification
        prev_owner = None
        inv_title = None
        try:
            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT owner, alert_title FROM investigations WHERE investigation_id = $1",
                    investigation_id,
                )
                if row:
                    prev_owner = row['owner']
                    inv_title = row['alert_title']
        except Exception:
            pass  # snapshot is best-effort

        success = await postgres_db.update_investigation_field(
            investigation_id, 'owner', owner
        )
        if not success:
            raise HTTPException(404, "Investigation not found")

        assigner = current_user.get('username') or current_user.get('email') or 'admin'
        await postgres_db.log_audit(
            username=assigner,
            action="assign_investigation",
            resource_type="investigation",
            resource_id=investigation_id,
            details={"new_owner": owner, "previous_owner": prev_owner}
        )

        # Notification — only fire when the owner actually changed AND we have
        # a real user to direct it at. Skip self-assignment (analyst clicking
        # "Assign to me" doesn't need to notify themselves).
        if owner and owner != prev_owner and owner != assigner:
            tenant_id = get_optional_tenant_id()
            target_user_id = None
            try:
                async with postgres_db.tenant_acquire() as conn:
                    user_row = await conn.fetchrow(
                        "SELECT id FROM users WHERE username = $1 OR email = $1",
                        owner,
                    )
                    if user_row:
                        target_user_id = str(user_row['id'])
            except Exception:
                pass

            if tenant_id:
                try:
                    from routes.notifications import create_notification
                    title_text = f"Assigned: {inv_title[:80]}" if inv_title else f"Investigation {investigation_id} assigned to you"
                    await create_notification(
                        tenant_id=str(tenant_id),
                        title=title_text,
                        message=f"{assigner} assigned this investigation to you.",
                        category="investigation",
                        severity="info",
                        link=f"/investigation/{investigation_id}",
                        user_id=target_user_id,  # user-specific delivery
                        metadata={
                            "investigation_id": investigation_id,
                            "assigner": assigner,
                            "previous_owner": prev_owner,
                        },
                    )
                except Exception as notify_err:
                    logger.warning(f"Owner-change notification failed for {investigation_id}: {notify_err}")

        return {"success": True, "owner": owner}
    except HTTPException:
        raise
    except Exception as e:
        logger.info(f"Error: {e}")
        raise HTTPException(500, str(e))


@app.patch("/api/v1/investigations/{investigation_id}/state")
async def update_state(investigation_id: str, state_data: dict):
    """Update investigation workflow state. When the new state is
    NEEDS_REVIEW, drop a tenant-wide notification so the queue isn't the
    only signal that human review is waiting."""
    from services.postgres_db import postgres_db
    from middleware.tenant_middleware import get_optional_tenant_id

    state = state_data.get("state")
    if not state:
        raise HTTPException(400, "State is required")

    valid_states = ['NEW', 'ANALYZING', 'NEEDS_REVIEW', 'IN_PROGRESS', 'CLOSED']
    if state.upper() not in valid_states:
        raise HTTPException(400, f"Invalid state. Must be one of: {valid_states}")

    if not postgres_db.connected:
        raise HTTPException(503, "Database not available")

    try:
        # Snapshot prior state + metadata for the notification body
        prev_state = None
        inv_title = None
        inv_severity = None
        inv_owner = None
        try:
            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT state, alert_title, severity, owner FROM investigations WHERE investigation_id = $1",
                    investigation_id,
                )
                if row:
                    prev_state = row['state']
                    inv_title = row['alert_title']
                    inv_severity = row['severity']
                    inv_owner = row['owner']
        except Exception:
            pass

        success = await postgres_db.update_investigation_field(
            investigation_id, 'state', state.upper()
        )
        if not success:
            raise HTTPException(404, "Investigation not found")

        await postgres_db.log_audit(
            username="admin",
            action="update_investigation_state",
            resource_type="investigation",
            resource_id=investigation_id,
            details={"new_state": state, "previous_state": prev_state}
        )

        # Fire NEEDS_REVIEW notification — only on transitions INTO that state
        # (so we don't repeatedly notify on edits while it's already there).
        if state.upper() == 'NEEDS_REVIEW' and prev_state != 'NEEDS_REVIEW':
            tenant_id = get_optional_tenant_id()
            if tenant_id:
                try:
                    from routes.notifications import create_notification
                    title_text = f"Ready for review: {inv_title[:80]}" if inv_title else f"Investigation {investigation_id} needs review"
                    await create_notification(
                        tenant_id=str(tenant_id),
                        title=title_text,
                        message=("Auto-triage flagged this for analyst review."
                                 + (f" Currently assigned to {inv_owner}." if inv_owner else " Unassigned.")),
                        category="investigation",
                        severity=(inv_severity or "medium").lower(),
                        link=f"/investigation/{investigation_id}",
                        metadata={
                            "investigation_id": investigation_id,
                            "state": "NEEDS_REVIEW",
                            "severity": inv_severity,
                        },
                    )
                except Exception as notify_err:
                    logger.warning(f"NEEDS_REVIEW notification failed for {investigation_id}: {notify_err}")

        return {"success": True, "state": state}
    except HTTPException:
        raise
    except Exception as e:
        logger.info(f"Error: {e}")
        raise HTTPException(500, str(e))


@app.post("/api/v1/investigations/{investigation_id}/notes")
async def add_note(investigation_id: str, note_data: dict):
    """Add a note to an investigation"""
    try:
        from services.postgres_db import postgres_db
        
        if not postgres_db.connected:
            raise HTTPException(503, "Database not connected")
        
        # Add note to PostgreSQL
        note_id = await postgres_db.add_investigation_note(
            investigation_id=investigation_id,
            content=note_data.get("content", ""),
            author=note_data.get("author", "unknown"),
            note_type=note_data.get("note_type", "HUMAN_NOTE"),
            author_type=note_data.get("author_type", "HUMAN")
        )
        
        if not note_id:
            raise HTTPException(500, "Failed to add note")
        
        return {
            "success": True,
            "note": {
                "note_id": note_id,
                "content": note_data.get("content", ""),
                "author": note_data.get("author", "unknown"),
                "author_type": note_data.get("author_type", "HUMAN"),
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.info(f"Error adding note: {e}")
        raise HTTPException(500, str(e))


@app.get("/api/v1/investigations/{investigation_id}/notes")
async def get_notes(investigation_id: str):
    """Get all notes for an investigation"""
    try:
        from services.postgres_db import postgres_db
        
        if not postgres_db.connected:
            raise HTTPException(503, "Database not connected")
        
        notes = await postgres_db.get_investigation_notes(investigation_id)
        return notes
        
    except HTTPException:
        raise
    except Exception as e:
        logger.info(f"Error getting notes: {e}")
        raise HTTPException(500, str(e))


@app.get("/api/v1/alerts/{alert_id}")
async def get_alert(alert_id: str):
    """Get alert by ID (accepts both UUID 'id' and formatted 'alert_id')"""
    from services.postgres_db import postgres_db

    # Try PostgreSQL first (primary database)
    if postgres_db.connected:
        try:
            async with postgres_db.tenant_acquire() as conn:
                # Try both alert_id and id (UUID) columns
                row = await conn.fetchrow(
                    'SELECT * FROM alerts WHERE alert_id = $1 OR id::text = $1',
                    alert_id
                )
                if row:
                    alert_data = dict(row)
                    # Parse JSON fields
                    if alert_data.get('raw_event') and isinstance(alert_data['raw_event'], str):
                        import json
                        try:
                            alert_data['raw_event'] = json.loads(alert_data['raw_event'])
                        except:
                            pass
                    return alert_data
        except Exception as e:
            logger.info(f"Warning: PostgreSQL query failed: {e}")

    # Try database fallback
    try:
        from services.database import db
        if db.client:
            alert_doc = await db.get_alert(alert_id)
            if alert_doc:
                return alert_doc
    except Exception as e:
        logger.info(f"Warning: database query failed: {e}")

    # Fall back to in-memory store
    if alert_id in alerts_store:
        return alerts_store[alert_id]

    raise HTTPException(
        status_code=404,
        detail=f"Alert {alert_id} not found"
    )


@app.get("/api/v1/stats")
async def get_statistics(time_range: str = "7d"):
    """
    Get system statistics from PostgreSQL with time range filtering

    time_range options: 24h, 7d, 30d, 90d
    """
    from services.postgres_db import postgres_db

    # Parse time range to interval
    interval_map = {
        "24h": "1 day",
        "7d": "7 days",
        "30d": "30 days",
        "90d": "90 days"
    }
    interval = interval_map.get(time_range, "7 days")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get alert counts within time range
            total_alerts = await conn.fetchval(
                f"SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '{interval}'"
            )
            open_alerts = await conn.fetchval(
                f"SELECT COUNT(*) FROM alerts WHERE status = 'open' AND created_at >= NOW() - INTERVAL '{interval}'"
            )
            investigating_alerts = await conn.fetchval(
                f"SELECT COUNT(*) FROM alerts WHERE status = 'investigating' AND created_at >= NOW() - INTERVAL '{interval}'"
            )

            # Get investigations count within time range
            total_investigations = await conn.fetchval(
                f"SELECT COUNT(*) FROM investigations WHERE created_at >= NOW() - INTERVAL '{interval}'"
            )
            open_investigations = await conn.fetchval(
                f"SELECT COUNT(*) FROM investigations WHERE state IN ('open', 'investigating') AND created_at >= NOW() - INTERVAL '{interval}'"
            )

            # Get severity distribution within time range
            severity_rows = await conn.fetch(f"""
                SELECT severity, COUNT(*) as count
                FROM alerts
                WHERE created_at >= NOW() - INTERVAL '{interval}'
                GROUP BY severity
            """)
            severity_distribution = {row['severity']: row['count'] for row in severity_rows}

            # Get status distribution within time range
            status_rows = await conn.fetch(f"""
                SELECT status, COUNT(*) as count
                FROM alerts
                WHERE created_at >= NOW() - INTERVAL '{interval}'
                GROUP BY status
            """)
            status_distribution = {row['status']: row['count'] for row in status_rows}

            # Get source distribution within time range
            source_rows = await conn.fetch(f"""
                SELECT source, COUNT(*) as count
                FROM alerts
                WHERE created_at >= NOW() - INTERVAL '{interval}'
                GROUP BY source
                ORDER BY count DESC
                LIMIT 10
            """)
            source_distribution = {row['source']: row['count'] for row in source_rows}

            # Get alert trend for the time range
            # Group by appropriate time bucket based on range
            if time_range == "24h":
                trend_query = f"""
                    SELECT DATE_TRUNC('hour', created_at) as date, COUNT(*) as count
                    FROM alerts
                    WHERE created_at >= NOW() - INTERVAL '{interval}'
                    GROUP BY DATE_TRUNC('hour', created_at)
                    ORDER BY date
                """
            else:
                trend_query = f"""
                    SELECT DATE(created_at) as date, COUNT(*) as count
                    FROM alerts
                    WHERE created_at >= NOW() - INTERVAL '{interval}'
                    GROUP BY DATE(created_at)
                    ORDER BY date
                """
            trend_rows = await conn.fetch(trend_query)
            alert_trend = [{'date': str(row['date']), 'count': row['count']} for row in trend_rows]

            # Get recent HIGH/CRITICAL alerts within time range. The dashboard
            # surfaces this as "Recent Critical Events" / "Executive Watchlist",
            # so we filter to the severities the label promises rather than
            # whatever happened to be most recent.
            #
            # LEFT JOIN to investigations so the dashboard can show the
            # workflow state and assignee — "where is each event right now" —
            # without an N+1 fetch per row. Investigation fields are nullable
            # because not every alert has been promoted.
            # `effective_state` collapses the "alert status vs investigation
            # state" disconnect the same way /api/v1/alerts does at runtime —
            # any terminal disposition or close on either side counts as
            # CLOSED. Without it the dashboard happily shows "NEEDS REVIEW"
            # for tickets the analyst already closed at the alert level.
            #
            # `riggs_confidence` pulls Riggs' deep-dive confidence out of the
            # investigation_data JSONB (`riggs_analysis.confidence`). That's
            # the value the drawer renders as "RIGGS ANALYSIS 90%". The
            # alert.ai_confidence column only carries the first-pass triage
            # number (e.g. 45%) so it's a misleading default.
            recent_alerts_rows = await conn.fetch(f"""
                SELECT
                    a.alert_id,
                    a.title,
                    a.severity,
                    a.status,
                    a.source,
                    a.ai_confidence,
                    a.created_at,
                    a.investigation_id,
                    i.state         AS investigation_state,
                    i.owner         AS investigation_owner,
                    i.disposition   AS investigation_disposition,
                    i.confidence    AS investigation_confidence,
                    CASE
                        WHEN i.state IN ('CLOSED', 'RESOLVED')
                            THEN i.state
                        WHEN i.disposition IN ('FALSE_POSITIVE', 'TRUE_POSITIVE', 'MALICIOUS', 'BENIGN')
                            THEN 'CLOSED'
                        WHEN a.status IN ('closed', 'resolved', 'false_positive', 'confirmed')
                            THEN UPPER(a.status)
                        ELSE COALESCE(i.state, UPPER(a.status))
                    END AS effective_state,
                    (i.investigation_data #>> '{{riggs_analysis,confidence}}')::float AS riggs_confidence
                FROM alerts a
                LEFT JOIN investigations i ON i.id = a.investigation_id
                WHERE a.created_at >= NOW() - INTERVAL '{interval}'
                  AND a.severity IN ('high', 'critical')
                ORDER BY
                  CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,
                  a.created_at DESC
                LIMIT 10
            """)
            recent_alerts = [
                {
                    'alert_id': row['alert_id'],
                    'title': row['title'],
                    'severity': row['severity'],
                    'status': row['status'],
                    'source': row['source'],
                    'investigation_id': str(row['investigation_id']) if row['investigation_id'] else None,
                    'investigation_state': row['investigation_state'],
                    'investigation_owner': row['investigation_owner'],
                    'investigation_disposition': row['investigation_disposition'],
                    'effective_state': row['effective_state'],
                    # Confidence resolution order:
                    #   1. Riggs deep-dive (investigation_data.riggs_analysis.confidence)
                    #   2. Investigation overall confidence column
                    #   3. Alert first-pass ai_confidence
                    'ai_confidence': (
                        float(row['riggs_confidence']) if row['riggs_confidence'] is not None
                        else float(row['investigation_confidence']) if row['investigation_confidence'] is not None
                        else float(row['ai_confidence']) if row['ai_confidence'] is not None
                        else None
                    ),
                    'created_at': row['created_at'].isoformat()
                }
                for row in recent_alerts_rows
            ]

            # ============================================
            # MTTR (Mean Time To Resolve) calculation
            # ============================================
            # MTTR averages how long it took to close terminal alerts
            # *closed* within the time window. We exclude batch-close
            # events (any closed_at timestamp shared by more than 5
            # alerts within ~1ms) because those are admin cleanup
            # operations, not real triage decisions — keeping them in
            # would inflate MTTR by days when an analyst cleans up
            # stale alerts en masse. We surface both mean and median so
            # the dashboard can show whichever is least misleading.
            mttr_result = await conn.fetchrow(f"""
                WITH non_batch AS (
                    SELECT a.created_at, COALESCE(a.closed_at, a.resolved_at) AS closed_at
                    FROM alerts a
                    JOIN (
                        SELECT COALESCE(closed_at, resolved_at) AS closed_at
                        FROM alerts
                        WHERE status IN ('resolved', 'closed', 'false_positive', 'confirmed')
                          AND COALESCE(closed_at, resolved_at) IS NOT NULL
                        GROUP BY COALESCE(closed_at, resolved_at)
                        HAVING COUNT(*) <= 5
                    ) g ON g.closed_at = COALESCE(a.closed_at, a.resolved_at)
                    WHERE a.status IN ('resolved', 'closed', 'false_positive', 'confirmed')
                      AND COALESCE(a.closed_at, a.resolved_at) IS NOT NULL
                      AND COALESCE(a.closed_at, a.resolved_at) >= NOW() - INTERVAL '{interval}'
                )
                SELECT
                    AVG(EXTRACT(EPOCH FROM (closed_at - created_at)))                          AS avg_seconds,
                    percentile_cont(0.5) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM (closed_at - created_at))) AS median_seconds,
                    COUNT(*)                                                                   AS resolved_count
                FROM non_batch
            """)
            # Display the MEDIAN as the headline MTTR, not the mean.
            # In a healthy SOC the bulk of alerts auto-close in seconds
            # while a handful sit in NEEDS_REVIEW for hours/days — the
            # mean gets distorted by those tail cases and stops being
            # a useful signal. Median tracks "the typical alert" which
            # is what analysts actually want to monitor over time.
            mttr_seconds = mttr_result['median_seconds'] if mttr_result and mttr_result['median_seconds'] else 0
            mttr_avg_seconds = mttr_result['avg_seconds'] if mttr_result and mttr_result['avg_seconds'] else 0
            mttr_minutes = round(mttr_seconds / 60, 1) if mttr_seconds else 0
            resolved_count = mttr_result['resolved_count'] if mttr_result else 0

            # ============================================
            # Processing Time Metrics (T1, T2, Queue)
            # ============================================
            # T1 Processing Time - alerts auto-closed without investigation
            t1_time_result = await conn.fetchrow(f"""
                SELECT
                    AVG(EXTRACT(EPOCH FROM (COALESCE(closed_at, resolved_at) - created_at))) as avg_seconds,
                    COUNT(*) as count
                FROM alerts
                WHERE status IN ('resolved', 'closed', 'false_positive', 'confirmed')
                AND COALESCE(closed_at, resolved_at) IS NOT NULL
                AND investigation_id IS NULL
                AND COALESCE(closed_at, resolved_at) >= NOW() - INTERVAL '{interval}'
            """)
            t1_avg_seconds = t1_time_result['avg_seconds'] if t1_time_result and t1_time_result['avg_seconds'] else 0
            t1_count = t1_time_result['count'] if t1_time_result else 0

            # T2 Processing Time - alerts that went through investigation
            t2_time_result = await conn.fetchrow(f"""
                SELECT
                    AVG(EXTRACT(EPOCH FROM (COALESCE(a.closed_at, a.resolved_at) - a.created_at))) as avg_seconds,
                    COUNT(*) as count
                FROM alerts a
                WHERE a.status IN ('resolved', 'closed', 'false_positive', 'confirmed')
                AND COALESCE(a.closed_at, a.resolved_at) IS NOT NULL
                AND a.investigation_id IS NOT NULL
                AND COALESCE(a.closed_at, a.resolved_at) >= NOW() - INTERVAL '{interval}'
            """)
            t2_avg_seconds = t2_time_result['avg_seconds'] if t2_time_result and t2_time_result['avg_seconds'] else 0
            t2_count = t2_time_result['count'] if t2_time_result else 0

            # Queue Wait Time - time from alert creation to first agent execution
            # This shows how long alerts wait before processing starts
            queue_time_result = await conn.fetchrow(f"""
                SELECT AVG(wait_seconds) as avg_wait
                FROM (
                    SELECT
                        EXTRACT(EPOCH FROM (MIN(ae.started_at) - a.created_at)) as wait_seconds
                    FROM alerts a
                    JOIN agent_executions ae ON ae.trigger_source_id = a.id::text
                    WHERE a.created_at >= NOW() - INTERVAL '{interval}'
                    AND ae.started_at IS NOT NULL
                    GROUP BY a.id
                ) sub
                WHERE wait_seconds >= 0
            """)
            queue_avg_seconds = queue_time_result['avg_wait'] if queue_time_result and queue_time_result['avg_wait'] else 0

            # Actual LLM processing time (from agent_executions duration)
            llm_time_result = await conn.fetchrow(f"""
                SELECT
                    AVG(CASE WHEN ad.tier = 1 THEN EXTRACT(EPOCH FROM (ae.completed_at - ae.started_at)) END) as t1_llm_avg,
                    AVG(CASE WHEN ad.tier = 2 THEN EXTRACT(EPOCH FROM (ae.completed_at - ae.started_at)) END) as t2_llm_avg,
                    COUNT(CASE WHEN ad.tier = 1 THEN 1 END) as t1_llm_count,
                    COUNT(CASE WHEN ad.tier = 2 THEN 1 END) as t2_llm_count
                FROM agent_executions ae
                JOIN agent_definitions ad ON ae.agent_id = ad.id
                WHERE ae.started_at >= NOW() - INTERVAL '{interval}'
                AND ae.completed_at IS NOT NULL
            """)
            t1_llm_seconds = llm_time_result['t1_llm_avg'] if llm_time_result and llm_time_result['t1_llm_avg'] else 0
            t2_llm_seconds = llm_time_result['t2_llm_avg'] if llm_time_result and llm_time_result['t2_llm_avg'] else 0

            processing_times = {
                "t1_total": {
                    "seconds": round(t1_avg_seconds, 1) if t1_avg_seconds else 0,
                    "label": f"{round(t1_avg_seconds, 1)}s" if t1_avg_seconds else "N/A",
                    "count": t1_count
                },
                "t2_total": {
                    "seconds": round(t2_avg_seconds, 1) if t2_avg_seconds else 0,
                    "label": f"{round(t2_avg_seconds/60, 1)}m" if t2_avg_seconds and t2_avg_seconds >= 60 else f"{round(t2_avg_seconds, 1)}s" if t2_avg_seconds else "N/A",
                    "count": t2_count
                },
                "queue_wait": {
                    "seconds": round(queue_avg_seconds, 1) if queue_avg_seconds else 0,
                    "label": f"{round(queue_avg_seconds, 1)}s" if queue_avg_seconds else "N/A"
                },
                "t1_llm": {
                    "seconds": round(t1_llm_seconds, 2) if t1_llm_seconds else 0,
                    "label": f"{round(t1_llm_seconds, 2)}s" if t1_llm_seconds else "N/A"
                },
                "t2_llm": {
                    "seconds": round(t2_llm_seconds, 2) if t2_llm_seconds else 0,
                    "label": f"{round(t2_llm_seconds, 2)}s" if t2_llm_seconds else "N/A"
                }
            }

            # ============================================
            # Investigation status distribution
            # ============================================
            inv_status_rows = await conn.fetch(f"""
                SELECT state, COUNT(*) as count
                FROM investigations
                WHERE created_at >= NOW() - INTERVAL '{interval}'
                GROUP BY state
                ORDER BY count DESC
            """)
            investigation_status_distribution = {row['state']: row['count'] for row in inv_status_rows}

            # ============================================
            # AI Impact Metrics (from agent executions)
            # ============================================
            ai_metrics = await conn.fetchrow(f"""
                SELECT
                    COUNT(*) as total_executions,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful,
                    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed,
                    AVG(EXTRACT(EPOCH FROM (completed_at - started_at))) as avg_duration_seconds
                FROM agent_executions
                WHERE started_at >= NOW() - INTERVAL '{interval}'
            """)

            # Count AI auto-closed alerts.
            # Historically only `Agent:<id>` was used (agent_executor path); the
            # Riggs review path (job_queue.py:_process_riggs_review_queue) now
            # also stamps `Riggs:auto` on close. Broaden the match so the
            # counter reflects every automated close. Closed_at may be null
            # for legacy rows so we also fall back to updated_at via closed_at
            # backfill in migration 076.
            ai_auto_closed = await conn.fetchval(f"""
                SELECT COUNT(*) FROM alerts
                WHERE (closed_by LIKE 'Agent:%' OR closed_by LIKE 'Riggs%')
                AND closed_at >= NOW() - INTERVAL '{interval}'
            """) or 0

            # Calculate hours saved (assume 15 min per alert for manual processing)
            hours_saved = round((ai_auto_closed * 15) / 60, 1)

            # AI accuracy (based on ai_confidence average)
            ai_accuracy_result = await conn.fetchval(f"""
                SELECT AVG(ai_confidence::numeric) * 100
                FROM alerts
                WHERE ai_confidence IS NOT NULL
                AND created_at >= NOW() - INTERVAL '{interval}'
            """)
            ai_accuracy = round(float(ai_accuracy_result), 1) if ai_accuracy_result else 0

            ai_impact = {
                "alerts_auto_closed": ai_auto_closed,
                "hours_saved": hours_saved,
                "accuracy_percent": ai_accuracy,
                "cost_savings": round(hours_saved * 150, 2),  # $150/hr analyst rate
                "total_executions": ai_metrics['total_executions'] if ai_metrics else 0,
                "successful_executions": ai_metrics['successful'] if ai_metrics else 0,
                "avg_execution_time_seconds": round(ai_metrics['avg_duration_seconds'] or 0, 2) if ai_metrics else 0
            }

            # ============================================
            # Automation Stats (daily breakdown)
            # ============================================
            automation_rows = await conn.fetch(f"""
                SELECT
                    DATE(COALESCE(closed_at, resolved_at)) as day,
                    COUNT(CASE WHEN closed_by LIKE 'Agent:%' OR closed_by LIKE 'Riggs%' THEN 1 END) as automated,
                    COUNT(CASE WHEN closed_by IS NULL
                            OR (closed_by NOT LIKE 'Agent:%' AND closed_by NOT LIKE 'Riggs%')
                          THEN 1 END) as manual
                FROM alerts
                WHERE COALESCE(closed_at, resolved_at) >= NOW() - INTERVAL '{interval}'
                AND status IN ('resolved', 'closed', 'false_positive', 'confirmed')
                AND COALESCE(closed_at, resolved_at) IS NOT NULL
                GROUP BY DATE(COALESCE(closed_at, resolved_at))
                ORDER BY day
            """)
            automation_trend = [
                {
                    'day': row['day'].strftime('%a') if row['day'] else 'N/A',
                    'date': str(row['day']),
                    'automated': row['automated'],
                    'manual': row['manual']
                }
                for row in automation_rows
            ]

            # ============================================
            # IOC & Threat Feed Stats
            # ============================================
            ioc_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_iocs,
                    COUNT(CASE WHEN reputation = 'malicious' THEN 1 END) as malicious,
                    COUNT(CASE WHEN reputation = 'suspicious' THEN 1 END) as suspicious,
                    COUNT(CASE WHEN source_type = 'threat_feed' THEN 1 END) as from_feeds
                FROM iocs
            """)

            feed_stats = await conn.fetchrow("""
                SELECT
                    COUNT(*) as total_feeds,
                    COUNT(CASE WHEN enabled = true THEN 1 END) as enabled_feeds
                FROM threat_feeds
            """)

            threat_intel_stats = {
                "total_iocs": ioc_stats['total_iocs'] if ioc_stats else 0,
                "malicious_iocs": ioc_stats['malicious'] if ioc_stats else 0,
                "suspicious_iocs": ioc_stats['suspicious'] if ioc_stats else 0,
                "iocs_from_feeds": ioc_stats['from_feeds'] if ioc_stats else 0,
                "total_feeds": feed_stats['total_feeds'] if feed_stats else 0,
                "enabled_feeds": feed_stats['enabled_feeds'] if feed_stats else 0
            }

            # ============================================
            # Enrichment Stats
            # ============================================
            enrichment_stats = await conn.fetchrow(f"""
                SELECT
                    COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending,
                    COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed,
                    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed
                FROM enrichment_priority_queue
                WHERE created_at >= NOW() - INTERVAL '{interval}'
            """)

            enrichment = {
                "pending": enrichment_stats['pending'] if enrichment_stats else 0,
                "completed": enrichment_stats['completed'] if enrichment_stats else 0,
                "failed": enrichment_stats['failed'] if enrichment_stats else 0
            }

            # ============================================
            # SLA: Response (ack) + Resolution (close) by severity
            # ============================================
            # Targets (minutes) by severity. Hardcoded for now — settings UI
            # to configure these is a follow-up.
            sla_targets = {
                "critical": {"ack": 15,   "close": 240},      # 15m / 4h
                "high":     {"ack": 60,   "close": 1440},     # 1h  / 24h
                "medium":   {"ack": 240,  "close": 4320},     # 4h  / 3d
                "low":      {"ack": 1440, "close": 10080},    # 24h / 7d
            }

            # Pull all closed investigations in window with ack/close durations.
            sla_rows = await conn.fetch(f"""
                SELECT
                    COALESCE(severity, 'medium') AS severity,
                    EXTRACT(EPOCH FROM (acknowledged_at - created_at)) / 60.0 AS ack_minutes,
                    EXTRACT(EPOCH FROM (completed_at    - created_at)) / 60.0 AS close_minutes
                FROM investigations
                WHERE created_at >= NOW() - INTERVAL '{interval}'
                  AND state IN ('CLOSED', 'RESOLVED')
            """)

            # Per-severity tallies for closed items (the SLA universe).
            severity_keys = ['critical', 'high', 'medium', 'low']
            sla_by_severity = {
                s: {"closed": 0, "ack_met": 0, "close_met": 0,
                    "ack_target": sla_targets[s]["ack"],
                    "close_target": sla_targets[s]["close"]}
                for s in severity_keys
            }
            ack_total, ack_met_total = 0, 0
            close_total, close_met_total = 0, 0
            for row in sla_rows:
                sev = (row['severity'] or 'medium').lower()
                if sev not in sla_by_severity:
                    sev = 'medium'
                bucket = sla_by_severity[sev]
                bucket["closed"] += 1

                # Acknowledgment SLA — only meaningful if we have an ack timestamp.
                ack_min = row['ack_minutes']
                if ack_min is not None:
                    ack_total += 1
                    if float(ack_min) <= bucket["ack_target"]:
                        bucket["ack_met"] += 1
                        ack_met_total += 1

                # Close SLA — guaranteed since we filtered on state IN (CLOSED, RESOLVED).
                close_min = row['close_minutes']
                if close_min is not None:
                    close_total += 1
                    if float(close_min) <= bucket["close_target"]:
                        bucket["close_met"] += 1
                        close_met_total += 1

            # Currently-open investigations whose ack target has already elapsed.
            # These don't count in the compliance %, but the breach count is
            # actionable for the analyst on call.
            open_ack_breach_rows = await conn.fetch("""
                SELECT
                    COALESCE(severity, 'medium') AS severity,
                    EXTRACT(EPOCH FROM (NOW() - created_at)) / 60.0 AS age_minutes
                FROM investigations
                WHERE state = 'NEW'
                  AND acknowledged_at IS NULL
            """)
            open_ack_breaches = 0
            for row in open_ack_breach_rows:
                sev = (row['severity'] or 'medium').lower()
                target = sla_targets.get(sev, sla_targets['medium'])["ack"]
                if float(row['age_minutes'] or 0) > target:
                    open_ack_breaches += 1

            def _pct(met, total):
                return round((met / total) * 100, 1) if total else None

            sla_summary = {
                "ack_compliance_pct":   _pct(ack_met_total, ack_total),
                "ack_breaches":         (ack_total - ack_met_total) + open_ack_breaches,
                "close_compliance_pct": _pct(close_met_total, close_total),
                "close_breaches":       close_total - close_met_total,
                "evaluated_count":      ack_total,            # closed items with ack data
                "resolved_count":       close_total,
                "by_severity": [
                    {
                        "severity":            s,
                        "closed":              sla_by_severity[s]["closed"],
                        "ack_met":             sla_by_severity[s]["ack_met"],
                        "ack_target_minutes":  sla_by_severity[s]["ack_target"],
                        "ack_compliance_pct":  _pct(sla_by_severity[s]["ack_met"],
                                                    sla_by_severity[s]["closed"]),
                        "close_met":           sla_by_severity[s]["close_met"],
                        "close_target_minutes": sla_by_severity[s]["close_target"],
                        "close_compliance_pct": _pct(sla_by_severity[s]["close_met"],
                                                     sla_by_severity[s]["closed"]),
                    }
                    for s in severity_keys
                ],
            }

            return {
                "total_alerts": total_alerts,
                "open_alerts": open_alerts,
                "investigating_alerts": investigating_alerts,
                "total_investigations": total_investigations,
                "open_investigations": open_investigations,
                "severity_distribution": severity_distribution,
                "status_distribution": status_distribution,
                "source_distribution": source_distribution,
                "investigation_status_distribution": investigation_status_distribution,
                "alert_trend": alert_trend,
                "recent_alerts": recent_alerts,
                "mttr": {
                    "minutes": mttr_minutes,
                    "seconds": round(mttr_seconds, 1) if mttr_seconds else 0,
                    "milliseconds": round(mttr_seconds * 1000) if mttr_seconds else 0,
                    "resolved_count": resolved_count,
                    "label": (
                        f"{round(mttr_seconds * 1000)}ms" if mttr_seconds < 1 else
                        f"{round(mttr_seconds, 1)}s" if mttr_minutes < 1 else
                        f"{mttr_minutes}m {int(mttr_seconds % 60)}s" if mttr_minutes < 60 else
                        f"{round(mttr_minutes/60, 1)}h"
                    ) if mttr_seconds else "0ms"
                },
                "processing_times": processing_times,
                "ai_impact": ai_impact,
                "automation_trend": automation_trend,
                "threat_intel": threat_intel_stats,
                "enrichment": enrichment,
                "sla": sla_summary,
                "time_range": time_range,
                "timestamp": datetime.utcnow().isoformat()
            }

    except Exception as e:
        logger.info(f"Error fetching stats: {e}")
        # Return empty stats if database error
        return {
            "total_alerts": 0,
            "open_alerts": 0,
            "investigating_alerts": 0,
            "total_investigations": 0,
            "open_investigations": 0,
            "severity_distribution": {},
            "status_distribution": {},
            "source_distribution": {},
            "alert_trend": [],
            "recent_alerts": [],
            "time_range": time_range,
            "error": str(e)
        }


@app.get("/api/v1/search")
async def global_search(q: str, limit: int = 50):
    """
    COMPREHENSIVE GLOBAL SEARCH - Searches EVERYTHING in the platform
    
    Searches across:
    - Alerts (title, description, alert_id, source, severity, status, raw_event)
    - Investigations (alert_title, investigation_id, owner, disposition, state)
    - IOCs (IPs, domains, hashes, emails, URLs, usernames in raw_event)
    - Users (username, email, full_name)
    - Audit logs (actions, usernames, resources)
    
    Args:
        q: Search query (minimum 2 characters)
        limit: Maximum results per category (default 50)
    
    Returns:
        {
            "query": "malware",
            "alerts": [...],
            "investigations": [...],
            "iocs": {
                "ips": [...],
                "domains": [...],
                "hashes": [...],
                "emails": [...],
                "urls": [...],
                "usernames": [...]
            },
            "users": [...],
            "audit_logs": [...],
            "counts": {
                "alerts": 15,
                "investigations": 3,
                "iocs": 8,
                "users": 1,
                "audit_logs": 42,
                "total": 69
            }
        }
    """
    from services.postgres_db import postgres_db
    import re
    
    if not q or len(q.strip()) < 2:
        return {
            "query": q,
            "alerts": [],
            "investigations": [],
            "iocs": {},
            "users": [],
            "audit_logs": [],
            "counts": {"alerts": 0, "investigations": 0, "iocs": 0, "users": 0, "audit_logs": 0, "total": 0},
            "message": "Query too short (minimum 2 characters)"
        }
    
    query = f"%{q.lower()}%"
    
    logger.info(f"[GLOBAL_SEARCH] Query: '{q}', Pattern: '{query}'")
    
    try:
        async with postgres_db.tenant_acquire() as conn:
            # ===================================================================
            # 1. SEARCH ALERTS
            # ===================================================================
            # Uses the existing `alerts.search_vector` GIN index (init-db.sql:151)
            # for full-text match on title/description, then OR's exact-ish
            # LIKE checks for ID-style fields (alert_id, source, category) that
            # the tsvector trigger does not cover. Falling back to LIKE for the
            # short-query case keeps things responsive on 1-2 character input.
            logger.info(f"[SEARCH] Searching alerts...")
            alert_rows = await conn.fetch("""
                SELECT alert_id, title, description, severity, status, source, created_at,
                       category, subcategory, confidence
                FROM alerts
                WHERE
                    ( length($3) >= 3 AND search_vector @@ plainto_tsquery('english', $3) )
                    OR LOWER(alert_id) LIKE $1
                    OR LOWER(COALESCE(source, '')) LIKE $1
                    OR LOWER(severity) = LOWER($3)
                    OR LOWER(status) = LOWER($3)
                    OR LOWER(COALESCE(category, '')) LIKE $1
                    OR LOWER(COALESCE(subcategory, '')) LIKE $1
                ORDER BY created_at DESC
                LIMIT $2
            """, query, limit, q)
            
            alerts = [
                {
                    'alert_id': row['alert_id'],
                    'title': row['title'],
                    'description': row['description'],
                    'severity': row['severity'],
                    'status': row['status'],
                    'source': row['source'],
                    'category': row['category'],
                    'subcategory': row['subcategory'],
                    'confidence': float(row['confidence']) if row['confidence'] else None,
                    'created_at': row['created_at'].isoformat(),
                    'match_type': 'alert'
                }
                for row in alert_rows
            ]
            logger.info(f"[SEARCH] Found {len(alerts)} alerts")
            
            # ===================================================================
            # 2. SEARCH INVESTIGATIONS
            # ===================================================================
            logger.info(f"[SEARCH] Searching investigations...")
            inv_rows = await conn.fetch("""
                SELECT investigation_id, alert_title, state, disposition, owner, created_at,
                       priority, severity, executive_summary
                FROM investigations
                WHERE 
                    LOWER(COALESCE(alert_title, '')) LIKE $1 OR
                    LOWER(investigation_id) LIKE $1 OR
                    LOWER(COALESCE(owner, '')) LIKE $1 OR
                    LOWER(state) LIKE $1 OR
                    LOWER(COALESCE(disposition, '')) LIKE $1 OR
                    LOWER(COALESCE(priority, '')) LIKE $1 OR
                    LOWER(COALESCE(executive_summary, '')) LIKE $1
                ORDER BY created_at DESC
                LIMIT $2
            """, query, limit)
            
            investigations = [
                {
                    'investigation_id': row['investigation_id'],
                    'title': row['alert_title'],
                    'state': row['state'],
                    'disposition': row['disposition'],
                    'owner': row['owner'],
                    'priority': row['priority'],
                    'severity': row['severity'],
                    'executive_summary': row['executive_summary'][:200] + '...' if row['executive_summary'] and len(row['executive_summary']) > 200 else row['executive_summary'],
                    'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                    'match_type': 'investigation'
                }
                for row in inv_rows
            ]
            logger.info(f"[SEARCH] Found {len(investigations)} investigations")
            
            # ===================================================================
            # 3. SEARCH IOCs (Pattern Detection + Deep Search)
            # ===================================================================
            logger.info(f"[SEARCH] Searching IOCs...")
            ioc_results = {
                'ips': [],
                'domains': [],
                'hashes': [],
                'emails': [],
                'urls': [],
                'usernames': []
            }
            
            # IP Address Pattern
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            if ip_pattern.match(q) or '.' in q:
                ip_rows = await conn.fetch("""
                    SELECT DISTINCT alert_id, title, severity, created_at
                    FROM alerts
                    WHERE raw_event::text LIKE $1
                    ORDER BY created_at DESC
                    LIMIT 10
                """, f'%{q}%')
                
                ioc_results['ips'] = [
                    {
                        'value': q,
                        'type': 'ip',
                        'alert_id': row['alert_id'],
                        'alert_title': row['title'],
                        'severity': row['severity'],
                        'created_at': row['created_at'].isoformat()
                    }
                    for row in ip_rows
                ]
            
            # Domain Pattern
            domain_pattern = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)
            if domain_pattern.match(q):
                domain_rows = await conn.fetch("""
                    SELECT DISTINCT alert_id, title, severity, created_at
                    FROM alerts
                    WHERE raw_event::text LIKE $1
                    ORDER BY created_at DESC
                    LIMIT 10
                """, f'%{q}%')
                
                ioc_results['domains'] = [
                    {
                        'value': q,
                        'type': 'domain',
                        'alert_id': row['alert_id'],
                        'alert_title': row['title'],
                        'severity': row['severity'],
                        'created_at': row['created_at'].isoformat()
                    }
                    for row in domain_rows
                ]
            
            # Hash Pattern (MD5: 32, SHA1: 40, SHA256: 64 chars)
            hash_pattern = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
            if hash_pattern.match(q):
                hash_rows = await conn.fetch("""
                    SELECT DISTINCT alert_id, title, severity, created_at
                    FROM alerts
                    WHERE raw_event::text LIKE $1
                    ORDER BY created_at DESC
                    LIMIT 10
                """, f'%{q}%')
                
                hash_type = 'MD5' if len(q) == 32 else 'SHA1' if len(q) == 40 else 'SHA256' if len(q) == 64 else 'Hash'
                
                ioc_results['hashes'] = [
                    {
                        'value': q,
                        'type': hash_type.lower(),
                        'alert_id': row['alert_id'],
                        'alert_title': row['title'],
                        'severity': row['severity'],
                        'created_at': row['created_at'].isoformat()
                    }
                    for row in hash_rows
                ]
            
            # Email Pattern
            email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
            if email_pattern.match(q):
                email_rows = await conn.fetch("""
                    SELECT DISTINCT alert_id, title, severity, created_at
                    FROM alerts
                    WHERE raw_event::text LIKE $1
                    ORDER BY created_at DESC
                    LIMIT 10
                """, f'%{q}%')
                
                ioc_results['emails'] = [
                    {
                        'value': q,
                        'type': 'email',
                        'alert_id': row['alert_id'],
                        'alert_title': row['title'],
                        'severity': row['severity'],
                        'created_at': row['created_at'].isoformat()
                    }
                    for row in email_rows
                ]
            
            # Username search (in raw_event user fields)
            username_rows = await conn.fetch("""
                SELECT DISTINCT alert_id, title, severity, created_at
                FROM alerts
                WHERE raw_event::text LIKE $1
                  AND (raw_event::text LIKE '%"username"%' OR 
                       raw_event::text LIKE '%"user"%' OR
                       raw_event::text LIKE '%"account"%')
                ORDER BY created_at DESC
                LIMIT 10
            """, f'%{q}%')
            
            ioc_results['usernames'] = [
                {
                    'value': q,
                    'type': 'username',
                    'alert_id': row['alert_id'],
                    'alert_title': row['title'],
                    'severity': row['severity'],
                    'created_at': row['created_at'].isoformat()
                }
                for row in username_rows
            ]
            
            total_iocs = sum(len(v) for v in ioc_results.values())
            logger.info(f"[SEARCH] Found {total_iocs} IOCs")
            
            # ===================================================================
            # 4. SEARCH USERS
            # ===================================================================
            logger.info(f"[SEARCH] Searching users...")
            user_rows = await conn.fetch("""
                SELECT username, email, full_name, role, created_at, disabled
                FROM users
                WHERE 
                    LOWER(username) LIKE $1 OR
                    LOWER(COALESCE(email, '')) LIKE $1 OR
                    LOWER(COALESCE(full_name, '')) LIKE $1 OR
                    LOWER(role) LIKE $1
                ORDER BY username
                LIMIT $2
            """, query, limit)
            
            users = [
                {
                    'username': row['username'],
                    'email': row['email'],
                    'full_name': row['full_name'],
                    'role': row['role'],
                    'disabled': row['disabled'],
                    'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                    'match_type': 'user'
                }
                for row in user_rows
            ]
            logger.info(f"[SEARCH] Found {len(users)} users")
            
            # ===================================================================
            # 5. SEARCH AUDIT LOGS
            # ===================================================================
            logger.info(f"[SEARCH] Searching audit logs...")
            audit_rows = await conn.fetch("""
                SELECT id, username, action, resource_type, resource_id, 
                       details, created_at
                FROM audit_log
                WHERE 
                    LOWER(COALESCE(username, '')) LIKE $1 OR
                    LOWER(action) LIKE $1 OR
                    LOWER(COALESCE(resource_type, '')) LIKE $1 OR
                    LOWER(COALESCE(resource_id, '')) LIKE $1 OR
                    LOWER(COALESCE(details::text, '')) LIKE $1
                ORDER BY created_at DESC
                LIMIT $2
            """, query, limit)
            
            audit_logs = [
                {
                    'id': str(row['id']),
                    'username': row['username'],
                    'action': row['action'],
                    'resource_type': row['resource_type'],
                    'resource_id': row['resource_id'],
                    'details': row['details'],
                    'timestamp': row['created_at'].isoformat(),
                    'match_type': 'audit_log'
                }
                for row in audit_rows
            ]
            logger.info(f"[SEARCH] Found {len(audit_logs)} audit logs")
            
            # ===================================================================
            # 6. KNOWLEDGE BASE (uses idx_kb_fts GIN index when query length >= 3)
            # ===================================================================
            logger.info(f"[SEARCH] Searching knowledge base...")
            kb_rows = await conn.fetch("""
                SELECT kb_id, title, content_type, category, tags,
                       LEFT(content, 240) AS content_excerpt
                FROM knowledge_base
                WHERE is_active = TRUE
                  AND (
                      ( length($2) >= 3 AND to_tsvector('english', title || ' ' || content)
                                            @@ plainto_tsquery('english', $2) )
                      OR LOWER(kb_id) LIKE $1
                      OR LOWER(COALESCE(category, '')) LIKE $1
                  )
                ORDER BY priority ASC, approved_at DESC NULLS LAST
                LIMIT $3
            """, query, q, limit)
            knowledge_base = [
                {
                    'kb_id': row['kb_id'],
                    'title': row['title'],
                    'content_type': row['content_type'],
                    'category': row['category'],
                    'tags': list(row['tags']) if row['tags'] else [],
                    'content_excerpt': row['content_excerpt'],
                    'match_type': 'knowledge_base',
                }
                for row in kb_rows
            ]

            # ===================================================================
            # 7. PLAYBOOKS
            # ===================================================================
            logger.info(f"[SEARCH] Searching playbooks...")
            playbook_rows = await conn.fetch("""
                SELECT id, name, description, tags, alert_types, is_active
                FROM playbooks
                WHERE
                    LOWER(name) LIKE $1
                    OR LOWER(COALESCE(description, '')) LIKE $1
                    OR EXISTS (SELECT 1 FROM unnest(COALESCE(tags, '{}'::text[])) t WHERE LOWER(t) LIKE $1)
                    OR EXISTS (SELECT 1 FROM unnest(COALESCE(alert_types, '{}'::text[])) a WHERE LOWER(a) LIKE $1)
                ORDER BY updated_at DESC NULLS LAST
                LIMIT $2
            """, query, limit)
            playbooks_results = [
                {
                    'id': str(row['id']),
                    'name': row['name'],
                    'description': row['description'],
                    'tags': list(row['tags']) if row['tags'] else [],
                    'alert_types': list(row['alert_types']) if row['alert_types'] else [],
                    'is_active': row['is_active'],
                    'match_type': 'playbook',
                }
                for row in playbook_rows
            ]

            # ===================================================================
            # 8. INTAKE FORM SUBMISSIONS (recent user-submitted reports)
            # ===================================================================
            logger.info(f"[SEARCH] Searching intake submissions...")
            intake_rows = await conn.fetch("""
                SELECT s.id, s.form_id, s.submitted_by, s.status, s.alert_id,
                       s.created_at, f.name AS form_name, f.title AS form_title
                FROM intake_form_submissions s
                LEFT JOIN intake_forms f ON f.id = s.form_id
                WHERE LOWER(COALESCE(s.submitted_by, '')) LIKE $1
                   OR LOWER(COALESCE(s.alert_id, '')) LIKE $1
                   OR LOWER(COALESCE(f.name, '')) LIKE $1
                   OR LOWER(COALESCE(f.title, '')) LIKE $1
                   OR LOWER(COALESCE(s.payload::text, '')) LIKE $1
                ORDER BY s.created_at DESC
                LIMIT $2
            """, query, limit)
            intake_submissions = [
                {
                    'submission_id': str(row['id']),
                    'form_id': str(row['form_id']) if row['form_id'] else None,
                    'form_name': row['form_name'],
                    'form_title': row['form_title'],
                    'submitted_by': row['submitted_by'],
                    'status': row['status'],
                    'alert_id': row['alert_id'],
                    'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                    'match_type': 'intake_submission',
                }
                for row in intake_rows
            ]

            # ===================================================================
            # 9. RECOMMENDED ACTIONS (Riggs-generated remediations)
            # ===================================================================
            logger.info(f"[SEARCH] Searching recommended actions...")
            action_rows = await conn.fetch("""
                SELECT id, investigation_id, action_type, title, description,
                       ioc_type, ioc_value, connector_name, status, priority, created_at
                FROM recommended_actions
                WHERE LOWER(title) LIKE $1
                   OR LOWER(COALESCE(description, '')) LIKE $1
                   OR LOWER(action_type) LIKE $1
                   OR LOWER(COALESCE(ioc_value, '')) LIKE $1
                   OR LOWER(COALESCE(connector_name, '')) LIKE $1
                   OR LOWER(status) LIKE $1
                ORDER BY created_at DESC
                LIMIT $2
            """, query, limit)
            recommended_actions_results = [
                {
                    'id': str(row['id']),
                    'investigation_id': str(row['investigation_id']) if row['investigation_id'] else None,
                    'action_type': row['action_type'],
                    'title': row['title'],
                    'description': row['description'],
                    'ioc_type': row['ioc_type'],
                    'ioc_value': row['ioc_value'],
                    'connector_name': row['connector_name'],
                    'status': row['status'],
                    'priority': row['priority'],
                    'created_at': row['created_at'].isoformat() if row['created_at'] else None,
                    'match_type': 'recommended_action',
                }
                for row in action_rows
            ]

            # ===================================================================
            # 10. DETECTION RULES
            # ===================================================================
            logger.info(f"[SEARCH] Searching detection rules...")
            try:
                detection_rows = await conn.fetch("""
                    SELECT rule_id, title, description, rule_type, severity, enabled
                    FROM detection_rules
                    WHERE LOWER(rule_id) LIKE $1
                       OR LOWER(title) LIKE $1
                       OR LOWER(COALESCE(description, '')) LIKE $1
                       OR LOWER(COALESCE(rule_type, '')) LIKE $1
                    ORDER BY title
                    LIMIT $2
                """, query, limit)
                detection_rules_results = [
                    {
                        'rule_id': row['rule_id'],
                        'title': row['title'],
                        'description': row['description'],
                        'rule_type': row['rule_type'],
                        'severity': row['severity'],
                        'enabled': row['enabled'],
                        'match_type': 'detection_rule',
                    }
                    for row in detection_rows
                ]
            except Exception as detection_err:
                # Schema may vary across tenants — don't fail the whole search
                # if detection_rules has different columns than expected.
                logger.warning(f"[SEARCH] detection_rules query failed, skipping: {detection_err}")
                detection_rules_results = []

            # ===================================================================
            # COMPILE RESULTS
            # ===================================================================
            total_results = (
                len(alerts) + len(investigations) + total_iocs + len(users) + len(audit_logs)
                + len(knowledge_base) + len(playbooks_results) + len(intake_submissions)
                + len(recommended_actions_results) + len(detection_rules_results)
            )

            result = {
                "query": q,
                "alerts": alerts,
                "investigations": investigations,
                "iocs": ioc_results,
                "users": users,
                "audit_logs": audit_logs,
                "knowledge_base": knowledge_base,
                "playbooks": playbooks_results,
                "intake_submissions": intake_submissions,
                "recommended_actions": recommended_actions_results,
                "detection_rules": detection_rules_results,
                "counts": {
                    "alerts": len(alerts),
                    "investigations": len(investigations),
                    "iocs": total_iocs,
                    "users": len(users),
                    "audit_logs": len(audit_logs),
                    "knowledge_base": len(knowledge_base),
                    "playbooks": len(playbooks_results),
                    "intake_submissions": len(intake_submissions),
                    "recommended_actions": len(recommended_actions_results),
                    "detection_rules": len(detection_rules_results),
                    "total": total_results
                }
            }
            
            logger.info(f"[SEARCH] TOTAL RESULTS: {total_results} ({len(alerts)} alerts, {len(investigations)} investigations, {total_iocs} IOCs, {len(users)} users, {len(audit_logs)} audit logs)")
            
            return result

    except Exception as e:
        logger.info(f"Error in global search: {e}")
        import traceback
        traceback.print_exc()
        # Return empty results instead of error for better UX
        return {
            "query": q,
            "alerts": [],
            "investigations": [],
            "iocs": {},
            "users": [],
            "audit_logs": [],
            "knowledge_base": [],
            "playbooks": [],
            "intake_submissions": [],
            "recommended_actions": [],
            "detection_rules": [],
            "counts": {
                "alerts": 0, "investigations": 0, "iocs": 0, "users": 0, "audit_logs": 0,
                "knowledge_base": 0, "playbooks": 0, "intake_submissions": 0,
                "recommended_actions": 0, "detection_rules": 0, "total": 0,
            },
            "error": str(e)
        }


@app.delete("/api/v1/investigations/{investigation_id}")
async def delete_investigation(investigation_id: str):
    """Delete an investigation"""
    if investigation_id not in investigations_store:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation {investigation_id} not found"
        )
    
    del investigations_store[investigation_id]
    return {"status": "deleted", "investigation_id": investigation_id}


@app.post("/api/v1/investigations/{investigation_id}/forward")
async def forward_investigation(
    investigation_id: str,
    integrations: Optional[List[str]] = None
):
    """
    Forward investigation results to external integrations (Splunk, SIEM, etc.)
    
    Args:
        investigation_id: Investigation to forward
        integrations: List of integration names (optional, defaults to all enabled)
    
    Example:
        POST /api/v1/investigations/inv-123/forward
        Body: {"integrations": ["splunk", "elasticsearch"]}
    """
    if investigation_id not in investigations_store:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation {investigation_id} not found"
        )
    
    investigation = investigations_store[investigation_id]
    
    # Forward to integrations
    from services.integrations import send_to_integrations
    
    try:
        results = await send_to_integrations(investigation, integrations)
        
        return {
            "status": "forwarded",
            "investigation_id": investigation_id,
            "results": results
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to forward investigation: {str(e)}"
        )


# ================== INVESTIGATION WORKFLOW ENDPOINTS (Phase 3.4) ==================

@app.post("/api/v1/investigations/{investigation_id}/claim")
async def claim_investigation(
    investigation_id: str,
    current_user: str = Depends(get_current_username)
):
    """
    Claim an investigation for yourself.

    Sets the current user as the owner and logs the ownership change.
    """
    from services.assignment_service import get_assignment_service

    service = get_assignment_service()
    result = await service.claim_investigation(investigation_id, current_user)

    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    return {
        "status": "claimed",
        "investigation_id": investigation_id,
        "owner": result.owner,
        "message": result.message
    }


@app.post("/api/v1/investigations/{investigation_id}/release")
async def release_investigation(
    investigation_id: str,
    reason: Optional[str] = None,
    current_user: str = Depends(get_current_username)
):
    """
    Release ownership of an investigation.

    Returns the investigation to the unassigned queue.
    """
    from services.assignment_service import get_assignment_service

    service = get_assignment_service()
    result = await service.release_investigation(investigation_id, current_user, reason)

    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    return {
        "status": "released",
        "investigation_id": investigation_id,
        "message": result.message
    }


class AssignRequest(BaseModel):
    new_owner: str
    reason: Optional[str] = None


@app.post("/api/v1/investigations/{investigation_id}/assign")
async def assign_investigation(
    investigation_id: str,
    request: AssignRequest,
    current_user: str = Depends(get_current_username)
):
    """
    Assign/reassign an investigation to another user.
    """
    from services.assignment_service import get_assignment_service

    service = get_assignment_service()
    result = await service.reassign_investigation(
        investigation_id,
        request.new_owner,
        current_user,
        request.reason
    )

    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    return {
        "status": "assigned",
        "investigation_id": investigation_id,
        "owner": result.owner,
        "message": result.message
    }


class EscalateRequest(BaseModel):
    level: int = 1
    reason: str


@app.post("/api/v1/investigations/{investigation_id}/escalate")
async def escalate_investigation(
    investigation_id: str,
    request: EscalateRequest,
    current_user: str = Depends(get_current_username)
):
    """
    Escalate an investigation to a higher tier.

    Levels:
    - 1: Tier 2 analysts
    - 2: SOC Manager
    - 3: Critical/On-call
    """
    from services.assignment_service import get_assignment_service

    service = get_assignment_service()
    result = await service.escalate_investigation(
        investigation_id,
        current_user,
        request.level,
        request.reason
    )

    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    return {
        "status": "escalated",
        "investigation_id": investigation_id,
        "escalation_level": request.level,
        "message": result.message
    }


# ============================================================================
# DEEP DIVE (Premium Feature — Pro+ Only)
# ============================================================================

@app.post("/api/v1/investigations/{investigation_id}/deep-dive")
async def deep_dive_investigation(
    investigation_id: str,
    request: Request,
    current_user: Dict = Depends(auth_get_current_user),
):
    """
    Perform an in-depth AI analysis on an investigation (Pro+ only).

    Returns comprehensive threat narrative, MITRE ATT&CK mapping,
    root cause analysis, and response recommendations.
    """
    from dependencies.license_checks import enforce_feature, _get_tenant_id_from_request, _get_tenant_tier
    from services.licensing.default_plans import get_default_entitlements

    # Enforce deep_dive feature gate + monthly limit
    tenant_id = await _get_tenant_id_from_request(request)
    if not tenant_id:
        raise HTTPException(status_code=401, detail="Tenant context required")

    tier = await _get_tenant_tier(str(tenant_id))
    entitlements = get_default_entitlements(tier)

    if not entitlements.features.get("deep_dive", False):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "feature_not_licensed",
                "feature": "deep_dive",
                "tier": tier.value,
                "message": "Deep Dive analysis is available on Pro and Enterprise plans. Upgrade to unlock.",
                "upgrade_url": "/pricing",
            },
        )

    # Check monthly limit (0 = unlimited for paid tiers)
    monthly_limit = entitlements.features.get("deep_dive_monthly_limit", 0)
    if monthly_limit > 0:
        from dependencies.license_checks import get_deep_dive_usage
        usage = await get_deep_dive_usage(str(tenant_id))
        if usage["remaining"] <= 0:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "deep_dive_limit_exceeded",
                    "feature": "deep_dive",
                    "used": usage["used"],
                    "limit": usage["limit"],
                    "remaining": 0,
                    "tier": tier.value,
                    "message": f"Monthly Deep Dive limit reached ({usage['used']}/{usage['limit']}). Upgrade to Pro for unlimited Deep Dives.",
                    "upgrade_url": "/pricing",
                },
            )

    from services.ai_triage_service import get_ai_triage_service

    service = get_ai_triage_service()
    result = await service.deep_dive_investigation(investigation_id, str(tenant_id))

    if "error" in result:
        if result["error"] == "quota_exceeded":
            raise HTTPException(status_code=429, detail=result)
        raise HTTPException(status_code=500, detail=result)

    return result


class BlockRequest(BaseModel):
    reason: str


@app.post("/api/v1/investigations/{investigation_id}/block")
async def block_investigation(
    investigation_id: str,
    request: BlockRequest,
    current_user: str = Depends(get_current_username)
):
    """
    Mark an investigation as blocked (waiting on external dependency).

    Pauses SLA tracking while blocked.
    """
    from services.assignment_service import get_assignment_service

    service = get_assignment_service()
    result = await service.block_investigation(investigation_id, current_user, request.reason)

    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    return {
        "status": "blocked",
        "investigation_id": investigation_id,
        "blocked_reason": request.reason,
        "message": result.message
    }


@app.post("/api/v1/investigations/{investigation_id}/unblock")
async def unblock_investigation(
    investigation_id: str,
    current_user: str = Depends(get_current_username)
):
    """
    Remove block from an investigation.

    Resumes SLA tracking.
    """
    from services.assignment_service import get_assignment_service

    service = get_assignment_service()
    result = await service.unblock_investigation(investigation_id, current_user)

    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    return {
        "status": "unblocked",
        "investigation_id": investigation_id,
        "message": result.message
    }


class ResolveRequest(BaseModel):
    resolution_type: str  # verified_malicious, false_positive, benign_activity, inconclusive, duplicate
    notes: Optional[str] = None


@app.post("/api/v1/investigations/{investigation_id}/resolve")
async def resolve_investigation(
    investigation_id: str,
    request: ResolveRequest,
    current_user: str = Depends(get_current_username)
):
    """
    Mark an investigation as resolved.

    Resolution types:
    - verified_malicious: Confirmed malicious activity
    - false_positive: Alert was incorrect
    - benign_activity: Activity was legitimate
    - inconclusive: Unable to determine
    - duplicate: Duplicate of another investigation
    """
    from services.assignment_service import get_assignment_service

    service = get_assignment_service()
    result = await service.resolve_investigation(
        investigation_id,
        current_user,
        request.resolution_type,
        request.notes
    )

    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    return {
        "status": "resolved",
        "investigation_id": investigation_id,
        "resolution_type": request.resolution_type,
        "message": result.message
    }


@app.post("/api/v1/investigations/{investigation_id}/close")
async def close_investigation(
    investigation_id: str,
    current_user: str = Depends(get_current_username)
):
    """
    Close a resolved investigation.

    Investigation must be in RESOLVED state first.
    """
    from services.assignment_service import get_assignment_service

    service = get_assignment_service()
    result = await service.close_investigation(investigation_id, current_user)

    if not result.success:
        raise HTTPException(status_code=400, detail=result.message)

    return {
        "status": "closed",
        "investigation_id": investigation_id,
        "message": result.message
    }


# NOTE: get_my_queue moved to static routes section (line ~1647)


@app.get("/api/v1/investigations/queue/team/{team_id}")
async def get_team_queue(
    team_id: str,
    current_user: str = Depends(get_current_username)
):
    """
    Get investigations for a team.

    Returns open investigations for all team members.
    """
    from services.assignment_service import get_assignment_service

    service = get_assignment_service()
    investigations = await service.get_team_queue(team_id)

    return {
        "team_id": team_id,
        "count": len(investigations),
        "investigations": investigations
    }


# NOTE: get_orphaned_investigations moved to static routes section (line ~1663)


@app.get("/api/v1/investigations/{investigation_id}/ownership-history")
async def get_ownership_history(
    investigation_id: str,
    current_user: str = Depends(get_current_username)
):
    """
    Get ownership change history for an investigation.
    """
    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT * FROM investigation_ownership_log
                WHERE investigation_id = (
                    SELECT id FROM investigations WHERE investigation_id = $1
                )
                ORDER BY created_at DESC
                """,
                investigation_id
            )

            return {
                "investigation_id": investigation_id,
                "history": [dict(row) for row in rows]
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


# ================== ASSIGNMENT RULES & TEAMS MANAGEMENT ==================

@app.get("/api/v1/assignment-rules")
async def list_assignment_rules(
    enabled_only: bool = True,
    current_user: str = Depends(get_current_username)
):
    """List assignment rules."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            if enabled_only:
                rows = await conn.fetch(
                    "SELECT * FROM assignment_rules WHERE enabled = true ORDER BY priority"
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM assignment_rules ORDER BY priority"
                )

            return {"rules": [dict(row) for row in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/teams")
async def list_teams(
    current_user: str = Depends(get_current_username)
):
    """List all teams."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM teams WHERE enabled = true ORDER BY name"
            )

            return {"teams": [dict(row) for row in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/teams/{team_id}")
async def get_team(
    team_id: str,
    current_user: str = Depends(get_current_username)
):
    """Get team details."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            team = await conn.fetchrow(
                "SELECT * FROM teams WHERE team_id = $1",
                team_id
            )

            if not team:
                raise HTTPException(status_code=404, detail="Team not found")

            return dict(team)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


class TeamUpdateRequest(BaseModel):
    members: Optional[List[str]] = None
    lead_user_id: Optional[str] = None
    max_concurrent_investigations: Optional[int] = None


@app.put("/api/v1/teams/{team_id}")
async def update_team(
    team_id: str,
    request: TeamUpdateRequest,
    current_user: str = Depends(get_current_username)
):
    """Update team configuration."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            updates = []
            params = []
            param_idx = 1

            if request.members is not None:
                updates.append(f"members = ${param_idx}")
                params.append(request.members)
                param_idx += 1

            if request.lead_user_id is not None:
                updates.append(f"lead_user_id = ${param_idx}")
                params.append(request.lead_user_id)
                param_idx += 1

            if request.max_concurrent_investigations is not None:
                updates.append(f"max_concurrent_investigations = ${param_idx}")
                params.append(request.max_concurrent_investigations)
                param_idx += 1

            if not updates:
                return {"status": "no changes"}

            updates.append("updated_at = NOW()")
            params.append(team_id)

            await conn.execute(
                f"UPDATE teams SET {', '.join(updates)} WHERE team_id = ${param_idx}",
                *params
            )

            return {"status": "updated", "team_id": team_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/sla-config")
async def get_sla_config(
    current_user: str = Depends(get_current_username)
):
    """Get SLA configuration for all priorities."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM sla_config ORDER BY priority"
            )

            return {"sla_config": [dict(row) for row in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


@app.get("/api/v1/escalation-config")
async def get_escalation_config(
    current_user: str = Depends(get_current_username)
):
    """Get escalation timer configuration."""
    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM escalation_config WHERE enabled = true ORDER BY threshold_minutes"
            )

            return {"escalation_config": [dict(row) for row in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")



@app.get("/api/v1/search/ioc/{ioc_value}")
async def search_by_ioc(ioc_value: str, ioc_type: Optional[str] = None):
    """
    Search investigations by IOC (Indicator of Compromise).
    
    Args:
        ioc_value: The IOC to search for (IP, domain, hash, etc.)
        ioc_type: Optional type filter (ips, domains, hashes, urls, emails, users, hosts)
    
    Example:
        GET /api/v1/search/ioc/192.168.1.100
        GET /api/v1/search/ioc/malicious-site.com?ioc_type=domains
    """
    try:
        from services.database import get_db
        db = get_db()
        
        if not db.client:
            raise HTTPException(
                status_code=503,
                detail="Database not available. IOC search requires database."
            )
        
        results = await db.search_by_ioc(ioc_value, ioc_type)
        
        return {
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "matches": len(results),
            "investigations": results
        }
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Search failed: {str(e)}"
        )


# ================== IOC THREAT INTEL MANAGEMENT ==================

@app.get("/api/v1/iocs")
async def get_all_iocs(
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 1000
):
    """Get all tracked IOCs with enrichment data"""
    try:
        from services.database import db
        
        if not db.connected:
            return []
        
        # Build query
        query = {}
        if ioc_type:
            query["ioc_type"] = ioc_type
        if severity:
            query["severity"] = severity
        
        # Get IOCs from correlation engine
        iocs_cursor = db.db.ioc_tracking.find(query).sort("last_seen", -1).limit(limit)
        iocs = await iocs_cursor.to_list(length=limit)
        
        # Convert _id to string if present (legacy field)
        for ioc in iocs:
            if "_id" in ioc:
                ioc["_id"] = str(ioc["_id"])
        
        return iocs

    except Exception as e:
        logger.info(f"Error fetching IOCs: {e}")
        return []


@app.get("/api/v1/iocs/stats")
async def get_ioc_stats():
    """Get IOC statistics from PostgreSQL"""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.pool:
            return {
                "total": 0,
                "by_type": {},
                "by_severity": {},
                "recent": 0
            }

        async with postgres_db.tenant_acquire() as conn:
            # Count total IOCs
            total = await conn.fetchval("SELECT COUNT(*) FROM iocs")

            # Count by type
            by_type_rows = await conn.fetch("""
                SELECT ioc_type, COUNT(*) as count
                FROM iocs
                GROUP BY ioc_type
            """)
            by_type = {row['ioc_type']: row['count'] for row in by_type_rows}

            # Count by severity
            by_severity_rows = await conn.fetch("""
                SELECT severity, COUNT(*) as count
                FROM iocs
                GROUP BY severity
            """)
            by_severity = {row['severity']: row['count'] for row in by_severity_rows}

            # Count recent (last 24 hours)
            recent = await conn.fetchval("""
                SELECT COUNT(*) FROM iocs
                WHERE last_seen >= NOW() - INTERVAL '24 hours'
            """)

            return {
                "total": total or 0,
                "by_type": by_type,
                "by_severity": by_severity,
                "recent": recent or 0
            }

    except Exception as e:
        logger.info(f"Error getting IOC stats: {e}")
        return {
            "total": 0,
            "by_type": {},
            "by_severity": {},
            "recent": 0
        }


@app.get("/api/v1/iocs/{ioc_value}")
async def get_ioc_detail(ioc_value: str):
    """Get detailed information about a specific IOC"""
    try:
        from services.database import db
        
        if not db.connected:
            raise HTTPException(503, "Database not connected")
        
        # Get IOC from tracking
        ioc = await db.db.ioc_tracking.find_one({"ioc_value": ioc_value})
        
        if not ioc:
            raise HTTPException(404, "IOC not found")
        
        # Get related alerts
        related_alerts = await db.db.alerts.find({
            "$or": [
                {"raw_data": {"$regex": ioc_value, "$options": "i"}},
                {"metadata": {"$regex": ioc_value, "$options": "i"}},
                {"raw_log": {"$regex": ioc_value, "$options": "i"}}
            ]
        }).to_list(length=100)
        
        # Get related investigations
        related_investigations = await db.db.investigations.find({
            "$or": [
                {"ioc_summary.ips": ioc_value},
                {"ioc_summary.domains": ioc_value},
                {"ioc_summary.hashes": ioc_value},
                {"ioc_summary.urls": ioc_value},
                {"ioc_summary.emails": ioc_value}
            ]
        }).to_list(length=100)
        
        # Convert _id fields
        if "_id" in ioc:
            ioc["_id"] = str(ioc["_id"])
        
        for alert in related_alerts:
            if "_id" in alert:
                alert["_id"] = str(alert["_id"])
        
        for inv in related_investigations:
            if "_id" in inv:
                inv["_id"] = str(inv["_id"])
        
        return {
            "ioc": ioc,
            "related_alerts": related_alerts,
            "related_investigations": related_investigations,
            "statistics": {
                "total_alerts": len(related_alerts),
                "total_investigations": len(related_investigations),
                "first_seen": ioc.get("first_seen"),
                "last_seen": ioc.get("last_seen"),
                "occurrences": ioc.get("occurrences", 0)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.info(f"Error getting IOC detail: {e}")
        raise HTTPException(500, str(e))


@app.post("/api/v1/iocs/{ioc_value}/enrich")
async def enrich_ioc(ioc_value: str):
    """Trigger enrichment for a specific IOC"""
    try:
        from services.database import db
        
        if not db.connected:
            raise HTTPException(503, "Database not connected")
        
        # TODO: Call enrichment services (VirusTotal, IPInfo, etc.)
        # For now, just update last enriched timestamp
        
        result = await db.db.ioc_tracking.update_one(
            {"ioc_value": ioc_value},
            {
                "$set": {
                    "last_enriched": datetime.utcnow(),
                    "enrichment_status": "pending"
                }
            }
        )
        
        if result.matched_count == 0:
            raise HTTPException(404, "IOC not found")
        
        return {
            "success": True,
            "message": "Enrichment triggered",
            "ioc_value": ioc_value
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.info(f"Error enriching IOC: {e}")
        raise HTTPException(500, str(e))


@app.get("/api/v1/database/stats")
async def get_database_stats():
    """
    Get database statistics and metrics.
    Requires database to be connected.
    """
    try:
        from services.database import get_db
        db = get_db()
        
        if not db.client:
            return {
                "status": "unavailable",
                "message": "Database not connected",
                "using_memory_storage": True
            }
        
        stats = await db.get_statistics()
        stats["status"] = "available"
        stats["database_name"] = db.database_name
        
        return stats
    
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get statistics: {str(e)}"
        )


async def run_investigation(investigation_id: str, alert: Alert):
    """
    Background task to run investigation with full IOC tracking.
    Called asynchronously from alert ingestion.
    """
    try:
        # Extract indicators (old format for planner)
        extractor = IndicatorExtractor()
        text = f"{alert.title} {alert.description or ''} {alert.raw_log or ''}"
        indicators = extractor.extract_all(text, alert.metadata)
        
        # Track IOCs in database using enhanced extractor
        try:
            from services.ioc_extractor import ioc_extractor
            from services.database import db
            
            if db.connected:
                # Extract and automatically track (returns dict)
                ioc_dict = await ioc_extractor.extract_and_track(
                    text=text,
                    metadata=alert.metadata,
                    db_service=db,
                    alert_id=alert.id,
                    investigation_id=investigation_id,
                    severity="medium"  # Will be updated based on verdict
                )
                logger.info(f"[OK] Tracked {sum(len(v) for v in ioc_dict.values())} IOCs from alert {alert.id}")
        except Exception as e:
            logger.warning(f"[WARN] IOC tracking error: {e}")
        
        # Get IOC correlations
        correlations = {}
        try:
            from services.database import db
            if db.connected and indicators:
                all_ioc_values = list(set(ind.value for ind in indicators))
                
                if all_ioc_values:
                    correlations = await db.get_ioc_correlations(all_ioc_values)
                    logger.info(f"[OK] Found correlations for {len(correlations)} IOCs")
        except Exception as e:
            logger.warning(f"[WARN] Could not get correlations: {e}")
        
        # Run investigation
        planner = AgentPlanner()
        result = await planner.investigate(alert, indicators)
        
        # Add correlations to result
        if correlations:
            result.ioc_correlations = correlations
        
        # Update IOC severities based on verdict
        try:
            from services.ioc_extractor import ioc_extractor
            from services.database import db
            
            if db.connected:
                severity = ioc_extractor.determine_severity(result.verdict)
                
                # Update all IOCs from this investigation
                for indicator in indicators:
                    await db.track_or_update_ioc({
                        "ioc_value": indicator.value,
                        "ioc_type": str(indicator.type).lower().replace("indicatortype.", ""),
                        "severity": severity,
                        "investigation_id": investigation_id
                    })
                
                logger.info(f"[OK] Updated IOC severities to {severity} based on verdict {result.verdict}")
        except Exception as e:
            logger.warning(f"[WARN] Could not update IOC severities: {e}")
        
        # Store result in memory
        investigations_store[investigation_id] = result
        
        # Save to database if available
        try:
            from services.database import db
            logger.info(f"[DB] Investigation - DB connected: {db.connected}")
            
            if db.connected:
                # Convert Pydantic model to dict for database
                if hasattr(result, 'model_dump'):
                    result_dict = result.model_dump(mode='json')
                else:
                    result_dict = result.dict()
                
                result_dict["investigation_id"] = investigation_id
                
                # Remove correlations from saved data (too large, query on demand)
                result_dict.pop("ioc_correlations", None)
                
                # Convert datetime strings back to datetime objects
                from datetime import datetime
                for field in ["timestamp", "created_at", "completed_at"]:
                    if field in result_dict and isinstance(result_dict[field], str):
                        try:
                            result_dict[field] = datetime.fromisoformat(result_dict[field].replace('Z', '+00:00'))
                        except:
                            pass
                
                logger.info(f"[SAVE] Attempting to save investigation: {investigation_id}")
                logger.debug(f"[DEBUG] Investigation dict keys: {result_dict.keys()}")
                
                save_result = await db.save_investigation(result_dict)
                logger.info(f"[SAVE] Save result: {save_result}")
                
                if save_result:
                    logger.info(f"[OK] Investigation {investigation_id} saved to database")
                else:
                    logger.error(f"[ERROR] Investigation {investigation_id} save returned False")
            else:
                logger.warning(f"[WARN] Database not connected, investigation saved to memory only")
        except Exception as e:
            logger.error(f"[ERROR] Error saving investigation to database: {e}")
            import traceback
            traceback.print_exc()
        
        logger.info(f"[OK] Investigation {investigation_id} completed: {result.verdict}")
    
    except Exception as e:
        logger.error(f"[ERROR] Investigation {investigation_id} failed: {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Store error result
        from models import InvestigationResult, IOCSummary
        error_result = InvestigationResult(
            investigation_id=investigation_id,
            alert_id=alert.id,
            executive_summary=f"Investigation failed: {str(e)}",
            technical_findings=[],
            timeline=[],
            severity=SeverityLevel.LOW,
            confidence=ConfidenceLevel.LOW,
            verdict=DispositionType.INCONCLUSIVE,
            disposition=DispositionType.INCONCLUSIVE,
            recommended_actions=[],
            ioc_summary=IOCSummary(),
            completed_at=datetime.utcnow()
        )
        investigations_store[investigation_id] = error_result
        
        # Try to save error to database
        try:
            from services.database import db
            if db.connected:
                error_dict = error_result.dict()
                error_dict["investigation_id"] = investigation_id
                await db.save_investigation(error_dict)
        except:
            pass


# ============================================================================
# VIRUSTOTAL ENRICHMENT ENDPOINTS
# ============================================================================

@app.post("/api/v1/enrich/ip")
async def enrich_ip_address(body: Dict = Body(...)):
    """
    Enrich an IP address using VirusTotal
    
    Request body:
        {"ip": "8.8.8.8"}
    
    Returns threat intelligence data
    """
    from services.virustotal import virustotal_service
    
    ip = body.get('ip')
    if not ip:
        raise HTTPException(status_code=400, detail="IP address is required")
    
    result = await virustotal_service.enrich_ip(ip)
    return result


@app.post("/api/v1/enrich/domain")
async def enrich_domain(body: Dict = Body(...)):
    """
    Enrich a domain using VirusTotal
    
    Request body:
        {"domain": "example.com"}
    
    Returns threat intelligence data
    """
    from services.virustotal import virustotal_service
    
    domain = body.get('domain')
    if not domain:
        raise HTTPException(status_code=400, detail="Domain is required")
    
    result = await virustotal_service.enrich_domain(domain)
    return result


@app.post("/api/v1/enrich/hash")
async def enrich_file_hash(body: Dict = Body(...)):
    """
    Enrich a file hash using VirusTotal
    
    Request body:
        {"hash": "44d88612fea8a8f36de82e1278abb02f"}
    
    Supports MD5, SHA1, SHA256
    Returns threat intelligence data
    """
    from services.virustotal import virustotal_service
    
    file_hash = body.get('hash')
    if not file_hash:
        raise HTTPException(status_code=400, detail="File hash is required")
    
    result = await virustotal_service.enrich_file_hash(file_hash)
    return result


async def _correlate_alert_task(alert_id: str, alert_dict: Dict[str, Any]):
    """
    Background task to correlate alert with existing investigations.

    Runs after enrichment completes to have IOC data available.
    """
    import asyncio
    from services.alert_correlation_service import get_correlation_service
    from services.postgres_db import postgres_db

    try:
        # Wait for enrichment to complete (up to 30 seconds)
        for i in range(30):
            await asyncio.sleep(1)

            # Check if enrichment data is available
            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow("""
                    SELECT raw_event FROM alerts WHERE alert_id = $1
                """, alert_id)

                if row and row['raw_event']:
                    raw_event = row['raw_event']
                    if isinstance(raw_event, str):
                        import json
                        raw_event = json.loads(raw_event)

                    # Check if enrichment data exists
                    if raw_event.get('_extracted'):
                        break

        # Get latest alert data with enrichment
        alert_data = await postgres_db.get_alert_by_id(alert_id)
        if not alert_data:
            logger.warning(f"Alert {alert_id}: Not found for correlation")
            return

        # Extract IOCs
        raw_event = alert_data.get('raw_event', {})
        if isinstance(raw_event, str):
            import json
            raw_event = json.loads(raw_event)

        extracted = raw_event.get('_extracted', {})
        iocs = {
            'ips': extracted.get('ips', []),
            'domains': extracted.get('domains', []),
            'hashes': extracted.get('file_hashes', []) + extracted.get('hashes', []),
            'emails': extracted.get('emails', [])
        }

        # Run correlation
        correlation_service = get_correlation_service()
        matched_inv = await correlation_service.correlate_alert(
            alert_id,
            alert_data,
            iocs
        )

        if matched_inv:
            logger.info(f"Alert {alert_id}: Correlated with investigation {matched_inv}")
        else:
            logger.debug(f"Alert {alert_id}: No correlations found")

    except Exception as e:
        logger.error(f"Alert {alert_id}: Correlation task failed - {e}")


@app.post("/api/v1/alerts/{alert_id}/enrich")
async def enrich_alert_iocs(alert_id: str, exc_info=True):
    """
    Auto-enrich all IOCs found in an alert

    Extracts IPs, domains, and hashes from alert raw_event
    and enriches them with VirusTotal
    """
    from services.postgres_db import postgres_db
    from services.virustotal import virustotal_service
    import re
    
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")
    
    # Get alert
    alert = await postgres_db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    raw_event = alert.get('raw_event', {})
    alert_text = str(raw_event)
    
    # Extract IOCs
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', alert_text)
    domains = re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', alert_text)
    hashes = re.findall(r'\b[a-fA-F0-9]{32,64}\b', alert_text)
    
    enrichments = {
        "alert_id": alert_id,
        "ips": [],
        "domains": [],
        "hashes": []
    }
    
    # Enrich IPs (limit to first 3)
    for ip in list(set(ips))[:3]:
        if not ip.startswith('10.') and not ip.startswith('192.168.') and not ip.startswith('172.'):
            result = await virustotal_service.enrich_ip(ip)
            enrichments["ips"].append(result)
    
    # Enrich domains (limit to first 3)
    for domain in list(set(domains))[:3]:
        result = await virustotal_service.enrich_domain(domain)
        enrichments["domains"].append(result)
    
    # Enrich hashes (limit to first 3)
    for hash_val in list(set(hashes))[:3]:
        result = await virustotal_service.enrich_file_hash(hash_val)
        enrichments["hashes"].append(result)
    
    return enrichments


# ==================== AI TRIAGE ENDPOINTS ====================

@app.get("/api/v1/alerts/{alert_id}/ai-triage")
async def get_alert_ai_triage(alert_id: str):
    """
    Get AI triage results for an alert.

    Returns the AI's verdict, confidence, summary, and full analysis.
    This endpoint makes the AI's decision visible to analysts.
    """
    from services.ai_triage_service import get_ai_triage_service

    ai_triage = get_ai_triage_service()
    result = await ai_triage.get_alert_triage(alert_id)

    if not result:
        raise HTTPException(status_code=404, detail="Alert not found or not yet triaged")

    return result


@app.post("/api/v1/alerts/{alert_id}/ai-triage/rerun")
async def rerun_alert_ai_triage(alert_id: str):
    """
    Re-run AI triage on an existing alert.

    Useful when:
    - New enrichment data is available
    - AI model has been updated
    - Manual review is needed
    """
    from services.ai_triage_service import get_ai_triage_service

    ai_triage = get_ai_triage_service()
    result = await ai_triage.retriage_alert(alert_id)

    if result.get('error'):
        raise HTTPException(status_code=400, detail=result['error'])

    return result


@app.get("/api/v1/ai-triage/stats")
async def get_ai_triage_stats():
    """
    Get AI triage statistics.

    Returns counts by verdict type and confidence distribution.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not available")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get verdict counts
            verdict_counts = await conn.fetch('''
                SELECT
                    ai_verdict,
                    COUNT(*) as count,
                    AVG(ai_confidence) as avg_confidence
                FROM alerts
                WHERE ai_verdict IS NOT NULL
                GROUP BY ai_verdict
                ORDER BY count DESC
            ''')

            # Get total triaged
            total_triaged = await conn.fetchval('''
                SELECT COUNT(*) FROM alerts WHERE ai_verdict IS NOT NULL
            ''')

            # Get pending (no verdict)
            pending_triage = await conn.fetchval('''
                SELECT COUNT(*) FROM alerts WHERE ai_verdict IS NULL AND status = 'open'
            ''')

            return {
                "total_triaged": total_triaged,
                "pending_triage": pending_triage,
                "verdicts": [
                    {
                        "verdict": row['ai_verdict'],
                        "count": row['count'],
                        "avg_confidence": float(row['avg_confidence']) if row['avg_confidence'] else None
                    }
                    for row in verdict_counts
                ]
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal server error")


# ── Static frontend (native single-node mode) ──────────────────────────────
# When SERVE_FRONTEND is enabled, this FastAPI process also serves the built
# React app, so a single port handles the UI, the REST API, and the WebSocket
# with no nginx/Caddy. In the Docker deployment this stays OFF (nginx serves
# the frontend), so default behaviour is unchanged. This block is registered
# last, after every API/WebSocket route, so the SPA catch-all never shadows them.
if os.getenv("SERVE_FRONTEND", "").lower() in ("1", "true", "yes"):
    from fastapi.staticfiles import StaticFiles
    from fastapi.responses import FileResponse

    _FRONTEND_DIR = os.path.abspath(os.getenv(
        "FRONTEND_DIR",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend", "build"),
    ))
    _SPA_INDEX = os.path.join(_FRONTEND_DIR, "index.html")

    if os.path.isfile(_SPA_INDEX):
        _static_dir = os.path.join(_FRONTEND_DIR, "static")
        if os.path.isdir(_static_dir):
            app.mount("/static", StaticFiles(directory=_static_dir), name="frontend-static")

        # Paths that must return a real 404 instead of falling back to the SPA.
        _NON_SPA_PREFIXES = ("api/", "ws/", "v1/", "docs", "redoc", "openapi.json", "health", "metrics")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def _spa_fallback(full_path: str):
            if full_path.startswith(_NON_SPA_PREFIXES):
                raise HTTPException(status_code=404, detail="Not found")
            candidate = os.path.normpath(os.path.join(_FRONTEND_DIR, full_path))
            if (
                full_path
                and candidate.startswith(_FRONTEND_DIR)
                and os.path.isfile(candidate)
            ):
                return FileResponse(candidate)
            return FileResponse(_SPA_INDEX)

        logger.info(f"SERVE_FRONTEND enabled; serving SPA from {_FRONTEND_DIR}")
    else:
        logger.warning(f"SERVE_FRONTEND set but no build found at {_FRONTEND_DIR}; static serving skipped")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
