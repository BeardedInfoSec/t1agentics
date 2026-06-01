# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Job Queue Service for T1 Agentics
Provides distributed job queue functionality using PostgreSQL.
Supports multiple queue types, priority, retries, and dead letter handling.
"""

import asyncio
import json
import os
import socket
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable, Awaitable
from dataclasses import dataclass
from enum import Enum
import logging

# NOTE: Verdict imports are done lazily inside functions to avoid circular imports
# Use: from models.verdict import Verdict, validate_verdict, normalize_verdict_safe

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _admin_pool_conn():
    """Get a DB connection with platform admin privileges for background job handlers.

    Job handlers run outside HTTP request context, so RLS blocks all queries.
    This sets app.is_platform_admin to bypass tenant isolation.
    """
    from services.postgres_db import postgres_db

    async with postgres_db.tenant_acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        try:
            yield conn
        finally:
            try:
                await conn.execute("RESET app.is_platform_admin")
            except Exception:
                pass


import re

# Pattern to match LLM special tokens like <|channel|>, <|message|>, <|im_end|>, etc.
LLM_TOKEN_PATTERN = re.compile(r'<\|[^|>]+\|>')


def strip_llm_tokens(text: str) -> str:
    """Remove LLM special tokens from text."""
    if not isinstance(text, str):
        return text
    cleaned = LLM_TOKEN_PATTERN.sub('', text)
    cleaned = re.sub(r'\s+', ' ', cleaned).strip()
    return cleaned


def _parse_llm_json_response(response: str, mode: str, context_id: str = "") -> Optional[Dict[str, Any]]:
    """
    Robustly parse JSON from LLM response with multiple fallback strategies.

    Handles:
    - Markdown code blocks (```json ... ```)
    - Trailing commas in arrays/objects
    - Single quotes instead of double quotes
    - JavaScript-style comments (// and /* */)
    - Truncated JSON (attempts partial recovery)
    - LLM special tokens (<|im_end|>, etc.)

    Args:
        response: Raw LLM response text
        mode: Analysis mode (for logging)
        context_id: Investigation/alert ID (for logging)

    Returns:
        Parsed JSON dict or None if all strategies fail
    """
    if not response:
        return None

    response_text = response.strip()

    # Step 1: Remove LLM special tokens
    response_text = strip_llm_tokens(response_text)

    # Step 2: Extract from markdown code blocks
    if '```json' in response_text:
        json_match = re.search(r'```json\s*([\s\S]*?)\s*```', response_text)
        if json_match:
            response_text = json_match.group(1).strip()
    elif '```' in response_text:
        json_match = re.search(r'```\s*([\s\S]*?)\s*```', response_text)
        if json_match:
            response_text = json_match.group(1).strip()

    # Step 3: Find JSON object boundaries
    # Look for the outermost { } pair
    first_brace = response_text.find('{')
    if first_brace == -1:
        logger.debug(f"[RIGGS_PARSE] No JSON object found in response for {mode}")
        return None

    # Find matching closing brace
    brace_count = 0
    last_brace = -1
    for i, char in enumerate(response_text[first_brace:], first_brace):
        if char == '{':
            brace_count += 1
        elif char == '}':
            brace_count -= 1
            if brace_count == 0:
                last_brace = i
                break

    if last_brace == -1:
        # No matching brace - try to recover truncated JSON
        response_text = response_text[first_brace:]
        # Add closing braces based on open count
        open_braces = response_text.count('{') - response_text.count('}')
        open_brackets = response_text.count('[') - response_text.count(']')
        response_text += ']' * max(0, open_brackets)
        response_text += '}' * max(0, open_braces)
        logger.debug(f"[RIGGS_PARSE] Attempted truncated JSON recovery for {mode}")
    else:
        response_text = response_text[first_brace:last_brace + 1]

    # Step 4: Clean up common JSON issues
    def clean_json(text: str) -> str:
        # Remove JavaScript-style comments
        text = re.sub(r'//.*?(?=\n|$)', '', text)  # Single-line comments
        text = re.sub(r'/\*[\s\S]*?\*/', '', text)  # Multi-line comments

        # Remove trailing commas before ] or }
        text = re.sub(r',\s*}', '}', text)
        text = re.sub(r',\s*]', ']', text)

        # Fix unquoted keys (simple cases only)
        text = re.sub(r'(\{|,)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:', r'\1"\2":', text)

        return text

    # Strategy 1: Direct parse
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Clean and retry
    cleaned = clean_json(response_text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    # Strategy 3: Try with single quotes converted to double quotes
    try:
        # Only convert single quotes that look like string delimiters
        # Be careful not to break apostrophes in text
        single_to_double = re.sub(r"'([^']*)'(?=\s*[:,\]\}])", r'"\1"', cleaned)
        return json.loads(single_to_double)
    except json.JSONDecodeError:
        pass

    # Strategy 4: Find any valid JSON substring
    try:
        # Try progressively smaller substrings
        for end_pos in range(len(cleaned), 10, -10):
            try:
                # Try to find a valid JSON ending
                test_str = cleaned[:end_pos]
                # Balance braces
                open_b = test_str.count('{') - test_str.count('}')
                open_br = test_str.count('[') - test_str.count(']')
                test_str += ']' * max(0, open_br) + '}' * max(0, open_b)
                result = json.loads(test_str)
                logger.info(f"[RIGGS_PARSE] Recovered partial JSON for {mode} ({context_id})")
                return result
            except json.JSONDecodeError:
                continue
    except Exception:
        pass

    # All strategies failed
    logger.warning(f"[RIGGS_PARSE] All JSON parsing strategies failed for {mode} ({context_id})")
    logger.debug(f"[RIGGS_PARSE] First 200 chars: {response_text[:200]}")
    return None


def _extract_essential_headers(headers: Any, body: str = None) -> Dict[str, Any]:
    """
    Extract email headers with SEMANTIC EXTRACTION before truncation.

    ═══════════════════════════════════════════════════════════════════════════════
    DIRECTIVE §6 COMPLIANCE: STRUCTURE OVER TRUNCATION
    ═══════════════════════════════════════════════════════════════════════════════
    Per directive:
    - Blind truncation is PROHIBITED
    - Semantic extraction MUST occur BEFORE truncation
    - T1 receives semantic extraction, not chopped text

    This function:
    1. Extracts ALL semantic security information FIRST
    2. THEN truncates raw headers for display (if needed)
    3. Returns both semantic extraction AND essential raw headers
    """
    if not headers:
        return {'_semantics': {}, '_raw_essential': {}}

    if isinstance(headers, str):
        try:
            headers = json.loads(headers)
        except (json.JSONDecodeError, TypeError):
            return {'_semantics': {}, '_raw_essential': {}}

    if not isinstance(headers, dict):
        return {'_semantics': {}, '_raw_essential': {}}

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 1: SEMANTIC EXTRACTION FIRST (Directive §6)
    # ═══════════════════════════════════════════════════════════════════════════
    # Extract all semantic security information BEFORE any truncation
    try:
        from services.email_semantic_extractor import extract_email_semantics
        semantics = extract_email_semantics(headers, body)
    except ImportError:
        logger.warning("Email semantic extractor not available, using basic extraction")
        semantics = _basic_semantic_extraction(headers)
    except Exception as e:
        logger.error(f"Semantic extraction failed: {e}")
        semantics = _basic_semantic_extraction(headers)

    # ═══════════════════════════════════════════════════════════════════════════
    # STEP 2: ESSENTIAL HEADERS FOR DISPLAY (truncation allowed AFTER extraction)
    # ═══════════════════════════════════════════════════════════════════════════
    essential_keys = {
        'authentication-results', 'received-spf', 'dkim-signature',
        'arc-authentication-results', 'arc-seal', 'arc-message-signature',
        'from', 'return-path', 'reply-to', 'sender',
        'x-originating-ip', 'x-sender-ip', 'x-ms-exchange-organization-authsource',
        'x-forefront-antispam-report', 'x-microsoft-antispam'
    }

    essential_headers = {}
    for key, value in headers.items():
        if key.lower() in essential_keys:
            # Truncation is NOW ALLOWED because semantic extraction already happened
            if isinstance(value, str) and len(value) > 2000:
                value = value[:2000] + '... [TRUNCATED - full data in _semantics]'
            essential_headers[key] = value

    return {
        '_semantics': semantics,  # Full semantic extraction (NEVER truncated)
        '_raw_essential': essential_headers  # Display headers (may be truncated)
    }


def _basic_semantic_extraction(headers: Dict[str, Any]) -> Dict[str, Any]:
    """
    Basic semantic extraction fallback when full extractor unavailable.
    """
    semantics = {
        'spf_result': {'result': 'unknown'},
        'dkim_result': {'result': 'unknown'},
        'dmarc_result': {'result': 'unknown'},
        'arc_valid': {'valid': None},
        'sender_alignment': {'aligned': None},
        'hop_count': 0,
        'extraction_complete': False,
        'fallback': True
    }

    # Basic SPF extraction
    auth_results = str(headers.get('Authentication-Results', headers.get('authentication-results', '')))
    if auth_results:
        if 'spf=pass' in auth_results.lower():
            semantics['spf_result']['result'] = 'pass'
        elif 'spf=fail' in auth_results.lower():
            semantics['spf_result']['result'] = 'fail'

        if 'dkim=pass' in auth_results.lower():
            semantics['dkim_result']['result'] = 'pass'
        elif 'dkim=fail' in auth_results.lower():
            semantics['dkim_result']['result'] = 'fail'

        if 'dmarc=pass' in auth_results.lower():
            semantics['dmarc_result']['result'] = 'pass'
        elif 'dmarc=fail' in auth_results.lower():
            semantics['dmarc_result']['result'] = 'fail'

    # Count Received headers
    for key in headers:
        if key.lower() == 'received':
            if isinstance(headers[key], list):
                semantics['hop_count'] = len(headers[key])
            else:
                semantics['hop_count'] = 1

    return semantics


def sanitize_for_postgres(value: Any) -> Any:
    """
    Sanitize values for PostgreSQL text columns.
    Removes null bytes which PostgreSQL cannot store.
    Also removes LLM special tokens like <|channel|>, <|message|>, etc.
    Converts UUID objects to strings for JSON serialization.
    """
    import uuid as uuid_module
    if isinstance(value, str):
        cleaned = value.replace('\x00', '').replace('\u0000', '')
        cleaned = strip_llm_tokens(cleaned)
        return cleaned
    elif isinstance(value, uuid_module.UUID):
        return str(value)
    elif isinstance(value, dict):
        return {k: sanitize_for_postgres(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [sanitize_for_postgres(item) for item in value]
    return value


class QueueName(str, Enum):
    """Standard queue names for T1 Agentics"""
    ENRICHMENT = "enrichment"      # IOC enrichment jobs
    AGENT = "agent"                # AI agent analysis tasks
    ACTION = "action"              # Response actions
    NOTIFICATION = "notification"  # Alerts, emails, webhooks
    CLEANUP = "cleanup"            # Maintenance tasks


class JobStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD = "dead"


@dataclass
class Job:
    """Represents a job in the queue"""
    id: str
    queue_name: str
    job_type: str
    payload: Dict[str, Any]
    priority: int = 5
    status: str = "pending"
    attempts: int = 0
    max_attempts: int = 3
    scheduled_for: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    locked_by: Optional[str] = None
    error_message: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None


class JobQueueService:
    """
    PostgreSQL-based job queue service.

    Features:
    - Multiple named queues
    - Priority-based processing
    - Automatic retries with exponential backoff
    - Dead letter queue for failed jobs
    - Distributed locking (safe for multiple workers)
    - Job result storage
    """

    def __init__(self, db=None):
        self.db = db
        self.node_id = os.getenv("NODE_ID", f"node-{socket.gethostname()}-{os.getpid()}")
        self._handlers: Dict[str, Callable[[Job], Awaitable[Any]]] = {}
        self._running = False
        self._worker_tasks: List[asyncio.Task] = []

    def set_db(self, db):
        """Set the database connection"""
        self.db = db

    async def enqueue(
        self,
        queue_name: str,
        job_type: str,
        payload: Dict[str, Any],
        priority: int = 5,
        max_attempts: int = 3,
        delay_seconds: int = 0,
        raise_on_full: bool = False
    ) -> Optional[str]:
        """
        Add a job to the queue.

        Args:
            queue_name: Which queue to add to (enrichment, agent, action, notification)
            job_type: Type of job (e.g., 'enrich_ip', 'analyze_alert', 'send_email')
            payload: Job data
            priority: 1 (highest) to 10 (lowest), default 5
            max_attempts: Max retry attempts before moving to dead letter
            delay_seconds: Delay before job becomes available

        Returns:
            Job ID or None if dropped due to backpressure
        """
        if not self.db or not self.db.pool:
            raise RuntimeError("Database not connected")

        scheduled_for = datetime.utcnow()
        if delay_seconds > 0:
            scheduled_for += timedelta(seconds=delay_seconds)

        async with self.db.tenant_acquire() as conn:
            # Backpressure: enforce queue capacity
            try:
                max_pending = _get_queue_limit(queue_name)
                pending_count = await conn.fetchval(
                    """
                    SELECT COUNT(*) FROM job_queue
                    WHERE queue_name = $1 AND status IN ('pending', 'processing')
                    """,
                    queue_name
                )
                if pending_count >= max_pending:
                    message = f"Queue '{queue_name}' at capacity ({pending_count}/{max_pending})"
                    logger.warning(message)
                    if raise_on_full:
                        raise QueueFullError(message)
                    return None
            except QueueFullError:
                raise
            except Exception as e:
                logger.error(f"Queue capacity check failed: {e}")

            job_id = await conn.fetchval("""
                INSERT INTO job_queue (queue_name, job_type, payload, priority, max_attempts, scheduled_for)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id
            """, queue_name, job_type, json.dumps(sanitize_for_postgres(payload)), priority, max_attempts, scheduled_for)

        logger.info(f"Enqueued job {job_id} to {queue_name}: {job_type}")
        return str(job_id)

    async def claim_job(self, queue_name: str, lock_seconds: int = 300) -> Optional[Job]:
        """
        Claim the next available job from a queue.
        Uses PostgreSQL's FOR UPDATE SKIP LOCKED for safe concurrent access.

        Args:
            queue_name: Queue to claim from
            lock_seconds: How long to hold the lock

        Returns:
            Job if one was claimed, None otherwise
        """
        if not self.db or not self.db.pool:
            return None

        async with self.db.tenant_acquire() as conn:
            # Use the stored function for atomic claim
            job_id = await conn.fetchval(
                "SELECT claim_job($1, $2, $3)",
                queue_name, self.node_id, lock_seconds
            )

            if not job_id:
                return None

            # Fetch the full job details
            row = await conn.fetchrow(
                "SELECT * FROM job_queue WHERE id = $1",
                job_id
            )

            if not row:
                return None

            return Job(
                id=str(row['id']),
                queue_name=row['queue_name'],
                job_type=row['job_type'],
                payload=json.loads(row['payload']) if isinstance(row['payload'], str) else row['payload'],
                priority=row['priority'],
                status=row['status'],
                attempts=row['attempts'],
                max_attempts=row['max_attempts'],
                scheduled_for=row['scheduled_for'],
                started_at=row['started_at'],
                completed_at=row['completed_at'],
                locked_by=row['locked_by'],
                error_message=row['error_message'],
                result=json.loads(row['result']) if row['result'] and isinstance(row['result'], str) else row['result'],
                created_at=row['created_at']
            )

    async def complete_job(self, job_id: str, result: Optional[Dict[str, Any]] = None) -> bool:
        """Mark a job as completed successfully"""
        if not self.db or not self.db.pool:
            return False

        async with self.db.tenant_acquire() as conn:
            success = await conn.fetchval(
                "SELECT complete_job($1, $2)",
                job_id,
                json.dumps(sanitize_for_postgres(result)) if result else None
            )

        logger.info(f"Completed job {job_id}")
        return success

    async def fail_job(self, job_id: str, error_message: str) -> bool:
        """Mark a job as failed (will retry or move to dead letter)"""
        if not self.db or not self.db.pool:
            return False

        async with self.db.tenant_acquire() as conn:
            success = await conn.fetchval(
                "SELECT fail_job($1, $2)",
                job_id, sanitize_for_postgres(error_message)
            )

        logger.warning(f"Failed job {job_id}: {error_message}")
        return success

    async def get_queue_stats(self, queue_name: Optional[str] = None) -> Dict[str, Any]:
        """Get statistics for queues"""
        if not self.db or not self.db.pool:
            return {}

        async with self.db.tenant_acquire() as conn:
            if queue_name:
                rows = await conn.fetch("""
                    SELECT status, COUNT(*) as count
                    FROM job_queue
                    WHERE queue_name = $1
                    GROUP BY status
                """, queue_name)

                stats = {queue_name: {row['status']: row['count'] for row in rows}}
            else:
                rows = await conn.fetch("""
                    SELECT queue_name, status, COUNT(*) as count
                    FROM job_queue
                    GROUP BY queue_name, status
                    ORDER BY queue_name, status
                """)

                stats = {}
                for row in rows:
                    if row['queue_name'] not in stats:
                        stats[row['queue_name']] = {}
                    stats[row['queue_name']][row['status']] = row['count']

        return stats

    async def get_dead_letter_jobs(self, queue_name: Optional[str] = None, limit: int = 100) -> List[Job]:
        """Get jobs that have failed all retry attempts"""
        if not self.db or not self.db.pool:
            return []

        async with self.db.tenant_acquire() as conn:
            if queue_name:
                rows = await conn.fetch("""
                    SELECT * FROM job_queue
                    WHERE status = 'dead' AND queue_name = $1
                    ORDER BY completed_at DESC
                    LIMIT $2
                """, queue_name, limit)
            else:
                rows = await conn.fetch("""
                    SELECT * FROM job_queue
                    WHERE status = 'dead'
                    ORDER BY completed_at DESC
                    LIMIT $1
                """, limit)

        return [
            Job(
                id=str(row['id']),
                queue_name=row['queue_name'],
                job_type=row['job_type'],
                payload=json.loads(row['payload']) if isinstance(row['payload'], str) else row['payload'],
                priority=row['priority'],
                status=row['status'],
                attempts=row['attempts'],
                max_attempts=row['max_attempts'],
                error_message=row['error_message'],
                created_at=row['created_at'],
                completed_at=row['completed_at']
            )
            for row in rows
        ]

    async def retry_dead_job(self, job_id: str) -> bool:
        """Retry a dead letter job"""
        if not self.db or not self.db.pool:
            return False

        async with self.db.tenant_acquire() as conn:
            result = await conn.execute("""
                UPDATE job_queue
                SET status = 'pending',
                    attempts = 0,
                    scheduled_for = CURRENT_TIMESTAMP,
                    error_message = NULL,
                    locked_by = NULL,
                    locked_until = NULL
                WHERE id = $1 AND status = 'dead'
            """, job_id)

        return "UPDATE 1" in result

    async def purge_old_jobs(self, days: int = 30) -> int:
        """Remove completed/dead jobs older than specified days"""
        if not self.db or not self.db.pool:
            return 0

        async with self.db.tenant_acquire() as conn:
            result = await conn.execute("""
                DELETE FROM job_queue
                WHERE status IN ('completed', 'dead')
                  AND completed_at < CURRENT_TIMESTAMP - ($1 || ' days')::INTERVAL
            """, days)

        count = int(result.split()[-1]) if result else 0
        logger.info(f"Purged {count} old jobs")
        return count

    # =========================================================================
    # Worker Methods
    # =========================================================================

    def register_handler(self, job_type: str, handler: Callable[[Job], Awaitable[Any]]):
        """Register a handler function for a job type"""
        self._handlers[job_type] = handler
        logger.info(f"Registered handler for job type: {job_type}")

    async def process_job(self, job: Job) -> bool:
        """Process a single job using registered handler"""
        handler = self._handlers.get(job.job_type)

        if not handler:
            logger.error(f"No handler registered for job type: {job.job_type}")
            await self.fail_job(job.id, f"No handler for job type: {job.job_type}")
            return False

        try:
            result = await handler(job)
            await self.complete_job(job.id, {"result": result} if result else None)
            return True
        except Exception as e:
            logger.exception(f"Error processing job {job.id}: {e}")
            await self.fail_job(job.id, str(e))
            return False

    async def worker_loop(self, queue_name: str, poll_interval: float = 1.0):
        """
        Worker loop that continuously processes jobs from a queue.

        Args:
            queue_name: Queue to process
            poll_interval: Seconds to wait between poll attempts when queue is empty
        """
        from services.postgres_db import set_platform_admin_mode

        logger.info(f"Starting worker for queue: {queue_name}")

        # Enable platform admin mode for the entire worker lifecycle.
        # Workers run in background tasks without HTTP request context,
        # so RLS would block claim_job / complete_job / fail_job calls.
        # Individual job handlers also set this, but we need it for the
        # queue infrastructure operations (claim, complete, fail) too.
        set_platform_admin_mode(True)

        try:
            while self._running:
                try:
                    job = await self.claim_job(queue_name)

                    if job:
                        await self.process_job(job)
                    else:
                        # No job available, wait before polling again
                        await asyncio.sleep(poll_interval)

                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.exception(f"Worker error for {queue_name}: {e}")
                    await asyncio.sleep(poll_interval)
        finally:
            set_platform_admin_mode(False)
            logger.info(f"Worker stopped for queue: {queue_name}")

    async def start_workers(self, queues: List[str], workers_per_queue: int = 1):
        """Start worker tasks for specified queues"""
        self._running = True

        for queue_name in queues:
            for i in range(workers_per_queue):
                task = asyncio.create_task(self.worker_loop(queue_name))
                self._worker_tasks.append(task)
                logger.info(f"Started worker {i+1}/{workers_per_queue} for queue: {queue_name}")

    async def stop_workers(self, timeout: float = 30.0):
        """Stop all worker tasks gracefully"""
        self._running = False

        if self._worker_tasks:
            logger.info(f"Stopping {len(self._worker_tasks)} workers...")

            # Wait for tasks to complete or timeout
            done, pending = await asyncio.wait(
                self._worker_tasks,
                timeout=timeout
            )

            # Cancel any still-running tasks
            for task in pending:
                task.cancel()

            self._worker_tasks.clear()
            logger.info("All workers stopped")


# Singleton instance
_job_queue_service: Optional[JobQueueService] = None
_job_queue_service_lock = asyncio.Lock()


async def get_job_queue_service() -> JobQueueService:
    """Get the global job queue service instance (async-safe)."""
    global _job_queue_service
    if _job_queue_service is None:
        async with _job_queue_service_lock:
            if _job_queue_service is None:
                _job_queue_service = JobQueueService()
    return _job_queue_service


async def register_agent_handlers(job_queue: JobQueueService):
    """Register handlers for agent-related job types"""

    async def handle_agent_analyze_alert(job: Job) -> Dict[str, Any]:
        """Handle agent alert analysis job"""
        from services.agent_service import get_agent_service
        from services.agent_executor import get_agent_executor
        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)

        service = get_agent_service()
        executor = get_agent_executor()

        agent_id = job.payload.get('agent_id')
        alert_id = job.payload.get('alert_id')
        alert_data = job.payload.get('alert_data', {})

        # Get the agent
        agent = await service.get_agent(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")
        if not agent.get('enabled', False):
            raise ValueError(f"Agent is disabled: {agent_id}")

        # Create execution record
        execution = await service.create_execution(
            agent_id=agent_id,
            trigger_type='alert',  # Using 'alert' - allowed by DB constraint
            trigger_source_id=alert_id,
            trigger_source_type='alert'
        )

        # Run the agent
        result = await executor.run_agent(
            agent=agent,
            execution_id=execution['execution_id'],
            input_data={
                "trigger_type": "alert_analysis",
                "trigger_source_id": alert_id,
                "trigger_source_type": "alert",
                "alert": alert_data
            }
        )

        return {
            "execution_id": execution['execution_id'],
            "agent_id": agent_id,
            "alert_id": alert_id,
            "result": result
        }

    def _truncate_raw_event_for_prompt(raw_event: Dict[str, Any], max_total_chars: int = 4000) -> Dict[str, Any]:
        """
        Truncate raw_event to fit within LLM context window.

        The Qwen 14B model has 8192 token context. With ~4 chars/token, we need
        to keep raw_event under ~4000 chars to leave room for system prompt,
        instructions, and output tokens.

        Strategy:
        - Preserve key metadata fields (sender, subject, etc.)
        - Truncate large text fields (body, description, etc.)
        - Remove redundant nested data
        """
        if not raw_event or not isinstance(raw_event, dict):
            return raw_event or {}

        # Fields to preserve in full (small metadata)
        preserve_fields = {
            'sender', 'from', 'from_address', 'to', 'recipient', 'subject',
            'original_subject', 'reporter_email', 'source', 'category',
            'severity', 'alert_type', 'message_id', 'report_id', 'timestamp',
            'received_at', 'status'
        }

        # Fields to truncate (potentially large text)
        truncate_fields = {
            'body': 1500,
            'body_text': 1500,
            'body_preview': 800,
            'description': 500,
            'raw_body': 1000,
            'email_body': 1500,
            'body_html': 0,  # Skip HTML entirely
            'headers': 500,   # Headers can be huge
            'email_headers': 500,
        }

        # Fields to skip entirely (redundant or too large)
        skip_fields = {
            '_extracted', 'attachments', 'email_attachments',
            'raw_headers', 'full_headers', 'original_message',
            'all_headers', 'iocs', 'received_chain'  # These are huge and redundant
        }

        truncated = {}
        current_size = 0

        # First pass: add preserved and truncated fields
        for key, value in raw_event.items():
            if key in skip_fields:
                continue

            if key in preserve_fields:
                str_val = str(value) if value else ''
                if len(str_val) < 500:  # Preserve if small
                    truncated[key] = value
                    current_size += len(str_val)
            elif key in truncate_fields:
                max_len = truncate_fields[key]
                if max_len == 0:
                    continue  # Skip entirely
                if isinstance(value, str) and len(value) > max_len:
                    truncated[key] = value[:max_len] + f'... [truncated {len(value) - max_len} chars]'
                else:
                    truncated[key] = value
                current_size += min(len(str(value or '')), max_len)
            else:
                # Unknown field - include if small
                str_val = str(value) if value else ''
                if len(str_val) < 200:
                    truncated[key] = value
                    current_size += len(str_val)

            # Stop if we're getting too large
            if current_size > max_total_chars:
                truncated['_truncation_notice'] = f'raw_event truncated to fit context window (original ~{len(str(raw_event))} chars)'
                break

        return truncated

    async def handle_agent_auto_triage(job: Job) -> Dict[str, Any]:
        """Handle automatic alert triage by finding and running appropriate agents"""
        logger.warning(f"[AUTO_TRIAGE_ENTRY] job_id={job.id}, payload={job.payload}")
        from services.agent_service import get_agent_service
        from services.agent_executor import get_agent_executor
        from services.postgres_db import postgres_db, set_platform_admin_mode

        # Enable platform admin mode for this entire job context.
        # This makes ALL pool.acquire() calls set app.is_platform_admin='true',
        # so agent_executor, agent_service, etc. can bypass tenant RLS.
        set_platform_admin_mode(True)

        service = get_agent_service()
        executor = get_agent_executor()

        alert_id = job.payload.get('alert_id')
        phishing_report_id = job.payload.get('phishing_report_id')

        # Get the alert and check for attachments
        phishing_email_content = None
        async with _admin_pool_conn() as conn:
            # Try by alert_id (varchar) first, then by id (UUID) if that fails
            row = await conn.fetchrow('SELECT * FROM alerts WHERE alert_id = $1', str(alert_id))
            if not row:
                # Try by UUID
                try:
                    import uuid as uuid_module
                    uuid_obj = uuid_module.UUID(str(alert_id))
                    row = await conn.fetchrow('SELECT * FROM alerts WHERE id = $1', uuid_obj)
                except (ValueError, TypeError):
                    pass
            if not row:
                raise ValueError(f"Alert not found: {alert_id}")

            alert = dict(row)
            if isinstance(alert.get('raw_data'), str):
                alert['raw_data'] = json.loads(alert['raw_data'])
            if isinstance(alert.get('raw_event'), str):
                try:
                    alert['raw_event'] = json.loads(alert['raw_event'])
                except (json.JSONDecodeError, TypeError):
                    alert['raw_event'] = {}

            # =====================================================
            # CRITICAL: Check if alert already has a confident T1 verdict
            # This prevents the job queue from overwriting verdicts
            # set by auto_enrichment -> ai_triage_service path
            # =====================================================
            existing_verdict = alert.get('ai_verdict')
            existing_confidence = alert.get('ai_confidence') or 0
            is_manual_trigger = job.payload.get('manual_trigger', False)

            # Skip if we already have a confident malicious/true_positive verdict
            # UNLESS this is a manual trigger (analyst explicitly requested re-analysis)
            if not is_manual_trigger and existing_verdict and existing_confidence >= 0.80:
                if str(existing_verdict).lower() in ['malicious', 'true_positive']:
                    logger.info(
                        f"[T1_SKIP] Alert {alert_id}: Already has confident verdict "
                        f"'{existing_verdict}' ({existing_confidence:.0%}) - skipping duplicate T1 run"
                    )
                    return {
                        "status": "skipped",
                        "reason": "confident_verdict_exists",
                        "alert_id": alert_id,
                        "existing_verdict": existing_verdict,
                        "existing_confidence": existing_confidence
                    }
            elif is_manual_trigger and existing_verdict:
                logger.info(
                    f"[MANUAL_RERUN] Alert {alert_id}: Bypassing skip - manual re-analysis requested "
                    f"(prior verdict: '{existing_verdict}')"
                )

            # Check for file attachments
            attachment_count = await conn.fetchval(
                'SELECT COUNT(*) FROM alert_attachments WHERE alert_id = $1 AND deleted_at IS NULL',
                alert.get('alert_id')
            )

            # =====================================================
            # PHISHING EMAIL CONTENT: Fetch full email body if this
            # is a phishing report analysis
            # =====================================================
            # Check for phishing report ID from multiple sources:
            # 1. Direct phishing_report_id in job payload
            # 2. report_id in alert's raw_event (e.g., PHR-80716BF8)
            # 3. phishing_report_id in alert's raw_event
            if not phishing_report_id:
                raw_event = alert.get('raw_event') or {}
                if isinstance(raw_event, str):
                    try:
                        raw_event = json.loads(raw_event)
                    except (json.JSONDecodeError, TypeError):
                        raw_event = {}
                raw_event = raw_event or {}
                phishing_report_id = raw_event.get('phishing_report_id') or raw_event.get('report_id')

            if phishing_report_id:
                try:
                    import uuid as uuid_module

                    # Handle both UUID format and report_id format (e.g., PHR-80716BF8)
                    if phishing_report_id.startswith('PHR-'):
                        # Look up by report_id string
                        phishing_row = await conn.fetchrow("""
                            SELECT
                                pr.id, pr.report_id, pr.reporter_email, pr.reported_from,
                                pr.reported_subject, pr.reported_body_preview,
                                pr.message_id as pr_message_id,
                                pr.reported_received_at,
                                pr.extracted_urls, pr.extracted_domains, pr.extracted_ips,
                                pr.extracted_emails, pr.extracted_hashes,
                                pr.attachment_count as pr_attachment_count,
                                pr.attachment_hashes, pr.severity, pr.status,
                                ie.message_id as email_message_id,
                                ie.body_text as email_body_text,
                                ie.body_html as email_body_html,
                                ie.headers as email_headers,
                                ie.from_address as original_sender_address,
                                ie.from_name as original_sender_name,
                                ie.to_addresses as email_to_addresses,
                                ie.cc_addresses as email_cc_addresses,
                                ie.in_reply_to as email_in_reply_to,
                                ie.references_header as email_references,
                                ie.received_at as email_received_at,
                                ie.attachments as email_attachments
                            FROM phishing_reports pr
                            LEFT JOIN inbound_email_queue ie ON pr.inbound_email_id = ie.id
                            WHERE pr.report_id = $1
                        """, phishing_report_id)
                    else:
                        # Try as UUID
                        phishing_uuid = uuid_module.UUID(phishing_report_id) if isinstance(phishing_report_id, str) else phishing_report_id

                        # Fetch phishing report with linked inbound email for full content
                        phishing_row = await conn.fetchrow("""
                        SELECT
                            pr.id, pr.report_id, pr.reporter_email, pr.reported_from,
                            pr.reported_subject, pr.reported_body_preview,
                            pr.message_id as pr_message_id,
                            pr.reported_received_at,
                            pr.extracted_urls, pr.extracted_domains, pr.extracted_ips,
                            pr.extracted_emails, pr.extracted_hashes,
                            pr.attachment_count as pr_attachment_count,
                            pr.attachment_hashes, pr.severity, pr.status,
                            ie.message_id as email_message_id,
                            ie.body_text as email_body_text,
                            ie.body_html as email_body_html,
                            ie.headers as email_headers,
                            ie.from_address as original_sender_address,
                            ie.from_name as original_sender_name,
                            ie.to_addresses as email_to_addresses,
                            ie.cc_addresses as email_cc_addresses,
                            ie.in_reply_to as email_in_reply_to,
                            ie.references_header as email_references,
                            ie.received_at as email_received_at,
                            ie.attachments as email_attachments
                        FROM phishing_reports pr
                        LEFT JOIN inbound_email_queue ie ON pr.inbound_email_id = ie.id
                        WHERE pr.id = $1
                    """, phishing_uuid)

                    if phishing_row:
                        phishing_data = dict(phishing_row)

                        # Build comprehensive phishing content for agent analysis
                        # Use full body_text if available, otherwise fallback to preview
                        full_email_body = phishing_data.get('email_body_text') or phishing_data.get('reported_body_preview') or ''

                        # CRITICAL: Aggressive truncation for 8192 token LLM context
                        # ~4 chars per token means we have ~2000 chars budget for email body
                        # (after accounting for system prompt, metadata, JSON structure)
                        MAX_EMAIL_BODY_CHARS = 2000  # ~500 tokens - reduced to prevent context overflow
                        total_body_length = len(full_email_body)
                        if total_body_length > MAX_EMAIL_BODY_CHARS:
                            # Show first portion with truncation notice
                            full_email_body = full_email_body[:MAX_EMAIL_BODY_CHARS] + f"\n\n[TRUNCATED - Showing first {MAX_EMAIL_BODY_CHARS} of {total_body_length} chars. Key indicators should be visible above.]"

                        # Get message ID from either source
                        message_id = phishing_data.get('email_message_id') or phishing_data.get('pr_message_id')

                        # Format received timestamp
                        received_at = phishing_data.get('email_received_at') or phishing_data.get('reported_received_at')
                        received_at_str = received_at.isoformat() if received_at else None

                        phishing_email_content = {
                            # Identifiers
                            "report_id": phishing_data.get('report_id'),
                            "message_id": message_id,

                            # Sender/Recipient metadata
                            "reporter_email": phishing_data.get('reporter_email'),
                            "original_sender": phishing_data.get('reported_from') or phishing_data.get('original_sender_address'),
                            "original_sender_name": phishing_data.get('original_sender_name'),
                            "to_addresses": phishing_data.get('email_to_addresses') or [],
                            "cc_addresses": phishing_data.get('email_cc_addresses') or [],

                            # Email content
                            "original_subject": phishing_data.get('reported_subject'),
                            "email_body": full_email_body,
                            # Skip HTML - text body is sufficient and saves tokens
                            "email_body_html": None,  # Removed - text body has the content

                            # ONLY essential headers for authentication analysis (SPF, DKIM, DMARC)
                            # Full headers can be 50KB+ and blow out the LLM context window
                            "email_headers": _extract_essential_headers(phishing_data.get('email_headers')),

                            # Threading metadata
                            "in_reply_to": phishing_data.get('email_in_reply_to'),
                            "references": phishing_data.get('email_references'),
                            "received_at": received_at_str,

                            # Pre-extracted IOCs
                            "extracted_iocs": {
                                "urls": phishing_data.get('extracted_urls') or [],
                                "domains": phishing_data.get('extracted_domains') or [],
                                "ips": phishing_data.get('extracted_ips') or [],
                                "emails": phishing_data.get('extracted_emails') or [],
                                "hashes": phishing_data.get('extracted_hashes') or []
                            },

                            # Attachments
                            "attachment_count": phishing_data.get('pr_attachment_count', 0),
                            "attachment_hashes": phishing_data.get('attachment_hashes') or [],
                            "email_attachments": phishing_data.get('email_attachments')
                        }
                        logger.info(f"Fetched phishing email content for report {phishing_report_id}: {len(full_email_body)} chars")
                except Exception as phishing_err:
                    logger.warning(f"Failed to fetch phishing report content: {phishing_err}")

        # =====================================================
        # PHASE 9.4: Asset Enrichment for Tier 1 Triage
        # =====================================================
        asset_context = None
        asset_prompt_addition = ""
        try:
            from services.asset_investigation_enrichment import get_asset_enrichment_service
            from services.asset_service import get_asset_service

            enrichment_service = get_asset_enrichment_service()
            enrichment_service.set_db(postgres_db)

            asset_svc = get_asset_service()
            asset_svc.set_db(postgres_db)
            enrichment_service.set_asset_service(asset_svc)

            # Enrich with asset data from alert
            alert_data_for_enrichment = {
                **alert.get('raw_data', {}),
                'title': alert.get('title'),
                'description': alert.get('description')
            }
            enrichment_result = await enrichment_service.enrich_alert(alert_data_for_enrichment)

            if enrichment_result.get('matched_assets'):
                asset_context = enrichment_result['asset_context']
                asset_prompt_addition = enrichment_service.get_agent_asset_context(
                    enrichment_result['matched_assets']
                )
                logger.info(f"Asset enrichment: Found {len(enrichment_result['matched_assets'])} assets for alert {alert_id}")
        except Exception as asset_err:
            logger.warning(f"Asset enrichment failed for alert {alert_id}: {asset_err}")

        # =====================================================
        # DETERMINISTIC PRE-CLASSIFIER: Handle clear-cut alerts
        # without calling the LLM agent
        # =====================================================
        try:
            from services.deterministic_classifier import get_deterministic_classifier

            classifier = get_deterministic_classifier()
            classifier.set_db(postgres_db)

            # Get enrichment data from alert's raw_event
            raw_event = alert.get('raw_event') or {}
            if isinstance(raw_event, str):
                try:
                    raw_event = json.loads(raw_event)
                except (json.JSONDecodeError, TypeError):
                    raw_event = {}
            raw_event = raw_event or {}

            enrichment_data = (raw_event.get('_extracted') or {}).get('enrichment', {})

            # Build alert data for classifier
            alert_data_for_classifier = {
                'title': alert.get('title'),
                'description': alert.get('description'),
                'raw_event': raw_event,
                'severity': alert.get('severity')
            }

            # Run deterministic classification
            deterministic_result = await classifier.classify(
                alert_data=alert_data_for_classifier,
                enrichment_data=enrichment_data,
                phishing_email_content=phishing_email_content
            )

            if deterministic_result and deterministic_result.get('skip_llm'):
                # Deterministic classification was confident - skip LLM entirely
                logger.info(f"[DETERMINISTIC] Alert {alert_id}: {deterministic_result['verdict']} "
                           f"({deterministic_result['confidence']:.0%}) via {deterministic_result['classification_method']}")

                # Update the alert with the verdict
                async with _admin_pool_conn() as conn:
                    verdict = deterministic_result['verdict']
                    confidence = deterministic_result['confidence']
                    summary = deterministic_result['summary']

                    if deterministic_result.get('should_auto_close'):
                        # Auto-close the alert
                        await conn.execute('''
                            UPDATE alerts
                            SET ai_verdict = $1, ai_confidence = $2, ai_summary = $3,
                                status = 'closed', resolution = $4,
                                resolved_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                            WHERE id = $5
                        ''',
                            verdict, confidence, summary,
                            f"Auto-closed by deterministic classifier: {deterministic_result['classification_method']}",
                            alert.get('id')
                        )
                        logger.info(f"[DETERMINISTIC] Alert {alert_id}: AUTO-CLOSED")
                    else:
                        # Just update the verdict
                        await conn.execute('''
                            UPDATE alerts
                            SET ai_verdict = $1, ai_confidence = $2, ai_summary = $3,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = $4
                        ''', verdict, confidence, summary, alert.get('id'))

                    # Create investigation if needed - but ONLY if alert doesn't already have one
                    # (entity correlation may have already linked the alert)
                    if deterministic_result.get('should_create_investigation'):
                        # Check if alert already has an investigation (from entity correlation)
                        existing_inv = await conn.fetchval(
                            'SELECT investigation_id FROM alerts WHERE id = $1',
                            alert.get('id')
                        )

                        if existing_inv:
                            logger.info(f"[DETERMINISTIC] Alert {alert_id} already linked to investigation - skipping creation")
                        else:
                            import secrets
                            inv_id = f"INV-{secrets.token_hex(4).upper()}"

                            # Link investigation to alert
                            await conn.execute(
                                'UPDATE alerts SET investigation_id = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
                                inv_id, alert.get('id')
                            )

                            # Create the investigation
                            # OPTIMIZED: Go directly to NEEDS_REVIEW, skip T2
                            await postgres_db.create_investigation({
                                'investigation_id': inv_id,
                                'alert_id': alert.get('alert_id'),
                                'alert_title': alert.get('title'),
                                'summary': summary,
                                'state': 'NEEDS_REVIEW',  # Skip T2, Riggs does deep analysis when analyst engages
                                'disposition': 'MALICIOUS_ACTIVITY',
                                'priority': 'P2',
                                'severity': alert.get('severity', 'high'),
                                'confidence': confidence,
                                'investigation_data': {
                                    'trigger': 'deterministic_classifier',
                                    'classification_method': deterministic_result['classification_method'],
                                    'key_findings': deterministic_result.get('key_findings', []),
                                    'tier1_analysis': {
                                        'verdict': verdict,
                                        'confidence': confidence,
                                        'summary': summary,
                                        'source': 'deterministic_classifier'
                                    }
                                },
                                'raw_alert': raw_event
                            })
                            logger.info(f"[DETERMINISTIC] Created investigation {inv_id} for alert {alert_id}")

                return {
                    "status": "deterministic_classification",
                    "alert_id": alert_id,
                    "verdict": deterministic_result['verdict'],
                    "confidence": deterministic_result['confidence'],
                    "classification_method": deterministic_result['classification_method'],
                    "skip_llm": True,
                    "result": deterministic_result
                }

        except Exception as classifier_err:
            logger.warning(f"Deterministic classifier failed for alert {alert_id}: {classifier_err}")
            # Continue with normal LLM-based triage on error

        # Find enabled Tier 1 triage agents
        agents = await service.list_agents(tier=1, enabled_only=True)

        if not agents:
            logger.warning(f"No enabled Tier 1 agents found for alert {alert_id}")
            return {"status": "no_agents", "alert_id": alert_id}

        # Use the first available agent (could be enhanced to match by focus area)
        agent = agents[0]

        # Create execution record
        execution = await service.create_execution(
            agent_id=str(agent['id']),
            trigger_type='alert',  # Using 'alert' - allowed by DB constraint
            trigger_source_id=alert_id,
            trigger_source_type='alert'
        )

        # Run the agent
        input_data = {
            "trigger_type": "auto_triage",
            "trigger_source_id": alert_id,
            "trigger_source_type": "alert",
            "alert": {
                "id": str(alert.get('id')),
                "alert_id": alert.get('alert_id'),
                "title": alert.get('title'),
                "description": alert.get('description'),
                "severity": alert.get('severity'),
                "status": alert.get('status'),
                "source_type": alert.get('source_type'),
                "category": alert.get('category'),
                "source_tool": alert.get('source_tool'),
                "raw_data": alert.get('raw_data', {}),
                # CRITICAL: Truncate raw_event to prevent exceeding LLM context window
                # Full phishing emails can be 20-30KB which blows out 8192 token limit
                "raw_event": _truncate_raw_event_for_prompt(alert.get('raw_event', {})),
                "has_attachments": attachment_count > 0,
                "attachment_count": attachment_count
            }
        }

        # Add asset context if available (Phase 9.4)
        if asset_context:
            input_data["asset_context"] = asset_context
            input_data["asset_summary"] = asset_prompt_addition

        # Add phishing email content if available
        if phishing_email_content:
            input_data["phishing_email"] = phishing_email_content
            input_data["is_phishing_report"] = True

        # Add instructions if there are attachments
        instructions = []

        # Special instructions for phishing email analysis
        if phishing_email_content:
            # Build header summary for agent
            headers = phishing_email_content.get('email_headers') or {}
            # Handle case where headers might be a JSON string instead of dict
            if isinstance(headers, str):
                try:
                    headers = json.loads(headers)
                except (json.JSONDecodeError, TypeError):
                    headers = {}
            header_summary = ""
            if headers and isinstance(headers, dict):
                # Extract key authentication headers
                auth_headers = []
                for key in ['Authentication-Results', 'Received-SPF', 'DKIM-Signature', 'ARC-Authentication-Results']:
                    if key.lower() in {k.lower(): v for k, v in headers.items()}:
                        auth_headers.append(key)
                if auth_headers:
                    header_summary = f"Authentication headers present: {', '.join(auth_headers)}"
                else:
                    header_summary = "No authentication headers found (suspicious)"

            instructions.append(f"""PHISHING EMAIL ANALYSIS:
This is a user-reported phishing email. You have access to the FULL email content, headers, and metadata.

**Email Metadata:**
- Message-ID: {phishing_email_content.get('message_id', 'Unknown')}
- From: {phishing_email_content.get('original_sender', 'Unknown')} ({phishing_email_content.get('original_sender_name', 'No display name')})
- To: {', '.join(phishing_email_content.get('to_addresses', [])) or 'Unknown'}
- CC: {', '.join(phishing_email_content.get('cc_addresses', [])) or 'None'}
- Subject: {phishing_email_content.get('original_subject', 'No subject')}
- Received: {phishing_email_content.get('received_at', 'Unknown')}
- In-Reply-To: {phishing_email_content.get('in_reply_to', 'None (new thread)')}

**Reporter:** {phishing_email_content.get('reporter_email', 'Unknown')}

**Email Headers:** Available in phishing_email.email_headers (check for SPF, DKIM, DMARC results)
{header_summary}

**Pre-Extracted IOCs (already parsed from email):**
- URLs: {len(phishing_email_content.get('extracted_iocs', {}).get('urls', []))} found
- Domains: {len(phishing_email_content.get('extracted_iocs', {}).get('domains', []))} found
- IPs: {len(phishing_email_content.get('extracted_iocs', {}).get('ips', []))} found
- Email Addresses: {len(phishing_email_content.get('extracted_iocs', {}).get('emails', []))} found
- Hashes: {len(phishing_email_content.get('extracted_iocs', {}).get('hashes', []))} found

**Full Email Body (analyze for phishing indicators):**
```
{(phishing_email_content.get('email_body', '') or '')[:2000]}{'... [truncated for context window]' if len(phishing_email_content.get('email_body', '') or '') > 2000 else ''}
```

ANALYSIS TASKS:
1. Analyze the email body for phishing indicators (urgency, threats, impersonation, suspicious requests)
2. Check email authentication results in headers (SPF, DKIM, DMARC) - spoofed emails often fail these
3. Analyze sender domain - does it match the claimed brand? Look for typosquatting
4. Check all extracted URLs/domains against threat intelligence using enrich_indicator tool
5. Look for brand impersonation, credential harvesting attempts, or malware delivery
6. Assess attachment hashes if present
7. Provide a clear verdict with confidence level""")

        if attachment_count > 0:
            instructions.append("IMPORTANT: This alert has file attachments. Use list_alert_attachments and analyze_file_attachment tools to analyze them.")
        if asset_prompt_addition:
            instructions.append(asset_prompt_addition)
        if instructions:
            input_data["instructions"] = "\n\n".join(instructions)

        # =====================================================
        # DECISION-ONLY MODE: Build pre-digested context for T1
        # This removes the need for tools by providing all enrichment
        # results directly in a human-readable format
        # =====================================================
        use_decision_only = True  # Enable decision-only mode for T1

        if use_decision_only:
            try:
                from services.context_stratification import build_predigested_t1_context
                from services.sender_trust_service import get_sender_trust_service

                # Get trusted sender info
                trusted_sender_info = None
                sender_email = (
                    phishing_email_content.get('original_sender', '') if phishing_email_content
                    else raw_event.get('sender', '') or raw_event.get('from', '')
                )

                if sender_email:
                    try:
                        trust_service = get_sender_trust_service()
                        ts_result = await trust_service.check_trusted_sender(sender_email)
                        pt_result = await trust_service.check_phishing_test(sender_email, alert.get('title', ''))

                        trusted_sender_info = {
                            'is_trusted_sender': ts_result.is_trusted if ts_result else False,
                            'trusted_sender_result': {
                                'trust_level': ts_result.trust_level if ts_result else None,
                                'organization': ts_result.organization if ts_result else None,
                                'category': ts_result.category if ts_result else None
                            } if ts_result and ts_result.is_trusted else None,
                            'is_phishing_test': pt_result.is_phishing_test if pt_result else False,
                            'phishing_test_result': {
                                'test_name': pt_result.test_name if pt_result else None,
                                'vendor': pt_result.vendor if pt_result else None
                            } if pt_result and pt_result.is_phishing_test else None
                        }
                    except Exception as ts_err:
                        logger.debug(f"Trusted sender check failed: {ts_err}")

                # Build pre-digested context
                predigested_context = build_predigested_t1_context(
                    alert=input_data["alert"],
                    enrichment_data=enrichment_data,
                    phishing_email_content=phishing_email_content,
                    trusted_sender_info=trusted_sender_info
                )

                # Add to input_data for the executor
                input_data["predigested_context"] = predigested_context
                input_data["decision_only_mode"] = True

                logger.info(f"[T1_DECISION_ONLY] Built pre-digested context for alert {alert_id}: {len(predigested_context)} chars")

            except Exception as ctx_err:
                logger.warning(f"Failed to build pre-digested context, using standard mode: {ctx_err}")
                use_decision_only = False

        result = await executor.run_agent(
            agent=agent,
            execution_id=execution['execution_id'],
            input_data=input_data,
            decision_only=use_decision_only
        )

        # =====================================================
        # STORE AI TRIAGE RESULT INCLUDING DECODED IOCs
        # =====================================================
        try:
            if isinstance(result, dict):
                ai_triage_data = {
                    'verdict': result.get('verdict'),
                    'confidence': result.get('confidence'),
                    'summary': result.get('summary'),
                    'key_findings': result.get('key_findings', []),
                    'decoded_iocs': result.get('decoded_iocs', {}),
                    'recommended_actions': result.get('recommended_actions', []),
                    'threat_type': result.get('threat_type'),
                    'timestamp': datetime.utcnow().isoformat()
                }

                # Update alert's raw_event with AI triage data
                async with _admin_pool_conn() as conn:
                    alert_row = await conn.fetchrow(
                        'SELECT raw_event FROM alerts WHERE alert_id = $1',
                        alert_id
                    )
                    if alert_row:
                        raw_event_data = alert_row['raw_event']
                        if isinstance(raw_event_data, str):
                            raw_event_data = json.loads(raw_event_data)
                        if '_extracted' not in raw_event_data:
                            raw_event_data['_extracted'] = {}
                        raw_event_data['_extracted']['ai_triage'] = ai_triage_data

                        # Update raw_event AND ai_verdict columns
                        verdict = ai_triage_data.get('verdict')
                        confidence = ai_triage_data.get('confidence')
                        # Normalize confidence to 0-100 scale if it's 0-1
                        if confidence and confidence <= 1.0:
                            confidence = int(confidence * 100)
                        summary = ai_triage_data.get('summary', '')[:500] if ai_triage_data.get('summary') else None

                        await conn.execute('''
                            UPDATE alerts
                            SET raw_event = $1,
                                ai_verdict = $2,
                                ai_confidence = $3,
                                ai_summary = $4,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE alert_id = $5
                        ''', json.dumps(raw_event_data, default=str), verdict, confidence, summary, alert_id)
                        logger.info(f"Stored AI triage result for alert {alert_id}: verdict={verdict}, confidence={confidence}, decoded_iocs={bool(ai_triage_data.get('decoded_iocs'))}")
        except Exception as store_err:
            logger.warning(f"Failed to store AI triage result: {store_err}")

        # =====================================================
        # TELEMETRY: Record Tier 1 verdict if linked to investigation
        # =====================================================
        try:
            # Extract verdict data from result
            # NOTE: Confidence should be 0.0-1.0 scale (decimal)
            verdict = 'needs_review'
            confidence = 0.5
            if isinstance(result, dict):
                verdict = result.get('verdict', result.get('classification', 'needs_review'))
                raw_conf = result.get('confidence', 0.5)
                # Normalize: if > 1, assume percentage and convert to decimal
                confidence = raw_conf / 100.0 if raw_conf > 1 else raw_conf
                # Check if an investigation was created/linked
                investigation_id = result.get('investigation_id')
                if investigation_id:
                    await telemetry.record_agent_verdict(
                        investigation_id=str(investigation_id),
                        agent_execution_id=execution['execution_id'],
                        agent_id=str(agent['id']),
                        agent_tier=1,
                        verdict=verdict,
                        confidence=confidence,
                        reasoning=result.get('summary', result.get('output', ''))[:500] if result.get('summary') or result.get('output') else None,
                        iocs_found=result.get('iocs_found', [])
                    )
                    await telemetry.record_investigation_path_step(
                        investigation_id=str(investigation_id),
                        agent_id=str(agent['id']),
                        tier=1,
                        event_type='tier_analysis',
                        verdict=verdict,
                        confidence=confidence,
                        details={
                            'execution_id': execution['execution_id'],
                            'agent_name': agent.get('system_name'),
                            'alert_id': alert_id
                        }
                    )
                    logger.info(f"Telemetry recorded for T1 triage of alert {alert_id}")
        except Exception as telemetry_err:
            logger.warning(f"Failed to record T1 telemetry: {telemetry_err}")

        return {
            "execution_id": execution['execution_id'],
            "agent_id": str(agent['id']),
            "agent_name": agent.get('system_name'),
            "alert_id": alert_id,
            "result": result
        }

    async def handle_agent_analyze_investigation(job: Job) -> Dict[str, Any]:
        """Handle Tier 2 agent analysis of escalated investigations"""
        from services.agent_service import get_agent_service
        from services.agent_executor import get_agent_executor
        from services.postgres_db import postgres_db, set_platform_admin_mode
        set_platform_admin_mode(True)

        service = get_agent_service()
        executor = get_agent_executor()

        agent_id = job.payload.get('agent_id')
        investigation_id = job.payload.get('investigation_id')
        alert_id = job.payload.get('alert_id')

        # Get the agent
        agent = await service.get_agent(agent_id)
        if not agent:
            raise ValueError(f"Agent not found: {agent_id}")
        if not agent.get('enabled', False):
            raise ValueError(f"Agent is disabled: {agent_id}")

        # Get investigation details
        import uuid as uuid_module
        async with _admin_pool_conn() as conn:
            # Convert string to UUID for query
            inv_uuid = uuid_module.UUID(investigation_id) if isinstance(investigation_id, str) else investigation_id
            inv_row = await conn.fetchrow('SELECT * FROM investigations WHERE id = $1', inv_uuid)
            if not inv_row:
                raise ValueError(f"Investigation not found: {investigation_id}")

            investigation = dict(inv_row)

            # Get associated alert. Fallback chain:
            #   1. payload's alert_id (UUID or string form)
            #   2. investigation.alert_id column (set when correlate creates the investigation)
            #   3. most recent alert pointing to this investigation
            # Without this fallback the agent gets alert=None and the LLM
            # produces a "no alert data provided" summary that overwrites
            # any real analysis a sibling handler may have written.
            alert = None
            alert_row = None

            async def _try_load_alert(maybe_id):
                if not maybe_id:
                    return None
                try:
                    aid_uuid = uuid_module.UUID(maybe_id) if isinstance(maybe_id, str) else maybe_id
                    return await conn.fetchrow('SELECT * FROM alerts WHERE id = $1', aid_uuid)
                except (ValueError, TypeError):
                    return await conn.fetchrow('SELECT * FROM alerts WHERE alert_id = $1', maybe_id)

            if alert_id:
                alert_row = await _try_load_alert(alert_id)

            if alert_row is None and investigation.get('alert_id'):
                alert_row = await _try_load_alert(investigation['alert_id'])

            if alert_row is None:
                fallback = await conn.fetchrow(
                    'SELECT * FROM alerts WHERE investigation_id = $1 ORDER BY created_at DESC LIMIT 1',
                    inv_uuid,
                )
                if fallback:
                    alert_row = fallback

            if alert_row:
                alert = dict(alert_row)
                if isinstance(alert.get('raw_event'), str):
                    alert['raw_event'] = json.loads(alert['raw_event'])

        if alert is None:
            # No alert recoverable for this investigation. Running the agent
            # without alert context produces "no alert data provided" output
            # that overwrites any real analysis a sibling handler wrote.
            # Fail the job loudly so the orphan investigation surfaces, and
            # do not touch executive_summary.
            raise ValueError(
                f"agent_analyze_investigation: no alert recoverable for "
                f"investigation {investigation_id} (payload alert_id={alert_id!r}, "
                f"investigation.alert_id={investigation.get('alert_id')!r}, "
                f"no alerts point back to this investigation). "
                f"Refusing to run analysis without alert context."
            )

        # =====================================================
        # PHASE 9.4: Asset Enrichment for Investigation Analysis
        # =====================================================
        asset_context = None
        asset_prompt_addition = ""
        try:
            from services.asset_investigation_enrichment import get_asset_enrichment_service
            from services.asset_service import get_asset_service

            enrichment_service = get_asset_enrichment_service()
            enrichment_service.set_db(postgres_db)

            asset_svc = get_asset_service()
            asset_svc.set_db(postgres_db)
            enrichment_service.set_asset_service(asset_svc)

            # Check if we already have asset enrichment in investigation_data
            inv_data = investigation.get('investigation_data') or {}
            if isinstance(inv_data, str):
                try:
                    inv_data = json.loads(inv_data)
                except (json.JSONDecodeError, TypeError):
                    inv_data = {}
            inv_data = inv_data or {}

            if inv_data.get('asset_enrichment'):
                # Use existing enrichment
                asset_context = inv_data['asset_enrichment']
                logger.debug(f"Using existing asset enrichment for investigation {investigation_id}")
            else:
                # Enrich now using alert data
                alert_data_for_enrichment = {}
                if alert:
                    alert_data_for_enrichment = {
                        **alert.get('raw_event', {}),
                        'title': alert.get('title'),
                        'description': alert.get('description')
                    }

                enrichment_result = await enrichment_service.enrich_alert(alert_data_for_enrichment)

                if enrichment_result.get('matched_assets'):
                    asset_context = enrichment_result['asset_context']

                    # Also update the investigation with this enrichment
                    await enrichment_service.enrich_investigation(
                        str(investigation_id),
                        alert_data_for_enrichment,
                        investigation.get('priority', 'P3')
                    )
                    logger.info(f"Asset enrichment: Found {len(enrichment_result['matched_assets'])} assets for investigation {investigation_id}")

            # Generate prompt addition if we have assets
            if asset_context and asset_context.get('assets'):
                asset_prompt_addition = enrichment_service.get_agent_asset_context(asset_context['assets'])

        except Exception as asset_err:
            logger.warning(f"Asset enrichment failed for investigation {investigation_id}: {asset_err}")

        # Create execution record
        execution = await service.create_execution(
            agent_id=agent_id,
            trigger_type='escalation',  # Using 'escalation' - valid trigger type for investigations
            trigger_source_id=str(investigation_id),
            trigger_source_type='investigation'
        )

        # Build input data with escalation context from investigation_data
        investigation_data = investigation.get('investigation_data') or {}
        if isinstance(investigation_data, str):
            try:
                investigation_data = json.loads(investigation_data)
            except (json.JSONDecodeError, TypeError):
                investigation_data = {}
        investigation_data = investigation_data or {}

        escalation_context = investigation_data.get('tier1_analysis', investigation_data.get('escalation_context', {}))

        # Get agent tier from payload or agent definition
        agent_tier = job.payload.get('tier') or agent.get('tier') or agent.get('level') or 1

        # Build input data
        input_data = {
            "trigger_type": "investigation_analysis",
            "trigger_source_id": str(investigation_id),
            "trigger_source_type": "investigation",
            "investigation": {
                "id": str(investigation.get('id')),
                "investigation_id": investigation.get('investigation_id'),
                "alert_id": alert_id,
                "severity": investigation.get('severity'),
                "priority": investigation.get('priority'),
                "state": investigation.get('state'),
                "executive_summary": investigation.get('executive_summary'),
                "escalation_reason": investigation.get('escalation_reason'),
                "escalated_to_tier": investigation.get('escalated_to_tier'),
                "tier1_findings": escalation_context
            },
            "alert": {
                "id": str(alert.get('id')) if alert else None,
                "title": alert.get('title') if alert else None,
                "description": alert.get('description') if alert else None,
                "severity": alert.get('severity') if alert else None,
                # Truncate raw_event to prevent context window overflow
                "raw_event": _truncate_raw_event_for_prompt(alert.get('raw_event', {})) if alert else {}
            } if alert else None
        }

        # Add asset context if available (Phase 9.4)
        if asset_context:
            input_data["asset_context"] = asset_context
        if asset_prompt_addition:
            input_data["instructions"] = asset_prompt_addition

        # Run the agent
        result = await executor.run_agent(
            agent=agent,
            execution_id=execution['execution_id'],
            input_data=input_data
        )

        # Debug: log the result to verify decoded_iocs
        if isinstance(result, dict):
            logger.info(f"[JOB_HANDLER_DEBUG] tier={agent_tier} result.keys()={list(result.keys())}")
            if 'decoded_iocs' in result:
                logger.info(f"[JOB_HANDLER_DEBUG] decoded_iocs found in result: {result.get('decoded_iocs')}")

        # Write the tier analysis back to the investigation
        tier_key = f'tier{agent_tier}_analysis'
        # OPTIMIZED FLOW: Skip T2, go to ANALYZING after T1
        # T1 does quick triage, Riggs auto-analyzes during ANALYZING
        # For Tier 2+, preserve existing state (may already be ANALYZING)
        next_state = 'ANALYZING' if agent_tier == 1 else None  # None = preserve existing state

        # Extract analysis data from result
        analysis_data = {
            'agent_id': agent_id,
            'agent_name': agent.get('name') or agent.get('system_name'),
            'execution_id': execution['execution_id'],
            'completed_at': datetime.utcnow().isoformat(),
        }

        # Parse result to extract summary, confidence, etc.
        # NOTE: Confidence must be normalized to 0.0-1.0 scale (decimal)
        # The agent_executor returns confidence as 0.0-1.0, frontend expects same
        if isinstance(result, dict):
            analysis_data['summary'] = result.get('summary') or result.get('executive_summary') or result.get('output', '')[:500]
            raw_confidence = result.get('confidence', 0.5)
            # Normalize confidence: if > 1, assume it's a percentage and convert to decimal
            if raw_confidence > 1:
                raw_confidence = raw_confidence / 100.0
            analysis_data['confidence'] = max(0.0, min(1.0, raw_confidence))  # Clamp to 0-1
            analysis_data['verdict'] = result.get('verdict', 'needs_review')
            analysis_data['recommendations'] = result.get('recommendations', [])
            analysis_data['evidence'] = result.get('evidence', [])
            analysis_data['iocs_found'] = result.get('iocs_found', [])

            # Extract decoded IOCs from T2 analysis (hidden IOCs found in encoded content)
            decoded_iocs = result.get('decoded_iocs', {})
            if decoded_iocs and any(decoded_iocs.values()):
                analysis_data['decoded_iocs'] = decoded_iocs
                logger.info(f"[T2_DECODED_IOCS] Found hidden IOCs in investigation {investigation_id}: {decoded_iocs}")
        elif isinstance(result, str):
            analysis_data['summary'] = result[:500] if result else 'Analysis completed - manual review recommended.'
            analysis_data['confidence'] = 0.5  # Default to 0.5 (50%) not 50
            analysis_data['verdict'] = 'needs_review'

        # Ensure we always have at least a minimal summary
        if not analysis_data.get('summary'):
            verdict = analysis_data.get('verdict', 'unknown')
            confidence = analysis_data.get('confidence', 0.5)
            conf_pct = int(confidence * 100) if confidence <= 1 else int(confidence)

            # Generate a more descriptive summary based on verdict
            verdict_descriptions = {
                'malicious': 'Security threat confirmed',
                'suspicious': 'Suspicious activity detected requiring further analysis',
                'benign': 'No security threat identified',
                'needs_review': 'Requires analyst review to determine threat level',
                'needs_escalation': 'Complex case requiring senior analyst review',
                'inconclusive': 'Unable to determine threat level with available data'
            }
            desc = verdict_descriptions.get(verdict.lower(), 'Analysis completed')
            analysis_data['summary'] = f"{desc}. Confidence: {conf_pct}%."

        # Update the investigation with tier analysis
        async with _admin_pool_conn() as conn:
            # Get current investigation_data to merge
            current_inv = await conn.fetchrow(
                'SELECT investigation_data FROM investigations WHERE id = $1',
                inv_uuid
            )
            current_data = current_inv['investigation_data'] if current_inv else {}
            if isinstance(current_data, str):
                current_data = json.loads(current_data)
            if current_data is None:
                current_data = {}

            # GUARD: Don't overwrite tier analysis if it already has a proper verdict
            # The agent executor's _tool_complete_analysis may have already written a good verdict
            # We don't want to overwrite it with a fallback from the job handler
            existing_tier_analysis = current_data.get(tier_key, {})
            existing_verdict = existing_tier_analysis.get('verdict') if isinstance(existing_tier_analysis, dict) else None
            new_verdict = analysis_data.get('verdict', 'needs_review')

            # Skip overwriting if existing has a strong verdict and new is a weak fallback
            strong_verdicts = {'malicious', 'benign', 'needs_escalation', 'true_positive', 'false_positive'}
            weak_verdicts = {'needs_review', 'suspicious', 'inconclusive', 'unknown'}

            if existing_verdict and existing_verdict.lower() in strong_verdicts:
                if new_verdict.lower() in weak_verdicts:
                    logger.info(f"[GUARD] Preserving existing {tier_key} verdict '{existing_verdict}' - not overwriting with weaker '{new_verdict}'")
                    # Use existing analysis, but still update state
                    analysis_data = existing_tier_analysis

            # Merge tier analysis into investigation_data
            current_data[tier_key] = analysis_data

            # Also update executive_summary if we have one
            exec_summary = analysis_data.get('summary', '')[:1000] if analysis_data.get('summary') else None

            # =====================================================
            # STORE DECODED IOCs IN INVESTIGATION indicators/ioc_summary
            # These are hidden IOCs extracted from encoded content by T2
            # =====================================================
            decoded_iocs = analysis_data.get('decoded_iocs', {})
            ioc_update_sql = ""
            ioc_params = []

            if decoded_iocs and any(decoded_iocs.values()):
                # Get current indicators and ioc_summary
                inv_row = await conn.fetchrow(
                    'SELECT indicators, ioc_summary FROM investigations WHERE id = $1',
                    inv_uuid
                )
                current_indicators = inv_row['indicators'] if inv_row and inv_row['indicators'] else []
                current_ioc_summary = inv_row['ioc_summary'] if inv_row and inv_row['ioc_summary'] else {}

                if isinstance(current_indicators, str):
                    current_indicators = json.loads(current_indicators)
                if isinstance(current_ioc_summary, str):
                    current_ioc_summary = json.loads(current_ioc_summary)

                # Ensure ioc_summary has proper structure
                if not current_ioc_summary:
                    current_ioc_summary = {'ips': [], 'domains': [], 'urls': [], 'hashes': [], 'emails': []}

                # Add decoded IPs to indicators and ioc_summary
                for ip in decoded_iocs.get('ips', []):
                    # Add to indicators
                    current_indicators.append({
                        'type': 'ip',
                        'value': ip,
                        'source': 'ai_decoded',
                        'note': 'Hidden IP extracted from encoded content (base64/obfuscated)',
                        'severity': 'high',
                        'is_hidden': True
                    })
                    # Add to ioc_summary
                    if ip not in current_ioc_summary.get('ips', []):
                        current_ioc_summary.setdefault('ips', []).append(ip)

                # Add decoded URLs
                for url in decoded_iocs.get('urls', []):
                    current_indicators.append({
                        'type': 'url',
                        'value': url,
                        'source': 'ai_decoded',
                        'note': 'Hidden URL extracted from encoded content',
                        'severity': 'high',
                        'is_hidden': True
                    })
                    if url not in current_ioc_summary.get('urls', []):
                        current_ioc_summary.setdefault('urls', []).append(url)

                # Add decoded domains
                for domain in decoded_iocs.get('domains', []):
                    current_indicators.append({
                        'type': 'domain',
                        'value': domain,
                        'source': 'ai_decoded',
                        'note': 'Hidden domain extracted from encoded content',
                        'severity': 'medium',
                        'is_hidden': True
                    })
                    if domain not in current_ioc_summary.get('domains', []):
                        current_ioc_summary.setdefault('domains', []).append(domain)

                # Add decoded emails
                for email in decoded_iocs.get('emails', []):
                    current_indicators.append({
                        'type': 'email',
                        'value': email,
                        'source': 'ai_decoded',
                        'note': 'Hidden email extracted from encoded content',
                        'severity': 'medium',
                        'is_hidden': True
                    })
                    if email not in current_ioc_summary.get('emails', []):
                        current_ioc_summary.setdefault('emails', []).append(email)

                logger.info(f"[T2_DECODED_IOCS] Adding {len(decoded_iocs.get('ips', []))} IPs, {len(decoded_iocs.get('urls', []))} URLs to investigation {investigation_id}")

                # Update with decoded IOCs included
                # If next_state is None, preserve existing state (for Tier 2+ where agent_executor sets it)
                if next_state:
                    await conn.execute('''
                        UPDATE investigations
                        SET investigation_data = $1::jsonb,
                            state = $2,
                            confidence = $3,
                            executive_summary = COALESCE($4, executive_summary),
                            indicators = $5::jsonb,
                            ioc_summary = $6::jsonb,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = $7
                    ''',
                        json.dumps(current_data),
                        next_state,
                        analysis_data.get('confidence', 0.5),
                        exec_summary,
                        json.dumps(current_indicators),
                        json.dumps(current_ioc_summary),
                        inv_uuid
                    )
                else:
                    # Tier 2+: Don't overwrite state - agent_executor already set the correct state
                    await conn.execute('''
                        UPDATE investigations
                        SET investigation_data = $1::jsonb,
                            confidence = $2,
                            executive_summary = COALESCE($3, executive_summary),
                            indicators = $4::jsonb,
                            ioc_summary = $5::jsonb,
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = $6
                    ''',
                        json.dumps(current_data),
                        analysis_data.get('confidence', 0.5),
                        exec_summary,
                        json.dumps(current_indicators),
                        json.dumps(current_ioc_summary),
                        inv_uuid
                    )
            else:
                # No decoded IOCs - standard update
                if next_state:
                    await conn.execute('''
                        UPDATE investigations
                        SET investigation_data = $1::jsonb,
                            state = $2,
                            confidence = $3,
                            executive_summary = COALESCE($4, executive_summary),
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = $5
                    ''',
                        json.dumps(current_data),
                        next_state,
                        analysis_data.get('confidence', 0.5),
                        exec_summary,
                        inv_uuid
                    )
                else:
                    # Tier 2+: Don't overwrite state - agent_executor already set the correct state
                    await conn.execute('''
                        UPDATE investigations
                        SET investigation_data = $1::jsonb,
                            confidence = $2,
                            executive_summary = COALESCE($3, executive_summary),
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = $4
                    ''',
                        json.dumps(current_data),
                        analysis_data.get('confidence', 0.5),
                        exec_summary,
                        inv_uuid
                    )

            logger.info(f"Updated investigation {investigation.get('investigation_id')} with {tier_key}")

            # =====================================================
            # PERSIST VERDICT TO DEDICATED COLUMNS
            # The JSON blob in investigation_data->>'tierN_analysis'->>'verdict' is the
            # rich record, but customer queue/dashboard filters read the dedicated
            # provisional_verdict / final_verdict columns. Without writing them here
            # those columns stay NULL and analysts can't filter by verdict.
            # =====================================================
            verdict_norm = (analysis_data.get('verdict') or '').upper().strip()
            if verdict_norm:
                verdict_confidence = analysis_data.get('confidence', 0.5)
                verdict_reasoning = analysis_data.get('summary') or None
                try:
                    if agent_tier == 1:
                        await conn.execute('''
                            UPDATE investigations
                            SET provisional_verdict = $1,
                                provisional_confidence = $2,
                                provisional_reasoning = $3,
                                provisional_at = CURRENT_TIMESTAMP,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = $4
                        ''', verdict_norm, verdict_confidence, verdict_reasoning, inv_uuid)
                    else:
                        await conn.execute('''
                            UPDATE investigations
                            SET final_verdict = $1,
                                final_confidence = $2,
                                final_reasoning = $3,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE id = $4
                        ''', verdict_norm, verdict_confidence, verdict_reasoning, inv_uuid)
                except Exception as verdict_err:
                    logger.warning(
                        f"Failed to persist {tier_key} verdict columns for investigation "
                        f"{investigation_id}: {verdict_err}"
                    )

            # =====================================================
            # ALSO UPDATE ALERT WITH DECODED IOCs
            # So the alert view shows the hidden indicators found
            # =====================================================
            if decoded_iocs and any(decoded_iocs.values()) and alert_id:
                try:
                    # Get alert to update
                    try:
                        alert_uuid = uuid_module.UUID(alert_id) if isinstance(alert_id, str) else alert_id
                        alert_row = await conn.fetchrow('SELECT raw_event FROM alerts WHERE id = $1', alert_uuid)
                    except ValueError:
                        alert_row = await conn.fetchrow('SELECT raw_event FROM alerts WHERE alert_id = $1', alert_id)

                    if alert_row:
                        raw_event = alert_row['raw_event']
                        if isinstance(raw_event, str):
                            raw_event = json.loads(raw_event)

                        if '_extracted' not in raw_event:
                            raw_event['_extracted'] = {}

                        # Store decoded IOCs in alert
                        raw_event['_extracted']['decoded_iocs'] = decoded_iocs
                        raw_event['_extracted']['ai_triage'] = raw_event['_extracted'].get('ai_triage', {})
                        raw_event['_extracted']['ai_triage']['decoded_iocs'] = decoded_iocs
                        raw_event['_extracted']['ai_triage']['has_hidden_iocs'] = True

                        # Update alert
                        try:
                            await conn.execute(
                                'UPDATE alerts SET raw_event = $1 WHERE id = $2',
                                json.dumps(raw_event, default=str), alert_uuid
                            )
                        except:
                            await conn.execute(
                                'UPDATE alerts SET raw_event = $1 WHERE alert_id = $2',
                                json.dumps(raw_event, default=str), alert_id
                            )
                        logger.info(f"[T2_DECODED_IOCS] Updated alert {alert_id} with decoded IOCs")
                except Exception as alert_update_err:
                    logger.warning(f"Failed to update alert with decoded IOCs: {alert_update_err}")

        # =====================================================
        # TELEMETRY: Record agent verdict and path step
        # =====================================================
        try:
            # Record the agent's verdict
            await telemetry.record_agent_verdict(
                investigation_id=str(investigation_id),
                agent_execution_id=execution['execution_id'],
                agent_id=agent_id,
                agent_tier=agent_tier,
                verdict=analysis_data.get('verdict', 'needs_review'),
                confidence=analysis_data.get('confidence', 0.5),  # Default to 0.5 (decimal), not 50
                reasoning=analysis_data.get('summary', '')[:500] if analysis_data.get('summary') else None,
                iocs_found=analysis_data.get('iocs_found', [])
            )

            # Record path step
            await telemetry.record_investigation_path_step(
                investigation_id=str(investigation_id),
                agent_id=agent_id,
                tier=agent_tier,
                event_type='tier_analysis',
                verdict=analysis_data.get('verdict'),
                confidence=analysis_data.get('confidence'),
                details={
                    'execution_id': execution['execution_id'],
                    'agent_name': agent.get('name') or agent.get('system_name')
                }
            )

            logger.info(f"Telemetry recorded for investigation {investigation.get('investigation_id')}")
        except Exception as telemetry_err:
            logger.warning(f"Failed to record telemetry: {telemetry_err}")

        return {
            "execution_id": execution['execution_id'],
            "agent_id": agent_id,
            "agent_name": agent.get('name'),
            "investigation_id": str(investigation_id),
            "alert_id": alert_id,
            "tier": agent_tier,
            "tier_analysis_key": tier_key,
            "result": result
        }

    async def handle_riggs_analysis(job: Job) -> Dict[str, Any]:
        """
        Handle automatic Riggs analysis for RIGGS_REVIEW investigations.

        NEW ARCHITECTURE (2026-01):
        - FAST mode: High-confidence validation (T1 >= 85% and clear verdict)
        - DEEP mode: Full investigation for ambiguous/complex cases
        - Single-flight guard prevents duplicate runs
        - ML feedback recorded for continuous learning

        Key rules:
        - FAST can only CONFIRM or ESCALATE, never silently close
        - Only DEEP can return NEEDS_INVESTIGATION
        - riggs_analysis is NEVER included in input (prevents feedback loops)
        """
        from services.postgres_db import postgres_db, set_platform_admin_mode
        from services.ai_triage_service import get_ai_triage_service
        from services.field_extraction import FieldExtractor
        set_platform_admin_mode(True)
        from agents.riggs import (
            select_riggs_prompt_flagged, get_riggs_max_tokens,
            build_riggs_input, RiggsFlightGuard, record_riggs_feedback,
            validate_no_riggs_recursion, RIGGS_EXCLUDED_FIELDS
        )
        from datetime import datetime
        import time
        # Verdict validation imports (canonical verdicts from models.verdict)
        from models.verdict import Verdict, validate_verdict, normalize_verdict_safe

        payload = job.payload
        investigation_id = payload.get('investigation_id')
        investigation_uuid = payload.get('investigation_uuid')

        logger.info(f"[RIGGS] Starting analysis for investigation {investigation_id}")
        print(f"[RIGGS] Starting analysis for investigation {investigation_id}", flush=True)

        # ═══════════════════════════════════════════════════════════════════
        # SINGLE-FLIGHT GUARD - Prevent duplicate Riggs runs
        # ═══════════════════════════════════════════════════════════════════
        flight_guard = RiggsFlightGuard(postgres_db)
        if not await flight_guard.mark_started(investigation_id):
            logger.info(f"[RIGGS] Investigation {investigation_id} already has Riggs running/complete, skipping")
            return {"status": "skipped", "reason": "already_running_or_complete"}

        # Track execution metrics
        start_time = time.time()
        execution_id = None
        tokens_used = 0

        try:
            # Create agent execution record for dashboard tracking
            async with _admin_pool_conn() as conn:
                # Get Riggs agent ID
                riggs_agent = await conn.fetchrow(
                    "SELECT id FROM agent_definitions WHERE codename = 'RIGGS' LIMIT 1"
                )
                if riggs_agent:
                    exec_id_str = f"RIGGS-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{str(uuid.uuid4())[:8].upper()}"
                    await conn.execute('''
                        INSERT INTO agent_executions (
                            execution_id, agent_id, trigger_type,
                            trigger_source_id, trigger_source_type, status, started_at
                        ) VALUES ($1, $2, $3, $4, $5, $6, NOW())
                    ''',
                        exec_id_str,
                        riggs_agent['id'],
                        'scheduled',
                        investigation_uuid or investigation_id,
                        'investigation',
                        'running'
                    )
                    execution_id = exec_id_str
                    logger.info(f"[RIGGS] Created execution record: {execution_id}")

        except Exception as exec_err:
            logger.warning(f"[RIGGS] Could not create execution record: {exec_err}")

        try:
            async with _admin_pool_conn() as conn:
                # Get investigation with alert data
                inv = await conn.fetchrow("""
                    SELECT i.*, a.raw_event, a.id as alert_uuid, a.title as alert_title,
                           a.description as alert_desc, a.severity as alert_severity,
                           a.source as alert_source
                    FROM investigations i
                    LEFT JOIN alerts a ON i.alert_id::text = a.alert_id OR i.alert_id::text = a.id::text
                    WHERE i.investigation_id = $1
                """, investigation_id)

                if not inv:
                    return {"status": "error", "message": f"Investigation {investigation_id} not found"}

                # Parse raw_event
                raw_event = inv['raw_event']
                if isinstance(raw_event, str):
                    try:
                        raw_event = json.loads(raw_event)
                    except:
                        raw_event = {}
                raw_event = raw_event or {}

                # ═══════════════════════════════════════════════════════════════════
                # RIGGS FIELD EXTRACTION - Use T1 extracted data when available
                # OPTIMIZATION: Avoid redundant extraction if T1 already did it
                # ═══════════════════════════════════════════════════════════════════
                from config.system_config import ENABLE_RIGGS_STREAMLINED
                from services.field_extraction import FieldExtractor

                # Get existing extracted data from T1 phase
                existing_extracted = raw_event.get('_extracted', {})
                existing_iocs = existing_extracted.get('iocs', {})
                enrichment = existing_extracted.get('enrichment', {})

                # Check if we should reuse T1 extraction or re-extract
                has_t1_extraction = bool(existing_iocs) or bool(existing_extracted.get('decoded_content'))

                if ENABLE_RIGGS_STREAMLINED and has_t1_extraction:
                    # STREAMLINED MODE: Reuse T1 extraction results
                    logger.info(f"[RIGGS] Using existing T1 extraction (streamlined mode)")
                    riggs_extraction = {
                        'iocs': existing_iocs,
                        'decoded_content': existing_extracted.get('decoded_content', []),
                        'decoded_iocs': existing_extracted.get('decoded_iocs', {}),
                        'defanged_iocs': existing_extracted.get('defanged_iocs', {}),
                        'entities': existing_extracted.get('entities', {}),
                    }
                    print(f"[RIGGS] Reused T1 extraction: {len(riggs_extraction.get('decoded_content', []))} decoded blocks", flush=True)
                else:
                    # STANDARD MODE: Re-extract for deep analysis
                    field_extractor = FieldExtractor()
                    riggs_extraction = field_extractor.extract_all(raw_event)
                    logger.info(f"[RIGGS] Field extraction complete: {len(riggs_extraction.get('iocs', {}).get('ips', []))} IPs, "
                               f"{len(riggs_extraction.get('iocs', {}).get('domains', []))} domains, "
                               f"{len(riggs_extraction.get('decoded_content', []))} decoded items")
                    print(f"[RIGGS] Extracted: {len(riggs_extraction.get('decoded_content', []))} decoded content blocks", flush=True)

                # ═══════════════════════════════════════════════════════════════════
                # MERGE RIGGS DISCOVERIES WITH EXISTING DATA
                # Riggs adds newly discovered IOCs without overwriting existing ones
                # ═══════════════════════════════════════════════════════════════════
                merged_iocs = _merge_iocs(existing_iocs, riggs_extraction.get('iocs', {}))

                # Add decoded IOCs (from base64 content)
                decoded_iocs = riggs_extraction.get('decoded_iocs', {})
                if decoded_iocs:
                    merged_iocs = _merge_iocs(merged_iocs, decoded_iocs)
                    logger.info(f"[RIGGS] Added decoded IOCs: {sum(len(v) for v in decoded_iocs.values() if isinstance(v, list))} items")

                # Add defanged IOCs
                defanged_iocs = riggs_extraction.get('defanged_iocs', {})
                if defanged_iocs:
                    merged_iocs = _merge_iocs(merged_iocs, defanged_iocs)

                # Get T1 analysis if available
                investigation_data = inv['investigation_data'] or {}
                if isinstance(investigation_data, str):
                    try:
                        investigation_data = json.loads(investigation_data)
                    except:
                        investigation_data = {}

                # CRITICAL: Validate no prior riggs_analysis in data (prevents feedback loops)
                try:
                    validate_no_riggs_recursion(investigation_data)
                except ValueError as e:
                    logger.error(f"[RIGGS] {e}")
                    await flight_guard.mark_complete(investigation_id, success=False)
                    return {"status": "error", "message": str(e)}

                t1_analysis = investigation_data.get('tier1_findings', {}) or investigation_data.get('tier1_analysis', {})
                ai_verdict = t1_analysis.get('verdict', inv.get('ai_verdict', 'UNKNOWN'))
                ai_confidence_raw = t1_analysis.get('confidence', inv.get('ai_confidence', 0))

                # Normalize T1 confidence to 0-100 integer
                ai_confidence = float(ai_confidence_raw)
                if ai_confidence <= 1.0:
                    ai_confidence = int(ai_confidence * 100)
                ai_confidence = int(ai_confidence)

                # ═══════════════════════════════════════════════════════════════════
                # PROMPT SELECTION - Flag-based (new) or FAST/DEEP (legacy)
                # ═══════════════════════════════════════════════════════════════════

                # Build common data structures needed for both paths
                alert_data = {
                    'has_encoded_content': len(riggs_extraction.get('decoded_content', [])) > 0,
                    'decoded_content': riggs_extraction.get('decoded_content', []),
                    'ioc_count': sum(len(v) for v in merged_iocs.values() if isinstance(v, list)),
                    'is_domain_controller': 'dc' in str(raw_event).lower() or 'domain controller' in str(raw_event).lower(),
                    'raw_event': raw_event,
                }

                # Build Riggs analysis using LLM
                ai_triage = get_ai_triage_service()

                # Common alert/inv data for both paths
                alert_dict = {
                    'alert_id': inv.get('alert_id', 'unknown'),
                    'title': inv.get('alert_title') or inv.get('title', 'Security Alert'),
                    'description': inv.get('alert_desc') or inv.get('executive_summary', ''),
                    'severity': inv.get('alert_severity') or inv.get('severity', 'medium'),
                    'source': inv.get('alert_source') or raw_event.get('source', 'unknown'),
                    'raw_event': raw_event,
                    'iocs_extracted': merged_iocs,
                }

                inv_dict = {
                    'investigation_id': investigation_id,
                    'alert_id': inv.get('alert_id', 'unknown'),
                    'severity': inv.get('alert_severity') or inv.get('severity', 'medium'),
                    't1_verdict': ai_verdict,
                    't1_confidence': ai_confidence,
                }

                # ═══════════════════════════════════════════════════════════════════
                # Flag-based prompt selection
                # Uses specialized prompts based on alert classification from T1
                # ═══════════════════════════════════════════════════════════════════
                alert_flags = investigation_data.get('alert_flags', ['unknown'])
                logger.info(f"[RIGGS] Alert flags: {alert_flags}")
                print(f"[RIGGS] Alert flags: {alert_flags}", flush=True)

                # ═══════════════════════════════════════════════════════════════════
                # KNOWLEDGE BASE QUERY - Get relevant SOPs for this alert type
                # ═══════════════════════════════════════════════════════════════════
                kb_recommendations = []
                try:
                    from services.knowledge_base_service import get_knowledge_base_service
                    kb_service = get_knowledge_base_service()

                    # Build semantic search query based on alert characteristics
                    threat_type = t1_analysis.get('threat_type', '')
                    alert_title = inv.get('alert_title') or inv.get('title', '')
                    alert_desc = inv.get('alert_desc') or inv.get('executive_summary', '')

                    # Create search query combining alert info and flags
                    flag_text = ' '.join([f.replace('_', ' ') for f in alert_flags if f != 'unknown'])
                    search_query = f"{alert_title} {flag_text} {threat_type}".strip()

                    if search_query:
                        logger.info(f"[RIGGS_KB] Searching KB with query: {search_query}")
                        kb_recommendations = await kb_service.semantic_search(
                            query=search_query,
                            limit=5,
                            min_similarity=0.65,  # Lower threshold to get more results
                            content_types=['sop', 'playbook', 'procedure', 'runbook']
                        )
                        logger.info(f"[RIGGS_KB] Found {len(kb_recommendations)} relevant SOPs")
                        print(f"[RIGGS_KB] Found {len(kb_recommendations)} KB recommendations", flush=True)
                except Exception as kb_err:
                    # Non-fatal - Riggs can still analyze without KB recommendations
                    logger.warning(f"[RIGGS_KB] Failed to query KB: {kb_err}")
                    print(f"[RIGGS_KB] Warning: KB query failed, continuing without recommendations", flush=True)

                # Build alert context for the prompt
                # Include email_auth_status and sender_legitimacy_verified for Riggs to use
                # when deciding whether to confirm or downgrade T1's BENIGN verdict
                email_auth_status = t1_analysis.get('email_auth_status', {})
                sender_verified = t1_analysis.get('sender_legitimacy_verified', False) or email_auth_status.get('all_passed', False)

                # ═══════════════════════════════════════════════════════════════
                # GET PRE-TRIAGE PLAYBOOK RESULTS
                # Include results of automated playbooks that ran before T1
                # ═══════════════════════════════════════════════════════════════
                playbook_results_summary = None
                try:
                    from services.playbook_orchestrator import get_playbook_orchestrator
                    orchestrator = get_playbook_orchestrator()
                    alert_id = inv.get('alert_id', 'unknown')
                    playbook_results_summary = await orchestrator.format_playbook_results_for_triage(alert_id)
                    if playbook_results_summary:
                        logger.info(f"[RIGGS] Including pre-triage playbook results for alert {alert_id}")
                except Exception as pb_err:
                    logger.warning(f"[RIGGS] Failed to get playbook results: {pb_err}")

                # Per-tenant LLM context overrides (extra prose + key
                # include/exclude). Fetched best-effort; failures fall
                # back to platform defaults so prompt construction never
                # blocks on this lookup.
                tenant_llm_context = None
                try:
                    tid = str(inv.get('tenant_id') or alert_dict.get('tenant_id') or '')
                    if tid:
                        from services import tenant_llm_context_service as _tlc
                        tenant_llm_context = await _tlc.get_for_tenant(tid)
                except Exception as _tlc_err:
                    logger.debug(f"[RIGGS] tenant_llm_context fetch skipped: {_tlc_err}")

                # Round B: pull all five platform-context bundles in one go.
                # Cheap, best-effort, and any individual failure just nulls
                # out that bundle rather than blocking triage.
                platform_ctx = {
                    'intake_context': None,
                    'entity_risk_summary': None,
                    'sla_context': None,
                    'available_actions': None,
                    'tenant_custom_rules': None,
                }
                try:
                    from services.riggs_platform_context import gather_platform_context
                    platform_ctx = await gather_platform_context(
                        tenant_id=str(inv.get('tenant_id') or alert_dict.get('tenant_id') or '') or None,
                        investigation=inv_dict,
                        alert=alert_dict,
                    )
                except Exception as _ctx_err:
                    logger.debug(f"[RIGGS] platform_context fetch skipped: {_ctx_err}")

                riggs_input = build_riggs_input(
                    investigation=inv_dict,
                    alert=alert_dict,
                    t1_analysis={
                        'verdict': ai_verdict,
                        'confidence': ai_confidence,
                        'summary': t1_analysis.get('summary', ''),
                        'email_auth_status': email_auth_status,
                        'sender_legitimacy_verified': sender_verified
                    },
                    mode="FLAG",  # Flag-based mode marker
                    decoded_content=riggs_extraction.get('decoded_content', []),
                    enrichment_summary={'malicious': len(enrichment.get('malicious', [])), 'total': len(enrichment)} if enrichment else None,
                    kb_recommendations=kb_recommendations,
                    playbook_results_summary=playbook_results_summary,
                    tenant_llm_context=tenant_llm_context,
                    **platform_ctx,
                )
                riggs_context = riggs_input.to_prompt_context()

                # Select flag-based prompt (includes secondary flags in context)
                full_prompt, riggs_prompt_metadata = select_riggs_prompt_flagged(
                    alert_flags=alert_flags,
                    t1_verdict=ai_verdict,
                    t1_confidence=ai_confidence,
                    t1_summary=t1_analysis.get('summary', ''),
                    alert_context=riggs_context
                )

                # Map flag names to user-friendly display names
                flag_display_names = {
                    'phishing': 'Phishing Analysis',
                    'email_triage': 'Email Triage',
                    'malware': 'Malware Analysis',
                    'lateral': 'Lateral Movement Analysis',
                    'c2': 'C2 Communication Analysis',
                    'creds': 'Credential Access Analysis',
                    'exfil': 'Data Exfiltration Analysis',
                    'persistence': 'Persistence Analysis',
                    'privesc': 'Privilege Escalation Analysis',
                    'evasion': 'Defense Evasion Analysis',
                    'unknown': 'General Analysis'
                }
                selected_flag = riggs_prompt_metadata.get('selected_flag', 'unknown')
                riggs_mode = flag_display_names.get(selected_flag, 'General Analysis')
                max_tokens = get_riggs_max_tokens()

                # Debug: Log prompt to file (disabled by default, set PROMPT_DEBUG=true to enable)
                if os.getenv('PROMPT_DEBUG', 'false').lower() == 'true':
                    try:
                        from datetime import datetime as dt_debug
                        debug_dir = "/app/prompt_debug"
                        os.makedirs(debug_dir, exist_ok=True)
                        timestamp = dt_debug.utcnow().strftime("%Y%m%d_%H%M%S")
                        safe_inv_id = str(investigation_id).replace('/', '_').replace('\\', '_')[:50]
                        filename = f"{debug_dir}/RIGGS_{riggs_mode}_{safe_inv_id}_{timestamp}.txt"
                        with open(filename, 'w') as f:
                            f.write(f"{'='*80}\n")
                            f.write(f"RIGGS {riggs_mode} ANALYSIS - Investigation: {investigation_id}\n")
                            f.write(f"Timestamp: {dt_debug.utcnow().isoformat()}\n")
                            f.write(f"T1: {ai_verdict} @ {ai_confidence}%\n")
                            f.write(f"{'='*80}\n\n")
                            f.write(f"[PROMPT] ({len(full_prompt)} chars):\n")
                            f.write(f"{'='*80}\n")
                            f.write(full_prompt)
                            f.write(f"\n\n{'='*80}\n")
                        print(f"[PROMPT_DEBUG] Riggs {riggs_mode} prompt saved to {filename}")
                    except Exception as debug_err:
                        print(f"[PROMPT_DEBUG] Failed to save prompt: {debug_err}")

                # Call LLM (max_tokens already set in branch above)
                riggs_analysis = await _run_riggs_analysis_with_mode(
                    ai_triage, full_prompt, investigation_id, riggs_mode, max_tokens
                )

                if riggs_analysis:
                    # ═══════════════════════════════════════════════════════════════
                    # FEEDBACK LOOP: Add Riggs-discovered IOCs to analysis
                    # ═══════════════════════════════════════════════════════════════

                    # Merge LLM-identified IOCs with extracted IOCs
                    llm_iocs = riggs_analysis.get('iocs', [])
                    for ioc in llm_iocs:
                        ioc_type = ioc.get('type', '').lower()
                        ioc_value = ioc.get('value', '')
                        if ioc_type and ioc_value:
                            # Map to our IOC structure
                            type_map = {'ip': 'ips', 'domain': 'domains', 'hash': 'hashes',
                                       'url': 'urls', 'email': 'emails'}
                            merged_key = type_map.get(ioc_type, f"{ioc_type}s")
                            if merged_key not in merged_iocs:
                                merged_iocs[merged_key] = []
                            if ioc_value not in merged_iocs[merged_key]:
                                merged_iocs[merged_key].append(ioc_value)

                    # Store Riggs extraction results and mode info
                    riggs_analysis['riggs_mode'] = riggs_mode  # Track which mode was used
                    riggs_analysis['riggs_extracted_iocs'] = merged_iocs
                    riggs_analysis['riggs_extracted_entities'] = riggs_extraction.get('entities', {})
                    riggs_analysis['decoded_content_count'] = len(riggs_extraction.get('decoded_content', []))
                    riggs_analysis['has_encoded_data'] = len(riggs_extraction.get('decoded_content', [])) > 0
                    # Include decoded content directly in riggs_analysis for frontend display
                    riggs_analysis['decoded_content'] = riggs_extraction.get('decoded_content', [])

                    # Store prompt metadata for auditability (only if informative)
                    if riggs_prompt_metadata:
                        # Clean up metadata - make flags more readable
                        clean_metadata = {
                            'analysis_type': riggs_mode,  # User-friendly name
                            'prompt_version': riggs_prompt_metadata.get('prompt_version', 'v2'),
                        }
                        # Only include all_flags if there are multiple meaningful flags
                        all_flags = riggs_prompt_metadata.get('all_flags', [])
                        meaningful_flags = [f for f in all_flags if f != 'unknown']
                        if meaningful_flags:
                            clean_metadata['detected_categories'] = [
                                flag_display_names.get(f, f) for f in meaningful_flags
                            ]
                        riggs_analysis['riggs_prompt_metadata'] = clean_metadata

                    # Save Riggs analysis to investigation_data
                    investigation_data['riggs_analysis'] = riggs_analysis
                    investigation_data['riggs_analyzed_at'] = datetime.utcnow().isoformat()
                    investigation_data['riggs_mode'] = riggs_mode
                    # Also store decoded_content at top level for easy access
                    investigation_data['decoded_content'] = riggs_extraction.get('decoded_content', [])

                    # ═══════════════════════════════════════════════════════════════
                    # PLAYBOOK RECOMMENDATIONS - Enhance Riggs output with suggestions
                    # ═══════════════════════════════════════════════════════════════
                    try:
                        from services.riggs_playbook_integration import get_riggs_playbook_integration
                        playbook_integration = get_riggs_playbook_integration()
                        riggs_analysis = await playbook_integration.enhance_riggs_output(
                            riggs_analysis=riggs_analysis,
                            alert=alert_dict,
                            investigation={'investigation_id': investigation_id, **inv_dict},
                            auto_recommend=True
                        )
                        investigation_data['riggs_analysis'] = riggs_analysis
                        logger.info(f"[RIGGS] Enhanced with {len(riggs_analysis.get('playbook_recommendations', []))} playbook recommendations")
                    except Exception as pb_err:
                        logger.warning(f"[RIGGS] Failed to enhance with playbook recommendations: {pb_err}")
                        # Continue without playbook recommendations - non-fatal

                    # ═══════════════════════════════════════════════════════════════
                    # UPDATE INVESTIGATION WITH MERGED IOCs AND ENTITIES
                    # ═══════════════════════════════════════════════════════════════

                    # Build indicators array for investigation
                    indicators = inv.get('indicators') or []
                    if isinstance(indicators, str):
                        try:
                            indicators = json.loads(indicators)
                        except:
                            indicators = []

                    # Add Riggs-discovered IOCs as indicators
                    existing_values = {i.get('value') for i in indicators if isinstance(i, dict)}
                    # NOTE: ioc_type comes in plural form ('ips', 'domains',
                    # 'hashes', etc.). Don't use rstrip('s') -- 'hashes'.
                    # rstrip('s') yields 'hashe', not 'hash', and downstream
                    # recommended_actions can't match an unknown type.
                    PLURAL_TO_SINGULAR = {
                        'ips': 'ip',
                        'private_ips': 'ip',
                        'public_ips': 'ip',
                        'domains': 'domain',
                        'urls': 'url',
                        'hashes': 'hash',
                        'md5s': 'hash',
                        'sha1s': 'hash',
                        'sha256s': 'hash',
                        'emails': 'email',
                        'usernames': 'username',
                        'hostnames': 'hostname',
                        'files': 'file',
                        'filenames': 'file',
                    }
                    for ioc_type, values in merged_iocs.items():
                        if isinstance(values, list):
                            singular = PLURAL_TO_SINGULAR.get(
                                ioc_type, ioc_type[:-1] if ioc_type.endswith('s') else ioc_type
                            )
                            for val in values:
                                if val and val not in existing_values:
                                    indicators.append({
                                        'type': singular,
                                        'value': val,
                                        'source': 'riggs_extraction',
                                        'discovered_by': 'riggs',
                                        'discovered_at': datetime.utcnow().isoformat()
                                    })
                                    existing_values.add(val)

                    # Update investigation with all data
                    # Note: Store indicators and ioc_summary in investigation_data
                    # as the investigations table doesn't have those columns
                    investigation_data['indicators'] = indicators
                    investigation_data['ioc_summary'] = merged_iocs

                    # Determine the new state based on Riggs verdict
                    # Use normalize_verdict_safe for robust handling of any verdict value
                    raw_verdict = riggs_analysis.get('verdict', 'UNKNOWN')
                    riggs_verdict = normalize_verdict_safe(raw_verdict, Verdict.UNKNOWN).value
                    riggs_confidence_raw = riggs_analysis.get('confidence', 0)
                    # Normalize confidence to percentage (0-100 scale)
                    riggs_confidence = float(riggs_confidence_raw)
                    if riggs_confidence <= 1.0:
                        riggs_confidence = int(riggs_confidence * 100)
                    riggs_confidence = int(riggs_confidence)
                    # Store normalized confidence back in riggs_analysis for consistent display
                    riggs_analysis['confidence'] = riggs_confidence

                    new_state = 'NEEDS_REVIEW'  # Default: AI done, needs human review
                    new_disposition = None  # Disposition is ONLY set when investigation is CLOSED

                    # DISPOSITION RULES:
                    # - Disposition should remain UNKNOWN until investigation is closed
                    # - Only auto-close (and set disposition) for high-confidence BENIGN verdicts
                    # - All other verdicts go to NEEDS_REVIEW with disposition unchanged

                    # Import auto-close configuration (lazy import to avoid circular deps)
                    from config.system_config import (
                        RIGGS_AUTO_CLOSE_ENABLED,
                        RIGGS_AUTO_CLOSE_THRESHOLD,
                        RIGGS_AUTO_CLOSE_VERDICTS
                    )

                    if riggs_mode == "FAST":
                        # FAST mode: Always needs human review, never set disposition
                        new_state = 'NEEDS_REVIEW'
                        new_disposition = None  # Keep existing disposition (UNKNOWN)
                    elif not RIGGS_AUTO_CLOSE_ENABLED:
                        # Auto-close disabled: all investigations go to NEEDS_REVIEW
                        new_state = 'NEEDS_REVIEW'
                        new_disposition = None
                        logger.info(f"[RIGGS] Auto-close disabled, investigation {investigation_id} -> NEEDS_REVIEW")
                    else:
                        # DEEP MODE: Full verdict handling with configurable auto-close
                        # Auto-close if verdict is in allowed list AND confidence meets threshold
                        if riggs_verdict in RIGGS_AUTO_CLOSE_VERDICTS and riggs_confidence >= RIGGS_AUTO_CLOSE_THRESHOLD:
                            new_state = 'CLOSED'
                            new_disposition = riggs_verdict  # Use the actual verdict as disposition
                            logger.info(f"[RIGGS] Auto-closing {investigation_id}: {riggs_verdict} @ {riggs_confidence}% (threshold: {RIGGS_AUTO_CLOSE_THRESHOLD}%)")
                        else:
                            # All other cases: needs human review, don't change disposition
                            new_state = 'NEEDS_REVIEW'
                            new_disposition = None  # Keep existing disposition (UNKNOWN)
                            if riggs_verdict in RIGGS_AUTO_CLOSE_VERDICTS:
                                logger.info(f"[RIGGS] {investigation_id}: {riggs_verdict} @ {riggs_confidence}% below threshold ({RIGGS_AUTO_CLOSE_THRESHOLD}%) -> NEEDS_REVIEW")

                    # Convert riggs_confidence (0-100) to decimal (0-1) for consistency with other handlers
                    riggs_confidence_decimal = riggs_confidence / 100.0 if riggs_confidence > 1 else riggs_confidence

                    # Calibrate severity based on Riggs verdict
                    # Benign alerts should not stay CRITICAL/HIGH -- downgrade them
                    new_severity = None
                    if riggs_verdict.upper() in ('BENIGN', 'FALSE_POSITIVE') and riggs_confidence >= 75:
                        new_severity = 'low'
                    elif riggs_verdict.upper() in ('SUSPICIOUS', 'NEEDS_INVESTIGATION') and riggs_confidence >= 70:
                        new_severity = 'medium'
                    # MALICIOUS/TRUE_POSITIVE verdicts keep existing severity (set by source)

                    if new_severity:
                        await conn.execute("""
                            UPDATE investigations
                            SET investigation_data = $1,
                                state = $2,
                                disposition = COALESCE($3, disposition),
                                confidence = $4,
                                severity = $6,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE investigation_id = $5
                        """, json.dumps(investigation_data, default=str),
                            new_state, new_disposition, riggs_confidence_decimal, investigation_id, new_severity)
                    else:
                        await conn.execute("""
                            UPDATE investigations
                            SET investigation_data = $1,
                                state = $2,
                                disposition = COALESCE($3, disposition),
                                confidence = $4,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE investigation_id = $5
                        """, json.dumps(investigation_data, default=str),
                            new_state, new_disposition, riggs_confidence_decimal, investigation_id)

                    logger.info(f"[RIGGS] Investigation {investigation_id} state: {new_state} (verdict: {riggs_verdict}, confidence: {riggs_confidence}%)")

                    # ═══════════════════════════════════════════════════════════════
                    # GENERATE RECOMMENDED ACTIONS from IOCs + available connectors
                    # ═══════════════════════════════════════════════════════════════
                    try:
                        from services.recommended_actions_service import generate_recommendations, save_recommendations
                        inv_tenant_id = str(inv.get('tenant_id', ''))
                        inv_uuid = str(inv.get('id', ''))
                        if inv_tenant_id and inv_uuid:
                            rec_actions = await generate_recommendations(
                                tenant_id=inv_tenant_id,
                                investigation_id=inv_uuid,
                                riggs_analysis=riggs_analysis,
                                iocs=merged_iocs,
                            )
                            if rec_actions:
                                await save_recommendations(
                                    tenant_id=inv_tenant_id,
                                    investigation_id=inv_uuid,
                                    recommendations=rec_actions,
                                )
                                logger.info(f"[RIGGS] Generated {len(rec_actions)} recommended actions for {investigation_id}")
                    except Exception as ra_err:
                        logger.warning(f"[RIGGS] Failed to generate recommended actions: {ra_err}")

                    # ═══════════════════════════════════════════════════════════════
                    # AUTO-TRIGGER DEEP DIVE for premium tiers
                    # Single, robust trigger point: regardless of which path created
                    # this investigation (correlate / auto_enrichment /
                    # agent_executor._handle_suspicious_escalation), Deep Dive should
                    # fire after Riggs general analysis completes if the tenant has
                    # the entitlement and Deep Dive hasn't already run.
                    # ═══════════════════════════════════════════════════════════════
                    try:
                        inv_tenant_id = str(inv.get('tenant_id', ''))
                        inv_uuid_str = str(inv.get('id', ''))
                        if inv_tenant_id and inv_uuid_str:
                            existing_deep = await conn.fetchval(
                                "SELECT investigation_data->'riggs_deep_analysis' FROM investigations WHERE id = $1",
                                inv.get('id'),
                            )
                            if not existing_deep:
                                from dependencies.license_checks import _get_tenant_tier
                                from services.licensing.default_plans import get_default_entitlements
                                tier = await _get_tenant_tier(inv_tenant_id)
                                entitlements = get_default_entitlements(tier)
                                features = entitlements.features or {}
                                if (
                                    features.get('deep_dive')
                                    and features.get('deep_dive_monthly_limit', 0) == 0
                                ):
                                    from services.ai_triage_service import get_ai_triage_service
                                    ai_triage = get_ai_triage_service()
                                    logger.info(
                                        f"[RIGGS->DEEP_DIVE] Premium tier ({getattr(tier, 'value', tier)}) - "
                                        f"queueing Deep Dive for {investigation_id}"
                                    )
                                    asyncio.create_task(
                                        ai_triage.deep_dive_investigation(inv_uuid_str, inv_tenant_id)
                                    )
                    except Exception as dd_err:
                        logger.warning(
                            f"[RIGGS->DEEP_DIVE] Failed to auto-trigger Deep Dive for {investigation_id}: {dd_err}"
                        )

                    # ═══════════════════════════════════════════════════════════════
                    # UPDATE ALERT with Riggs extraction data (feedback to source)
                    # ═══════════════════════════════════════════════════════════════
                    if inv.get('alert_uuid'):
                        # Merge Riggs extraction into alert's _extracted
                        raw_event['_extracted'] = raw_event.get('_extracted', {})
                        raw_event['_extracted']['riggs_analysis'] = {
                            'analyzed_at': datetime.utcnow().isoformat(),
                            'decoded_content': riggs_extraction.get('decoded_content', []),
                            'decoded_iocs': decoded_iocs,
                            'entities': riggs_extraction.get('entities', {}),
                            'has_encoded_data': len(riggs_extraction.get('decoded_content', [])) > 0
                        }
                        raw_event['_extracted']['iocs'] = merged_iocs

                        # Build Riggs summary to append to ai_summary
                        riggs_summary_parts = []
                        riggs_summary_parts.append(f"\n\n--- Riggs Analysis [{datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC] ---")

                        # Add verdict and key insights
                        if riggs_analysis.get('verdict'):
                            riggs_summary_parts.append(f"**Deep Analysis Verdict: {riggs_analysis.get('verdict')}** ({riggs_analysis.get('confidence', 0)}% confidence)")

                        if riggs_analysis.get('summary'):
                            riggs_summary_parts.append(riggs_analysis.get('summary'))

                        # Add key findings
                        key_findings = riggs_analysis.get('key_findings', [])
                        if key_findings:
                            riggs_summary_parts.append("**Key Findings:** " + "; ".join(key_findings[:3]))

                        # Add decoded content info
                        decoded_count = len(riggs_extraction.get('decoded_content', []))
                        if decoded_count > 0:
                            riggs_summary_parts.append(f"**Decoded Artifacts:** {decoded_count} encoded payloads decoded and analyzed")

                        # Add IOC discovery info
                        new_iocs = sum(len(v) for v in decoded_iocs.values() if isinstance(v, list))
                        if new_iocs > 0:
                            riggs_summary_parts.append(f"**Hidden IOCs Discovered:** {new_iocs} IOCs extracted from encoded content")

                        riggs_summary = " ".join(riggs_summary_parts)

                        # Fetch current ai_summary and append Riggs analysis
                        current_alert = await conn.fetchrow(
                            "SELECT ai_summary FROM alerts WHERE id = $1",
                            inv['alert_uuid']
                        )
                        current_summary = current_alert['ai_summary'] if current_alert and current_alert['ai_summary'] else ""
                        updated_summary = current_summary + riggs_summary

                        await conn.execute("""
                            UPDATE alerts SET raw_event = $1, ai_summary = $2, updated_at = CURRENT_TIMESTAMP
                            WHERE id = $3
                        """, json.dumps(raw_event, default=str), updated_summary, inv['alert_uuid'])

                        # If investigation was auto-closed, also close the source alert.
                        # Stamp closed_by + closed_at so the dashboard auto-closed
                        # counter (WHERE closed_by LIKE 'Riggs%') counts it.
                        if new_state == 'CLOSED':
                            await conn.execute("""
                                UPDATE alerts
                                SET status = 'closed',
                                    ai_verdict = $1,
                                    ai_confidence = $2,
                                    closed_by = COALESCE(closed_by, 'Riggs:auto'),
                                    closed_at = COALESCE(closed_at, CURRENT_TIMESTAMP),
                                    updated_at = CURRENT_TIMESTAMP
                                WHERE id = $3
                                  AND status NOT IN ('closed', 'resolved')
                            """, riggs_verdict.lower(), riggs_confidence_decimal, inv['alert_uuid'])
                            # Persist the investigation-side transition too. The
                            # outer loop sets `new_state = 'CLOSED'` locally, but
                            # without an UPDATE here the row stays at NEEDS_REVIEW,
                            # leaving the dashboard "state=Closed" diverging from
                            # the drawer "Status=NEEDS REVIEW". Disposition mirrors
                            # the Riggs verdict so the resolution column is also
                            # right.
                            verdict_to_disposition = {
                                'benign': 'BENIGN',
                                'false_positive': 'FALSE_POSITIVE',
                                'true_positive': 'TRUE_POSITIVE',
                                'malicious': 'MALICIOUS',
                            }
                            riggs_disposition = verdict_to_disposition.get(
                                riggs_verdict.lower(),
                                None,
                            )
                            await conn.execute("""
                                UPDATE investigations
                                   SET state         = 'CLOSED',
                                       disposition   = COALESCE($2, disposition),
                                       completed_at  = COALESCE(completed_at, CURRENT_TIMESTAMP),
                                       updated_at    = CURRENT_TIMESTAMP
                                 WHERE investigation_id = $1
                                   AND state NOT IN ('CLOSED', 'RESOLVED')
                            """, investigation_id, riggs_disposition)
                            logger.info(f"[RIGGS] Auto-closed source alert + investigation for {investigation_id} (disposition={riggs_disposition})")

                            # Surface the auto-close in the notification bell —
                            # but ONLY for outcomes worth a glance. BENIGN is
                            # the bulk noise (legitimate Shopify confirmations
                            # etc.); silencing it stops the bell from drowning
                            # in happy-path closes. We still notify on:
                            #   - TRUE_POSITIVE / MALICIOUS  (Riggs auto-closed
                            #     a real threat — analyst should double-check)
                            #   - FALSE_POSITIVE             (good signal for
                            #     tuning detection rules)
                            #   - low-confidence closes      (Riggs wasn't sure,
                            #     analyst should sanity-check)
                            try:
                                conf_pct = int(round((riggs_confidence_decimal or 0) * 100))
                                disp_upper = (riggs_disposition or '').upper()
                                worth_notifying = (
                                    disp_upper in ('TRUE_POSITIVE', 'MALICIOUS', 'FALSE_POSITIVE')
                                    or conf_pct < 80
                                )
                                inv_tenant_id = str(inv.get('tenant_id') or '')
                                if worth_notifying and inv_tenant_id:
                                    from routes.notifications import create_notification
                                    inv_title = inv.get('alert_title') or inv.get('title') or 'Investigation'
                                    # TP / MALICIOUS warrants a louder
                                    # severity than a tuning-data FP.
                                    notif_severity = (
                                        'high' if disp_upper in ('TRUE_POSITIVE', 'MALICIOUS')
                                        else 'info'
                                    )
                                    await create_notification(
                                        tenant_id=inv_tenant_id,
                                        title=f"Auto-closed: {inv_title[:80]}",
                                        message=(
                                            f"Riggs closed this investigation as "
                                            f"{(riggs_disposition or riggs_verdict or 'resolved').lower()} "
                                            f"({conf_pct}% confidence). Reopen from the queue if needed."
                                        ),
                                        category="investigation",
                                        severity=notif_severity,
                                        link=f"/investigation/{investigation_id}",
                                        metadata={
                                            "investigation_id": investigation_id,
                                            "auto_closed_by": "Riggs",
                                            "disposition": riggs_disposition,
                                            "confidence_pct": conf_pct,
                                            "event_type": "riggs_auto_close",
                                        },
                                    )
                            except Exception as notify_err:
                                logger.warning(f"[RIGGS] Auto-close notification failed for {investigation_id}: {notify_err}")

                    duration_ms = int((time.time() - start_time) * 1000)
                    token_count = riggs_analysis.get('tokens_used', 0)

                    logger.info(f"[RIGGS] {riggs_mode} analysis complete for {investigation_id} - "
                               f"{len(indicators)} total indicators, {len(merged_iocs.get('ips', []))} IPs")
                    print(f"[RIGGS] {riggs_mode} done in {duration_ms}ms: {len(indicators)} indicators, "
                          f"decoded_content={riggs_analysis.get('decoded_content_count', 0)}", flush=True)

                    # ═══════════════════════════════════════════════════════════════════
                    # ML FEEDBACK: Record for learning
                    # ═══════════════════════════════════════════════════════════════════
                    try:
                        await record_riggs_feedback(
                            db=postgres_db,
                            investigation={
                                'investigation_id': investigation_id,
                                'alert_id': inv.get('alert_id', 'unknown'),
                                't1_verdict': ai_verdict,
                                't1_confidence': ai_confidence,
                                'severity': inv.get('alert_severity') or inv.get('severity', 'medium'),
                                'source': inv.get('alert_source') or raw_event.get('source', 'unknown'),
                            },
                            riggs_result=riggs_analysis,
                            mode=riggs_mode,
                            processing_time_ms=duration_ms,
                            token_count=token_count
                        )
                    except Exception as fb_err:
                        logger.warning(f"[RIGGS] Failed to record feedback: {fb_err}")

                    # Mark flight guard as complete
                    await flight_guard.mark_complete(investigation_id, success=True)

                    # Update execution record as completed
                    if execution_id:
                        try:
                            await conn.execute('''
                                UPDATE agent_executions
                                SET status = 'completed',
                                    completed_at = NOW(),
                                    duration_ms = $1,
                                    tokens_used = $2,
                                    outcome = $3
                                WHERE execution_id = $4
                            ''',
                                duration_ms,
                                token_count,
                                json.dumps({
                                    'summary': riggs_analysis.get('summary', ''),
                                    'verdict': riggs_analysis.get('verdict', 'ANALYZED'),
                                    'confidence': riggs_analysis.get('confidence', 0),
                                    'mode': riggs_mode,
                                    'iocs_discovered': sum(len(v) for v in merged_iocs.values() if isinstance(v, list))
                                }),
                                execution_id
                            )
                            logger.info(f"[RIGGS] Execution {execution_id} completed in {duration_ms}ms")
                        except Exception as upd_err:
                            logger.warning(f"[RIGGS] Could not update execution record: {upd_err}")

                    return {
                        "status": "success",
                        "investigation_id": investigation_id,
                        "riggs_mode": riggs_mode,
                        "riggs_analysis": True,
                        "widgets_generated": list(riggs_analysis.keys()),
                        "iocs_discovered": sum(len(v) for v in merged_iocs.values() if isinstance(v, list)),
                        "has_encoded_data": riggs_analysis.get('has_encoded_data', False),
                        "duration_ms": duration_ms
                    }
                else:
                    # Mark as failed if no analysis generated
                    await flight_guard.mark_complete(investigation_id, success=False)
                    if execution_id:
                        try:
                            async with _admin_pool_conn() as conn2:
                                await conn2.execute('''
                                    UPDATE agent_executions
                                    SET status = 'failed',
                                        completed_at = NOW(),
                                        duration_ms = $1,
                                        error_message = 'Failed to generate Riggs analysis'
                                    WHERE execution_id = $2
                                ''', int((time.time() - start_time) * 1000), execution_id)
                        except:
                            pass
                    return {"status": "error", "message": "Failed to generate Riggs analysis"}

        except Exception as e:
            logger.error(f"[RIGGS] Analysis error: {e}")
            print(f"[RIGGS] Analysis error: {e}", flush=True)
            import traceback
            traceback.print_exc()

            # Mark flight guard as failed
            try:
                await flight_guard.mark_complete(investigation_id, success=False)
            except Exception as fg_err:
                logger.error(f"[RIGGS] Failed to mark flight guard as failed for {investigation_id}: {fg_err}")

            # Mark execution as failed
            if execution_id:
                try:
                    async with _admin_pool_conn() as conn2:
                        await conn2.execute('''
                            UPDATE agent_executions
                            SET status = 'failed',
                                completed_at = NOW(),
                                duration_ms = $1,
                                error_message = $2
                            WHERE execution_id = $3
                        ''', int((time.time() - start_time) * 1000), str(e)[:500], execution_id)
                except:
                    pass

            return {"status": "error", "message": str(e)}

    def _merge_iocs(existing: dict, new: dict) -> dict:
        """Merge new IOCs into existing, avoiding duplicates."""
        merged = {}
        all_keys = set(list(existing.keys()) + list(new.keys()))

        for key in all_keys:
            existing_vals = existing.get(key, [])
            new_vals = new.get(key, [])

            # Handle both list and set types
            if isinstance(existing_vals, set):
                existing_vals = list(existing_vals)
            if isinstance(new_vals, set):
                new_vals = list(new_vals)
            if not isinstance(existing_vals, list):
                existing_vals = [existing_vals] if existing_vals else []
            if not isinstance(new_vals, list):
                new_vals = [new_vals] if new_vals else []

            # Merge without duplicates
            merged[key] = list(set(existing_vals + new_vals))

        return merged

    async def _run_riggs_analysis_with_mode(
        ai_triage,
        full_prompt: str,
        investigation_id: str,
        mode: str,
        max_tokens: int
    ) -> dict:
        """
        Run Riggs analysis with mode-specific settings.

        FAST mode: Smaller prompt, quick validation (~600 tokens output)
        DEEP mode: Full prompt, comprehensive analysis (~1500 tokens output)

        Returns structured analysis JSON or None on failure.
        """
        # Verdict validation imports (canonical verdicts from models.verdict)
        from models.verdict import Verdict, validate_verdict

        try:
            # Call LLM with mode-specific settings
            response = await ai_triage._call_llm_for_triage(
                full_prompt,
                f"riggs_{mode.lower()}_analysis",
                max_tokens=max_tokens
            )

            if not response:
                logger.error(f"[RIGGS] No LLM response for {mode} mode")
                return None

            # Parse JSON from response with robust error handling
            analysis = _parse_llm_json_response(response, mode, investigation_id)

            if not analysis:
                logger.warning(f"[RIGGS] Failed to parse LLM response for {mode} mode")
                return None

            # Normalize confidence to 0-100 integer
            if 'confidence' in analysis:
                conf = analysis['confidence']
                if isinstance(conf, float) and conf <= 1.0:
                    analysis['confidence'] = int(conf * 100)
                else:
                    analysis['confidence'] = int(conf)

            # Ensure required fields based on mode
            if mode == "FAST":
                analysis.setdefault('verdict', 'SUSPICIOUS')
                analysis.setdefault('confidence', 70)
                analysis.setdefault('threat_type', 'unknown')
                analysis.setdefault('summary', '')
                analysis.setdefault('key_findings', [])
                analysis.setdefault('affected_entities', [])
                analysis.setdefault('iocs', [])
                analysis.setdefault('mitre', [])
                analysis.setdefault('recommendations', [])
                analysis.setdefault('escalate_to_deep', False)
            else:
                # DEEP mode has more fields
                analysis.setdefault('verdict', 'SUSPICIOUS')
                analysis.setdefault('confidence', 50)
                analysis.setdefault('threat_type', 'unknown')
                analysis.setdefault('threat_type_justification', '')
                analysis.setdefault('summary', '')
                analysis.setdefault('key_findings', [])
                analysis.setdefault('affected_entities', [])
                analysis.setdefault('timeline', [])
                analysis.setdefault('mitre', [])
                analysis.setdefault('iocs', [])
                analysis.setdefault('decoded_artifacts', [])
                analysis.setdefault('recommendations', [])
                analysis.setdefault('confidence_factors', {'supports': [], 'limits': []})
                analysis.setdefault('what_would_change_verdict', [])

            # ═══════════════════════════════════════════════════════════════
            # VERDICT VALIDATION: Ensure Riggs output uses canonical verdicts
            # ═══════════════════════════════════════════════════════════════
            raw_verdict = analysis.get('verdict', 'UNKNOWN')
            try:
                validated_verdict = validate_verdict(raw_verdict, "Riggs LLM output")
                analysis['verdict'] = validated_verdict.value  # Use canonical uppercase
                logger.info(f"[RIGGS_VERDICT] Validated verdict: {raw_verdict} -> {validated_verdict.value}")
            except ValueError as e:
                # Invalid verdict from LLM - log warning and normalize to SUSPICIOUS
                logger.warning(f"[RIGGS_VERDICT] Invalid verdict from LLM: {raw_verdict}. Defaulting to SUSPICIOUS. Error: {e}")
                analysis['verdict'] = Verdict.SUSPICIOUS.value
                analysis['verdict_validation_warning'] = f"Original LLM verdict '{raw_verdict}' was invalid, normalized to SUSPICIOUS"

            # Generate default recommendations if LLM didn't provide any
            if not analysis.get('recommendations'):
                verdict = analysis.get('verdict', '').upper()
                if verdict == 'MALICIOUS':
                    analysis['recommendations'] = [
                        {"action": "Isolate affected systems from network to prevent lateral movement", "priority": "high"},
                        {"action": "Collect forensic artifacts (memory dump, event logs, network traffic)", "priority": "high"},
                        {"action": "Block identified malicious IOCs at perimeter and endpoint", "priority": "high"},
                        {"action": "Notify incident response team and escalate per incident severity", "priority": "medium"},
                        {"action": "Conduct root cause analysis to identify initial access vector", "priority": "medium"},
                    ]
                elif verdict == 'SUSPICIOUS':
                    analysis['recommendations'] = [
                        {"action": "Enhance monitoring on affected entities for additional indicators", "priority": "medium"},
                        {"action": "Gather additional context from user or asset owner", "priority": "medium"},
                        {"action": "Review related alerts within correlation window", "priority": "medium"},
                        {"action": "Consider temporary access restrictions pending investigation", "priority": "low"},
                    ]
                elif verdict == 'NEEDS_INVESTIGATION':
                    analysis['recommendations'] = [
                        {"action": "Conduct deep-dive analysis with full forensic data collection", "priority": "medium"},
                        {"action": "Correlate with threat intelligence for IOC context", "priority": "medium"},
                        {"action": "Interview asset owner or user for operational context", "priority": "low"},
                    ]

            logger.info(f"[RIGGS] {mode} analysis parsed: verdict={analysis.get('verdict')} conf={analysis.get('confidence')}")
            return analysis

        except Exception as e:
            logger.error(f"[RIGGS] {mode} analysis error: {e}")
            import traceback
            traceback.print_exc()
            return None

    async def _run_riggs_deep_analysis(ai_triage, alert_context: dict, investigation_id: str) -> dict:
        """
        DEPRECATED: Legacy deep analysis function.
        Kept for backward compatibility.
        New code should use _run_riggs_analysis_with_mode with DEEP mode.
        """
        from datetime import datetime

        raw_event = alert_context.get('raw_event', {})
        enrichment = alert_context.get('enrichment', {})
        iocs = alert_context.get('iocs', {})
        riggs_extraction = alert_context.get('riggs_extraction', {})

        # Build decoded content section (critical for encoded malware analysis)
        # IMPORTANT: Truncate to avoid exceeding model context limit (8192 tokens)
        decoded_section = ""
        decoded_content = riggs_extraction.get('decoded_content', [])
        if decoded_content:
            decoded_section = "\n\n[DECODED BASE64/ENCODED CONTENT - CRITICAL]:\n"
            for i, dc in enumerate(decoded_content[:3]):  # Limit to 3 blocks
                decoded_section += f"Block {i+1}:\n"
                decoded_section += f"  Encoded: {dc.get('encoded', '')[:80]}...\n"
                # Truncate decoded content to 500 chars to stay within context limits
                decoded_text = str(dc.get('decoded', ''))[:500]
                decoded_section += f"  DECODED: {decoded_text}{'...[truncated]' if len(str(dc.get('decoded', ''))) > 500 else ''}\n\n"

        # Build entities section
        entities_section = ""
        entities = riggs_extraction.get('entities', {})
        if entities:
            entities_section = "\n\n[EXTRACTED ENTITIES]:\n"
            for entity_type, values in entities.items():
                if values:
                    entities_section += f"  {entity_type}: {', '.join(str(v) for v in values[:10])}\n"

        # Build decoded IOCs section (IOCs found in encoded content)
        decoded_iocs_section = ""
        decoded_iocs = riggs_extraction.get('decoded_iocs', {})
        if any(decoded_iocs.values()):
            decoded_iocs_section = "\n\n[IOCs FROM DECODED CONTENT - HIGH PRIORITY]:\n"
            for ioc_type, values in decoded_iocs.items():
                if values:
                    decoded_iocs_section += f"  {ioc_type}: {', '.join(str(v) for v in list(values)[:10])}\n"

        # ═══════════════════════════════════════════════════════════════════
        # With Qwen2.5-32B (32K context), we can pass much more data
        # Only truncate extremely large fields to stay within limits
        # ═══════════════════════════════════════════════════════════════════
        def truncate_large_strings(obj, max_str_len=8000, max_depth=5, depth=0):
            """Truncate only extremely large strings, preserve structure"""
            if depth > max_depth:
                return "[nested data omitted]"
            if isinstance(obj, dict):
                result = {}
                for k, v in obj.items():
                    # Skip binary/base64 encoded data fields that are huge
                    if k.lower() in {'attachment_content', 'binary_data', 'raw_bytes'}:
                        if isinstance(v, str) and len(v) > 1000:
                            result[k] = f"[{len(v)} bytes binary data - omitted]"
                            continue
                    result[k] = truncate_large_strings(v, max_str_len, max_depth, depth + 1)
                return result
            elif isinstance(obj, list):
                return [truncate_large_strings(item, max_str_len, max_depth, depth + 1) for item in obj[:20]]
            elif isinstance(obj, str):
                if len(obj) > max_str_len:
                    return obj[:max_str_len] + f"...[truncated, +{len(obj)-max_str_len} chars]"
                return obj
            return obj

        # Aggressive truncation for 8K context (Qwen 14B limit)
        # ~8K tokens = ~32K chars, but we need 2K for response, so ~24K chars max
        # Split: raw_event ~8K, enrichment ~4K, iocs ~2K, prompt ~5K, buffer ~5K
        processed_raw_event = truncate_large_strings(raw_event, max_str_len=2000)
        processed_enrichment = truncate_large_strings(enrichment, max_str_len=1000)
        processed_iocs = truncate_large_strings(iocs, max_str_len=500)

        # Build the analysis prompt with enhanced context
        # This prompt enforces strict evidence discipline and non-human artifact extraction
        prompt = f"""You are Riggs, a senior SOC investigator performing deep, evidence-based security analysis for incident response, threat hunting, and executive reporting.

Your primary differentiator is the ability to extract, normalize, and structure non-human-readable security data (binary artifacts, encoded content, compressed data, memory-like fragments, hex previews) into clear, actionable intelligence.

Your output must be technically accurate, defensible under peer review, and explicitly distinguish between observed evidence and inferred behavior.

You do not reverse engineer malware.
You translate raw telemetry into structured security intelligence.

═══════════════════════════════════════════════════════════════════════════
ALERT METADATA
═══════════════════════════════════════════════════════════════════════════
Title: {alert_context.get('title')}
Description: {alert_context.get('description')}
Severity: {alert_context.get('severity')}
Source: {alert_context.get('source')}
T1 Verdict: {alert_context.get('t1_verdict')} ({alert_context.get('t1_confidence')}% confidence)

═══════════════════════════════════════════════════════════════════════════
RAW EVENT DATA
═══════════════════════════════════════════════════════════════════════════
{json.dumps(processed_raw_event, indent=2, default=str)[:8000]}
{decoded_section}
═══════════════════════════════════════════════════════════════════════════
ENRICHMENT RESULTS
═══════════════════════════════════════════════════════════════════════════
{json.dumps(processed_enrichment, indent=2, default=str)[:4000]}

═══════════════════════════════════════════════════════════════════════════
EXTRACTED IOCs
═══════════════════════════════════════════════════════════════════════════
{json.dumps(processed_iocs, indent=2, default=str)[:2000]}
{decoded_iocs_section}
{entities_section}
═══════════════════════════════════════════════════════════════════════════
ANALYSIS REQUIREMENTS (STRICT)
═══════════════════════════════════════════════════════════════════════════
1. Correlate evidence across sources (email, endpoint, network).
2. Prefer decoded and raw evidence over summaries.
3. If non-human-readable data is present:
   - You MUST extract it into structured artifacts.
   - You MUST classify what the data IS, not what it DOES.
   - You MUST preserve provenance.
4. Describe only what is OBSERVED.
5. Do NOT assume execution, persistence, or exfiltration unless explicitly observed.
6. If execution is not observed, explicitly state "execution was not observed".
7. Build a timeline with observed vs inferred clearly marked.
8. Map relevant MITRE ATT&CK techniques with concise explanations.
9. Recommendations must be proportional to confidence and observed impact.

═══════════════════════════════════════════════════════════════════════════
CRITICAL CLAIM DISCIPLINE (NON-NEGOTIABLE)
═══════════════════════════════════════════════════════════════════════════
- Do NOT label payload behavior without execution evidence.
- Do NOT infer payload intent from encoding alone.
- Do NOT reverse engineer binaries or memory fragments.
- Ignore noise blobs unless correlated.
- Do NOT carry assumptions from previous alerts.
- If evidence is partial, label conclusions as "inferred".

═══════════════════════════════════════════════════════════════════════════
VERDICT & THREAT TYPE RULES
═══════════════════════════════════════════════════════════════════════════
MALICIOUS: Correlated malicious behaviors observed.
SUSPICIOUS: Indicators present but key behaviors unobserved.
NEEDS_INVESTIGATION: Insufficient or conflicting evidence.
BENIGN: Evidence supports legitimate activity.

Threat Type Precision:
- Use "downloader" when external payload retrieval is observed WITHOUT execution.
- Use "malware" only when payload execution or malicious behavior is confirmed.
- Use "phishing" when email delivery is the primary vector.
- Use "c2" when command-and-control communication is confirmed.

═══════════════════════════════════════════════════════════════════════════
OUTPUT FORMAT (JSON ONLY - NO MARKDOWN)
═══════════════════════════════════════════════════════════════════════════
{{
  "verdict": "MALICIOUS|SUSPICIOUS|BENIGN|NEEDS_INVESTIGATION",
  "confidence": 0-100 (percentage, e.g., 70 means 70% confident),
  "threat_type": "downloader|malware|phishing|c2|credential_theft|data_exfiltration|persistence|lateral_movement|other",
  "threat_type_justification": "One sentence explaining why this threat type was chosen",
  "summary": "Executive summary distinguishing observed vs inferred",
  "key_findings": ["finding 1", "finding 2"],
  "affected_entities": [
    {{"entity_type": "user|host|domain|ip_address", "value": "..."}}
  ],
  "timeline": [
    {{"step": "description", "status": "observed|inferred", "time_estimate": "ISO timestamp or relative"}}
  ],
  "mitre_techniques": [
    {{"id": "T1xxx", "name": "...", "description": "why this applies"}}
  ],
  "iocs": [
    {{"type": "ip_address|domain|url|file_name|hash", "value": "..."}}
  ],
  "non_human_artifacts": [
    {{
      "artifact_id": "artifact-N",
      "source": "where this came from",
      "artifact_type": "binary|encoded|compressed|memory_fragment|unknown",
      "representation": "raw_bytes|hex|base64|mixed",
      "observed_properties": {{
        "size_bytes": 0,
        "entropy": "low|medium|high|unknown",
        "file_header": "",
        "encoding_type": "",
        "compression_type": ""
      }},
      "analysis_notes": "Observed facts only",
      "recommended_next_steps": []
    }}
  ],
  "confidence_explanation": {{
    "supporting_evidence": [],
    "confidence_limiters": [],
    "inference_notes": ""
  }},
  "evidence_weighting": {{
    "high_confidence_signals": [],
    "medium_confidence_signals": [],
    "low_confidence_or_noise": []
  }},
  "recommendations": [
    {{"action": "specific step", "priority": "high|medium|low"}}
  ],
  "risk_factors": [],
  "what_would_change_verdict": []
}}

If non-human-readable data exists and non_human_artifacts is missing, the response is INVALID.
Return ONLY valid JSON, no markdown or explanations."""

        # ═══════════════════════════════════════════════════════════════════════════
        # DEBUG: Log complete Riggs prompt to file for analysis (disabled by default)
        # Set PROMPT_DEBUG=true in .env to enable
        # ═══════════════════════════════════════════════════════════════════════════
        if os.getenv('PROMPT_DEBUG', 'false').lower() == 'true':
            try:
                from datetime import datetime as dt_debug
                debug_dir = "/app/prompt_debug"
                os.makedirs(debug_dir, exist_ok=True)
                timestamp = dt_debug.utcnow().strftime("%Y%m%d_%H%M%S")
                safe_inv_id = str(investigation_id).replace('/', '_').replace('\\', '_')[:50]
                filename = f"{debug_dir}/RIGGS_DEEP_{safe_inv_id}_{timestamp}.txt"
                with open(filename, 'w') as f:
                    f.write(f"{'='*80}\n")
                    f.write(f"RIGGS DEEP ANALYSIS - Investigation: {investigation_id}\n")
                    f.write(f"Timestamp: {dt_debug.utcnow().isoformat()}\n")
                    f.write(f"{'='*80}\n\n")
                    f.write(f"[RIGGS PROMPT] ({len(prompt)} chars):\n")
                    f.write(f"{'='*80}\n")
                    f.write(prompt)
                    f.write(f"\n\n{'='*80}\n")
                print(f"[PROMPT_DEBUG] Riggs prompt saved to {filename}")
            except Exception as e:
                print(f"[PROMPT_DEBUG] Failed to save Riggs prompt: {e}")

        try:
            # Get LLM response
            response = await ai_triage._call_llm_for_triage(prompt, "riggs_deep_analysis")

            if not response:
                logger.error("[RIGGS] No LLM response")
                return None

            # Parse JSON from response
            analysis = None
            response_text = response.strip()

            # Try to extract JSON
            if response_text.startswith('{'):
                try:
                    analysis = json.loads(response_text)
                except json.JSONDecodeError:
                    # Try to find JSON in response
                    import re
                    json_match = re.search(r'\{[\s\S]*\}', response_text)
                    if json_match:
                        try:
                            analysis = json.loads(json_match.group())
                        except:
                            pass

            if not analysis:
                # Build minimal analysis from available data
                logger.warning("[RIGGS] Failed to parse LLM response, building from available data")
                analysis = _build_fallback_analysis(alert_context)

            # Ensure required fields (new Riggs schema)
            analysis.setdefault('verdict', alert_context.get('t1_verdict', 'UNKNOWN'))
            analysis.setdefault('confidence', alert_context.get('t1_confidence', 50))
            analysis.setdefault('threat_type', 'unknown')
            analysis.setdefault('threat_type_justification', 'Insufficient evidence for classification')
            analysis.setdefault('summary', alert_context.get('description', 'Analysis pending'))
            analysis.setdefault('key_findings', [])
            analysis.setdefault('affected_entities', [])
            analysis.setdefault('timeline', [])
            analysis.setdefault('mitre_techniques', [])
            analysis.setdefault('iocs', [])
            analysis.setdefault('recommendations', [])
            analysis.setdefault('non_human_artifacts', [])
            analysis.setdefault('confidence_explanation', {
                'supporting_evidence': [],
                'confidence_limiters': ['LLM parse failure - fallback analysis'],
                'inference_notes': []
            })
            analysis.setdefault('evidence_weighting', {
                'high_confidence_signals': [],
                'medium_confidence_signals': [],
                'low_confidence_signals': []
            })

            return analysis

        except Exception as e:
            logger.error(f"[RIGGS] Analysis error: {e}")
            return _build_fallback_analysis(alert_context)

    def _build_fallback_analysis(alert_context: dict) -> dict:
        """Build analysis from available data when LLM fails - new Riggs schema."""
        raw_event = alert_context.get('raw_event', {})
        enrichment = alert_context.get('enrichment', {})
        iocs_data = alert_context.get('iocs', {})

        # Extract affected entities
        affected = []
        if raw_event.get('host') or raw_event.get('hostname'):
            affected.append({'type': 'host', 'value': raw_event.get('host') or raw_event.get('hostname'), 'role': 'target'})
        if raw_event.get('user') or raw_event.get('username'):
            affected.append({'type': 'user', 'value': raw_event.get('user') or raw_event.get('username'), 'role': 'target'})
        if raw_event.get('process') or raw_event.get('processName'):
            affected.append({'type': 'process', 'value': raw_event.get('process') or raw_event.get('processName'), 'role': 'indicator'})

        # Extract IOCs from enrichment results
        iocs = []
        results = enrichment.get('results', {})
        for ioc_type in ['ips', 'domains', 'hashes', 'urls']:
            for item in results.get(ioc_type, []):
                if isinstance(item, dict):
                    iocs.append({
                        'type': ioc_type.rstrip('s'),
                        'value': item.get('value', item.get('ioc', '')),
                        'verdict': item.get('verdict', 'unknown'),
                        'context': item.get('context', '')
                    })

        # Build timeline from timestamps in raw_event
        timeline = []
        if raw_event.get('timestamp') or raw_event.get('created_at'):
            timeline.append({
                'timestamp': raw_event.get('timestamp') or raw_event.get('created_at'),
                'event': alert_context.get('title', 'Alert triggered'),
                'phase': 'detection'
            })

        # Build confidence explanation for fallback
        confidence_limiters = ['LLM analysis unavailable - fallback extraction only']
        supporting_evidence = []
        if iocs:
            supporting_evidence.append(f"Extracted {len(iocs)} IOCs from enrichment data")
        if affected:
            supporting_evidence.append(f"Identified {len(affected)} affected entities")

        return {
            'verdict': alert_context.get('t1_verdict', 'NEEDS_INVESTIGATION'),
            'confidence': alert_context.get('t1_confidence', 50),
            'threat_type': 'unknown',
            'threat_type_justification': 'LLM analysis unavailable - insufficient evidence for threat classification',
            'summary': alert_context.get('description', 'Analysis based on available data - LLM fallback'),
            'key_findings': [f"Alert: {alert_context.get('title', 'Security alert detected')}"],
            'affected_entities': affected,
            'timeline': timeline,
            'mitre_techniques': [],
            'iocs': iocs,
            'recommendations': [
                {'priority': 1, 'action': 'Review alert details and enrichment data', 'category': 'investigate'},
                {'priority': 2, 'action': 'Verify affected systems', 'category': 'contain'}
            ],
            'risk_factors': [],
            'what_would_change_verdict': ['Full LLM analysis with decoded artifact examination'],
            'non_human_artifacts': [],
            'confidence_explanation': {
                'supporting_evidence': supporting_evidence,
                'confidence_limiters': confidence_limiters,
                'inference_notes': ['Fallback analysis - no LLM deep analysis performed']
            },
            'evidence_weighting': {
                'high_confidence_signals': [],
                'medium_confidence_signals': [e for e in supporting_evidence],
                'low_confidence_signals': ['Fallback extraction only - no behavioral analysis']
            }
        }

    # Register the handlers
    job_queue.register_handler('agent_analyze_alert', handle_agent_analyze_alert)
    job_queue.register_handler('agent_auto_triage', handle_agent_auto_triage)
    job_queue.register_handler('agent_analyze_investigation', handle_agent_analyze_investigation)
    job_queue.register_handler('riggs_analysis', handle_riggs_analysis)

    logger.info("Agent job handlers registered (including Riggs auto-analysis)")
class QueueFullError(RuntimeError):
    """Raised when a queue is at capacity."""
    pass


def _get_queue_limit(queue_name: str) -> int:
    """Get max pending size for a given queue."""
    specific = os.getenv(f"JOB_QUEUE_MAX_PENDING_{queue_name.upper()}")
    if specific and specific.isdigit():
        return int(specific)
    return int(os.getenv("JOB_QUEUE_MAX_PENDING", "10000"))
