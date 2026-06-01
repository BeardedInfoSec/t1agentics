# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Execution Engine

Executes visual playbook graphs by processing nodes and following edges.
Handles node execution, branching, approvals, form collection, and more.

Node Types Supported:
- trigger: Alert/schedule/webhook triggers
- riggs_analyze: AI analysis via Riggs
- enrich: IOC/entity enrichment
- action: Response actions (with approval gates)
- condition: If/else branching
- switch: Multi-way branching
- loop: Iteration over lists
- parallel: Parallel branch execution
- merge: Merge parallel branches
- python_code: Custom Python (sandboxed)
- function_call: Call saved function
- transform: Data transformation (JSONPath)
- approval_gate: Wait for human approval
- webform: Show form, wait for submission
- file_upload: Request file upload
- user_input: Simple text/choice input
- list_lookup: Check against custom list
- list_update: Add/remove from list
- edl_add: Add IOCs to an EDL list (with optional approval)
- edl_remove: Remove IOCs from an EDL list (with optional approval)
- variable_set: Set execution variable
- variable_get: Get execution variable
- notify: Send notification
- create_ticket: Create ticket
- webhook_call: Call external webhook
- delay: Wait for duration
- schedule: Schedule future execution
- end: End playbook
"""

import json
import logging
import asyncio
import uuid
import re
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field, validator
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# Execution Models
# ============================================================================

class ExecutionStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    WAITING_INPUT = "waiting_input"
    WAITING_FILE = "waiting_file"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class NodeResult(BaseModel):
    """Normalized execution result envelope for every node handler."""
    node_id: str
    kind: str  # node type (trigger, action, condition, etc.)
    status: str = "success"  # success, failed, skipped, waiting
    ok: bool = True  # auto-computed from status
    started_at: datetime = Field(default_factory=datetime.utcnow)
    ended_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    integration_instance_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    inputs: Dict[str, Any] = Field(default_factory=dict)
    outputs: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    meta: Dict[str, Any] = Field(default_factory=dict)

    @validator('ok', always=True, pre=False)
    def _compute_ok(cls, v, values):
        return values.get('status', 'success') == 'success'


class ExecutionContext(BaseModel):
    """Runtime context passed between nodes."""
    # Trigger data
    trigger: Dict[str, Any] = Field(default_factory=dict)

    # Variables set during execution
    variables: Dict[str, Any] = Field(default_factory=dict)

    # Results from previous nodes (keyed by node_id)
    nodes: Dict[str, Any] = Field(default_factory=dict)

    # Current execution metadata
    execution_id: Optional[str] = None
    playbook_id: Optional[str] = None
    alert_id: Optional[str] = None
    investigation_id: Optional[str] = None

    # Tenant context (required for multi-tenant bridge calls)
    tenant_id: Optional[str] = None

    # User context
    user_id: Optional[str] = None
    user_email: Optional[str] = None

    # Parallel execution tracking
    completed_node_ids: List[str] = Field(default_factory=list)
    total_nodes_executed: int = 0
    max_total_nodes: int = 500  # Circuit breaker


# ============================================================================
# Playbook Engine
# ============================================================================

class PlaybookEngine:
    """
    Core execution engine for visual playbooks.

    Processes node graphs, executes nodes, and manages execution state.
    """

    def __init__(self):
        self._node_handlers: Dict[str, callable] = {}
        self._register_default_handlers()

    def _register_default_handlers(self):
        """Register default node type handlers."""
        self._node_handlers = {
            "trigger": self._execute_trigger,
            "riggs_analyze": self._execute_riggs_analyze,
            "enrich": self._execute_enrich,
            "action": self._execute_action,
            "analyze": self._execute_analyze,
            "respond": self._execute_respond,
            "condition": self._execute_condition,
            "switch": self._execute_switch,
            "loop": self._execute_loop,
            "parallel": self._execute_parallel,
            "merge": self._execute_merge,
            "python_code": self._execute_python_code,
            # Unified canvas "code" block — dispatches by config.mode to the
            # underlying engine handler (script/assign/transform/note).
            "code": self._execute_code,
            # Unified canvas "utility" block — dispatches by config.operation
            # to case-update / EDL / note handlers (or returns a clear error
            # for operations whose schema isn't provisioned yet).
            "utility": self._execute_utility,
            "function_call": self._execute_function_call,
            "transform": self._execute_transform,
            "approval_gate": self._execute_approval_gate,
            # Canonical-name aliases so playbooks saved with the newer
            # Workflow Studio kinds still execute. Both names route to
            # the same handler.
            "approval": self._execute_approval_gate,
            "decision": self._execute_condition,
            "webform": self._execute_webform,
            "file_upload": self._execute_file_upload,
            "user_input": self._execute_user_input,
            "list_lookup": self._execute_list_lookup,
            "list_update": self._execute_list_update,
            "edl_add": self._execute_edl_add,
            "edl_remove": self._execute_edl_remove,
            "variable_set": self._execute_variable_set,
            "variable_get": self._execute_variable_get,
            "notify": self._execute_notify,
            "create_ticket": self._execute_create_ticket,
            "webhook_call": self._execute_webhook_call,
            "case_update": self._execute_case_update,
            "subflow": self._execute_subflow,
            "note": self._execute_note,
            "delay": self._execute_delay,
            "schedule": self._execute_schedule,
            "end": self._execute_end,
            # AI agent node (generic LLM call inside playbook)
            "ai_agent": self._execute_ai_agent,
        }

    # ========================================================================
    # Public API
    # ========================================================================

    def _json_safe(self, obj: Any) -> Any:
        """Convert nested datetimes (and related types) to JSON-safe values."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, dict):
            return {key: self._json_safe(value) for key, value in obj.items()}
        if isinstance(obj, list):
            return [self._json_safe(value) for value in obj]
        if isinstance(obj, tuple):
            return [self._json_safe(value) for value in obj]
        return obj

    async def test_single_node(
        self,
        node_id: str,
        node_kind: str,
        node_config: Dict[str, Any],
        sample_context: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Execute a single node in isolation for testing purposes.
        Does not persist any execution record to the database.
        Returns the node's outputs or error.
        """
        try:
            # Build a minimal fake node dict
            node = {
                'id': node_id,
                'type': 'signal',
                'data': {
                    'kind': node_kind,
                    'label': 'Test Node',
                    'config': node_config,
                },
            }

            # Build sample context — use provided or the standard fixture
            if not sample_context:
                sample_context = {
                    'manual': True,
                    'alert': {
                        'id': 'sample-alert-001',
                        'title': 'Sample Alert: Phishing Email Detected',
                        'severity': 'high',
                        'source': 'email_gateway',
                        'sender': 'attacker@evil.com',
                        'sender_domain': 'evil.com',
                        'iocs': ['evil.com', '192.168.1.100'],
                        'entities': [{'type': 'domain', 'value': 'evil.com'}],
                        'tags': ['phishing', 'email'],
                    },
                }

            context = ExecutionContext(
                trigger=sample_context,
                execution_id='test-run',
                tenant_id=str(tenant_id) if tenant_id else None,
            )

            # Minimal canvas_data (no edges needed for single node test)
            canvas_data = {'nodes': [node], 'edges': []}

            # Try direct kind, then common aliases
            _kind_aliases = {
                'action': 'respond', 'enrich': 'analyze', 'riggs_analyze': 'analyze',
                'condition': 'decision', 'approval_gate': 'approval',
                'notify': 'respond', 'create_ticket': 'respond',
                'webhook_call': 'respond', 'python_code': 'code',
                'variable_set': 'code', 'variable_get': 'code',
            }
            handler = (
                self._node_handlers.get(node_kind)
                or self._node_handlers.get(_kind_aliases.get(node_kind, ''))
            )
            if not handler:
                return {'ok': False, 'error': f"No handler for node type '{node_kind}'", 'outputs': {}}

            start = datetime.utcnow()
            result = await handler(node, node_config, context, canvas_data)
            duration_ms = (datetime.utcnow() - start).total_seconds() * 1000

            return {
                'ok': result.status not in ('failed', 'error'),
                'status': result.status,
                'outputs': result.outputs or {},
                'error': result.error,
                'duration_ms': round(duration_ms, 1),
            }
        except Exception as e:
            logger.error(f"test_single_node error: {e}")
            return {'ok': False, 'error': str(e), 'outputs': {}}

    async def start_execution(
        self,
        playbook_id: str,
        trigger_context: Dict[str, Any],
        triggered_by: str = "manual",
        triggered_by_user_id: Optional[str] = None,
        allow_disabled: bool = False
    ) -> Dict[str, Any]:
        """
        Start execution of a playbook.

        Args:
            playbook_id: ID of the playbook to execute
            trigger_context: Data from the trigger (alert, schedule, etc.)
            triggered_by: Source of trigger (manual, riggs, alert, schedule, webhook)
            triggered_by_user_id: User ID if triggered manually

        Returns:
            Execution record
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            # Load playbook
            async with postgres_db.tenant_acquire() as conn:
                playbook = await conn.fetchrow(
                    "SELECT * FROM playbooks WHERE id = $1",
                    playbook_id if isinstance(playbook_id, uuid.UUID) else uuid.UUID(playbook_id)
                )

                if not playbook:
                    return {"error": f"Playbook {playbook_id} not found"}

                if not playbook['is_enabled'] and not allow_disabled:
                    return {"error": "Playbook is not enabled"}

                # Create execution record
                execution_id = f"PBX-{uuid.uuid4().hex[:6].upper()}"

                # Use the Python ContextVar (set by TenantMiddleware) rather than
                # round-tripping through PostgreSQL session state, which can return
                # empty string if the connection was acquired before SET propagated.
                from middleware.tenant_middleware import get_optional_tenant_id
                tenant_id = get_optional_tenant_id()
                if not tenant_id:
                    # Fallback: read from playbook row itself
                    tenant_id = str(playbook.get('tenant_id', '')) or None
                    # tenant_acquire() skipped set_config (ContextVar was None) — set it now
                    # so the RLS policy on playbook_executions sees the correct tenant.
                    if tenant_id:
                        await conn.execute(
                            "SELECT set_config('app.current_tenant_id', $1, false)",
                            str(tenant_id)
                        )

                context = ExecutionContext(
                    trigger=trigger_context,
                    execution_id=execution_id,
                    playbook_id=str(playbook_id),
                    alert_id=trigger_context.get("alert_id"),
                    investigation_id=trigger_context.get("investigation_id"),
                    tenant_id=str(tenant_id) if tenant_id else None,
                    user_id=triggered_by_user_id
                )

                # Find start node (trigger node)
                canvas_data = playbook['canvas_data']
                if isinstance(canvas_data, str):
                    canvas_data = json.loads(canvas_data)

                nodes = canvas_data.get('nodes', [])
                start_node = next(
                    (n for n in nodes if n.get('type') == 'trigger'),
                    nodes[0] if nodes else None
                )

                if not start_node:
                    return {"error": "Playbook has no trigger node"}

                # Insert execution record
                row = await conn.fetchrow('''
                    INSERT INTO playbook_executions (
                        execution_id, playbook_id, playbook_version,
                        alert_id, investigation_id,
                        status, current_node_id,
                        execution_context, node_results,
                        triggered_by, triggered_by_user_id,
                        tenant_id,
                        started_at, timeout_at
                    ) VALUES ($1, $2, $3, $4, $5, 'running', $6, $7, '{}', $8, $9, $10, NOW(), NOW() + INTERVAL '1 hour')
                    RETURNING *
                ''',
                    execution_id,
                    playbook['id'],
                    playbook['version'],
                    uuid.UUID(context.alert_id) if context.alert_id else None,
                    uuid.UUID(context.investigation_id) if context.investigation_id else None,
                    start_node['id'],
                    json.dumps(self._json_safe(context.dict())),
                    triggered_by,
                    uuid.UUID(triggered_by_user_id) if triggered_by_user_id else None,
                    uuid.UUID(tenant_id) if tenant_id else None
                )

            # Start async execution
            asyncio.create_task(self._run_execution(
                str(row['id']),
                execution_id,
                canvas_data,
                context,
                start_node['id']
            ))

            logger.info(f"Started playbook execution: {execution_id}")

            return {
                "execution_id": execution_id,
                "playbook_id": str(playbook_id),
                "status": "running",
                "started_at": row['started_at'].isoformat() if row['started_at'] else None
            }

        except Exception as e:
            logger.error(f"Failed to start execution: {e}")
            return {"error": str(e)}

    async def resume_execution(
        self,
        execution_id: str,
        resume_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Resume a paused execution (after approval, form submission, etc.).

        Args:
            execution_id: Execution ID (PBX-XXXXXX)
            resume_data: Data to inject (form data, approval result, etc.)

        Returns:
            Updated execution status
        """
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            async with postgres_db.tenant_acquire() as conn:
                # Get execution
                execution = await conn.fetchrow(
                    "SELECT * FROM playbook_executions WHERE execution_id = $1",
                    execution_id
                )

                if not execution:
                    return {"error": f"Execution {execution_id} not found"}

                if execution['status'] not in ['waiting_approval', 'waiting_input', 'waiting_file']:
                    return {"error": f"Execution is not waiting (status: {execution['status']})"}

                # Get playbook
                playbook = await conn.fetchrow(
                    "SELECT * FROM playbooks WHERE id = $1",
                    execution['playbook_id']
                )

                if not playbook:
                    return {"error": "Playbook not found"}

                # Load context
                context_data = execution['execution_context']
                if isinstance(context_data, str):
                    context_data = json.loads(context_data)
                context = ExecutionContext(**context_data)

                # Inject resume data
                if resume_data:
                    current_node_id = execution['current_node_id']
                    context.nodes[current_node_id] = {
                        "resume_data": resume_data,
                        "status": "completed"
                    }

                # Update status
                await conn.execute('''
                    UPDATE playbook_executions
                    SET status = 'running',
                        execution_context = $1
                    WHERE execution_id = $2
                ''', json.dumps(context.dict()), execution_id)

                # Get canvas data
                canvas_data = playbook['canvas_data']
                if isinstance(canvas_data, str):
                    canvas_data = json.loads(canvas_data)

                current_node_id = execution['current_node_id']

                # Determine start node for resumed execution.
                # For action/respond nodes that were just approved, re-execute the
                # current node so the action actually fires (context now has approved
                # resume_data which causes _execute_action to skip the approval check).
                _approval_node_types = {'respond', 'action', 'edl_add', 'edl_remove'}
                canvas_nodes = canvas_data.get('nodes', [])
                current_node = next((n for n in canvas_nodes if n['id'] == current_node_id), None)
                current_node_kind = (current_node or {}).get('data', {}).get('kind', '')

                if resume_data and resume_data.get('approved') and current_node_kind in _approval_node_types:
                    # Re-execute the current node (approval already injected into context)
                    resume_from = current_node_id
                else:
                    # Standard resume: skip past the waiting node to the next one
                    next_nodes = self._get_next_nodes(canvas_data, current_node_id)
                    resume_from = next_nodes[0] if next_nodes else None

                if resume_from:
                    asyncio.create_task(self._run_execution(
                        str(execution['id']),
                        execution_id,
                        canvas_data,
                        context,
                        resume_from
                    ))

                return {
                    "execution_id": execution_id,
                    "status": "running",
                    "resumed": True
                }

        except Exception as e:
            logger.error(f"Failed to resume execution: {e}")
            return {"error": str(e)}

    async def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get execution details."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return None

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM playbook_executions WHERE execution_id = $1",
                    execution_id
                )
                return self._row_to_dict(row) if row else None

        except Exception as e:
            logger.error(f"Failed to get execution {execution_id}: {e}")
            return None

    async def cancel_execution(self, execution_id: str, reason: str = None) -> Dict[str, Any]:
        """Cancel a running execution."""
        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return {"error": "Database not connected"}

            async with postgres_db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE playbook_executions
                    SET status = 'cancelled',
                        completed_at = NOW(),
                        error_message = $1
                    WHERE execution_id = $2
                      AND status IN ('running', 'waiting_approval', 'waiting_input', 'waiting_file')
                ''', reason or "Cancelled by user", execution_id)

            return {"execution_id": execution_id, "status": "cancelled"}

        except Exception as e:
            logger.error(f"Failed to cancel execution: {e}")
            return {"error": str(e)}

    async def get_available_data_paths(
        self,
        playbook_id: str,
        node_id: str,
        execution_id: str = None
    ) -> List[Dict[str, Any]]:
        """
        Get available data paths at a specific node.

        Returns paths from trigger, previous nodes, and variables.
        """
        paths = []

        try:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                return paths

            async with postgres_db.tenant_acquire() as conn:
                # Get playbook
                playbook = await conn.fetchrow(
                    "SELECT * FROM playbooks WHERE id = $1",
                    uuid.UUID(playbook_id)
                )

                if not playbook:
                    return paths

                canvas_data = playbook['canvas_data']
                if isinstance(canvas_data, str):
                    canvas_data = json.loads(canvas_data)

                nodes = canvas_data.get('nodes', [])
                edges = canvas_data.get('edges', [])

                # Find all upstream nodes
                upstream_ids = self._get_upstream_nodes(nodes, edges, node_id)

                # Trigger paths
                paths.append({
                    "source": "trigger",
                    "path": "$.trigger",
                    "description": "Trigger data (alert, schedule, etc.)",
                    "sample_paths": [
                        "$.trigger.alert.severity",
                        "$.trigger.alert.title",
                        "$.trigger.alert.iocs",
                        "$.trigger.alert.entities"
                    ]
                })

                # Node output paths
                for uid in upstream_ids:
                    node = next((n for n in nodes if n['id'] == uid), None)
                    if node:
                        node_type = node.get('data', {}).get('kind') or node.get('type', 'unknown')
                        sample_paths = self._get_sample_paths_for_type(node_type, uid)
                        paths.append({
                            "source": "node",
                            "node_id": uid,
                            "node_type": node_type,
                            "label": node.get('data', {}).get('label', uid),
                            "path": f"$.nodes.{uid}",
                            "sample_paths": sample_paths
                        })

                # Variable paths
                paths.append({
                    "source": "variables",
                    "path": "$.variables",
                    "description": "Execution variables",
                    "sample_paths": ["$.variables.*"]
                })

                # Context paths
                paths.append({
                    "source": "context",
                    "path": "$.context",
                    "description": "Execution context",
                    "sample_paths": [
                        "$.context.execution_id",
                        "$.context.playbook_id",
                        "$.context.user_id"
                    ]
                })

                # If we have a running execution, include actual values
                if execution_id:
                    execution = await conn.fetchrow(
                        "SELECT execution_context FROM playbook_executions WHERE execution_id = $1",
                        execution_id
                    )
                    if execution:
                        context_data = execution['execution_context']
                        if isinstance(context_data, str):
                            context_data = json.loads(context_data)

                        for path in paths:
                            if path['source'] == 'node' and path['node_id'] in context_data.get('nodes', {}):
                                path['current_value'] = context_data['nodes'][path['node_id']]
                            if path['source'] == 'trigger' and context_data.get('trigger') is not None:
                                path['current_value'] = context_data.get('trigger')
                            if path['source'] == 'variables' and context_data.get('variables') is not None:
                                path['current_value'] = context_data.get('variables')

            return paths

        except Exception as e:
            logger.error(f"Failed to get data paths: {e}")
            return paths

    # ========================================================================
    # Execution Flow
    # ========================================================================

    async def _run_execution(
        self,
        db_id: str,
        execution_id: str,
        canvas_data: Dict[str, Any],
        context: ExecutionContext,
        start_node_id: str
    ):
        """
        Main execution loop - processes nodes sequentially.
        """
        try:
            from services.postgres_db import postgres_db

            nodes = canvas_data.get('nodes', [])
            edges = canvas_data.get('edges', [])

            node_results = {}

            # Execute a single node and return its result
            async def execute_single_node(node_id: str) -> Tuple[str, NodeResult]:
                """Execute a single node and return (node_id, result)."""
                node = next((n for n in nodes if n['id'] == node_id), None)
                if not node:
                    return node_id, NodeResult(
                        node_id=node_id,
                        kind="unknown",
                        status="failed",
                        error=f"Node {node_id} not found"
                    )

                # Get node kind from data.kind (frontend stores type as "signalNode", actual kind is in data.kind)
                node_type = node.get('data', {}).get('kind') or node.get('type', 'unknown')
                node_config = node.get('data', {}).get('config', {})

                logger.info(f"[{execution_id}] Executing node: {node_id} ({node_type})")

                handler = self._node_handlers.get(node_type, self._execute_unknown)
                start_time = datetime.utcnow()

                try:
                    result = await handler(node, node_config, context, canvas_data)
                except Exception as e:
                    logger.error(f"Node execution error: {e}")
                    result = NodeResult(
                        node_id=node_id,
                        kind=node_type,
                        status="failed",
                        error=str(e)
                    )

                end_time = datetime.utcnow()
                result.ended_at = end_time
                result.duration_ms = (end_time - start_time).total_seconds() * 1000

                return node_id, result

            # Recursive function to execute a branch
            async def execute_branch(start_id: str) -> Optional[str]:
                """
                Execute nodes starting from start_id until branch ends or needs merge.
                Returns error message if failed, None if successful.
                """
                current_node_id = start_id

                while current_node_id:
                    # Circuit breaker check
                    context.total_nodes_executed += 1
                    if context.total_nodes_executed > context.max_total_nodes:
                        return f"Circuit breaker: exceeded {context.max_total_nodes} nodes"

                    # Check if this is a merge node - need to verify all incoming branches completed
                    node = next((n for n in nodes if n['id'] == current_node_id), None)
                    if not node:
                        return f"Node {current_node_id} not found"

                    node_type = node.get('data', {}).get('kind') or node.get('type', 'unknown')
                    node_config = node.get('data', {}).get('config', {})

                    # Check if this node has multiple incoming edges (implicit merge point)
                    # If so, wait for all incoming branches to complete before executing
                    incoming_node_ids = self._get_incoming_node_ids(edges, current_node_id)
                    if len(incoming_node_ids) > 1:
                        all_complete = all(nid in context.completed_node_ids for nid in incoming_node_ids)
                        if not all_complete:
                            # This branch reached a convergence point but other branches aren't done yet
                            logger.info(f"[{execution_id}] Branch waiting at {current_node_id} for other branches")
                            return None  # Success, just waiting for other branches

                    # Update current node in DB
                    async with postgres_db.tenant_acquire() as conn:
                        await conn.execute('''
                            UPDATE playbook_executions
                            SET current_node_id = $1,
                                execution_context = $2
                            WHERE id = $3
                        ''', current_node_id, json.dumps(self._json_safe(context.dict())), uuid.UUID(db_id))

                    # Get retry and error policy config
                    max_retries = int(node_config.get('max_retries', 0))
                    retry_delay = float(node_config.get('retry_delay_seconds', 5))
                    error_policy = node_config.get('error_policy', 'stop')  # stop, continue, route_to_error

                    # Execute the node with retry logic
                    result = None
                    last_error = None
                    for attempt in range(max_retries + 1):
                        if attempt > 0:
                            logger.info(f"[{execution_id}] Retry {attempt}/{max_retries} for node {current_node_id}")
                            await asyncio.sleep(retry_delay)

                        _, result = await execute_single_node(current_node_id)

                        if result.status != "failed":
                            break
                        last_error = result.error
                        result.meta['attempt'] = attempt + 1

                    # Store result
                    node_results[current_node_id] = self._json_safe(result.dict())
                    if result.outputs:
                        context.nodes[current_node_id] = result.outputs

                    # Check if execution should pause
                    if result.status == "waiting":
                        waiting_status = self._get_waiting_status(node_type)

                        # Check for scheduled delay - store resume_at timestamp
                        resume_at = None
                        if result.outputs and result.outputs.get('waiting_for') == 'scheduled_delay':
                            resume_at_str = result.outputs.get('resume_at')
                            if resume_at_str:
                                resume_at = datetime.fromisoformat(resume_at_str)

                        async with postgres_db.tenant_acquire() as conn:
                            if resume_at:
                                await conn.execute('''
                                    UPDATE playbook_executions
                                    SET status = $1,
                                        current_node_id = $2,
                                        node_results = $3,
                                        execution_context = $4,
                                        resume_at = $5
                                    WHERE id = $6
                                ''',
                                    waiting_status,
                                    current_node_id,
                                    json.dumps(self._json_safe(node_results)),
                                    json.dumps(self._json_safe(context.dict())),
                                    resume_at,
                                    uuid.UUID(db_id)
                                )
                            else:
                                await conn.execute('''
                                    UPDATE playbook_executions
                                    SET status = $1,
                                        current_node_id = $2,
                                        node_results = $3,
                                        execution_context = $4
                                    WHERE id = $5
                                ''',
                                    waiting_status,
                                    current_node_id,
                                    json.dumps(self._json_safe(node_results)),
                                    json.dumps(self._json_safe(context.dict())),
                                    uuid.UUID(db_id)
                                )

                        logger.info(f"[{execution_id}] Paused at node {current_node_id} ({waiting_status})" +
                                   (f", resumes at {resume_at}" if resume_at else ""))
                        return None  # Not an error, just paused

                    # Handle node failure with error policy
                    if result.status == "failed":
                        error_msg = last_error or result.error or "Node execution failed"

                        # Store error in context for downstream access
                        context.nodes[current_node_id] = {
                            "error": error_msg,
                            "status": "failed",
                            "attempts": result.meta.get('attempt', 1)
                        }

                        if error_policy == 'continue':
                            # Log and continue to next node
                            logger.warning(f"[{execution_id}] Node {current_node_id} failed but continuing: {error_msg}")
                            context.completed_node_ids.append(current_node_id)
                            # Fall through to get next nodes

                        elif error_policy == 'route_to_error':
                            # Look for error branch edge
                            error_edge = self._get_error_edge(edges, current_node_id)
                            if error_edge:
                                logger.info(f"[{execution_id}] Routing to error handler from {current_node_id}")
                                context.completed_node_ids.append(current_node_id)
                                current_node_id = error_edge['target']
                                continue  # Skip normal next node logic
                            else:
                                # No error edge, fail
                                return error_msg

                        else:  # 'stop' (default)
                            return error_msg

                    # Mark node complete (for success or continue cases)
                    if current_node_id not in context.completed_node_ids:
                        context.completed_node_ids.append(current_node_id)

                    # Check for end node
                    if node_type == "end":
                        return None  # Success

                    # Handle loop iteration
                    if node_type == "loop" and result.outputs.get('items'):
                        items = result.outputs['items']
                        loop_variable = result.outputs.get('loop_variable', 'item')
                        next_nodes = self._get_next_nodes(canvas_data, current_node_id, result)

                        if not next_nodes:
                            return None  # No nodes to iterate over

                        max_loop_iterations = int(node_config.get('max_iterations', 500))
                        if len(items) > max_loop_iterations:
                            return (
                                f"Loop circuit breaker: {len(items)} items exceeds max "
                                f"{max_loop_iterations} iterations. Set max_iterations in node config to override."
                            )

                        logger.info(f"[{execution_id}] Loop starting {len(items)} iterations")

                        # Execute iterations sequentially (to maintain variable state)
                        iteration_results = []
                        for idx, item in enumerate(items):
                            # Set loop variable for this iteration
                            context.variables[loop_variable] = item
                            context.variables[f'{loop_variable}_index'] = idx

                            # Execute the connected nodes for this iteration
                            for next_id in next_nodes:
                                # Reset completed status for iteration nodes
                                # (they can be re-executed in each iteration)
                                iter_error = await execute_branch(next_id)
                                if iter_error:
                                    # Store partial results and fail
                                    context.nodes[current_node_id] = {
                                        **result.outputs,
                                        "iterations": iteration_results,
                                        "failed_at_index": idx,
                                        "error": iter_error
                                    }
                                    return iter_error

                            iteration_results.append({
                                "index": idx,
                                "item": item,
                                "completed": True
                            })

                        # All iterations complete
                        context.nodes[current_node_id] = {
                            **result.outputs,
                            "iterations": iteration_results,
                            "completed_count": len(iteration_results)
                        }
                        return None  # Loop complete

                    # Find next node(s)
                    next_nodes = self._get_next_nodes(canvas_data, current_node_id, result)

                    if not next_nodes:
                        return None  # Branch complete

                    if len(next_nodes) == 1:
                        # Single next node - continue sequentially
                        current_node_id = next_nodes[0]
                    else:
                        # Multiple next nodes - parallel branches
                        logger.info(f"[{execution_id}] Starting {len(next_nodes)} parallel branches from {current_node_id}")

                        # Execute all branches in parallel
                        branch_tasks = [execute_branch(nid) for nid in next_nodes]
                        branch_results = await asyncio.gather(*branch_tasks, return_exceptions=True)

                        # Check for errors in any branch
                        for i, br in enumerate(branch_results):
                            if isinstance(br, Exception):
                                return f"Branch {next_nodes[i]} failed: {str(br)}"
                            elif br is not None:  # br is error message string
                                return br

                        return None  # All branches completed successfully

                return None  # Loop exited normally

            # Start execution from the start node
            error = await execute_branch(start_node_id)

            # Finalize execution
            async with postgres_db.tenant_acquire() as conn:
                if error:
                    await conn.execute('''
                        UPDATE playbook_executions
                        SET status = 'failed',
                            completed_at = NOW(),
                            node_results = $1,
                            error_message = $2
                        WHERE id = $3
                    ''', json.dumps(self._json_safe(node_results)), error, uuid.UUID(db_id))
                    logger.info(f"[{execution_id}] Failed: {error}")
                else:
                    await conn.execute('''
                        UPDATE playbook_executions
                        SET status = 'completed',
                            completed_at = NOW(),
                            node_results = $1
                        WHERE id = $2
                    ''', json.dumps(self._json_safe(node_results)), uuid.UUID(db_id))
                    logger.info(f"[{execution_id}] Completed successfully")

        except Exception as e:
            logger.error(f"Execution error: {e}")
            try:
                from services.postgres_db import postgres_db
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute('''
                        UPDATE playbook_executions
                        SET status = 'failed',
                            completed_at = NOW(),
                            error_message = $1
                        WHERE id = $2
                    ''', str(e), uuid.UUID(db_id))
            except:
                pass

    def _get_next_nodes(
        self,
        canvas_data: Dict[str, Any],
        current_node_id: str,
        result: NodeResult = None
    ) -> List[str]:
        """Find next node(s) based on edges and result."""
        edges = canvas_data.get('edges', [])
        next_nodes = []

        for edge in edges:
            if edge.get('source') == current_node_id:
                source_handle = edge.get('sourceHandle')

                # Skip error edges - they're only followed explicitly on failure
                if source_handle == 'error':
                    continue

                if result and result.outputs and 'branch' in result.outputs:
                    # Condition node - check branch
                    branch = result.outputs['branch']
                    if source_handle == branch or source_handle == str(branch).lower():
                        next_nodes.append(edge['target'])
                elif source_handle is None or source_handle == 'default':
                    # Normal edge (no handle or default handle)
                    next_nodes.append(edge['target'])
                elif source_handle in ('yes', 'no'):
                    # Condition edge without branch output - follow all
                    next_nodes.append(edge['target'])
                else:
                    # Other handles follow normal flow
                    next_nodes.append(edge['target'])

        return next_nodes

    def _get_incoming_node_ids(
        self,
        edges: List[Dict],
        node_id: str
    ) -> List[str]:
        """Find all immediate source nodes that connect to this node."""
        incoming = []
        for edge in edges:
            if edge.get('target') == node_id:
                source = edge.get('source')
                if source:
                    incoming.append(source)
        return incoming

    def _get_error_edge(
        self,
        edges: List[Dict],
        node_id: str
    ) -> Optional[Dict]:
        """Find an error branch edge from a node (sourceHandle='error')."""
        for edge in edges:
            if edge.get('source') == node_id:
                if edge.get('sourceHandle') == 'error':
                    return edge
        return None

    def _get_upstream_nodes(
        self,
        nodes: List[Dict],
        edges: List[Dict],
        node_id: str
    ) -> List[str]:
        """Find all nodes upstream of a given node."""
        upstream = []
        visited = set()

        def trace_back(nid):
            for edge in edges:
                if edge.get('target') == nid:
                    source = edge.get('source')
                    if source and source not in visited:
                        visited.add(source)
                        upstream.append(source)
                        trace_back(source)

        trace_back(node_id)
        return upstream

    def _get_waiting_status(self, node_type: str) -> str:
        """Get the waiting status based on node type."""
        if node_type in ['approval_gate', 'action', 'edl_add', 'edl_remove']:
            return 'waiting_approval'
        elif node_type in ['webform', 'user_input']:
            return 'waiting_input'
        elif node_type == 'file_upload':
            return 'waiting_file'
        elif node_type == 'delay':
            return 'waiting_delay'
        return 'waiting_input'

    def _get_sample_paths_for_type(self, node_type: str, node_id: str) -> List[str]:
        """Get sample JSONPath expressions for a node type."""
        base = f"$.nodes.{node_id}"

        samples = {
            "riggs_analyze": [
                f"{base}.verdict",
                f"{base}.confidence",
                f"{base}.recommendations",
                f"{base}.iocs"
            ],
            "enrich": [
                f"{base}.enrichments",
                f"{base}.risk_score",
                f"{base}.categories"
            ],
            "condition": [
                f"{base}.branch",
                f"{base}.evaluated_value"
            ],
            "action": [
                f"{base}.success",
                f"{base}.result"
            ],
            "webform": [
                f"{base}.form_data",
                f"{base}.submitted_by"
            ],
            "transform": [
                f"{base}.result"
            ],
            "edl_add": [
                f"{base}.success",
                f"{base}.list_slug",
                f"{base}.added_count",
                f"{base}.items"
            ],
            "edl_remove": [
                f"{base}.success",
                f"{base}.list_slug",
                f"{base}.removed_count",
                f"{base}.items"
            ],
            "list_lookup": [
                f"{base}.found",
                f"{base}.item"
            ]
        }

        return samples.get(node_type, [f"{base}.result"])

    # ========================================================================
    # Node Handlers
    # ========================================================================

    async def _execute_trigger(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute trigger node - just passes through trigger data."""
        return NodeResult(
            node_id=node['id'],
            kind="trigger",
            status="success",
            outputs={"trigger_data": context.trigger}
        )

    async def _execute_riggs_analyze(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Execute Riggs AI analysis node.

        Uses curated analysis templates (guardrails) instead of raw user prompts.
        Calls the AI Triage Service for real AI-powered analysis.
        Requires alert_id in context.trigger or context.alert_id.
        """
        try:
            from services.ai_triage_service import AITriageService
            from config.analysis_templates import ANALYSIS_TEMPLATES, VALID_TEMPLATE_IDS, FOCUS_TO_TEMPLATE

            # Validate template_id — reject unknown templates
            template_id = config.get('template_id')
            if not template_id:
                # Backward compat: map old focus field to template
                legacy_focus = config.get('focus', 'threat_assessment')
                template_id = FOCUS_TO_TEMPLATE.get(legacy_focus, 'phishing_triage')

            if template_id not in VALID_TEMPLATE_IDS:
                return NodeResult(
                    node_id=node['id'],
                    kind="riggs_analyze",
                    status="failed",
                    error=f"Invalid analysis template: {template_id}. Choose from the available templates."
                )

            template = ANALYSIS_TEMPLATES[template_id]

            # Sanitize custom_instructions — hard cap at 500 chars, strip control chars
            custom_instructions = (config.get('custom_instructions') or '').strip()[:500]
            import re
            custom_instructions = re.sub(r'[\x00-\x1f\x7f]', '', custom_instructions)

            # Get alert data from context
            alert_data = context.trigger.get('alert', {})
            alert_id = context.alert_id or alert_data.get('alert_id') or alert_data.get('id')

            if not alert_id:
                return NodeResult(
                    node_id=node['id'],
                    kind="riggs_analyze",
                    status="failed",
                    error=(
                        "No alert_id found in execution context. "
                        "riggs_analyze requires an alert to analyze. "
                        "Ensure the playbook is triggered by an alert or alert_id is set in trigger context."
                    )
                )

            # Get enrichment data if available (from previous enrich node)
            enrichment_data = {}
            for node_id, node_result in context.nodes.items():
                if isinstance(node_result, dict) and node_result.get('kind') == 'enrich':
                    enrichment_data = node_result.get('outputs', {}).get('enrichments', {})
                    break

            # Call AI Triage Service with template guardrails
            triage_service = AITriageService()
            result = await triage_service.triage_alert(
                alert_id=str(alert_id),
                alert_data=alert_data,
                enrichment_data=enrichment_data,
                alert_flags=config.get('alert_flags'),
                template_prompt=template.get('system_prompt'),
                template_max_tokens=template.get('max_tokens', 800),
                custom_instructions=custom_instructions,
            )

            if not result:
                return NodeResult(
                    node_id=node['id'],
                    kind="riggs_analyze",
                    status="failed",
                    error="AI Triage Service returned no result"
                )

            # Map triage result to expected output format
            analysis = {
                "verdict": result.get('verdict', 'UNKNOWN'),
                "confidence": result.get('confidence', 0) / 100 if result.get('confidence', 0) > 1 else result.get('confidence', 0),
                "summary": result.get('summary') or result.get('explanation', ''),
                "recommendations": result.get('recommendations', []),
                "iocs": alert_data.get('iocs', []),
                "risk_score": int(result.get('confidence', 50)),
                "threat_type": result.get('threat_type'),
                "mitre_techniques": result.get('mitre', []),
                "affected_entities": result.get('affected_entities', []),
                "reasoning": result.get('reasoning', '')
            }

            return NodeResult(
                node_id=node['id'],
                kind="riggs_analyze",
                status="success",
                outputs=analysis
            )

        except ImportError as e:
            return NodeResult(
                node_id=node['id'],
                kind="riggs_analyze",
                status="failed",
                error=f"AI Triage Service not available: {e}"
            )
        except Exception as e:
            logger.error(f"riggs_analyze failed: {e}")
            return NodeResult(
                node_id=node['id'],
                kind="riggs_analyze",
                status="failed",
                error=str(e)
            )

    async def _execute_enrich(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute enrichment node via integration bridge."""
        try:
            # Get observable value from data path. Canvas writes observable_path;
            # legacy/imported playbooks use data_path. Accept either.
            data_path = (
                config.get('observable_path')
                or config.get('data_path')
                or '$.trigger.alert.iocs'
            )
            observable_value = self._extract_json_path(context.dict(), data_path)
            observable_type = config.get('observable_type', 'ip')

            # Get integration instance IDs. Canvas writes "sources" (list of
            # integration_instance_ids it picked); legacy uses the longer name.
            integration_instance_ids = (
                config.get('integration_instance_ids')
                or config.get('sources')
                or []
            )
            if isinstance(integration_instance_ids, str):
                integration_instance_ids = [i.strip() for i in integration_instance_ids.split(',') if i.strip()]

            # FAIL if no integrations configured - do not return fake data
            if not integration_instance_ids:
                return NodeResult(
                    node_id=node['id'],
                    kind="enrich",
                    status="failed",
                    error=(
                        "No enrichment integrations configured. "
                        "Configure integration_instance_ids in the enrich node to use VirusTotal, "
                        "AbuseIPDB, Shodan, or other enrichment integrations."
                    )
                )

            # Call integration bridge for real enrichment
            from services.playbook_integration_bridge import get_integration_bridge
            bridge = get_integration_bridge()

            # Handle single value or list of values
            values = observable_value if isinstance(observable_value, list) else [observable_value] if observable_value else []
            all_results = []
            aggregated_verdicts = []

            for value in values:
                bridge_result = await bridge.enrich_observable(
                    observable_type=observable_type,
                    observable_value=str(value),
                    integration_instance_ids=integration_instance_ids,
                    context=context.dict(),
                    tenant_id=context.tenant_id or "default"
                )
                all_results.append({
                    "value": value,
                    "ok": bridge_result.get("ok"),
                    "results": bridge_result.get("outputs", {}).get("results", []),
                    "aggregated_verdict": bridge_result.get("outputs", {}).get("aggregated_verdict")
                })
                if bridge_result.get("outputs", {}).get("aggregated_verdict"):
                    aggregated_verdicts.append(bridge_result["outputs"]["aggregated_verdict"])

            # Compute overall verdict
            overall_verdict = "unknown"
            severity_order = ["malicious", "suspicious", "clean", "unknown"]
            for sev in severity_order:
                if any(v == sev for v in aggregated_verdicts):
                    overall_verdict = sev
                    break

            return NodeResult(
                node_id=node['id'],
                kind="enrich",
                status="success",
                outputs={
                    "enrichments": all_results,
                    "count": len(all_results),
                    "aggregated_verdict": overall_verdict
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="enrich",
                status="failed",
                error=str(e)
            )

    async def _execute_analyze(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Router for consolidated analyze node — dispatches to riggs_analyze or enrich."""
        mode = config.get("mode", "ai_analysis")
        if mode == "enrich":
            return await self._execute_enrich(node, config, context, canvas_data)
        return await self._execute_riggs_analyze(node, config, context, canvas_data)

    async def _execute_ai_agent(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Generic AI agent node — runs a configurable Claude prompt and stores
        the result in context. Supports {{ $.path }} template interpolation in prompts.
        """
        try:
            from services.claude_service import get_claude_service
            import uuid as _uuid

            system_prompt = config.get('system_prompt', 'You are a helpful security analyst assistant.')
            user_prompt_template = config.get('user_prompt', '')
            model = config.get('model') or None  # None → claude_service uses default
            max_tokens = int(config.get('max_tokens', 1000))
            output_key = config.get('output_key') or node['id']
            response_format = config.get('response_format', 'text')  # 'text' or 'json'

            if not user_prompt_template:
                return NodeResult(
                    node_id=node['id'],
                    kind='ai_agent',
                    status='failed',
                    error='User prompt is required for the AI Agent node.',
                )

            # Resolve {{ $.path.to.value }} template vars
            user_prompt = self._resolve_template(user_prompt_template, context)
            system_resolved = self._resolve_template(system_prompt, context)

            # Determine tenant_id
            tenant_id_str = context.tenant_id
            if not tenant_id_str:
                return NodeResult(
                    node_id=node['id'],
                    kind='ai_agent',
                    status='failed',
                    error='No tenant_id in execution context — cannot track AI usage.',
                )

            claude = await get_claude_service()
            response = await claude.complete(
                tenant_id=_uuid.UUID(tenant_id_str),
                prompt=user_prompt,
                system=system_resolved,
                model=model,
                max_tokens=max_tokens,
                request_type='playbook_ai_agent',
            )

            text = response.text
            parsed = None
            if response_format == 'json':
                # Strip markdown code fences if present
                clean = text.strip()
                if clean.startswith('```'):
                    clean = '\n'.join(clean.split('\n')[1:])
                    if clean.endswith('```'):
                        clean = clean[:-3].strip()
                try:
                    import json as _json
                    parsed = _json.loads(clean)
                except Exception:
                    parsed = None  # Graceful: return raw text even if JSON parse fails

            outputs = {
                'text': text,
                'input_tokens': response.input_tokens,
                'output_tokens': response.output_tokens,
            }
            if parsed is not None:
                outputs['parsed'] = parsed

            # Also store under output_key so downstream nodes can reference it
            context.nodes[output_key] = outputs

            return NodeResult(
                node_id=node['id'],
                kind='ai_agent',
                status='success',
                outputs=outputs,
            )

        except Exception as e:
            logger.error(f"AI agent node error: {e}")
            return NodeResult(
                node_id=node['id'],
                kind='ai_agent',
                status='failed',
                error=str(e),
            )

    async def _execute_respond(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Router for consolidated respond node — dispatches to action, notify, or create_ticket."""
        response_type = config.get("response_type", "integration_action")
        if response_type == "notify":
            return await self._execute_notify(node, config, context, canvas_data)
        if response_type == "create_ticket":
            return await self._execute_create_ticket(node, config, context, canvas_data)
        return await self._execute_action(node, config, context, canvas_data)

    async def _execute_action(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute response action node."""
        try:
            action_type = config.get('action_type')
            requires_approval = config.get('requires_approval', False)
            target_path = config.get('target_path')

            # If this node was previously approved (resuming from waiting_approval),
            # skip the approval gate and proceed to execution.
            prior = context.nodes.get(node['id'], {})
            if isinstance(prior, dict) and prior.get('resume_data', {}).get('approved'):
                requires_approval = False

            # Extract target
            target = None
            if target_path:
                target = self._extract_json_path(context.dict(), target_path)

            if requires_approval:
                # Create approval request and wait
                from services.action_approval_service import get_action_approval_service
                approval_service = get_action_approval_service()

                approval = await approval_service.create_approval_request(
                    action_name=action_type,
                    integration_name=config.get('integration', 'generic'),
                    target_type=config.get('target_type', 'unknown'),
                    target_identifier=str(target) if target else 'unknown',
                    reason=f"Playbook action: {action_type}",
                    alert_id=context.alert_id,
                    investigation_id=context.investigation_id,
                    priority=config.get('priority', 'medium')
                )

                return NodeResult(
                    node_id=node['id'],
                    kind="action",
                    status="waiting",
                    outputs={
                        "approval_id": approval.get('approval_id'),
                        "action_type": action_type,
                        "target": target,
                        "waiting_for": "approval"
                    }
                )
            else:
                # Execute via integration bridge if instance configured
                integration_instance_id = config.get('integration_instance_id')
                endpoint_id = config.get('endpoint_id') or action_type

                if integration_instance_id:
                    from services.playbook_integration_bridge import get_integration_bridge
                    bridge = get_integration_bridge()

                    # Build params from config
                    params = config.get('params', {})
                    if target_path:
                        params['target'] = f"$.resolved_target"
                    bridge_result = await bridge.execute_action(
                        integration_instance_id=integration_instance_id,
                        endpoint_id=endpoint_id,
                        params=params,
                        context={**context.dict(), "resolved_target": target},
                        tenant_id=context.tenant_id or "default"
                    )

                    return NodeResult(
                        node_id=node['id'],
                        kind="action",
                        status="success" if bridge_result.get("ok") else "failed",
                        integration_instance_id=integration_instance_id,
                        endpoint_id=endpoint_id,
                        inputs={"resolved_params": bridge_result.get("inputs", {}).get("resolved_params", {})},
                        outputs=bridge_result.get("outputs", {}),
                        error=bridge_result.get("error"),
                        meta=bridge_result.get("meta", {})
                    )
                else:
                    # FAIL if no integration configured - do not return fake success
                    return NodeResult(
                        node_id=node['id'],
                        kind="action",
                        status="failed",
                        error=(
                            f"No integration configured for action '{action_type}'. "
                            "Configure integration_instance_id and endpoint_id in the action node "
                            "to connect to a real integration (CrowdStrike, SentinelOne, etc.)."
                        )
                    )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="action",
                status="failed",
                error=str(e)
            )

    async def _execute_condition(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute condition (if/else) node."""
        try:
            field_path = config.get('field', '')
            operator = config.get('operator', 'equals')
            value = config.get('value')

            expression = config.get('expression')
            if expression:
                parsed = self._parse_expression(expression)
                if parsed:
                    field_path, operator, value = parsed

            # Extract field value
            actual_value = self._extract_json_path(context.dict(), field_path)

            # Evaluate condition
            result = self._evaluate_condition(actual_value, operator, value)

            return NodeResult(
                node_id=node['id'],
                kind="condition",
                status="success",
                outputs={
                    "branch": "yes" if result else "no",
                    "evaluated_value": actual_value,
                    "condition": f"{field_path} {operator} {value}"
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="condition",
                status="failed",
                error=str(e)
            )

    async def _execute_switch(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute switch (multi-way branch) node."""
        try:
            field_path = config.get('field', '')
            cases = config.get('cases', {})
            default_branch = config.get('default', 'default')

            actual_value = self._extract_json_path(context.dict(), field_path)

            # Find matching case
            branch = default_branch
            for case_value, case_branch in cases.items():
                if str(actual_value) == str(case_value):
                    branch = case_branch
                    break

            return NodeResult(
                node_id=node['id'],
                kind="switch",
                status="success",
                outputs={
                    "branch": branch,
                    "evaluated_value": actual_value
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="switch",
                status="failed",
                error=str(e)
            )

    async def _execute_loop(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Execute loop node - iterates over a list.

        For each item in the list:
        1. Sets context.variables[loop_variable] = current item
        2. Sets context.variables[loop_variable + '_index'] = current index
        3. The flow continues to connected nodes which can access the loop variable

        Config:
        - items_path: JSONPath to array (e.g., '$.trigger.alert.iocs')
        - loop_variable: Name of variable to set (default: 'item')
        - max_iterations: Safety limit (default: 100)
        """
        try:
            items_path = config.get('items_path', '')
            loop_variable = config.get('loop_variable', 'item')
            max_iterations = int(config.get('max_iterations', 100))

            if not items_path:
                return NodeResult(
                    node_id=node['id'],
                    kind="loop",
                    status="failed",
                    error="items_path is required"
                )

            # Extract items from context
            items = self._extract_json_path(context.dict(), items_path)

            if items is None:
                items = []
            elif not isinstance(items, list):
                items = [items]  # Wrap single item in list

            # Apply max iterations limit
            total_items = len(items)
            if total_items > max_iterations:
                logger.warning(
                    f"Loop truncated: {total_items} items exceeds max_iterations ({max_iterations})"
                )
                items = items[:max_iterations]

            # Store loop metadata in context for downstream nodes
            context.variables[f'{loop_variable}_total'] = total_items
            context.variables[f'{loop_variable}_items'] = items

            return NodeResult(
                node_id=node['id'],
                kind="loop",
                status="success",
                outputs={
                    "items": items,
                    "total_count": total_items,
                    "processed_count": len(items),
                    "loop_variable": loop_variable,
                    "truncated": total_items > max_iterations
                }
            )

        except Exception as e:
            logger.error(f"Loop execution error: {e}")
            return NodeResult(
                node_id=node['id'],
                kind="loop",
                status="failed",
                error=str(e)
            )

    async def _execute_parallel(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Execute parallel branch start node.

        The parallel node is a marker that indicates the start of parallel execution.
        The actual parallel execution is handled in _run_execution when it detects
        multiple outgoing edges from this node (or any node).
        """
        edges = canvas_data.get('edges', [])
        outgoing_count = sum(1 for e in edges if e.get('source') == node['id'])

        return NodeResult(
            node_id=node['id'],
            kind="parallel",
            status="success",
            outputs={
                "message": f"Starting {outgoing_count} parallel branches",
                "branch_count": outgoing_count
            }
        )

    async def _execute_merge(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute merge node - combines parallel branches.

        Collects results from all incoming branches and outputs merged data.
        The merge node waits until all incoming branches have completed before
        executing (handled in execute_branch).
        """
        edges = canvas_data.get('edges', [])

        # Get all incoming node IDs
        incoming_node_ids = self._get_incoming_node_ids(edges, node['id'])

        # Collect results from each incoming branch
        branch_results = {}
        for incoming_id in incoming_node_ids:
            node_result = context.nodes.get(incoming_id)
            if node_result:
                branch_results[incoming_id] = {
                    "status": node_result.get("status"),
                    "outputs": node_result.get("outputs"),
                    "kind": node_result.get("kind"),
                }

        # Determine merge strategy from config
        merge_strategy = config.get('strategy', 'collect')  # collect, first_success, all_success

        merged_outputs = {}
        all_successful = all(
            br.get("status") == "success"
            for br in branch_results.values()
        )
        any_successful = any(
            br.get("status") == "success"
            for br in branch_results.values()
        )

        if merge_strategy == 'collect':
            # Collect all branch outputs into a single object
            merged_outputs = {
                "branches": branch_results,
                "branch_count": len(branch_results),
                "all_successful": all_successful,
            }
        elif merge_strategy == 'first_success':
            # Use first successful branch result
            for node_id, result in branch_results.items():
                if result.get("status") == "success":
                    merged_outputs = result.get("outputs", {})
                    merged_outputs["source_branch"] = node_id
                    break
        elif merge_strategy == 'all_success':
            # Fail if any branch failed
            if not all_successful:
                failed_branches = [
                    nid for nid, br in branch_results.items()
                    if br.get("status") != "success"
                ]
                return NodeResult(
                    node_id=node['id'],
                    kind="merge",
                    status="failed",
                    error=f"Branches failed: {', '.join(failed_branches)}",
                    outputs={"branches": branch_results}
                )
            merged_outputs = {
                "branches": branch_results,
                "branch_count": len(branch_results),
            }

        logger.info(
            f"[{context.execution_id}] Merge node {node['id']}: "
            f"merged {len(branch_results)} branches (strategy={merge_strategy})"
        )

        return NodeResult(
            node_id=node['id'],
            kind="merge",
            status="success",
            outputs=merged_outputs
        )

    async def _execute_utility(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Dispatcher for the unified canvas "utility" block. Reads
        config.operation and dispatches to an existing handler (or direct DB
        write) with the right shape. The 9 canvas operations are:
            update_status, update_severity, update_owner, set_sla, add_note,
            add_tag, remove_tag, edl_add, edl_remove
        set_sla / add_tag / remove_tag return a clear "not yet supported"
        error since the underlying columns aren't in the schema yet.
        """
        op = (config.get('operation') or '').strip().lower()

        # `case_update` is what Riggs and the legacy case_update node both
        # use — route it to the case update handler with status/severity/
        # resolution fields passed straight through.
        if op == 'case_update':
            target = 'investigation' if context.investigation_id else 'alert'
            payload = {
                'target': target,
                'status': config.get('status'),
                'severity': config.get('severity'),
                'resolution': config.get('resolution'),
                'disposition': config.get('disposition'),
            }
            return await self._execute_case_update(node, payload, context, canvas_data)

        if op == 'update_status':
            return await self._execute_case_update(node, {
                'target': 'alert',
                'field': 'status',
                'value': config.get('status'),
            }, context, canvas_data)

        if op == 'update_severity':
            target = 'alert' if context.alert_id else 'investigation'
            return await self._execute_case_update(node, {
                'target': target,
                'field': 'severity',
                'value': config.get('severity'),
            }, context, canvas_data)

        if op == 'update_owner':
            return await self._execute_case_update(node, {
                'target': 'investigation',
                'field': 'owner',
                'value': config.get('owner'),
            }, context, canvas_data)

        if op == 'add_note':
            if not context.investigation_id:
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='failed',
                    error="add_note requires an investigation context",
                )
            note_text = self._resolve_template(config.get('note', ''), context)
            try:
                from services.postgres_db import postgres_db
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO investigation_notes
                            (investigation_id, note_type, author, author_type,
                             content, tenant_id)
                        VALUES ($1, 'SYSTEM_NOTE', 'playbook', 'SYSTEM',
                                $2, $3::uuid)
                        """,
                        str(context.investigation_id),
                        note_text,
                        context.tenant_id,
                    )
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='success',
                    outputs={'operation': 'add_note', 'note': note_text},
                )
            except Exception as e:
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='failed',
                    error=f"add_note failed: {e}",
                )

        if op == 'edl_add':
            return await self._execute_edl_add(node, {
                'list_slug': config.get('edl_name'),
                'values_path': config.get('edl_value'),
                'static_values': config.get('static_values', ''),
                'comment': config.get('comment', 'Added by utility node'),
                'requires_approval': bool(config.get('requires_approval', False)),
                'source_type': 'playbook',
            }, context, canvas_data)

        if op == 'edl_remove':
            return await self._execute_edl_remove(node, {
                'list_slug': config.get('edl_name'),
                'values_path': config.get('edl_value'),
                'static_values': config.get('static_values', ''),
                'comment': config.get('comment', 'Removed by utility node'),
                'requires_approval': bool(config.get('requires_approval', False)),
            }, context, canvas_data)

        if op == 'set_sla':
            if not context.alert_id:
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='failed',
                    error='set_sla requires an alert context',
                )
            try:
                sla_minutes = int(config.get('sla_minutes'))
            except (TypeError, ValueError):
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='failed',
                    error='sla_minutes must be an integer',
                )
            try:
                from services.postgres_db import postgres_db
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute(
                        "UPDATE alerts SET sla_minutes = $1, updated_at = NOW() "
                        "WHERE id = $2",
                        sla_minutes,
                        uuid.UUID(context.alert_id),
                    )
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='success',
                    outputs={'operation': 'set_sla', 'sla_minutes': sla_minutes},
                )
            except Exception as e:
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='failed',
                    error=f'set_sla failed: {e}',
                )

        if op in ('add_tag', 'remove_tag'):
            if not context.alert_id:
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='failed',
                    error=f'{op} requires an alert context',
                )
            tag = (config.get('tag') or '').strip()
            if not tag:
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='failed',
                    error=f'{op} requires a non-empty tag',
                )
            sql = (
                "UPDATE alerts SET tags = array_append(tags, $1), updated_at = NOW() "
                "WHERE id = $2 AND NOT ($1 = ANY(tags))"
                if op == 'add_tag'
                else "UPDATE alerts SET tags = array_remove(tags, $1), updated_at = NOW() "
                     "WHERE id = $2"
            )
            try:
                from services.postgres_db import postgres_db
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute(sql, tag, uuid.UUID(context.alert_id))
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='success',
                    outputs={'operation': op, 'tag': tag},
                )
            except Exception as e:
                return NodeResult(
                    node_id=node['id'],
                    kind='utility',
                    status='failed',
                    error=f'{op} failed: {e}',
                )

        return NodeResult(
            node_id=node['id'],
            kind='utility',
            status='failed',
            error=f"Unknown utility operation '{op}'",
        )

    async def _execute_code(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Dispatcher for the unified canvas "code" block. Reads config.mode and
        delegates to the matching engine handler. Frontend nests mode-specific
        fields under config.script / config.assign / config.transform_config —
        unwrap into the flat shape each handler expects.
        """
        mode = (config.get('mode') or 'script').lower()

        if mode in ('script', 'function', 'python', 'python_code', 'function_call'):
            script = config.get('script') or {}
            flat = {
                'code': script.get('code', config.get('code', '')),
                'inputs': script.get('inputs', config.get('inputs', [])),
                'function_name': script.get('function_name', config.get('function_name', 'main')),
            }
            return await self._execute_python_code(node, flat, context, canvas_data)

        if mode in ('assign', 'set', 'variable_set'):
            assign = config.get('assign') or {}
            flat = {
                'name': assign.get('name', config.get('name', '')),
                'value_path': assign.get('value_path', config.get('value_path', '')),
                'static_value': assign.get('static_value', config.get('static_value', '')),
            }
            return await self._execute_variable_set(node, flat, context, canvas_data)

        if mode in ('get', 'variable_get'):
            assign = config.get('assign') or {}
            flat = {'name': assign.get('name', config.get('name', ''))}
            return await self._execute_variable_get(node, flat, context, canvas_data)

        if mode in ('extract', 'transform', 'filter', 'map'):
            flat = {
                'input_path': config.get('input_path', ''),
                'transform_type': config.get('transform_type', mode if mode != 'transform' else 'identity'),
                'transform_config': config.get('transform_config', {}),
            }
            return await self._execute_transform(node, flat, context, canvas_data)

        if mode == 'note':
            flat = {'note': config.get('note', '')}
            return await self._execute_note(node, flat, context, canvas_data)

        return NodeResult(
            node_id=node['id'],
            kind="code",
            status="failed",
            error=f"Unknown code-block mode '{mode}'",
        )

    async def _execute_python_code(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute custom Python code node (sandboxed)."""
        try:
            code = config.get('code', '')
            inputs = config.get('inputs', {})
            if isinstance(inputs, str):
                try:
                    inputs = json.loads(inputs)
                except Exception:
                    inputs = {}
            function_name = config.get('function_name', 'main') or 'main'
            # Also check the node title as function name
            if not function_name or function_name == 'main':
                node_title = node.get('data', {}).get('title', '')
                if node_title:
                    import re as _re
                    sanitized = _re.sub(r'[^a-z0-9_]', '_', node_title.lower().strip())
                    sanitized = _re.sub(r'_+', '_', sanitized).strip('_')
                    sanitized = _re.sub(r'^[0-9]+', '', sanitized)
                    if sanitized:
                        function_name = sanitized

            # Resolve input paths
            resolved_inputs = {}
            if isinstance(inputs, list):
                # New format: array of {key, value}
                # If value starts with "$." it's a data path, otherwise static
                for entry in inputs:
                    key = entry.get('key', '')
                    if not key:
                        continue
                    val = entry.get('value', '') or entry.get('path', '')
                    if entry.get('type') == 'static':
                        resolved_inputs[key] = val
                    elif isinstance(val, str) and val.startswith('$.'):
                        resolved_inputs[key] = self._extract_json_path(
                            context.dict(), val
                        )
                    else:
                        resolved_inputs[key] = val
            elif isinstance(inputs, dict):
                # Legacy format: {key: path}
                for key, path in inputs.items():
                    resolved_inputs[key] = self._extract_json_path(context.dict(), path)

            # Execute in sandbox
            from services.playbook_sandbox import execute_in_sandbox, SandboxConfig
            sandbox_result = execute_in_sandbox(
                code=code,
                inputs=resolved_inputs,
                config=SandboxConfig(),
                function_name=function_name
            )

            if not sandbox_result.success:
                return NodeResult(
                    node_id=node['id'],
                    kind="python_code",
                    status="failed",
                    error=sandbox_result.error or "Python execution failed"
                )

            result = {
                "result": sandbox_result.output,
                "stdout": sandbox_result.stdout,
                "execution_time_ms": sandbox_result.execution_time_ms,
                "memory_used_mb": sandbox_result.memory_used_mb
            }

            return NodeResult(
                node_id=node['id'],
                kind="python_code",
                status="success",
                outputs=result
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="python_code",
                status="failed",
                error=str(e)
            )

    async def _execute_function_call(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute saved function call node."""
        try:
            function_name = config.get('function_name')
            function_id = config.get('function_id')
            inputs = config.get('inputs', {})
            if isinstance(inputs, str):
                try:
                    inputs = json.loads(inputs)
                except Exception:
                    inputs = {}

            # Resolve inputs
            resolved_inputs = {}
            for key, path in inputs.items():
                resolved_inputs[key] = self._extract_json_path(context.dict(), path)

            # Load function code
            from services.postgres_db import postgres_db
            from services.playbook_sandbox import execute_in_sandbox, SandboxConfig

            async with postgres_db.tenant_acquire() as conn:
                if function_id:
                    row = await conn.fetchrow(
                        "SELECT * FROM playbook_functions WHERE id = $1",
                        uuid.UUID(function_id)
                    )
                else:
                    row = await conn.fetchrow(
                        "SELECT * FROM playbook_functions WHERE name = $1",
                        function_name
                    )

                if not row:
                    return NodeResult(
                        node_id=node['id'],
                        kind="function_call",
                        status="failed",
                        error="Function not found"
                    )

                if not row['is_approved']:
                    return NodeResult(
                        node_id=node['id'],
                        kind="function_call",
                        status="failed",
                        error="Function is not approved"
                    )

                code = row['code']
                if not function_name:
                    function_name = row['name']

            sandbox_result = execute_in_sandbox(
                code=code,
                inputs=resolved_inputs,
                config=SandboxConfig(),
                function_name=function_name or 'main'
            )

            if not sandbox_result.success:
                return NodeResult(
                    node_id=node['id'],
                    kind="function_call",
                    status="failed",
                    error=sandbox_result.error or "Function execution failed"
                )

            result = {
                "result": sandbox_result.output,
                "stdout": sandbox_result.stdout,
                "execution_time_ms": sandbox_result.execution_time_ms,
                "memory_used_mb": sandbox_result.memory_used_mb,
                "function_name": function_name
            }

            return NodeResult(
                node_id=node['id'],
                kind="function_call",
                status="success",
                outputs=result
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="function_call",
                status="failed",
                error=str(e)
            )

    async def _execute_transform(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute data transformation node."""
        try:
            input_path = config.get('input_path', '')
            transform_type = config.get('transform_type', 'identity')
            transform_config = config.get('transform_config', {})

            # Get input data
            input_data = self._extract_json_path(context.dict(), input_path)

            # Apply transformation
            if transform_type == 'extract':
                output_path = transform_config.get('output_path', '')
                result = self._extract_json_path(input_data, output_path)
            elif transform_type == 'filter':
                # Filter array items
                filter_path = transform_config.get('filter_path')
                filter_value = transform_config.get('filter_value')
                result = [item for item in (input_data or [])
                         if self._extract_json_path(item, filter_path) == filter_value]
            elif transform_type == 'map':
                # Map array items
                map_path = transform_config.get('map_path')
                result = [self._extract_json_path(item, map_path) for item in (input_data or [])]
            else:
                result = input_data

            return NodeResult(
                node_id=node['id'],
                kind="transform",
                status="success",
                outputs={"result": result}
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="transform",
                status="failed",
                error=str(e)
            )

    async def _execute_approval_gate(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute approval gate node."""
        try:
            from services.postgres_db import postgres_db

            message = config.get('message', 'Approval required to continue')
            assign_to = config.get('assign_to', 'team')
            timeout_minutes = config.get('timeout_minutes', 60)

            # Create approval request
            from middleware.tenant_middleware import get_optional_tenant_id
            async with postgres_db.tenant_acquire() as conn:
                # Resolve the execution UUID first. When running in test-node
                # mode (or before the execution row is inserted), the lookup
                # returns None and the original inline subquery used to leave
                # execution_id as NULL, violating the NOT NULL constraint.
                execution_uuid = await conn.fetchval(
                    "SELECT id FROM playbook_executions WHERE execution_id = $1",
                    context.execution_id,
                )
                if execution_uuid is None:
                    return NodeResult(
                        node_id=node['id'],
                        kind="approval_gate",
                        status="failed",
                        error=(
                            "Approval gate requires a persisted playbook execution. "
                            f"No row found in playbook_executions for execution_id='{context.execution_id}'. "
                            "Run this node from a real playbook execution rather than the test-node panel."
                        ),
                    )
                await conn.execute('''
                    INSERT INTO playbook_node_approvals (
                        execution_id, node_id, action_type, action_details,
                        reason, status, expires_at, tenant_id
                    ) VALUES (
                        $1, $2, 'approval_gate', $3, $4, 'pending',
                        NOW() + $5 * INTERVAL '1 minute', $6
                    )
                ''',
                    execution_uuid,
                    node['id'],
                    json.dumps(config),
                    message,
                    timeout_minutes,
                    get_optional_tenant_id()
                )

            return NodeResult(
                node_id=node['id'],
                kind="approval_gate",
                status="waiting",
                outputs={
                    "message": message,
                    "waiting_for": "approval",
                    "assign_to": assign_to
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="approval_gate",
                status="failed",
                error=str(e)
            )

    async def _execute_webform(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute webform node - waits for user input."""
        try:
            form_id = config.get('form_id')
            inline_fields = config.get('fields', [])
            if isinstance(inline_fields, str):
                try:
                    inline_fields = json.loads(inline_fields)
                except Exception:
                    inline_fields = []
            timeout_minutes = config.get('timeout_minutes', 60)

            return NodeResult(
                node_id=node['id'],
                kind="webform",
                status="waiting",
                outputs={
                    "form_id": form_id,
                    "fields": inline_fields,
                    "waiting_for": "form_submission",
                    "form_url": f"/forms/{context.execution_id}/{node['id']}"
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="webform",
                status="failed",
                error=str(e)
            )

    async def _execute_file_upload(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute file upload node."""
        try:
            allowed_types = config.get('allowed_types', ['*/*'])
            if isinstance(allowed_types, str):
                allowed_types = [t.strip() for t in allowed_types.split(',') if t.strip()]
            max_size_mb = config.get('max_size_mb', 10)

            return NodeResult(
                node_id=node['id'],
                kind="file_upload",
                status="waiting",
                outputs={
                    "allowed_types": allowed_types,
                    "max_size_mb": max_size_mb,
                    "waiting_for": "file_upload",
                    "upload_url": f"/upload/{context.execution_id}/{node['id']}"
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="file_upload",
                status="failed",
                error=str(e)
            )

    async def _execute_user_input(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute simple user input node."""
        try:
            prompt = config.get('prompt', 'Please provide input')
            input_type = config.get('input_type', 'text')
            options = config.get('options', [])
            if isinstance(options, str):
                options = [opt.strip() for opt in options.split(',') if opt.strip()]

            return NodeResult(
                node_id=node['id'],
                kind="user_input",
                status="waiting",
                outputs={
                    "prompt": prompt,
                    "input_type": input_type,
                    "options": options,
                    "waiting_for": "user_input"
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="user_input",
                status="failed",
                error=str(e)
            )

    async def _execute_list_lookup(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute list lookup node."""
        try:
            from services.postgres_db import postgres_db

            list_name = config.get('list_name')
            value_path = config.get('value_path')

            # Get value to look up
            value = self._extract_json_path(context.dict(), value_path)

            # Look up in list
            async with postgres_db.tenant_acquire() as conn:
                list_row = await conn.fetchrow(
                    "SELECT * FROM playbook_lists WHERE name = $1",
                    list_name
                )

                if not list_row:
                    return NodeResult(
                        node_id=node['id'],
                        kind="list_lookup",
                        status="success",
                        outputs={"found": False, "error": f"List '{list_name}' not found"}
                    )

                items = list_row['items']
                if isinstance(items, str):
                    items = json.loads(items)

                found = value in items if isinstance(items, list) else value in items.keys()

                return NodeResult(
                    node_id=node['id'],
                    kind="list_lookup",
                    status="success",
                    outputs={
                        "found": found,
                        "value": value,
                        "list_name": list_name,
                        "list_type": list_row['list_type']
                    }
                )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="list_lookup",
                status="failed",
                error=str(e)
            )

    async def _execute_list_update(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute list update node."""
        try:
            from services.postgres_db import postgres_db

            list_name = config.get('list_name')
            operation = config.get('operation', 'add')  # add or remove
            value_path = config.get('value_path')

            value = self._extract_json_path(context.dict(), value_path)

            async with postgres_db.tenant_acquire() as conn:
                if operation == 'add':
                    await conn.execute('''
                        UPDATE playbook_lists
                        SET items = items || $1::jsonb,
                            item_count = item_count + 1,
                            updated_at = NOW()
                        WHERE name = $2
                    ''', json.dumps([value]), list_name)
                else:
                    await conn.execute('''
                        UPDATE playbook_lists
                        SET items = items - $1,
                            item_count = GREATEST(0, item_count - 1),
                            updated_at = NOW()
                        WHERE name = $2
                    ''', str(value), list_name)

            return NodeResult(
                node_id=node['id'],
                kind="list_update",
                status="success",
                outputs={
                    "operation": operation,
                    "value": value,
                    "list_name": list_name
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="list_update",
                status="failed",
                error=str(e)
            )

    async def _execute_edl_add(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Execute EDL add node - adds IOCs to an External Dynamic List.

        Config:
        - list_slug: str - slug of the target EDL list
        - values_path: str - JSONPath to IOC value(s) from context
        - static_values: str - comma/newline separated static values (fallback)
        - comment: str - reason/comment for the addition
        - ttl_seconds: int - optional TTL override
        - requires_approval: bool - whether to gate behind approval (default: true)
        - source_type: str - provenance label (default: 'playbook')

        When requires_approval is true, the node pauses execution and creates
        an approval request. Once approved, it resumes and performs the add.
        """
        try:
            from services.postgres_db import postgres_db
            from services.edl_service import get_edl_service

            list_slug = config.get('list_slug')
            values_path = config.get('values_path')
            static_values = config.get('static_values', '')
            comment = config.get('comment', 'Added by playbook')
            ttl_seconds = config.get('ttl_seconds')
            requires_approval = config.get('requires_approval', False)
            source_type = config.get('source_type', 'playbook')

            if not list_slug:
                return NodeResult(
                    node_id=node['id'],
                    kind="edl_add",
                    status="failed",
                    error="list_slug is required"
                )

            # Resolve IOC values from context or static config
            values = []
            if values_path:
                extracted = self._extract_json_path(context.dict(), values_path)
                if isinstance(extracted, list):
                    values.extend([str(v) for v in extracted])
                elif extracted:
                    values.append(str(extracted))

            if static_values:
                for line in static_values.strip().split('\n'):
                    for part in line.split(','):
                        cleaned = part.strip()
                        if cleaned and not cleaned.startswith('#'):
                            values.append(cleaned)

            if not values:
                return NodeResult(
                    node_id=node['id'],
                    kind="edl_add",
                    status="failed",
                    error="No IOC values resolved"
                )

            # Deduplicate
            values = list(dict.fromkeys(values))

            # If approval is required and not yet approved, pause execution
            if requires_approval:
                async with postgres_db.tenant_acquire() as conn:
                    # Check if already approved for this node
                    existing = await conn.fetchrow('''
                        SELECT status FROM playbook_node_approvals
                        WHERE execution_id = (
                            SELECT id FROM playbook_executions WHERE execution_id = $1
                        ) AND node_id = $2
                        ORDER BY requested_at DESC LIMIT 1
                    ''', context.execution_id, node['id'])

                    if not existing or existing['status'] == 'rejected':
                        if existing and existing['status'] == 'rejected':
                            return NodeResult(
                                node_id=node['id'],
                                kind="edl_add",
                                status="failed",
                                error="Approval rejected by analyst"
                            )

                        # Create approval request. Resolve the execution
                        # UUID first; the original inline subquery used to
                        # silently insert NULL when no execution row
                        # existed, violating NOT NULL.
                        from middleware.tenant_middleware import get_optional_tenant_id
                        timeout_minutes = config.get('timeout_minutes', 60)
                        execution_uuid = await conn.fetchval(
                            "SELECT id FROM playbook_executions WHERE execution_id = $1",
                            context.execution_id,
                        )
                        if execution_uuid is None:
                            return NodeResult(
                                node_id=node['id'],
                                kind="edl_add",
                                status="failed",
                                error=(
                                    "EDL add with approval requires a persisted playbook execution. "
                                    f"No row found in playbook_executions for execution_id='{context.execution_id}'."
                                ),
                            )
                        await conn.execute('''
                            INSERT INTO playbook_node_approvals (
                                execution_id, node_id, action_type, action_details,
                                reason, status, expires_at, tenant_id
                            ) VALUES (
                                $1, $2, 'edl_add', $3, $4, 'pending',
                                NOW() + $5 * INTERVAL '1 minute', $6
                            )
                        ''',
                            execution_uuid,
                            node['id'],
                            json.dumps({
                                "list_slug": list_slug,
                                "values": values,
                                "comment": comment,
                            }),
                            f"Add {len(values)} IOC(s) to EDL list '{list_slug}'",
                            timeout_minutes,
                            get_optional_tenant_id()
                        )

                        return NodeResult(
                            node_id=node['id'],
                            kind="edl_add",
                            status="waiting",
                            outputs={
                                "message": f"Approval required: Add {len(values)} IOC(s) to EDL '{list_slug}'",
                                "waiting_for": "approval",
                                "list_slug": list_slug,
                                "values_preview": values[:10],
                                "total_values": len(values),
                            }
                        )

                    elif existing['status'] == 'pending':
                        return NodeResult(
                            node_id=node['id'],
                            kind="edl_add",
                            status="waiting",
                            outputs={
                                "message": f"Waiting for approval: Add to EDL '{list_slug}'",
                                "waiting_for": "approval",
                            }
                        )
                    # If approved, fall through to execute

            # Execute the add
            svc = get_edl_service()
            edl = await svc.get_list_by_slug(list_slug)
            if not edl:
                return NodeResult(
                    node_id=node['id'],
                    kind="edl_add",
                    status="failed",
                    error=f"EDL list not found: {list_slug}"
                )

            list_id = str(edl['list_id'])
            source_id = f"playbook:{context.playbook_id}:exec:{context.execution_id}"

            if len(values) == 1:
                await svc.add_item(
                    list_id=list_id,
                    ioc_value=values[0],
                    source_type=source_type,
                    source_id=source_id,
                    added_by=context.user_email or context.user_id or 'playbook',
                    comment=comment,
                    ttl_seconds=ttl_seconds,
                )
                result_count = 1
            else:
                result = await svc.add_items_bulk(
                    list_id=list_id,
                    ioc_values=values,
                    source_type=source_type,
                    source_id=source_id,
                    added_by=context.user_email or context.user_id or 'playbook',
                    comment=comment,
                    ttl_seconds=ttl_seconds,
                )
                result_count = result.get('added', 0)

            # Regenerate cached content so delivery endpoints serve updated list
            try:
                await svc.generate_content(list_id)
            except Exception as regen_err:
                logger.warning(f"EDL content regeneration failed after add: {regen_err}")

            logger.info(
                f"EDL playbook block: added {result_count} IOCs to '{list_slug}' "
                f"(playbook={context.playbook_id}, exec={context.execution_id})"
            )

            return NodeResult(
                node_id=node['id'],
                kind="edl_add",
                status="success",
                outputs={
                    "success": True,
                    "list_slug": list_slug,
                    "list_id": list_id,
                    "added_count": result_count,
                    "items": values,
                    "comment": comment,
                }
            )

        except Exception as e:
            logger.error(f"EDL add block failed: {e}")
            return NodeResult(
                node_id=node['id'],
                kind="edl_add",
                status="failed",
                error=str(e)
            )

    async def _execute_edl_remove(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Execute EDL remove node - removes IOCs from an External Dynamic List.

        Config:
        - list_slug: str - slug of the target EDL list
        - values_path: str - JSONPath to IOC value(s) from context
        - static_values: str - comma/newline separated static values (fallback)
        - reason: str - reason for removal
        - requires_approval: bool - whether to gate behind approval (default: true)

        When requires_approval is true, the node pauses execution and creates
        an approval request. Once approved, it resumes and performs the removal.
        """
        try:
            from services.postgres_db import postgres_db
            from services.edl_service import get_edl_service

            list_slug = config.get('list_slug')
            values_path = config.get('values_path')
            static_values = config.get('static_values', '')
            reason = config.get('reason', 'Removed by playbook')
            requires_approval = config.get('requires_approval', False)

            if not list_slug:
                return NodeResult(
                    node_id=node['id'],
                    kind="edl_remove",
                    status="failed",
                    error="list_slug is required"
                )

            # Resolve IOC values
            values = []
            if values_path:
                extracted = self._extract_json_path(context.dict(), values_path)
                if isinstance(extracted, list):
                    values.extend([str(v) for v in extracted])
                elif extracted:
                    values.append(str(extracted))

            if static_values:
                for line in static_values.strip().split('\n'):
                    for part in line.split(','):
                        cleaned = part.strip()
                        if cleaned and not cleaned.startswith('#'):
                            values.append(cleaned)

            if not values:
                return NodeResult(
                    node_id=node['id'],
                    kind="edl_remove",
                    status="failed",
                    error="No IOC values resolved"
                )

            values = list(dict.fromkeys(values))

            # Approval gate
            if requires_approval:
                async with postgres_db.tenant_acquire() as conn:
                    existing = await conn.fetchrow('''
                        SELECT status FROM playbook_node_approvals
                        WHERE execution_id = (
                            SELECT id FROM playbook_executions WHERE execution_id = $1
                        ) AND node_id = $2
                        ORDER BY requested_at DESC LIMIT 1
                    ''', context.execution_id, node['id'])

                    if not existing or existing['status'] == 'rejected':
                        if existing and existing['status'] == 'rejected':
                            return NodeResult(
                                node_id=node['id'],
                                kind="edl_remove",
                                status="failed",
                                error="Approval rejected by analyst"
                            )

                        from middleware.tenant_middleware import get_optional_tenant_id
                        timeout_minutes = config.get('timeout_minutes', 60)
                        execution_uuid = await conn.fetchval(
                            "SELECT id FROM playbook_executions WHERE execution_id = $1",
                            context.execution_id,
                        )
                        if execution_uuid is None:
                            return NodeResult(
                                node_id=node['id'],
                                kind="edl_remove",
                                status="failed",
                                error=(
                                    "EDL remove with approval requires a persisted playbook execution. "
                                    f"No row found in playbook_executions for execution_id='{context.execution_id}'."
                                ),
                            )
                        await conn.execute('''
                            INSERT INTO playbook_node_approvals (
                                execution_id, node_id, action_type, action_details,
                                reason, status, expires_at, tenant_id
                            ) VALUES (
                                $1, $2, 'edl_remove', $3, $4, 'pending',
                                NOW() + $5 * INTERVAL '1 minute', $6
                            )
                        ''',
                            execution_uuid,
                            node['id'],
                            json.dumps({
                                "list_slug": list_slug,
                                "values": values,
                                "reason": reason,
                            }),
                            f"Remove {len(values)} IOC(s) from EDL list '{list_slug}'",
                            timeout_minutes,
                            get_optional_tenant_id()
                        )

                        return NodeResult(
                            node_id=node['id'],
                            kind="edl_remove",
                            status="waiting",
                            outputs={
                                "message": f"Approval required: Remove {len(values)} IOC(s) from EDL '{list_slug}'",
                                "waiting_for": "approval",
                                "list_slug": list_slug,
                                "values_preview": values[:10],
                                "total_values": len(values),
                            }
                        )

                    elif existing['status'] == 'pending':
                        return NodeResult(
                            node_id=node['id'],
                            kind="edl_remove",
                            status="waiting",
                            outputs={
                                "message": f"Waiting for approval: Remove from EDL '{list_slug}'",
                                "waiting_for": "approval",
                            }
                        )

            # Execute the removal
            svc = get_edl_service()
            edl = await svc.get_list_by_slug(list_slug)
            if not edl:
                return NodeResult(
                    node_id=node['id'],
                    kind="edl_remove",
                    status="failed",
                    error=f"EDL list not found: {list_slug}"
                )

            list_id = str(edl['list_id'])

            if len(values) == 1:
                removed = await svc.remove_item(
                    list_id=list_id,
                    ioc_value=values[0],
                    removed_by=context.user_email or context.user_id or 'playbook',
                    reason=reason,
                )
                result_count = 1 if removed else 0
            else:
                result = await svc.remove_items_bulk(
                    list_id=list_id,
                    ioc_values=values,
                    removed_by=context.user_email or context.user_id or 'playbook',
                    reason=reason,
                )
                result_count = result.get('removed', 0)

            # Regenerate cached content so delivery endpoints serve updated list
            try:
                await svc.generate_content(list_id)
            except Exception as regen_err:
                logger.warning(f"EDL content regeneration failed after remove: {regen_err}")

            logger.info(
                f"EDL playbook block: removed {result_count} IOCs from '{list_slug}' "
                f"(playbook={context.playbook_id}, exec={context.execution_id})"
            )

            return NodeResult(
                node_id=node['id'],
                kind="edl_remove",
                status="success",
                outputs={
                    "success": True,
                    "list_slug": list_slug,
                    "list_id": list_id,
                    "removed_count": result_count,
                    "items": values,
                    "reason": reason,
                }
            )

        except Exception as e:
            logger.error(f"EDL remove block failed: {e}")
            return NodeResult(
                node_id=node['id'],
                kind="edl_remove",
                status="failed",
                error=str(e)
            )

    async def _execute_variable_set(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute variable set node."""
        try:
            var_name = config.get('name')
            value_path = config.get('value_path')
            static_value = config.get('static_value')

            if value_path:
                value = self._extract_json_path(context.dict(), value_path)
            else:
                value = static_value

            context.variables[var_name] = value

            return NodeResult(
                node_id=node['id'],
                kind="variable_set",
                status="success",
                outputs={"name": var_name, "value": value}
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="variable_set",
                status="failed",
                error=str(e)
            )

    async def _execute_variable_get(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute variable get node."""
        try:
            var_name = config.get('name')
            value = context.variables.get(var_name)

            return NodeResult(
                node_id=node['id'],
                kind="variable_get",
                status="success",
                outputs={"name": var_name, "value": value}
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="variable_get",
                status="failed",
                error=str(e)
            )

    async def _execute_notify(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Execute notification node.

        This is an action node with a friendly UI — calls the integration bridge
        with a Slack/Teams/email endpoint.
        """
        try:
            channel = config.get('channel', 'email')

            # Canvas writes channel-specific fields (email_recipients/email_subject,
            # slack_channel, teams_webhook, webhook_url). Engine originally read
            # only the generic `recipients`/`subject`/`channel_name`. Accept both.
            recipients = config.get('recipients')
            if not recipients:
                email_r = config.get('email_recipients')
                if isinstance(email_r, str):
                    recipients = [r.strip() for r in email_r.split(',') if r.strip()]
                elif isinstance(email_r, list):
                    recipients = email_r
                else:
                    recipients = []

            subject = config.get('subject') or config.get('email_subject') or 'Playbook Notification'
            message_template = config.get('message', '')

            # Channel-specific destination → channel_name for the bridge below.
            channel_name = (
                config.get('channel_name')
                or (config.get('slack_channel') if channel == 'slack' else None)
                or (config.get('teams_webhook') if channel == 'teams' else None)
                or (config.get('webhook_url') if channel == 'webhook' else None)
            )
            if channel_name:
                # Stash it back on config so the bridge call below picks it up.
                config = {**config, 'channel_name': channel_name}

            # Resolve placeholders in message
            message = self._resolve_template(message_template, context)

            # Check if a real integration instance is configured
            integration_instance_id = config.get('integration_instance_id')

            if integration_instance_id:
                from services.playbook_integration_bridge import get_integration_bridge
                bridge = get_integration_bridge()

                # Map channel to endpoint
                endpoint_map = {
                    'slack': 'send_message',
                    'teams': 'send_message',
                    'email': 'send_email',
                }
                endpoint_id = config.get('endpoint_id') or endpoint_map.get(channel, 'send_message')

                params = {
                    'channel': config.get('channel_name') or recipients[0] if recipients else '#general',
                    'text': message,
                    'subject': subject,
                    'to': recipients[0] if recipients else None,
                }

                bridge_result = await bridge.execute_action(
                    integration_instance_id=integration_instance_id,
                    endpoint_id=endpoint_id,
                    params=params,
                    context=context.dict(),
                    tenant_id=context.tenant_id or "default"
                )

                return NodeResult(
                    node_id=node['id'],
                    kind="notify",
                    status="success" if bridge_result.get("ok") else "failed",
                    integration_instance_id=integration_instance_id,
                    endpoint_id=endpoint_id,
                    outputs={
                        "channel": channel,
                        "recipients": recipients,
                        "subject": subject,
                        "message": message,
                        "sent": bridge_result.get("ok", False),
                        "raw": bridge_result.get("outputs", {}).get("raw", {})
                    },
                    error=bridge_result.get("error"),
                    meta=bridge_result.get("meta", {})
                )

            # No external integration configured. Fall back to the in-app
            # notification inbox (the bell icon) so the playbook still tells
            # somebody something useful instead of just failing.
            try:
                from services.postgres_db import postgres_db
                title = subject if subject and subject != 'Playbook Notification' else (message[:80] if message else 'Playbook notification')
                # Severity: high|warning|critical|info — map node priority + channel intent.
                priority_hint = (config.get('priority') or '').lower()
                severity = {
                    'critical': 'critical',
                    'high': 'warning',
                    'medium': 'info',
                    'low': 'info',
                    'normal': 'info',
                }.get(priority_hint, 'info')
                # Deep-link to the investigation if we have one, else the alert.
                link = None
                if context.investigation_id:
                    link = f"/investigations/{context.investigation_id}"
                elif context.alert_id:
                    link = f"/alerts/{context.alert_id}"
                async with postgres_db.tenant_acquire() as conn:
                    await conn.execute(
                        """
                        INSERT INTO notifications
                            (tenant_id, user_id, title, message, category, severity, link, metadata)
                        VALUES ($1::uuid, NULL, $2, $3, 'playbook', $4, $5, $6::jsonb)
                        """,
                        context.tenant_id,
                        title[:255],
                        message,
                        severity,
                        link,
                        json.dumps({
                            "playbook_id": context.playbook_id,
                            "execution_id": context.execution_id,
                            "node_id": node['id'],
                            "channel_requested": channel,
                            "fallback_reason": "no_integration_configured",
                        }),
                    )
                return NodeResult(
                    node_id=node['id'],
                    kind="notify",
                    status="success",
                    outputs={
                        "channel": "in_app_bell",
                        "channel_requested": channel,
                        "fallback": True,
                        "subject": title,
                        "message": message,
                        "sent": True,
                    },
                )
            except Exception as inbox_err:
                logger.exception(f"In-app notification fallback failed: {inbox_err}")
                return NodeResult(
                    node_id=node['id'],
                    kind="notify",
                    status="failed",
                    error=(
                        f"No integration configured for notification channel '{channel}', "
                        f"and the in-app notification fallback also failed: {inbox_err}"
                    ),
                )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="notify",
                status="failed",
                error=str(e)
            )

    async def _execute_create_ticket(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Execute ticket creation node.

        This is an action node with a friendly UI — calls the integration bridge
        with a Jira/ServiceNow create_issue endpoint.
        """
        try:
            # Canvas writes `system`; legacy playbooks use `integration`. Accept both.
            integration = config.get('integration') or config.get('system') or 'servicenow'
            title = config.get('title', 'Playbook Ticket')
            description = config.get('description', '')
            priority = config.get('priority', 'medium')

            # Resolve templates
            title = self._resolve_template(title, context)
            description = self._resolve_template(description, context)

            # Check if a real integration instance is configured
            integration_instance_id = config.get('integration_instance_id')

            if integration_instance_id:
                from services.playbook_integration_bridge import get_integration_bridge
                bridge = get_integration_bridge()

                endpoint_id = config.get('endpoint_id') or 'create_issue'

                params = {
                    'summary': title,
                    'title': title,
                    'description': description,
                    'priority': priority,
                    # Canvas writes project_key/issue_type/table; engine previously
                    # only passed project/issue_type. Forward all of them so the
                    # integration adapter (Jira/SNOW/etc.) picks the right one.
                    'project': config.get('project') or config.get('project_key'),
                    'project_key': config.get('project_key') or config.get('project'),
                    'issue_type': config.get('issue_type', 'Task'),
                    'table': config.get('table'),
                }

                bridge_result = await bridge.execute_action(
                    integration_instance_id=integration_instance_id,
                    endpoint_id=endpoint_id,
                    params=params,
                    context=context.dict(),
                    tenant_id=context.tenant_id or "default"
                )

                # Try to extract ticket ID from response
                ticket_id = (
                    bridge_result.get("outputs", {}).get("mapped", {}).get("key") or
                    bridge_result.get("outputs", {}).get("mapped", {}).get("id") or
                    bridge_result.get("outputs", {}).get("raw", {}).get("key") or
                    f"TKT-{uuid.uuid4().hex[:6].upper()}"
                )

                return NodeResult(
                    node_id=node['id'],
                    kind="create_ticket",
                    status="success" if bridge_result.get("ok") else "failed",
                    integration_instance_id=integration_instance_id,
                    endpoint_id=endpoint_id,
                    outputs={
                        "ticket_id": ticket_id,
                        "integration": integration,
                        "title": title,
                        "priority": priority,
                        "raw": bridge_result.get("outputs", {}).get("raw", {})
                    },
                    error=bridge_result.get("error"),
                    meta=bridge_result.get("meta", {})
                )

            # FAIL if no integration configured - do not return fake ticket
            return NodeResult(
                node_id=node['id'],
                kind="create_ticket",
                status="failed",
                error=(
                    f"No integration configured for ticketing system '{integration}'. "
                    "Configure integration_instance_id in the create_ticket node to connect to "
                    "Jira, ServiceNow, or another ticketing integration."
                )
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="create_ticket",
                status="failed",
                error=str(e)
            )

    async def _execute_webhook_call(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute webhook call node."""
        try:
            import httpx

            url = config.get('url')
            method = config.get('method', 'POST')
            headers = config.get('headers', {})
            if isinstance(headers, str):
                try:
                    headers = json.loads(headers)
                except Exception:
                    headers = {}
            body_template = config.get('body', '{}')

            # Resolve body template
            body = self._resolve_template(body_template, context)

            async with httpx.AsyncClient(timeout=30.0) as client:
                if method == 'GET':
                    response = await client.get(url, headers=headers)
                elif method == 'POST':
                    response = await client.post(url, headers=headers, content=body)
                elif method == 'PUT':
                    response = await client.put(url, headers=headers, content=body)
                else:
                    response = await client.request(method, url, headers=headers, content=body)

            return NodeResult(
                node_id=node['id'],
                kind="webhook_call",
                status="success",
                outputs={
                    "status_code": response.status_code,
                    "response": response.text[:1000] if response.text else None
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="webhook_call",
                status="failed",
                error=str(e)
            )

    async def _execute_case_update(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute case update node - update alert or investigation fields."""
        try:
            from services.postgres_db import postgres_db

            target = config.get('target')
            field = config.get('field')
            value = config.get('value')
            value_path = config.get('value_path')

            if value_path:
                value = self._extract_json_path(context.dict(), value_path)

            if not field:
                return NodeResult(
                    node_id=node['id'],
                    kind="case_update",
                    status="failed",
                    error="Missing field to update"
                )

            if not target:
                target = 'alert' if context.alert_id else 'investigation'

            # Allow-list maps user-facing field names to actual column names
            ALLOWED_ALERT_FIELDS = {
                'status': 'status', 'severity': 'severity', 'category': 'category',
                'subcategory': 'subcategory', 'confidence': 'confidence'
            }
            ALLOWED_INV_FIELDS = {
                'state': 'state', 'disposition': 'disposition', 'priority': 'priority',
                'owner': 'owner', 'severity': 'severity'
            }

            async with postgres_db.tenant_acquire() as conn:
                if target == 'alert':
                    if not context.alert_id:
                        return NodeResult(
                            node_id=node['id'],
                            kind="case_update",
                            status="failed",
                            error="No alert_id in context"
                        )
                    col = ALLOWED_ALERT_FIELDS.get(field)
                    if not col:
                        return NodeResult(
                            node_id=node['id'],
                            kind="case_update",
                            status="failed",
                            error=f"Field '{field}' not allowed for alerts"
                        )
                    await conn.execute(
                        f"UPDATE alerts SET {col} = $1, updated_at = NOW() WHERE id = $2",
                        value,
                        uuid.UUID(context.alert_id)
                    )
                else:
                    if not context.investigation_id:
                        return NodeResult(
                            node_id=node['id'],
                            kind="case_update",
                            status="failed",
                            error="No investigation_id in context"
                        )
                    col = ALLOWED_INV_FIELDS.get(field)
                    if not col:
                        return NodeResult(
                            node_id=node['id'],
                            kind="case_update",
                            status="failed",
                            error=f"Field '{field}' not allowed for investigations"
                        )
                    await conn.execute(
                        f"UPDATE investigations SET {col} = $1, updated_at = NOW() WHERE id = $2",
                        value,
                        uuid.UUID(context.investigation_id)
                    )

            return NodeResult(
                node_id=node['id'],
                kind="case_update",
                status="success",
                outputs={
                    "target": target,
                    "field": field,
                    "value": value
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="case_update",
                status="failed",
                error=str(e)
            )

    async def _execute_subflow(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute subflow node - triggers another playbook."""
        try:
            from services.postgres_db import postgres_db

            playbook_id = config.get('playbook_id')
            playbook_name = config.get('playbook_name')

            async with postgres_db.tenant_acquire() as conn:
                if playbook_id:
                    row = await conn.fetchrow(
                        "SELECT id FROM playbooks WHERE id = $1",
                        uuid.UUID(playbook_id)
                    )
                elif playbook_name:
                    row = await conn.fetchrow(
                        "SELECT id FROM playbooks WHERE name = $1",
                        playbook_name
                    )
                else:
                    row = None

            if not row:
                return NodeResult(
                    node_id=node['id'],
                    kind="subflow",
                    status="failed",
                    error="Subflow playbook not found"
                )

            target_id = str(row['id'])
            trigger_context = {
                "parent_execution_id": context.execution_id,
                "parent_node_id": node['id'],
                "parent_playbook_id": context.playbook_id,
                "trigger": context.trigger,
                "alert_id": context.alert_id,
                "investigation_id": context.investigation_id
            }

            result = await self.start_execution(
                playbook_id=target_id,
                trigger_context=trigger_context,
                triggered_by="subflow",
                triggered_by_user_id=context.user_id,
                allow_disabled=False
            )

            if "error" in result:
                return NodeResult(
                    node_id=node['id'],
                    kind="subflow",
                    status="failed",
                    error=result["error"]
                )

            return NodeResult(
                node_id=node['id'],
                kind="subflow",
                status="success",
                outputs={
                    "playbook_id": target_id,
                    "execution_id": result.get("execution_id")
                }
            )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="subflow",
                status="failed",
                error=str(e)
            )

    async def _execute_note(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute note node - no-op with metadata."""
        return NodeResult(
            node_id=node['id'],
            kind="note",
            status="success",
            outputs={"note": config.get('note')}
        )

    async def _execute_delay(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Execute delay node.

        - For delays <= 60s: actually wait (asyncio.sleep)
        - For delays > 60s: return waiting status with resume_at timestamp
          The background scheduler will resume execution after the delay
        """
        try:
            duration_seconds = int(config.get('duration_seconds', 60))

            # For short delays, actually wait
            if duration_seconds <= 60:
                await asyncio.sleep(duration_seconds)
                return NodeResult(
                    node_id=node['id'],
                    kind="delay",
                    status="success",
                    outputs={"waited_seconds": duration_seconds}
                )
            else:
                # For longer delays, schedule resumption
                resume_at = datetime.utcnow() + timedelta(seconds=duration_seconds)

                return NodeResult(
                    node_id=node['id'],
                    kind="delay",
                    status="waiting",
                    outputs={
                        "waiting_for": "scheduled_delay",
                        "duration_seconds": duration_seconds,
                        "resume_at": resume_at.isoformat(),
                        "message": f"Scheduled to resume at {resume_at.isoformat()}"
                    }
                )

        except Exception as e:
            return NodeResult(
                node_id=node['id'],
                kind="delay",
                status="failed",
                error=str(e)
            )

    async def _execute_schedule(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """
        Execute schedule node - schedules future execution.

        NOT YET IMPLEMENTED - Use delay node for timed waits,
        or configure playbook trigger_conditions with cron schedule.
        """
        return NodeResult(
            node_id=node['id'],
            kind="schedule",
            status="failed",
            error=(
                "Schedule node is not yet implemented. "
                "For timed execution: use the 'delay' node instead. "
                "For recurring schedules: configure trigger_conditions.schedule with a cron expression "
                "in the playbook settings."
            )
        )

    async def _execute_end(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Execute end node."""
        disposition = config.get('disposition', 'completed')
        summary = config.get('summary', '')

        return NodeResult(
            node_id=node['id'],
            kind="end",
            status="success",
            outputs={
                "disposition": disposition,
                "summary": self._resolve_template(summary, context) if summary else None
            }
        )

    async def _execute_unknown(
        self,
        node: Dict,
        config: Dict,
        context: ExecutionContext,
        canvas_data: Dict
    ) -> NodeResult:
        """Handle unknown node types."""
        node_kind = node.get('data', {}).get('kind') or node.get('type', 'unknown')
        return NodeResult(
            node_id=node['id'],
            kind=node_kind,
            status="failed",
            error=f"Unknown node type: {node_kind}"
        )

    # ========================================================================
    # Helpers
    # ========================================================================

    def _extract_json_path(self, data: Any, path: str) -> Any:
        """
        Extract value from data using JSONPath-like syntax.

        Supports:
        - $.field - direct field access
        - $.field.nested - nested field access
        - $.array[0] - array index
        - $.array[*] - all array elements
        """
        if not path:
            return data

        if not path.startswith('$'):
            path = '$.' + path

        # Remove leading $.
        path = path[2:] if path.startswith('$.') else path[1:]

        if not path:
            return data

        parts = self._parse_json_path(path)
        current = data

        for part in parts:
            if current is None:
                return None

            if part == '*':
                if isinstance(current, list):
                    return current
                return None

            elif part.isdigit():
                idx = int(part)
                if isinstance(current, list) and idx < len(current):
                    current = current[idx]
                else:
                    return None

            else:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None

        return current

    def _parse_json_path(self, path: str) -> List[str]:
        """Parse JSONPath into parts."""
        parts = []
        current = ''

        i = 0
        while i < len(path):
            char = path[i]

            if char == '.':
                if current:
                    parts.append(current)
                    current = ''

            elif char == '[':
                if current:
                    parts.append(current)
                    current = ''
                j = path.find(']', i)
                if j > i:
                    index = path[i+1:j]
                    parts.append(index)
                    i = j

            else:
                current += char

            i += 1

        if current:
            parts.append(current)

        return parts

    def _evaluate_condition(self, actual: Any, operator: str, expected: Any) -> bool:
        """Evaluate a condition."""
        if operator == 'equals' or operator == '==':
            return str(actual) == str(expected)
        elif operator == 'not_equals' or operator == '!=':
            return str(actual) != str(expected)
        elif operator == 'contains':
            return str(expected) in str(actual)
        elif operator == 'not_contains':
            return str(expected) not in str(actual)
        elif operator == 'greater_than' or operator == '>':
            try:
                return float(actual) > float(expected)
            except:
                return False
        elif operator == 'less_than' or operator == '<':
            try:
                return float(actual) < float(expected)
            except:
                return False
        elif operator == 'greater_or_equal' or operator == '>=':
            try:
                return float(actual) >= float(expected)
            except:
                return False
        elif operator == 'less_or_equal' or operator == '<=':
            try:
                return float(actual) <= float(expected)
            except:
                return False
        elif operator == 'is_empty':
            return not actual or (isinstance(actual, (list, dict, str)) and len(actual) == 0)
        elif operator == 'is_not_empty':
            return actual and (not isinstance(actual, (list, dict, str)) or len(actual) > 0)
        elif operator == 'in':
            if isinstance(expected, list):
                return actual in expected
            return str(actual) in str(expected).split(',')
        elif operator == 'not_in':
            if isinstance(expected, list):
                return actual not in expected
            return str(actual) not in str(expected).split(',')
        elif operator == 'matches':
            try:
                return bool(re.match(str(expected), str(actual)))
            except:
                return False
        else:
            return str(actual) == str(expected)

    def _parse_expression(self, expression: str) -> Optional[Tuple[str, str, Any]]:
        """
        Parse a simple expression. Accepts two syntaxes:
            $.path == "value"            (JSONPath)
            {{trigger.alert.foo}} == 'X' (Jinja-style, what the Riggs
                                          builder and the UI templates use)
        The Jinja form is normalized to JSONPath internally so the rest
        of the engine doesn't need to know about two dialects.
        Returns (field_path, operator, value) or None if parsing fails.
        """
        if not expression:
            return None

        # Normalize Jinja-style `{{path}}` to JSONPath `$.path` so a single
        # regex handles both. We accept `{{alert.foo}}` (implied prefix
        # under trigger.) and `{{trigger.alert.foo}}` (explicit).
        def _jinja_to_jsonpath(match):
            inner = match.group(1).strip()
            if inner.startswith('$.'):
                return inner
            if inner.startswith('trigger.') or inner == 'trigger':
                return '$.' + inner
            # Bare `alert.X`, `case.X`, `nodes.X`, `variables.X` etc.
            # are all rooted at trigger/context — prefix accordingly.
            if inner.startswith(('alert.', 'case.', 'nodes.', 'variables.')) or inner in ('alert', 'case'):
                return '$.trigger.' + inner if inner.startswith('alert') else '$.' + inner
            return '$.' + inner
        normalized = re.sub(r'\{\{([^}]+)\}\}', _jinja_to_jsonpath, expression)

        pattern = r'^\s*([\$]\.[^\s]+)\s*(==|!=|>=|<=|>|<|contains|not_contains|in|not_in)\s*(.+?)\s*$'
        match = re.match(pattern, normalized)
        if not match:
            return None

        field_path = match.group(1)
        operator = match.group(2)
        raw_value = match.group(3).strip()

        # Strip quotes
        if (raw_value.startswith('"') and raw_value.endswith('"')) or (
            raw_value.startswith("'") and raw_value.endswith("'")
        ):
            raw_value = raw_value[1:-1]

        # Try to parse JSON literals
        try:
            parsed = json.loads(raw_value)
            return field_path, operator, parsed
        except Exception:
            pass

        # Try numeric
        try:
            if '.' in raw_value:
                return field_path, operator, float(raw_value)
            return field_path, operator, int(raw_value)
        except Exception:
            return field_path, operator, raw_value

    def _resolve_template(self, template: str, context: ExecutionContext) -> str:
        """Resolve placeholders in template string."""
        if not template:
            return template

        # Replace {$.path} patterns
        pattern = r'\{\$\.([^}]+)\}'

        def replacer(match):
            path = '$.' + match.group(1)
            value = self._extract_json_path(context.dict(), path)
            return str(value) if value is not None else ''

        return re.sub(pattern, replacer, template)

    def _row_to_dict(self, row) -> Dict[str, Any]:
        """Convert database row to dictionary."""
        if not row:
            return None

        result = dict(row)

        # Convert UUID to string
        for field in ['id', 'playbook_id', 'alert_id', 'investigation_id', 'triggered_by_user_id']:
            if result.get(field):
                result[field] = str(result[field])

        # Convert datetime to ISO string
        for field in ['started_at', 'completed_at', 'timeout_at', 'created_at']:
            if result.get(field):
                result[field] = result[field].isoformat()

        # Parse JSONB fields
        for field in ['execution_context', 'node_results']:
            if result.get(field) and isinstance(result[field], str):
                try:
                    result[field] = json.loads(result[field])
                except:
                    pass

        return result


# ============================================================================
# Singleton
# ============================================================================

_engine: Optional[PlaybookEngine] = None


def get_playbook_engine() -> PlaybookEngine:
    """Get singleton playbook engine instance."""
    global _engine
    if _engine is None:
        _engine = PlaybookEngine()
    return _engine
