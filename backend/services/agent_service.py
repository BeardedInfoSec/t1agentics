# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Agent Service - Enterprise-grade AI Agent Management

Manages the lifecycle of AI agents in T1 Agentics:
- Agent CRUD operations
- Permission enforcement
- Guardrail validation
- Execution tracking
- Approval workflows
- Action rollback capabilities
- Per-agent circuit breaker

Design Principle: "Identity is cosmetic. Authority is enforced."
"""

import uuid
import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict
import asyncio

# Import the enhanced guardrail engine
from services.guardrail_engine import get_guardrail_engine, check_guardrails as enhanced_check_guardrails

logger = logging.getLogger(__name__)


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


def sanitize_for_postgres(value: Any) -> Any:
    """
    Sanitize values for PostgreSQL text columns.
    Removes null bytes (\u0000) which PostgreSQL cannot store in text columns.
    Also removes LLM special tokens like <|channel|>, <|message|>, etc.
    """
    if isinstance(value, str):
        # Remove null bytes that PostgreSQL can't handle
        cleaned = value.replace('\x00', '').replace('\u0000', '')
        # Remove LLM special tokens
        cleaned = strip_llm_tokens(cleaned)
        return cleaned
    elif isinstance(value, dict):
        return {k: sanitize_for_postgres(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [sanitize_for_postgres(item) for item in value]
    return value


class AgentTier(Enum):
    """Agent tier levels with associated risk"""
    TIER_1 = 1  # Triage & Enrichment - LOW risk
    TIER_2 = 2  # Investigation - MEDIUM risk
    TIER_3 = 3  # Response - HIGH risk


class ActionType(Enum):
    """Types of actions an agent can perform"""
    READ = "read"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class ExecutionStatus(Enum):
    """Agent execution states"""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    AWAITING_APPROVAL = "awaiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class ApprovalStatus(Enum):
    """Approval request states"""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"      # Normal operation
    OPEN = "open"          # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing if recovered


@dataclass
class CircuitBreakerConfig:
    """Configuration for per-agent circuit breaker"""
    failure_threshold: int = 5        # Failures before opening
    success_threshold: int = 3        # Successes to close from half-open
    timeout_seconds: int = 300        # Time before trying half-open
    half_open_max_calls: int = 3      # Max calls in half-open state


@dataclass
class AgentCircuitBreaker:
    """Per-agent circuit breaker to prevent cascading failures"""
    agent_id: str
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    success_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_state_change: Optional[datetime] = None
    config: CircuitBreakerConfig = field(default_factory=CircuitBreakerConfig)
    half_open_calls: int = 0

    def can_execute(self) -> tuple[bool, str]:
        """Check if execution is allowed"""
        now = datetime.utcnow()

        if self.state == CircuitState.CLOSED:
            return True, "Circuit closed - normal operation"

        elif self.state == CircuitState.OPEN:
            # Check if timeout has elapsed
            if self.last_failure_time:
                elapsed = (now - self.last_failure_time).total_seconds()
                if elapsed >= self.config.timeout_seconds:
                    # Transition to half-open
                    self.state = CircuitState.HALF_OPEN
                    self.half_open_calls = 0
                    self.last_state_change = now
                    return True, "Circuit half-open - testing recovery"
            return False, f"Circuit open - agent disabled due to {self.failure_count} failures"

        elif self.state == CircuitState.HALF_OPEN:
            if self.half_open_calls < self.config.half_open_max_calls:
                return True, "Circuit half-open - limited execution"
            return False, "Circuit half-open - max test calls reached"

        return False, "Unknown circuit state"

    def record_success(self):
        """Record successful execution"""
        now = datetime.utcnow()

        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1
            self.half_open_calls += 1

            if self.success_count >= self.config.success_threshold:
                # Recovered - close circuit
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
                self.last_state_change = now
                logger.info(f"Circuit breaker CLOSED for agent {self.agent_id} - recovered")

        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success
            if self.failure_count > 0:
                self.failure_count = max(0, self.failure_count - 1)

    def record_failure(self):
        """Record failed execution"""
        now = datetime.utcnow()
        self.failure_count += 1
        self.last_failure_time = now

        if self.state == CircuitState.HALF_OPEN:
            # Any failure in half-open reopens circuit
            self.state = CircuitState.OPEN
            self.success_count = 0
            self.last_state_change = now
            logger.warning(f"Circuit breaker REOPENED for agent {self.agent_id}")

        elif self.state == CircuitState.CLOSED:
            if self.failure_count >= self.config.failure_threshold:
                self.state = CircuitState.OPEN
                self.last_state_change = now
                logger.warning(f"Circuit breaker OPENED for agent {self.agent_id} after {self.failure_count} failures")

    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status"""
        return {
            "agent_id": self.agent_id,
            "state": self.state.value,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "last_failure": self.last_failure_time.isoformat() if self.last_failure_time else None,
            "last_state_change": self.last_state_change.isoformat() if self.last_state_change else None,
            "config": {
                "failure_threshold": self.config.failure_threshold,
                "success_threshold": self.config.success_threshold,
                "timeout_seconds": self.config.timeout_seconds
            }
        }


@dataclass
class RollbackAction:
    """Defines a rollback action that can undo an agent action"""
    original_action_id: str
    action_type: str
    target_type: str
    target_id: str
    rollback_method: str  # API endpoint or action to call
    rollback_params: Dict[str, Any]
    execution_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    rollback_executed: bool = False
    rollback_result: Optional[Dict[str, Any]] = None


# Circuit breaker registry (singleton pattern)
_circuit_breakers: Dict[str, AgentCircuitBreaker] = {}


def get_circuit_breaker(agent_id: str) -> AgentCircuitBreaker:
    """Get or create circuit breaker for an agent"""
    if agent_id not in _circuit_breakers:
        _circuit_breakers[agent_id] = AgentCircuitBreaker(agent_id=agent_id)
    return _circuit_breakers[agent_id]


def reset_circuit_breaker(agent_id: str) -> bool:
    """Manually reset a circuit breaker"""
    if agent_id in _circuit_breakers:
        _circuit_breakers[agent_id] = AgentCircuitBreaker(agent_id=agent_id)
        logger.info(f"Circuit breaker manually reset for agent {agent_id}")
        return True
    return False


@dataclass
class AgentDefinition:
    """Complete agent definition with all configuration"""
    id: str
    tier: int
    focus: str
    role: str
    system_name: str
    codename: Optional[str]
    description: str
    permissions: Dict[str, Any]
    guardrails: Dict[str, Any]
    model_config: Dict[str, Any]
    audit_config: Dict[str, Any]
    enabled: bool
    created_by: str
    created_at: datetime
    updated_at: datetime
    version: str


class AgentService:
    """
    Service for managing AI agents with enforced permissions and guardrails.
    """

    def __init__(self):
        self._postgres = None
        self._initialized = False

    async def initialize(self):
        """Initialize the service with database connection"""
        if self._initialized:
            return

        try:
            from services.postgres_db import postgres_db
            self._postgres = postgres_db
            self._initialized = True
            logger.info("Agent service initialized")
        except Exception as e:
            logger.error(f"Failed to initialize agent service: {e}")
            raise

    def _generate_system_name(self, tier: int, focus: str, role: str) -> str:
        """Generate the canonical system name for an agent"""
        return f"Tier {tier} {focus} {role} Agent"

    def _generate_agent_id(self) -> str:
        """Generate a unique agent ID"""
        return f"AGT-{uuid.uuid4().hex[:8].upper()}"

    def _generate_execution_id(self) -> str:
        """Generate a unique execution ID"""
        return f"EXE-{uuid.uuid4().hex[:12].upper()}"

    def _generate_request_id(self) -> str:
        """Generate a unique approval request ID"""
        return f"APR-{uuid.uuid4().hex[:12].upper()}"

    # =========================================================================
    # AGENT CRUD OPERATIONS
    # =========================================================================

    async def create_agent(
        self,
        tier: int,
        focus: str,
        role: str,
        description: str,
        permissions: Dict[str, Any],
        guardrails: Dict[str, Any],
        model_config: Dict[str, Any],
        audit_config: Dict[str, Any],
        codename: Optional[str] = None,
        created_by: str = "system"
    ) -> Dict[str, Any]:
        """
        Create a new agent definition.

        The system_name is auto-generated based on tier, focus, and role.
        Codename is optional and purely cosmetic.
        """
        await self.initialize()

        # Validate tier
        if tier not in [1, 2, 3]:
            raise ValueError(f"Invalid tier: {tier}. Must be 1, 2, or 3.")

        # Enforce tier-based permission restrictions
        self._validate_tier_permissions(tier, permissions)

        # Generate system name (identity is cosmetic, authority is enforced)
        system_name = self._generate_system_name(tier, focus, role)

        async with self._postgres.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                INSERT INTO agent_definitions (
                    tier, focus, role, system_name, codename, description,
                    permissions, guardrails, model_config, audit_config,
                    enabled, created_by, version
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                RETURNING *
            ''',
                tier, focus, role, system_name, codename, description,
                json.dumps(permissions), json.dumps(guardrails),
                json.dumps(model_config), json.dumps(audit_config),
                True, created_by, "1.0.0"
            )

            agent = dict(row)
            # Parse JSONB fields
            for field in ['permissions', 'guardrails', 'model_config', 'audit_config']:
                if isinstance(agent.get(field), str):
                    agent[field] = json.loads(agent[field])

            logger.info(f"Created agent: {system_name} (ID: {agent['id']})")
            return agent

    async def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get an agent by ID"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM agent_definitions WHERE id = $1',
                uuid.UUID(agent_id) if isinstance(agent_id, str) else agent_id
            )

            if row:
                agent = dict(row)
                for field in ['permissions', 'guardrails', 'model_config', 'audit_config']:
                    if isinstance(agent.get(field), str):
                        agent[field] = json.loads(agent[field])
                return agent
            return None

    async def list_agents(
        self,
        tier: Optional[int] = None,
        focus: Optional[str] = None,
        enabled_only: bool = False,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List agents with optional filters"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            query_parts = ['SELECT * FROM agent_definitions WHERE 1=1']
            params = []
            param_count = 1

            if tier is not None:
                query_parts.append(f'AND tier = ${param_count}')
                params.append(tier)
                param_count += 1

            if focus:
                query_parts.append(f'AND focus = ${param_count}')
                params.append(focus)
                param_count += 1

            if enabled_only:
                query_parts.append('AND enabled = true')

            query_parts.append(f'ORDER BY tier, focus, created_at DESC')
            query_parts.append(f'LIMIT ${param_count} OFFSET ${param_count + 1}')
            params.extend([limit, offset])

            query = ' '.join(query_parts)
            rows = await conn.fetch(query, *params)

            agents = []
            for row in rows:
                agent = dict(row)
                for field in ['permissions', 'guardrails', 'model_config', 'audit_config']:
                    if isinstance(agent.get(field), str):
                        agent[field] = json.loads(agent[field])
                agents.append(agent)

            return agents

    async def update_agent(
        self,
        agent_id: str,
        updates: Dict[str, Any],
        updated_by: str = "system"
    ) -> Optional[Dict[str, Any]]:
        """
        Update an agent definition.

        Note: tier, focus, and role cannot be changed after creation.
        To change these, create a new agent.
        """
        await self.initialize()

        # Prevent changing identity fields
        protected_fields = ['id', 'tier', 'focus', 'role', 'system_name', 'created_at', 'created_by']
        for field in protected_fields:
            if field in updates:
                raise ValueError(f"Cannot modify protected field: {field}")

        # Get current agent to validate tier restrictions
        current = await self.get_agent(agent_id)
        if not current:
            return None

        # Validate permissions against tier if being updated
        if 'permissions' in updates:
            self._validate_tier_permissions(current['tier'], updates['permissions'])

        # Build update query
        set_parts = []
        params = []
        param_count = 1

        for key, value in updates.items():
            if key in ['permissions', 'guardrails', 'model_config', 'audit_config']:
                value = json.dumps(value)
            set_parts.append(f'{key} = ${param_count}')
            params.append(value)
            param_count += 1

        set_parts.append(f'updated_at = CURRENT_TIMESTAMP')

        async with self._postgres.tenant_acquire() as conn:
            query = f'''
                UPDATE agent_definitions
                SET {', '.join(set_parts)}
                WHERE id = ${param_count}
                RETURNING *
            '''
            params.append(uuid.UUID(agent_id))

            row = await conn.fetchrow(query, *params)

            if row:
                agent = dict(row)
                for field in ['permissions', 'guardrails', 'model_config', 'audit_config']:
                    if isinstance(agent.get(field), str):
                        agent[field] = json.loads(agent[field])
                logger.info(f"Updated agent: {agent['system_name']}")
                return agent
            return None

    async def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent definition"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            result = await conn.execute(
                'DELETE FROM agent_definitions WHERE id = $1',
                uuid.UUID(agent_id)
            )
            deleted = result == 'DELETE 1'
            if deleted:
                logger.info(f"Deleted agent: {agent_id}")
            return deleted

    async def enable_agent(self, agent_id: str) -> bool:
        """Enable an agent"""
        result = await self.update_agent(agent_id, {'enabled': True})
        return result is not None

    async def disable_agent(self, agent_id: str) -> bool:
        """Disable an agent"""
        result = await self.update_agent(agent_id, {'enabled': False})
        return result is not None

    # =========================================================================
    # AGENT TEMPLATES
    # =========================================================================

    async def list_templates(
        self,
        tier: Optional[int] = None,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List available agent templates"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            query_parts = ['SELECT * FROM agent_templates WHERE 1=1']
            params = []
            param_count = 1

            if tier is not None:
                query_parts.append(f'AND tier = ${param_count}')
                params.append(tier)
                param_count += 1

            if category:
                query_parts.append(f'AND category = ${param_count}')
                params.append(category)
                param_count += 1

            query_parts.append('ORDER BY tier, name')
            query = ' '.join(query_parts)

            rows = await conn.fetch(query, *params)

            templates = []
            for row in rows:
                template = dict(row)
                for field in ['permissions', 'guardrails', 'model_config', 'audit_config']:
                    if isinstance(template.get(field), str):
                        template[field] = json.loads(template[field])
                templates.append(template)

            return templates

    async def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        """Get a template by ID"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM agent_templates WHERE template_id = $1',
                template_id
            )

            if row:
                template = dict(row)
                for field in ['permissions', 'guardrails', 'model_config', 'audit_config']:
                    if isinstance(template.get(field), str):
                        template[field] = json.loads(template[field])
                return template
            return None

    async def create_agent_from_template(
        self,
        template_id: str,
        codename: Optional[str] = None,
        description_override: Optional[str] = None,
        model_config_override: Optional[Dict[str, Any]] = None,
        created_by: str = "system"
    ) -> Dict[str, Any]:
        """Create a new agent from a template"""
        template = await self.get_template(template_id)
        if not template:
            raise ValueError(f"Template not found: {template_id}")

        # Increment usage count
        async with self._postgres.tenant_acquire() as conn:
            await conn.execute(
                'UPDATE agent_templates SET usage_count = usage_count + 1 WHERE template_id = $1',
                template_id
            )

        # Merge model_config with override (override takes precedence)
        model_config = template['model_config'].copy() if template.get('model_config') else {}
        if model_config_override:
            model_config.update(model_config_override)

        return await self.create_agent(
            tier=template['tier'],
            focus=template['focus'],
            role=template['role'],
            description=description_override or template['description'],
            permissions=template['permissions'],
            guardrails=template['guardrails'],
            model_config=model_config,
            audit_config=template['audit_config'],
            codename=codename,
            created_by=created_by
        )

    # =========================================================================
    # PERMISSION VALIDATION
    # =========================================================================

    def _validate_tier_permissions(self, tier: int, permissions: Dict[str, Any]):
        """
        Enforce tier-based permission restrictions.

        Tier 1: Read-only + enrichment
        Tier 2: Read + limited writes (tickets, comments, tags)
        Tier 3: Full access with approval requirements
        """
        applications = permissions.get('applications', [])

        for app in applications:
            actions = app.get('actions', [])
            for action in actions:
                action_type = action.get('type', 'read')

                # Tier 1: No write or destructive actions
                if tier == 1 and action_type in ['write', 'destructive']:
                    # Allow only specific write actions for Tier 1
                    allowed_tier1_writes = ['add_comment', 'add_note']
                    if action.get('action') not in allowed_tier1_writes:
                        raise ValueError(
                            f"Tier 1 agents cannot have {action_type} action: {action.get('action')}"
                        )

                # Tier 2: No destructive actions
                if tier == 2 and action_type == 'destructive':
                    raise ValueError(
                        f"Tier 2 agents cannot have destructive actions: {action.get('action')}"
                    )

                # Tier 3: Destructive actions must require approval by default
                if tier == 3 and action_type == 'destructive':
                    if not action.get('requires_approval', True):
                        logger.warning(
                            f"Tier 3 destructive action without approval requirement: {action.get('action')}"
                        )

    def validate_action_allowed(
        self,
        agent: Dict[str, Any],
        application_id: str,
        action_name: str,
        target_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check if an agent is allowed to perform a specific action.

        Returns:
            {
                "allowed": bool,
                "requires_approval": bool,
                "blocked_reason": str or None,
                "action_type": str
            }
        """
        permissions = agent.get('permissions', {})
        applications = permissions.get('applications', [])

        # Find the application
        app = next((a for a in applications if a.get('id') == application_id), None)
        if not app:
            return {
                "allowed": False,
                "requires_approval": False,
                "blocked_reason": f"Application not permitted: {application_id}",
                "action_type": None
            }

        # Find the action
        actions = app.get('actions', [])
        action = next((a for a in actions if a.get('action') == action_name), None)
        if not action:
            return {
                "allowed": False,
                "requires_approval": False,
                "blocked_reason": f"Action not permitted: {action_name}",
                "action_type": None
            }

        # Check denied targets
        denied_targets = action.get('denied_targets', [])
        if target_id and target_id in denied_targets:
            return {
                "allowed": False,
                "requires_approval": False,
                "blocked_reason": f"Target denied: {target_id}",
                "action_type": action.get('type')
            }

        # Check allowed targets (if specified, target must be in list)
        allowed_targets = action.get('allowed_targets', [])
        if allowed_targets and target_id and target_id not in allowed_targets:
            return {
                "allowed": False,
                "requires_approval": False,
                "blocked_reason": f"Target not in allowed list: {target_id}",
                "action_type": action.get('type')
            }

        # Action is allowed
        requires_approval = action.get('requires_approval', False)
        if not requires_approval:
            # Check agent-level default
            requires_approval = permissions.get('require_approval', False)

        return {
            "allowed": True,
            "requires_approval": requires_approval,
            "blocked_reason": None,
            "action_type": action.get('type')
        }

    # =========================================================================
    # GUARDRAIL CHECKING
    # =========================================================================

    def check_guardrails(
        self,
        agent: Dict[str, Any],
        action_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Check if an action violates any guardrails.

        Uses the enhanced guardrail engine with:
        - Pattern-based never rule evaluation
        - Semantic target detection (domain controllers, privileged accounts)
        - Real threat indicator detection (ransomware, lateral movement)
        - Tier-based action restrictions
        - Rate limit enforcement
        - Operating hours checks

        Returns:
            {
                "passed": bool,
                "violations": [{"rule": str, "reason": str, "severity": str, "blocked": bool}],
                "escalation_required": bool,
                "escalation_reasons": [str],
                "warnings": [str]
            }
        """
        # Use the enhanced guardrail engine
        return enhanced_check_guardrails(agent, action_context)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if an IP is private (RFC1918)"""
        if not ip:
            return False
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except:
            return False

    # =========================================================================
    # EXECUTION TRACKING
    # =========================================================================

    async def create_execution(
        self,
        agent_id: str,
        trigger_type: str,
        trigger_source_id: Optional[str] = None,
        trigger_source_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a new agent execution record"""
        await self.initialize()

        execution_id = self._generate_execution_id()

        async with self._postgres.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                INSERT INTO agent_executions (
                    execution_id, agent_id, trigger_type,
                    trigger_source_id, trigger_source_type, status
                ) VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
            ''',
                execution_id,
                uuid.UUID(agent_id),
                trigger_type,
                trigger_source_id,
                trigger_source_type,
                'pending'
            )

            execution = dict(row)
            for field in ['reasoning', 'evidence', 'actions', 'outcome', 'compliance', 'error_details']:
                if isinstance(execution.get(field), str):
                    execution[field] = json.loads(execution[field])

            logger.info(f"Created execution: {execution_id} for agent {agent_id}")
            return execution

    async def update_execution(
        self,
        execution_id: str,
        updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update an execution record"""
        await self.initialize()

        set_parts = []
        params = []
        param_count = 1

        for key, value in updates.items():
            if key in ['reasoning', 'evidence', 'actions', 'outcome', 'compliance', 'error_details', 'llm_metrics']:
                # Sanitize data before JSON encoding to remove null bytes
                value = json.dumps(sanitize_for_postgres(value))
            elif key == 'actions_taken':
                # actions_taken is an INTEGER column, not JSONB — pass as int
                value = int(value) if value is not None else 0
            elif isinstance(value, str):
                # Sanitize string values too
                value = sanitize_for_postgres(value)
            set_parts.append(f'{key} = ${param_count}')
            params.append(value)
            param_count += 1

        try:
            async with self._postgres.tenant_acquire() as conn:
                query = f'''
                    UPDATE agent_executions
                    SET {', '.join(set_parts)}
                    WHERE execution_id = ${param_count}
                    RETURNING *
                '''
                params.append(execution_id)

                row = await conn.fetchrow(query, *params)

                if row:
                    execution = dict(row)
                    for field in ['reasoning', 'evidence', 'actions', 'outcome', 'compliance', 'error_details']:
                        if isinstance(execution.get(field), str):
                            execution[field] = json.loads(execution[field])
                    return execution
                return None
        except Exception as e:
            logger.error(f"update_execution failed for {execution_id}: {e}")
            logger.error(f"Update keys: {list(updates.keys())}")
            raise

    async def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get an execution by ID"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            row = await conn.fetchrow(
                'SELECT * FROM agent_executions WHERE execution_id = $1',
                execution_id
            )

            if row:
                execution = dict(row)
                for field in ['reasoning', 'evidence', 'actions', 'outcome', 'compliance', 'error_details']:
                    if isinstance(execution.get(field), str):
                        execution[field] = json.loads(execution[field])
                return execution
            return None

    async def list_executions(
        self,
        agent_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List executions with optional filters"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            query_parts = ['SELECT * FROM agent_executions WHERE 1=1']
            params = []
            param_count = 1

            if agent_id:
                query_parts.append(f'AND agent_id = ${param_count}')
                params.append(uuid.UUID(agent_id))
                param_count += 1

            if status:
                query_parts.append(f'AND status = ${param_count}')
                params.append(status)
                param_count += 1

            query_parts.append(f'ORDER BY created_at DESC')
            query_parts.append(f'LIMIT ${param_count} OFFSET ${param_count + 1}')
            params.extend([limit, offset])

            query = ' '.join(query_parts)
            rows = await conn.fetch(query, *params)

            executions = []
            for row in rows:
                execution = dict(row)
                for field in ['reasoning', 'evidence', 'actions', 'outcome', 'compliance', 'error_details']:
                    if isinstance(execution.get(field), str):
                        execution[field] = json.loads(execution[field])
                executions.append(execution)

            return executions

    # =========================================================================
    # APPROVAL WORKFLOW
    # =========================================================================

    async def create_approval_request(
        self,
        execution_id: str,
        agent_id: str,
        action: str,
        target_type: Optional[str],
        target_id: Optional[str],
        action_type: str,
        reasoning: str,
        confidence: float,
        evidence: List[Dict[str, Any]] = None,
        timeout_minutes: int = 30
    ) -> Dict[str, Any]:
        """Create an approval request for a pending action"""
        await self.initialize()

        request_id = self._generate_request_id()
        expires_at = datetime.utcnow() + timedelta(minutes=timeout_minutes)

        async with self._postgres.tenant_acquire() as conn:
            # Get execution UUID
            exe_row = await conn.fetchrow(
                'SELECT id FROM agent_executions WHERE execution_id = $1',
                execution_id
            )
            if not exe_row:
                raise ValueError(f"Execution not found: {execution_id}")

            row = await conn.fetchrow('''
                INSERT INTO agent_approval_requests (
                    request_id, execution_id, agent_id, action,
                    target_type, target_id, action_type, reasoning,
                    confidence, evidence, expires_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                RETURNING *
            ''',
                request_id,
                exe_row['id'],
                uuid.UUID(agent_id),
                action,
                target_type,
                target_id,
                action_type,
                reasoning,
                confidence,
                json.dumps(evidence or []),
                expires_at
            )

            request = dict(row)
            if isinstance(request.get('evidence'), str):
                request['evidence'] = json.loads(request['evidence'])

            logger.info(f"Created approval request: {request_id}")

            # Send notification for the approval request
            await self._notify_approval_request(request_id, agent_id, action, target_type, target_id, reasoning, confidence, expires_at)

            return request

    async def _notify_approval_request(
        self,
        request_id: str,
        agent_id: str,
        action: str,
        target_type: Optional[str],
        target_id: Optional[str],
        reasoning: str,
        confidence: float,
        expires_at: datetime
    ):
        """Send notification for a new approval request via email/Slack/Teams"""
        try:
            from services.email_service import get_email_service

            email_service = get_email_service()
            if not email_service.db:
                email_service.set_db(self._postgres)
                await email_service.initialize()

            # Get agent name for the notification
            agent_name = "Unknown Agent"
            async with self._postgres.tenant_acquire() as conn:
                agent_row = await conn.fetchrow(
                    'SELECT system_name, codename, tier FROM agent_definitions WHERE id = $1',
                    uuid.UUID(agent_id)
                )
                if agent_row:
                    agent_name = agent_row['codename'] or agent_row['system_name']
                    tier = agent_row['tier']

            # Build notification data
            notification_data = {
                'title': f'Agent Action Requires Approval: {action}',
                'severity': 'high',  # Approval requests are always high priority
                'alert_id': request_id,
                'source': f'AI Agent: {agent_name} (Tier {tier})',
                'description': f'''Agent "{agent_name}" is requesting approval to perform:

Action: {action}
Target: {target_type or 'N/A'} - {target_id or 'N/A'}
Confidence: {confidence:.0%}
Expires: {expires_at.strftime('%Y-%m-%d %H:%M UTC')}

Reasoning: {reasoning[:500]}''',
                'request_id': request_id,
                'agent_name': agent_name,
                'action': action,
                'target_type': target_type,
                'target_id': target_id,
                'confidence': confidence,
                'expires_at': expires_at.isoformat()
            }

            # Send notification - the email service will check configured rules
            sent = await email_service.notify_event(
                event_type='agent_approval_required',
                data=notification_data,
                skip_rate_limit=True  # Don't rate limit approval requests
            )

            if sent > 0:
                logger.info(f"Sent {sent} notifications for approval request {request_id}")
            else:
                logger.debug(f"No notifications configured for approval requests")

        except Exception as e:
            # Don't fail the approval creation if notification fails
            logger.error(f"Failed to send approval notification: {e}")

    async def list_pending_approvals(
        self,
        agent_id: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """List pending approval requests"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            query_parts = ['''
                SELECT ar.*, ad.system_name as agent_name, ad.codename as agent_codename
                FROM agent_approval_requests ar
                JOIN agent_definitions ad ON ar.agent_id = ad.id
                WHERE ar.status = 'pending' AND ar.expires_at > CURRENT_TIMESTAMP
            ''']
            params = []
            param_count = 1

            if agent_id:
                query_parts.append(f'AND ar.agent_id = ${param_count}')
                params.append(uuid.UUID(agent_id))
                param_count += 1

            query_parts.append('ORDER BY ar.requested_at ASC')
            query_parts.append(f'LIMIT ${param_count}')
            params.append(limit)

            query = ' '.join(query_parts)
            rows = await conn.fetch(query, *params)

            requests = []
            for row in rows:
                request = dict(row)
                if isinstance(request.get('evidence'), str):
                    request['evidence'] = json.loads(request['evidence'])
                requests.append(request)

            return requests

    async def approve_request(
        self,
        request_id: str,
        approved_by: str,
        note: Optional[str] = None
    ) -> Dict[str, Any]:
        """Approve a pending request"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                UPDATE agent_approval_requests
                SET status = 'approved',
                    responded_by = $1,
                    responded_at = CURRENT_TIMESTAMP,
                    response_note = $2
                WHERE request_id = $3 AND status = 'pending'
                RETURNING *
            ''', approved_by, note, request_id)

            if row:
                request = dict(row)
                logger.info(f"Approved request: {request_id} by {approved_by}")
                return request
            return None

    async def deny_request(
        self,
        request_id: str,
        denied_by: str,
        note: Optional[str] = None
    ) -> Dict[str, Any]:
        """Deny a pending request"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                UPDATE agent_approval_requests
                SET status = 'denied',
                    responded_by = $1,
                    responded_at = CURRENT_TIMESTAMP,
                    response_note = $2
                WHERE request_id = $3 AND status = 'pending'
                RETURNING *
            ''', denied_by, note, request_id)

            if row:
                request = dict(row)
                logger.info(f"Denied request: {request_id} by {denied_by}")
                return request
            return None

    # =========================================================================
    # ACTION LOGGING
    # =========================================================================

    async def log_action(
        self,
        execution_id: str,
        agent_id: str,
        action: str,
        action_type: str,
        status: str,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        required_approval: bool = False,
        reasoning: Optional[str] = None,
        confidence: Optional[float] = None,
        result: Optional[Dict[str, Any]] = None,
        error_message: Optional[str] = None,
        blocked_by_guardrail: Optional[str] = None,
        guardrail_rule: Optional[str] = None
    ) -> Dict[str, Any]:
        """Log an action in the immutable audit trail"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            # Get execution UUID
            exe_row = await conn.fetchrow(
                'SELECT id FROM agent_executions WHERE execution_id = $1',
                execution_id
            )
            if not exe_row:
                raise ValueError(f"Execution not found: {execution_id}")

            # Sanitize string values to remove null bytes that PostgreSQL can't handle
            sanitized_action = sanitize_for_postgres(action) if action else action
            sanitized_reasoning = sanitize_for_postgres(reasoning) if reasoning else reasoning
            sanitized_result = json.dumps(sanitize_for_postgres(result)) if result else None
            sanitized_error = sanitize_for_postgres(error_message) if error_message else error_message

            row = await conn.fetchrow('''
                INSERT INTO agent_action_log (
                    execution_id, agent_id, action, action_type, status,
                    target_type, target_id, required_approval, reasoning,
                    confidence, result, error_message, blocked_by_guardrail,
                    guardrail_rule
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                RETURNING *
            ''',
                exe_row['id'],
                uuid.UUID(agent_id),
                sanitized_action,
                action_type,
                status,
                target_type,
                target_id,
                required_approval,
                sanitized_reasoning,
                confidence,
                sanitized_result,
                sanitized_error,
                blocked_by_guardrail,
                guardrail_rule
            )

            log_entry = dict(row)
            if isinstance(log_entry.get('result'), str):
                log_entry['result'] = json.loads(log_entry['result'])

            # Also write to main audit_log for admin visibility
            try:
                # Get agent name for the audit log
                agent_row = await conn.fetchrow(
                    'SELECT system_name, codename FROM agent_definitions WHERE id = $1',
                    uuid.UUID(agent_id)
                )
                agent_name = agent_row['codename'] or agent_row['system_name'] if agent_row else 'Unknown Agent'

                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = get_optional_tenant_id()

                await conn.execute('''
                    INSERT INTO audit_log (username, action, resource_type, resource_id, details, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6)
                ''',
                    f"AI:{agent_name}",  # Username shows it's from AI agent
                    sanitized_action,
                    target_type or 'agent_action',
                    target_id or execution_id,
                    json.dumps(sanitize_for_postgres({
                        'execution_id': execution_id,
                        'action_type': action_type,
                        'status': status,
                        'reasoning': reasoning,
                        'confidence': confidence
                    })),
                    uuid.UUID(str(_tenant_id)) if _tenant_id else None
                )
            except Exception as audit_err:
                logger.warning(f"Failed to write to audit_log: {audit_err}")

            return log_entry

    async def get_action_log(
        self,
        execution_id: str
    ) -> List[Dict[str, Any]]:
        """Get all actions for an execution"""
        await self.initialize()

        async with self._postgres.tenant_acquire() as conn:
            # Get execution UUID
            exe_row = await conn.fetchrow(
                'SELECT id FROM agent_executions WHERE execution_id = $1',
                execution_id
            )
            if not exe_row:
                return []

            rows = await conn.fetch('''
                SELECT * FROM agent_action_log
                WHERE execution_id = $1
                ORDER BY created_at ASC
            ''', exe_row['id'])

            actions = []
            for row in rows:
                action = dict(row)
                if isinstance(action.get('result'), str):
                    action['result'] = json.loads(action['result'])
                actions.append(action)

            return actions

    # =========================================================================
    # CIRCUIT BREAKER INTEGRATION
    # =========================================================================

    async def check_circuit_breaker(self, agent_id: str) -> Dict[str, Any]:
        """
        Check if an agent's circuit breaker allows execution.

        Returns:
            {
                "allowed": bool,
                "reason": str,
                "circuit_state": str,
                "failure_count": int
            }
        """
        circuit = get_circuit_breaker(agent_id)
        can_execute, reason = circuit.can_execute()

        return {
            "allowed": can_execute,
            "reason": reason,
            "circuit_state": circuit.state.value,
            "failure_count": circuit.failure_count
        }

    async def record_execution_result(
        self,
        agent_id: str,
        execution_id: str,
        success: bool,
        error_message: Optional[str] = None
    ):
        """
        Record execution result for circuit breaker tracking.

        Called after each agent execution completes.
        """
        circuit = get_circuit_breaker(agent_id)

        if success:
            circuit.record_success()
        else:
            circuit.record_failure()

            # If circuit opened, log to database
            if circuit.state == CircuitState.OPEN:
                await self._log_circuit_event(
                    agent_id, execution_id, 'circuit_opened',
                    f"Circuit opened after {circuit.failure_count} failures: {error_message}"
                )

    async def _log_circuit_event(
        self,
        agent_id: str,
        execution_id: str,
        event_type: str,
        details: str
    ):
        """Log circuit breaker events for monitoring"""
        try:
            async with self._postgres.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = get_optional_tenant_id()

                await conn.execute('''
                    INSERT INTO audit_log (username, action, resource_type, resource_id, details, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6)
                ''',
                    'SYSTEM:CircuitBreaker',
                    event_type,
                    'agent',
                    agent_id,
                    json.dumps({
                        'execution_id': execution_id,
                        'details': details,
                        'timestamp': datetime.utcnow().isoformat()
                    }),
                    uuid.UUID(str(_tenant_id)) if _tenant_id else None
                )
        except Exception as e:
            logger.error(f"Failed to log circuit event: {e}")

    async def get_all_circuit_breakers(self) -> List[Dict[str, Any]]:
        """Get status of all circuit breakers"""
        return [cb.get_status() for cb in _circuit_breakers.values()]

    async def reset_agent_circuit_breaker(self, agent_id: str, reset_by: str) -> bool:
        """Manually reset a circuit breaker (admin action)"""
        success = reset_circuit_breaker(agent_id)

        if success:
            await self._log_circuit_event(
                agent_id, '',
                'circuit_reset',
                f'Manually reset by {reset_by}'
            )

        return success

    # =========================================================================
    # ACTION ROLLBACK CAPABILITIES
    # =========================================================================

    # Registry of rollback handlers by action type
    ROLLBACK_HANDLERS = {
        'block_ip': 'unblock_ip',
        'unblock_ip': 'block_ip',
        'disable_user': 'enable_user',
        'enable_user': 'disable_user',
        'quarantine_file': 'restore_file',
        'restore_file': 'quarantine_file',
        'isolate_endpoint': 'reconnect_endpoint',
        'reconnect_endpoint': 'isolate_endpoint',
        'add_to_blocklist': 'remove_from_blocklist',
        'remove_from_blocklist': 'add_to_blocklist',
        'revoke_session': None,  # Cannot undo
        'delete_email': None,    # Cannot undo
    }

    async def create_rollback_record(
        self,
        execution_id: str,
        action_id: str,
        action_type: str,
        target_type: str,
        target_id: str,
        action_params: Dict[str, Any]
    ) -> Optional[str]:
        """
        Create a rollback record for a completed action.

        This enables "undo" functionality for agent actions.
        """
        await self.initialize()

        # Determine rollback method
        rollback_method = self.ROLLBACK_HANDLERS.get(action_type)
        if not rollback_method:
            logger.debug(f"No rollback available for action type: {action_type}")
            return None

        # Build rollback params (mirror of original action)
        rollback_params = {
            'target_type': target_type,
            'target_id': target_id,
            'original_action': action_type,
            'original_params': action_params
        }

        try:
            async with self._postgres.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    INSERT INTO agent_rollback_actions (
                        execution_id, original_action_id, original_action_type,
                        target_type, target_id, rollback_method, rollback_params,
                        expires_at
                    ) VALUES (
                        (SELECT id FROM agent_executions WHERE execution_id = $1),
                        $2, $3, $4, $5, $6, $7, $8
                    )
                    RETURNING id
                ''',
                    execution_id,
                    action_id,
                    action_type,
                    target_type,
                    target_id,
                    rollback_method,
                    json.dumps(rollback_params),
                    datetime.utcnow() + timedelta(hours=24)  # 24hr rollback window
                )

                logger.info(f"Created rollback record for {action_type} on {target_type}:{target_id}")
                return str(row['id']) if row else None

        except Exception as e:
            logger.error(f"Failed to create rollback record: {e}")
            return None

    async def get_rollback_actions(
        self,
        execution_id: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        include_expired: bool = False,
        include_executed: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Get available rollback actions.

        Args:
            execution_id: Filter by execution
            target_type: Filter by target type
            target_id: Filter by target ID
            include_expired: Include expired rollbacks
            include_executed: Include already-executed rollbacks
        """
        await self.initialize()

        try:
            async with self._postgres.tenant_acquire() as conn:
                query_parts = ['SELECT * FROM agent_rollback_actions WHERE 1=1']
                params = []
                param_count = 1

                if execution_id:
                    query_parts.append(f'''
                        AND execution_id = (
                            SELECT id FROM agent_executions WHERE execution_id = ${param_count}
                        )
                    ''')
                    params.append(execution_id)
                    param_count += 1

                if target_type:
                    query_parts.append(f'AND target_type = ${param_count}')
                    params.append(target_type)
                    param_count += 1

                if target_id:
                    query_parts.append(f'AND target_id = ${param_count}')
                    params.append(target_id)
                    param_count += 1

                if not include_expired:
                    query_parts.append('AND expires_at > CURRENT_TIMESTAMP')

                if not include_executed:
                    query_parts.append('AND executed_at IS NULL')

                query_parts.append('ORDER BY created_at DESC')
                query = ' '.join(query_parts)

                rows = await conn.fetch(query, *params)

                results = []
                for row in rows:
                    r = dict(row)
                    if isinstance(r.get('rollback_params'), str):
                        r['rollback_params'] = json.loads(r['rollback_params'])
                    if isinstance(r.get('result'), str):
                        r['result'] = json.loads(r['result'])
                    results.append(r)

                return results

        except Exception as e:
            logger.error(f"Failed to get rollback actions: {e}")
            return []

    async def execute_rollback(
        self,
        rollback_id: str,
        executed_by: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute a rollback action to undo a previous agent action.

        Args:
            rollback_id: ID of the rollback record
            executed_by: Username executing the rollback
            reason: Reason for the rollback

        Returns:
            Result of the rollback attempt
        """
        await self.initialize()

        try:
            async with self._postgres.tenant_acquire() as conn:
                # Get rollback record
                row = await conn.fetchrow('''
                    SELECT * FROM agent_rollback_actions WHERE id = $1
                ''', uuid.UUID(rollback_id))

                if not row:
                    return {"success": False, "error": "Rollback record not found"}

                rollback = dict(row)

                # Check if expired
                if rollback['expires_at'] < datetime.utcnow():
                    return {"success": False, "error": "Rollback has expired"}

                # Check if already executed
                if rollback['executed_at']:
                    return {"success": False, "error": "Rollback already executed"}

                rollback_params = json.loads(rollback['rollback_params']) if isinstance(rollback['rollback_params'], str) else rollback['rollback_params']

                # Execute the rollback via integration framework
                result = await self._execute_rollback_action(
                    rollback['rollback_method'],
                    rollback['target_type'],
                    rollback['target_id'],
                    rollback_params
                )

                # Update rollback record
                await conn.execute('''
                    UPDATE agent_rollback_actions
                    SET executed_at = CURRENT_TIMESTAMP,
                        executed_by = $1,
                        success = $2,
                        result = $3,
                        execution_note = $4
                    WHERE id = $5
                ''',
                    executed_by,
                    result.get('success', False),
                    json.dumps(result),
                    reason,
                    uuid.UUID(rollback_id)
                )

                # Log to audit trail
                from middleware.tenant_middleware import get_optional_tenant_id
                _tenant_id = get_optional_tenant_id()

                await conn.execute('''
                    INSERT INTO audit_log (username, action, resource_type, resource_id, details, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6)
                ''',
                    executed_by,
                    f"rollback_{rollback['rollback_method']}",
                    rollback['target_type'],
                    rollback['target_id'],
                    json.dumps({
                        'rollback_id': rollback_id,
                        'original_action': rollback['original_action_type'],
                        'reason': reason,
                        'result': result
                    }),
                    uuid.UUID(str(_tenant_id)) if _tenant_id else None
                )

                logger.info(f"Executed rollback {rollback_id} by {executed_by}: {result.get('success')}")

                return result

        except Exception as e:
            logger.error(f"Failed to execute rollback: {e}")
            return {"success": False, "error": str(e)}

    async def _execute_rollback_action(
        self,
        method: str,
        target_type: str,
        target_id: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute the actual rollback action.

        This connects to the integration framework to perform the reversal.
        """
        try:
            from services.integration_manager import integration_manager
            from integrations.engines.execution_engine import execute_action

            # Map rollback methods to integration actions
            action_mapping = {
                'unblock_ip': {'integration': 'firewall', 'action': 'unblock_ip'},
                'block_ip': {'integration': 'firewall', 'action': 'block_ip'},
                'enable_user': {'integration': 'active_directory', 'action': 'enable_user'},
                'disable_user': {'integration': 'active_directory', 'action': 'disable_user'},
                'restore_file': {'integration': 'edr', 'action': 'restore_file'},
                'quarantine_file': {'integration': 'edr', 'action': 'quarantine_file'},
                'reconnect_endpoint': {'integration': 'edr', 'action': 'reconnect'},
                'isolate_endpoint': {'integration': 'edr', 'action': 'isolate'},
                'remove_from_blocklist': {'integration': 'blocklist', 'action': 'remove'},
                'add_to_blocklist': {'integration': 'blocklist', 'action': 'add'},
            }

            if method not in action_mapping:
                return {"success": False, "error": f"Unknown rollback method: {method}"}

            action_config = action_mapping[method]

            # Build action payload
            action_payload = {
                'integration_id': action_config['integration'],
                'action': action_config['action'],
                'target_type': target_type,
                'target_id': target_id,
                **params.get('original_params', {})
            }

            # Execute via integration framework
            result = await execute_action(action_payload)

            return {
                "success": result.get('success', False),
                "method": method,
                "target": f"{target_type}:{target_id}",
                "result": result
            }

        except ImportError as e:
            # Integration framework not available - simulate success for now
            logger.warning(f"Integration framework not available for rollback: {e}")
            return {
                "success": True,
                "method": method,
                "target": f"{target_type}:{target_id}",
                "simulated": True,
                "note": "Integration framework not available - action logged only"
            }

        except Exception as e:
            logger.error(f"Rollback action execution failed: {e}")
            return {"success": False, "error": str(e)}

    async def get_rollback_stats(self) -> Dict[str, Any]:
        """Get statistics about rollback actions"""
        await self.initialize()

        try:
            async with self._postgres.tenant_acquire() as conn:
                stats = await conn.fetchrow('''
                    SELECT
                        COUNT(*) as total_rollbacks,
                        COUNT(*) FILTER (WHERE executed_at IS NOT NULL) as executed,
                        COUNT(*) FILTER (WHERE executed_at IS NOT NULL AND success = TRUE) as successful,
                        COUNT(*) FILTER (WHERE executed_at IS NOT NULL AND success = FALSE) as failed,
                        COUNT(*) FILTER (WHERE executed_at IS NULL AND expires_at > CURRENT_TIMESTAMP) as pending,
                        COUNT(*) FILTER (WHERE executed_at IS NULL AND expires_at <= CURRENT_TIMESTAMP) as expired
                    FROM agent_rollback_actions
                ''')

                return dict(stats) if stats else {}

        except Exception as e:
            logger.error(f"Failed to get rollback stats: {e}")
            return {}


# Singleton instance
agent_service = AgentService()


def get_agent_service() -> AgentService:
    """Get the agent service instance"""
    return agent_service
