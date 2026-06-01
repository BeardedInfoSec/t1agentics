# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
AI Token Usage Tracking Service

Tracks token usage for all AI provider calls including:
- LM Studio (local)
- OpenAI
- Claude/Anthropic
- Gemini
- Ollama
- Azure OpenAI

Provides:
- Real-time usage logging
- Daily/monthly aggregations
- Cost estimation
- Usage analytics
"""

import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from decimal import Decimal

logger = logging.getLogger(__name__)


# Cost per 1K tokens (in USD cents) - configurable
DEFAULT_COSTS = {
    # OpenAI
    "gpt-4": {"prompt": 3.0, "completion": 6.0},
    "gpt-4-turbo": {"prompt": 1.0, "completion": 3.0},
    "gpt-4o": {"prompt": 0.5, "completion": 1.5},
    "gpt-4o-mini": {"prompt": 0.015, "completion": 0.06},
    "gpt-3.5-turbo": {"prompt": 0.05, "completion": 0.15},

    # Claude
    "claude-sonnet-4-5-20250929": {"prompt": 0.3, "completion": 1.5},
    "claude-sonnet-4-5": {"prompt": 0.3, "completion": 1.5},
    "claude-opus-4-6": {"prompt": 1.5, "completion": 7.5},
    "claude-3-opus": {"prompt": 1.5, "completion": 7.5},
    "claude-3-sonnet": {"prompt": 0.3, "completion": 1.5},
    "claude-3-haiku": {"prompt": 0.025, "completion": 0.125},
    "claude-3.5-sonnet": {"prompt": 0.3, "completion": 1.5},
    "claude-3-5-sonnet": {"prompt": 0.3, "completion": 1.5},

    # Gemini
    "gemini-pro": {"prompt": 0.05, "completion": 0.15},
    "gemini-1.5-pro": {"prompt": 0.35, "completion": 1.05},
    "gemini-1.5-flash": {"prompt": 0.0375, "completion": 0.15},

    # Local models (free)
    "local": {"prompt": 0.0, "completion": 0.0},
    "lmstudio": {"prompt": 0.0, "completion": 0.0},
    "ollama": {"prompt": 0.0, "completion": 0.0},
}


class TokenUsageRecord:
    """Represents a single token usage record"""

    def __init__(
        self,
        request_id: str,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: int,
        integration_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        request_type: Optional[str] = None,
        investigation_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        status: str = "success",
        response_time_ms: Optional[int] = None,
        error_message: Optional[str] = None,
        estimated_cost_cents: Optional[Decimal] = None,
        model_load_time_ms: Optional[int] = None,
        inference_time_ms: Optional[int] = None,
        is_cold_start: bool = False,
        tenant_id: Optional[str] = None,
        cache_creation_tokens: int = 0,
        cache_read_tokens: int = 0,
    ):
        self.request_id = request_id
        self.provider = provider
        self.model = model
        self.prompt_tokens = prompt_tokens
        self.completion_tokens = completion_tokens
        self.total_tokens = total_tokens
        self.integration_id = integration_id
        self.endpoint = endpoint
        self.request_type = request_type
        self.investigation_id = investigation_id
        self.alert_id = alert_id
        self.user_id = user_id
        self.agent_id = agent_id
        self.status = status
        self.response_time_ms = response_time_ms
        self.error_message = error_message
        self.estimated_cost_cents = estimated_cost_cents or Decimal("0")
        self.model_load_time_ms = model_load_time_ms
        self.inference_time_ms = inference_time_ms
        self.is_cold_start = is_cold_start
        self.tenant_id = tenant_id
        self.cache_creation_tokens = cache_creation_tokens
        self.cache_read_tokens = cache_read_tokens
        self.created_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "provider": self.provider,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "integration_id": self.integration_id,
            "endpoint": self.endpoint,
            "request_type": self.request_type,
            "investigation_id": self.investigation_id,
            "alert_id": self.alert_id,
            "user_id": self.user_id,
            "agent_id": self.agent_id,
            "status": self.status,
            "response_time_ms": self.response_time_ms,
            "model_load_time_ms": self.model_load_time_ms,
            "inference_time_ms": self.inference_time_ms,
            "is_cold_start": self.is_cold_start,
            "error_message": self.error_message,
            "estimated_cost_cents": float(self.estimated_cost_cents),
            "tenant_id": self.tenant_id,
            "cache_creation_tokens": self.cache_creation_tokens,
            "cache_read_tokens": self.cache_read_tokens,
            "created_at": self.created_at.isoformat()
        }


class TokenTrackingService:
    """
    Service for tracking AI token usage
    """

    def __init__(self, db=None):
        self.db = db
        self.cost_config = DEFAULT_COSTS.copy()
        self._memory_store: List[TokenUsageRecord] = []  # Fallback if no DB

    def set_db(self, db):
        """Set database connection"""
        self.db = db

    def configure_cost(self, model: str, prompt_cost: float, completion_cost: float):
        """Configure cost per 1K tokens for a model"""
        self.cost_config[model] = {
            "prompt": prompt_cost,
            "completion": completion_cost
        }

    def _get_prompt_cost_per_1k(self, model: str) -> float:
        """Lookup the per-1k prompt cost in cents for a model, with prefix fallback."""
        if model in self.cost_config:
            return float(self.cost_config[model]["prompt"])
        model_lower = model.lower()
        for key in self.cost_config:
            if model_lower.startswith(key.lower()) or key.lower() in model_lower:
                return float(self.cost_config[key]["prompt"])
        return 0.0

    def estimate_cost(self, model: str, prompt_tokens: int, completion_tokens: int) -> Decimal:
        """
        Estimate cost for token usage

        Args:
            model: Model name
            prompt_tokens: Number of prompt tokens
            completion_tokens: Number of completion tokens

        Returns:
            Estimated cost in USD cents
        """
        # Find matching cost config
        cost = None
        model_lower = model.lower()

        # Check exact match first
        if model in self.cost_config:
            cost = self.cost_config[model]
        else:
            # Check prefix matches
            for key in self.cost_config:
                if model_lower.startswith(key.lower()) or key.lower() in model_lower:
                    cost = self.cost_config[key]
                    break

        if not cost:
            # Default to free (local model)
            cost = {"prompt": 0.0, "completion": 0.0}

        # Calculate cost (costs are per 1K tokens)
        prompt_cost = Decimal(str(cost["prompt"])) * Decimal(prompt_tokens) / Decimal(1000)
        completion_cost = Decimal(str(cost["completion"])) * Decimal(completion_tokens) / Decimal(1000)

        return prompt_cost + completion_cost

    async def track(
        self,
        provider: str,
        model: str,
        prompt_tokens: int,
        completion_tokens: int,
        total_tokens: Optional[int] = None,
        integration_id: Optional[str] = None,
        endpoint: Optional[str] = None,
        request_type: Optional[str] = None,
        investigation_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        user_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        status: str = "success",
        response_time_ms: Optional[int] = None,
        error_message: Optional[str] = None,
        model_load_time_ms: Optional[int] = None,
        inference_time_ms: Optional[int] = None,
        is_cold_start: bool = False,
        tenant_id: Optional[str] = None,
        cache_creation_tokens: int = 0,
        cache_read_tokens: int = 0,
    ) -> TokenUsageRecord:
        """
        Track a token usage event

        Args:
            provider: AI provider (lmstudio, openai, claude, etc.)
            model: Model name
            prompt_tokens: Number of input tokens
            completion_tokens: Number of output tokens
            total_tokens: Total tokens (calculated if not provided)
            integration_id: Associated integration ID
            endpoint: API endpoint called
            request_type: Type of request (chat, completion, triage, etc.)
            investigation_id: Associated investigation
            alert_id: Associated alert
            user_id: User who made the request
            agent_id: AI agent ID
            status: Request status
            response_time_ms: Response time in milliseconds (total including load)
            error_message: Error message if failed
            model_load_time_ms: Time spent loading model (cold start only)
            inference_time_ms: Actual inference time excluding load
            is_cold_start: Whether this request triggered a model load

        Returns:
            TokenUsageRecord
        """
        if total_tokens is None:
            total_tokens = prompt_tokens + completion_tokens

        # Estimate cost. Anthropic caching pricing:
        #   cache_read_tokens   : 0.10× input rate (90% discount)
        #   cache_creation      : 1.25× input rate (25% premium — paid once per cache write)
        #   base prompt_tokens  : 1.00× input rate (the uncached portion)
        # prompt_tokens here is the BASE (uncached) portion only; cache writes
        # and reads are separate buckets so we charge each at its own rate.
        estimated_cost = self.estimate_cost(model, prompt_tokens, completion_tokens)
        if cache_creation_tokens or cache_read_tokens:
            base_prompt_cost_per_1k = self._get_prompt_cost_per_1k(model)
            cache_write_cents = (
                Decimal(str(base_prompt_cost_per_1k)) * Decimal("1.25")
                * Decimal(cache_creation_tokens) / Decimal(1000)
            )
            cache_read_cents = (
                Decimal(str(base_prompt_cost_per_1k)) * Decimal("0.10")
                * Decimal(cache_read_tokens) / Decimal(1000)
            )
            estimated_cost = estimated_cost + cache_write_cents + cache_read_cents

        # Create record
        record = TokenUsageRecord(
            request_id=f"req_{uuid.uuid4().hex[:12]}",
            provider=provider,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            integration_id=integration_id,
            endpoint=endpoint,
            request_type=request_type,
            investigation_id=investigation_id,
            alert_id=alert_id,
            user_id=user_id,
            agent_id=agent_id,
            status=status,
            response_time_ms=response_time_ms,
            error_message=error_message,
            estimated_cost_cents=estimated_cost,
            model_load_time_ms=model_load_time_ms,
            inference_time_ms=inference_time_ms,
            is_cold_start=is_cold_start,
            tenant_id=tenant_id,
            cache_creation_tokens=cache_creation_tokens,
            cache_read_tokens=cache_read_tokens,
        )

        # Save to database
        await self._save_record(record)

        logger.info(
            f"Token usage tracked: {provider}/{model} - "
            f"{prompt_tokens}+{completion_tokens}={total_tokens} tokens, "
            f"${float(estimated_cost)/100:.4f}"
        )

        return record

    async def _save_record(self, record: TokenUsageRecord):
        """Save record to database"""
        if self.db and hasattr(self.db, 'pool') and self.db.pool:
            try:
                # Parse tenant_id to UUID if provided as string
                tenant_uuid = None
                if record.tenant_id:
                    try:
                        import uuid as _uuid
                        tenant_uuid = _uuid.UUID(record.tenant_id) if isinstance(record.tenant_id, str) else record.tenant_id
                    except (ValueError, AttributeError):
                        pass

                query = """
                    INSERT INTO ai_token_usage (
                        request_id, provider, model, integration_id,
                        prompt_tokens, completion_tokens, total_tokens,
                        estimated_cost_cents, endpoint, request_type,
                        investigation_id, alert_id, user_id, agent_id,
                        status, response_time_ms, error_message, created_at,
                        model_load_time_ms, inference_time_ms, is_cold_start,
                        tenant_id, cache_creation_tokens, cache_read_tokens
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                        $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
                        $22, $23, $24
                    )
                """
                async with self.db.tenant_acquire() as conn:
                    await conn.execute(
                        query,
                        record.request_id,
                        record.provider,
                        record.model,
                        record.integration_id,
                        record.prompt_tokens,
                        record.completion_tokens,
                        record.total_tokens,
                        float(record.estimated_cost_cents),
                        record.endpoint,
                        record.request_type,
                        record.investigation_id,
                        record.alert_id,
                        record.user_id,
                        record.agent_id,
                        record.status,
                        record.response_time_ms,
                        record.error_message,
                        record.created_at,
                        record.model_load_time_ms,
                        record.inference_time_ms,
                        record.is_cold_start,
                        tenant_uuid,
                        record.cache_creation_tokens,
                        record.cache_read_tokens,
                    )
                cold_start_info = " [COLD START]" if record.is_cold_start else ""
                logger.info(f"[OK] Token usage saved: {record.provider}/{record.model} - {record.total_tokens} tokens{cold_start_info}")
            except Exception as e:
                logger.error(f"Failed to save token usage to database: {e}")
                self._memory_store.append(record)
        else:
            logger.warning("Token tracking: No database connection, storing in memory")
            self._memory_store.append(record)

    async def get_usage_summary(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get usage summary with optional filters

        Returns aggregated stats for the period including:
        - avg_response_time_ms: Average total response time (includes load)
        - avg_inference_time_ms: Average inference time (excludes cold starts)
        - p95_inference_time_ms: 95th percentile inference time
        - total_load_time_ms: Total time spent on model loading
        - cold_start_count: Number of cold starts
        """
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()

        if self.db and hasattr(self.db, 'pool') and self.db.pool:
            try:
                query = """
                    SELECT
                        COUNT(*) as request_count,
                        COALESCE(SUM(prompt_tokens), 0) as total_prompt_tokens,
                        COALESCE(SUM(completion_tokens), 0) as total_completion_tokens,
                        COALESCE(SUM(total_tokens), 0) as total_tokens,
                        COALESCE(SUM(estimated_cost_cents), 0) as total_cost_cents,
                        COALESCE(AVG(response_time_ms), 0) as avg_response_time_ms,
                        COALESCE(AVG(inference_time_ms), AVG(response_time_ms)) as avg_inference_time_ms,
                        COALESCE(SUM(model_load_time_ms), 0) as total_load_time_ms,
                        COUNT(CASE WHEN is_cold_start = true THEN 1 END) as cold_start_count,
                        COUNT(CASE WHEN status = 'success' THEN 1 END) as successful,
                        COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed
                    FROM ai_token_usage
                    WHERE created_at >= $1 AND created_at <= $2
                """
                params = [start_date, end_date]

                if provider:
                    query += f" AND provider = ${len(params) + 1}"
                    params.append(provider)

                if model:
                    query += f" AND model = ${len(params) + 1}"
                    params.append(model)

                async with self.db.tenant_acquire() as conn:
                    row = await conn.fetchrow(query, *params)

                    # Calculate P95 inference time (excluding cold starts for accurate measure)
                    p95_query = """
                        SELECT PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY COALESCE(inference_time_ms, response_time_ms)) as p95
                        FROM ai_token_usage
                        WHERE created_at >= $1 AND created_at <= $2
                        AND (is_cold_start = false OR is_cold_start IS NULL)
                    """
                    p95_params = [start_date, end_date]
                    if provider:
                        p95_query += f" AND provider = ${len(p95_params) + 1}"
                        p95_params.append(provider)
                    if model:
                        p95_query += f" AND model = ${len(p95_params) + 1}"
                        p95_params.append(model)

                    p95_row = await conn.fetchrow(p95_query, *p95_params)
                    p95_inference_time_ms = float(p95_row["p95"] or 0) if p95_row else 0

                return {
                    "period": {
                        "start": start_date.isoformat(),
                        "end": end_date.isoformat()
                    },
                    "request_count": row["request_count"] or 0,
                    "total_prompt_tokens": row["total_prompt_tokens"] or 0,
                    "total_completion_tokens": row["total_completion_tokens"] or 0,
                    "total_tokens": row["total_tokens"] or 0,
                    "total_cost_cents": float(row["total_cost_cents"] or 0),
                    "total_cost_usd": float(row["total_cost_cents"] or 0) / 100,
                    "avg_response_time_ms": float(row["avg_response_time_ms"] or 0),
                    "avg_inference_time_ms": float(row["avg_inference_time_ms"] or 0),
                    "p95_inference_time_ms": p95_inference_time_ms,
                    "total_load_time_ms": int(row["total_load_time_ms"] or 0),
                    "cold_start_count": row["cold_start_count"] or 0,
                    "successful_requests": row["successful"] or 0,
                    "failed_requests": row["failed"] or 0
                }
            except Exception as e:
                logger.error(f"Failed to get usage summary: {e}")

        # Fallback to memory store
        filtered = [
            r for r in self._memory_store
            if r.created_at >= start_date and r.created_at <= end_date
            and (not provider or r.provider == provider)
            and (not model or r.model == model)
        ]

        # Calculate inference times excluding cold starts
        non_cold_start = [r for r in filtered if not r.is_cold_start]
        inference_times = [r.inference_time_ms or r.response_time_ms or 0 for r in non_cold_start]
        sorted_inference = sorted(inference_times)
        p95_idx = int(len(sorted_inference) * 0.95) if sorted_inference else 0
        p95_inference = sorted_inference[p95_idx] if sorted_inference else 0

        return {
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "request_count": len(filtered),
            "total_prompt_tokens": sum(r.prompt_tokens for r in filtered),
            "total_completion_tokens": sum(r.completion_tokens for r in filtered),
            "total_tokens": sum(r.total_tokens for r in filtered),
            "total_cost_cents": sum(float(r.estimated_cost_cents) for r in filtered),
            "total_cost_usd": sum(float(r.estimated_cost_cents) for r in filtered) / 100,
            "avg_response_time_ms": (
                sum(r.response_time_ms or 0 for r in filtered) / len(filtered)
                if filtered else 0
            ),
            "avg_inference_time_ms": (
                sum(r.inference_time_ms or r.response_time_ms or 0 for r in filtered) / len(filtered)
                if filtered else 0
            ),
            "p95_inference_time_ms": p95_inference,
            "total_load_time_ms": sum(r.model_load_time_ms or 0 for r in filtered),
            "cold_start_count": sum(1 for r in filtered if r.is_cold_start),
            "successful_requests": sum(1 for r in filtered if r.status == "success"),
            "failed_requests": sum(1 for r in filtered if r.status == "failed")
        }

    async def get_daily_usage(
        self,
        days: int = 30,
        provider: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get daily usage breakdown"""
        start_date = datetime.utcnow() - timedelta(days=days)

        if self.db and hasattr(self.db, 'pool') and self.db.pool:
            try:
                query = """
                    SELECT
                        DATE(created_at) as usage_date,
                        provider,
                        COUNT(*) as request_count,
                        SUM(total_tokens) as total_tokens,
                        SUM(estimated_cost_cents) as total_cost_cents
                    FROM ai_token_usage
                    WHERE created_at >= $1
                """
                params = [start_date]

                if provider:
                    query += " AND provider = $2"
                    params.append(provider)

                query += " GROUP BY DATE(created_at), provider ORDER BY usage_date DESC"

                async with self.db.tenant_acquire() as conn:
                    rows = await conn.fetch(query, *params)
                return [
                    {
                        "date": row["usage_date"].isoformat() if row["usage_date"] else None,
                        "provider": row["provider"],
                        "request_count": row["request_count"],
                        "total_tokens": row["total_tokens"],
                        "total_cost_usd": float(row["total_cost_cents"] or 0) / 100
                    }
                    for row in rows
                ]
            except Exception as e:
                logger.error(f"Failed to get daily usage: {e}")

        return []

    async def get_usage_by_provider(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get usage breakdown by provider"""
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()

        if self.db and hasattr(self.db, 'pool') and self.db.pool:
            try:
                query = """
                    SELECT
                        provider,
                        COUNT(*) as request_count,
                        SUM(prompt_tokens) as total_prompt_tokens,
                        SUM(completion_tokens) as total_completion_tokens,
                        SUM(total_tokens) as total_tokens,
                        SUM(estimated_cost_cents) as total_cost_cents,
                        AVG(response_time_ms) as avg_response_time_ms
                    FROM ai_token_usage
                    WHERE created_at >= $1 AND created_at <= $2
                    GROUP BY provider
                    ORDER BY total_tokens DESC
                """
                async with self.db.tenant_acquire() as conn:
                    rows = await conn.fetch(query, start_date, end_date)
                return [
                    {
                        "provider": row["provider"],
                        "request_count": row["request_count"],
                        "total_prompt_tokens": row["total_prompt_tokens"],
                        "total_completion_tokens": row["total_completion_tokens"],
                        "total_tokens": row["total_tokens"],
                        "total_cost_usd": float(row["total_cost_cents"] or 0) / 100,
                        "avg_response_time_ms": float(row["avg_response_time_ms"] or 0)
                    }
                    for row in rows
                ]
            except Exception as e:
                logger.error(f"Failed to get usage by provider: {e}")

        return []

    async def get_usage_by_model(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """Get usage breakdown by model"""
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=30)
        if not end_date:
            end_date = datetime.utcnow()

        if self.db and hasattr(self.db, 'pool') and self.db.pool:
            try:
                query = """
                    SELECT
                        provider,
                        model,
                        COUNT(*) as request_count,
                        SUM(total_tokens) as total_tokens,
                        SUM(estimated_cost_cents) as total_cost_cents,
                        AVG(response_time_ms) as avg_response_time_ms
                    FROM ai_token_usage
                    WHERE created_at >= $1 AND created_at <= $2
                    GROUP BY provider, model
                    ORDER BY total_tokens DESC
                    LIMIT $3
                """
                async with self.db.tenant_acquire() as conn:
                    rows = await conn.fetch(query, start_date, end_date, limit)
                return [
                    {
                        "provider": row["provider"],
                        "model": row["model"],
                        "request_count": row["request_count"],
                        "total_tokens": row["total_tokens"],
                        "total_cost_usd": float(row["total_cost_cents"] or 0) / 100,
                        "avg_response_time_ms": float(row["avg_response_time_ms"] or 0)
                    }
                    for row in rows
                ]
            except Exception as e:
                logger.error(f"Failed to get usage by model: {e}")

        return []

    async def get_recent_requests(
        self,
        limit: int = 50,
        provider: Optional[str] = None,
        status: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get recent token usage requests"""
        if self.db and hasattr(self.db, 'pool') and self.db.pool:
            try:
                query = """
                    SELECT *
                    FROM ai_token_usage
                    WHERE 1=1
                """
                params = []

                if provider:
                    params.append(provider)
                    query += f" AND provider = ${len(params)}"

                if status:
                    params.append(status)
                    query += f" AND status = ${len(params)}"

                params.append(limit)
                query += f" ORDER BY created_at DESC LIMIT ${len(params)}"

                async with self.db.tenant_acquire() as conn:
                    rows = await conn.fetch(query, *params)
                return [
                    {
                        "request_id": row["request_id"],
                        "provider": row["provider"],
                        "model": row["model"],
                        "prompt_tokens": row["prompt_tokens"],
                        "completion_tokens": row["completion_tokens"],
                        "total_tokens": row["total_tokens"],
                        "cost_usd": float(row["estimated_cost_cents"] or 0) / 100,
                        "request_type": row["request_type"],
                        "status": row["status"],
                        "response_time_ms": row["response_time_ms"],
                        "created_at": row["created_at"].isoformat() if row["created_at"] else None
                    }
                    for row in rows
                ]
            except Exception as e:
                logger.error(f"Failed to get recent requests: {e}")

        # Fallback to memory
        filtered = self._memory_store[-limit:]
        if provider:
            filtered = [r for r in filtered if r.provider == provider]
        if status:
            filtered = [r for r in filtered if r.status == status]

        return [r.to_dict() for r in reversed(filtered)]

    async def reset_all(self) -> Dict[str, Any]:
        """
        Reset all token usage data.

        Returns:
            Dict with deleted count and status
        """
        deleted_count = 0

        if self.db and hasattr(self.db, 'pool') and self.db.pool:
            try:
                async with self.db.tenant_acquire() as conn:
                    result = await conn.execute("DELETE FROM ai_token_usage")
                    # Parse the DELETE count from result string like "DELETE 42"
                    if result and result.startswith("DELETE"):
                        try:
                            deleted_count = int(result.split()[1])
                        except (IndexError, ValueError):
                            pass
                    logger.info(f"Reset token usage: deleted {deleted_count} records")
            except Exception as e:
                logger.error(f"Failed to reset token usage: {e}")
                return {"success": False, "error": str(e), "deleted_count": 0}

        # Also clear memory store
        memory_count = len(self._memory_store)
        self._memory_store.clear()

        return {
            "success": True,
            "deleted_count": deleted_count + memory_count,
            "message": f"Deleted {deleted_count} database records and {memory_count} in-memory records"
        }


# Singleton instance
_token_tracker: Optional[TokenTrackingService] = None


def get_token_tracker() -> TokenTrackingService:
    """Get the global token tracking service"""
    global _token_tracker
    if _token_tracker is None:
        _token_tracker = TokenTrackingService()
    return _token_tracker


async def init_token_tracking(db=None) -> TokenTrackingService:
    """Initialize token tracking with database connection"""
    tracker = get_token_tracker()
    if db:
        tracker.set_db(db)
    return tracker
