# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
LLM Client Adapter for Unified Reasoning Engine

This module provides an LLM client that wraps the existing AgentExecutor
to make LLM calls for the reasoning engine.

The client:
- Uses the configured AI provider (Anthropic, OpenAI, LM Studio, etc.)
- Tracks token usage
- Handles retries and errors gracefully
- Returns structured responses
"""

import logging
import os
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from uuid import UUID

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from an LLM call."""
    success: bool
    content: str
    raw_response: Dict[str, Any]
    prompt_tokens: int = 0
    completion_tokens: int = 0
    response_time_ms: int = 0
    model: str = ""
    provider: str = ""
    error: Optional[str] = None


class ReasoningLLMClient:
    """
    LLM client for the unified reasoning engine.

    Wraps the existing AgentExecutor to provide a clean interface
    for the reasoning engine to make LLM calls.
    """

    # Default model configuration for reasoning
    DEFAULT_CONFIG = {
        "temperature": 0.1,  # Low temperature for consistent reasoning
        "max_tokens_per_task": 1000,  # Hard cap: 800-1200 tokens for focused output
        "tier": 2  # Use Tier 2 (reasoning) model by default
    }

    # Token budgets per tier to prevent workload starvation
    TIER_BUDGETS = {
        1: {"max_concurrent": 4, "max_tokens": 800},   # T1: Fast triage on 3090
        2: {"max_concurrent": 3, "max_tokens": 1200},  # T2: Deep analysis on 5090 (60-70%)
        "chat": {"max_concurrent": 2, "max_tokens": 1000}  # Chat: 30-40% of 5090
    }

    def __init__(self, model_config: Optional[Dict[str, Any]] = None):
        """
        Initialize the LLM client.

        Args:
            model_config: Optional model configuration override.
                         If not provided, uses DEFAULT_CONFIG with
                         the configured AI provider's tier2_model.
        """
        self._executor = None
        self._model_config = model_config or self.DEFAULT_CONFIG.copy()
        self._initialized = False

    async def _get_executor(self):
        """Get or create the AgentExecutor instance."""
        if self._executor is None:
            from services.agent_executor import AgentExecutor
            self._executor = AgentExecutor()
            await self._executor.initialize()
        return self._executor

    async def complete(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        json_mode: bool = False,
        temperature: Optional[float] = None,
        tenant_id: Optional[str] = None,
        request_type: str = "reasoning",
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> LLMResponse:
        """
        Make a completion request to the LLM.

        Args:
            prompt: The user prompt to send
            system_prompt: Optional system prompt
            json_mode: If True, request JSON output
            temperature: Optional temperature override
            tenant_id: Tenant making the request. Falls back to
                DEFAULT_TENANT_ID env var (platform tenant) when not
                provided, so reasoning-engine spend always lands on
                *some* tenant's ledger rather than slipping through
                quota and the daily kill-switch entirely.
            request_type: Cost-tracking label (default "reasoning")
            alert_id: Optional associated alert for usage attribution
            investigation_id: Optional associated investigation

        Returns:
            LLMResponse with the result
        """
        # Build config
        config = self._model_config.copy()
        if temperature is not None:
            config["temperature"] = temperature

        # Preferred path: route Claude calls through services.claude_service
        # so per-tenant quotas, the platform-wide daily $25 kill-switch,
        # tenant_claude_usage accounting, and Stripe metered overage all
        # apply. Reasoning previously called AgentExecutor.call_llm
        # directly, which skipped every one of those.
        #
        # We fall through to the legacy executor path when:
        #   - ANTHROPIC_API_KEY is not configured (dev / LM Studio path), OR
        #   - the claude_service import or call raises non-quota errors
        # so dev workflows on local models keep working unchanged.
        try:
            from services.claude_service import get_claude_service, QuotaExceededError
            claude_service = await get_claude_service()
            if claude_service.is_configured:
                tid_str = tenant_id or os.environ.get("DEFAULT_TENANT_ID")
                if tid_str:
                    try:
                        tid_uuid = UUID(str(tid_str))
                    except (ValueError, AttributeError, TypeError):
                        logger.warning(
                            f"Reasoning LLM: invalid tenant_id '{tid_str}', "
                            f"falling back to executor path"
                        )
                        tid_uuid = None

                    if tid_uuid is not None:
                        try:
                            cs_response = await claude_service.complete(
                                tenant_id=tid_uuid,
                                prompt=prompt,
                                system=system_prompt,
                                max_tokens=config.get("max_tokens_per_task", 1000),
                                temperature=config.get("temperature", 0.1),
                                request_type=request_type,
                                alert_id=UUID(alert_id) if alert_id else None,
                                investigation_id=UUID(investigation_id) if investigation_id else None,
                            )
                            return LLMResponse(
                                success=True,
                                content=cs_response.text,
                                raw_response={
                                    "usage": {
                                        "prompt_tokens": cs_response.input_tokens,
                                        "completion_tokens": cs_response.output_tokens,
                                    },
                                    "model": cs_response.model,
                                    "cache_creation_tokens": cs_response.cache_creation_tokens,
                                    "cache_read_tokens": cs_response.cache_read_tokens,
                                },
                                prompt_tokens=cs_response.input_tokens,
                                completion_tokens=cs_response.output_tokens,
                                response_time_ms=cs_response.response_time_ms,
                                model=cs_response.model,
                                provider="claude",
                            )
                        except QuotaExceededError as qe:
                            # Quota / kill-switch hit. Do NOT silently fall
                            # through to the executor — that would defeat
                            # the whole point of the change. Return a clean
                            # failed response and let the reasoning engine
                            # short-circuit gracefully.
                            logger.warning(
                                f"Reasoning LLM: quota exhausted for {tid_str}: {qe}"
                            )
                            return LLMResponse(
                                success=False,
                                content="",
                                raw_response={"quota_exceeded": True},
                                error=str(qe),
                                model=self._model_config.get("model", ""),
                                provider="claude",
                            )
        except Exception as e:
            logger.warning(
                f"Reasoning LLM: claude_service routing unavailable, "
                f"falling back to executor: {e}"
            )

        # Legacy / dev fallback: AgentExecutor path. Supports LM Studio
        # and any other configured non-Claude provider. Quota tracking
        # does NOT apply here, which is acceptable for dev only.
        try:
            executor = await self._get_executor()

            # Build messages
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            # Call LLM
            response = await executor.call_llm(
                messages=messages,
                model_config=config,
                tools=None,
                stream=False
            )

            # Extract content
            if response.get("success", True):
                content = response.get("content", "")

                # Handle different response formats
                if not content:
                    # Try to extract from choices (OpenAI format)
                    choices = response.get("choices", [])
                    if choices:
                        content = choices[0].get("message", {}).get("content", "")

                return LLMResponse(
                    success=True,
                    content=content,
                    raw_response=response,
                    prompt_tokens=response.get("usage", {}).get("prompt_tokens", 0),
                    completion_tokens=response.get("usage", {}).get("completion_tokens", 0),
                    response_time_ms=response.get("response_time_ms", 0),
                    model=response.get("model", ""),
                    provider=response.get("provider_name", "")
                )
            else:
                return LLMResponse(
                    success=False,
                    content="",
                    raw_response=response,
                    error=response.get("error", "Unknown error")
                )

        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return LLMResponse(
                success=False,
                content="",
                raw_response={},
                error=str(e)
            )

    async def complete_structured(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        schema: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Make a completion request expecting a structured JSON response.

        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt
            schema: Expected JSON schema (for validation)
            tenant_id: Tenant for quota/cost attribution
            alert_id: Optional associated alert
            investigation_id: Optional associated investigation

        Returns:
            Parsed JSON response or error dict
        """
        # Enhance prompt for JSON output
        json_prompt = f"{prompt}\n\nRespond ONLY with valid JSON. No other text."

        response = await self.complete(
            prompt=json_prompt,
            system_prompt=system_prompt,
            json_mode=True,
            tenant_id=tenant_id,
            alert_id=alert_id,
            investigation_id=investigation_id,
        )

        if not response.success:
            return {
                "error": response.error,
                "success": False
            }

        # Try to parse JSON
        try:
            # Clean up response - sometimes LLMs wrap in markdown
            content = response.content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            parsed = json.loads(content)
            return parsed

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON response: {e}")
            return {
                "error": f"Invalid JSON response: {e}",
                "raw_content": response.content,
                "success": False
            }

    async def reason(
        self,
        context: str,
        question: str,
        system_prompt: Optional[str] = None,
        tenant_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> LLMResponse:
        """
        Make a reasoning request - optimized for security analysis.

        Uses lower temperature for consistent, analytical responses.

        Args:
            context: Investigation context
            question: The reasoning question
            system_prompt: Optional system prompt override
            tenant_id: Tenant for quota/cost attribution
            alert_id: Optional associated alert
            investigation_id: Optional associated investigation

        Returns:
            LLMResponse with reasoning result
        """
        prompt = f"""CONTEXT:
{context}

QUESTION:
{question}

Analyze carefully and provide your assessment."""

        return await self.complete(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.05,  # Very low for reasoning
            tenant_id=tenant_id,
            alert_id=alert_id,
            investigation_id=investigation_id,
        )


# =============================================================================
# SINGLETON
# =============================================================================

_llm_client: Optional[ReasoningLLMClient] = None


def get_reasoning_llm_client(model_config: Optional[Dict[str, Any]] = None) -> ReasoningLLMClient:
    """Get the global reasoning LLM client instance."""
    global _llm_client
    if _llm_client is None:
        _llm_client = ReasoningLLMClient(model_config)
    return _llm_client
