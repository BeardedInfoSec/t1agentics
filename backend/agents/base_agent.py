# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Base AI Agent

Foundation for all AI agents. Uses the integration system for AI provider access.
Enforces permissions, policies, and provides common functionality.
"""

import json
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import Enum

from integrations.engines.execution_engine import (
    get_execution_engine, ExecutionRequest, ExecutionContext
)
from integrations.registry.integration_registry import get_registry
from integrations.observables import Observable


class AgentType(str, Enum):
    """Types of AI agents"""
    INVESTIGATION = "investigation"
    TRIAGE = "triage"
    ENRICHMENT = "enrichment"
    ANALYST = "analyst"
    CUSTOM = "custom"


class AIProvider(str, Enum):
    """Supported AI providers"""
    OPENAI = "openai"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    LMSTUDIO = "lmstudio"
    AZURE_OPENAI = "azure_openai"


class AgentConfig:
    """Configuration for an AI agent"""
    
    def __init__(
        self,
        agent_id: str,
        agent_type: AgentType,
        primary_provider: AIProvider = AIProvider.OPENAI,
        fallback_providers: Optional[List[AIProvider]] = None,
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000,
        enabled: bool = True
    ):
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.primary_provider = primary_provider
        self.fallback_providers = fallback_providers or []
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.enabled = enabled
        
        # Set default model if not specified
        if not self.model:
            self.model = self._get_default_model(primary_provider)
    
    def _get_default_model(self, provider: AIProvider) -> str:
        """Get default model for provider"""
        defaults = {
            AIProvider.OPENAI: "gpt-4o",
            AIProvider.GEMINI: "gemini-pro",
            AIProvider.OLLAMA: "llama3:8b",
            AIProvider.LMSTUDIO: "local-model",
            AIProvider.AZURE_OPENAI: "gpt-4"
        }
        return defaults.get(provider, "gpt-4o")


class BaseAgent:
    """
    Base AI Agent
    
    All agents extend this class and use the integration system
    for AI provider access.
    """
    
    def __init__(self, config: AgentConfig):
        self.config = config
        self.execution_engine = get_execution_engine()
        self.registry = get_registry()
        self.execution_history: List[Dict[str, Any]] = []
    
    async def execute(
        self,
        action_id: str,
        input_payload: Dict[str, Any],
        observable: Optional[Observable] = None
    ) -> Dict[str, Any]:
        """
        Execute an AI action using the integration system
        
        This goes through the full integration execution flow with
        all safety checks enforced.
        """
        if not self.config.enabled:
            raise ValueError(f"Agent {self.config.agent_id} is disabled")
        
        # Try primary provider
        provider = self.config.primary_provider.value
        
        try:
            result = await self._execute_with_provider(
                provider,
                action_id,
                input_payload,
                observable
            )
            
            # Log execution
            self._log_execution(provider, action_id, result, success=True)
            
            return result.data
            
        except Exception as e:
            print(f"[ERROR] Primary provider {provider} failed: {e}")
            
            # Try fallback providers
            for fallback in self.config.fallback_providers:
                try:
                    print(f"[FALLBACK] Trying fallback provider: {fallback.value}")
                    result = await self._execute_with_provider(
                        fallback.value,
                        action_id,
                        input_payload,
                        observable
                    )
                    
                    self._log_execution(fallback.value, action_id, result, success=True)
                    return result.data
                    
                except Exception as fallback_error:
                    print(f"[ERROR] Fallback {fallback.value} failed: {fallback_error}")
                    continue
            
            # All providers failed
            self._log_execution(provider, action_id, None, success=False, error=str(e))
            raise Exception(f"All AI providers failed for agent {self.config.agent_id}")
    
    async def _execute_with_provider(
        self,
        provider_id: str,
        action_id: str,
        input_payload: Dict[str, Any],
        observable: Optional[Observable]
    ):
        """Execute with a specific provider"""
        
        # Add model and temperature to payload
        input_payload = {
            **input_payload,
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens
        }
        
        # Execute through integration system
        result = await self.execution_engine.execute(ExecutionRequest(
            integration_id=provider_id,
            action_id=action_id,
            input_payload=input_payload,
            context=ExecutionContext(
                actor_id=self.config.agent_id,
                actor_type="ai_agent"
            ),
            observable=observable
        ))
        
        if not result.success:
            raise Exception(result.error)
        
        return result
    
    def _log_execution(
        self,
        provider: str,
        action: str,
        result: Any,
        success: bool,
        error: Optional[str] = None
    ):
        """Log execution for audit trail"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": self.config.agent_id,
            "provider": provider,
            "action": action,
            "success": success,
            "error": error,
            "cached": result.cached if result else False
        }
        self.execution_history.append(log_entry)
        
        # Keep only last 100 entries
        if len(self.execution_history) > 100:
            self.execution_history = self.execution_history[-100:]
    
    def get_execution_history(self) -> List[Dict[str, Any]]:
        """Get agent execution history"""
        return self.execution_history
    
    def clear_history(self):
        """Clear execution history"""
        self.execution_history = []
    
    async def test_connection(self) -> bool:
        """Test if the primary provider is available"""
        try:
            # Try a simple test action
            await self.execute(
                action_id="chat",
                input_payload={
                    "messages": [{"role": "user", "content": "test"}],
                    "max_tokens": 10
                }
            )
            return True
        except Exception as e:
            logger.debug(f"LLM model warmup test failed: {e}")
            return False
    
    def _parse_json_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse JSON from AI response
        
        AI models sometimes wrap JSON in markdown or add explanation.
        This extracts the JSON.
        """
        # Try direct parse first
        try:
            return json.loads(response_text)
        except json.JSONDecodeError:
            logger.debug("Direct JSON parse failed, trying markdown extraction")

        # Try to extract JSON from markdown
        import re
        json_match = re.search(r'```json\s*(\{.*?\})\s*```', response_text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError as e:
                logger.debug(f"Markdown JSON extraction failed: {e}")

        # Try to find any JSON object
        json_match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError as e:
                logger.debug(f"Fallback JSON extraction failed: {e}")

        # Couldn't parse - return as text
        logger.warning(f"Could not parse JSON from AI response, returning as plain text")
        return {"response": response_text}


# Global agent registry
_agents: Dict[str, BaseAgent] = {}


def register_agent(agent: BaseAgent):
    """Register an agent"""
    _agents[agent.config.agent_id] = agent


def get_agent(agent_id: str) -> Optional[BaseAgent]:
    """Get a registered agent"""
    return _agents.get(agent_id)


def list_agents() -> List[BaseAgent]:
    """List all registered agents"""
    return list(_agents.values())


def unregister_agent(agent_id: str):
    """Unregister an agent"""
    if agent_id in _agents:
        del _agents[agent_id]
