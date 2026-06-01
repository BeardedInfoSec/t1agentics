# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Ollama Integration

Local AI models via Ollama:
- Llama 3 (8B, 70B)
- Mistral
- CodeLlama
- Phi-3
- And any other Ollama-supported models
"""

from integrations.registry.integration_registry import (
    Integration, ActionSchema, IntegrationType, AuthType, get_registry
)
from integrations.observables import ObservableType


def register_ollama() -> Integration:
    """Register Ollama integration"""
    
    integration = Integration(
        id="ollama",
        name="Ollama (Local)",
        type=IntegrationType.CUSTOM,
        description="Local AI models via Ollama - run AI entirely on your infrastructure",
        version="1.0.0",
        auth_type=AuthType.NONE,  # Local, no auth needed
        auth_config={},
        base_url="http://localhost:11434/api",  # Default Ollama port
        enabled=False,
        vendor="Ollama",
        documentation_url="https://ollama.ai/docs",
        tags=["ai", "llm", "local", "privacy"],
        actions=[
            # Alert analysis
            ActionSchema(
                id="analyze_alert",
                name="Analyze Alert (Local AI)",
                description="Analyze alerts using local Ollama models",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/generate",
                requires_auth=False,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "llama3:8b"},
                        "prompt": {"type": "string"},
                        "alert_title": {"type": "string"},
                        "alert_description": {"type": "string"},
                        "temperature": {"type": "number", "default": 0.7},
                        "stream": {"type": "boolean", "default": False}
                    },
                    "required": ["alert_title"]
                }
            ),
            
            # Investigation
            ActionSchema(
                id="investigate",
                name="Local AI Investigation",
                description="Full investigation using local Ollama models",
                observable_type=ObservableType.INVESTIGATION,
                http_method="POST",
                endpoint="/generate",
                requires_auth=False,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "llama3:70b"},
                        "prompt": {"type": "string"},
                        "alert_data": {"type": "object"},
                        "temperature": {"type": "number", "default": 0.7}
                    },
                    "required": ["prompt", "alert_data"]
                }
            ),
            
            # Triage
            ActionSchema(
                id="triage",
                name="Local AI Triage",
                description="Quick triage using lightweight local model",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/generate",
                requires_auth=False,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "llama3:8b"},
                        "prompt": {"type": "string"},
                        "temperature": {"type": "number", "default": 0.1}
                    },
                    "required": ["prompt"]
                }
            ),
            
            # Chat
            ActionSchema(
                id="chat",
                name="Local Chat",
                description="Chat with local AI model",
                http_method="POST",
                endpoint="/chat",
                requires_auth=False,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "llama3:8b"},
                        "messages": {"type": "array"},
                        "stream": {"type": "boolean", "default": False}
                    },
                    "required": ["messages"]
                }
            ),
            
            # List models
            ActionSchema(
                id="list_models",
                name="List Available Models",
                description="List all locally installed Ollama models",
                http_method="GET",
                endpoint="/tags",
                requires_auth=False,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {}
                }
            )
        ]
    )
    
    registry = get_registry()
    registry.register(integration)
    return integration
