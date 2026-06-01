# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
LM Studio Integration

Local AI models via LM Studio - OpenAI-compatible local API
Supports any GGUF model from Hugging Face
"""

from integrations.registry.integration_registry import (
    Integration, ActionSchema, IntegrationType, AuthType, get_registry
)
from integrations.observables import ObservableType


def register_lmstudio() -> Integration:
    """Register LM Studio integration"""
    
    integration = Integration(
        id="lmstudio",
        name="LM Studio (Local)",
        type=IntegrationType.CUSTOM,
        description="Local AI models via LM Studio - OpenAI-compatible API for local models",
        version="1.0.0",
        auth_type=AuthType.NONE,  # Local, no auth
        auth_config={},
        base_url="http://localhost:1234/v1",  # Default LM Studio port
        enabled=False,
        vendor="LM Studio",
        documentation_url="https://lmstudio.ai/docs",
        tags=["ai", "llm", "local", "privacy", "huggingface"],
        actions=[
            # Alert analysis
            ActionSchema(
                id="analyze_alert",
                name="Analyze Alert (LM Studio)",
                description="Analyze alerts using LM Studio local models",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/chat/completions",
                requires_auth=False,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "local-model"},
                        "messages": {"type": "array"},
                        "temperature": {"type": "number", "default": 0.7},
                        "max_tokens": {"type": "integer", "default": 2000}
                    },
                    "required": ["messages"]
                }
            ),
            
            # Investigation
            ActionSchema(
                id="investigate",
                name="LM Studio Investigation",
                description="Full investigation using LM Studio",
                observable_type=ObservableType.INVESTIGATION,
                http_method="POST",
                endpoint="/chat/completions",
                requires_auth=False,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string"},
                        "messages": {"type": "array"},
                        "temperature": {"type": "number", "default": 0.7},
                        "max_tokens": {"type": "integer", "default": 4000}
                    },
                    "required": ["messages"]
                }
            ),
            
            # Triage
            ActionSchema(
                id="triage",
                name="LM Studio Triage",
                description="Quick triage with local model",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/chat/completions",
                requires_auth=False,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string"},
                        "messages": {"type": "array"},
                        "temperature": {"type": "number", "default": 0.1},
                        "max_tokens": {"type": "integer", "default": 500}
                    },
                    "required": ["messages"]
                }
            ),
            
            # List models
            ActionSchema(
                id="list_models",
                name="List Loaded Models",
                description="List currently loaded models in LM Studio",
                http_method="GET",
                endpoint="/models",
                requires_auth=False,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={"type": "object", "properties": {}}
            )
        ]
    )
    
    registry = get_registry()
    registry.register(integration)
    return integration
