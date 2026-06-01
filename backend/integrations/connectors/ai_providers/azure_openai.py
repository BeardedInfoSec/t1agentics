# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Azure OpenAI / GitHub Copilot Integration

Microsoft's AI offerings:
- Azure OpenAI (GPT-4, GPT-3.5)
- GitHub Copilot (enterprise)
"""

from integrations.registry.integration_registry import (
    Integration, ActionSchema, IntegrationType, AuthType, get_registry
)
from integrations.observables import ObservableType


def register_azure_openai() -> Integration:
    """Register Azure OpenAI integration"""
    
    integration = Integration(
        id="azure_openai",
        name="Azure OpenAI",
        type=IntegrationType.CUSTOM,
        description="Microsoft Azure OpenAI Service for enterprise AI",
        version="1.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "api-key",
            "key_location": "header",
            "key_value": "",
            "deployment_id": "",  # Azure-specific
            "api_version": "2024-02-15-preview"
        },
        base_url="",  # User must set: https://{resource}.openai.azure.com
        enabled=False,
        vendor="Microsoft",
        documentation_url="https://learn.microsoft.com/en-us/azure/ai-services/openai/",
        tags=["ai", "llm", "microsoft", "enterprise"],
        actions=[
            # Alert analysis
            ActionSchema(
                id="analyze_alert",
                name="Analyze Alert (Azure)",
                description="Analyze alerts using Azure OpenAI",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/openai/deployments/{deployment_id}/chat/completions",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
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
                name="Azure Investigation",
                description="Full investigation using Azure OpenAI",
                observable_type=ObservableType.INVESTIGATION,
                http_method="POST",
                endpoint="/openai/deployments/{deployment_id}/chat/completions",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
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
                name="Azure Triage",
                description="Quick triage with Azure OpenAI",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/openai/deployments/{deployment_id}/chat/completions",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "messages": {"type": "array"},
                        "temperature": {"type": "number", "default": 0.1},
                        "max_tokens": {"type": "integer", "default": 500}
                    },
                    "required": ["messages"]
                }
            )
        ]
    )
    
    registry = get_registry()
    registry.register(integration)
    return integration
