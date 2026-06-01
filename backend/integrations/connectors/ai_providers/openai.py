# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
OpenAI Integration

Provides access to OpenAI's language models:
- GPT-4o
- GPT-4-turbo
- GPT-3.5-turbo
- GPT-4

Actions:
- analyze_alert: Analyze security alerts
- enrich_ioc: Enrich IOCs with AI analysis
- investigate: Full investigation
- triage: Quick triage
- chat: General chat completion
"""

from integrations.registry.integration_registry import (
    Integration, ActionSchema, IntegrationType, AuthType, get_registry
)
from integrations.observables import ObservableType


def register_openai() -> Integration:
    """Register OpenAI integration"""
    
    integration = Integration(
        id="openai",
        name="OpenAI",
        type=IntegrationType.CUSTOM,  # Will add AI_PROVIDER type
        description="OpenAI language models for AI-powered security analysis",
        version="1.0.0",
        auth_type=AuthType.BEARER_TOKEN,
        auth_config={
            "token": "",  # User must configure
            "organization": ""  # Optional
        },
        base_url="https://api.openai.com/v1",
        enabled=False,
        vendor="OpenAI",
        documentation_url="https://platform.openai.com/docs/api-reference",
        tags=["ai", "llm", "analysis"],
        actions=[
            # Alert analysis
            ActionSchema(
                id="analyze_alert",
                name="Analyze Alert with AI",
                description="Use GPT-4 to analyze a security alert and provide insights",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/chat/completions",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "gpt-4o"},
                        "alert_title": {"type": "string"},
                        "alert_description": {"type": "string"},
                        "alert_metadata": {"type": "object"},
                        "temperature": {"type": "number", "default": 0.7},
                        "max_tokens": {"type": "integer", "default": 2000}
                    },
                    "required": ["alert_title"]
                }
            ),
            
            # IOC enrichment
            ActionSchema(
                id="enrich_ioc",
                name="Enrich IOC with AI",
                description="Use AI to provide context and analysis for an IOC",
                observable_type=ObservableType.IP,
                http_method="POST",
                endpoint="/chat/completions",
                requires_auth=True,
                policy_enforced=True,  # Respect enrichment policy
                cacheable=True,
                cache_ttl_days=30,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "gpt-4o"},
                        "ioc_type": {"type": "string"},
                        "ioc_value": {"type": "string"},
                        "context": {"type": "string"},
                        "temperature": {"type": "number", "default": 0.3}
                    },
                    "required": ["ioc_type", "ioc_value"]
                }
            ),
            
            # Full investigation
            ActionSchema(
                id="investigate",
                name="AI Investigation",
                description="Perform a full AI-powered investigation",
                observable_type=ObservableType.INVESTIGATION,
                http_method="POST",
                endpoint="/chat/completions",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,  # Don't cache investigations
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "gpt-4o"},
                        "alert_data": {"type": "object"},
                        "iocs": {"type": "array"},
                        "enrichment_data": {"type": "object"},
                        "temperature": {"type": "number", "default": 0.7},
                        "max_tokens": {"type": "integer", "default": 4000}
                    },
                    "required": ["alert_data"]
                }
            ),
            
            # Quick triage
            ActionSchema(
                id="triage",
                name="AI Triage",
                description="Quick triage classification (benign/suspicious/malicious)",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/chat/completions",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "gpt-3.5-turbo"},
                        "alert_title": {"type": "string"},
                        "alert_description": {"type": "string"},
                        "temperature": {"type": "number", "default": 0.1},
                        "max_tokens": {"type": "integer", "default": 500}
                    },
                    "required": ["alert_title"]
                }
            ),
            
            # General chat completion
            ActionSchema(
                id="chat",
                name="Chat Completion",
                description="General purpose chat completion",
                http_method="POST",
                endpoint="/chat/completions",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "model": {"type": "string", "default": "gpt-4o"},
                        "messages": {"type": "array"},
                        "temperature": {"type": "number", "default": 0.7},
                        "max_tokens": {"type": "integer", "default": 2000},
                        "stream": {"type": "boolean", "default": False}
                    },
                    "required": ["messages"]
                }
            )
        ]
    )
    
    registry = get_registry()
    registry.register(integration)
    return integration
