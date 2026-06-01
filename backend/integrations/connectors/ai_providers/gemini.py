# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Google Gemini Integration

Provides access to Google's Gemini models:
- Gemini Pro
- Gemini Pro Vision
"""

from integrations.registry.integration_registry import (
    Integration, ActionSchema, IntegrationType, AuthType, get_registry
)
from integrations.observables import ObservableType


def register_gemini() -> Integration:
    """Register Google Gemini integration"""
    
    integration = Integration(
        id="gemini",
        name="Google Gemini",
        type=IntegrationType.CUSTOM,
        description="Google's Gemini AI models for security analysis",
        version="1.0.0",
        auth_type=AuthType.API_KEY,
        auth_config={
            "key_name": "key",
            "key_location": "query",  # Gemini uses query param
            "key_value": ""
        },
        base_url="https://generativelanguage.googleapis.com/v1beta",
        enabled=False,
        vendor="Google",
        documentation_url="https://ai.google.dev/docs",
        tags=["ai", "llm", "google"],
        actions=[
            # Alert analysis
            ActionSchema(
                id="analyze_alert",
                name="Analyze Alert with Gemini",
                description="Use Gemini Pro to analyze security alerts",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/models/gemini-pro:generateContent",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=7,
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_title": {"type": "string"},
                        "alert_description": {"type": "string"},
                        "temperature": {"type": "number", "default": 0.7},
                        "max_tokens": {"type": "integer", "default": 2048}
                    },
                    "required": ["alert_title"]
                }
            ),
            
            # Investigation
            ActionSchema(
                id="investigate",
                name="Gemini Investigation",
                description="Full investigation using Gemini Pro",
                observable_type=ObservableType.INVESTIGATION,
                http_method="POST",
                endpoint="/models/gemini-pro:generateContent",
                requires_auth=True,
                policy_enforced=False,
                cacheable=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_data": {"type": "object"},
                        "iocs": {"type": "array"},
                        "temperature": {"type": "number", "default": 0.7}
                    },
                    "required": ["alert_data"]
                }
            ),
            
            # Triage
            ActionSchema(
                id="triage",
                name="Gemini Triage",
                description="Quick triage with Gemini",
                observable_type=ObservableType.ALERT,
                http_method="POST",
                endpoint="/models/gemini-pro:generateContent",
                requires_auth=True,
                policy_enforced=False,
                cacheable=True,
                cache_ttl_days=1,
                input_schema={
                    "type": "object",
                    "properties": {
                        "alert_title": {"type": "string"},
                        "temperature": {"type": "number", "default": 0.1}
                    },
                    "required": ["alert_title"]
                }
            )
        ]
    )
    
    registry = get_registry()
    registry.register(integration)
    return integration
