# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Definition Service

Handles parsing, validation, and conversion of user-defined integrations
from YAML/JSON format to the IntegrationRegistry format.
"""

import yaml
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from uuid import uuid4
from pydantic import BaseModel, Field, validator
from enum import Enum


class IntegrationType(str, Enum):
    THREAT_INTEL = "threat_intel"
    ENRICHMENT = "enrichment"
    SANDBOX = "sandbox"
    TICKETING = "ticketing"
    SIEM = "siem"
    SOAR = "soar"
    COMMUNICATION = "communication"
    CASE_MANAGEMENT = "case_management"
    EDR = "edr"
    FIREWALL = "firewall"
    NETWORK = "network"
    VULNERABILITY = "vulnerability"
    IDENTITY = "identity"
    CUSTOM = "custom"


class AuthType(str, Enum):
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    OAUTH2 = "oauth2"
    BASIC_AUTH = "basic_auth"
    CUSTOM_HEADER = "custom_header"
    NONE = "none"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class ObservableType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    FILE = "file"
    USER = "user"
    HOST = "host"
    ALERT = "alert"
    INVESTIGATION = "investigation"


# ============================================================
# YAML Schema Models (what users write)
# ============================================================

class AuthConfigSchema(BaseModel):
    """Authentication configuration in YAML"""
    type: AuthType
    header_name: Optional[str] = None  # For api_key type
    token_url: Optional[str] = None    # For oauth2 type
    client_id_env: Optional[str] = None  # Env var for client ID
    client_secret_env: Optional[str] = None  # Env var for client secret


class OutputMappingSchema(BaseModel):
    """Maps API response fields to standardized output"""
    # Key is the output field name, value is JSONPath
    class Config:
        extra = "allow"


class ActionSchema(BaseModel):
    """Action definition in YAML"""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    observable_type: Optional[ObservableType] = None
    method: HttpMethod = HttpMethod.GET
    endpoint: str = Field(..., min_length=1)

    # Request configuration
    headers: Optional[Dict[str, str]] = None
    query_params: Optional[Dict[str, str]] = None
    body_template: Optional[str] = None

    # Response handling
    output_mapping: Optional[Dict[str, str]] = None  # JSONPath mappings

    # Behavior
    cacheable: bool = True
    cache_ttl_days: int = Field(default=1, ge=0, le=365)
    requires_approval: bool = False
    read_only: bool = True

    # Rate limiting
    rate_limit_per_minute: Optional[int] = Field(default=None, ge=1, le=1000)

    @validator('endpoint')
    def validate_endpoint(cls, v):
        # Endpoint should start with /
        if not v.startswith('/'):
            v = '/' + v
        return v

    @validator('name')
    def validate_name(cls, v):
        # Name should be alphanumeric with underscores
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', v):
            raise ValueError('Action name must start with letter and contain only letters, numbers, underscores')
        return v


class IntegrationDefinitionSchema(BaseModel):
    """Root integration definition schema"""
    name: str = Field(..., min_length=1, max_length=255)
    type: IntegrationType
    version: str = Field(default="1.0.0", pattern=r'^\d+\.\d+\.\d+$')
    vendor: Optional[str] = None
    description: Optional[str] = None
    documentation_url: Optional[str] = None
    icon_url: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    # Connection
    base_url: str = Field(..., min_length=1)
    auth: AuthConfigSchema

    # Default headers for all requests
    default_headers: Optional[Dict[str, str]] = None

    # Actions
    actions: List[ActionSchema] = Field(..., min_items=1)

    @validator('base_url')
    def validate_base_url(cls, v):
        # Must be a valid URL
        if not v.startswith(('http://', 'https://')):
            raise ValueError('base_url must start with http:// or https://')
        # Remove trailing slash
        return v.rstrip('/')

    @validator('actions')
    def validate_unique_action_names(cls, v):
        names = [a.name for a in v]
        if len(names) != len(set(names)):
            raise ValueError('Action names must be unique')
        return v


# ============================================================
# Validation Result Models
# ============================================================

class ValidationError(BaseModel):
    field: str
    message: str
    severity: str = "error"  # error, warning


class ValidationResult(BaseModel):
    valid: bool
    errors: List[ValidationError] = Field(default_factory=list)
    warnings: List[ValidationError] = Field(default_factory=list)
    parsed_definition: Optional[Dict[str, Any]] = None


# ============================================================
# Integration Definition Service
# ============================================================

class IntegrationDefinitionService:
    """
    Service for parsing, validating, and converting user-defined integrations.
    """

    def parse_yaml(self, content: str) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Parse YAML content into a dictionary.

        Returns:
            Tuple of (parsed_dict, error_message)
        """
        try:
            data = yaml.safe_load(content)
            if not isinstance(data, dict):
                return None, "YAML must be a dictionary/object"

            # Handle nested 'integration' key
            if 'integration' in data:
                data = data['integration']

            return data, None
        except yaml.YAMLError as e:
            return None, f"Invalid YAML syntax: {str(e)}"

    def parse_json(self, content: str) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Parse JSON content into a dictionary.

        Returns:
            Tuple of (parsed_dict, error_message)
        """
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                return None, "JSON must be an object"

            # Handle nested 'integration' key
            if 'integration' in data:
                data = data['integration']

            return data, None
        except json.JSONDecodeError as e:
            return None, f"Invalid JSON syntax: {str(e)}"

    def validate(self, content: str, format: str = "yaml") -> ValidationResult:
        """
        Validate integration definition content.

        Args:
            content: YAML or JSON string
            format: "yaml" or "json"

        Returns:
            ValidationResult with errors and warnings
        """
        errors = []
        warnings = []

        # Parse content
        if format == "yaml":
            data, parse_error = self.parse_yaml(content)
        else:
            data, parse_error = self.parse_json(content)

        if parse_error:
            return ValidationResult(
                valid=False,
                errors=[ValidationError(field="content", message=parse_error)]
            )

        # Validate against schema
        try:
            definition = IntegrationDefinitionSchema(**data)
            parsed_data = definition.dict()
        except Exception as e:
            # Extract Pydantic validation errors
            error_str = str(e)
            errors.append(ValidationError(
                field="schema",
                message=f"Schema validation failed: {error_str}"
            ))
            return ValidationResult(valid=False, errors=errors)

        # Additional validation checks

        # Check auth configuration
        auth = definition.auth
        if auth.type == AuthType.API_KEY and not auth.header_name:
            errors.append(ValidationError(
                field="auth.header_name",
                message="header_name is required for api_key auth type"
            ))

        if auth.type == AuthType.OAUTH2:
            if not auth.token_url:
                errors.append(ValidationError(
                    field="auth.token_url",
                    message="token_url is required for oauth2 auth type"
                ))

        # Check actions
        for i, action in enumerate(definition.actions):
            # Check endpoint placeholders
            placeholders = re.findall(r'\{(\w+)\}', action.endpoint)
            if 'value' not in placeholders and action.observable_type:
                warnings.append(ValidationError(
                    field=f"actions[{i}].endpoint",
                    message=f"Endpoint may need {{value}} placeholder for observable",
                    severity="warning"
                ))

            # Check body template JSON validity
            if action.body_template:
                try:
                    # Try to parse as JSON (after replacing placeholders)
                    test_body = action.body_template.replace('{value}', 'test')
                    test_body = re.sub(r'\{[^}]+\}', '"test"', test_body)
                    json.loads(test_body)
                except json.JSONDecodeError:
                    warnings.append(ValidationError(
                        field=f"actions[{i}].body_template",
                        message="body_template may not be valid JSON",
                        severity="warning"
                    ))

            # Check output mapping JSONPath syntax
            if action.output_mapping:
                for key, path in action.output_mapping.items():
                    if not path.startswith('$'):
                        warnings.append(ValidationError(
                            field=f"actions[{i}].output_mapping.{key}",
                            message=f"JSONPath should start with $ (got: {path})",
                            severity="warning"
                        ))

        # Check base_url accessibility (optional, can be done in test phase)
        if not definition.base_url.startswith('https://'):
            warnings.append(ValidationError(
                field="base_url",
                message="Using HTTP instead of HTTPS may be insecure",
                severity="warning"
            ))

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            parsed_definition=parsed_data
        )

    def convert_to_registry_format(
        self,
        definition: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Convert validated definition to IntegrationRegistry format.

        Args:
            definition: Validated definition dictionary
            user_id: ID of user creating the integration

        Returns:
            Dictionary in IntegrationRegistry format
        """
        now = datetime.utcnow().isoformat()
        integration_id = str(uuid4())

        # Convert actions
        registry_actions = []
        for action in definition.get('actions', []):
            registry_action = {
                'id': f"{integration_id}_{action['name']}",
                'name': action['name'],
                'description': action.get('description', ''),
                'observable_type': action.get('observable_type'),
                'http_method': action.get('method', 'GET'),
                'endpoint': action['endpoint'],
                'requires_auth': definition['auth']['type'] != 'none',
                'action_type': self._infer_action_type(action),
                'read_only': action.get('read_only', True),
                'policy_enforced': True,
                'requires_permission': action.get('requires_approval', False),
                'cacheable': action.get('cacheable', True),
                'cache_ttl_days': action.get('cache_ttl_days', 1),
                'input_schema': self._build_input_schema(action),
                'output_schema': self._build_output_schema(action),
                'rate_limit_per_minute': action.get('rate_limit_per_minute'),
                'headers': action.get('headers', {}),
                'query_params': action.get('query_params', {}),
                'body_template': action.get('body_template'),
                'output_mapping': action.get('output_mapping', {}),
            }
            registry_actions.append(registry_action)

        # Build registry format
        registry_integration = {
            'id': integration_id,
            'name': definition['name'],
            'type': definition['type'],
            'description': definition.get('description', ''),
            'version': definition.get('version', '1.0.0'),
            'vendor': definition.get('vendor'),
            'documentation_url': definition.get('documentation_url'),
            'icon_url': definition.get('icon_url'),
            'tags': definition.get('tags', []),

            # Auth
            'auth_type': definition['auth']['type'],
            'auth_config': {
                'header_name': definition['auth'].get('header_name'),
                'token_url': definition['auth'].get('token_url'),
            },
            'credential_id': None,  # Set when credential is linked

            # Connection
            'base_url': definition['base_url'],
            'default_headers': definition.get('default_headers', {}),
            'enabled': False,  # Disabled until tested and published

            # Actions
            'actions': registry_actions,

            # Metadata
            'is_user_defined': True,
            'yaml_definition': None,  # Will be set separately
            'validation_status': 'validated',
            'created_by': user_id,
            'created_at': now,
            'updated_at': now,
        }

        return registry_integration

    def _infer_action_type(self, action: Dict[str, Any]) -> str:
        """Infer action type from action configuration."""
        name_lower = action['name'].lower()

        if any(x in name_lower for x in ['lookup', 'get', 'query', 'search', 'check']):
            return 'investigate'
        elif any(x in name_lower for x in ['enrich', 'reputation', 'score']):
            return 'enrich'
        elif any(x in name_lower for x in ['block', 'isolate', 'quarantine', 'disable']):
            return 'contain'
        elif any(x in name_lower for x in ['remove', 'delete', 'unblock', 'enable']):
            return 'remediate'
        elif any(x in name_lower for x in ['notify', 'alert', 'send', 'email']):
            return 'notify'
        elif any(x in name_lower for x in ['submit', 'scan', 'analyze']):
            return 'analyze'
        else:
            return 'investigate'

    def _build_input_schema(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Build JSON Schema for action inputs."""
        schema = {
            "type": "object",
            "properties": {},
            "required": []
        }

        # Add value property if observable_type is set
        if action.get('observable_type'):
            schema['properties']['value'] = {
                "type": "string",
                "description": f"The {action['observable_type']} value to look up"
            }
            schema['required'].append('value')

        # Extract placeholders from endpoint and body_template
        endpoint = action.get('endpoint', '')
        body = action.get('body_template', '')

        placeholders = set(re.findall(r'\{(\w+)\}', endpoint + body))
        placeholders.discard('value')  # Already handled

        for placeholder in placeholders:
            schema['properties'][placeholder] = {
                "type": "string",
                "description": f"Value for {placeholder}"
            }

        return schema

    def _build_output_schema(self, action: Dict[str, Any]) -> Dict[str, Any]:
        """Build JSON Schema for action outputs based on output_mapping."""
        schema = {
            "type": "object",
            "properties": {}
        }

        output_mapping = action.get('output_mapping', {})
        for key in output_mapping:
            schema['properties'][key] = {
                "type": "string",
                "description": f"Mapped from {output_mapping[key]}"
            }

        return schema


# ============================================================
# Template Definitions
# ============================================================

INTEGRATION_TEMPLATES = {
    "threat_intel": """integration:
  name: "My Threat Intel"
  type: threat_intel
  version: "1.0.0"
  vendor: "My Company"
  description: "Custom threat intelligence API"

  base_url: https://api.example.com/v1

  auth:
    type: api_key
    header_name: X-API-Key

  actions:
    - name: lookup_ip
      description: "Look up IP reputation"
      observable_type: ip
      method: GET
      endpoint: /ip/{value}
      cacheable: true
      cache_ttl_days: 1
      output_mapping:
        reputation: $.data.risk_score
        categories: $.data.categories
        last_seen: $.data.last_seen

    - name: lookup_domain
      description: "Look up domain reputation"
      observable_type: domain
      method: GET
      endpoint: /domain/{value}
      cacheable: true
      cache_ttl_days: 1
      output_mapping:
        reputation: $.data.risk_score
        categories: $.data.categories

    - name: lookup_hash
      description: "Look up file hash"
      observable_type: file_hash
      method: GET
      endpoint: /file/{value}
      cacheable: true
      cache_ttl_days: 7
      output_mapping:
        malicious: $.data.is_malicious
        detections: $.data.detection_count
        family: $.data.malware_family
""",

    "siem": """integration:
  name: "My SIEM"
  type: siem
  version: "1.0.0"
  vendor: "My Company"
  description: "Custom SIEM integration"

  base_url: https://siem.example.com/api

  auth:
    type: bearer_token

  actions:
    - name: search_events
      description: "Search for security events"
      method: POST
      endpoint: /search
      body_template: |
        {
          "query": "{query}",
          "time_range": "{time_range}",
          "limit": 100
        }
      output_mapping:
        events: $.results
        total: $.total_count

    - name: get_alert
      description: "Get alert details"
      observable_type: alert
      method: GET
      endpoint: /alerts/{value}
      output_mapping:
        title: $.alert.title
        severity: $.alert.severity
        source: $.alert.source
""",

    "ticketing": """integration:
  name: "My Ticketing System"
  type: ticketing
  version: "1.0.0"
  vendor: "My Company"
  description: "Custom ticketing integration"

  base_url: https://tickets.example.com/api/v2

  auth:
    type: basic_auth

  actions:
    - name: create_ticket
      description: "Create a new ticket"
      method: POST
      endpoint: /tickets
      requires_approval: false
      read_only: false
      body_template: |
        {
          "title": "{title}",
          "description": "{description}",
          "priority": "{priority}",
          "assignee": "{assignee}"
        }
      output_mapping:
        ticket_id: $.ticket.id
        ticket_url: $.ticket.url

    - name: update_ticket
      description: "Update an existing ticket"
      method: PUT
      endpoint: /tickets/{ticket_id}
      requires_approval: false
      read_only: false
      body_template: |
        {
          "status": "{status}",
          "comment": "{comment}"
        }

    - name: get_ticket
      description: "Get ticket details"
      method: GET
      endpoint: /tickets/{ticket_id}
      output_mapping:
        status: $.ticket.status
        assignee: $.ticket.assignee
        created: $.ticket.created_at
""",

    "edr": """integration:
  name: "My EDR"
  type: edr
  version: "1.0.0"
  vendor: "My Company"
  description: "Custom EDR integration"

  base_url: https://edr.example.com/api

  auth:
    type: api_key
    header_name: Authorization

  actions:
    - name: get_device
      description: "Get device information"
      observable_type: host
      method: GET
      endpoint: /devices/{value}
      output_mapping:
        hostname: $.device.hostname
        os: $.device.os_version
        last_seen: $.device.last_seen
        status: $.device.status

    - name: isolate_device
      description: "Isolate device from network"
      observable_type: host
      method: POST
      endpoint: /devices/{value}/isolate
      requires_approval: true
      read_only: false
      body_template: |
        {
          "reason": "{reason}",
          "duration_hours": {duration}
        }

    - name: get_processes
      description: "Get running processes on device"
      observable_type: host
      method: GET
      endpoint: /devices/{value}/processes
      output_mapping:
        processes: $.processes
        count: $.total
"""
}


def get_template(template_type: str) -> Optional[str]:
    """Get an integration template by type."""
    return INTEGRATION_TEMPLATES.get(template_type)


def list_templates() -> List[Dict[str, str]]:
    """List all available templates."""
    return [
        {"type": key, "preview": val[:200] + "..."}
        for key, val in INTEGRATION_TEMPLATES.items()
    ]
