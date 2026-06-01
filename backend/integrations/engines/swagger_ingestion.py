# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Swagger / OpenAPI Ingestion Engine

Auto-import integration definitions from OpenAPI/Swagger specifications.

When a Swagger spec is ingested:
1. Discover all endpoints
2. Extract HTTP method, path, parameters, auth, schemas
3. Normalize each endpoint into an T1 Agentics Action
4. Generate integration definition
5. Make actions callable by API, automations, AI agents, UI

Supports:
- OpenAPI 3.0+
- Swagger 2.0
- Remote URLs
- Local files
- Diff-aware (detect changes)
"""

import httpx
import yaml
import json
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
from datetime import datetime

from integrations.registry.integration_registry import (
    Integration, ActionSchema, IntegrationType, AuthType, get_registry
)
from integrations.observables import ObservableType


class OpenAPISpec(BaseModel):
    """Parsed OpenAPI/Swagger specification"""
    openapi_version: str
    title: str
    version: str
    description: Optional[str] = None
    base_url: str
    servers: List[str] = []
    paths: Dict[str, Any] = {}
    components: Dict[str, Any] = {}
    security: List[Dict[str, Any]] = []
    
    
class SwaggerIngestionEngine:
    """
    Swagger/OpenAPI Ingestion Engine
    
    Auto-generates integration definitions from API specifications.
    """
    
    def __init__(self):
        self.registry = get_registry()
    
    async def ingest_from_url(
        self,
        spec_url: str,
        integration_id: Optional[str] = None,
        integration_type: IntegrationType = IntegrationType.CUSTOM,
        enabled: bool = False
    ) -> Integration:
        """
        Ingest OpenAPI spec from a URL
        
        Args:
            spec_url: URL to OpenAPI/Swagger spec (JSON or YAML)
            integration_id: Optional custom integration ID
            integration_type: Type of integration
            enabled: Whether to enable integration immediately
            
        Returns:
            Generated Integration object
        """
        # Fetch spec
        async with httpx.AsyncClient() as client:
            response = await client.get(spec_url, timeout=30.0)
            response.raise_for_status()
            
            content_type = response.headers.get('content-type', '')
            
            if 'json' in content_type:
                spec_data = response.json()
            elif 'yaml' in content_type or 'yml' in spec_url:
                spec_data = yaml.safe_load(response.text)
            else:
                # Try JSON first, fall back to YAML
                try:
                    spec_data = response.json()
                except:
                    spec_data = yaml.safe_load(response.text)
        
        return await self.ingest_from_dict(
            spec_data,
            spec_url=spec_url,
            integration_id=integration_id,
            integration_type=integration_type,
            enabled=enabled
        )
    
    async def ingest_from_file(
        self,
        file_path: str,
        integration_id: Optional[str] = None,
        integration_type: IntegrationType = IntegrationType.CUSTOM,
        enabled: bool = False
    ) -> Integration:
        """Ingest OpenAPI spec from a local file"""
        with open(file_path, 'r') as f:
            if file_path.endswith('.json'):
                spec_data = json.load(f)
            else:
                spec_data = yaml.safe_load(f)
        
        return await self.ingest_from_dict(
            spec_data,
            spec_url=f"file://{file_path}",
            integration_id=integration_id,
            integration_type=integration_type,
            enabled=enabled
        )
    
    async def ingest_from_dict(
        self,
        spec_data: Dict[str, Any],
        spec_url: Optional[str] = None,
        integration_id: Optional[str] = None,
        integration_type: IntegrationType = IntegrationType.CUSTOM,
        enabled: bool = False
    ) -> Integration:
        """
        Ingest OpenAPI spec from a dictionary
        
        This is the core ingestion method.
        """
        # Parse spec
        spec = self._parse_spec(spec_data)
        
        # Generate integration ID if not provided
        if not integration_id:
            integration_id = self._generate_integration_id(spec.title)
        
        # Determine auth type
        auth_type, auth_config = self._extract_auth(spec)
        
        # Generate actions from paths
        actions = self._generate_actions(spec)
        
        # Create integration
        integration = Integration(
            id=integration_id,
            name=spec.title,
            type=integration_type,
            description=spec.description,
            version=spec.version,
            auth_type=auth_type,
            auth_config=auth_config,
            base_url=spec.base_url,
            enabled=enabled,
            actions=actions,
            openapi_spec_url=spec_url,
            openapi_imported_at=datetime.utcnow()
        )
        
        # Register integration
        self.registry.register(integration)
        
        return integration
    
    def _parse_spec(self, spec_data: Dict[str, Any]) -> OpenAPISpec:
        """Parse OpenAPI specification"""
        
        # Detect version
        if 'openapi' in spec_data:
            openapi_version = spec_data['openapi']
            is_openapi_3 = True
        elif 'swagger' in spec_data:
            openapi_version = spec_data['swagger']
            is_openapi_3 = False
        else:
            raise ValueError("Invalid OpenAPI/Swagger spec: missing version field")
        
        # Extract info
        info = spec_data.get('info', {})
        title = info.get('title', 'Unnamed Integration')
        version = info.get('version', '1.0.0')
        description = info.get('description')
        
        # Extract servers / base URL
        if is_openapi_3:
            servers = spec_data.get('servers', [])
            if servers:
                base_url = servers[0].get('url', '')
                server_list = [s.get('url') for s in servers]
            else:
                base_url = ''
                server_list = []
        else:
            # Swagger 2.0
            schemes = spec_data.get('schemes', ['https'])
            host = spec_data.get('host', '')
            base_path = spec_data.get('basePath', '')
            base_url = f"{schemes[0]}://{host}{base_path}"
            server_list = [base_url]
        
        # Extract paths
        paths = spec_data.get('paths', {})
        
        # Extract components/definitions
        if is_openapi_3:
            components = spec_data.get('components', {})
        else:
            components = {
                'schemas': spec_data.get('definitions', {})
            }
        
        # Extract security
        security = spec_data.get('security', [])
        
        return OpenAPISpec(
            openapi_version=openapi_version,
            title=title,
            version=version,
            description=description,
            base_url=base_url,
            servers=server_list,
            paths=paths,
            components=components,
            security=security
        )
    
    def _extract_auth(self, spec: OpenAPISpec) -> tuple[AuthType, Dict[str, Any]]:
        """Extract authentication configuration from spec"""
        
        if not spec.security:
            return (AuthType.NONE, {})
        
        # Get first security scheme
        security_scheme_name = list(spec.security[0].keys())[0] if spec.security else None
        
        if not security_scheme_name:
            return (AuthType.NONE, {})
        
        # Get security scheme definition
        security_schemes = spec.components.get('securitySchemes', {})
        scheme = security_schemes.get(security_scheme_name, {})
        
        scheme_type = scheme.get('type', '').lower()
        
        if scheme_type == 'apikey':
            return (AuthType.API_KEY, {
                'key_name': scheme.get('name', 'x-api-key'),
                'key_location': scheme.get('in', 'header'),
                'key_value': ''  # User must configure
            })
        elif scheme_type == 'http':
            http_scheme = scheme.get('scheme', '').lower()
            if http_scheme == 'bearer':
                return (AuthType.BEARER_TOKEN, {'token': ''})
            elif http_scheme == 'basic':
                return (AuthType.BASIC_AUTH, {'username': '', 'password': ''})
        elif scheme_type == 'oauth2':
            return (AuthType.OAUTH2, {
                'client_id': '',
                'client_secret': '',
                'auth_url': scheme.get('flows', {}).get('authorizationCode', {}).get('authorizationUrl', ''),
                'token_url': scheme.get('flows', {}).get('authorizationCode', {}).get('tokenUrl', '')
            })
        
        return (AuthType.NONE, {})
    
    def _generate_actions(self, spec: OpenAPISpec) -> List[ActionSchema]:
        """Generate action schemas from OpenAPI paths"""
        
        actions = []
        
        for path, path_item in spec.paths.items():
            for method, operation in path_item.items():
                if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    continue
                
                # Generate action ID
                operation_id = operation.get('operationId')
                if operation_id:
                    action_id = operation_id
                else:
                    # Generate from path and method
                    action_id = f"{method}_{path.replace('/', '_').replace('{', '').replace('}', '').strip('_')}"
                
                # Extract parameters
                parameters = operation.get('parameters', [])
                
                # Build input schema
                input_schema = self._build_input_schema(parameters, operation.get('requestBody'))
                
                # Build output schema  
                output_schema = self._build_output_schema(operation.get('responses', {}))
                
                # Determine observable type (if applicable)
                observable_type = self._infer_observable_type(path, parameters)
                
                # Extract headers
                headers = {}
                query_params = {}

                for param in parameters:
                    if param.get('in') == 'header':
                        headers[param['name']] = param.get('default', '')
                    elif param.get('in') == 'query':
                        query_params[param['name']] = param.get('default', '')

                # Determine content type from requestBody
                content_type = "application/json"  # default
                request_body = operation.get('requestBody')
                if request_body:
                    content = request_body.get('content', {})
                    if 'multipart/form-data' in content:
                        content_type = "multipart/form-data"
                    elif 'application/x-www-form-urlencoded' in content:
                        content_type = "application/x-www-form-urlencoded"
                    elif 'application/json' in content:
                        content_type = "application/json"

                # Create action
                action = ActionSchema(
                    id=action_id,
                    name=operation.get('summary', action_id),
                    description=operation.get('description'),
                    observable_type=observable_type,
                    http_method=method.upper(),
                    endpoint=path,
                    requires_auth=True,  # Default to requiring auth
                    policy_enforced=observable_type is not None,  # Enforce policy if observable-based
                    cacheable=method.upper() == 'GET',  # Cache GET requests
                    cache_ttl_days=30,
                    input_schema=input_schema,
                    output_schema=output_schema,
                    headers=headers,
                    query_params=query_params,
                    content_type=content_type
                )
                
                actions.append(action)
        
        return actions
    
    def _build_input_schema(
        self,
        parameters: List[Dict[str, Any]],
        request_body: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build JSON schema for action input"""
        
        schema = {
            "type": "object",
            "properties": {},
            "required": []
        }
        
        # Add parameters
        for param in parameters:
            param_name = param.get('name')
            param_schema = param.get('schema', {})
            
            schema['properties'][param_name] = param_schema
            
            if param.get('required'):
                schema['required'].append(param_name)
        
        # Add request body
        if request_body:
            content = request_body.get('content', {})
            json_content = content.get('application/json', {})
            body_schema = json_content.get('schema', {})
            
            if body_schema:
                # Merge with parameters
                if 'properties' in body_schema:
                    schema['properties'].update(body_schema['properties'])
                if 'required' in body_schema:
                    schema['required'].extend(body_schema['required'])
        
        return schema
    
    def _build_output_schema(self, responses: Dict[str, Any]) -> Dict[str, Any]:
        """Build JSON schema for action output"""
        
        # Look for 200 response
        success_response = responses.get('200') or responses.get('201')
        
        if not success_response:
            return {}
        
        content = success_response.get('content', {})
        json_content = content.get('application/json', {})
        return json_content.get('schema', {})
    
    def _infer_observable_type(
        self,
        path: str,
        parameters: List[Dict[str, Any]]
    ) -> Optional[ObservableType]:
        """Infer observable type from path and parameters"""
        
        path_lower = path.lower()
        
        # Check path for indicators
        if 'ip' in path_lower or 'address' in path_lower:
            return ObservableType.IP
        elif 'domain' in path_lower or 'hostname' in path_lower:
            return ObservableType.DOMAIN
        elif 'url' in path_lower:
            return ObservableType.URL
        elif 'hash' in path_lower or 'file' in path_lower and 'hash' in path_lower:
            return ObservableType.FILE_HASH
        elif 'file' in path_lower:
            return ObservableType.FILE
        elif 'email' in path_lower:
            return ObservableType.EMAIL
        
        # Check parameters
        for param in parameters:
            param_name = param.get('name', '').lower()
            if param_name in ['ip', 'ip_address', 'ipaddress']:
                return ObservableType.IP
            elif param_name in ['domain', 'hostname']:
                return ObservableType.DOMAIN
            elif param_name in ['url']:
                return ObservableType.URL
            elif param_name in ['hash', 'file_hash', 'md5', 'sha256']:
                return ObservableType.FILE_HASH
            elif param_name in ['email', 'email_address']:
                return ObservableType.EMAIL
        
        return None
    
    def _generate_integration_id(self, title: str) -> str:
        """Generate integration ID from title"""
        # Convert to lowercase, replace spaces with underscores
        integration_id = title.lower().replace(' ', '_').replace('-', '_')
        # Remove special characters
        integration_id = ''.join(c for c in integration_id if c.isalnum() or c == '_')
        return integration_id
    
    async def update_integration(
        self,
        integration_id: str,
        spec_url: Optional[str] = None
    ) -> Integration:
        """
        Update an existing integration from its OpenAPI spec
        
        Detects changes and updates actions accordingly.
        """
        integration = self.registry.get(integration_id)
        if not integration:
            raise ValueError(f"Integration {integration_id} not found")
        
        # Get spec URL
        if not spec_url:
            spec_url = integration.openapi_spec_url
        
        if not spec_url:
            raise ValueError("No OpenAPI spec URL found for integration")
        
        # Re-ingest
        updated_integration = await self.ingest_from_url(
            spec_url,
            integration_id=integration_id,
            integration_type=integration.type,
            enabled=integration.enabled
        )
        
        return updated_integration


# Singleton instance
_ingestion_engine: Optional[SwaggerIngestionEngine] = None


def get_ingestion_engine() -> SwaggerIngestionEngine:
    """Get the global Swagger ingestion engine instance"""
    global _ingestion_engine
    if _ingestion_engine is None:
        _ingestion_engine = SwaggerIngestionEngine()
    return _ingestion_engine
