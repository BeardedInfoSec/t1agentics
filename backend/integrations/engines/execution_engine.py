# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Integration Execution Engine

Unified execution flow for all integration actions.
NO integration may bypass this engine.

Responsibilities:
1. Authenticate caller (actor)
2. Check action permissions
3. Evaluate enrichment policy (if applicable)
4. Check cache
5. Inject credentials
6. Execute API call
7. Normalize output
8. Cache results
9. Emit events
10. Audit logging
"""

import asyncio
import httpx
import json
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from enum import Enum

from integrations.observables import Observable, ObservableType, EnrichmentResult
from integrations.registry.integration_registry import get_registry, Integration, ActionSchema
from integrations.policies.enrichment_policy import evaluate_enrichment_policy, PolicyDecision
from integrations.policies.action_permissions import check_action_permission, PermissionDecision
from integrations.policies.data_retention import get_cache_ttl_days
from integrations.policies.circuit_breaker import get_circuit_breaker_registry, CircuitBreakerOpenError
from integrations.policies.rate_limiter import get_rate_limiter, RateLimitStatus


class ExecutionStatus(str, Enum):
    """Execution status"""
    SUCCESS = "success"
    FAILED = "failed"
    DENIED = "denied"
    CACHED = "cached"
    POLICY_BLOCKED = "policy_blocked"
    CIRCUIT_OPEN = "circuit_open"  # Integration circuit breaker is open
    RATE_LIMITED = "rate_limited"  # Rate limit exceeded


class ExecutionContext(BaseModel):
    """Context for an integration execution"""
    actor_id: str
    actor_type: str
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        json_schema_extra = {
            "example": {
                "actor_id": "ai_analyst",
                "actor_type": "ai_agent",
                "request_id": "req_abc123",
                "metadata": {"investigation_id": "inv-123"}
            }
        }


class ExecutionRequest(BaseModel):
    """Request to execute an integration action"""
    integration_id: str
    action_id: str
    input_payload: Dict[str, Any]
    context: ExecutionContext
    observable: Optional[Observable] = None
    force_refresh: bool = Field(default=False)  # Skip cache
    
    class Config:
        json_schema_extra = {
            "example": {
                "integration_id": "virustotal",
                "action_id": "enrich_hash",
                "input_payload": {"hash": "44d88612fea8a8f36de82e1278abb02f"},
                "context": {
                    "actor_id": "ai_analyst",
                    "actor_type": "ai_agent"
                }
            }
        }


class ExecutionResult(BaseModel):
    """Result of an integration execution"""
    status: ExecutionStatus
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    # Metadata
    cached: bool = Field(default=False)
    cache_age_seconds: Optional[int] = None
    execution_time_ms: Optional[int] = None
    
    # Policy decisions
    permission_decision: Optional[PermissionDecision] = None
    enrichment_decision: Optional[PolicyDecision] = None
    rate_limit_status: Optional[RateLimitStatus] = None

    # Audit trail
    integration_id: str
    action_id: str
    actor_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "success": True,
                "data": {
                    "malicious": 42,
                    "verdict": "malicious"
                },
                "cached": False,
                "execution_time_ms": 523,
                "integration_id": "virustotal",
                "action_id": "enrich_hash",
                "actor_id": "ai_analyst",
                "timestamp": "2025-12-15T03:00:00Z"
            }
        }


class IntegrationCache:
    """In-memory cache for integration results"""
    
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
    
    def _make_key(
        self,
        integration_id: str,
        action_id: str,
        input_payload: Dict[str, Any]
    ) -> str:
        """Generate cache key"""
        payload_str = json.dumps(input_payload, sort_keys=True)
        return f"{integration_id}:{action_id}:{payload_str}"
    
    def get(
        self,
        integration_id: str,
        action_id: str,
        input_payload: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Get cached result"""
        key = self._make_key(integration_id, action_id, input_payload)
        cached = self._cache.get(key)
        
        if not cached:
            return None
        
        # Check if expired
        ttl_days = get_cache_ttl_days(integration_id, action_id)
        cached_at = datetime.fromisoformat(cached['cached_at'])
        expires_at = cached_at + timedelta(days=ttl_days)
        
        if datetime.utcnow() > expires_at:
            # Expired, remove from cache
            del self._cache[key]
            return None
        
        return cached
    
    def set(
        self,
        integration_id: str,
        action_id: str,
        input_payload: Dict[str, Any],
        result: Dict[str, Any]
    ) -> None:
        """Store result in cache"""
        key = self._make_key(integration_id, action_id, input_payload)
        self._cache[key] = {
            'result': result,
            'cached_at': datetime.utcnow().isoformat(),
            'integration_id': integration_id,
            'action_id': action_id
        }
    
    def invalidate(
        self,
        integration_id: Optional[str] = None,
        action_id: Optional[str] = None
    ) -> int:
        """Invalidate cache entries"""
        if not integration_id:
            # Clear entire cache
            count = len(self._cache)
            self._cache.clear()
            return count
        
        # Remove matching entries
        keys_to_remove = []
        for key, value in self._cache.items():
            if value['integration_id'] == integration_id:
                if not action_id or value['action_id'] == action_id:
                    keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._cache[key]
        
        return len(keys_to_remove)
    
    def cleanup_expired(self) -> int:
        """Remove expired entries"""
        keys_to_remove = []
        
        for key, value in self._cache.items():
            integration_id = value['integration_id']
            action_id = value['action_id']
            ttl_days = get_cache_ttl_days(integration_id, action_id)
            
            cached_at = datetime.fromisoformat(value['cached_at'])
            expires_at = cached_at + timedelta(days=ttl_days)
            
            if datetime.utcnow() > expires_at:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._cache[key]
        
        return len(keys_to_remove)


class IntegrationExecutionEngine:
    """
    Integration Execution Engine
    
    Central execution engine for all integration actions.
    Enforces permissions, policies, caching, and auditing.
    """
    
    def __init__(self):
        self.registry = get_registry()
        self.cache = IntegrationCache()
        self.event_handlers: List[callable] = []
    
    async def execute(self, request: ExecutionRequest) -> ExecutionResult:
        """
        Execute an integration action
        
        This is the ONLY way to execute integration actions.
        All safety checks are enforced here.
        """
        start_time = datetime.utcnow()
        
        # 1. Get integration and action
        integration = self.registry.get(request.integration_id)
        if not integration:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                success=False,
                error=f"Integration {request.integration_id} not found",
                integration_id=request.integration_id,
                action_id=request.action_id,
                actor_id=request.context.actor_id
            )
        
        if not integration.enabled:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                success=False,
                error=f"Integration {request.integration_id} is disabled",
                integration_id=request.integration_id,
                action_id=request.action_id,
                actor_id=request.context.actor_id
            )
        
        action = self.registry.get_action(request.integration_id, request.action_id)
        if not action:
            return ExecutionResult(
                status=ExecutionStatus.FAILED,
                success=False,
                error=f"Action {request.action_id} not found in integration {request.integration_id}",
                integration_id=request.integration_id,
                action_id=request.action_id,
                actor_id=request.context.actor_id
            )
        
        # 2. Check action permissions (skip for automated/service actors)
        permission_decision = None
        if action.requires_permission and getattr(request.context, 'actor_type', '') != 'automation':
            permission_decision = check_action_permission(
                request.context.actor_id,
                request.integration_id,
                request.action_id
            )

            if not permission_decision.allowed:
                result = ExecutionResult(
                    status=ExecutionStatus.DENIED,
                    success=False,
                    error=f"Permission denied: {permission_decision.reason}",
                    permission_decision=permission_decision,
                    integration_id=request.integration_id,
                    action_id=request.action_id,
                    actor_id=request.context.actor_id
                )
                await self._emit_event("integration.action.denied", result)
                return result
        
        # 3. Evaluate enrichment policy (if applicable)
        enrichment_decision = None
        if action.policy_enforced and request.observable:
            enrichment_decision = evaluate_enrichment_policy(request.observable)
            
            if not enrichment_decision.allowed:
                result = ExecutionResult(
                    status=ExecutionStatus.POLICY_BLOCKED,
                    success=False,
                    error=f"Enrichment policy blocked: {enrichment_decision.reason}",
                    enrichment_decision=enrichment_decision,
                    integration_id=request.integration_id,
                    action_id=request.action_id,
                    actor_id=request.context.actor_id
                )
                await self._emit_event("enrichment.blocked", result)
                return result
        
        # 4. Check cache (if cacheable and not forced refresh)
        if action.cacheable and not request.force_refresh:
            cached_result = self.cache.get(
                request.integration_id,
                request.action_id,
                request.input_payload
            )
            
            if cached_result:
                cache_age = (datetime.utcnow() - datetime.fromisoformat(cached_result['cached_at'])).total_seconds()
                
                result = ExecutionResult(
                    status=ExecutionStatus.CACHED,
                    success=True,
                    data=cached_result['result'],
                    cached=True,
                    cache_age_seconds=int(cache_age),
                    permission_decision=permission_decision,
                    enrichment_decision=enrichment_decision,
                    integration_id=request.integration_id,
                    action_id=request.action_id,
                    actor_id=request.context.actor_id
                )
                await self._emit_event("integration.action.cached", result)
                return result
        
        # 5. Check circuit breaker
        circuit_registry = get_circuit_breaker_registry()
        if not circuit_registry.can_call(request.integration_id):
            breaker_status = circuit_registry.get_status(request.integration_id)
            retry_in = breaker_status.get('time_until_retry_seconds') if breaker_status else None

            result = ExecutionResult(
                status=ExecutionStatus.CIRCUIT_OPEN,
                success=False,
                error=f"Circuit breaker open for {request.integration_id}. Retry in {retry_in}s." if retry_in else f"Circuit breaker open for {request.integration_id}",
                permission_decision=permission_decision,
                enrichment_decision=enrichment_decision,
                integration_id=request.integration_id,
                action_id=request.action_id,
                actor_id=request.context.actor_id
            )
            await self._emit_event("integration.circuit_open", result)
            return result

        # 6. Check rate limit
        rate_limiter = get_rate_limiter()
        rate_limit_status = rate_limiter.try_acquire(
            request.integration_id,
            request.action_id,
            action.rate_limit_per_minute
        )

        if not rate_limit_status.allowed:
            result = ExecutionResult(
                status=ExecutionStatus.RATE_LIMITED,
                success=False,
                error=f"Rate limit exceeded for {request.integration_id}. Retry in {rate_limit_status.wait_seconds:.1f}s." if rate_limit_status.wait_seconds else f"Rate limit exceeded for {request.integration_id}",
                permission_decision=permission_decision,
                enrichment_decision=enrichment_decision,
                rate_limit_status=rate_limit_status,
                integration_id=request.integration_id,
                action_id=request.action_id,
                actor_id=request.context.actor_id
            )
            await self._emit_event("integration.rate_limited", result)
            return result

        # 7. Execute API call
        try:
            api_result = await self._execute_api_call(
                integration,
                action,
                request.input_payload
            )

            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Record success for circuit breaker
            circuit_registry.record_success(request.integration_id)

            result = ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                success=True,
                data=api_result,
                cached=False,
                execution_time_ms=int(execution_time),
                permission_decision=permission_decision,
                enrichment_decision=enrichment_decision,
                rate_limit_status=rate_limit_status,
                integration_id=request.integration_id,
                action_id=request.action_id,
                actor_id=request.context.actor_id
            )

            # 8. Cache result (if cacheable)
            if action.cacheable:
                self.cache.set(
                    request.integration_id,
                    request.action_id,
                    request.input_payload,
                    api_result
                )

            # 9. Emit success event
            await self._emit_event("integration.action.executed", result)

            return result

        except Exception as e:
            execution_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Record failure for circuit breaker
            circuit_registry.record_failure(request.integration_id, str(e))

            result = ExecutionResult(
                status=ExecutionStatus.FAILED,
                success=False,
                error=str(e),
                execution_time_ms=int(execution_time),
                permission_decision=permission_decision,
                enrichment_decision=enrichment_decision,
                rate_limit_status=rate_limit_status,
                integration_id=request.integration_id,
                action_id=request.action_id,
                actor_id=request.context.actor_id
            )

            await self._emit_event("integration.action.failed", result)
            return result
    
    async def _execute_api_call(
        self,
        integration: Integration,
        action: ActionSchema,
        input_payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the actual API call"""
        
        # Build URL
        url = integration.base_url + action.endpoint
        
        # Replace path parameters
        for key, value in input_payload.items():
            url = url.replace(f"{{{key}}}", str(value))
        
        # Build headers
        headers = action.headers.copy()
        
        # Inject authentication
        if action.requires_auth:
            headers = await self._inject_auth(integration, headers)
        
        # Extract auth query params from headers (if API key location is "query")
        auth_query_params = {}
        headers_clean = {}
        for key, value in headers.items():
            if key.startswith("__auth_query__"):
                param_name = key.replace("__auth_query__", "")
                auth_query_params[param_name] = value
            else:
                headers_clean[key] = value
        headers = headers_clean

        # Make request
        async with httpx.AsyncClient() as client:
            if action.http_method.upper() == "GET":
                # For GET requests, merge action.query_params with input_payload
                # input_payload params that weren't used as path params should be query params
                query_params = dict(action.query_params) if action.query_params else {}

                # Add auth query params (e.g., IPInfo token parameter)
                query_params.update(auth_query_params)

                # Add input_payload values that aren't path parameters as query params
                # Build a map of internal_name -> api_name from action parameters
                # Also track which params are explicitly marked as path params (in: "path")
                param_api_names = {}
                path_params = set()
                for param in action.parameters:
                    internal_name = param.get('name', '')
                    # Use api_name if defined, otherwise use name as-is
                    api_name = param.get('api_name', internal_name)
                    param_api_names[internal_name] = api_name
                    # Check if explicitly marked as path param
                    if param.get('in') == 'path':
                        path_params.add(internal_name)

                for key, value in input_payload.items():
                    # Skip if explicitly marked as path param OR if placeholder exists in endpoint
                    if key in path_params or f"{{{key}}}" in action.endpoint:
                        continue
                    # Map to API name if defined in parameters
                    api_key = param_api_names.get(key, key)
                    query_params[api_key] = value

                response = await client.get(
                    url,
                    headers=headers,
                    params=query_params,
                    timeout=30.0
                )
            elif action.http_method.upper() == "POST":
                # Choose content type based on action.content_type
                content_type = getattr(action, 'content_type', 'application/json')
                if content_type == "application/x-www-form-urlencoded":
                    response = await client.post(
                        url,
                        headers=headers,
                        data=input_payload,
                        timeout=30.0
                    )
                elif content_type == "multipart/form-data":
                    # For multipart, input_payload may contain:
                    # - 'file_data': base64 encoded file content
                    # - 'file_name': name of the file
                    # - 'file_content_type': MIME type of the file
                    # OR already formatted 'files' dict for httpx
                    import base64
                    files = input_payload.pop('files', None)
                    file_data = input_payload.pop('file_data', None)
                    file_name = input_payload.pop('file_name', 'file')
                    file_content_type = input_payload.pop('file_content_type', 'application/octet-stream')

                    if file_data and not files:
                        # Decode base64 file data
                        try:
                            decoded_data = base64.b64decode(file_data)
                            files = {'file': (file_name, decoded_data, file_content_type)}
                        except Exception as e:
                            raise ValueError(f"Failed to decode file data: {e}")

                    # Remove Content-Type header - httpx will set it with boundary for multipart
                    multipart_headers = {k: v for k, v in headers.items() if k.lower() != 'content-type'}

                    response = await client.post(
                        url,
                        headers=multipart_headers,
                        data=input_payload,
                        files=files,
                        timeout=120.0  # Longer timeout for file uploads
                    )
                else:  # application/json
                    response = await client.post(
                        url,
                        headers=headers,
                        json=input_payload,
                        timeout=30.0
                    )
            elif action.http_method.upper() == "PUT":
                # Choose content type based on action.content_type
                content_type = getattr(action, 'content_type', 'application/json')
                if content_type == "application/x-www-form-urlencoded":
                    response = await client.put(
                        url,
                        headers=headers,
                        data=input_payload,
                        timeout=30.0
                    )
                else:  # application/json
                    response = await client.put(
                        url,
                        headers=headers,
                        json=input_payload,
                        timeout=30.0
                    )
            elif action.http_method.upper() == "DELETE":
                response = await client.delete(
                    url,
                    headers=headers,
                    timeout=30.0
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {action.http_method}")

            response.raise_for_status()

            # Handle empty response body gracefully
            response_text = response.text.strip()
            if not response_text:
                # Empty response is valid for some APIs (e.g., URLScan.io search with no results)
                return {"results": [], "total": 0, "_empty_response": True}

            try:
                return response.json()
            except Exception as json_err:
                # Log the issue but don't fail - return raw text wrapped
                print(f"[ExecutionEngine] Warning: Failed to parse JSON response: {json_err}. Response: {response_text[:200]}")
                return {"_raw_response": response_text, "_parse_error": str(json_err)}
    
    async def _inject_auth(
        self,
        integration: Integration,
        headers: Dict[str, str]
    ) -> Dict[str, str]:
        """
        Inject authentication credentials into headers.

        If credential_id is set, fetches from credential vault.
        Otherwise uses auth_config directly (for backwards compatibility).
        """
        # Check if auth headers were pre-resolved by T1 Connect bridge
        resolved = integration.auth_config.get('_resolved_headers')
        if resolved:
            headers.update(resolved)
            return headers

        # Try to find credential_id - first from integration object, then from DB
        credential_id = integration.credential_id

        # If no credential_id on integration, look up in database
        if not credential_id:
            try:
                from services.postgres_db import postgres_db
                if postgres_db.connected and postgres_db.pool:
                    async with postgres_db.tenant_acquire() as conn:
                        # Look up credential that has this integration in its integration_ids
                        row = await conn.fetchrow(
                            """SELECT credential_id FROM credentials_vault
                               WHERE integration_ids::text ILIKE $1
                               LIMIT 1""",
                            f'%{integration.id}%'
                        )
                        if row:
                            credential_id = row['credential_id']
                            print(f"[_inject_auth] Found credential_id from DB: {credential_id}")
            except Exception as e:
                print(f"[_inject_auth] DB lookup failed: {e}")

        # If credential_id is set, fetch from credential service
        if credential_id:
            print(f"[_inject_auth] Fetching from credential vault: {credential_id}")
            try:
                from services.credentials_service import get_credentials_service
                cred_service = get_credentials_service()
                auth_headers = await cred_service.get_auth_headers(credential_id)
                print(f"[_inject_auth] Got auth_headers: {list(auth_headers.keys()) if auth_headers else 'None'}")
                if auth_headers:
                    headers.update(auth_headers)
                    print(f"[_inject_auth] Updated headers with credential vault auth")
                    return headers
                else:
                    print(f"[_inject_auth] No auth headers returned from credential service")
            except Exception as e:
                print(f"[_inject_auth] WARNING: Failed to fetch credential {credential_id}: {e}")
                import traceback
                traceback.print_exc()

        # Fallback to auth_config (for legacy/direct config)
        auth_config = integration.auth_config

        if integration.auth_type.value == "api_key":
            key_name = auth_config.get("key_name", "x-api-key")
            key_value = auth_config.get("key_value", "")
            key_location = auth_config.get("key_location", "header")

            if key_value:
                if key_location == "query":
                    # Return query params to be added by caller
                    # Store in headers dict with special prefix for extraction later
                    headers[f"__auth_query__{key_name}"] = key_value
                else:  # header (default)
                    headers[key_name] = key_value

        elif integration.auth_type.value == "bearer_token":
            token = auth_config.get("token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"

        elif integration.auth_type.value == "basic_auth":
            import base64
            username = auth_config.get("username", "")
            password = auth_config.get("password", "")
            if username or password:
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {credentials}"

        elif integration.auth_type.value == "custom_header":
            for key, value in auth_config.items():
                if key.startswith("header_"):
                    header_name = key.replace("header_", "")
                    headers[header_name] = value

        return headers
    
    async def _emit_event(self, event_type: str, result: ExecutionResult) -> None:
        """Emit event to registered handlers"""
        event = {
            "type": event_type,
            "result": result.model_dump(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        for handler in self.event_handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                print(f"Error in event handler: {e}")
    
    def register_event_handler(self, handler: callable) -> None:
        """Register an event handler"""
        self.event_handlers.append(handler)
    
    def invalidate_cache(
        self,
        integration_id: Optional[str] = None,
        action_id: Optional[str] = None
    ) -> int:
        """Invalidate cache entries"""
        return self.cache.invalidate(integration_id, action_id)
    
    def cleanup_expired_cache(self) -> int:
        """Remove expired cache entries"""
        return self.cache.cleanup_expired()


# Singleton instance
_execution_engine: Optional[IntegrationExecutionEngine] = None


def get_execution_engine() -> IntegrationExecutionEngine:
    """Get the global execution engine instance"""
    global _execution_engine
    if _execution_engine is None:
        _execution_engine = IntegrationExecutionEngine()
    return _execution_engine
