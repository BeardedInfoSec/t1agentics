# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Action Execution Engine - Job Runner for API Calls

Handles:
- Executing API calls with proper authentication
- Automatic token refresh for expired credentials
- Retry logic with exponential backoff
- Rate limiting per integration
- Job queuing and execution history
- Async execution with callbacks
"""

import asyncio
import httpx
import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Callable, Awaitable
from enum import Enum
from pydantic import BaseModel, Field
from collections import defaultdict
import time

logger = logging.getLogger(__name__)


class JobStatus(str, Enum):
    """Status of an execution job"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    RETRYING = "retrying"
    CANCELLED = "cancelled"
    TOKEN_REFRESH = "token_refresh"


class HttpMethod(str, Enum):
    """Supported HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class ActionRequest(BaseModel):
    """Request to execute an API action"""
    # Identification
    action_id: Optional[str] = Field(default_factory=lambda: f"action_{secrets.token_urlsafe(8)}")
    integration_id: Optional[str] = None  # For rate limiting and logging
    
    # Request details
    url: str
    method: HttpMethod = HttpMethod.GET
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    
    # Authentication
    credential_id: Optional[str] = None  # Use stored credential
    
    # Execution options
    timeout_seconds: int = 30
    retry_count: int = 3
    retry_backoff_seconds: float = 1.0
    
    # Callbacks
    callback_url: Optional[str] = None  # Webhook to call on completion
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True


class ActionResult(BaseModel):
    """Result of an action execution"""
    action_id: str
    status: JobStatus
    
    # Response data
    status_code: Optional[int] = None
    response_body: Optional[Any] = None
    response_headers: Optional[Dict[str, str]] = None
    
    # Timing
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    
    # Retry info
    attempt_number: int = 1
    total_attempts: int = 1
    
    # Error info
    error: Optional[str] = None
    error_type: Optional[str] = None
    
    # Token refresh info
    token_refreshed: bool = False
    
    # Metadata
    integration_id: Optional[str] = None
    credential_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self):
        self._calls: Dict[str, List[float]] = defaultdict(list)
        self._limits: Dict[str, int] = {}  # calls per minute
    
    def set_limit(self, key: str, calls_per_minute: int):
        """Set rate limit for a key (e.g., integration_id)"""
        self._limits[key] = calls_per_minute
    
    def get_limit(self, key: str) -> int:
        """Get rate limit for a key"""
        return self._limits.get(key, 60)  # Default 60/min
    
    async def acquire(self, key: str) -> bool:
        """
        Try to acquire a rate limit slot.
        Returns True if allowed, False if rate limited.
        """
        now = time.time()
        limit = self.get_limit(key)
        
        # Clean old entries (older than 1 minute)
        self._calls[key] = [t for t in self._calls[key] if now - t < 60]
        
        if len(self._calls[key]) >= limit:
            return False
        
        self._calls[key].append(now)
        return True
    
    async def wait_for_slot(self, key: str, timeout: float = 60.0) -> bool:
        """Wait until a rate limit slot is available"""
        start = time.time()
        while time.time() - start < timeout:
            if await self.acquire(key):
                return True
            await asyncio.sleep(0.1)
        return False
    
    def get_wait_time(self, key: str) -> float:
        """Get estimated wait time in seconds"""
        now = time.time()
        self._calls[key] = [t for t in self._calls[key] if now - t < 60]
        
        if len(self._calls[key]) < self.get_limit(key):
            return 0
        
        # Return time until oldest call expires
        oldest = min(self._calls[key])
        return max(0, 60 - (now - oldest))


class TokenRefresher:
    """Handles automatic token refresh"""
    
    def __init__(self, credentials_service):
        self.credentials_service = credentials_service
        self._refresh_locks: Dict[str, asyncio.Lock] = {}
    
    async def check_and_refresh(self, credential_id: str) -> bool:
        """
        Check if token needs refresh and refresh if necessary.
        Returns True if token was refreshed or is valid.
        """
        # Get credential
        cred = await self.credentials_service.get(credential_id, include_secrets=False)
        if not cred:
            logger.error(f"Credential {credential_id} not found")
            return False
        
        # Check if bearer token with expiry
        if cred.auth_type.value != 'bearer':
            return True  # Not a bearer token, no refresh needed
        
        # Get the record with secrets for refresh
        record = await self.credentials_service._get_record(credential_id)
        if not record:
            return False
        
        # Check expiry
        token_expires_at = record.get("token_expires_at")
        if not token_expires_at:
            return True  # No expiry set, assume valid
        
        # Parse expiry
        if isinstance(token_expires_at, str):
            expires_at = datetime.fromisoformat(token_expires_at.replace('Z', '+00:00'))
        else:
            expires_at = token_expires_at
        
        # Add buffer (refresh 5 minutes before expiry)
        buffer = timedelta(minutes=5)
        if datetime.utcnow() < (expires_at - buffer):
            return True  # Token still valid
        
        # Need to refresh - use lock to prevent concurrent refreshes
        if credential_id not in self._refresh_locks:
            self._refresh_locks[credential_id] = asyncio.Lock()
        
        async with self._refresh_locks[credential_id]:
            # Double-check after acquiring lock
            record = await self.credentials_service._get_record(credential_id)
            token_expires_at = record.get("token_expires_at")
            if token_expires_at:
                if isinstance(token_expires_at, str):
                    expires_at = datetime.fromisoformat(token_expires_at.replace('Z', '+00:00'))
                else:
                    expires_at = token_expires_at
                if datetime.utcnow() < (expires_at - buffer):
                    return True  # Another task already refreshed
            
            return await self._do_refresh(credential_id, record)
    
    async def _do_refresh(self, credential_id: str, record: Dict[str, Any]) -> bool:
        """Actually perform the token refresh"""
        token_url = record.get("token_url")
        if not token_url:
            logger.warning(f"No token_url configured for credential {credential_id}")
            return False
        
        # Get refresh token
        encrypted_secrets = json.loads(record.get("encrypted_secrets", "{}"))
        refresh_token = self.credentials_service.vault.decrypt(
            encrypted_secrets.get("refresh_token", "")
        )
        
        if not refresh_token:
            logger.warning(f"No refresh_token available for credential {credential_id}")
            return False
        
        logger.info(f"Refreshing token for credential {credential_id}")
        
        try:
            async with httpx.AsyncClient() as client:
                # Standard OAuth2 refresh request
                response = await client.post(
                    token_url,
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": refresh_token
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    timeout=30.0
                )
                
                if response.status_code != 200:
                    logger.error(f"Token refresh failed: {response.status_code} - {response.text}")
                    return False
                
                data = response.json()
                
                # Update credential with new tokens
                new_access_token = data.get("access_token")
                new_refresh_token = data.get("refresh_token", refresh_token)
                expires_in = data.get("expires_in", 3600)  # Default 1 hour
                
                if not new_access_token:
                    logger.error("No access_token in refresh response")
                    return False
                
                # Calculate new expiry
                new_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
                
                # Update encrypted secrets
                encrypted_secrets["bearer_token"] = self.credentials_service.vault.encrypt(new_access_token)
                encrypted_secrets["refresh_token"] = self.credentials_service.vault.encrypt(new_refresh_token)
                
                record["encrypted_secrets"] = json.dumps(encrypted_secrets)
                record["token_expires_at"] = new_expires_at.isoformat()
                record["updated_at"] = datetime.utcnow().isoformat()
                
                # Save updated record
                if self.credentials_service.db:
                    await self.credentials_service._update_in_db(credential_id, record)
                else:
                    self.credentials_service._memory_store[credential_id] = record
                
                logger.info(f"Token refreshed successfully for {credential_id}, expires at {new_expires_at}")
                return True
                
        except Exception as e:
            logger.error(f"Token refresh error for {credential_id}: {e}")
            return False


class ActionExecutionEngine:
    """
    Main execution engine for API actions.
    
    Features:
    - Execute HTTP requests with authentication
    - Automatic token refresh
    - Retry with exponential backoff
    - Rate limiting per integration
    - Job history tracking
    - Async callbacks
    """
    
    def __init__(self, credentials_service=None):
        self.credentials_service = credentials_service
        self.rate_limiter = RateLimiter()
        self.token_refresher = None
        
        # Job tracking
        self._jobs: Dict[str, ActionResult] = {}
        self._job_queue: asyncio.Queue = asyncio.Queue()
        self._running = False
        self._workers: List[asyncio.Task] = []
        
        # Event handlers
        self._on_complete_handlers: List[Callable[[ActionResult], Awaitable[None]]] = []
        
        # Stats
        self._stats = {
            "total_executed": 0,
            "successful": 0,
            "failed": 0,
            "retries": 0,
            "tokens_refreshed": 0
        }
    
    def set_credentials_service(self, credentials_service):
        """Set the credentials service (for dependency injection)"""
        self.credentials_service = credentials_service
        self.token_refresher = TokenRefresher(credentials_service)
    
    def set_rate_limit(self, integration_id: str, calls_per_minute: int):
        """Set rate limit for an integration"""
        self.rate_limiter.set_limit(integration_id, calls_per_minute)
    
    def on_complete(self, handler: Callable[[ActionResult], Awaitable[None]]):
        """Register a handler to be called when an action completes"""
        self._on_complete_handlers.append(handler)
    
    async def start_workers(self, num_workers: int = 5):
        """Start background worker tasks"""
        if self._running:
            return
        
        self._running = True
        for i in range(num_workers):
            task = asyncio.create_task(self._worker(i))
            self._workers.append(task)
        
        logger.info(f"Started {num_workers} execution workers")
    
    async def stop_workers(self):
        """Stop background workers"""
        self._running = False
        for task in self._workers:
            task.cancel()
        self._workers = []
        logger.info("Stopped execution workers")
    
    async def _worker(self, worker_id: int):
        """Background worker that processes the job queue"""
        logger.info(f"Worker {worker_id} started")
        
        while self._running:
            try:
                # Wait for a job with timeout
                try:
                    request = await asyncio.wait_for(
                        self._job_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Execute the job
                result = await self._execute_with_retry(request)
                
                # Call completion handlers
                for handler in self._on_complete_handlers:
                    try:
                        await handler(result)
                    except Exception as e:
                        logger.error(f"Error in completion handler: {e}")
                
                # Call webhook callback if specified
                if request.callback_url:
                    await self._call_callback(request.callback_url, result)
                
                self._job_queue.task_done()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Worker {worker_id} error: {e}")
    
    async def execute(self, request: ActionRequest) -> ActionResult:
        """
        Execute an action synchronously (wait for result).
        """
        return await self._execute_with_retry(request)
    
    async def execute_async(self, request: ActionRequest) -> str:
        """
        Queue an action for async execution.
        Returns the action_id for tracking.
        """
        # Create initial job entry
        self._jobs[request.action_id] = ActionResult(
            action_id=request.action_id,
            status=JobStatus.PENDING,
            started_at=datetime.utcnow(),
            integration_id=request.integration_id,
            credential_id=request.credential_id,
            metadata=request.metadata
        )
        
        # Queue the request
        await self._job_queue.put(request)
        
        return request.action_id
    
    def get_job_status(self, action_id: str) -> Optional[ActionResult]:
        """Get the status of a job"""
        return self._jobs.get(action_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get execution statistics"""
        return {
            **self._stats,
            "pending_jobs": self._job_queue.qsize(),
            "tracked_jobs": len(self._jobs)
        }
    
    async def _execute_with_retry(self, request: ActionRequest) -> ActionResult:
        """Execute request with retry logic"""
        started_at = datetime.utcnow()
        last_error = None
        token_refreshed = False
        
        for attempt in range(1, request.retry_count + 1):
            try:
                # Update job status
                self._jobs[request.action_id] = ActionResult(
                    action_id=request.action_id,
                    status=JobStatus.RUNNING if attempt == 1 else JobStatus.RETRYING,
                    started_at=started_at,
                    attempt_number=attempt,
                    total_attempts=request.retry_count,
                    integration_id=request.integration_id,
                    credential_id=request.credential_id,
                    token_refreshed=token_refreshed,
                    metadata=request.metadata
                )
                
                # Check rate limit
                rate_key = request.integration_id or "default"
                if not await self.rate_limiter.wait_for_slot(rate_key, timeout=30.0):
                    raise Exception(f"Rate limit exceeded for {rate_key}")
                
                # Check and refresh token if needed
                if request.credential_id and self.token_refresher:
                    refreshed = await self.token_refresher.check_and_refresh(request.credential_id)
                    if refreshed and not token_refreshed:
                        # Token was just refreshed
                        token_refreshed = True
                        self._stats["tokens_refreshed"] += 1
                
                # Build headers with authentication
                headers = dict(request.headers)
                if request.credential_id and self.credentials_service:
                    auth_headers = await self.credentials_service.get_auth_headers(request.credential_id)
                    headers.update(auth_headers)
                
                # Execute request
                result = await self._make_request(request, headers)
                
                # Success
                completed_at = datetime.utcnow()
                duration_ms = int((completed_at - started_at).total_seconds() * 1000)
                
                self._stats["total_executed"] += 1
                self._stats["successful"] += 1
                
                final_result = ActionResult(
                    action_id=request.action_id,
                    status=JobStatus.SUCCESS,
                    status_code=result["status_code"],
                    response_body=result["body"],
                    response_headers=result["headers"],
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_ms=duration_ms,
                    attempt_number=attempt,
                    total_attempts=attempt,
                    token_refreshed=token_refreshed,
                    integration_id=request.integration_id,
                    credential_id=request.credential_id,
                    metadata=request.metadata
                )
                
                self._jobs[request.action_id] = final_result
                return final_result
                
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Attempt {attempt}/{request.retry_count} failed for {request.action_id}: {e}")
                
                if attempt < request.retry_count:
                    # Exponential backoff
                    wait_time = request.retry_backoff_seconds * (2 ** (attempt - 1))
                    self._stats["retries"] += 1
                    await asyncio.sleep(wait_time)
        
        # All retries exhausted
        completed_at = datetime.utcnow()
        duration_ms = int((completed_at - started_at).total_seconds() * 1000)
        
        self._stats["total_executed"] += 1
        self._stats["failed"] += 1
        
        final_result = ActionResult(
            action_id=request.action_id,
            status=JobStatus.FAILED,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            attempt_number=request.retry_count,
            total_attempts=request.retry_count,
            error=last_error,
            error_type=type(last_error).__name__ if last_error else None,
            token_refreshed=token_refreshed,
            integration_id=request.integration_id,
            credential_id=request.credential_id,
            metadata=request.metadata
        )
        
        self._jobs[request.action_id] = final_result
        return final_result
    
    async def _make_request(
        self,
        request: ActionRequest,
        headers: Dict[str, str]
    ) -> Dict[str, Any]:
        """Make the actual HTTP request"""
        async with httpx.AsyncClient() as client:
            # Build request kwargs
            kwargs = {
                "url": request.url,
                "headers": headers,
                "params": request.query_params if request.query_params else None,
                "timeout": request.timeout_seconds
            }
            
            # Add body for methods that support it
            if request.method in [HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH]:
                if request.body:
                    kwargs["json"] = request.body
            
            # Make request
            response = await client.request(request.method, **kwargs)
            
            # Check for errors
            if response.status_code >= 400:
                # Try to get error message from response
                try:
                    error_body = response.json()
                except:
                    error_body = response.text
                raise Exception(f"HTTP {response.status_code}: {error_body}")
            
            # Parse response
            try:
                body = response.json()
            except:
                body = response.text
            
            return {
                "status_code": response.status_code,
                "body": body,
                "headers": dict(response.headers)
            }
    
    async def _call_callback(self, callback_url: str, result: ActionResult):
        """Call webhook callback with result"""
        try:
            async with httpx.AsyncClient() as client:
                await client.post(
                    callback_url,
                    json=result.dict(),
                    timeout=10.0
                )
        except Exception as e:
            logger.error(f"Failed to call callback {callback_url}: {e}")
    
    # Convenience methods for common operations
    
    async def get(
        self,
        url: str,
        credential_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ActionResult:
        """Convenience method for GET requests"""
        return await self.execute(ActionRequest(
            url=url,
            method=HttpMethod.GET,
            credential_id=credential_id,
            headers=headers or {},
            query_params=params or {},
            **kwargs
        ))
    
    async def post(
        self,
        url: str,
        body: Optional[Dict[str, Any]] = None,
        credential_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ActionResult:
        """Convenience method for POST requests"""
        return await self.execute(ActionRequest(
            url=url,
            method=HttpMethod.POST,
            body=body,
            credential_id=credential_id,
            headers=headers or {},
            **kwargs
        ))
    
    async def put(
        self,
        url: str,
        body: Optional[Dict[str, Any]] = None,
        credential_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ActionResult:
        """Convenience method for PUT requests"""
        return await self.execute(ActionRequest(
            url=url,
            method=HttpMethod.PUT,
            body=body,
            credential_id=credential_id,
            headers=headers or {},
            **kwargs
        ))
    
    async def delete(
        self,
        url: str,
        credential_id: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs
    ) -> ActionResult:
        """Convenience method for DELETE requests"""
        return await self.execute(ActionRequest(
            url=url,
            method=HttpMethod.DELETE,
            credential_id=credential_id,
            headers=headers or {},
            **kwargs
        ))


# Singleton instance
_execution_engine: Optional[ActionExecutionEngine] = None


def get_execution_engine() -> ActionExecutionEngine:
    """Get the global execution engine instance"""
    global _execution_engine
    if _execution_engine is None:
        _execution_engine = ActionExecutionEngine()
    return _execution_engine


async def init_execution_engine(credentials_service=None, num_workers: int = 5):
    """Initialize the execution engine with dependencies"""
    engine = get_execution_engine()
    
    if credentials_service:
        engine.set_credentials_service(credentials_service)
    
    await engine.start_workers(num_workers)
    
    return engine
