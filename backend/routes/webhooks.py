# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Webhook API Routes
Public and admin endpoints for webhook management

Supports multiple log formats:
- JSON (native)
- XML
- CSV
- Syslog (RFC 3164, RFC 5424)
- CEF (Common Event Format)
- LEEF (Log Event Extended Format)
- Plain text (AI-extracted)
- Windows Event Log XML
- Key-value pairs
"""

from fastapi import APIRouter, HTTPException, Header, Body, Depends, Request, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime
from collections import defaultdict
import time
import threading
import secrets
import logging

from services.database import db
from dependencies.auth import get_current_user_or_api_key, User, UserRole
from services.alert_id_generator import generate_alert_id
from services.log_parser_service import get_log_parser, LogFormat

logger = logging.getLogger(__name__)

# Public router (no auth required)
router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

# Admin router (auth required)
admin_router = APIRouter(prefix="/api/v1/admin/webhooks", tags=["webhook-admin"])


# ==================== WEBHOOK RATE LIMITER ====================

class WebhookRateLimiter:
    """
    Sliding window rate limiter for webhook ingestion.
    Tracks request timestamps per webhook and enforces per-hour limits.
    """

    def __init__(self):
        self._requests: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def check_and_consume(self, webhook_name: str, rate_limit: int) -> tuple:
        """
        Check if a request is allowed and record it if so.

        Args:
            webhook_name: The webhook identifier
            rate_limit: Maximum requests allowed per hour

        Returns:
            Tuple of (allowed: bool, remaining: int, retry_after: Optional[int])
            - allowed: Whether the request can proceed
            - remaining: How many more requests are allowed in the current window
            - retry_after: Seconds until the next request would be allowed (None if allowed)
        """
        if rate_limit <= 0:
            # rate_limit of 0 or negative means unlimited
            return True, 0, None

        now = time.time()
        window_start = now - 3600  # 1-hour sliding window

        with self._lock:
            # Prune old entries outside the window
            self._requests[webhook_name] = [
                ts for ts in self._requests[webhook_name] if ts > window_start
            ]

            current_count = len(self._requests[webhook_name])
            remaining = max(0, rate_limit - current_count)

            if current_count >= rate_limit:
                # Rate limit exceeded - calculate retry_after from oldest request in window
                oldest = self._requests[webhook_name][0]
                retry_after = int(oldest - window_start) + 1
                return False, 0, retry_after

            # Allow and record
            self._requests[webhook_name].append(now)
            remaining = max(0, rate_limit - current_count - 1)
            return True, remaining, None

    def get_usage(self, webhook_name: str) -> dict:
        """Get current usage stats for a webhook."""
        now = time.time()
        window_start = now - 3600

        with self._lock:
            self._requests[webhook_name] = [
                ts for ts in self._requests[webhook_name] if ts > window_start
            ]
            return {
                "current_count": len(self._requests[webhook_name]),
                "window": "1 hour"
            }

    def reset(self, webhook_name: str = None):
        """Reset rate limit counters."""
        with self._lock:
            if webhook_name:
                self._requests.pop(webhook_name, None)
            else:
                self._requests.clear()


# Singleton rate limiter instance
_webhook_rate_limiter = WebhookRateLimiter()


# ==================== MODELS ====================

class WebhookCreate(BaseModel):
    name: str
    description: Optional[str] = None
    rate_limit: Optional[int] = 100


class WebhookUpdate(BaseModel):
    # All optional - PATCH-style semantics. Token + webhook_id are immutable.
    name: Optional[str] = None
    description: Optional[str] = None
    rate_limit: Optional[int] = None
    enabled: Optional[bool] = None


class AlertWebhookRequest(BaseModel):
    alert_data: Dict[str, Any]  # Plain JSON, no encryption


# ==================== HEC INGEST ENDPOINT ====================

@router.post("/ingest/{webhook_name}")
async def ingest_webhook(
    webhook_name: str,
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: Optional[str] = Header(None),
    x_log_format: Optional[str] = Header(None, alias="X-Log-Format"),
    x_source_hint: Optional[str] = Header(None, alias="X-Source-Hint")
):
    """
    Universal webhook ingestion endpoint.
    Accepts multiple log formats and auto-detects format.

    Supported formats:
    - JSON (application/json)
    - XML (application/xml, text/xml)
    - CSV (text/csv)
    - Syslog RFC 3164/5424
    - CEF (Common Event Format)
    - LEEF (Log Event Extended Format)
    - Plain text / raw logs (AI-extracted)
    - Windows Event Log XML
    - Key-value pairs

    Headers:
    - Authorization: HEC <token>
    - Content-Type: Format hint (optional, auto-detected)
    - X-Log-Format: Force specific format (json, xml, csv, syslog, cef, leef, raw)
    - X-Source-Hint: Hint about log source for AI extraction (e.g., "firewall", "windows")

    Body: Log data in any supported format
    """
    try:
        # Get the webhook config
        webhook = await db.get_webhook(webhook_name)
        if not webhook:
            raise HTTPException(status_code=404, detail=f"Webhook '{webhook_name}' not found")

        if not webhook.get('enabled', True):
            raise HTTPException(status_code=403, detail="Webhook is disabled")

        # SECURITY: Validate webhook token if configured
        # Token can be provided as:
        # - Authorization: HEC <token>
        # - Authorization: Bearer <token>
        # - X-Webhook-Token: <token>
        stored_token = webhook.get('token')
        if stored_token:
            provided_token = None

            # Check Authorization header
            if authorization:
                if authorization.upper().startswith('HEC '):
                    provided_token = authorization[4:].strip()
                elif authorization.upper().startswith('BEARER '):
                    provided_token = authorization[7:].strip()
                else:
                    provided_token = authorization.strip()

            # Check X-Webhook-Token header as fallback
            if not provided_token:
                provided_token = request.headers.get('X-Webhook-Token', '').strip()

            if not provided_token:
                logger.warning(f"Webhook {webhook_name}: Unauthorized - no token provided")
                raise HTTPException(
                    status_code=401,
                    detail="Unauthorized. Provide token via 'Authorization: HEC <token>' or 'X-Webhook-Token' header."
                )

            # Constant-time comparison to prevent timing attacks
            if not secrets.compare_digest(provided_token, stored_token):
                logger.warning(f"Webhook {webhook_name}: Unauthorized - invalid token")
                raise HTTPException(status_code=401, detail="Unauthorized. Invalid webhook token.")

            logger.debug(f"Webhook {webhook_name}: Token validated successfully")

        # Set tenant context from webhook record (since webhook ingestion
        # is exempt from TenantMiddleware, we resolve tenant from the webhook)
        webhook_tenant_id = webhook.get('tenant_id')
        if webhook_tenant_id:
            from middleware.tenant_middleware import current_tenant_id
            current_tenant_id.set(str(webhook_tenant_id))
            logger.debug(f"Webhook {webhook_name}: Set tenant context to {webhook_tenant_id}")

        # RATE LIMITING: Enforce per-webhook rate limit
        rate_limit = webhook.get('rate_limit', 100)
        if rate_limit and rate_limit > 0:
            allowed, remaining, retry_after = _webhook_rate_limiter.check_and_consume(
                webhook_name, rate_limit
            )
            if not allowed:
                logger.warning(
                    f"Webhook {webhook_name}: Rate limit exceeded "
                    f"({rate_limit}/hr). Retry after {retry_after}s."
                )
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded. This webhook allows {rate_limit} requests per hour. "
                           f"Try again in {retry_after} seconds.",
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(rate_limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Window": "3600"
                    }
                )
            logger.debug(
                f"Webhook {webhook_name}: Rate limit OK ({remaining} remaining of {rate_limit}/hr)"
            )

        # Get raw body content
        raw_body = await request.body()
        content_type = request.headers.get('content-type', '')

        try:
            raw_content = raw_body.decode('utf-8')
        except UnicodeDecodeError:
            try:
                raw_content = raw_body.decode('latin-1')
            except:
                raise HTTPException(status_code=400, detail="Unable to decode request body")

        # Use log parser to detect and parse format
        log_parser = get_log_parser()
        payload, detected_format, parse_metadata = await log_parser.parse(
            raw_content,
            content_type=content_type,
            source_hint=x_source_hint or webhook.get('source_hint')
        )

        logger.info(f"Webhook {webhook_name}: Detected format {detected_format.value}, parsed successfully")

        # Handle wrapped payloads for JSON (e.g., {"alert_data": {...}} or {"event": {...}})
        if detected_format == LogFormat.JSON:
            if 'alert_data' in payload:
                payload = payload['alert_data']
            elif 'event' in payload:
                payload = payload['event']
            elif 'data' in payload and isinstance(payload['data'], dict):
                payload = payload['data']

        # Add parse metadata to payload
        if '_metadata' not in payload:
            payload['_metadata'] = {}
        payload['_metadata']['log_format'] = detected_format.value
        payload['_metadata']['parse_info'] = parse_metadata

        # PCI Compliance: Obfuscate PII before storing.
        # Tenant-defined custom patterns layer on top of the built-ins.
        try:
            from services.pii_obfuscation import get_pii_service
            from services.tenant_pii_patterns_service import get_compiled_for_tenant
            pii_service = get_pii_service()

            # Resolve tenant_id for tenant-specific patterns. Webhook
            # records carry it on the row; failing that, current context.
            _tenant_id = None
            try:
                if webhook and isinstance(webhook, dict):
                    _tenant_id = webhook.get('tenant_id')
                if not _tenant_id:
                    from middleware.tenant_middleware import current_tenant_id as _ctid
                    _tenant_id = _ctid.get()
            except Exception:
                _tenant_id = None

            extra_patterns = await get_compiled_for_tenant(str(_tenant_id)) if _tenant_id else []
            payload, pii_report = pii_service.obfuscate_event(payload, extra_patterns=extra_patterns)
            if pii_report.get('matches_count', 0) > 0:
                logger.info(f"Webhook {webhook_name}: PII obfuscated - {pii_report['matches_count']} items masked for PCI compliance")
                # Store PII report in metadata for audit
                if '_metadata' not in payload:
                    payload['_metadata'] = {}
                payload['_metadata']['pii_obfuscation'] = pii_report
        except Exception as pii_err:
            logger.warning(f"Webhook {webhook_name}: PII obfuscation warning - {pii_err}")

        # Extract alert data - use systematic alert ID format
        existing_id = payload.get('id') or payload.get('event_id') or payload.get('alert_id')
        if existing_id:
            alert_id = existing_id
        else:
            # Generate systematic ID based on source/category
            alert_id = await generate_alert_id(
                source=f'webhook:{webhook_name}',
                source_type=payload.get('source_type'),
                category=payload.get('category'),
                title=payload.get('title')
            )
        title = payload.get('title', 'Webhook Alert')
        description = payload.get('description', '')
        severity = payload.get('severity', 'medium').lower()
        
        # Map severity to priority
        severity_to_priority = {
            'critical': 'P1',
            'high': 'P2', 
            'medium': 'P3',
            'low': 'P4'
        }
        priority = severity_to_priority.get(severity, 'P3')
        
        # Extract vendor information for trust tracking
        # Look for vendor in multiple possible locations
        vendor_name = (
            payload.get('vendor') or
            payload.get('source_vendor') or
            payload.get('_metadata', {}).get('vendor') or
            webhook.get('vendor') or  # Configured on webhook itself
            None
        )

        # Extract vendor's stated confidence (if provided)
        vendor_confidence = None
        raw_confidence = payload.get('confidence') or payload.get('vendor_confidence')
        if raw_confidence is not None:
            try:
                # Normalize to 0.0-1.0 scale
                conf_val = float(raw_confidence)
                vendor_confidence = conf_val / 100.0 if conf_val > 1.0 else conf_val
            except (ValueError, TypeError):
                pass

        # Create alert in database
        # NOTE: event_class='assertion' - webhook alerts are VENDOR CLAIMS, not raw observations
        alert_data = {
            'alert_id': alert_id,
            'title': title,
            'description': description,
            'severity': severity,
            'source': f'webhook:{webhook_name}',
            'source_type': 'webhook',  # Explicitly mark source type
            'status': 'open',  # Must be: open, investigating, resolved, closed
            'category': payload.get('category'),
            'subcategory': payload.get('subcategory'),
            'raw_event': payload,  # Store full webhook payload
            # Telemetry classification: webhook alerts are ASSERTIONS (vendor claims)
            'event_class': 'assertion',
            # Vendor trust tracking
            'vendor': vendor_name,
            'vendor_confidence': vendor_confidence,
            # vendor_reputation and false_positive_rate are calculated fields,
            # populated by the vendor trust service during correlation
        }

        # Check for duplicates before saving (Phase 2.4)
        is_duplicate = False
        dedupe_action = None
        try:
            from services.alert_deduplication import get_dedupe_service
            dedupe_service = get_dedupe_service()
            dedupe_result = await dedupe_service.check_duplicate(alert_data)

            if dedupe_result.is_duplicate:
                is_duplicate = True
                dedupe_action = dedupe_result.action

                if dedupe_action == 'suppress':
                    # Don't create the alert at all
                    logger.info(f"Webhook {webhook_name}: Alert suppressed (duplicate of {dedupe_result.existing_alert_id})")
                    return {
                        "status": "suppressed",
                        "alert_id": alert_id,
                        "message": "Alert suppressed as duplicate",
                        "existing_alert_id": dedupe_result.existing_alert_id,
                        "group_id": dedupe_result.existing_group_id
                    }
                elif dedupe_action == 'group':
                    # Add fingerprint and group info to alert
                    alert_data['fingerprint'] = dedupe_result.fingerprint
                    alert_data['alert_group_id'] = dedupe_result.existing_group_id
                    alert_data['is_primary'] = False
                    logger.info(f"Webhook {webhook_name}: Alert grouped with {dedupe_result.existing_group_id} (count: {dedupe_result.group_alert_count + 1})")
            else:
                # Not a duplicate, but may have a new group created
                if dedupe_result.fingerprint:
                    alert_data['fingerprint'] = dedupe_result.fingerprint
                if dedupe_result.existing_group_id:
                    alert_data['alert_group_id'] = dedupe_result.existing_group_id
                    alert_data['is_primary'] = True
        except Exception as dedupe_err:
            logger.warning(f"Webhook {webhook_name}: Deduplication check warning - {dedupe_err}")

        # Save alert only - investigations are created manually by analysts
        saved_alert = await db.create_alert(alert_data)

        # Auto-correlate alert to open investigations (time-window based)
        linked_investigation = None
        try:
            from services.alert_correlation import correlate_and_link_alert
            linked_investigation = await correlate_and_link_alert(alert_data)
            if linked_investigation:
                logger.info(f"Webhook {webhook_name}: Alert {alert_id} auto-linked to investigation {linked_investigation}")
        except Exception as corr_link_err:
            logger.warning(f"Webhook {webhook_name}: Alert correlation check failed - {corr_link_err}")

        # Trigger automatic IOC enrichment in background
        try:
            from services.auto_enrichment import enrich_alert_background
            from middleware.tenant_middleware import get_optional_tenant_id
            _webhook_tenant_id = get_optional_tenant_id()
            background_tasks.add_task(
                enrich_alert_background,
                alert_id=alert_id,
                raw_event=payload,
                tenant_id=_webhook_tenant_id
            )
            logger.info(f"Webhook {webhook_name}: Auto-enrichment queued for {alert_id}")
        except Exception as enrich_err:
            logger.warning(f"Failed to queue enrichment for {alert_id}: {enrich_err}")

        # DISABLED: Legacy IOC correlation - replaced by entity-based correlation
        # Entity correlation runs in job_queue.py after T1 triage and uses
        # user/host as primary anchors instead of IOC-only matching.
        # This prevents the race condition where IOC correlation would override
        # entity correlation decisions.
        #
        # Original code (disabled 2026-01-20):
        # try:
        #     from services.ioc_correlation_engine import get_correlation_engine
        #     async def correlate_alert(a_id: str, a_data: dict):
        #         engine = get_correlation_engine()
        #         await engine.link_alert_iocs(a_id, a_data)
        #         await engine.check_correlations(a_id, a_data)
        #     background_tasks.add_task(correlate_alert, saved_alert, alert_data)
        #     logger.info(f"Webhook {webhook_name}: IOC correlation queued for {alert_id}")
        # except Exception as corr_err:
        #     logger.warning(f"Failed to queue correlation for {alert_id}: {corr_err}")

        # Update webhook stats
        await db.update_webhook_stats(webhook_name)

        # Trigger playbooks configured for webhook events
        try:
            import asyncio
            from services.playbook_trigger_service import trigger_playbooks_for_event
            asyncio.create_task(
                trigger_playbooks_for_event(
                    event_type="webhook",
                    alert=payload,
                    alert_id=alert_id,
                    webhook_path=str(request.url.path)
                )
            )
        except Exception as trigger_err:
            logger.warning(f"Webhook {webhook_name}: Playbook trigger failed - {trigger_err}")

        # Log the ingestion
        logger.info(f"Webhook {webhook_name}: Created alert {alert_id}")

        response = {
            "status": "accepted",
            "alert_id": alert_id,
            "message": "Alert received successfully",
            "format_detected": detected_format.value,
        }

        # Include rate limit info in response
        if rate_limit and rate_limit > 0:
            usage = _webhook_rate_limiter.get_usage(webhook_name)
            response["rate_limit"] = {
                "limit": rate_limit,
                "remaining": max(0, rate_limit - usage["current_count"]),
                "window": "1 hour"
            }

        # Include AI extraction info if used
        if parse_metadata.get('ai_extracted') or parse_metadata.get('ai_fallback'):
            response["ai_extracted"] = True

        # Include correlation info if alert was auto-linked
        if linked_investigation:
            response["linked_investigation"] = linked_investigation
            response["message"] = f"Alert received and auto-linked to investigation {linked_investigation}"

        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Webhook ingestion error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))


# ==================== PUBLIC ENDPOINTS ====================

@router.post("/alerts")
async def receive_webhook_alert(
    webhook_token: str = Header(..., alias="X-Webhook-Token"),
    request: AlertWebhookRequest = Body(...)
):
    """Public endpoint to receive alerts via webhook (legacy)"""
    from fastapi.responses import JSONResponse
    
    # This is a legacy endpoint - use /ingest/{name} instead
    return JSONResponse(
        content={"status": "use /api/v1/webhooks/ingest/{webhook_name} instead"},
        status_code=400
    )


@router.get("/health")
async def webhook_health():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "webhook_receiver",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/formats")
async def list_supported_formats():
    """List all supported log formats for webhook ingestion"""
    return {
        "supported_formats": [
            {
                "format": "json",
                "content_types": ["application/json"],
                "description": "Native JSON format - direct passthrough",
                "example": '{"title": "Alert", "severity": "high", "description": "..."}'
            },
            {
                "format": "xml",
                "content_types": ["application/xml", "text/xml"],
                "description": "XML format - converted to JSON structure",
                "example": '<alert><title>Alert</title><severity>high</severity></alert>'
            },
            {
                "format": "windows_event",
                "content_types": ["application/xml", "text/xml"],
                "description": "Windows Event Log XML format",
                "example": '<Event xmlns="..."><System><EventID>4625</EventID>...</System></Event>'
            },
            {
                "format": "csv",
                "content_types": ["text/csv"],
                "description": "CSV format with header row",
                "example": 'title,severity,source\\nAlert1,high,firewall'
            },
            {
                "format": "syslog_rfc3164",
                "content_types": ["text/plain"],
                "description": "BSD Syslog format (RFC 3164)",
                "example": '<34>Oct 11 22:14:15 mymachine su: failed login'
            },
            {
                "format": "syslog_rfc5424",
                "content_types": ["text/plain"],
                "description": "Syslog format (RFC 5424)",
                "example": '<34>1 2023-10-11T22:14:15.003Z host app - - - Message'
            },
            {
                "format": "cef",
                "content_types": ["text/plain"],
                "description": "ArcSight Common Event Format",
                "example": 'CEF:0|Vendor|Product|1.0|100|Event|5|src=1.2.3.4 dst=5.6.7.8'
            },
            {
                "format": "leef",
                "content_types": ["text/plain"],
                "description": "IBM QRadar Log Event Extended Format",
                "example": 'LEEF:1.0|Vendor|Product|1.0|EventID|src=1.2.3.4'
            },
            {
                "format": "key_value",
                "content_types": ["text/plain"],
                "description": "Key=value pair format",
                "example": 'timestamp=2023-10-11 severity=high msg="Login failed"'
            },
            {
                "format": "raw_text",
                "content_types": ["text/plain", "*/*"],
                "description": "Raw text - AI-powered extraction",
                "example": 'Any unstructured log text - AI will extract fields'
            }
        ],
        "headers": {
            "X-Log-Format": "Force specific format parsing (optional)",
            "X-Source-Hint": "Hint about log source for AI extraction (e.g., 'firewall', 'windows')"
        },
        "notes": [
            "Format is auto-detected from content",
            "Content-Type header provides hints but is not required",
            "Raw text uses AI to extract structured fields",
            "CSV with multiple rows creates batch alerts"
        ]
    }


# ==================== ADMIN ENDPOINTS ====================

async def require_webhook_admin(request: Request, authorization: Optional[str] = Header(None)) -> User:
    """Require authentication for webhook admin endpoints"""
    user, api_key = await get_current_user_or_api_key(request, authorization)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Provide a valid JWT token or API key."
        )
    # Require admin or user role (not readonly)
    if user.role not in [UserRole.ADMIN, UserRole.USER]:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions. Admin or User role required."
        )
    return user


@admin_router.get("")
async def list_webhooks(user: User = Depends(require_webhook_admin)):
    """List all webhooks (requires auth)"""
    webhooks = await db.get_all_webhooks()
    
    # Remove sensitive token from response
    for webhook in webhooks:
        webhook.pop("token", None)
        if "_id" in webhook:
            webhook["_id"] = str(webhook["_id"])
    
    return webhooks


@admin_router.post("")
async def create_webhook(
    webhook_data: WebhookCreate,
    user: User = Depends(require_webhook_admin)
):
    """Create a new webhook (requires auth)"""
    webhook_id = f"webhook_{secrets.token_hex(8)}"
    webhook_token = f"whtoken_{secrets.token_urlsafe(32)}"

    webhook = {
        "webhook_id": webhook_id,
        "name": webhook_data.name,
        "description": webhook_data.description,
        "token": webhook_token,
        # No encryption key needed
        "enabled": True,
        "rate_limit": webhook_data.rate_limit,
        "created_by": user.username,
        "created_at": datetime.utcnow(),
        "last_used": None,
        "request_count": 0
    }

    result = await db.create_webhook(webhook)

    await db.create_log({
        "level": "info",
        "message": f"Webhook created: {webhook_data.name}",
        "source": "webhook_admin",
        "details": {"webhook_id": webhook_id, "created_by": user.username}
    })
    
    return {
        **result,
        "webhook_url": f"http://localhost:8000/api/v1/webhooks/ingest/{webhook_data.name}",
        "token": webhook_token
    }


@admin_router.put("/{webhook_id}")
async def update_webhook(
    webhook_id: str,
    updates: WebhookUpdate,
    user: User = Depends(require_webhook_admin),
):
    """Update mutable fields on a webhook. Token and webhook_id are immutable."""
    existing = await db.get_webhook(webhook_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Webhook not found")

    payload = updates.dict(exclude_unset=True)
    updated = await db.update_webhook(webhook_id, payload)
    if not updated:
        raise HTTPException(status_code=500, detail="Update failed")

    await db.create_log({
        "level": "info",
        "message": f"Webhook updated: {existing.get('name')}",
        "source": "webhook_admin",
        "details": {
            "webhook_id": webhook_id,
            "updated_by": user.username,
            "fields": list(payload.keys()),
        },
    })

    updated.pop("token", None)
    if "_id" in updated:
        updated["_id"] = str(updated["_id"])
    return updated


@admin_router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: str,
    user: User = Depends(require_webhook_admin)
):
    """Delete a webhook (requires auth)"""
    webhook = await db.get_webhook(webhook_id)

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    await db.delete_webhook(webhook_id)

    await db.create_log({
        "level": "info",
        "message": f"Webhook deleted: {webhook['name']}",
        "source": "webhook_admin",
        "details": {"webhook_id": webhook_id, "deleted_by": user.username}
    })

    return {"status": "deleted", "webhook_id": webhook_id}
