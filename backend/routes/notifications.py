# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Email Notification Routes
API endpoints for managing SMTP configuration, notification rules, and webhook channels
"""

from fastapi import APIRouter, HTTPException, Header, Request
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, EmailStr
from datetime import datetime
import uuid
import logging

from services.email_service import get_email_service, SMTPConfig, NotificationRule, WebhookChannel, CHANNEL_TYPES
from services.postgres_db import postgres_db
from routes.admin import get_current_username, require_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])


# ==================== MODELS ====================

class SMTPConfigRequest(BaseModel):
    host: str
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    use_ssl: bool = False
    from_email: str
    from_name: str = "T1 Agentics SOC"
    enabled: bool = False


class SMTPConfigResponse(BaseModel):
    host: str
    port: int
    username: str
    use_tls: bool
    use_ssl: bool
    from_email: str
    from_name: str
    enabled: bool


class SMTPTestResult(BaseModel):
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None


class NotificationRuleRequest(BaseModel):
    name: str
    enabled: bool = True
    event_types: List[str] = []
    severity_filter: List[str] = []
    recipients: List[str] = []
    subject_template: str = "[T1 Agentics] {event_type}: {title}"
    body_template: Optional[str] = None
    include_approval_links: bool = False
    approval_ttl_minutes: int = 60
    approval_require_auth: bool = False


class NotificationRuleResponse(BaseModel):
    id: str
    name: str
    enabled: bool
    event_types: List[str]
    severity_filter: List[str]
    recipients: List[str]
    subject_template: str
    body_template: Optional[str]
    include_approval_links: bool = False
    approval_ttl_minutes: int = 60
    approval_require_auth: bool = False


class EmailLogEntry(BaseModel):
    id: str
    rule_id: Optional[str]
    event_type: str
    recipients: List[str]
    subject: str
    status: str
    error_message: Optional[str]
    sent_at: datetime


class TestEmailRequest(BaseModel):
    recipient: EmailStr
    subject: str = "T1 Agentics Test Email"
    message: str = "This is a test email from T1 Agentics SOC Platform."


# ==================== SMTP CONFIGURATION ====================

@router.get("/smtp", response_model=Optional[SMTPConfigResponse])
async def get_smtp_config(request: Request, authorization: str = Header(None)):
    """Get current SMTP configuration (password hidden)"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    config = await email_service.get_smtp_config()

    if not config:
        return None

    return SMTPConfigResponse(
        host=config.host,
        port=config.port,
        username=config.username,
        use_tls=config.use_tls,
        use_ssl=config.use_ssl,
        from_email=config.from_email,
        from_name=config.from_name,
        enabled=config.enabled
    )


@router.post("/smtp", response_model=SMTPConfigResponse)
async def save_smtp_config(
    request: Request,
    config: SMTPConfigRequest,
    authorization: str = Header(None)
):
    """Save SMTP configuration"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    smtp_config = SMTPConfig(
        host=config.host,
        port=config.port,
        username=config.username,
        password=config.password,
        use_tls=config.use_tls,
        use_ssl=config.use_ssl,
        from_email=config.from_email,
        from_name=config.from_name,
        enabled=config.enabled
    )

    success = await email_service.save_smtp_config(smtp_config)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to save SMTP configuration")

    return SMTPConfigResponse(
        host=config.host,
        port=config.port,
        username=config.username,
        use_tls=config.use_tls,
        use_ssl=config.use_ssl,
        from_email=config.from_email,
        from_name=config.from_name,
        enabled=config.enabled
    )


@router.post("/smtp/test", response_model=SMTPTestResult)
async def test_smtp_connection(request: Request, authorization: str = Header(None)):
    """Test SMTP connection with current configuration"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    result = await email_service.test_smtp_connection()

    return SMTPTestResult(**result)


@router.post("/smtp/test-email", response_model=SMTPTestResult)
async def send_test_email(
    request: Request,
    test_email: TestEmailRequest,
    authorization: str = Header(None)
):
    """Send a test email to verify configuration"""
    await require_admin(request, authorization)

    email_service = get_email_service()

    if not email_service.config:
        return SMTPTestResult(success=False, error="SMTP not configured")

    # Build test email HTML
    body_html = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1f2937; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: linear-gradient(135deg, #7c4dff 0%, #b388ff 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; text-align: center; }}
            .content {{ background: #f9fafb; padding: 30px; border: 1px solid #e5e7eb; border-radius: 0 0 8px 8px; }}
            .success {{ background: #10b981; color: white; padding: 12px 24px; border-radius: 6px; display: inline-block; margin-top: 16px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2 style="margin: 0;">T1 Agentics SOC</h2>
                <p style="margin: 8px 0 0 0; opacity: 0.9;">Test Email</p>
            </div>
            <div class="content">
                <h3>Email Configuration Test</h3>
                <p>{test_email.message}</p>
                <p>If you received this email, your SMTP configuration is working correctly!</p>
                <div class="success">Configuration Verified</div>
                <p style="color: #6b7280; font-size: 14px; margin-top: 20px;">
                    Sent at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
                </p>
            </div>
        </div>
    </body>
    </html>
    '''

    # Temporarily enable for test
    original_enabled = email_service.config.enabled
    email_service.config.enabled = True

    try:
        success = await email_service.send_email(
            to=[test_email.recipient],
            subject=test_email.subject,
            body_html=body_html,
            body_text=test_email.message
        )
    finally:
        email_service.config.enabled = original_enabled

    if success:
        return SMTPTestResult(success=True, message=f"Test email sent to {test_email.recipient}")
    else:
        return SMTPTestResult(success=False, error="Failed to send test email. Check SMTP configuration.")


# ==================== NOTIFICATION RULES ====================

@router.get("/rules", response_model=List[NotificationRuleResponse])
async def get_notification_rules(request: Request, authorization: str = Header(None)):
    """Get all notification rules"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    rules = await email_service.get_notification_rules()

    return [
        NotificationRuleResponse(
            id=rule.id,
            name=rule.name,
            enabled=rule.enabled,
            event_types=rule.event_types,
            severity_filter=rule.severity_filter,
            recipients=rule.recipients,
            subject_template=rule.subject_template,
            body_template=rule.body_template,
            include_approval_links=rule.include_approval_links,
            approval_ttl_minutes=rule.approval_ttl_minutes,
            approval_require_auth=rule.approval_require_auth
        )
        for rule in rules
    ]


@router.post("/rules", response_model=NotificationRuleResponse)
async def create_notification_rule(
    request: Request,
    rule: NotificationRuleRequest,
    authorization: str = Header(None)
):
    """Create a new notification rule"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    rule_id = f"rule-{uuid.uuid4().hex[:8]}"

    notification_rule = NotificationRule(
        id=rule_id,
        name=rule.name,
        enabled=rule.enabled,
        event_types=rule.event_types,
        severity_filter=rule.severity_filter,
        recipients=rule.recipients,
        subject_template=rule.subject_template,
        body_template=rule.body_template,
        include_approval_links=rule.include_approval_links,
        approval_ttl_minutes=rule.approval_ttl_minutes,
        approval_require_auth=rule.approval_require_auth
    )

    success = await email_service.save_notification_rule(notification_rule)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to create notification rule")

    return NotificationRuleResponse(
        id=rule_id,
        name=rule.name,
        enabled=rule.enabled,
        event_types=rule.event_types,
        severity_filter=rule.severity_filter,
        recipients=rule.recipients,
        subject_template=rule.subject_template,
        body_template=rule.body_template,
        include_approval_links=rule.include_approval_links,
        approval_ttl_minutes=rule.approval_ttl_minutes,
        approval_require_auth=rule.approval_require_auth
    )


@router.put("/rules/{rule_id}", response_model=NotificationRuleResponse)
async def update_notification_rule(
    request: Request,
    rule_id: str,
    rule: NotificationRuleRequest,
    authorization: str = Header(None)
):
    """Update an existing notification rule"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    notification_rule = NotificationRule(
        id=rule_id,
        name=rule.name,
        enabled=rule.enabled,
        event_types=rule.event_types,
        severity_filter=rule.severity_filter,
        recipients=rule.recipients,
        subject_template=rule.subject_template,
        body_template=rule.body_template,
        include_approval_links=rule.include_approval_links,
        approval_ttl_minutes=rule.approval_ttl_minutes,
        approval_require_auth=rule.approval_require_auth
    )

    success = await email_service.save_notification_rule(notification_rule)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to update notification rule")

    return NotificationRuleResponse(
        id=rule_id,
        name=rule.name,
        enabled=rule.enabled,
        event_types=rule.event_types,
        severity_filter=rule.severity_filter,
        recipients=rule.recipients,
        subject_template=rule.subject_template,
        body_template=rule.body_template,
        include_approval_links=rule.include_approval_links,
        approval_ttl_minutes=rule.approval_ttl_minutes,
        approval_require_auth=rule.approval_require_auth
    )


@router.delete("/rules/{rule_id}")
async def delete_notification_rule(
    request: Request,
    rule_id: str,
    authorization: str = Header(None)
):
    """Delete a notification rule"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    success = await email_service.delete_notification_rule(rule_id)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete notification rule")

    return {"success": True, "message": f"Rule {rule_id} deleted"}


# ==================== EMAIL LOGS ====================

@router.get("/logs", response_model=List[EmailLogEntry])
async def get_email_logs(
    request: Request,
    limit: int = 50,
    authorization: str = Header(None)
):
    """Get email notification logs"""
    await require_admin(request, authorization)

    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, rule_id, event_type, recipients, subject, status, error_message, sent_at
                FROM email_log
                ORDER BY sent_at DESC
                LIMIT $1
            ''', limit)

            return [
                EmailLogEntry(
                    id=str(row['id']),
                    rule_id=row['rule_id'],
                    event_type=row['event_type'],
                    recipients=row['recipients'] or [],
                    subject=row['subject'],
                    status=row['status'],
                    error_message=row['error_message'],
                    sent_at=row['sent_at']
                )
                for row in rows
            ]
    except Exception as e:
        logger.error(f"Failed to get email logs: {e}")
        return []


# ==================== EVENT TYPES ====================

@router.get("/event-types")
async def get_event_types(request: Request, authorization: str = Header(None)):
    """Get available event types for notification rules"""
    await get_current_username(request, authorization)

    return {
        "event_types": [
            # Alert events
            {"id": "alert_created", "name": "Alert Created", "description": "When a new alert is ingested", "category": "alerts"},
            {"id": "alert_escalated", "name": "Alert Escalated", "description": "When an alert is escalated to higher tier", "category": "alerts"},
            {"id": "alert_critical", "name": "Critical Alert", "description": "When a critical severity alert is created", "category": "alerts"},
            {"id": "alert_resolved", "name": "Alert Resolved", "description": "When an alert is resolved/closed", "category": "alerts"},

            # Investigation events
            {"id": "investigation_created", "name": "Investigation Created", "description": "When a new investigation is opened", "category": "investigations"},
            {"id": "investigation_closed", "name": "Investigation Closed", "description": "When an investigation is resolved", "category": "investigations"},
            {"id": "investigation_escalated", "name": "Investigation Escalated", "description": "When investigation is escalated to higher tier", "category": "investigations"},

            # AI events
            {"id": "ai_verdict_true_positive", "name": "AI: True Positive", "description": "When AI determines alert is true positive", "category": "ai"},
            {"id": "ai_verdict_malicious", "name": "AI: Malicious Verdict", "description": "When AI determines alert is malicious", "category": "ai"},
            {"id": "ai_needs_human_review", "name": "AI: Needs Human Review", "description": "When AI cannot make a confident determination", "category": "ai"},

            # File attachment events
            {"id": "file_attachment_uploaded", "name": "File Uploaded", "description": "When a file is attached to an alert", "category": "files"},
            {"id": "file_malicious_detected", "name": "Malicious File Detected", "description": "When file analysis detects malicious content", "category": "files"},

            # Case management events
            {"id": "case_created", "name": "Case Created", "description": "When a new case is opened", "category": "cases"},
            {"id": "case_closed", "name": "Case Closed", "description": "When a case is closed", "category": "cases"},
            {"id": "case_assigned", "name": "Case Assigned", "description": "When a case is assigned to an analyst", "category": "cases"},

            # System events
            {"id": "daily_summary", "name": "Daily Summary", "description": "Daily digest of SOC activity", "category": "system"},
            {"id": "weekly_report", "name": "Weekly Report", "description": "Weekly SOC metrics and summary", "category": "system"},
            {"id": "integration_error", "name": "Integration Error", "description": "When an integration fails repeatedly", "category": "system"},
        ],
        "severities": [
            {"id": "critical", "name": "Critical", "color": "#dc2626"},
            {"id": "high", "name": "High", "color": "#f97316"},
            {"id": "medium", "name": "Medium", "color": "#eab308"},
            {"id": "low", "name": "Low", "color": "#3b82f6"},
        ],
        "categories": [
            {"id": "alerts", "name": "Alert Events", "icon": "[ALERT]"},
            {"id": "investigations", "name": "Investigation Events", "icon": "[SEARCH]"},
            {"id": "ai", "name": "AI Agent Events", "icon": "[AI]"},
            {"id": "files", "name": "File Events", "icon": "[FILE]"},
            {"id": "cases", "name": "Case Management", "icon": "[CASE]"},
            {"id": "system", "name": "System Events", "icon": "[SYS]"},
        ]
    }


# ==================== WEBHOOK CHANNELS ====================

class WebhookChannelRequest(BaseModel):
    name: str
    channel_type: str  # slack, teams, webex, discord, generic
    webhook_url: str
    enabled: bool = True


class WebhookChannelResponse(BaseModel):
    id: str
    name: str
    channel_type: str
    webhook_url: str
    enabled: bool


class WebhookTestResult(BaseModel):
    success: bool
    message: Optional[str] = None
    error: Optional[str] = None


@router.get("/channels/types")
async def get_channel_types(request: Request, authorization: str = Header(None)):
    """Get available webhook channel types"""
    await get_current_username(request, authorization)

    return {
        "channel_types": [
            {"id": key, **value}
            for key, value in CHANNEL_TYPES.items()
        ]
    }


@router.get("/channels", response_model=List[WebhookChannelResponse])
async def get_webhook_channels(request: Request, authorization: str = Header(None)):
    """Get all webhook channels"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    channels = await email_service.get_webhook_channels()

    return [
        WebhookChannelResponse(
            id=channel.id,
            name=channel.name,
            channel_type=channel.channel_type,
            webhook_url=channel.webhook_url,
            enabled=channel.enabled
        )
        for channel in channels
    ]


@router.post("/channels", response_model=WebhookChannelResponse)
async def create_webhook_channel(
    request: Request,
    channel: WebhookChannelRequest,
    authorization: str = Header(None)
):
    """Create a new webhook channel"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    channel_id = f"channel-{uuid.uuid4().hex[:8]}"

    webhook_channel = WebhookChannel(
        id=channel_id,
        name=channel.name,
        channel_type=channel.channel_type,
        webhook_url=channel.webhook_url,
        enabled=channel.enabled
    )

    success = await email_service.save_webhook_channel(webhook_channel)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to create webhook channel")

    return WebhookChannelResponse(
        id=channel_id,
        name=channel.name,
        channel_type=channel.channel_type,
        webhook_url=channel.webhook_url,
        enabled=channel.enabled
    )


@router.put("/channels/{channel_id}", response_model=WebhookChannelResponse)
async def update_webhook_channel(
    request: Request,
    channel_id: str,
    channel: WebhookChannelRequest,
    authorization: str = Header(None)
):
    """Update an existing webhook channel"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    webhook_channel = WebhookChannel(
        id=channel_id,
        name=channel.name,
        channel_type=channel.channel_type,
        webhook_url=channel.webhook_url,
        enabled=channel.enabled
    )

    success = await email_service.save_webhook_channel(webhook_channel)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to update webhook channel")

    return WebhookChannelResponse(
        id=channel_id,
        name=channel.name,
        channel_type=channel.channel_type,
        webhook_url=channel.webhook_url,
        enabled=channel.enabled
    )


@router.delete("/channels/{channel_id}")
async def delete_webhook_channel(
    request: Request,
    channel_id: str,
    authorization: str = Header(None)
):
    """Delete a webhook channel"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    success = await email_service.delete_webhook_channel(channel_id)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete webhook channel")

    return {"success": True, "message": f"Channel {channel_id} deleted"}


@router.post("/channels/{channel_id}/test", response_model=WebhookTestResult)
async def test_webhook_channel(
    request: Request,
    channel_id: str,
    authorization: str = Header(None)
):
    """Test a webhook channel"""
    await require_admin(request, authorization)

    email_service = get_email_service()
    email_service.set_db(postgres_db)

    channels = await email_service.get_webhook_channels()
    channel = next((c for c in channels if c.id == channel_id), None)

    if not channel:
        return WebhookTestResult(success=False, error="Channel not found")

    result = await email_service.test_webhook_channel(channel)

    return WebhookTestResult(**result)


# ==================== IN-APP NOTIFICATION INBOX ====================

class NotificationResponse(BaseModel):
    id: str
    title: str
    message: Optional[str] = None
    category: str = "system"
    severity: str = "info"
    link: Optional[str] = None
    read: bool = False
    created_at: str


@router.get("/inbox")
async def get_notifications(
    request: Request,
    authorization: str = Header(None),
    limit: int = 50,
    unread_only: bool = False,
):
    """Get in-app notifications for the current user."""
    user = await _get_inbox_user(request, authorization)
    tenant_id = user.get("tenant_id")
    user_id = str(user.get("id"))

    query = """
        SELECT id, title, message, category, severity, link, read, created_at
        FROM notifications
        WHERE tenant_id = $1::uuid
          AND (user_id = $2::uuid OR user_id IS NULL)
    """
    params = [tenant_id, user_id]

    if unread_only:
        query += " AND read = FALSE"

    query += " ORDER BY created_at DESC LIMIT $" + str(len(params) + 1)
    params.append(limit)

    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(query, *params)
        return {
            "notifications": [
                {
                    "id": str(r["id"]),
                    "title": r["title"],
                    "message": r["message"],
                    "category": r["category"],
                    "severity": r["severity"],
                    "link": r["link"],
                    "read": r["read"],
                    "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                }
                for r in rows
            ]
        }
    except Exception as e:
        logger.error(f"Failed to fetch notifications: {e}")
        return {"notifications": []}


@router.get("/inbox/count")
async def get_unread_count(
    request: Request,
    authorization: str = Header(None),
):
    """Get unread notification count for the bell badge."""
    user = await _get_inbox_user(request, authorization)
    tenant_id = user.get("tenant_id")
    user_id = str(user.get("id"))

    try:
        async with postgres_db.tenant_acquire() as conn:
            count = await conn.fetchval(
                """
                SELECT COUNT(*) FROM notifications
                WHERE tenant_id = $1::uuid
                  AND (user_id = $2::uuid OR user_id IS NULL)
                  AND read = FALSE
                """,
                tenant_id, user_id,
            )
        return {"unread_count": count or 0}
    except Exception as e:
        logger.error(f"Failed to count notifications: {e}")
        return {"unread_count": 0}


@router.post("/inbox/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    request: Request,
    authorization: str = Header(None),
):
    """Mark a single notification as read."""
    user = await _get_inbox_user(request, authorization)
    tenant_id = user.get("tenant_id")
    user_id = str(user.get("id"))

    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                UPDATE notifications SET read = TRUE, read_at = NOW()
                WHERE id = $1::uuid
                  AND tenant_id = $2::uuid
                  AND (user_id = $3::uuid OR user_id IS NULL)
                """,
                notification_id, tenant_id, user_id,
            )
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Failed to mark notification read: {e}")
        raise HTTPException(status_code=500, detail="Failed to update notification")


@router.post("/inbox/read-all")
async def mark_all_read(
    request: Request,
    authorization: str = Header(None),
):
    """Mark all notifications as read for the current user."""
    user = await _get_inbox_user(request, authorization)
    tenant_id = user.get("tenant_id")
    user_id = str(user.get("id"))

    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                UPDATE notifications SET read = TRUE, read_at = NOW()
                WHERE tenant_id = $1::uuid
                  AND (user_id = $2::uuid OR user_id IS NULL)
                  AND read = FALSE
                """,
                tenant_id, user_id,
            )
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Failed to mark all read: {e}")
        raise HTTPException(status_code=500, detail="Failed to update notifications")


async def create_notification(
    tenant_id: str,
    title: str,
    message: str = None,
    category: str = "system",
    severity: str = "info",
    link: str = None,
    user_id: str = None,
    metadata: dict = None,
):
    """
    Create a notification for a tenant (or specific user).
    Call from anywhere in the backend to push notifications.

    Usage:
        from routes.notifications import create_notification
        await create_notification(
            tenant_id="...",
            title="Critical alert requires review",
            message="INV-ABC123 has been escalated",
            category="alert",
            severity="critical",
            link="/investigations/INV-ABC123",
        )
    """
    try:
        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)
        async with postgres_db.pool.acquire() as conn:
            await conn.execute("SET LOCAL app.is_platform_admin = 'true'")
            await conn.execute(
                """
                INSERT INTO notifications (tenant_id, user_id, title, message, category, severity, link, metadata)
                VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb)
                """,
                tenant_id,
                user_id,
                title,
                message,
                category,
                severity,
                link,
                __import__("json").dumps(metadata or {}),
            )
    except Exception as e:
        logger.warning(f"Failed to create notification: {e}")


async def _get_inbox_user(request: Request, authorization: str = None) -> Dict:
    """Get the authenticated user for inbox operations."""
    from routes.admin import get_auth_token, get_current_user_from_token
    token, _ = get_auth_token(request, authorization)
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user = await get_current_user_from_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return user
