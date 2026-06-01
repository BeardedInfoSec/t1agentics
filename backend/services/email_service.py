# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Email Notification Service
Handles SMTP configuration and email notifications for T1 Agentics SOC platform
Supports multi-channel notifications: Email, Slack, Teams, Webex
"""

import os
import smtplib
import ssl
import logging
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import asyncio
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Base URL for external links (configurable via environment)
BASE_URL = os.environ.get('BASE_URL', 'http://localhost:8000')


# ========================================================================
# WEBHOOK CHANNEL TYPES
# ========================================================================

CHANNEL_TYPES = {
    'slack': {
        'name': 'Slack',
        'icon': '[SLACK]',
        'color': '#4A154B'
    },
    'teams': {
        'name': 'Microsoft Teams',
        'icon': '[TEAMS]',
        'color': '#6264A7'
    },
    'webex': {
        'name': 'Cisco Webex',
        'icon': '[WEBEX]',
        'color': '#00BCEB'
    },
    'discord': {
        'name': 'Discord',
        'icon': '[DISCORD]',
        'color': '#5865F2'
    },
    'generic': {
        'name': 'Generic Webhook',
        'icon': '[WEBHOOK]',
        'color': '#6B7280'
    }
}


@dataclass
class WebhookChannel:
    """Webhook channel configuration"""
    id: str
    name: str
    channel_type: str  # slack, teams, webex, discord, generic
    webhook_url: str
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SMTPConfig:
    """SMTP Configuration"""
    host: str
    port: int
    username: str
    password: str
    use_tls: bool = True
    use_ssl: bool = False
    from_email: str = ""
    from_name: str = "T1 Agentics SOC"
    enabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excluding password for safety)"""
        data = asdict(self)
        data['password'] = '***' if self.password else ''
        return data


@dataclass
class NotificationRule:
    """Notification rule configuration"""
    id: str
    name: str
    enabled: bool = True
    event_types: List[str] = None  # alert_created, alert_escalated, investigation_closed, etc.
    severity_filter: List[str] = None  # critical, high, medium, low
    recipients: List[str] = None
    subject_template: str = "[T1 Agentics] {event_type}: {title}"
    body_template: str = ""
    include_approval_links: bool = False  # Whether to include approve/reject links in emails
    approval_ttl_minutes: int = 60  # TTL for approval links
    approval_require_auth: bool = False  # Whether approval links require authentication

    def __post_init__(self):
        if self.event_types is None:
            self.event_types = []
        if self.severity_filter is None:
            self.severity_filter = []
        if self.recipients is None:
            self.recipients = []


class EmailService:
    """Email notification service with SMTP support"""

    # Rate limiting: max notifications per entity per time window
    RATE_LIMIT_WINDOW_SECONDS = 300  # 5 minutes
    RATE_LIMIT_MAX_PER_ENTITY = 3

    def __init__(self):
        self.config: Optional[SMTPConfig] = None
        self.rules: Dict[str, NotificationRule] = {}
        self.db = None
        self._executor = ThreadPoolExecutor(max_workers=3)
        self._rate_limit_cache: Dict[str, List[float]] = {}  # entity_id -> list of timestamps

    async def cleanup(self):
        """Shutdown the thread pool executor."""
        logger.info("EmailService: shutting down thread pool executor")
        self._executor.shutdown(wait=False)

    def set_db(self, db):
        """Set database instance for persistence"""
        self.db = db

    def _check_rate_limit(self, entity_id: str) -> bool:
        """
        Check if we should rate limit notifications for an entity.
        Returns True if rate limited (should NOT send), False if OK to send.
        """
        import time
        current_time = time.time()
        cutoff_time = current_time - self.RATE_LIMIT_WINDOW_SECONDS

        # Get or create timestamp list for this entity
        if entity_id not in self._rate_limit_cache:
            self._rate_limit_cache[entity_id] = []

        # Remove old timestamps outside the window
        self._rate_limit_cache[entity_id] = [
            ts for ts in self._rate_limit_cache[entity_id]
            if ts > cutoff_time
        ]

        # Check if we're at the limit
        if len(self._rate_limit_cache[entity_id]) >= self.RATE_LIMIT_MAX_PER_ENTITY:
            logger.warning(f"Rate limit reached for entity {entity_id}: {len(self._rate_limit_cache[entity_id])} notifications in {self.RATE_LIMIT_WINDOW_SECONDS}s")
            return True  # Rate limited

        # Record this notification
        self._rate_limit_cache[entity_id].append(current_time)

        # Cleanup old entries (keep cache from growing indefinitely)
        if len(self._rate_limit_cache) > 1000:
            oldest_key = min(self._rate_limit_cache.keys(),
                           key=lambda k: self._rate_limit_cache[k][-1] if self._rate_limit_cache[k] else 0)
            del self._rate_limit_cache[oldest_key]

        return False  # Not rate limited

    async def initialize(self):
        """Load configuration from database"""
        if not self.db:
            logger.warning("Email service: No database configured")
            return

        try:
            # Load SMTP config from database
            config = await self.get_smtp_config()
            if config:
                self.config = config
                logger.info(f"Email service initialized: SMTP={config.host}:{config.port}")
            else:
                logger.info("Email service: No SMTP configured yet")

            # Load notification rules
            rules = await self.get_notification_rules()
            for rule in rules:
                self.rules[rule.id] = rule
            logger.info(f"Loaded {len(self.rules)} notification rules")

        except Exception as e:
            logger.error(f"Failed to initialize email service: {e}")

    async def get_smtp_config(self) -> Optional[SMTPConfig]:
        """Get SMTP configuration from database, falling back to env vars."""
        # Try database first
        if self.db and self.db.pool:
            try:
                async with self.db.tenant_acquire() as conn:
                    row = await conn.fetchrow(
                        "SELECT * FROM email_config WHERE id = 'smtp'"
                    )
                    if row:
                        return SMTPConfig(
                            host=row['smtp_host'],
                            port=row['smtp_port'],
                            username=row['smtp_username'],
                            password=row['smtp_password'],
                            use_tls=row['use_tls'],
                            use_ssl=row['use_ssl'],
                            from_email=row['from_email'],
                            from_name=row['from_name'],
                            enabled=row['enabled']
                        )
            except Exception as e:
                logger.error(f"Failed to get SMTP config from DB: {e}")

        # Fallback to environment variables
        smtp_host = os.environ.get("SMTP_HOST")
        smtp_password = os.environ.get("SMTP_PASSWORD")
        if smtp_host and smtp_password:
            smtp_username = os.environ.get("SMTP_USERNAME", "")
            smtp_from = os.environ.get("SMTP_FROM_EMAIL", smtp_username)
            return SMTPConfig(
                host=smtp_host,
                port=int(os.environ.get("SMTP_PORT", "587")),
                username=smtp_username,
                password=smtp_password,
                use_tls=os.environ.get("SMTP_USE_TLS", "true").lower() == "true",
                use_ssl=os.environ.get("SMTP_USE_SSL", "false").lower() == "true",
                from_email=smtp_from,
                from_name=os.environ.get("SMTP_FROM_NAME", "T1 Agentics"),
                enabled=True,
            )

        return None

    async def save_smtp_config(self, config: SMTPConfig) -> bool:
        """Save SMTP configuration to database"""
        if not self.db:
            return False

        try:
            async with self.db.tenant_acquire() as conn:
                await conn.execute('''
                    INSERT INTO email_config (
                        id, smtp_host, smtp_port, smtp_username, smtp_password,
                        use_tls, use_ssl, from_email, from_name, enabled, updated_at
                    ) VALUES ('smtp', $1, $2, $3, $4, $5, $6, $7, $8, $9, CURRENT_TIMESTAMP)
                    ON CONFLICT (id) DO UPDATE SET
                        smtp_host = $1,
                        smtp_port = $2,
                        smtp_username = $3,
                        smtp_password = $4,
                        use_tls = $5,
                        use_ssl = $6,
                        from_email = $7,
                        from_name = $8,
                        enabled = $9,
                        updated_at = CURRENT_TIMESTAMP
                ''',
                    config.host.strip(),
                    config.port,
                    config.username.strip(),
                    config.password.strip() if config.password else "",
                    config.use_tls,
                    config.use_ssl,
                    config.from_email.strip() if config.from_email else "",
                    config.from_name.strip() if config.from_name else "T1 Agentics SOC",
                    config.enabled
                )
            self.config = config
            logger.info(f"SMTP config saved: {config.host}:{config.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to save SMTP config: {e}")
            return False

    async def test_smtp_connection(self) -> Dict[str, Any]:
        """Test SMTP connection with current configuration"""
        if not self.config:
            return {"success": False, "error": "No SMTP configuration"}

        if not self.config.host:
            return {"success": False, "error": "SMTP host not configured"}

        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor,
                self._test_smtp_sync
            )
            return result
        except Exception as e:
            logger.error(f"SMTP test failed: {e}")
            return {"success": False, "error": str(e)}

    def _test_smtp_sync(self) -> Dict[str, Any]:
        """Synchronous SMTP test"""
        try:
            if self.config.use_ssl:
                context = ssl.create_default_context()
                server = smtplib.SMTP_SSL(
                    self.config.host,
                    self.config.port,
                    context=context,
                    timeout=10
                )
            else:
                server = smtplib.SMTP(
                    self.config.host,
                    self.config.port,
                    timeout=10
                )
                if self.config.use_tls:
                    server.starttls()

            if self.config.username and self.config.password:
                server.login(self.config.username, self.config.password)

            server.quit()
            return {"success": True, "message": "SMTP connection successful"}

        except smtplib.SMTPAuthenticationError as e:
            return {"success": False, "error": f"Authentication failed: {e}"}
        except smtplib.SMTPConnectError as e:
            return {"success": False, "error": f"Connection failed: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def send_email(
        self,
        to: List[str],
        subject: str,
        body_html: str,
        body_text: Optional[str] = None
    ) -> bool:
        """Send email asynchronously"""
        if not self.config or not self.config.enabled:
            logger.debug("Email not sent: service disabled")
            return False

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor,
                lambda: self._send_email_sync(to, subject, body_html, body_text)
            )
            return result
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False

    def _send_email_sync(
        self,
        to: List[str],
        subject: str,
        body_html: str,
        body_text: Optional[str] = None
    ) -> bool:
        """Synchronous email sending"""
        try:
            logger.info(f"Preparing to send email to {to}")
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.from_name} <{self.config.from_email}>"
            msg['To'] = ', '.join(to)

            # Plain text fallback
            if body_text:
                part1 = MIMEText(body_text, 'plain')
                msg.attach(part1)

            # HTML body
            part2 = MIMEText(body_html, 'html')
            msg.attach(part2)

            # Connect and send (with timeout to prevent hanging)
            logger.info(f"Connecting to SMTP server {self.config.host}:{self.config.port}")

            # Create SSL context for secure connections
            context = ssl.create_default_context()

            if self.config.use_ssl:
                # Direct SSL connection (typically port 465)
                server = smtplib.SMTP_SSL(
                    self.config.host,
                    self.config.port,
                    context=context,
                    timeout=30
                )
            else:
                # Plain connection first, then upgrade to TLS (typically port 587)
                server = smtplib.SMTP(self.config.host, self.config.port, timeout=30)
                server.ehlo()  # Identify ourselves to the server
                if self.config.use_tls:
                    logger.info("Starting TLS...")
                    server.starttls(context=context)  # Pass SSL context for proper TLS handshake
                    server.ehlo()  # Re-identify after TLS

            if self.config.username and self.config.password:
                logger.info(f"Logging in as {self.config.username}")
                server.login(self.config.username, self.config.password)

            logger.info("Sending email...")
            server.sendmail(
                self.config.from_email,
                to,
                msg.as_string()
            )
            server.quit()

            logger.info(f"Email sent successfully to {to}: {subject}")
            return True

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication failed: {e}")
            return False
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP Connection failed: {e}")
            return False
        except TimeoutError as e:
            logger.error(f"SMTP Timeout: {e}")
            return False
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False

    # ========================================================================
    # NOTIFICATION RULES
    # ========================================================================

    async def get_notification_rules(self) -> List[NotificationRule]:
        """Get all notification rules from database"""
        if not self.db:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM notification_rules ORDER BY name"
                )
                rules = []
                for row in rows:
                    rules.append(NotificationRule(
                        id=row['rule_id'],
                        name=row['name'],
                        enabled=row['enabled'],
                        event_types=row['event_types'] or [],
                        severity_filter=row['severity_filter'] or [],
                        recipients=row['recipients'] or [],
                        subject_template=row['subject_template'],
                        body_template=row['body_template'],
                        include_approval_links=row.get('include_approval_links', False),
                        approval_ttl_minutes=row.get('approval_ttl_minutes', 60),
                        approval_require_auth=row.get('approval_require_auth', False)
                    ))
                return rules
        except Exception as e:
            logger.error(f"Failed to get notification rules: {e}")
            return []

    async def save_notification_rule(self, rule: NotificationRule) -> bool:
        """Save or update notification rule"""
        if not self.db:
            return False

        try:
            async with self.db.tenant_acquire() as conn:
                from middleware.tenant_middleware import get_optional_tenant_id
                _tid = get_optional_tenant_id() or '00000000-0000-0000-0000-000000000001'
                await conn.execute('''
                    INSERT INTO notification_rules (
                        rule_id, name, enabled, event_types, severity_filter,
                        recipients, subject_template, body_template,
                        include_approval_links, approval_ttl_minutes, approval_require_auth,
                        updated_at, tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, CURRENT_TIMESTAMP, $12)
                    ON CONFLICT (rule_id) DO UPDATE SET
                        name = $2,
                        enabled = $3,
                        event_types = $4,
                        severity_filter = $5,
                        recipients = $6,
                        subject_template = $7,
                        body_template = $8,
                        include_approval_links = $9,
                        approval_ttl_minutes = $10,
                        approval_require_auth = $11,
                        updated_at = CURRENT_TIMESTAMP
                ''',
                    rule.id,
                    rule.name,
                    rule.enabled,
                    rule.event_types,
                    rule.severity_filter,
                    rule.recipients,
                    rule.subject_template,
                    rule.body_template,
                    rule.include_approval_links,
                    rule.approval_ttl_minutes,
                    rule.approval_require_auth,
                    _tid
                )
            self.rules[rule.id] = rule
            logger.info(f"Notification rule saved: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to save notification rule: {e}")
            return False

    async def delete_notification_rule(self, rule_id: str) -> bool:
        """Delete notification rule"""
        if not self.db:
            return False

        try:
            async with self.db.tenant_acquire() as conn:
                result = await conn.execute(
                    "DELETE FROM notification_rules WHERE rule_id = $1",
                    rule_id
                )
            if rule_id in self.rules:
                del self.rules[rule_id]
            logger.info(f"Notification rule deleted: {rule_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete notification rule: {e}")
            return False

    # ========================================================================
    # EVENT NOTIFICATIONS
    # ========================================================================

    async def notify_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        skip_rate_limit: bool = False
    ) -> int:
        """
        Send notifications for an event based on matching rules.
        Returns number of notifications sent (email + webhooks).

        Args:
            event_type: Type of event (e.g., 'alert_created', 'investigation_closed')
            data: Event data including alert_id, severity, title, etc.
            skip_rate_limit: If True, bypass rate limiting (use for critical alerts)
        """
        # Determine entity ID for rate limiting
        entity_id = data.get('alert_id') or data.get('investigation_id') or data.get('case_id') or 'global'

        # Check rate limit (unless skipped or critical severity)
        severity = data.get('severity', 'medium').lower()
        if not skip_rate_limit and severity != 'critical':
            if self._check_rate_limit(f"{entity_id}:{event_type}"):
                logger.info(f"Notification rate limited for {entity_id}: {event_type}")
                return 0

        sent_count = 0

        # Send to webhook channels (always, regardless of SMTP config)
        try:
            channels = await self.get_webhook_channels()
            for channel in channels:
                if channel.enabled:
                    success = await self.send_webhook_notification(channel, event_type, data)
                    if success:
                        sent_count += 1
        except Exception as e:
            logger.error(f"Failed to send webhook notifications: {e}")

        # Send emails if SMTP is configured and enabled
        if not self.config or not self.config.enabled:
            return sent_count

        for rule in self.rules.values():
            if not rule.enabled:
                continue

            # Check event type match
            if rule.event_types and event_type not in rule.event_types:
                continue

            # Check severity filter
            if rule.severity_filter and severity not in rule.severity_filter:
                continue

            # Generate approval links if enabled
            approval_links = None
            if rule.include_approval_links:
                approval_links = await self._generate_approval_links(
                    event_type=event_type,
                    data=data,
                    ttl_minutes=rule.approval_ttl_minutes,
                    require_auth=rule.approval_require_auth
                )

            # Build email content
            subject = self._render_template(rule.subject_template, event_type, data)
            body_html = self._build_email_body(event_type, data, rule.body_template, approval_links)

            # Send to all recipients
            if rule.recipients:
                success = await self.send_email(
                    rule.recipients,
                    subject,
                    body_html
                )

                # Log the email
                await self._log_email(
                    rule_id=rule.id,
                    event_type=event_type,
                    recipients=rule.recipients,
                    subject=subject,
                    success=success
                )

                if success:
                    sent_count += 1

        return sent_count

    async def _generate_approval_links(
        self,
        event_type: str,
        data: Dict[str, Any],
        ttl_minutes: int = 60,
        require_auth: bool = False
    ) -> Optional[Dict[str, str]]:
        """Generate approval/reject links for email notifications"""
        try:
            from services.approval_service import get_approval_service

            approval_service = get_approval_service()
            approval_service.set_db(self.db)

            # Determine entity type and ID from the data
            entity_type = 'alert'
            entity_id = data.get('alert_id')

            if not entity_id:
                entity_id = data.get('investigation_id')
                if entity_id:
                    entity_type = 'investigation'

            if not entity_id:
                entity_id = data.get('case_id')
                if entity_id:
                    entity_type = 'case'

            if not entity_id:
                logger.warning("Cannot generate approval links: no entity ID found")
                return None

            # Convert entity_id to string if it's a UUID
            entity_id_str = str(entity_id) if hasattr(entity_id, 'hex') else entity_id

            # Create a JSON-safe copy of the data for metadata (convert UUIDs to strings)
            safe_data = {}
            for k, v in data.items():
                if hasattr(v, 'hex'):  # UUID object
                    safe_data[k] = str(v)
                elif isinstance(v, (str, int, float, bool, type(None))):
                    safe_data[k] = v
                else:
                    safe_data[k] = str(v)

            # Create approval token pair
            tokens = await approval_service.create_approval_pair(
                action_type=event_type,
                entity_type=entity_type,
                entity_id=entity_id_str,
                ttl_minutes=ttl_minutes,
                require_auth=require_auth,
                created_by='email_notification',
                metadata={'event_type': event_type, 'data': safe_data}
            )

            # Build URLs - use the backend page endpoint
            base_url = BASE_URL
            approve_url = f"{base_url}/api/v1/approval-tokens/page/{tokens['approve'].token_secret}"
            reject_url = f"{base_url}/api/v1/approval-tokens/page/{tokens['reject'].token_secret}"

            return {
                'approve_url': approve_url,
                'reject_url': reject_url,
                'expires_at': tokens['approve'].expires_at.isoformat() if tokens['approve'].expires_at else None
            }

        except Exception as e:
            logger.error(f"Failed to generate approval links: {e}")
            return None

    async def _log_email(
        self,
        rule_id: str,
        event_type: str,
        recipients: List[str],
        subject: str,
        success: bool,
        error_message: Optional[str] = None
    ):
        """Log sent email to database"""
        if not self.db:
            return

        try:
            async with self.db.tenant_acquire() as conn:
                await conn.execute('''
                    INSERT INTO email_log (rule_id, event_type, recipients, subject, status, error_message)
                    VALUES ($1, $2, $3, $4, $5, $6)
                ''',
                    rule_id,
                    event_type,
                    recipients,
                    subject,
                    'sent' if success else 'failed',
                    error_message
                )
        except Exception as e:
            logger.error(f"Failed to log email: {e}")

    def _render_template(
        self,
        template: str,
        event_type: str,
        data: Dict[str, Any]
    ) -> str:
        """Render a template string with event data"""
        try:
            # Build template context with defaults, then override with actual data
            context = {
                'event_type': event_type.replace('_', ' ').title(),
                'title': 'N/A',
                'severity': 'N/A',
                'source': 'N/A',
                'alert_id': 'N/A',
                'investigation_id': 'N/A',
                'status': 'N/A',
                'timestamp': datetime.utcnow().isoformat(),
            }
            # Override with actual data values
            context.update(data)
            return template.format(**context)
        except KeyError as e:
            logger.warning(f"Template variable not found: {e}")
            return template

    def _build_email_body(
        self,
        event_type: str,
        data: Dict[str, Any],
        custom_template: Optional[str] = None,
        approval_links: Optional[Dict[str, str]] = None
    ) -> str:
        """Build HTML email body for notification"""
        if custom_template:
            return self._render_template(custom_template, event_type, data)

        # Default template
        severity_colors = {
            'critical': '#dc2626',
            'high': '#f97316',
            'medium': '#eab308',
            'low': '#3b82f6'
        }
        severity = data.get('severity', 'medium').lower()
        severity_color = severity_colors.get(severity, '#6b7280')

        # Build approval buttons section if links are provided
        approval_section = ""
        if approval_links:
            approval_section = f'''
                    <div style="margin-top: 24px; padding: 20px; background: linear-gradient(135deg, #1e293b 0%, #334155 100%); border-radius: 8px; text-align: center;">
                        <p style="color: #94a3b8; margin: 0 0 16px 0; font-size: 14px;">
                            Quick Action Required - Links expire at {approval_links.get('expires_at', 'N/A')[:19].replace('T', ' ')} UTC
                        </p>
                        <div style="display: inline-block;">
                            <a href="{approval_links.get('approve_url', '#')}"
                               style="display: inline-block; padding: 12px 32px; background: #22c55e; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 0 8px;">
                                Approve
                            </a>
                            <a href="{approval_links.get('reject_url', '#')}"
                               style="display: inline-block; padding: 12px 32px; background: #ef4444; color: white; text-decoration: none; border-radius: 6px; font-weight: 600; margin: 0 8px;">
                                Reject
                            </a>
                        </div>
                        <p style="color: #64748b; margin: 16px 0 0 0; font-size: 12px;">
                            These are one-time use links. Once clicked, the action cannot be undone.
                        </p>
                    </div>
            '''

        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1f2937; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #7c4dff 0%, #b388ff 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
                .content {{ background: #f9fafb; padding: 20px; border: 1px solid #e5e7eb; }}
                .severity {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600; color: white; background: {severity_color}; }}
                .detail {{ margin: 12px 0; padding: 12px; background: white; border-radius: 6px; border: 1px solid #e5e7eb; }}
                .label {{ color: #6b7280; font-size: 12px; text-transform: uppercase; }}
                .value {{ color: #1f2937; font-weight: 600; }}
                .footer {{ padding: 16px; text-align: center; color: #6b7280; font-size: 12px; }}
                .button {{ display: inline-block; padding: 10px 20px; background: #7c4dff; color: white; text-decoration: none; border-radius: 6px; margin-top: 16px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2 style="margin: 0;">T1 Agentics SOC Alert</h2>
                    <p style="margin: 8px 0 0 0; opacity: 0.9;">{event_type.replace('_', ' ').title()}</p>
                </div>
                <div class="content">
                    <div style="margin-bottom: 16px;">
                        <span class="severity">{severity.upper()}</span>
                    </div>

                    <h3 style="margin: 0 0 16px 0;">{data.get('title', 'Security Alert')}</h3>

                    <div class="detail">
                        <div class="label">Alert ID</div>
                        <div class="value">{data.get('alert_id', 'N/A')}</div>
                    </div>

                    <div class="detail">
                        <div class="label">Source</div>
                        <div class="value">{data.get('source', 'N/A')}</div>
                    </div>

                    <div class="detail">
                        <div class="label">Description</div>
                        <div class="value">{data.get('description', 'No description available')}</div>
                    </div>

                    <div class="detail">
                        <div class="label">Timestamp</div>
                        <div class="value">{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
                    </div>

                    {approval_section}

                    <a href="#" class="button">View in T1 Agentics</a>
                </div>
                <div class="footer">
                    This is an automated notification from T1 Agentics SOC Platform.
                </div>
            </div>
        </body>
        </html>
        '''

    # ========================================================================
    # WEBHOOK CHANNELS
    # ========================================================================

    async def get_webhook_channels(self) -> List[WebhookChannel]:
        """Get all webhook channels from database"""
        if not self.db:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    "SELECT * FROM webhook_channels ORDER BY name"
                )
                return [
                    WebhookChannel(
                        id=row['channel_id'],
                        name=row['name'],
                        channel_type=row['channel_type'],
                        webhook_url=row['webhook_url'],
                        enabled=row['enabled']
                    )
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Failed to get webhook channels: {e}")
            return []

    async def save_webhook_channel(self, channel: WebhookChannel) -> bool:
        """Save or update webhook channel"""
        if not self.db:
            return False

        try:
            async with self.db.tenant_acquire() as conn:
                await conn.execute('''
                    INSERT INTO webhook_channels (
                        channel_id, name, channel_type, webhook_url, enabled, updated_at
                    ) VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
                    ON CONFLICT (channel_id) DO UPDATE SET
                        name = $2,
                        channel_type = $3,
                        webhook_url = $4,
                        enabled = $5,
                        updated_at = CURRENT_TIMESTAMP
                ''',
                    channel.id,
                    channel.name,
                    channel.channel_type,
                    channel.webhook_url,
                    channel.enabled
                )
            logger.info(f"Webhook channel saved: {channel.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to save webhook channel: {e}")
            return False

    async def delete_webhook_channel(self, channel_id: str) -> bool:
        """Delete webhook channel"""
        if not self.db:
            return False

        try:
            async with self.db.tenant_acquire() as conn:
                await conn.execute(
                    "DELETE FROM webhook_channels WHERE channel_id = $1",
                    channel_id
                )
            logger.info(f"Webhook channel deleted: {channel_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete webhook channel: {e}")
            return False

    async def send_webhook_notification(
        self,
        channel: WebhookChannel,
        event_type: str,
        data: Dict[str, Any]
    ) -> bool:
        """Send notification to webhook channel"""
        if not channel.enabled:
            return False

        try:
            payload = self._build_webhook_payload(channel.channel_type, event_type, data)

            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    channel.webhook_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'}
                )
                response.raise_for_status()

            logger.info(f"Webhook sent to {channel.name}: {event_type}")
            return True

        except Exception as e:
            logger.error(f"Webhook failed for {channel.name}: {e}")
            return False

    def _build_webhook_payload(
        self,
        channel_type: str,
        event_type: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build webhook payload based on channel type"""
        title = data.get('title', event_type.replace('_', ' ').title())
        severity = data.get('severity', 'medium').upper()
        description = data.get('description', 'No description')
        alert_id = data.get('alert_id', 'N/A')

        severity_colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#f97316',
            'MEDIUM': '#eab308',
            'LOW': '#3b82f6'
        }
        color = severity_colors.get(severity, '#6b7280')

        if channel_type == 'slack':
            return {
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"T1 Agentics: {event_type.replace('_', ' ').title()}"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Title:*\n{title}"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n{severity}"},
                            {"type": "mrkdwn", "text": f"*Alert ID:*\n{alert_id}"},
                            {"type": "mrkdwn", "text": f"*Source:*\n{data.get('source', 'N/A')}"}
                        ]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Description:*\n{description[:500]}"}
                    }
                ],
                "attachments": [{"color": color, "blocks": []}]
            }

        elif channel_type == 'teams':
            return {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": color.replace('#', ''),
                "summary": f"T1 Agentics: {title}",
                "sections": [{
                    "activityTitle": f"T1 Agentics: {event_type.replace('_', ' ').title()}",
                    "facts": [
                        {"name": "Title", "value": title},
                        {"name": "Severity", "value": severity},
                        {"name": "Alert ID", "value": alert_id},
                        {"name": "Source", "value": data.get('source', 'N/A')}
                    ],
                    "text": description[:500],
                    "markdown": True
                }]
            }

        elif channel_type == 'webex':
            return {
                "markdown": f"""**T1 Agentics: {event_type.replace('_', ' ').title()}**

**Title:** {title}
**Severity:** {severity}
**Alert ID:** {alert_id}
**Source:** {data.get('source', 'N/A')}

{description[:500]}"""
            }

        elif channel_type == 'discord':
            return {
                "embeds": [{
                    "title": f"T1 Agentics: {event_type.replace('_', ' ').title()}",
                    "color": int(color.replace('#', ''), 16),
                    "fields": [
                        {"name": "Title", "value": title, "inline": True},
                        {"name": "Severity", "value": severity, "inline": True},
                        {"name": "Alert ID", "value": alert_id, "inline": True},
                        {"name": "Source", "value": data.get('source', 'N/A'), "inline": True},
                        {"name": "Description", "value": description[:500], "inline": False}
                    ],
                    "footer": {"text": "T1 Agentics SOC Platform"},
                    "timestamp": datetime.utcnow().isoformat()
                }]
            }

        else:  # generic
            return {
                "event_type": event_type,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data
            }

    async def test_webhook_channel(self, channel: WebhookChannel) -> Dict[str, Any]:
        """Test webhook channel connection"""
        try:
            test_data = {
                'title': 'Test Notification',
                'severity': 'low',
                'alert_id': 'TEST-001',
                'source': 'T1 Agentics Test',
                'description': 'This is a test notification from T1 Agentics SOC Platform.'
            }

            success = await self.send_webhook_notification(channel, 'test_notification', test_data)

            if success:
                return {"success": True, "message": f"Test message sent to {channel.name}"}
            else:
                return {"success": False, "error": "Failed to send test message"}

        except Exception as e:
            return {"success": False, "error": str(e)}


# Global instance
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Get or create the global email service instance"""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
