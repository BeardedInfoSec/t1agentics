# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Inbound Email Processing Service - Phase 12.3

Handles:
- IMAP mailbox polling for phishing reports
- Email parsing and IOC extraction
- Attachment handling
- Auto-create alerts from forwarded emails
- Reply-to threading for approvals
"""

import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr
import html
import logging
import re
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json

from services.alert_id_generator import generate_alert_id_sync

logger = logging.getLogger(__name__)


def clean_email_body(text: str) -> str:
    """
    Clean email body text by:
    1. Decoding HTML entities (&#847;, &zwnj;, &nbsp;, etc.)
    2. Removing zero-width and invisible characters
    3. Collapsing excessive whitespace
    """
    if not text:
        return ""

    # Decode HTML entities (&#847; -> actual char, &nbsp; -> space, etc.)
    text = html.unescape(text)

    # Remove zero-width and invisible characters
    invisible_chars = [
        '​', '‌', '‍', '‎', '‏',
        '͏', '﻿', '­', '⁠',
        '⁡', '⁢', '⁣', '⁤', '᠎',
    ]
    for char in invisible_chars:
        text = text.replace(char, '')

    # Remove control characters
    text = re.sub(r'[--]', '', text)

    # Collapse multiple spaces/newlines into single space
    text = re.sub(r'\s+', ' ', text)

    return text.strip()


@dataclass
class ParsedEmail:
    """Parsed email structure"""
    message_id: str
    from_address: str
    from_name: str
    to_addresses: List[str]
    cc_addresses: List[str]
    subject: str
    body_text: str
    body_html: str
    attachments: List[Dict[str, Any]]
    headers: Dict[str, str]
    in_reply_to: Optional[str]
    references: Optional[str]
    received_at: datetime


@dataclass
class ExtractedIOCs:
    """IOCs extracted from email content"""
    urls: List[str]
    domains: List[str]
    ips: List[str]
    emails: List[str]
    hashes: List[str]


class InboundEmailService:
    """
    Service for processing inbound emails from configured mailboxes.

    Supports:
    - IMAP polling for phishing reports
    - Automatic IOC extraction
    - Alert creation from forwarded emails
    - Approval response processing
    """

    # IOC extraction patterns
    URL_PATTERN = re.compile(
        r'https?://[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    IP_PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    )
    EMAIL_PATTERN = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    HASH_PATTERNS = {
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    }

    def __init__(self):
        self.db = None
        # Increased from 3 to 10 workers for better parallelism
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._polling_tasks: Dict[str, asyncio.Task] = {}
        self._stop_polling = False

    async def cleanup(self):
        """Shutdown the thread pool executor and stop polling."""
        logger.info("InboundEmailService: shutting down thread pool executor")
        self._stop_polling = True
        self._executor.shutdown(wait=False)

    def set_db(self, db):
        """Set database connection"""
        self.db = db

    async def initialize(self):
        """Initialize service and start polling for enabled mailboxes"""
        if not self.db or not self.db.pool:
            logger.warning("Inbound email service: No database configured")
            return

        try:
            # Use platform admin mode to load mailboxes across all tenants
            from services.postgres_db import set_platform_admin_mode
            set_platform_admin_mode(True)
            try:
                mailboxes = await self.get_enabled_mailboxes()
            finally:
                set_platform_admin_mode(False)

            logger.info(f"Inbound email service initialized with {len(mailboxes)} mailboxes")

            # Start polling for each mailbox
            for mailbox in mailboxes:
                await self.start_mailbox_polling(mailbox)

        except Exception as e:
            logger.error(f"Failed to initialize inbound email service: {e}")

    async def shutdown(self):
        """Stop all polling tasks"""
        self._stop_polling = True
        for mailbox_id, task in self._polling_tasks.items():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._polling_tasks.clear()
        logger.info("Inbound email service shut down")

    # =========================================================================
    # MAILBOX MANAGEMENT
    # =========================================================================

    async def get_enabled_mailboxes(self) -> List[Dict[str, Any]]:
        """Get all enabled inbound mailboxes"""
        if not self.db or not self.db.pool:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                rows = await conn.fetch('''
                    SELECT * FROM inbound_mailboxes
                    WHERE enabled = TRUE
                    ORDER BY name
                ''')
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get mailboxes: {e}")
            return []

    async def get_mailbox(self, mailbox_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific mailbox by ID"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    SELECT * FROM inbound_mailboxes WHERE id = $1
                ''', mailbox_id)
                return dict(row) if row else None
        except Exception as e:
            logger.error(f"Failed to get mailbox: {e}")
            return None

    async def create_mailbox(self, config: Dict[str, Any]) -> Optional[str]:
        """Create a new inbound mailbox configuration"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    INSERT INTO inbound_mailboxes (
                        mailbox_id, name, description, mailbox_type,
                        protocol, server, port, use_ssl, username, password, folder,
                        poll_interval_seconds, enabled,
                        auto_create_alerts, auto_acknowledge, auto_ai_analysis,
                        assign_to_queue, default_severity,
                        created_by, tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
                    RETURNING id
                ''',
                    config.get('mailbox_id', f"mailbox_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"),
                    config['name'],
                    config.get('description'),
                    config.get('mailbox_type', 'phishing_reports'),
                    config.get('protocol', 'imap'),
                    config.get('server'),
                    config.get('port', 993),
                    config.get('use_ssl', True),
                    config.get('username'),
                    config.get('password'),
                    config.get('folder', 'INBOX'),
                    config.get('poll_interval_seconds', 300),
                    config.get('enabled', True),
                    config.get('auto_create_alerts', True),
                    config.get('auto_acknowledge', True),
                    config.get('auto_ai_analysis', True),
                    config.get('assign_to_queue'),
                    config.get('default_severity', 'medium'),
                    config.get('created_by'),
                    uuid.UUID(str(config['tenant_id']))
                )

                mailbox_id = str(row['id'])
                logger.info(f"Created inbound mailbox: {config['name']}")

                # Start polling if enabled
                if config.get('enabled', True):
                    mailbox = await self.get_mailbox(mailbox_id)
                    if mailbox:
                        await self.start_mailbox_polling(mailbox)

                return mailbox_id

        except Exception as e:
            logger.error(f"Failed to create mailbox: {e}")
            return None

    async def update_mailbox(self, mailbox_id: str, updates: Dict[str, Any]) -> bool:
        """Update mailbox configuration"""
        if not self.db or not self.db.pool:
            return False

        try:
            # Build dynamic update query
            set_clauses = []
            values = [mailbox_id]
            param_idx = 2

            allowed_fields = [
                'name', 'description', 'server', 'port', 'use_ssl',
                'username', 'password', 'folder', 'poll_interval_seconds',
                'enabled', 'auto_create_alerts', 'auto_acknowledge',
                'assign_to_queue', 'default_severity'
            ]

            for field in allowed_fields:
                if field in updates:
                    set_clauses.append(f"{field} = ${param_idx}")
                    values.append(updates[field])
                    param_idx += 1

            if not set_clauses:
                return True  # Nothing to update

            set_clauses.append("updated_at = CURRENT_TIMESTAMP")

            async with self.db.tenant_acquire() as conn:
                await conn.execute(f'''
                    UPDATE inbound_mailboxes
                    SET {', '.join(set_clauses)}
                    WHERE id = $1
                ''', *values)

            # Handle polling state change
            if 'enabled' in updates:
                if updates['enabled']:
                    mailbox = await self.get_mailbox(mailbox_id)
                    if mailbox:
                        await self.start_mailbox_polling(mailbox)
                else:
                    await self.stop_mailbox_polling(mailbox_id)

            logger.info(f"Updated mailbox: {mailbox_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to update mailbox: {e}")
            return False

    async def delete_mailbox(self, mailbox_id: str) -> bool:
        """Delete mailbox configuration"""
        if not self.db or not self.db.pool:
            return False

        try:
            # Stop polling first
            await self.stop_mailbox_polling(mailbox_id)

            async with self.db.tenant_acquire() as conn:
                await conn.execute('''
                    DELETE FROM inbound_mailboxes WHERE id = $1
                ''', mailbox_id)

            logger.info(f"Deleted mailbox: {mailbox_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete mailbox: {e}")
            return False

    async def test_mailbox_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test connection to a mailbox"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self._executor,
                lambda: self._test_imap_connection(config)
            )
            return result
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _test_imap_connection(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronous IMAP connection test"""
        try:
            if config.get('use_ssl', True):
                imap = imaplib.IMAP4_SSL(
                    config['server'],
                    config.get('port', 993)
                )
            else:
                imap = imaplib.IMAP4(
                    config['server'],
                    config.get('port', 143)
                )

            imap.login(config['username'], config['password'])

            # Select folder to verify access
            folder = config.get('folder', 'INBOX')
            status, data = imap.select(folder, readonly=True)

            if status == 'OK':
                message_count = int(data[0])
                imap.logout()
                return {
                    "success": True,
                    "message": f"Connected successfully. {message_count} messages in {folder}",
                    "email_count": message_count
                }
            else:
                imap.logout()
                return {"success": False, "error": f"Could not select folder: {folder}"}

        except imaplib.IMAP4.error as e:
            return {"success": False, "error": f"IMAP error: {e}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # =========================================================================
    # MAILBOX POLLING
    # =========================================================================

    async def start_mailbox_polling(self, mailbox: Dict[str, Any]):
        """Start polling task for a mailbox"""
        mailbox_id = str(mailbox['id'])

        if mailbox_id in self._polling_tasks:
            logger.warning(f"Polling already active for mailbox: {mailbox_id}")
            return

        async def poll_loop():
            from services.postgres_db import set_platform_admin_mode
            from middleware.tenant_middleware import current_tenant_id as _tenant_ctx_var
            while not self._stop_polling:
                try:
                    # Set tenant context for this mailbox's polling cycle
                    _tid = str(mailbox.get('tenant_id', ''))
                    if _tid:
                        _tenant_ctx_var.set(_tid)
                    set_platform_admin_mode(True)
                    try:
                        await self.poll_mailbox(mailbox_id)
                    finally:
                        set_platform_admin_mode(False)
                except Exception as e:
                    logger.error(f"Error polling mailbox {mailbox_id}: {e}")

                # Wait for next poll
                await asyncio.sleep(mailbox.get('poll_interval_seconds', 300))

        task = asyncio.create_task(poll_loop())
        self._polling_tasks[mailbox_id] = task
        logger.info(f"Started polling for mailbox: {mailbox.get('name', mailbox_id)}")

    async def stop_mailbox_polling(self, mailbox_id: str):
        """Stop polling task for a mailbox"""
        if mailbox_id in self._polling_tasks:
            self._polling_tasks[mailbox_id].cancel()
            try:
                await self._polling_tasks[mailbox_id]
            except asyncio.CancelledError:
                pass
            del self._polling_tasks[mailbox_id]
            logger.info(f"Stopped polling for mailbox: {mailbox_id}")

    async def reprocess_pending(self, mailbox_id: str) -> Dict[str, Any]:
        """Re-process pending emails in the queue (no IMAP fetch)"""
        logger.info(f"[REPROCESS] Starting for mailbox {mailbox_id}")
        mailbox = await self.get_mailbox(mailbox_id)
        if not mailbox:
            return {"success": False, "error": "Mailbox not found"}

        try:
            async with self.db.tenant_acquire() as conn:
                rows = await conn.fetch('''
                    SELECT id, from_address, from_name, subject, body_text, body_html,
                           attachments, headers, message_id
                    FROM inbound_email_queue
                    WHERE mailbox_id = $1 AND status = 'pending'
                    ORDER BY created_at
                ''', uuid.UUID(mailbox_id))

            processed = 0
            for row in rows:
                email_data = {
                    'from_address': row['from_address'],
                    'from_name': row['from_name'],
                    'subject': row['subject'],
                    'body_text': row['body_text'],
                    'body_html': row['body_html'],
                    'attachments': json.loads(row['attachments']) if row['attachments'] else [],
                    'headers': json.loads(row['headers']) if row['headers'] else {},
                    'message_id': row['message_id']
                }

                mailbox_type = mailbox.get('mailbox_type', 'general')
                try:
                    if mailbox_type == 'phishing_reports':
                        await self._process_phishing_report(mailbox, str(row['id']), email_data)
                    elif mailbox_type == 'alert_inbox':
                        await self._process_alert_inbox_email(mailbox, str(row['id']), email_data)
                    else:
                        await self._update_queue_status(str(row['id']), 'processed')
                    processed += 1
                except Exception as e:
                    logger.error(f"[REPROCESS] Failed email {row['id']}: {e}")
                    await self._update_queue_status(str(row['id']), 'failed', str(e))

            logger.info(f"[REPROCESS] Done: {processed}/{len(rows)} processed")
            return {"success": True, "processed": processed, "total_found": len(rows)}

        except Exception as e:
            logger.error(f"[REPROCESS] Error: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

    async def poll_mailbox(self, mailbox_id: str) -> Dict[str, Any]:
        """Poll a mailbox for new emails"""
        logger.info(f"[POLL] Starting poll_mailbox for {mailbox_id}")
        mailbox = await self.get_mailbox(mailbox_id)
        if not mailbox:
            logger.error(f"[POLL] Mailbox {mailbox_id} not found")
            return {"success": False, "error": "Mailbox not found"}

        try:
            logger.info(f"[POLL] Got mailbox config: {mailbox.get('name')}, starting fetch...")
            # Run directly instead of in executor (more reliable)
            result = self._fetch_new_emails(mailbox)
            logger.info(f"[POLL] Fetch complete: {result.get('processed', 0)} emails")

            # Deduplicate emails BEFORE counting
            highest_uid = result.get('highest_uid')
            emails = result.get('emails', [])
            if emails:
                emails = await self._filter_duplicate_emails(emails)
                logger.info(f"[POLL] After duplicate filtering: {len(emails)} new emails")

            # Update poll status and UID watermark (counter updated AFTER processing)
            async with self.db.tenant_acquire() as conn:
                if highest_uid and highest_uid > 0:
                    await conn.execute('''
                        UPDATE inbound_mailboxes
                        SET last_poll_at = CURRENT_TIMESTAMP,
                            last_poll_status = $2,
                            last_uid_synced = GREATEST(COALESCE(last_uid_synced, 0), $3)
                        WHERE id = $1
                    ''', mailbox_id, 'success' if result['success'] else 'failed',
                       highest_uid)
                else:
                    await conn.execute('''
                        UPDATE inbound_mailboxes
                        SET last_poll_at = CURRENT_TIMESTAMP,
                            last_poll_status = $2
                        WHERE id = $1
                    ''', mailbox_id, 'success' if result['success'] else 'failed')

            # Process new emails in parallel (up to 10 concurrent)
            # Track actual successful processing count
            actually_processed = 0
            if emails:
                batch_size = 10
                for i in range(0, len(emails), batch_size):
                    batch = emails[i:i + batch_size]
                    results_list = await asyncio.gather(
                        *[self.process_email(mailbox, email_data) for email_data in batch],
                        return_exceptions=True
                    )
                    # Count successes (non-exception, non-None returns)
                    for r in results_list:
                        if not isinstance(r, Exception) and r is not False:
                            actually_processed += 1

            # Update emails_processed_total with actual count AFTER processing
            if actually_processed > 0:
                async with self.db.tenant_acquire() as conn:
                    await conn.execute('''
                        UPDATE inbound_mailboxes
                        SET emails_processed_total = emails_processed_total + $2
                        WHERE id = $1
                    ''', mailbox_id, actually_processed)

            result['processed'] = actually_processed
            return result

        except Exception as e:
            logger.error(f"Failed to poll mailbox: {e}")

            # Update poll status with error
            try:
                async with self.db.tenant_acquire() as conn:
                    await conn.execute('''
                        UPDATE inbound_mailboxes
                        SET last_poll_at = CURRENT_TIMESTAMP,
                            last_poll_status = 'failed'
                        WHERE id = $1
                    ''', mailbox_id)
            except:
                pass

            return {"success": False, "error": str(e)}

    def _fetch_new_emails(self, mailbox: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronously fetch new emails from IMAP"""
        import socket
        emails = []

        try:
            logger.info(f"[IMAP] Connecting to {mailbox['server']}:{mailbox.get('port', 993)} for {mailbox.get('name', 'unknown')}")

            # Set socket timeout for IMAP operations (30 seconds - reduced from 120s for faster failure detection)
            socket.setdefaulttimeout(30)

            if mailbox.get('use_ssl', True):
                imap = imaplib.IMAP4_SSL(
                    mailbox['server'],
                    mailbox.get('port', 993)
                )
            else:
                imap = imaplib.IMAP4(
                    mailbox['server'],
                    mailbox.get('port', 143)
                )

            imap.login(mailbox['username'], mailbox['password'])
            folder = mailbox.get('folder', 'INBOX')
            status, select_data = imap.select(folder)
            total_messages = int(select_data[0]) if select_data else 0
            logger.info(f"[IMAP] Selected folder '{folder}' - {total_messages} total messages")

            # Triple search strategy:
            # 1. UID watermark — catches anything newer than last sync
            # 2. UNSEEN — catches moved/relabeled messages below watermark
            # 3. SINCE date — catches emails Gmail marks as SEEN via filters/tabs
            #    (Gmail category tabs + auto-filters can set \Seen flag)
            last_uid = mailbox.get('last_uid_synced') or 0
            uid_set = set()

            if last_uid > 0:
                # 1. Search by UID watermark
                search_criteria = f'UID {last_uid + 1}:*'
                status, messages = imap.uid('search', None, search_criteria)
                if status == 'OK' and messages[0]:
                    for u in messages[0].split():
                        if int(u) > last_uid:
                            uid_set.add(u)

                # 2. Search UNSEEN to catch moved/relabeled messages
                status2, messages2 = imap.uid('search', None, 'UNSEEN')
                if status2 == 'OK' and messages2[0]:
                    for u in messages2[0].split():
                        uid_set.add(u)

                # 3. Search by date (last 1 day) to catch Gmail-auto-read emails
                #    Include ALL recent messages — duplicate check in process_email
                #    prevents reprocessing (checks message_id in DB)
                from datetime import datetime, timedelta
                since_date = (datetime.utcnow() - timedelta(days=1)).strftime('%d-%b-%Y')
                status3, messages3 = imap.uid('search', None, f'SINCE {since_date}')
                if status3 == 'OK' and messages3[0]:
                    for u in messages3[0].split():
                        uid_set.add(u)

                logger.info(f"[IMAP] Search results — UID>{last_uid}: {len(messages[0].split()) if messages[0] else 0}, "
                           f"UNSEEN: {len(messages2[0].split()) if messages2[0] else 0}, "
                           f"SINCE {since_date}: {len(messages3[0].split()) if messages3[0] else 0}")
            else:
                # First poll or no UID tracked — UNSEEN only
                status, messages = imap.uid('search', None, 'UNSEEN')
                if status != 'OK':
                    logger.error(f"[IMAP] Search failed with status: {status}")
                    imap.logout()
                    return {"success": False, "error": "Failed to search messages"}
                if messages[0]:
                    uid_set = set(messages[0].split())

            message_uids = sorted(uid_set, key=lambda u: int(u))
            logger.info(f"[IMAP] Found {len(message_uids)} candidate messages (merged UID+UNSEEN+SINCE)")

            highest_uid = last_uid
            total_to_fetch = min(len(message_uids), 50)
            for idx, uid in enumerate(message_uids[:50]):  # Limit to 50 per poll
                try:
                    uid_int = int(uid)
                    logger.info(f"[IMAP] Fetching email {idx+1}/{total_to_fetch} (UID: {uid_int})")
                    status, msg_data = imap.uid('fetch', uid, '(RFC822)')
                    if status == 'OK':
                        raw_email = msg_data[0][1]
                        parsed = self._parse_email(raw_email)
                        if parsed:
                            parsed['imap_uid'] = uid_int
                            emails.append(parsed)
                            logger.info(f"[IMAP] Parsed email: {parsed.get('subject', 'No subject')[:50]}")

                        if uid_int > highest_uid:
                            highest_uid = uid_int

                except socket.timeout:
                    logger.warning(f"[IMAP] Timeout fetching UID {uid}, skipping")
                except Exception as e:
                    logger.warning(f"[IMAP] Failed to process UID {uid}: {e}")

            imap.logout()

            logger.info(f"[IMAP] Poll complete: {len(emails)} emails fetched from {len(message_uids)} new")
            return {
                "success": True,
                "emails": emails,
                "processed": len(emails),
                "total_found": len(message_uids),
                "highest_uid": highest_uid
            }

        except Exception as e:
            logger.error(f"[IMAP] Connection/fetch error: {e}")
            return {"success": False, "error": str(e), "emails": [], "processed": 0}

    def _parse_email(self, raw_email: bytes) -> Optional[Dict[str, Any]]:
        """Parse raw email into structured data"""
        try:
            msg = email.message_from_bytes(raw_email)

            # Decode subject
            subject = ""
            if msg['Subject']:
                decoded_parts = decode_header(msg['Subject'])
                subject_parts = []
                for part, encoding in decoded_parts:
                    if isinstance(part, bytes):
                        subject_parts.append(part.decode(encoding or 'utf-8', errors='replace'))
                    else:
                        subject_parts.append(part)
                subject = ''.join(subject_parts)

            # Parse From
            from_name, from_address = parseaddr(msg.get('From', ''))

            # Parse To and CC
            to_addresses = [parseaddr(addr)[1] for addr in (msg.get('To', '') or '').split(',') if addr.strip()]
            cc_addresses = [parseaddr(addr)[1] for addr in (msg.get('Cc', '') or '').split(',') if addr.strip()]

            # Get body
            body_text = ""
            body_html = ""
            attachments = []

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))

                    if 'attachment' in content_disposition:
                        # Handle attachment
                        filename = part.get_filename() or 'unnamed'
                        content = part.get_payload(decode=True)
                        if content:
                            attachments.append({
                                'filename': filename,
                                'content_type': content_type,
                                'size_bytes': len(content),
                                'hash_sha256': hashlib.sha256(content).hexdigest(),
                                'content': content  # Store raw bytes for later storage
                            })
                    elif content_type == 'text/plain':
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode('utf-8', errors='replace')
                    elif content_type == 'text/html':
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_html = payload.decode('utf-8', errors='replace')
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    if msg.get_content_type() == 'text/html':
                        body_html = payload.decode('utf-8', errors='replace')
                    else:
                        body_text = payload.decode('utf-8', errors='replace')

            return {
                'message_id': msg.get('Message-ID', ''),
                'from_address': from_address,
                'from_name': from_name,
                'to_addresses': to_addresses,
                'cc_addresses': cc_addresses,
                'subject': subject,
                'body_text': body_text,
                'body_html': body_html,
                'attachments': attachments,
                'headers': {k: v for k, v in msg.items()},
                'in_reply_to': msg.get('In-Reply-To'),
                'references': msg.get('References'),
                'received_at': datetime.now(timezone.utc)
            }

        except Exception as e:
            logger.error(f"Failed to parse email: {e}")
            return None

    # =========================================================================
    # EMAIL PROCESSING
    # =========================================================================

    async def _filter_duplicate_emails(self, emails: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter out duplicate emails using a single batch query.

        OPTIMIZATION: Instead of checking each email individually (N queries),
        we check all message_ids in a single query (1 query).

        Args:
            emails: List of parsed email dictionaries

        Returns:
            List of emails that don't already exist in the queue
        """
        if not emails or not self.db or not self.db.pool:
            return emails

        try:
            # Extract all message_ids
            message_ids = [e.get('message_id') for e in emails if e.get('message_id')]
            if not message_ids:
                return emails

            # Single query to find existing message_ids
            async with self.db.tenant_acquire() as conn:
                existing_rows = await conn.fetch('''
                    SELECT message_id FROM inbound_email_queue
                    WHERE message_id = ANY($1::text[])
                ''', message_ids)

                existing_ids = {row['message_id'] for row in existing_rows}

            # Filter out duplicates
            new_emails = [e for e in emails if e.get('message_id') not in existing_ids]

            if len(existing_ids) > 0:
                logger.debug(f"Filtered {len(existing_ids)} duplicate emails in batch")

            return new_emails

        except Exception as e:
            logger.error(f"Batch duplicate check failed, falling back to individual checks: {e}")
            return emails  # Fall back to individual checks in _save_to_queue

    async def process_email(self, mailbox: Dict[str, Any], email_data: Dict[str, Any]):
        """Process a received email based on mailbox type.
        Returns True if successfully processed, False if skipped/failed."""
        email_id = None
        try:
            # Save to queue first
            email_id = await self._save_to_queue(mailbox, email_data)
            if not email_id:
                return False  # Duplicate or save failure

            mailbox_type = mailbox.get('mailbox_type', 'general')

            if mailbox_type == 'phishing_reports':
                await self._process_phishing_report(mailbox, email_id, email_data)
            elif mailbox_type == 'approval_responses':
                await self._process_approval_response(mailbox, email_id, email_data)
            elif mailbox_type == 'alert_inbox':
                await self._process_alert_inbox_email(mailbox, email_id, email_data)
            else:
                # Mark as processed without further action
                await self._update_queue_status(email_id, 'processed')

            return True

        except Exception as e:
            logger.error(f"Failed to process email: {e}")
            if email_id:
                await self._update_queue_status(email_id, 'failed', str(e))
            return False

    async def _save_to_queue(self, mailbox: Dict[str, Any], email_data: Dict[str, Any]) -> Optional[str]:
        """Save email to processing queue"""
        try:
            async with self.db.tenant_acquire() as conn:
                # Check for duplicate message_id
                existing = await conn.fetchval('''
                    SELECT id FROM inbound_email_queue WHERE message_id = $1
                ''', email_data.get('message_id'))

                if existing:
                    logger.debug(f"Duplicate email skipped: {email_data.get('message_id')}")
                    return None

                # Prepare attachments for JSON serialization (remove raw bytes content)
                # The actual file content is handled separately in _store_email_attachments
                attachments_for_db = []
                for att in email_data.get('attachments', []):
                    attachments_for_db.append({
                        'filename': att.get('filename'),
                        'content_type': att.get('content_type'),
                        'size_bytes': att.get('size_bytes'),
                        'hash_sha256': att.get('hash_sha256')
                        # Note: 'content' (bytes) is intentionally excluded - not JSON serializable
                    })

                # Prepare headers - ensure all values are strings (some headers may be bytes)
                headers = email_data.get('headers', {})
                headers_for_db = {}
                for k, v in headers.items():
                    if isinstance(v, bytes):
                        headers_for_db[k] = v.decode('utf-8', errors='replace')
                    else:
                        headers_for_db[k] = str(v) if v is not None else None

                from middleware.tenant_middleware import get_optional_tenant_id
                import uuid as _uuid
                _tenant_id = mailbox.get('tenant_id') or get_optional_tenant_id()

                row = await conn.fetchrow('''
                    INSERT INTO inbound_email_queue (
                        mailbox_id, message_id, from_address, from_name,
                        to_addresses, cc_addresses, subject,
                        body_text, body_html, attachments, headers,
                        in_reply_to, references_header, received_at,
                        email_type,
                        tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
                    RETURNING id
                ''',
                    mailbox['id'],
                    email_data.get('message_id'),
                    email_data.get('from_address'),
                    email_data.get('from_name'),
                    email_data.get('to_addresses', []),
                    email_data.get('cc_addresses', []),
                    email_data.get('subject'),
                    email_data.get('body_text'),
                    email_data.get('body_html'),
                    json.dumps(attachments_for_db),
                    json.dumps(headers_for_db),
                    email_data.get('in_reply_to'),
                    email_data.get('references'),
                    email_data.get('received_at'),
                    mailbox.get('mailbox_type'),
                    _uuid.UUID(str(_tenant_id)) if _tenant_id else None
                )

                return str(row['id'])

        except Exception as e:
            logger.error(f"Failed to save email to queue: {e}")
            return None

    async def _update_queue_status(
        self,
        email_id: str,
        status: str,
        error: str = None,
        result: Dict[str, Any] = None
    ):
        """Update email queue status"""
        try:
            async with self.db.tenant_acquire() as conn:
                await conn.execute('''
                    UPDATE inbound_email_queue
                    SET status = $2,
                        error_message = $3,
                        processing_result = $4,
                        processed_at = CURRENT_TIMESTAMP
                    WHERE id = $1
                ''', email_id, status, error, json.dumps(result) if result else None)
        except Exception as e:
            logger.error(f"Failed to update queue status: {e}")

    async def _process_alert_inbox_email(
        self,
        mailbox: Dict[str, Any],
        email_id: str,
        email_data: Dict[str, Any]
    ):
        """Process an email from an alert_inbox mailbox — create an alert directly"""
        import re as re_module
        try:
            # Extract IOCs from email content
            content = (email_data.get('body_text', '') + ' ' +
                      email_data.get('body_html', ''))
            iocs = self.extract_iocs(content)

            # Build IOC dict in frontend-expected format: _extracted.iocs
            extracted_iocs = {
                'ips': list(iocs.ips[:10]),
                'domains': list(iocs.domains[:10]),
                'hashes': list(iocs.hashes[:10]),
                'urls': list(iocs.urls[:10])
            }
            total_iocs = sum(len(v) for v in extracted_iocs.values())

            # Get clean email body
            email_body = clean_email_body(email_data.get('body_text', '') or '')
            html_body_raw = email_data.get('body_html', '')
            if not email_body and html_body_raw:
                html_body = html_body_raw
                html_body = re_module.sub(r'<script[^>]*>.*?</script>', '', html_body, flags=re_module.DOTALL | re_module.IGNORECASE)
                html_body = re_module.sub(r'<style[^>]*>.*?</style>', '', html_body, flags=re_module.DOTALL | re_module.IGNORECASE)
                email_body = re_module.sub(r'<[^>]+>', ' ', html_body)
                email_body = clean_email_body(email_body)

            # Extract security headers
            email_headers = email_data.get('headers', {})
            security_headers = {}
            for hdr in ['Authentication-Results', 'Received-SPF', 'DKIM-Signature',
                        'X-Spam-Status', 'X-Spam-Score', 'X-Originating-IP',
                        'Return-Path', 'Reply-To', 'X-Mailer']:
                value = email_headers.get(hdr) or email_headers.get(hdr.lower())
                if value:
                    security_headers[hdr] = value

            # Determine severity from mailbox config
            severity = mailbox.get('default_severity', 'medium')

            # Generate alert ID
            alert_id = generate_alert_id_sync(
                source='email_inbox',
                source_type='email',
                category='email_inbox',
                title=email_data.get('subject', '')
            )

            sender = email_data.get('from_address', 'unknown')
            subject = email_data.get('subject', 'No subject')

            # Get tenant from mailbox config (background tasks have no request context)
            tenant_id = mailbox.get('tenant_id')
            if not tenant_id:
                raise RuntimeError(f"Mailbox {mailbox.get('name')} has no tenant_id configured")

            async with self.db.tenant_acquire() as conn:
                await conn.execute(
                    "SELECT set_config('app.current_tenant_id', $1, false)",
                    str(tenant_id)
                )
                # Build a useful description with body preview
                body_preview = (email_body[:500] if email_body else '').strip()
                sender_domain = sender.split('@')[-1] if '@' in sender else 'unknown'
                attachment_count = len(email_data.get('attachments', []))

                desc_parts = [f"From: {sender}"]
                if subject:
                    desc_parts.append(f"Subject: {subject}")
                if total_iocs > 0:
                    ioc_summary = []
                    if extracted_iocs['urls']:
                        ioc_summary.append(f"{len(extracted_iocs['urls'])} URLs")
                    if extracted_iocs['domains']:
                        ioc_summary.append(f"{len(extracted_iocs['domains'])} domains")
                    if extracted_iocs['ips']:
                        ioc_summary.append(f"{len(extracted_iocs['ips'])} IPs")
                    if extracted_iocs['hashes']:
                        ioc_summary.append(f"{len(extracted_iocs['hashes'])} hashes")
                    desc_parts.append(f"IOCs: {', '.join(ioc_summary)}")
                if attachment_count > 0:
                    desc_parts.append(f"Attachments: {attachment_count}")
                if body_preview:
                    desc_parts.append(f"\n---\n{body_preview}")

                alert_description = '\n'.join(desc_parts)
                alert_title = f"Email: {subject[:120]}" if subject else f"Email from {sender}"

                row = await conn.fetchrow('''
                    INSERT INTO alerts (
                        alert_id, tenant_id, title, description, severity, status,
                        source, source_type, raw_event
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    RETURNING id
                ''',
                    alert_id,
                    uuid.UUID(str(tenant_id)),
                    alert_title,
                    alert_description,
                    severity,
                    'open',
                    'email_inbox',
                    'email',
                    json.dumps({
                        'sender': sender,
                        'sender_domain': sender_domain,
                        'subject': subject,
                        'body': email_body[:3000] if email_body else '',
                        'attachment_count': attachment_count,
                        'email_headers': security_headers,
                        'mailbox_name': mailbox.get('name'),
                        'message_id': email_data.get('message_id'),
                        '_extracted': {
                            'iocs': extracted_iocs
                        }
                    })
                )

                logger.info(f"Created alert {alert_id} from alert_inbox email: {subject[:60]}")

                # Store attachments if any
                attachments = email_data.get('attachments', [])
                if attachments:
                    await self._store_email_attachments(alert_id, attachments)

            # Update queue status
            await self._update_queue_status(email_id, 'processed', result={
                'alert_id': str(row['id']),
                'alert_display_id': alert_id
            })

            # Trigger auto-enrichment
            try:
                from services.auto_enrichment import enrich_alert_background
                asyncio.create_task(enrich_alert_background(alert_id, {
                    'sender': sender,
                    'subject': subject,
                    'body': email_body[:3000] if email_body else '',
                    '_extracted': {
                        'iocs': extracted_iocs
                    }
                }, tenant_id=str(tenant_id)))
            except Exception as enrich_err:
                logger.warning(f"Failed to queue enrichment for {alert_id}: {enrich_err}")

        except Exception as e:
            logger.error(f"Failed to process alert_inbox email: {e}", exc_info=True)
            await self._update_queue_status(email_id, 'failed', str(e))

    async def _process_phishing_report(
        self,
        mailbox: Dict[str, Any],
        email_id: str,
        email_data: Dict[str, Any]
    ):
        """Process a user-submitted phishing report"""
        try:
            # Extract IOCs from email body
            content = (email_data.get('body_text', '') + ' ' +
                      email_data.get('body_html', ''))
            iocs = self.extract_iocs(content)

            # Extract Message-ID from headers
            headers = email_data.get('headers', {})
            message_id = headers.get('Message-ID') or headers.get('message-id') or email_data.get('message_id')

            # Generate similarity hash for campaign linking
            similarity_hash = self._generate_similarity_hash(email_data, iocs)

            # Create phishing report
            async with self.db.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    INSERT INTO phishing_reports (
                        inbound_email_id, message_id, similarity_hash,
                        reporter_email, reporter_name,
                        reported_subject, reported_from, reported_body_preview,
                        extracted_urls, extracted_domains, extracted_ips,
                        extracted_emails, extracted_hashes,
                        attachment_count, attachment_hashes,
                        severity, status
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
                    RETURNING id, report_id
                ''',
                    email_id,
                    message_id,
                    similarity_hash,
                    email_data.get('from_address'),
                    email_data.get('from_name'),
                    email_data.get('subject'),
                    email_data.get('from_address'),  # The reporter is also the "from"
                    clean_email_body(email_data.get('body_text', '') or '')[:1000],  # Preview
                    iocs.urls,
                    iocs.domains,
                    iocs.ips,
                    iocs.emails,
                    iocs.hashes,
                    len(email_data.get('attachments', [])),
                    [a.get('hash_sha256') for a in email_data.get('attachments', [])],
                    mailbox.get('default_severity', 'medium'),
                    'new'
                )

                # Try to link to existing campaign or create new one
                await self._link_to_campaign(conn, row['id'], email_data, iocs, similarity_hash)

                report_id = row['report_id']

            # Auto-create alert if configured
            alert_id = None
            investigation_id = None
            if mailbox.get('auto_create_alerts', True):
                alert_id = await self._create_alert_from_phishing_report(
                    email_data, iocs, report_id, mailbox
                )

                # Update report with alert reference
                if alert_id:
                    async with self.db.tenant_acquire() as conn:
                        await conn.execute('''
                            UPDATE phishing_reports SET alert_id = $2 WHERE id = $1
                        ''', row['id'], alert_id)

                    # Auto-queue for AI agent analysis if enabled
                    if mailbox.get('auto_ai_analysis', True):
                        investigation_id = await self._queue_ai_analysis(
                            row['id'], email_data, iocs, alert_id, report_id
                        )

            # Send acknowledgment email if configured
            if mailbox.get('auto_acknowledge', True):
                await self._send_phishing_acknowledgment(
                    email_data.get('from_address'),
                    report_id
                )

            # Update queue status
            await self._update_queue_status(
                email_id, 'processed',
                result={'report_id': report_id, 'alert_id': str(alert_id) if alert_id else None}
            )

            logger.info(f"Processed phishing report: {report_id}")

        except Exception as e:
            logger.error(f"Failed to process phishing report: {e}")
            await self._update_queue_status(email_id, 'failed', str(e))

    def _extract_original_sender_from_forwarded(self, body: str, html_body: str = None) -> Optional[str]:
        """
        Extract the original sender from a forwarded email body.

        When users forward phishing emails to report them, the original sender
        is typically in the forwarded message headers within the body.

        Looks for patterns like:
        - From: sender@example.com
        - From: "Sender Name" <sender@example.com>
        - ---------- Forwarded message --------- From: sender@example.com
        """
        import re as re_module

        # Combine text and HTML for searching
        search_text = (body or '') + '\n' + (html_body or '')

        # Common patterns for forwarded email "From" lines
        patterns = [
            # Standard forwarded message format
            r'(?:From|Von|De|Da|От):\s*(?:"?[^"<]*"?\s*)?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
            # Gmail-style forwarded
            r'---------- Forwarded message ---------[^<]*From:\s*(?:[^<]*<)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
            # Outlook-style forwarded
            r'(?:From|Subject|Date|To):[^\n]*\nFrom:\s*(?:[^<]*<)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>?',
        ]

        for pattern in patterns:
            match = re_module.search(pattern, search_text, re_module.IGNORECASE | re_module.MULTILINE)
            if match:
                sender_email = match.group(1).lower().strip()
                # Validate it's not the reporter's own email and looks legit
                if '@' in sender_email and '.' in sender_email.split('@')[1]:
                    logger.debug(f"Extracted original sender from forwarded email: {sender_email}")
                    return sender_email

        return None

    async def _create_alert_from_phishing_report(
        self,
        email_data: Dict[str, Any],
        iocs: ExtractedIOCs,
        report_id: str,
        mailbox: Dict[str, Any]
    ) -> Optional[str]:
        """Create an alert from a phishing report"""
        try:
            import re as re_module
            # Get tenant from mailbox config (background tasks have no request context)
            tenant_id = mailbox.get('tenant_id')
            if not tenant_id:
                raise RuntimeError(f"Mailbox {mailbox.get('name')} has no tenant_id configured")

            async with self.db.tenant_acquire() as conn:
                await conn.execute(
                    "SELECT set_config('app.current_tenant_id', $1, false)",
                    str(tenant_id)
                )
                # Generate systematic alert ID for phishing reports
                alert_id = generate_alert_id_sync(
                    source='phishing_report',
                    source_type='email',
                    category='phishing',
                    title=email_data.get('subject', '')
                )

                # Build IOC list
                ioc_list = []
                for url in iocs.urls[:10]:
                    ioc_list.append({'type': 'url', 'value': url})
                for domain in iocs.domains[:10]:
                    ioc_list.append({'type': 'domain', 'value': domain})
                for ip in iocs.ips[:10]:
                    ioc_list.append({'type': 'ip', 'value': ip})
                for hash_val in iocs.hashes[:10]:
                    ioc_list.append({'type': 'hash', 'value': hash_val})

                # Add attachment file hashes to IOC list for enrichment
                for attachment in email_data.get('attachments', []):
                    if attachment.get('hash_sha256'):
                        ioc_list.append({
                            'type': 'hash',
                            'value': attachment['hash_sha256'],
                            'context': f"Attachment: {attachment.get('filename', 'unknown')}"
                        })

                # Get email body - prefer plain text, fallback to HTML stripped
                email_body = clean_email_body(email_data.get('body_text', '') or '')
                html_body_raw = email_data.get('body_html', '')
                if not email_body and html_body_raw:
                    html_body = html_body_raw
                    # Remove script/style tags and their content
                    html_body = re_module.sub(r'<script[^>]*>.*?</script>', '', html_body, flags=re_module.DOTALL | re_module.IGNORECASE)
                    html_body = re_module.sub(r'<style[^>]*>.*?</style>', '', html_body, flags=re_module.DOTALL | re_module.IGNORECASE)
                    # Remove all HTML tags
                    email_body = re_module.sub(r'<[^>]+>', ' ', html_body)
                    # Clean up whitespace and decode HTML entities
                    email_body = clean_email_body(email_body)

                # Try to extract the original sender from forwarded email content
                original_sender = self._extract_original_sender_from_forwarded(
                    email_data.get('body_text', ''),
                    html_body_raw
                )
                # If we couldn't extract it, use the reporter as fallback (direct submission case)
                if not original_sender:
                    original_sender = email_data.get('from_address')

                # =====================================================
                # PRE-FILTER: Skip alert creation for trusted senders
                # =====================================================
                if original_sender:
                    try:
                        from services.sender_trust_service import get_sender_trust_service
                        sender_trust_service = get_sender_trust_service()
                        sender_trust_service.set_db(self.db)
                        trust_result = await sender_trust_service.check_trusted_sender(original_sender)

                        if trust_result.is_trusted:
                            sender_domain = original_sender.split('@')[-1] if '@' in original_sender else original_sender
                            logger.info(
                                f"Skipping alert creation for trusted sender: {original_sender} "
                                f"(domain: {sender_domain}, trust_level: {trust_result.trust_level}, "
                                f"category: {trust_result.category})"
                            )
                            return None  # Skip alert creation
                    except Exception as trust_err:
                        # On error, proceed with alert creation (fail open for security)
                        logger.warning(f"Failed to check sender trust, proceeding with alert: {trust_err}")

                # Extract email headers for security analysis
                email_headers = email_data.get('headers', {})

                # Extract security-relevant headers
                security_headers = {}
                security_header_names = [
                    'Authentication-Results', 'Received-SPF', 'DKIM-Signature',
                    'ARC-Authentication-Results', 'X-Spam-Status', 'X-Spam-Score',
                    'X-Originating-IP', 'X-Sender-IP', 'X-MS-Exchange-Organization-SCL',
                    'X-Microsoft-Antispam', 'X-Forefront-Antispam-Report',
                    'Return-Path', 'Reply-To', 'X-Mailer', 'X-Priority',
                    'Content-Type', 'MIME-Version'
                ]
                for header_name in security_header_names:
                    # Check both exact and case-insensitive matches
                    value = email_headers.get(header_name) or email_headers.get(header_name.lower())
                    if value:
                        security_headers[header_name] = value

                # Extract Received headers (important for tracing email path)
                received_headers = []
                for key, value in email_headers.items():
                    if key.lower() == 'received':
                        if isinstance(value, list):
                            received_headers.extend(value)
                        else:
                            received_headers.append(value)

                row = await conn.fetchrow('''
                    INSERT INTO alerts (
                        alert_id, tenant_id, title, description, severity, status,
                        source, source_type, raw_event
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    RETURNING id
                ''',
                    alert_id,
                    uuid.UUID(str(tenant_id)),
                    f"Phishing Report: {email_data.get('subject', 'No subject')[:100]}",
                    f"User-reported phishing email. Original sender: {original_sender}. "
                    f"Report ID: {report_id}",
                    mailbox.get('default_severity', 'medium'),
                    'open',
                    'email_submission',
                    'email',
                    json.dumps({
                        'report_id': report_id,
                        'reporter': email_data.get('from_address'),
                        'original_sender': original_sender,
                        'sender_domain': original_sender.split('@')[-1] if original_sender and '@' in original_sender else None,
                        'subject': email_data.get('subject'),
                        'body': email_body[:3000] if email_body else '',
                        'iocs': ioc_list,
                        'attachment_count': len(email_data.get('attachments', [])),
                        'email_headers': security_headers,
                        'received_chain': received_headers[:10],  # Limit to first 10 hops
                        'all_headers': {k: v for k, v in list(email_headers.items())[:50]}  # Store all headers (limited)
                    })
                )

                logger.info(f"Created alert {alert_id} from phishing report")

                # Store email attachments if any
                attachments = email_data.get('attachments', [])
                if attachments:
                    await self._store_email_attachments(alert_id, attachments)

                # Trigger auto-enrichment for the alert
                raw_event = {
                    'report_id': report_id,
                    'reporter': email_data.get('from_address'),
                    'original_sender': original_sender,
                    'sender_domain': original_sender.split('@')[-1] if original_sender and '@' in original_sender else None,
                    'subject': email_data.get('subject'),
                    'body': email_body[:3000] if email_body else '',
                    'iocs': ioc_list,
                    'attachment_count': len(email_data.get('attachments', [])),
                    'email_headers': security_headers,
                    'received_chain': received_headers[:10]
                }
                try:
                    import asyncio
                    from services.auto_enrichment import enrich_alert_background
                    # Run enrichment in background task
                    asyncio.create_task(enrich_alert_background(alert_id, raw_event, tenant_id=str(tenant_id)))
                    logger.info(f"Queued auto-enrichment for alert {alert_id}")
                except Exception as enrich_err:
                    logger.warning(f"Failed to queue enrichment for {alert_id}: {enrich_err}")

                return row['id']

        except Exception as e:
            logger.error(f"Failed to create alert from phishing report: {e}")
            return None

    async def _store_email_attachments(
        self,
        alert_id: str,
        attachments: List[Dict[str, Any]]
    ) -> None:
        """
        Store email attachments using the file storage service.

        Args:
            alert_id: The alert ID to associate attachments with
            attachments: List of attachment dicts with 'content', 'filename', etc.
        """
        try:
            from services.file_storage import get_file_storage

            storage = get_file_storage()

            for attachment in attachments:
                content = attachment.get('content')
                if not content:
                    logger.warning(f"Attachment {attachment.get('filename')} has no content, skipping")
                    continue

                filename = attachment.get('filename', 'unnamed')

                try:
                    # Store the file
                    stored_file = await storage.store_file(
                        file_data=content,
                        original_filename=filename,
                        alert_id=alert_id,
                        uploaded_by='email_submission',
                        description=f"Email attachment from phishing report"
                    )

                    # Save to database
                    async with self.db.tenant_acquire() as conn:
                        from middleware.tenant_middleware import get_optional_tenant_id
                        import uuid as _uuid
                        _tenant_id = get_optional_tenant_id()

                        await conn.execute('''
                            INSERT INTO alert_attachments (
                                attachment_id, alert_id, filename, original_filename,
                                file_size, mime_type, storage_path, storage_type,
                                md5_hash, sha1_hash, sha256_hash,
                                description, uploaded_by, analysis_status,
                                tenant_id
                            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                        ''',
                            stored_file.attachment_id,
                            alert_id,
                            stored_file.filename,
                            stored_file.original_filename,
                            stored_file.file_size,
                            stored_file.mime_type,
                            stored_file.storage_path,
                            'local',
                            stored_file.md5_hash,
                            stored_file.sha1_hash,
                            stored_file.sha256_hash,
                            f"Email attachment: {filename}",
                            'email_submission',
                            'pending',
                            _uuid.UUID(str(_tenant_id)) if _tenant_id else None
                        )

                    logger.info(f"Stored attachment {filename} for alert {alert_id} ({stored_file.sha256_hash})")

                except Exception as e:
                    logger.error(f"Failed to store attachment {filename}: {e}")
                    continue

        except Exception as e:
            logger.error(f"Failed to store email attachments: {e}")

    async def _queue_ai_analysis(
        self,
        phishing_report_uuid,
        email_data: Dict[str, Any],
        iocs: ExtractedIOCs,
        alert_id,
        report_id: str
    ) -> Optional[str]:
        """Create investigation and queue for AI agent analysis"""
        try:
            from services.job_queue import get_job_queue_service, QueueName
            job_queue = await get_job_queue_service()

            async with self.db.tenant_acquire() as conn:
                # Build IOCs for investigation data
                iocs_data = {
                    'urls': iocs.urls,
                    'domains': iocs.domains,
                    'ips': iocs.ips,
                    'emails': iocs.emails,
                    'hashes': iocs.hashes
                }

                # Get email body - prefer plain text, fallback to HTML stripped
                email_body = email_data.get('body_text', '') or ''
                if not email_body and email_data.get('body_html'):
                    import re
                    html_body = email_data.get('body_html', '')
                    # Remove script/style tags and their content
                    html_body = re.sub(r'<script[^>]*>.*?</script>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
                    html_body = re.sub(r'<style[^>]*>.*?</style>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
                    # Remove all HTML tags
                    email_body = re.sub(r'<[^>]+>', ' ', html_body)
                    # Clean up whitespace
                    email_body = re.sub(r'\s+', ' ', email_body).strip()
                    # Decode common HTML entities
                    email_body = email_body.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')

                # Create investigation
                import uuid
                import secrets
                inv_uuid = uuid.uuid4()
                inv_number = f"INV-{secrets.token_hex(4).upper()}"

                investigation_id = await conn.fetchval("""
                    INSERT INTO investigations (
                        id, investigation_id, alert_title, executive_summary, state, severity,
                        alert_id, investigation_data
                    ) VALUES (
                        $1, $2, $3, $4, 'NEW', 'medium',
                        $5, $6
                    ) RETURNING id
                """,
                    inv_uuid,
                    inv_number,
                    f"Phishing Analysis: {email_data.get('subject', 'No subject')[:100]}",
                    f"Auto-created investigation for phishing report.\n\n"
                    f"Reporter: {email_data.get('from_address')}\n"
                    f"Subject: {email_data.get('subject')}\n"
                    f"Body Preview: {email_body[:500]}",
                    alert_id if alert_id else None,
                    json.dumps({
                        "source": "phishing_report",
                        "phishing_report_id": str(phishing_report_uuid),
                        "report_id": report_id,
                        "reporter": email_data.get('from_address'),
                        "original_sender": email_data.get('from_address'),
                        "original_subject": email_data.get('subject'),
                        "email_body": email_body[:3000],
                        "iocs": iocs_data,
                        "source": "auto_phishing_analysis"
                    }),
                    'system'
                )

                # Update phishing report with investigation link
                await conn.execute('''
                    UPDATE phishing_reports
                    SET investigation_id = $1, status = 'analyzing', updated_at = NOW()
                    WHERE id = $2
                ''', investigation_id, phishing_report_uuid)

                # Get an enabled Tier 1 agent
                tier1_agent = await conn.fetchrow("""
                    SELECT id, system_name FROM agent_definitions
                    WHERE tier = 1 AND enabled = true
                    ORDER BY RANDOM()
                    LIMIT 1
                """)

                if not tier1_agent:
                    logger.warning("No enabled Tier 1 agents for auto phishing analysis")
                    return str(investigation_id)

                # Queue the analysis job
                job_id = await job_queue.enqueue(
                    queue_name=QueueName.AGENT,
                    job_type='agent_auto_triage',
                    payload={
                        'agent_id': str(tier1_agent['id']),
                        'investigation_id': str(investigation_id),
                        'alert_id': str(alert_id) if alert_id else None,
                        'source': 'auto_phishing_analysis',
                        'phishing_report_id': str(phishing_report_uuid)
                    },
                    priority=5  # Normal priority for auto-triggered
                )

                if not job_id:
                    logger.warning(f"Queue full - skipped AI analysis for phishing report {report_id}")
                    return str(investigation_id)

                logger.info(f"Queued AI analysis job {job_id} for phishing report {report_id}")
                return str(investigation_id)

        except Exception as e:
            logger.error(f"Failed to queue AI analysis: {e}")
            return None

    async def _send_phishing_acknowledgment(self, recipient: str, report_id: str):
        """Send acknowledgment email to phishing reporter"""
        try:
            from services.email_service import get_email_service

            email_service = get_email_service()
            email_service.set_db(self.db)

            # Get template
            async with self.db.tenant_acquire() as conn:
                template = await conn.fetchrow('''
                    SELECT * FROM email_templates WHERE template_id = 'phishing_confirmation'
                ''')

            if not template:
                logger.warning("Phishing confirmation template not found")
                return

            # Render template
            subject = template['subject_template'].replace('{report_id}', report_id)
            body = template['html_template'].replace('{report_id}', report_id)
            body = body.replace('{submitted_at}', datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))
            body = body.replace('{reporter_email}', recipient)

            await email_service.send_email([recipient], subject, body)
            logger.info(f"Sent phishing acknowledgment to {recipient}")

        except Exception as e:
            logger.error(f"Failed to send acknowledgment: {e}")

    async def _process_approval_response(
        self,
        mailbox: Dict[str, Any],
        email_id: str,
        email_data: Dict[str, Any]
    ):
        """
        Process an approval response email.

        Supports multiple approval mechanisms:
        1. Reply-based: Parse email body for approve/reject keywords
        2. Token-based: Look for approval tokens in subject or body
        3. Link-based: Track clicked approval links (magic links)

        The decision is then applied to the pending agent approval request.
        """
        try:
            from_email = email_data.get('from_address', '').lower()
            subject = email_data.get('subject', '')
            body = email_data.get('body_text', '') or ''
            body_lower = body.lower()
            in_reply_to = email_data.get('in_reply_to')
            references = email_data.get('references', '')

            # Step 1: Extract approval token if present
            # Tokens can be in subject [APPROVE-TOKEN-xxx] or body
            approval_token = await self._extract_approval_token(subject, body)
            request_id = None
            request_data = None

            # Step 2: Look up the original approval request
            if approval_token:
                request_data = await self._find_approval_by_token(approval_token)
                if request_data:
                    request_id = request_data.get('request_id')
            elif in_reply_to:
                # Try to find by In-Reply-To header matching our sent email
                request_data = await self._find_approval_by_message_id(in_reply_to, references)
                if request_data:
                    request_id = request_data.get('request_id')

            if not request_data:
                logger.warning(f"Could not find approval request for email from {from_email}")
                await self._update_queue_status(
                    email_id, 'ignored',
                    'Could not match to pending approval request'
                )
                return

            # Step 3: Validate the responder is authorized
            authorized_approvers = request_data.get('authorized_approvers', [])
            if authorized_approvers and from_email not in [a.lower() for a in authorized_approvers]:
                logger.warning(f"Unauthorized approval attempt from {from_email}")
                await self._update_queue_status(
                    email_id, 'rejected',
                    f'Sender {from_email} not authorized to approve'
                )
                # Optionally notify about unauthorized attempt
                return

            # Step 4: Check if already processed
            if request_data.get('status') != 'pending':
                await self._update_queue_status(
                    email_id, 'ignored',
                    f"Request already {request_data.get('status')}"
                )
                return

            # Step 5: Check if expired
            if request_data.get('expires_at'):
                expires = request_data['expires_at']
                if isinstance(expires, str):
                    from dateutil import parser
                    expires = parser.parse(expires)
                if expires < datetime.now(timezone.utc):
                    await self._update_queue_status(
                        email_id, 'rejected',
                        'Approval request has expired'
                    )
                    return

            # Step 6: Parse response decision
            decision, confidence, notes = self._parse_approval_decision(body_lower, subject.lower())

            if decision == 'unclear':
                # Send clarification request
                await self._send_clarification_request(
                    from_email,
                    request_id,
                    request_data
                )
                await self._update_queue_status(
                    email_id, 'pending_clarification',
                    'Response unclear, clarification requested',
                    result={'original_body': body[:500]}
                )
                return

            # Step 7: Apply the decision
            success = await self._apply_approval_decision(
                request_id,
                decision,
                from_email,
                notes or f"Via email reply from {from_email}"
            )

            if success:
                await self._update_queue_status(
                    email_id, 'processed',
                    result={
                        'decision': decision,
                        'request_id': request_id,
                        'responder': from_email,
                        'confidence': confidence
                    }
                )

                # Send confirmation
                await self._send_approval_confirmation(from_email, request_id, decision, request_data)

                logger.info(f"Processed approval response: {decision} for {request_id} by {from_email}")
            else:
                await self._update_queue_status(
                    email_id, 'failed',
                    'Failed to apply approval decision'
                )

        except Exception as e:
            logger.error(f"Failed to process approval response: {e}")
            await self._update_queue_status(email_id, 'failed', str(e))

    async def _extract_approval_token(self, subject: str, body: str) -> Optional[str]:
        """
        Extract approval token from email subject or body.

        Token formats:
        - [APPROVE-xxxx-yyyy-zzzz]
        - [DENY-xxxx-yyyy-zzzz]
        - Token: xxxx-yyyy-zzzz
        - ?token=xxxx-yyyy-zzzz in URLs
        """
        import re as re_module

        combined = subject + ' ' + body

        # Pattern for bracketed tokens
        bracket_match = re_module.search(
            r'\[(?:APPROVE|DENY|APPROVAL|TOKEN)[:\-]?\s*([A-Za-z0-9\-]{8,64})\]',
            combined,
            re_module.IGNORECASE
        )
        if bracket_match:
            return bracket_match.group(1)

        # Pattern for "Token: xxx" format
        token_match = re_module.search(
            r'(?:Token|Approval\s*ID|Request\s*ID)[:\s]+([A-Za-z0-9\-]{8,64})',
            combined,
            re_module.IGNORECASE
        )
        if token_match:
            return token_match.group(1)

        # Pattern for URL query param
        url_match = re_module.search(
            r'[?&]token=([A-Za-z0-9\-]{8,64})',
            combined,
            re_module.IGNORECASE
        )
        if url_match:
            return url_match.group(1)

        return None

    async def _find_approval_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Find an approval request by its token"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                # Look in agent_approval_requests
                row = await conn.fetchrow('''
                    SELECT
                        ar.id, ar.request_id, ar.agent_id, ar.execution_id,
                        ar.action, ar.target_type, ar.target_id,
                        ar.reasoning, ar.confidence, ar.status,
                        ar.expires_at, ar.metadata
                    FROM agent_approval_requests ar
                    WHERE ar.request_id = $1
                       OR ar.metadata->>'email_token' = $1
                ''', token)

                if row:
                    result = dict(row)
                    # Parse metadata for authorized approvers
                    metadata = result.get('metadata')
                    if metadata:
                        if isinstance(metadata, str):
                            metadata = json.loads(metadata)
                        result['authorized_approvers'] = metadata.get('authorized_approvers', [])
                    return result

                return None

        except Exception as e:
            logger.error(f"Error finding approval by token: {e}")
            return None

    async def _find_approval_by_message_id(
        self,
        in_reply_to: str,
        references: str
    ) -> Optional[Dict[str, Any]]:
        """Find approval request by email Message-ID threading"""
        if not self.db or not self.db.pool:
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                # Look for approval request where we sent an email with this Message-ID
                row = await conn.fetchrow('''
                    SELECT
                        ar.id, ar.request_id, ar.agent_id, ar.execution_id,
                        ar.action, ar.target_type, ar.target_id,
                        ar.reasoning, ar.confidence, ar.status,
                        ar.expires_at, ar.metadata
                    FROM agent_approval_requests ar
                    WHERE ar.metadata->>'email_message_id' = $1
                       OR ar.metadata->>'email_message_id' = ANY(string_to_array($2, ' '))
                    ORDER BY ar.created_at DESC
                    LIMIT 1
                ''', in_reply_to, references)

                if row:
                    result = dict(row)
                    metadata = result.get('metadata')
                    if metadata:
                        if isinstance(metadata, str):
                            metadata = json.loads(metadata)
                        result['authorized_approvers'] = metadata.get('authorized_approvers', [])
                    return result

                return None

        except Exception as e:
            logger.error(f"Error finding approval by message ID: {e}")
            return None

    def _parse_approval_decision(
        self,
        body: str,
        subject: str
    ) -> Tuple[str, float, Optional[str]]:
        """
        Parse the approval decision from email content.

        Returns: (decision, confidence, notes)
        - decision: 'approved', 'denied', 'unclear'
        - confidence: 0.0-1.0 how confident we are in the parsing
        - notes: Any additional notes extracted
        """
        combined = subject + ' ' + body

        # Strong approval signals
        strong_approve = [
            'i approve', 'approved', 'yes, approve', 'go ahead',
            'permission granted', 'authorize this', 'confirmed',
            'lgtm', 'looks good'
        ]

        # Strong denial signals
        strong_deny = [
            'i deny', 'denied', 'reject', 'rejected', 'do not approve',
            'no, deny', 'not authorized', 'disapproved', 'stop this',
            'cancel', 'abort'
        ]

        # Weak signals (require more context)
        weak_approve = ['yes', 'ok', 'sure', 'fine', 'proceed']
        weak_deny = ['no', 'nope', 'negative', 'don\'t', 'stop']

        # Check strong signals first
        for signal in strong_approve:
            if signal in combined:
                # Extract any notes after the approval
                notes = self._extract_notes_from_body(body)
                return ('approved', 0.95, notes)

        for signal in strong_deny:
            if signal in combined:
                notes = self._extract_notes_from_body(body)
                return ('denied', 0.95, notes)

        # Check weak signals
        approve_count = sum(1 for s in weak_approve if s in combined)
        deny_count = sum(1 for s in weak_deny if s in combined)

        if approve_count > 0 and deny_count == 0:
            return ('approved', 0.7, self._extract_notes_from_body(body))
        elif deny_count > 0 and approve_count == 0:
            return ('denied', 0.7, self._extract_notes_from_body(body))
        elif approve_count > deny_count:
            return ('approved', 0.5, self._extract_notes_from_body(body))
        elif deny_count > approve_count:
            return ('denied', 0.5, self._extract_notes_from_body(body))

        return ('unclear', 0.0, None)

    def _extract_notes_from_body(self, body: str) -> Optional[str]:
        """Extract any notes or comments from the email body"""
        # Remove common reply headers
        lines = body.split('\n')
        note_lines = []

        for line in lines:
            line = line.strip()
            # Skip empty lines and quoted text
            if not line or line.startswith('>') or line.startswith('|'):
                continue
            # Skip common headers
            if any(line.lower().startswith(h) for h in
                   ['from:', 'to:', 'subject:', 'date:', 'sent:', 'cc:']):
                continue
            # Skip signatures
            if line.startswith('--') or line.startswith('___'):
                break
            note_lines.append(line)

        if note_lines:
            notes = ' '.join(note_lines[:5])  # First 5 meaningful lines
            return notes[:500] if len(notes) > 500 else notes

        return None

    async def _apply_approval_decision(
        self,
        request_id: str,
        decision: str,
        responder: str,
        notes: Optional[str]
    ) -> bool:
        """Apply the approval decision to the agent request"""
        if not self.db or not self.db.pool:
            return False

        try:
            status = 'approved' if decision == 'approved' else 'denied'

            async with self.db.tenant_acquire() as conn:
                result = await conn.execute('''
                    UPDATE agent_approval_requests
                    SET status = $1,
                        reviewed_by = $2,
                        reviewed_at = CURRENT_TIMESTAMP,
                        review_notes = $3
                    WHERE request_id = $4 AND status = 'pending'
                ''', status, responder, notes, request_id)

                if result == 'UPDATE 1':
                    logger.info(f"Applied approval decision: {status} for {request_id}")

                    # Trigger agent to resume if approved
                    if status == 'approved':
                        await self._notify_agent_of_approval(request_id)

                    return True

                return False

        except Exception as e:
            logger.error(f"Error applying approval decision: {e}")
            return False

    async def _notify_agent_of_approval(self, request_id: str):
        """Notify the agent service that an approval was granted"""
        try:
            from services.agent_service import agent_service
            await agent_service.process_approval_decision(
                request_id,
                'approved',
                'email_response'
            )
        except ImportError:
            logger.debug("Agent service not available for notification")
        except Exception as e:
            logger.error(f"Failed to notify agent of approval: {e}")

    async def _send_clarification_request(
        self,
        recipient: str,
        request_id: str,
        request_data: Dict[str, Any]
    ):
        """Send a clarification request when the response is unclear"""
        try:
            from services.email_service import get_email_service
            email_service = get_email_service()

            subject = f"Clarification needed: Approval request {request_id}"
            body = f"""
Your response to the approval request was unclear.

Please reply with one of the following:
- APPROVE - to approve the action
- DENY - to deny the action

Original request:
- Action: {request_data.get('action')}
- Target: {request_data.get('target_type')} / {request_data.get('target_id')}
- Reasoning: {request_data.get('reasoning')}

Request ID: {request_id}
"""

            await email_service.send_email(
                to=recipient,
                subject=subject,
                body=body
            )

        except Exception as e:
            logger.error(f"Failed to send clarification request: {e}")

    async def _send_approval_confirmation(
        self,
        recipient: str,
        request_id: str,
        decision: str,
        request_data: Dict[str, Any]
    ):
        """Send confirmation that the approval was processed"""
        try:
            from services.email_service import get_email_service
            email_service = get_email_service()

            action_word = "APPROVED" if decision == 'approved' else "DENIED"
            subject = f"Approval {action_word}: {request_id}"
            body = f"""
Your approval response has been processed.

Decision: {action_word}
Request ID: {request_id}
Action: {request_data.get('action')}
Target: {request_data.get('target_type')} / {request_data.get('target_id')}

{"The agent will now proceed with the action." if decision == 'approved' else "The action has been cancelled."}
"""

            await email_service.send_email(
                to=recipient,
                subject=subject,
                body=body
            )

        except Exception as e:
            logger.error(f"Failed to send approval confirmation: {e}")

    # =========================================================================
    # IOC EXTRACTION
    # =========================================================================

    def extract_iocs(self, content: str) -> ExtractedIOCs:
        """Extract IOCs from email content"""
        urls = list(set(self.URL_PATTERN.findall(content)))

        # Extract domains from URLs
        domains = set()
        for url in urls:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                if parsed.netloc:
                    domains.add(parsed.netloc.lower())
            except:
                pass

        ips = list(set(self.IP_PATTERN.findall(content)))

        # Filter out common IPs
        ips = [ip for ip in ips if not ip.startswith('127.')
               and not ip.startswith('0.')
               and not ip.startswith('255.')]

        emails = list(set(self.EMAIL_PATTERN.findall(content)))

        # Extract hashes
        hashes = []
        for hash_type, pattern in self.HASH_PATTERNS.items():
            matches = pattern.findall(content)
            hashes.extend(matches)
        hashes = list(set(hashes))

        return ExtractedIOCs(
            urls=urls[:50],  # Limit results
            domains=list(domains)[:30],
            ips=ips[:30],
            emails=emails[:20],
            hashes=hashes[:30]
        )

    # =========================================================================
    # CAMPAIGN LINKING
    # =========================================================================

    def _generate_similarity_hash(self, email_data: Dict[str, Any], iocs: ExtractedIOCs) -> str:
        """
        Generate a hash for similarity matching.

        Uses:
        - Sender domain (normalized)
        - Subject template (with variables removed)
        - First URL domain
        - First extracted domain

        This allows grouping emails from the same campaign that may vary slightly.
        """
        components = []

        # Extract sender domain
        from_address = email_data.get('from_address', '')
        if '@' in from_address:
            sender_domain = from_address.split('@')[-1].lower().strip()
            components.append(f"sender:{sender_domain}")

        # Normalize subject (remove numbers, names, etc.)
        subject = email_data.get('subject', '')
        normalized_subject = self._normalize_subject(subject)
        if normalized_subject:
            components.append(f"subj:{normalized_subject}")

        # First URL domain
        if iocs.urls:
            try:
                from urllib.parse import urlparse
                first_url = iocs.urls[0]
                parsed = urlparse(first_url)
                if parsed.netloc:
                    components.append(f"url:{parsed.netloc.lower()}")
            except:
                pass

        # First extracted domain
        elif iocs.domains:
            components.append(f"domain:{iocs.domains[0].lower()}")

        # Create hash
        if not components:
            return None

        combined = "|".join(sorted(components))
        return hashlib.sha256(combined.encode()).hexdigest()[:16]

    def _normalize_subject(self, subject: str) -> str:
        """
        Normalize email subject for similarity matching.

        Removes:
        - Numbers (invoice numbers, ticket IDs, etc.)
        - Common variable patterns
        - Extra whitespace
        """
        if not subject:
            return ""

        normalized = subject.lower()

        # Remove numbers (invoice numbers, IDs, etc.)
        normalized = re.sub(r'\d+', '#', normalized)

        # Remove common variable patterns
        normalized = re.sub(r'(re:|fw:|fwd:)', '', normalized)
        normalized = re.sub(r'\[.*?\]', '', normalized)  # Remove [External] etc.

        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()

        # Truncate for hash stability
        return normalized[:100]

    async def _link_to_campaign(
        self,
        conn,
        report_id: str,
        email_data: Dict[str, Any],
        iocs: ExtractedIOCs,
        similarity_hash: str
    ):
        """
        Try to link a phishing report to an existing campaign, or create a new one.

        Campaign matching criteria (in order):
        1. Same similarity hash (subject + sender domain + URL patterns)
        2. Same sender domain with similar URLs
        3. Same URLs/domains across multiple reports
        """
        if not similarity_hash:
            return

        try:
            # Look for existing campaign with matching similarity hash
            existing = await conn.fetchrow('''
                SELECT pr.campaign_id, pc.id as campaign_pk
                FROM phishing_reports pr
                JOIN phishing_campaigns pc ON pr.campaign_id = pc.id
                WHERE pr.similarity_hash = $1
                  AND pr.id != $2
                  AND pr.campaign_id IS NOT NULL
                LIMIT 1
            ''', similarity_hash, report_id)

            if existing:
                # Link to existing campaign
                campaign_id = existing['campaign_pk']
                reporter_email = email_data.get('from_address', '')

                await conn.execute('''
                    UPDATE phishing_reports SET campaign_id = $1 WHERE id = $2
                ''', campaign_id, report_id)

                # OPTIMIZATION: Check if reporter is new to this campaign (O(1) vs O(n) COUNT DISTINCT)
                is_new_reporter = await conn.fetchval('''
                    SELECT NOT EXISTS(
                        SELECT 1 FROM phishing_reports
                        WHERE campaign_id = $1 AND reporter_email = $2 AND id != $3
                        LIMIT 1
                    )
                ''', campaign_id, reporter_email, report_id)

                # Update campaign stats - only increment unique_targets if new reporter
                await conn.execute('''
                    UPDATE phishing_campaigns SET
                        report_count = report_count + 1,
                        last_seen = NOW(),
                        unique_targets = unique_targets + $2,
                        updated_at = NOW()
                    WHERE id = $1
                ''', campaign_id, 1 if is_new_reporter else 0)

                logger.info(f"Linked phishing report to existing campaign {campaign_id}")
                return

            # No matching campaign - check for similar sender domains with shared IOCs
            from_address = email_data.get('from_address', '')
            sender_domain = from_address.split('@')[-1].lower() if '@' in from_address else None

            if sender_domain and iocs.urls:
                # Look for campaigns with same sender domain and overlapping URLs
                similar = await conn.fetchrow('''
                    SELECT pc.id
                    FROM phishing_campaigns pc
                    WHERE pc.common_sender_domain = $1
                      AND pc.common_urls && $2::text[]
                      AND pc.status != 'false_positive'
                    LIMIT 1
                ''', sender_domain, iocs.urls[:5])

                if similar:
                    campaign_id = similar['id']
                    reporter_email = email_data.get('from_address', '')

                    await conn.execute('''
                        UPDATE phishing_reports SET campaign_id = $1 WHERE id = $2
                    ''', campaign_id, report_id)

                    # OPTIMIZATION: Check if reporter is new to this campaign (O(1) vs O(n) COUNT DISTINCT)
                    is_new_reporter = await conn.fetchval('''
                        SELECT NOT EXISTS(
                            SELECT 1 FROM phishing_reports
                            WHERE campaign_id = $1 AND reporter_email = $2 AND id != $3
                            LIMIT 1
                        )
                    ''', campaign_id, reporter_email, report_id)

                    # Update campaign stats - only increment unique_targets if new reporter
                    await conn.execute('''
                        UPDATE phishing_campaigns SET
                            report_count = report_count + 1,
                            last_seen = NOW(),
                            unique_targets = unique_targets + $2,
                            common_urls = ARRAY(
                                SELECT DISTINCT unnest(common_urls || $3::text[]) LIMIT 50
                            ),
                            updated_at = NOW()
                        WHERE id = $1
                    ''', campaign_id, 1 if is_new_reporter else 0, iocs.urls[:10])

                    logger.info(f"Linked phishing report to campaign {campaign_id} via sender + URLs")
                    return

            # Create new campaign if we have enough identifying info
            if sender_domain or iocs.urls or iocs.domains:
                subject = email_data.get('subject', 'Unknown')
                campaign_row = await conn.fetchrow('''
                    INSERT INTO phishing_campaigns (
                        name, common_sender_domain, common_subject_pattern,
                        common_urls, common_domains, common_ips,
                        first_seen, last_seen
                    ) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
                    RETURNING id
                ''',
                    f"Campaign: {subject[:50]}",
                    sender_domain,
                    self._normalize_subject(subject),
                    iocs.urls[:20],
                    iocs.domains[:10],
                    iocs.ips[:10]
                )

                await conn.execute('''
                    UPDATE phishing_reports SET campaign_id = $1 WHERE id = $2
                ''', campaign_row['id'], report_id)

                logger.info(f"Created new phishing campaign {campaign_row['id']}")

        except Exception as e:
            logger.error(f"Failed to link to campaign: {e}")
            # Don't fail the report creation if campaign linking fails

    # =========================================================================
    # QUERY METHODS
    # =========================================================================

    async def get_phishing_reports(
        self,
        status: str = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get phishing reports"""
        if not self.db or not self.db.pool:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                query = '''
                    SELECT * FROM phishing_reports
                    WHERE ($1::text IS NULL OR status = $1)
                    ORDER BY created_at DESC
                    LIMIT $2 OFFSET $3
                '''
                rows = await conn.fetch(query, status, limit, offset)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get phishing reports: {e}")
            return []

    async def get_email_queue(
        self,
        mailbox_id: str = None,
        status: str = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get emails from processing queue"""
        if not self.db or not self.db.pool:
            return []

        try:
            async with self.db.tenant_acquire() as conn:
                query = '''
                    SELECT eq.*, mb.name as mailbox_name
                    FROM inbound_email_queue eq
                    LEFT JOIN inbound_mailboxes mb ON eq.mailbox_id = mb.id
                    WHERE ($1::uuid IS NULL OR eq.mailbox_id = $1)
                      AND ($2::text IS NULL OR eq.status = $2)
                    ORDER BY eq.created_at DESC
                    LIMIT $3
                '''
                rows = await conn.fetch(query, mailbox_id, status, limit)
                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get email queue: {e}")
            return []

    # =========================================================================
    # ALERT CREATION FROM PHISHING REPORTS
    # =========================================================================

    async def create_alert_from_report(
        self,
        report_id: str,
        created_by: str = 'system',
        background_tasks: Optional[Any] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Create an alert from a phishing report, including full email content.

        Args:
            report_id: UUID of the phishing report
            created_by: Username of the creator
            background_tasks: FastAPI BackgroundTasks for reliable enrichment scheduling

        Returns:
            Dict with alert_id and raw_event if successful, None otherwise
        """
        if not self.db or not self.db.pool:
            logger.error("No database connection for creating alert")
            return None

        try:
            import uuid as uuid_lib

            async with self.db.tenant_acquire() as conn:
                # Get full phishing report with all email data
                report = await conn.fetchrow("""
                    SELECT
                        pr.id, pr.reporter_email, pr.original_sender, pr.original_subject,
                        pr.email_body, pr.email_headers, pr.iocs_extracted,
                        pr.attachments, pr.confidence_score, pr.auto_analysis_result,
                        pr.created_at, pr.mailbox_id, pr.message_id, pr.campaign_id,
                        pc.campaign_id as campaign_readable_id, pc.name as campaign_name
                    FROM phishing_reports pr
                    LEFT JOIN phishing_campaigns pc ON pr.campaign_id = pc.id
                    WHERE pr.id = $1
                """, uuid_lib.UUID(report_id))

                if not report:
                    logger.error(f"Phishing report not found: {report_id}")
                    return None

                # Parse IOCs if stored as string
                iocs_extracted = report['iocs_extracted']
                if isinstance(iocs_extracted, str):
                    try:
                        import json
                        iocs_extracted = json.loads(iocs_extracted)
                    except:
                        iocs_extracted = {}

                # Parse headers if stored as string
                email_headers = report['email_headers']
                if isinstance(email_headers, str):
                    try:
                        import json
                        email_headers = json.loads(email_headers)
                    except:
                        email_headers = {}

                # Parse auto analysis if stored as string
                auto_analysis = report['auto_analysis_result']
                if isinstance(auto_analysis, str):
                    try:
                        import json
                        auto_analysis = json.loads(auto_analysis)
                    except:
                        auto_analysis = {}

                # Parse attachments if stored as string
                attachments = report['attachments']
                if isinstance(attachments, str):
                    try:
                        import json
                        attachments = json.loads(attachments)
                    except:
                        attachments = []

                # Extract Message-ID from headers if not in dedicated field
                message_id = report['message_id']
                if not message_id and email_headers:
                    message_id = email_headers.get('Message-ID') or email_headers.get('message-id')

                # =====================================================
                # PRE-FILTER: Skip alert creation for trusted senders
                # =====================================================
                original_sender = report['original_sender']
                if original_sender:
                    try:
                        from services.sender_trust_service import get_sender_trust_service
                        sender_trust_service = get_sender_trust_service()
                        sender_trust_service.set_db(self.db)
                        trust_result = await sender_trust_service.check_trusted_sender(original_sender)

                        if trust_result.is_trusted:
                            sender_domain = original_sender.split('@')[-1] if '@' in original_sender else original_sender
                            logger.info(
                                f"Skipping alert creation for trusted sender: {original_sender} "
                                f"(domain: {sender_domain}, trust_level: {trust_result.trust_level}, "
                                f"category: {trust_result.category})"
                            )
                            return None  # Skip alert creation
                    except Exception as trust_err:
                        # On error, proceed with alert creation (fail open for security)
                        logger.warning(f"Failed to check sender trust, proceeding with alert: {trust_err}")

                # Build comprehensive alert metadata with full email content
                alert_metadata = {
                    "source": "phishing_report",
                    "phishing_report_id": report_id,
                    "reporter_email": report['reporter_email'],
                    "original_sender": report['original_sender'],
                    "original_subject": report['original_subject'],
                    "confidence_score": float(report['confidence_score']) if report['confidence_score'] else None,

                    # Message tracking
                    "message_id": message_id,

                    # Campaign information (if linked)
                    "campaign": {
                        "id": str(report['campaign_id']) if report['campaign_id'] else None,
                        "campaign_id": report['campaign_readable_id'],
                        "name": report['campaign_name']
                    } if report['campaign_id'] else None,

                    # Full email content
                    "email": {
                        "body": report['email_body'],
                        "headers": email_headers,
                        "subject": report['original_subject'],
                        "from": report['original_sender'],
                        "reported_by": report['reporter_email'],
                        "message_id": message_id  # Also include in email section
                    },

                    # Extracted IOCs
                    "iocs_extracted": iocs_extracted,

                    # Attachments metadata (not full content for storage efficiency)
                    "attachments": attachments or [],
                    "attachment_count": len(attachments) if attachments else 0,

                    # Auto-analysis results
                    "auto_analysis": auto_analysis,

                    # Timestamps
                    "reported_at": report['created_at'].isoformat() if report['created_at'] else None
                }

                # Determine severity based on AI confidence (NOT IOC count - high count doesn't mean malicious)
                severity = "medium"
                confidence = report['confidence_score'] or 0

                # Severity is based on how confident we are it's malicious, not IOC count
                if confidence >= 0.9:
                    severity = "critical"
                elif confidence >= 0.75:
                    severity = "high"
                elif confidence < 0.3:
                    severity = "low"

                # Create the alert with full email context
                import json
                alert_id = await conn.fetchval("""
                    INSERT INTO alerts (
                        title,
                        description,
                        severity,
                        status,
                        source,
                        source_ref,
                        alert_metadata,
                        raw_event,
                        created_by,
                        created_at,
                        updated_at
                    ) VALUES (
                        $1, $2, $3, 'open', 'phishing_report', $4, $5, $6, $7, NOW(), NOW()
                    ) RETURNING id
                """,
                    f"Phishing Report: {report['original_subject'][:150] if report['original_subject'] else 'No Subject'}",
                    f"Phishing email reported by {report['reporter_email']}. "
                    f"Original sender: {report['original_sender']}. "
                    f"Extracted {ioc_count} IOCs.",
                    severity,
                    report_id,
                    json.dumps(alert_metadata),
                    json.dumps({
                        "email_body": report['email_body'],
                        "email_headers": email_headers,
                        "attachments": attachments
                    }),
                    created_by
                )

                # Update the phishing report with alert link
                await conn.execute("""
                    UPDATE phishing_reports
                    SET alert_id = $1, status = 'investigating', updated_at = NOW()
                    WHERE id = $2
                """, alert_id, uuid_lib.UUID(report_id))

                # Track IOCs from the report in the main IOC database
                for ioc_type, ioc_values in (iocs_extracted or {}).items():
                    if not isinstance(ioc_values, list):
                        ioc_values = [ioc_values] if ioc_values else []
                    for ioc_value in ioc_values[:50]:  # Limit per type
                        try:
                            await conn.execute("""
                                INSERT INTO iocs (ioc_value, ioc_type, source, severity, first_seen, last_seen)
                                VALUES ($1, $2, 'phishing_alert', $3, NOW(), NOW())
                                ON CONFLICT (ioc_value, ioc_type)
                                DO UPDATE SET last_seen = NOW(), sighting_count = iocs.sighting_count + 1
                            """, str(ioc_value), ioc_type, severity)
                        except Exception as e:
                            logger.warning(f"Could not track IOC {ioc_value}: {e}")

                logger.info(f"Created alert {alert_id} from phishing report {report_id}")

                # Build raw_event for enrichment
                raw_event_for_enrichment = {
                    "email_body": report['email_body'],
                    "email_headers": email_headers,
                    "attachments": attachments,
                    "iocs_extracted": iocs_extracted,
                    "original_sender": report['original_sender'],
                    "original_subject": report['original_subject']
                }

                # Trigger auto-enrichment using FastAPI BackgroundTasks for reliability
                if background_tasks:
                    try:
                        from services.auto_enrichment import enrich_alert_background
                        background_tasks.add_task(
                            enrich_alert_background,
                            alert_id=str(alert_id),
                            raw_event=raw_event_for_enrichment,
                            tenant_id=str(tenant_id)
                        )
                        logger.info(f"Queued auto-enrichment for alert {alert_id} via BackgroundTasks")
                    except Exception as enrich_err:
                        logger.warning(f"Failed to queue enrichment for alert {alert_id}: {enrich_err}")
                else:
                    # Fallback to asyncio.create_task if no background_tasks provided
                    # (less reliable but maintains backwards compatibility)
                    try:
                        import asyncio
                        from services.auto_enrichment import enrich_alert_background
                        asyncio.create_task(enrich_alert_background(str(alert_id), raw_event_for_enrichment, tenant_id=str(tenant_id)))
                        logger.info(f"Queued auto-enrichment for alert {alert_id} via asyncio.create_task (fallback)")
                    except Exception as enrich_err:
                        logger.warning(f"Failed to queue enrichment for alert {alert_id}: {enrich_err}")

                return {
                    'alert_id': str(alert_id),
                    'raw_event': raw_event_for_enrichment
                }

        except Exception as e:
            logger.error(f"Failed to create alert from phishing report: {e}")
            import traceback
            traceback.print_exc()
            return None


# Global instance
_inbound_email_service: Optional[InboundEmailService] = None


def get_inbound_email_service() -> InboundEmailService:
    """Get or create the global inbound email service"""
    global _inbound_email_service
    if _inbound_email_service is None:
        _inbound_email_service = InboundEmailService()
    return _inbound_email_service
