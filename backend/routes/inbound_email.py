# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Inbound Email Management API Routes
Handles mailbox configuration, email queue viewing, and phishing reports

SECURITY NOTE (2026-01-21 Audit):
All routes MUST use Depends(get_current_user) for authentication.
Admin routes MUST use Depends(require_admin) for authorization.
"""

from fastapi import APIRouter, HTTPException, Query, BackgroundTasks, Request, Depends
from pydantic import BaseModel, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
import secrets
import json

from services.postgres_db import postgres_db
from services.inbound_email_service import InboundEmailService
from dependencies.auth import get_current_user, require_admin

router = APIRouter(prefix="/api/v1/email/inbound", tags=["inbound-email"], dependencies=[Depends(get_current_user)])


def get_user_from_request(request: Request) -> dict:
    """Extract user dict from request state (set by auth middleware)."""
    if hasattr(request.state, 'user') and request.state.user:
        return request.state.user
    return {'username': 'unknown'}

# SECURITY: All routes require authentication via Depends(get_current_user)
# Mailbox configuration routes require admin role via Depends(require_admin)

# ============================================================================
# Request/Response Models
# ============================================================================

class MailboxConfigCreate(BaseModel):
    name: str
    mailbox_type: str  # 'phishing_reports', 'alert_inbox', 'approval_responses'
    imap_server: str
    imap_port: int = 993
    use_ssl: bool = True
    username: str
    password: str
    folder: str = "INBOX"
    poll_interval_seconds: int = 300
    auto_process: bool = True
    create_alerts: bool = True
    auto_ai_analysis: bool = True
    alert_severity: str = "medium"

    # SECURITY VALIDATORS (2026-01-21 Audit)
    @validator('imap_port')
    def validate_port(cls, v):
        if v < 1 or v > 65535:
            raise ValueError('Port must be between 1 and 65535')
        return v

    @validator('poll_interval_seconds')
    def validate_poll_interval(cls, v):
        if v < 60:
            raise ValueError('Poll interval must be at least 60 seconds')
        if v > 86400:
            raise ValueError('Poll interval cannot exceed 24 hours (86400 seconds)')
        return v

    @validator('imap_server')
    def validate_server(cls, v):
        # Prevent SSRF by blocking localhost and private IPs
        lower_v = v.lower().strip()
        blocked_hosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        if lower_v in blocked_hosts or lower_v.startswith('192.168.') or lower_v.startswith('10.') or lower_v.startswith('172.'):
            raise ValueError('Internal/private IMAP servers are not allowed')
        return v

class MailboxConfigUpdate(BaseModel):
    name: Optional[str] = None
    imap_server: Optional[str] = None
    imap_port: Optional[int] = None
    use_ssl: Optional[bool] = None
    username: Optional[str] = None
    password: Optional[str] = None
    folder: Optional[str] = None
    poll_interval_seconds: Optional[int] = None
    auto_process: Optional[bool] = None
    is_active: Optional[bool] = None
    create_alerts: Optional[bool] = None
    auto_ai_analysis: Optional[bool] = None
    alert_severity: Optional[str] = None

class PhishingReportUpdate(BaseModel):
    status: Optional[str] = None  # 'pending', 'investigating', 'confirmed_phishing', 'false_positive', 'resolved'
    analyst_notes: Optional[str] = None
    verdict: Optional[str] = None  # 'phishing', 'spam', 'legitimate', 'suspicious'
    investigation_id: Optional[str] = None

class ManualPhishingReport(BaseModel):
    reporter_email: str
    subject: str
    body: str
    original_sender: Optional[str] = None
    original_headers: Optional[Dict[str, Any]] = None
    attachments: Optional[List[Dict[str, Any]]] = None

class BulkUpdateRequest(BaseModel):
    report_ids: List[str]
    status: Optional[str] = None
    verdict: Optional[str] = None

class IOCExtractRequest(BaseModel):
    text: str

# ============================================================================
# Mailbox Configuration Endpoints
# ============================================================================

@router.get("/mailboxes")
async def list_mailboxes(
    include_inactive: bool = False,
    current_user: dict = Depends(require_admin)  # SECURITY: Admin only
):
    """List all configured inbound mailboxes (Admin only)"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        query = """
            SELECT id, name, mailbox_type, server as imap_server, port as imap_port, use_ssl,
                   username, folder, poll_interval_seconds, enabled as is_active,
                   auto_create_alerts as create_alerts, default_severity as alert_severity,
                   last_poll_at, last_poll_status as last_error,
                   emails_processed_total as emails_processed,
                   created_at, updated_at
            FROM inbound_mailboxes
        """
        if not include_inactive:
            query += " WHERE enabled = true"
        query += " ORDER BY name"

        rows = await conn.fetch(query)
        return {
            "mailboxes": [dict(r) for r in rows],
            "total": len(rows)
        }

@router.post("/mailboxes")
async def create_mailbox(
    config: MailboxConfigCreate,
    current_user: dict = Depends(require_admin)  # SECURITY: Admin only
):
    """Create a new inbound mailbox configuration (Admin only)"""
    service = InboundEmailService()
    service.set_db(postgres_db)

    # Convert to dict format expected by the service
    # Strip whitespace from credentials to avoid copy-paste issues
    mailbox_config = {
        'name': config.name.strip() if config.name else config.name,
        'mailbox_type': config.mailbox_type,
        'server': config.imap_server.strip() if config.imap_server else config.imap_server,
        'port': config.imap_port,
        'use_ssl': config.use_ssl,
        'username': config.username.strip() if config.username else config.username,
        'password': config.password.strip() if config.password else config.password,
        'folder': config.folder.strip() if config.folder else config.folder,
        'poll_interval_seconds': config.poll_interval_seconds,
        'enabled': config.auto_process,
        'auto_create_alerts': config.create_alerts,
        'auto_ai_analysis': config.auto_ai_analysis,
        'default_severity': config.alert_severity,
        'tenant_id': current_user.get('tenant_id')
    }

    mailbox_id = await service.create_mailbox(mailbox_config)

    if not mailbox_id:
        raise HTTPException(status_code=500, detail="Failed to create mailbox")

    return {
        "success": True,
        "mailbox_id": mailbox_id,
        "message": f"Mailbox '{config.name}' created successfully"
    }

@router.get("/mailboxes/{mailbox_id}")
async def get_mailbox(
    mailbox_id: str,
    current_user: dict = Depends(require_admin)  # SECURITY: Admin only
):
    """Get details for a specific mailbox (Admin only)"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        row = await conn.fetchrow("""
            SELECT id, name, mailbox_type, server as imap_server, port as imap_port, use_ssl,
                   username, folder, poll_interval_seconds, enabled as is_active,
                   auto_create_alerts as create_alerts, default_severity as alert_severity,
                   last_poll_at, last_poll_status as last_error,
                   emails_processed_total as emails_processed,
                   created_at, updated_at
            FROM inbound_mailboxes
            WHERE id = $1
        """, uuid.UUID(mailbox_id))

        if not row:
            raise HTTPException(status_code=404, detail="Mailbox not found")

        return dict(row)

@router.put("/mailboxes/{mailbox_id}")
async def update_mailbox(
    mailbox_id: str,
    updates: MailboxConfigUpdate,
    current_user: dict = Depends(require_admin)  # SECURITY: Admin only
):
    """Update mailbox configuration (Admin only)"""
    service = InboundEmailService()
    service.set_db(postgres_db)

    # Strip whitespace from credentials if updating
    update_data = updates.model_dump(exclude_none=True)
    for key in ['username', 'password', 'imap_server', 'folder']:
        if key in update_data and update_data[key]:
            update_data[key] = update_data[key].strip()

    success = await service.update_mailbox(mailbox_id, update_data)

    if not success:
        raise HTTPException(status_code=404, detail="Mailbox not found")

    return {"success": True, "message": "Mailbox updated successfully"}

@router.delete("/mailboxes/{mailbox_id}")
async def delete_mailbox(
    mailbox_id: str,
    current_user: dict = Depends(require_admin)  # SECURITY: Admin only
):
    """Delete a mailbox configuration (Admin only)"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        result = await conn.execute("""
            DELETE FROM inbound_mailboxes WHERE id = $1
        """, uuid.UUID(mailbox_id))

        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="Mailbox not found")

    return {"success": True, "message": "Mailbox deleted"}

@router.post("/mailboxes/{mailbox_id}/poll")
async def trigger_mailbox_poll(
    mailbox_id: str,
    current_user: dict = Depends(require_admin)  # SECURITY: Admin only
):
    """Manually trigger a mailbox poll - runs synchronously for reliability (Admin only)"""
    import logging
    logger = logging.getLogger(__name__)

    service = InboundEmailService()
    service.set_db(postgres_db)

    # Verify mailbox exists
    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, name FROM inbound_mailboxes WHERE id = $1",
            uuid.UUID(mailbox_id)
        )
        if not row:
            raise HTTPException(status_code=404, detail="Mailbox not found")

    # Run poll synchronously (no background task - more reliable)
    logger.info(f"[POLL_ROUTE] Starting poll for mailbox {row['name']}")
    result = await service.poll_mailbox(mailbox_id)
    logger.info(f"[POLL_ROUTE] Poll complete: {result}")

    return {
        "success": result.get("success", False),
        "message": f"Poll completed for mailbox '{row['name']}'",
        "emails_processed": result.get("processed", 0),
        "total_found": result.get("total_found", 0)
    }

@router.post("/mailboxes/{mailbox_id}/reprocess")
async def reprocess_pending_emails(
    mailbox_id: str,
    current_user: dict = Depends(require_admin)
):
    """Reprocess pending emails in the queue without fetching from IMAP (Admin only)"""
    import logging
    logger = logging.getLogger(__name__)

    service = InboundEmailService()
    service.set_db(postgres_db)

    logger.info(f"[REPROCESS_ROUTE] Starting reprocess for mailbox {mailbox_id}")
    result = await service.reprocess_pending(mailbox_id)
    logger.info(f"[REPROCESS_ROUTE] Complete: {result}")

    return {
        "success": result.get("success", False),
        "message": f"Reprocessed {result.get('processed', 0)} emails",
        "emails_processed": result.get("processed", 0),
        "total_found": result.get("total_found", 0)
    }

@router.post("/mailboxes/{mailbox_id}/test")
async def test_mailbox_connection(mailbox_id: str):
    """Test IMAP connection to mailbox"""
    # Get mailbox config from database
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        row = await conn.fetchrow("""
            SELECT id, server, port, use_ssl, username, password, folder
            FROM inbound_mailboxes
            WHERE id = $1
        """, uuid.UUID(mailbox_id))

        if not row:
            raise HTTPException(status_code=404, detail="Mailbox not found")

        config = {
            'server': row['server'],
            'port': row['port'],
            'use_ssl': row['use_ssl'],
            'username': row['username'],
            'password': row['password'],
            'folder': row['folder'] or 'INBOX'
        }

    service = InboundEmailService()
    service.set_db(postgres_db)

    result = await service.test_mailbox_connection(config)

    return {
        "success": result.get("success", False),
        "message": result.get("message") or result.get("error", "Unknown error"),
        "email_count": result.get("email_count")
    }

# ============================================================================
# Email Queue Endpoints
# ============================================================================

@router.get("/queue")
async def list_email_queue(
    status: Optional[str] = None,
    mailbox_id: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0
):
    """List emails in the processing queue"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        conditions = []
        params = []
        param_idx = 1

        if status:
            conditions.append(f"eq.status = ${param_idx}")
            params.append(status)
            param_idx += 1

        if mailbox_id:
            conditions.append(f"eq.mailbox_id = ${param_idx}")
            params.append(uuid.UUID(mailbox_id))
            param_idx += 1

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        query = f"""
            SELECT eq.id, eq.mailbox_id, eq.message_id, eq.from_address,
                   eq.subject, eq.received_at, eq.status as processing_status,
                   eq.error_message, eq.processed_at,
                   eq.created_at, im.name as mailbox_name
            FROM inbound_email_queue eq
            LEFT JOIN inbound_mailboxes im ON eq.mailbox_id = im.id
            WHERE {where_clause}
            ORDER BY eq.received_at DESC NULLS LAST
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)

        # Get total count
        count_query = f"SELECT COUNT(*) FROM inbound_email_queue eq WHERE {where_clause}"
        total = await conn.fetchval(count_query, *params[:-2]) if params[:-2] else await conn.fetchval(count_query)

        return {
            "emails": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset
        }

@router.get("/queue/{email_id}")
async def get_queued_email(email_id: str):
    """Get details for a specific queued email"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        row = await conn.fetchrow("""
            SELECT eq.*, im.name as mailbox_name
            FROM inbound_email_queue eq
            LEFT JOIN inbound_mailboxes im ON eq.mailbox_id = im.id
            WHERE eq.id = $1
        """, uuid.UUID(email_id))

        if not row:
            raise HTTPException(status_code=404, detail="Email not found")

        return dict(row)

@router.post("/queue/{email_id}/reprocess")
async def reprocess_email(email_id: str):
    """Reprocess a failed email"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        # Reset status to pending
        result = await conn.execute("""
            UPDATE inbound_email_queue
            SET status = 'pending',
                error_message = NULL
            WHERE id = $1
        """, uuid.UUID(email_id))

        if result == "UPDATE 0":
            raise HTTPException(status_code=404, detail="Email not found")

    return {"success": True, "message": "Email queued for reprocessing"}

@router.delete("/queue/{email_id}")
async def delete_queued_email(email_id: str):
    """Delete an email from the queue"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        result = await conn.execute("""
            DELETE FROM inbound_email_queue WHERE id = $1
        """, uuid.UUID(email_id))

        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="Email not found")

    return {"success": True, "message": "Email deleted from queue"}

# ============================================================================
# Phishing Report Endpoints
# ============================================================================

@router.get("/phishing-reports")
async def list_phishing_reports(
    status: Optional[str] = None,
    verdict: Optional[str] = None,
    days: int = Query(default=30, le=90),
    limit: int = Query(default=50, le=200),
    offset: int = 0
):
    """List phishing reports submitted by users"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        conditions = ["pr.created_at > NOW() - make_interval(days => $1)"]
        params = [days]
        param_idx = 2

        if status:
            conditions.append(f"pr.status = ${param_idx}")
            params.append(status)
            param_idx += 1

        if verdict:
            conditions.append(f"pr.verdict = ${param_idx}")
            params.append(verdict)
            param_idx += 1

        where_clause = " AND ".join(conditions)

        query = f"""
            SELECT pr.id, pr.report_id, pr.reporter_email, pr.reported_from as original_sender,
                   pr.reported_subject as original_subject, pr.status, pr.verdict,
                   pr.severity, pr.analysis_notes as analyst_notes,
                   pr.investigation_id, pr.alert_id, pr.created_at as reported_at,
                   pr.analyzed_at, pr.analyzed_by,
                   pr.message_id, pr.campaign_id,
                   pc.campaign_id as campaign_readable_id, pc.name as campaign_name,
                   JSONB_BUILD_OBJECT(
                       'urls', pr.extracted_urls,
                       'domains', pr.extracted_domains,
                       'ips', pr.extracted_ips,
                       'emails', pr.extracted_emails,
                       'hashes', pr.extracted_hashes
                   ) as iocs_extracted
            FROM phishing_reports pr
            LEFT JOIN phishing_campaigns pc ON pr.campaign_id = pc.id
            WHERE {where_clause}
            ORDER BY pr.created_at DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """
        params.extend([limit, offset])

        rows = await conn.fetch(query, *params)

        # Get total count (params minus limit/offset at the end)
        count_params = params[:-2]
        count_query = f"SELECT COUNT(*) FROM phishing_reports pr WHERE {where_clause}"
        total = await conn.fetchval(count_query, *count_params)

        return {
            "reports": [dict(r) for r in rows],
            "total": total,
            "limit": limit,
            "offset": offset
        }

@router.get("/phishing-reports/stats")
async def get_phishing_stats(days: int = Query(default=30, le=90)):
    """Get phishing report statistics"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        stats = await conn.fetchrow("""
            SELECT
                COUNT(*) as total_reports,
                COUNT(*) FILTER (WHERE status = 'new') as pending,
                COUNT(*) FILTER (WHERE status = 'analyzing') as investigating,
                COUNT(*) FILTER (WHERE status IN ('closed', 'confirmed_safe', 'false_positive')) as resolved,
                COUNT(*) FILTER (WHERE status = 'confirmed_phishing') as confirmed_phishing,
                COUNT(*) FILTER (WHERE verdict = 'spam') as spam,
                COUNT(*) FILTER (WHERE status = 'false_positive') as false_positives,
                COUNT(*) FILTER (WHERE status = 'suspicious') as suspicious,
                COUNT(*) FILTER (WHERE alert_id IS NOT NULL) as alerts_created,
                COUNT(*) FILTER (WHERE investigation_id IS NOT NULL) as investigations_created,
                COUNT(DISTINCT reporter_email) as unique_reporters
            FROM phishing_reports
            WHERE created_at > NOW() - make_interval(days => $1)
        """, days)

        # Get daily trend
        trend = await conn.fetch("""
            SELECT DATE(created_at) as date,
                   COUNT(*) as reports,
                   COUNT(*) FILTER (WHERE status = 'confirmed_phishing') as confirmed
            FROM phishing_reports
            WHERE created_at > NOW() - make_interval(days => $1)
            GROUP BY DATE(created_at)
            ORDER BY date
        """, days)

        # Get top reporters
        top_reporters = await conn.fetch("""
            SELECT reporter_email, COUNT(*) as report_count,
                   COUNT(*) FILTER (WHERE status = 'confirmed_phishing') as true_positives
            FROM phishing_reports
            WHERE created_at > NOW() - make_interval(days => $1)
            GROUP BY reporter_email
            ORDER BY report_count DESC
            LIMIT 10
        """, days)

        return {
            "summary": dict(stats),
            "daily_trend": [dict(r) for r in trend],
            "top_reporters": [dict(r) for r in top_reporters]
        }

@router.get("/phishing-reports/{report_id}")
async def get_phishing_report(report_id: str):
    """Get details for a specific phishing report"""
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        row = await conn.fetchrow("""
            SELECT pr.*, im.name as mailbox_name
            FROM phishing_reports pr
            LEFT JOIN inbound_mailboxes im ON pr.mailbox_id = im.id
            WHERE pr.id = $1
        """, uuid.UUID(report_id))

        if not row:
            raise HTTPException(status_code=404, detail="Phishing report not found")

        result = dict(row)

        # Get associated alert if exists
        if result.get('alert_id'):
            alert = await conn.fetchrow(
                "SELECT id, title, severity, status FROM alerts WHERE id = $1",
                result['alert_id']
            )
            if alert:
                result['alert'] = dict(alert)

        # Get associated investigation if exists
        if result.get('investigation_id'):
            inv = await conn.fetchrow(
                "SELECT id, title, status, severity FROM investigations WHERE id = $1",
                result['investigation_id']
            )
            if inv:
                result['investigation'] = dict(inv)

        return result

@router.put("/phishing-reports/{report_id}")
async def update_phishing_report(report_id: str, updates: PhishingReportUpdate, request: Request):
    """Update a phishing report (status, verdict, notes) with write-back to queue"""
    user = get_user_from_request(request)
    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        update_fields = []
        params = [uuid.UUID(report_id)]
        param_idx = 2

        if updates.status:
            update_fields.append(f"status = ${param_idx}")
            params.append(updates.status)
            param_idx += 1

            # Set analyzed_at/analyzed_by for classification statuses
            if updates.status in ('confirmed_phishing', 'false_positive', 'confirmed_safe', 'suspicious', 'closed'):
                update_fields.append("analyzed_at = NOW()")
                update_fields.append(f"analyzed_by = ${param_idx}")
                params.append(user.get('username', 'unknown'))
                param_idx += 1

        if updates.verdict:
            update_fields.append(f"verdict = ${param_idx}")
            params.append(updates.verdict)
            param_idx += 1

        if updates.analyst_notes:
            update_fields.append(f"analyst_notes = ${param_idx}")
            params.append(updates.analyst_notes)
            param_idx += 1

        if updates.investigation_id:
            update_fields.append(f"investigation_id = ${param_idx}")
            params.append(uuid.UUID(updates.investigation_id))
            param_idx += 1

        if not update_fields:
            raise HTTPException(status_code=400, detail="No updates provided")

        update_fields.append("updated_at = NOW()")

        query = f"""
            UPDATE phishing_reports
            SET {', '.join(update_fields)}
            WHERE id = $1
            RETURNING id, inbound_email_id, status, verdict
        """

        result = await conn.fetchrow(query, *params)

        if not result:
            raise HTTPException(status_code=404, detail="Phishing report not found")

        # Write-back: update the inbound_email_queue with the verdict/status
        if result.get('inbound_email_id'):
            write_back_result = {
                'status': result.get('status'),
                'verdict': result.get('verdict'),
                'updated_by': user.get('username', 'unknown'),
            }
            try:
                await conn.execute('''
                    UPDATE inbound_email_queue
                    SET processing_result = $2,
                        processed_at = CURRENT_TIMESTAMP
                    WHERE id = $1
                ''', result['inbound_email_id'],
                   json.dumps(write_back_result))
            except Exception:
                pass  # Non-critical write-back

    return {"success": True, "message": "Phishing report updated"}

@router.post("/phishing-reports/{report_id}/create-alert")
async def create_alert_from_report(report_id: str, request: Request, background_tasks: BackgroundTasks):
    """Create an alert from a phishing report"""
    user = get_user_from_request(request)
    service = InboundEmailService()
    service.set_db(postgres_db)

    # Create the alert (enrichment will be triggered via background_tasks)
    result = await service.create_alert_from_report(
        report_id,
        user.get('username', 'unknown'),
        background_tasks=background_tasks
    )

    if not result or not result.get('alert_id'):
        raise HTTPException(status_code=400, detail="Could not create alert")

    return {
        "success": True,
        "alert_id": result['alert_id'],
        "message": "Alert created from phishing report"
    }

@router.post("/phishing-reports/{report_id}/create-investigation")
async def create_investigation_from_report(report_id: str, request: Request):
    """Create an investigation from a phishing report"""
    user = get_user_from_request(request)
    pool = postgres_db

    async with pool.tenant_acquire() as conn:
        # Get report details
        report = await conn.fetchrow("""
            SELECT id, reporter_email, original_sender, original_subject,
                   iocs_extracted, alert_id
            FROM phishing_reports WHERE id = $1
        """, uuid.UUID(report_id))

        if not report:
            raise HTTPException(status_code=404, detail="Phishing report not found")

        # Create investigation
        import uuid
        import secrets
        inv_uuid = uuid.uuid4()
        inv_number = f"INV-{secrets.token_hex(4).upper()}"

        inv_id = await conn.fetchval("""
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
            f"Phishing Investigation: {report['original_subject'][:100]}",
            f"Investigation of reported phishing email from {report['original_sender']}",
            report['alert_id'] if report['alert_id'] else None,
            {
                "source": "phishing_report",
                "phishing_report_id": str(report_id),
                "reporter": report['reporter_email'],
                "original_sender": report['original_sender'],
                "iocs": report['iocs_extracted']
            },
            user.get('username', 'unknown')
        )

        # Update report with investigation link
        await conn.execute("""
            UPDATE phishing_reports
            SET investigation_id = $1, status = 'investigating', updated_at = NOW()
            WHERE id = $2
        """, inv_id, uuid.UUID(report_id))

    # Auto-trigger analysis for the newly created investigation
    try:
        from services.auto_analysis_trigger import auto_trigger_analysis_for_investigation
        tenant_id = user.get("tenant_id")
        if tenant_id:
            job_id = await auto_trigger_analysis_for_investigation(
                investigation_id=str(inv_uuid),
                tenant_id=tenant_id,
                priority=5  # Normal priority
            )
    except Exception as auto_err:
        logger.warning(f"Failed to auto-trigger analysis for investigation {inv_id}: {auto_err}")

    return {
        "success": True,
        "investigation_id": str(inv_id),
        "message": "Investigation created from phishing report"
    }

@router.post("/phishing-reports/manual")
async def submit_manual_phishing_report(report: ManualPhishingReport):
    """Manually submit a phishing report (for API/automation use)"""
    service = InboundEmailService()
    service.set_db(postgres_db)

    # Extract IOCs from email content
    iocs = service.extract_iocs(report.body)

    async with pool.tenant_acquire() as conn:
        report_id = await conn.fetchval("""
            INSERT INTO phishing_reports (
                reporter_email, original_sender, original_subject,
                original_body, original_headers, iocs_extracted,
                status, source
            ) VALUES ($1, $2, $3, $4, $5, $6, 'pending', 'manual_api')
            RETURNING id
        """,
            report.reporter_email,
            report.original_sender,
            report.subject,
            report.body,
            report.original_headers,
            iocs
        )

    return {
        "success": True,
        "report_id": str(report_id),
        "iocs_extracted": iocs,
        "message": "Phishing report submitted successfully"
    }

# ============================================================================
# Bulk Operations
# ============================================================================

@router.post("/phishing-reports/bulk-update")
async def bulk_update_reports(data: BulkUpdateRequest, request: Request):
    """Bulk update multiple phishing reports"""
    user = get_user_from_request(request)

    if not data.report_ids:
        raise HTTPException(status_code=400, detail="No report IDs provided")

    if not data.status and not data.verdict:
        raise HTTPException(status_code=400, detail="Must provide status or verdict")

    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        update_fields = ["updated_at = NOW()"]
        params = []
        param_idx = 1

        if data.status:
            update_fields.append(f"status = ${param_idx}")
            params.append(data.status)
            param_idx += 1

            # Set analyzed_at/analyzed_by for classification statuses
            if data.status in ('confirmed_phishing', 'false_positive', 'confirmed_safe', 'suspicious', 'closed'):
                update_fields.append("analyzed_at = NOW()")
                update_fields.append(f"analyzed_by = ${param_idx}")
                params.append(user.get('username', 'unknown'))
                param_idx += 1

        if data.verdict:
            update_fields.append(f"verdict = ${param_idx}")
            params.append(data.verdict)
            param_idx += 1

        # Add report IDs as array
        uuids = [uuid.UUID(rid) for rid in data.report_ids]
        params.append(uuids)

        query = f"""
            UPDATE phishing_reports
            SET {', '.join(update_fields)}
            WHERE id = ANY(${param_idx})
        """

        result = await conn.execute(query, *params)
        updated_count = int(result.split()[-1])

        # Write-back: update associated inbound_email_queue entries
        if updated_count > 0 and data.status:
            write_back_result = json.dumps({
                'status': data.status,
                'verdict': data.verdict,
                'updated_by': user.get('username', 'unknown'),
            })
            try:
                await conn.execute('''
                    UPDATE inbound_email_queue
                    SET processing_result = $2,
                        processed_at = CURRENT_TIMESTAMP
                    WHERE id IN (
                        SELECT inbound_email_id FROM phishing_reports
                        WHERE id = ANY($1) AND inbound_email_id IS NOT NULL
                    )
                ''', uuids, write_back_result)
            except Exception:
                pass  # Non-critical write-back

    return {
        "success": True,
        "updated_count": updated_count,
        "message": f"Updated {updated_count} phishing reports"
    }

# ============================================================================
# IOC Extraction Endpoint
# ============================================================================

@router.post("/extract-iocs")
async def extract_iocs_from_text(data: IOCExtractRequest):
    """Extract IOCs from provided text (utility endpoint)"""
    service = InboundEmailService()
    service.set_db(postgres_db)

    iocs = service.extract_iocs(data.text)

    return {
        "iocs": iocs,
        "total_count": sum(len(v) for v in iocs.values())
    }


@router.post("/phishing-reports/{report_id}/extract-iocs")
async def extract_iocs_from_report(report_id: str, request: Request):
    """Extract IOCs from a phishing report and save to database"""
    from services.ioc_extractor import ioc_extractor
    import json

    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        # Get the report with email body and headers
        report = await conn.fetchrow("""
            SELECT id, original_subject, original_sender, reporter_email,
                   email_body, email_headers, iocs_extracted
            FROM phishing_reports WHERE id = $1
        """, uuid.UUID(report_id))

        if not report:
            raise HTTPException(status_code=404, detail="Phishing report not found")

        # Combine text sources for IOC extraction
        text_parts = []
        if report['original_subject']:
            text_parts.append(report['original_subject'])
        if report['original_sender']:
            text_parts.append(report['original_sender'])
        if report['email_body']:
            text_parts.append(report['email_body'])

        # Parse headers if they exist
        headers_text = ""
        if report['email_headers']:
            headers = report['email_headers']
            if isinstance(headers, str):
                try:
                    headers = json.loads(headers)
                except:
                    headers_text = headers
            if isinstance(headers, dict):
                headers_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
            elif isinstance(headers, list):
                headers_text = "\n".join(
                    f"{h[0] if isinstance(h, (list, tuple)) else h.get('name', '')}: {h[1] if isinstance(h, (list, tuple)) else h.get('value', '')}"
                    for h in headers
                )
            text_parts.append(headers_text)

        combined_text = "\n".join(text_parts)

        # Extract IOCs
        extracted_iocs = ioc_extractor.extract_all(combined_text)

        # Save extracted IOCs to the report
        await conn.execute("""
            UPDATE phishing_reports
            SET iocs_extracted = $2, updated_at = NOW()
            WHERE id = $1
        """, uuid.UUID(report_id), json.dumps(extracted_iocs))

        # Also track IOCs in the main IOC database
        for ioc_type, ioc_values in extracted_iocs.items():
            for ioc_value in ioc_values:
                try:
                    await conn.execute("""
                        INSERT INTO iocs (ioc_value, ioc_type, source, severity, first_seen, last_seen)
                        VALUES ($1, $2, 'phishing_report', 'medium', NOW(), NOW())
                        ON CONFLICT (ioc_value, ioc_type)
                        DO UPDATE SET last_seen = NOW(), sighting_count = iocs.sighting_count + 1
                    """, ioc_value, ioc_type)
                except Exception as e:
                    print(f"Warning: Could not track IOC {ioc_value}: {e}")

        return {
            "success": True,
            "report_id": report_id,
            "iocs_extracted": extracted_iocs,
            "total_count": sum(len(v) for v in extracted_iocs.values()),
            "message": f"Extracted {sum(len(v) for v in extracted_iocs.values())} IOCs"
        }


@router.post("/phishing-reports/{report_id}/enrich")
async def enrich_phishing_report(report_id: str, background_tasks: BackgroundTasks, request: Request):
    """Run agent-based enrichment on extracted IOCs from a phishing report"""
    import json

    pool = postgres_db
    async with pool.tenant_acquire() as conn:
        # Get the report with extracted IOCs
        report = await conn.fetchrow("""
            SELECT id, original_subject, original_sender, iocs_extracted,
                   email_body, auto_analysis_result
            FROM phishing_reports WHERE id = $1
        """, uuid.UUID(report_id))

        if not report:
            raise HTTPException(status_code=404, detail="Phishing report not found")

        # Parse IOCs
        iocs_extracted = report['iocs_extracted']
        if isinstance(iocs_extracted, str):
            try:
                iocs_extracted = json.loads(iocs_extracted)
            except:
                iocs_extracted = {}

        if not iocs_extracted:
            raise HTTPException(status_code=400, detail="No IOCs to enrich. Run extraction first.")

        # Collect IOCs to enrich
        iocs_to_enrich = []
        for ioc_type, ioc_values in iocs_extracted.items():
            if not isinstance(ioc_values, list):
                ioc_values = [ioc_values] if ioc_values else []
            for ioc_value in ioc_values:
                iocs_to_enrich.append({
                    "type": ioc_type,
                    "value": ioc_value
                })

        # Queue enrichment job
        enrichment_results = {}

        try:
            from services.auto_enrichment import AutoEnrichmentService
            from services.threat_intel_service import ThreatIntelService

            enrichment_service = AutoEnrichmentService()
            threat_intel = ThreatIntelService()
            threat_intel.set_db(postgres_db)

            # Enrich each IOC
            for ioc in iocs_to_enrich[:20]:  # Limit to first 20 IOCs to avoid rate limits
                try:
                    ioc_type = ioc['type']
                    ioc_value = ioc['value']

                    # Map ioc_type to threat intel type
                    type_mapping = {
                        'ip': 'ip',
                        'domain': 'domain',
                        'url': 'url',
                        'md5': 'hash',
                        'sha1': 'hash',
                        'sha256': 'hash',
                        'email': 'email'
                    }
                    lookup_type = type_mapping.get(ioc_type, ioc_type)

                    # Lookup IOC
                    result = await threat_intel.lookup(ioc_value, lookup_type)

                    if result and result.get('success'):
                        enrichment_results[ioc_value] = {
                            "type": ioc_type,
                            "data": result.get('data', {}),
                            "sources": result.get('sources', []),
                            "risk_score": result.get('risk_score'),
                            "is_malicious": result.get('is_malicious', False)
                        }

                except Exception as e:
                    enrichment_results[ioc['value']] = {
                        "type": ioc['type'],
                        "error": str(e)
                    }

            # Save enrichment results to report
            existing_analysis = report['auto_analysis_result']
            if isinstance(existing_analysis, str):
                try:
                    existing_analysis = json.loads(existing_analysis)
                except:
                    existing_analysis = {}
            if not existing_analysis:
                existing_analysis = {}

            existing_analysis['ioc_enrichment'] = enrichment_results
            existing_analysis['enrichment_timestamp'] = datetime.now().isoformat()

            await conn.execute("""
                UPDATE phishing_reports
                SET auto_analysis_result = $2, updated_at = NOW()
                WHERE id = $1
            """, uuid.UUID(report_id), json.dumps(existing_analysis))

            # Calculate summary stats
            malicious_count = sum(1 for r in enrichment_results.values()
                                if isinstance(r, dict) and r.get('is_malicious'))
            enriched_count = sum(1 for r in enrichment_results.values()
                               if isinstance(r, dict) and 'data' in r)

            return {
                "success": True,
                "report_id": report_id,
                "enrichment_results": enrichment_results,
                "summary": {
                    "total_iocs": len(iocs_to_enrich),
                    "enriched": enriched_count,
                    "malicious_found": malicious_count
                },
                "message": f"Enriched {enriched_count} IOCs, found {malicious_count} malicious"
            }

        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Enrichment failed: {str(e)}")


# ============================================================================
# PHISHING CAMPAIGNS
# ============================================================================

@router.get("/campaigns")
async def list_phishing_campaigns(
    request: Request,
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """List phishing campaigns with related report counts"""
    async with postgres_db.tenant_acquire() as conn:
        # Build query
        where_clauses = []
        params = []
        param_idx = 1

        if status:
            where_clauses.append(f"pc.status = ${param_idx}")
            params.append(status)
            param_idx += 1

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        campaigns = await conn.fetch(f"""
            SELECT
                pc.*,
                COUNT(DISTINCT pr.id) as actual_report_count,
                COUNT(DISTINCT pr.reporter_email) as actual_unique_targets,
                ARRAY_AGG(DISTINCT pr.original_subject) FILTER (WHERE pr.original_subject IS NOT NULL) as sample_subjects
            FROM phishing_campaigns pc
            LEFT JOIN phishing_reports pr ON pr.campaign_id = pc.id
            {where_sql}
            GROUP BY pc.id
            ORDER BY pc.last_seen DESC NULLS LAST, pc.created_at DESC
            LIMIT ${param_idx} OFFSET ${param_idx + 1}
        """, *params, limit, offset)

        # Get total count
        count_result = await conn.fetchval(f"""
            SELECT COUNT(*) FROM phishing_campaigns pc {where_sql}
        """, *params)

        return {
            "campaigns": [dict(c) for c in campaigns],
            "total": count_result,
            "limit": limit,
            "offset": offset
        }


@router.get("/campaigns/{campaign_id}")
async def get_campaign_details(campaign_id: str, request: Request):
    """Get campaign details with all linked reports"""
    async with postgres_db.tenant_acquire() as conn:
        # Try to find by campaign_id (readable) or UUID
        campaign = await conn.fetchrow("""
            SELECT * FROM phishing_campaigns
            WHERE campaign_id = $1 OR id::text = $1
        """, campaign_id)

        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")

        # Get linked reports
        reports = await conn.fetch("""
            SELECT
                id, report_id, reporter_email, original_sender, original_subject,
                severity, status, confidence_score, created_at
            FROM phishing_reports
            WHERE campaign_id = $1
            ORDER BY created_at DESC
        """, campaign['id'])

        return {
            "campaign": dict(campaign),
            "reports": [dict(r) for r in reports],
            "report_count": len(reports)
        }


@router.patch("/campaigns/{campaign_id}")
async def update_campaign(campaign_id: str, request: Request):
    """Update campaign details"""
    user = get_user_from_request(request)
    body = await request.json()

    async with postgres_db.tenant_acquire() as conn:
        # Find campaign
        campaign = await conn.fetchrow("""
            SELECT id FROM phishing_campaigns
            WHERE campaign_id = $1 OR id::text = $1
        """, campaign_id)

        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")

        # Build update
        updates = []
        params = [campaign['id']]
        param_idx = 2

        allowed_fields = ['name', 'description', 'status', 'severity', 'threat_actor', 'attack_type']
        for field in allowed_fields:
            if field in body:
                updates.append(f"{field} = ${param_idx}")
                params.append(body[field])
                param_idx += 1

        if not updates:
            raise HTTPException(status_code=400, detail="No valid fields to update")

        updates.append("updated_at = NOW()")

        await conn.execute(f"""
            UPDATE phishing_campaigns
            SET {', '.join(updates)}
            WHERE id = $1
        """, *params)

        return {"success": True, "message": "Campaign updated"}


@router.post("/campaigns/{campaign_id}/merge/{target_campaign_id}")
async def merge_campaigns(campaign_id: str, target_campaign_id: str, request: Request):
    """Merge one campaign into another"""
    user = get_user_from_request(request)

    async with postgres_db.tenant_acquire() as conn:
        # Find source campaign
        source = await conn.fetchrow("""
            SELECT id FROM phishing_campaigns
            WHERE campaign_id = $1 OR id::text = $1
        """, campaign_id)

        if not source:
            raise HTTPException(status_code=404, detail="Source campaign not found")

        # Find target campaign
        target = await conn.fetchrow("""
            SELECT id FROM phishing_campaigns
            WHERE campaign_id = $1 OR id::text = $1
        """, target_campaign_id)

        if not target:
            raise HTTPException(status_code=404, detail="Target campaign not found")

        if source['id'] == target['id']:
            raise HTTPException(status_code=400, detail="Cannot merge campaign with itself")

        # Move all reports to target campaign
        result = await conn.execute("""
            UPDATE phishing_reports
            SET campaign_id = $1
            WHERE campaign_id = $2
        """, target['id'], source['id'])

        # Update target campaign stats
        await conn.execute("""
            UPDATE phishing_campaigns SET
                report_count = (SELECT COUNT(*) FROM phishing_reports WHERE campaign_id = $1),
                unique_targets = (SELECT COUNT(DISTINCT reporter_email) FROM phishing_reports WHERE campaign_id = $1),
                first_seen = LEAST(first_seen, (SELECT MIN(created_at) FROM phishing_reports WHERE campaign_id = $1)),
                last_seen = GREATEST(last_seen, (SELECT MAX(created_at) FROM phishing_reports WHERE campaign_id = $1)),
                updated_at = NOW()
            WHERE id = $1
        """, target['id'])

        # Delete source campaign
        await conn.execute("""
            DELETE FROM phishing_campaigns WHERE id = $1
        """, source['id'])

        return {
            "success": True,
            "message": f"Campaigns merged successfully",
            "target_campaign_id": target_campaign_id
        }


@router.post("/phishing-reports/{report_id}/ai-analyze")
async def trigger_ai_analysis(report_id: str, background_tasks: BackgroundTasks, request: Request):
    """Trigger AI agent analysis on a phishing report

    This creates an investigation from the report (if not already exists) and
    queues it for AI agent analysis (Tier 1 triage).
    """
    import json
    from services.job_queue import get_job_queue_service, QueueName, QueueFullError

    user = get_user_from_request(request)
    pool = postgres_db

    async with pool.tenant_acquire() as conn:
        # Get the phishing report with linked inbound email for full email body
        report = await conn.fetchrow("""
            SELECT pr.id, pr.report_id, pr.reporter_email,
                   pr.reported_from as original_sender,
                   pr.reported_subject as original_subject,
                   pr.reported_body_preview,
                   ie.body_text as email_body_text,
                   ie.body_html as email_body_html,
                   pr.investigation_id, pr.alert_id, pr.status,
                   pr.extracted_urls, pr.extracted_domains, pr.extracted_ips,
                   pr.extracted_emails, pr.extracted_hashes
            FROM phishing_reports pr
            LEFT JOIN inbound_email_queue ie ON pr.inbound_email_id = ie.id
            WHERE pr.id = $1
        """, uuid.UUID(report_id))

        if not report:
            raise HTTPException(status_code=404, detail="Phishing report not found")

        investigation_id = report['investigation_id']
        alert_id = report['alert_id']

        # Use full email body - prefer plain text, fallback to HTML stripped
        import re
        email_body = report['email_body_text'] or ''
        if not email_body and report['email_body_html']:
            html_body = report['email_body_html']
            # Remove script/style tags and their content
            html_body = re.sub(r'<script[^>]*>.*?</script>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
            html_body = re.sub(r'<style[^>]*>.*?</style>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
            # Remove all HTML tags
            email_body = re.sub(r'<[^>]+>', ' ', html_body)
            # Clean up whitespace
            email_body = re.sub(r'\s+', ' ', email_body).strip()
            # Decode common HTML entities
            email_body = email_body.replace('&nbsp;', ' ').replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"')

        # Final fallback to preview if still empty
        if not email_body:
            email_body = report['reported_body_preview'] or ''

        # If no investigation exists, create one
        if not investigation_id:
            # Build IOCs for investigation data
            iocs_data = {}
            for field, key in [
                ('extracted_urls', 'urls'),
                ('extracted_domains', 'domains'),
                ('extracted_ips', 'ips'),
                ('extracted_emails', 'emails'),
                ('extracted_hashes', 'hashes')
            ]:
                if report[field]:
                    iocs_data[key] = report[field]

            # Generate investigation ID in the format INV-YYYYMMDD-XXXXXXXX
            inv_date = datetime.now().strftime('%Y%m%d')
            inv_suffix = secrets.token_hex(4).upper()
            generated_inv_id = f"INV-{inv_date}-{inv_suffix}"

            investigation_id = await conn.fetchval("""
                INSERT INTO investigations (
                    investigation_id, alert_id, state, severity,
                    alert_title, executive_summary, investigation_data
                ) VALUES (
                    $1, $2, 'NEW', 'medium',
                    $3, $4, $5
                ) RETURNING id
            """,
                generated_inv_id,
                alert_id,
                f"AI Analysis: {report['original_subject'][:100]}",
                f"AI agent analysis of phishing report from {report['original_sender']}.\n\n"
                f"Reporter: {report['reporter_email']}\n"
                f"Email Body: {email_body[:1000]}",
                json.dumps({
                    "phishing_report_id": str(report_id),
                    "reporter": report['reporter_email'],
                    "original_sender": report['original_sender'],
                    "original_subject": report['original_subject'],
                    "email_body": email_body[:2000],
                    "iocs": iocs_data,
                    "source": "phishing_ai_analysis"
                })
            )

            # Update report with investigation link
            await conn.execute("""
                UPDATE phishing_reports
                SET investigation_id = $1, status = 'analyzing', updated_at = NOW()
                WHERE id = $2
            """, investigation_id, uuid.UUID(report_id))

        # Get an enabled Tier 1 agent for triage
        tier1_agent = await conn.fetchrow("""
            SELECT id, system_name FROM agent_definitions
            WHERE tier = 1 AND enabled = true
            ORDER BY RANDOM()
            LIMIT 1
        """)

        if not tier1_agent:
            raise HTTPException(
                status_code=400,
                detail="No enabled Tier 1 agents available. Please configure an AI agent first."
            )

        # Queue the analysis job
        try:
            job_queue = await get_job_queue_service()
            job_id = await job_queue.enqueue(
                queue_name=QueueName.AGENT,
                job_type='agent_auto_triage',
                payload={
                    'agent_id': str(tier1_agent['id']),
                    'investigation_id': str(investigation_id),
                    'alert_id': str(alert_id) if alert_id else None,
                    'source': 'phishing_report_analysis',
                    'phishing_report_id': str(report_id)
                },
                priority=3,  # Higher priority for user-triggered analysis
                raise_on_full=True
            )

            return {
                "success": True,
                "investigation_id": str(investigation_id),
                "job_id": job_id,
                "agent_name": tier1_agent['system_name'],
                "message": f"AI analysis queued with agent '{tier1_agent['system_name']}'"
            }

        except QueueFullError as e:
            raise HTTPException(status_code=429, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to queue analysis: {str(e)}")


@router.post("/phishing-reports/{report_id}/link-campaign")
async def link_report_to_campaign(report_id: str, request: Request):
    """Manually link a phishing report to a campaign"""
    user = get_user_from_request(request)
    body = await request.json()

    campaign_id = body.get('campaign_id')
    if not campaign_id:
        raise HTTPException(status_code=400, detail="campaign_id is required")

    async with postgres_db.tenant_acquire() as conn:
        # Find the report
        report = await conn.fetchrow("""
            SELECT id FROM phishing_reports WHERE id = $1
        """, uuid.UUID(report_id))

        if not report:
            raise HTTPException(status_code=404, detail="Phishing report not found")

        # Find the campaign
        campaign = await conn.fetchrow("""
            SELECT id FROM phishing_campaigns
            WHERE campaign_id = $1 OR id::text = $1
        """, campaign_id)

        if not campaign:
            raise HTTPException(status_code=404, detail="Campaign not found")

        # Link report to campaign
        await conn.execute("""
            UPDATE phishing_reports SET campaign_id = $1 WHERE id = $2
        """, campaign['id'], report['id'])

        # Update campaign stats
        await conn.execute("""
            UPDATE phishing_campaigns SET
                report_count = (SELECT COUNT(*) FROM phishing_reports WHERE campaign_id = $1),
                unique_targets = (SELECT COUNT(DISTINCT reporter_email) FROM phishing_reports WHERE campaign_id = $1),
                last_seen = GREATEST(last_seen, NOW()),
                updated_at = NOW()
            WHERE id = $1
        """, campaign['id'])

        return {"success": True, "message": "Report linked to campaign"}
