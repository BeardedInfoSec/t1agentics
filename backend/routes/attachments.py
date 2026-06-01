# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Alert Attachments API - File Upload and Management

Endpoints for:
- Uploading files to alerts
- Downloading attachments
- Listing attachments for an alert
- File metadata and analysis status
- Deleting attachments
"""

from fastapi import APIRouter, HTTPException, Header, Query, Request, UploadFile, File, Form, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path
import io
import logging

from routes.admin import require_admin, get_current_username
from dependencies.auth import get_current_user
from middleware.tenant_middleware import get_optional_tenant_id
from services.file_storage import get_file_storage, StoredFile

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/attachments", tags=["attachments"], dependencies=[Depends(get_current_user)])


# ==================== MODELS ====================

class AttachmentResponse(BaseModel):
    """Attachment metadata response"""
    attachment_id: str
    alert_id: str
    filename: str
    original_filename: str
    file_size: int
    mime_type: Optional[str]
    md5_hash: str
    sha1_hash: str
    sha256_hash: str
    description: Optional[str]
    uploaded_by: Optional[str]
    uploaded_at: str
    analysis_status: str
    is_malicious: Optional[bool]
    threat_score: Optional[int]


class AttachmentListResponse(BaseModel):
    """List of attachments"""
    alert_id: str
    attachments: List[AttachmentResponse]
    total_count: int
    total_size_bytes: int


class UploadResponse(BaseModel):
    """Upload success response"""
    success: bool
    attachment_id: str
    filename: str
    sha256_hash: str
    message: str


# ==================== ENDPOINTS ====================

@router.post("/upload/{alert_id}", response_model=UploadResponse)
async def upload_attachment(
    request: Request,
    alert_id: str,
    file: UploadFile = File(..., description="File to upload"),
    description: str = Form(None, description="Optional file description"),
    authorization: str = Header(None)
):
    """
    Upload a file attachment to an alert.

    Supported file types include documents, images, logs, PCAPs, and executables.
    Executable files are automatically quarantined.
    Maximum file size: 50MB
    """
    username = await get_current_username(request, authorization)

    # Read file data
    try:
        file_data = await file.read()
    except Exception as e:
        logger.error(f"[ATTACHMENTS] Failed to read uploaded file: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

    # Validate alert exists
    from services.postgres_db import postgres_db

    async with postgres_db.tenant_acquire() as conn:
        alert = await conn.fetchrow(
            'SELECT alert_id FROM alerts WHERE alert_id = $1',
            alert_id
        )
        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    # Store file
    storage = get_file_storage()
    try:
        stored_file = await storage.store_file(
            file_data=file_data,
            original_filename=file.filename,
            alert_id=alert_id,
            uploaded_by=username,
            description=description
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"[ATTACHMENTS] Failed to store file: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to store file: {str(e)}")

    # Save attachment record to database
    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute('''
                INSERT INTO alert_attachments (
                    attachment_id, alert_id, filename, original_filename,
                    file_size, mime_type, storage_path, storage_type,
                    md5_hash, sha1_hash, sha256_hash,
                    description, uploaded_by, analysis_status, tenant_id
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
                description,
                username,
                'pending',
                get_optional_tenant_id()
            )

        logger.info(f"[ATTACHMENTS] Uploaded {stored_file.original_filename} to alert {alert_id} ({stored_file.sha256_hash})")

        # Send notification for file upload
        try:
            from services.email_service import get_email_service
            email_service = get_email_service()
            email_service.set_db(postgres_db)
            await email_service.notify_event('file_attachment_uploaded', {
                'alert_id': alert_id,
                'attachment_id': stored_file.attachment_id,
                'filename': stored_file.original_filename,
                'file_size': stored_file.file_size,
                'sha256_hash': stored_file.sha256_hash,
                'uploaded_by': username,
                'title': f"File uploaded: {stored_file.original_filename}",
                'severity': 'low'
            })
        except Exception as notify_error:
            logger.warning(f"[ATTACHMENTS] Failed to send notification: {notify_error}")

    except Exception as e:
        logger.error(f"[ATTACHMENTS] Failed to save attachment record: {e}")
        # Try to clean up the stored file
        await storage.delete_file(stored_file.storage_path)
        raise HTTPException(status_code=500, detail=f"Failed to save attachment: {str(e)}")

    return UploadResponse(
        success=True,
        attachment_id=stored_file.attachment_id,
        filename=stored_file.original_filename,
        sha256_hash=stored_file.sha256_hash,
        message=f"File uploaded successfully"
    )


@router.get("/alert/{alert_id}", response_model=AttachmentListResponse)
async def list_alert_attachments(
    request: Request,
    alert_id: str,
    include_deleted: bool = Query(False, description="Include soft-deleted attachments"),
    authorization: str = Header(None)
):
    """List all attachments for an alert"""
    await get_current_username(request, authorization)

    from services.postgres_db import postgres_db

    async with postgres_db.tenant_acquire() as conn:
        # Check alert exists
        alert = await conn.fetchrow(
            'SELECT alert_id FROM alerts WHERE alert_id = $1',
            alert_id
        )
        if not alert:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

        # Get attachments
        query = '''
            SELECT attachment_id, alert_id, filename, original_filename,
                   file_size, mime_type, md5_hash, sha1_hash, sha256_hash,
                   description, uploaded_by, uploaded_at,
                   analysis_status, is_malicious, threat_score
            FROM alert_attachments
            WHERE alert_id = $1
        '''
        if not include_deleted:
            query += ' AND deleted_at IS NULL'
        query += ' ORDER BY uploaded_at DESC'

        rows = await conn.fetch(query, alert_id)

        attachments = []
        total_size = 0
        for row in rows:
            attachments.append(AttachmentResponse(
                attachment_id=row['attachment_id'],
                alert_id=row['alert_id'],
                filename=row['filename'],
                original_filename=row['original_filename'],
                file_size=row['file_size'],
                mime_type=row['mime_type'],
                md5_hash=row['md5_hash'],
                sha1_hash=row['sha1_hash'],
                sha256_hash=row['sha256_hash'],
                description=row['description'],
                uploaded_by=row['uploaded_by'],
                uploaded_at=row['uploaded_at'].isoformat() if row['uploaded_at'] else None,
                analysis_status=row['analysis_status'] or 'pending',
                is_malicious=row['is_malicious'],
                threat_score=row['threat_score']
            ))
            total_size += row['file_size']

    return AttachmentListResponse(
        alert_id=alert_id,
        attachments=attachments,
        total_count=len(attachments),
        total_size_bytes=total_size
    )


@router.get("/{attachment_id}")
async def get_attachment_metadata(
    request: Request,
    attachment_id: str,
    authorization: str = Header(None)
):
    """Get attachment metadata by ID"""
    await get_current_username(request, authorization)

    from services.postgres_db import postgres_db

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow('''
            SELECT attachment_id, alert_id, filename, original_filename,
                   file_size, mime_type, storage_path, storage_type,
                   md5_hash, sha1_hash, sha256_hash,
                   description, uploaded_by, uploaded_at,
                   analysis_status, analysis_result, is_malicious, threat_score
            FROM alert_attachments
            WHERE attachment_id = $1 AND deleted_at IS NULL
        ''', attachment_id)

        if not row:
            raise HTTPException(status_code=404, detail="Attachment not found")

        return {
            "attachment_id": row['attachment_id'],
            "alert_id": row['alert_id'],
            "filename": row['filename'],
            "original_filename": row['original_filename'],
            "file_size": row['file_size'],
            "mime_type": row['mime_type'],
            "storage_type": row['storage_type'],
            "md5_hash": row['md5_hash'],
            "sha1_hash": row['sha1_hash'],
            "sha256_hash": row['sha256_hash'],
            "description": row['description'],
            "uploaded_by": row['uploaded_by'],
            "uploaded_at": row['uploaded_at'].isoformat() if row['uploaded_at'] else None,
            "analysis_status": row['analysis_status'],
            "analysis_result": row['analysis_result'] or {},
            "is_malicious": row['is_malicious'],
            "threat_score": row['threat_score']
        }


@router.get("/{attachment_id}/download")
async def download_attachment(
    request: Request,
    attachment_id: str,
    authorization: str = Header(None)
):
    """
    Download an attachment file.

    Returns the file with appropriate Content-Type and Content-Disposition headers.
    """
    await get_current_username(request, authorization)

    from services.postgres_db import postgres_db

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow('''
            SELECT storage_path, original_filename, mime_type, sha256_hash
            FROM alert_attachments
            WHERE attachment_id = $1 AND deleted_at IS NULL
        ''', attachment_id)

        if not row:
            raise HTTPException(status_code=404, detail="Attachment not found")

    storage = get_file_storage()
    file_data = await storage.get_file(row['storage_path'])

    if not file_data:
        raise HTTPException(status_code=404, detail="File not found in storage")

    # Verify file integrity
    if not await storage.verify_file(row['storage_path'], row['sha256_hash']):
        logger.warning(f"[ATTACHMENTS] File integrity check failed: {attachment_id}")
        raise HTTPException(status_code=500, detail="File integrity check failed")

    logger.info(f"[ATTACHMENTS] Download: {row['original_filename']} ({attachment_id})")

    return StreamingResponse(
        io.BytesIO(file_data),
        media_type=row['mime_type'] or 'application/octet-stream',
        headers={
            'Content-Disposition': f'attachment; filename="{row["original_filename"]}"',
            'Content-Length': str(len(file_data)),
            'X-SHA256': row['sha256_hash']
        }
    )


@router.delete("/{attachment_id}")
async def delete_attachment(
    request: Request,
    attachment_id: str,
    hard_delete: bool = Query(False, description="Permanently delete (default: soft delete)"),
    authorization: str = Header(None)
):
    """
    Delete an attachment.

    By default performs a soft delete (marks as deleted but keeps file).
    Use hard_delete=true to permanently remove the file.
    """
    username = await get_current_username(request, authorization)

    from services.postgres_db import postgres_db

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow('''
            SELECT storage_path, original_filename
            FROM alert_attachments
            WHERE attachment_id = $1 AND deleted_at IS NULL
        ''', attachment_id)

        if not row:
            raise HTTPException(status_code=404, detail="Attachment not found")

        if hard_delete:
            # Delete from storage
            storage = get_file_storage()
            await storage.delete_file(row['storage_path'])

            # Delete from database
            await conn.execute(
                'DELETE FROM alert_attachments WHERE attachment_id = $1',
                attachment_id
            )
            logger.info(f"[ATTACHMENTS] Hard deleted: {row['original_filename']} by {username}")
            message = "Attachment permanently deleted"
        else:
            # Soft delete
            await conn.execute('''
                UPDATE alert_attachments
                SET deleted_at = CURRENT_TIMESTAMP
                WHERE attachment_id = $1
            ''', attachment_id)
            logger.info(f"[ATTACHMENTS] Soft deleted: {row['original_filename']} by {username}")
            message = "Attachment marked as deleted"

    return {
        "success": True,
        "attachment_id": attachment_id,
        "message": message
    }


@router.post("/{attachment_id}/analyze")
async def analyze_attachment(
    request: Request,
    attachment_id: str,
    authorization: str = Header(None)
):
    """
    Trigger analysis of an attachment.

    This will:
    1. Extract file metadata
    2. Submit hash to threat intel services
    3. Update analysis status and results
    """
    await require_admin(request, authorization)

    from services.postgres_db import postgres_db
    from services.file_metadata import get_metadata_extractor

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow('''
            SELECT alert_id, storage_path, original_filename, sha256_hash, sha1_hash, md5_hash, file_size, mime_type
            FROM alert_attachments
            WHERE attachment_id = $1 AND deleted_at IS NULL
        ''', attachment_id)

        if not row:
            raise HTTPException(status_code=404, detail="Attachment not found")

        # Update status to analyzing
        await conn.execute('''
            UPDATE alert_attachments
            SET analysis_status = 'analyzing'
            WHERE attachment_id = $1
        ''', attachment_id)

    # Get file data for analysis
    storage = get_file_storage()
    file_data = await storage.get_file(row['storage_path'])

    if not file_data:
        raise HTTPException(status_code=404, detail="File not found in storage")

    # Extract metadata
    try:
        extractor = get_metadata_extractor()
        metadata = await extractor.extract(
            file_data=file_data,
            filename=row['original_filename'],
            mime_type=row['mime_type']
        )
    except Exception as e:
        logger.error(f"[ATTACHMENTS] Metadata extraction failed: {e}")
        metadata = {"error": str(e)}

    # Check hash with threat intel
    threat_result = None
    is_malicious = None
    threat_score = None
    nested_threats = []  # Track threats found in archives/emails

    try:
        from services.threat_intel_service import get_threat_intel_service, IOCType

        threat_intel = get_threat_intel_service()

        # Check the main file hash
        hash_type = IOCType.HASH_SHA256
        hash_value = row['sha256_hash']

        report = await threat_intel.enrich_ioc(hash_value, hash_type)

        if report:
            threat_result = {
                "verdict": report.consensus_verdict.value if report.consensus_verdict else "unknown",
                "score": report.consensus_score,
                "sources_checked": report.sources_checked,
                "sources_flagged": report.sources_flagged
            }

            if report.consensus_verdict:
                is_malicious = report.consensus_verdict.value in ['malicious']
                threat_score = report.consensus_score

        # Check nested file hashes (from archives and email attachments)
        contents_to_check = []

        # Get hashes from archive contents
        if metadata.get('archive_info') and metadata['archive_info'].get('contents'):
            for content_file in metadata['archive_info']['contents']:
                if content_file.get('sha256'):
                    contents_to_check.append({
                        'name': content_file.get('name', 'unknown'),
                        'sha256': content_file['sha256'],
                        'source': 'archive'
                    })

        # Get hashes from email attachments
        if metadata.get('email_info') and metadata['email_info'].get('attachments'):
            for attachment in metadata['email_info']['attachments']:
                if attachment.get('sha256'):
                    contents_to_check.append({
                        'name': attachment.get('filename', 'unknown'),
                        'sha256': attachment['sha256'],
                        'source': 'email'
                    })

        # Check each nested file hash
        for content in contents_to_check[:20]:  # Limit to 20 files
            try:
                nested_report = await threat_intel.enrich_ioc(content['sha256'], IOCType.HASH_SHA256)
                if nested_report and nested_report.consensus_verdict:
                    nested_threat = {
                        'filename': content['name'],
                        'sha256': content['sha256'],
                        'source': content['source'],
                        'verdict': nested_report.consensus_verdict.value,
                        'score': nested_report.consensus_score
                    }
                    nested_threats.append(nested_threat)

                    # If any nested file is malicious, flag the whole attachment
                    if nested_report.consensus_verdict.value == 'malicious':
                        is_malicious = True
                        if threat_score is None or nested_report.consensus_score > threat_score:
                            threat_score = nested_report.consensus_score
                        logger.warning(f"[ATTACHMENTS] Malicious file found in archive/email: {content['name']} ({content['sha256']})")
            except Exception as nested_error:
                logger.debug(f"[ATTACHMENTS] Failed to check nested file {content['name']}: {nested_error}")

        if nested_threats:
            threat_result = threat_result or {}
            threat_result['nested_file_results'] = nested_threats
            threat_result['nested_files_checked'] = len(contents_to_check)
            threat_result['nested_threats_found'] = len([t for t in nested_threats if t['verdict'] == 'malicious'])

    except Exception as e:
        logger.warning(f"[ATTACHMENTS] Threat intel lookup failed: {e}")
        threat_result = {"error": str(e)}

    # If threat intel came back clean/unknown, submit to sandbox for dynamic analysis
    sandbox_result = None
    sandbox_submitted = False

    # Check if sandbox submission is appropriate
    should_sandbox = (
        not is_malicious and  # Not already known malicious
        threat_result and
        threat_result.get('verdict') in ['unknown', 'clean', None] and
        row['file_size'] < 32 * 1024 * 1024  # Less than 32MB (sandbox limit)
    )

    # Check for file types that should be sandboxed
    sandboxable_extensions = {
        '.exe', '.dll', '.msi', '.scr',  # Windows executables
        '.ps1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta',  # Scripts
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',  # Office docs (macros)
        '.pdf',  # PDFs can have exploits
        '.zip', '.rar', '.7z',  # Archives containing executables
        '.eml', '.msg'  # Emails with attachments
    }

    file_ext = Path(row['original_filename']).suffix.lower()
    has_dangerous_nested = (
        metadata.get('archive_info', {}).get('contains_executables') or
        any(a.get('is_dangerous') for a in metadata.get('email_info', {}).get('attachments', []))
    )

    if should_sandbox and (file_ext in sandboxable_extensions or has_dangerous_nested):
        try:
            from services.sandbox_service import get_sandbox_service, SandboxProvider

            sandbox = get_sandbox_service()
            sandbox.set_db(postgres_db)

            # Check if already analyzed in sandbox
            existing = await sandbox.check_existing_analysis(row['sha256_hash'])

            if existing and existing.get('found'):
                sandbox_result = existing
                logger.info(f"[ATTACHMENTS] Found existing sandbox analysis: {existing.get('verdict')}")

                # Update verdict if sandbox found it malicious
                if existing.get('verdict') in ['malicious', 'suspicious']:
                    is_malicious = True
                    threat_score = existing.get('threat_score') or 75
            else:
                # Submit for sandbox analysis
                submit_result = await sandbox.submit_file(
                    file_data=file_data,
                    filename=row['original_filename'],
                    sha256_hash=row['sha256_hash'],
                    alert_id=row['alert_id'],
                    attachment_id=attachment_id
                )

                if submit_result and not submit_result.get('error'):
                    sandbox_submitted = True
                    sandbox_result = submit_result
                    logger.info(f"[ATTACHMENTS] Submitted to sandbox: {submit_result.get('job_id')}")
                else:
                    logger.warning(f"[ATTACHMENTS] Sandbox submission failed: {submit_result}")

        except Exception as sandbox_error:
            logger.warning(f"[ATTACHMENTS] Sandbox integration error: {sandbox_error}")
            sandbox_result = {"error": str(sandbox_error)}

    # Build analysis result
    analysis_result = {
        "metadata": metadata,
        "threat_intel": threat_result,
        "sandbox": sandbox_result,
        "analyzed_at": datetime.utcnow().isoformat()
    }

    # Update database and send notifications
    alert_title = 'Unknown Alert'
    async with postgres_db.tenant_acquire() as conn:
        import json
        await conn.execute('''
            UPDATE alert_attachments
            SET analysis_status = 'analyzed',
                analysis_result = $2,
                is_malicious = $3,
                threat_score = $4
            WHERE attachment_id = $1
        ''', attachment_id, json.dumps(analysis_result), is_malicious, threat_score)

        # Get alert details for notification context
        alert_row = await conn.fetchrow(
            'SELECT title, severity FROM alerts WHERE alert_id = $1',
            row['alert_id']
        )
        if alert_row:
            alert_title = alert_row['title']

    logger.info(f"[ATTACHMENTS] Analysis complete: {row['original_filename']} - malicious: {is_malicious}")

    # Send notification if malicious file detected
    if is_malicious:
        try:
            from services.email_service import get_email_service
            email_service = get_email_service()
            email_service.set_db(postgres_db)

            # Build description including nested threat info
            description = f"File analysis detected malicious content in '{row['original_filename']}' attached to alert '{alert_title}'. Threat score: {threat_score or 'Unknown'}"

            if nested_threats:
                malicious_nested = [t for t in nested_threats if t['verdict'] == 'malicious']
                if malicious_nested:
                    nested_names = ', '.join([t['filename'] for t in malicious_nested[:3]])
                    description += f"\n\nMalicious files found inside: {nested_names}"
                    if len(malicious_nested) > 3:
                        description += f" (+{len(malicious_nested) - 3} more)"

            await email_service.notify_event('file_malicious_detected', {
                'alert_id': row['alert_id'],
                'attachment_id': attachment_id,
                'filename': row['original_filename'],
                'sha256_hash': row['sha256_hash'],
                'threat_score': threat_score,
                'nested_threats': len([t for t in nested_threats if t['verdict'] == 'malicious']) if nested_threats else 0,
                'title': f"Malicious file detected: {row['original_filename']}",
                'description': description,
                'severity': 'critical'  # Malicious files are always critical
            }, skip_rate_limit=True)  # Don't rate limit malicious detections
        except Exception as notify_error:
            logger.warning(f"[ATTACHMENTS] Failed to send malicious file notification: {notify_error}")

    return {
        "success": True,
        "attachment_id": attachment_id,
        "analysis_status": "analyzed",
        "analysis_result": analysis_result,
        "is_malicious": is_malicious,
        "threat_score": threat_score
    }


@router.get("/storage/stats")
async def get_storage_stats(request: Request, authorization: str = Header(None)):
    """Get file storage statistics"""
    await require_admin(request, authorization)

    storage = get_file_storage()
    stats = storage.get_storage_stats()

    from services.postgres_db import postgres_db

    async with postgres_db.tenant_acquire() as conn:
        db_stats = await conn.fetchrow('''
            SELECT
                COUNT(*) as total_attachments,
                COUNT(*) FILTER (WHERE deleted_at IS NOT NULL) as deleted_count,
                COUNT(*) FILTER (WHERE is_malicious = true) as malicious_count,
                COUNT(*) FILTER (WHERE analysis_status = 'pending') as pending_analysis,
                SUM(file_size) as total_size_bytes
            FROM alert_attachments
        ''')

        stats['database'] = {
            'total_attachments': db_stats['total_attachments'],
            'deleted_count': db_stats['deleted_count'],
            'malicious_count': db_stats['malicious_count'],
            'pending_analysis': db_stats['pending_analysis'],
            'total_size_bytes': db_stats['total_size_bytes'] or 0
        }

    return stats


# ==================== SANDBOX ENDPOINTS ====================

@router.post("/{attachment_id}/sandbox")
async def submit_to_sandbox(
    request: Request,
    attachment_id: str,
    authorization: str = Header(None)
):
    """
    Submit an attachment to sandbox for dynamic analysis.

    Use this to manually trigger sandbox analysis for a file that
    wasn't automatically submitted (e.g., if sandbox wasn't configured
    at the time of initial analysis).
    """
    await require_admin(request, authorization)

    from services.postgres_db import postgres_db
    from services.sandbox_service import get_sandbox_service

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow('''
            SELECT alert_id, storage_path, original_filename, sha256_hash, file_size
            FROM alert_attachments
            WHERE attachment_id = $1 AND deleted_at IS NULL
        ''', attachment_id)

        if not row:
            raise HTTPException(status_code=404, detail="Attachment not found")

    # Check file size limit
    if row['file_size'] > 32 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large for sandbox (max 32MB)")

    # Get file data
    storage = get_file_storage()
    file_data = await storage.get_file(row['storage_path'])

    if not file_data:
        raise HTTPException(status_code=404, detail="File not found in storage")

    # Submit to sandbox
    sandbox = get_sandbox_service()
    sandbox.set_db(postgres_db)

    result = await sandbox.submit_file(
        file_data=file_data,
        filename=row['original_filename'],
        sha256_hash=row['sha256_hash'],
        alert_id=row['alert_id'],
        attachment_id=attachment_id
    )

    if result.get('error'):
        raise HTTPException(status_code=500, detail=result['error'])

    return result


@router.get("/{attachment_id}/sandbox")
async def get_sandbox_status(
    request: Request,
    attachment_id: str,
    authorization: str = Header(None)
):
    """
    Get sandbox analysis status for an attachment.

    Returns the current status and results if analysis is complete.
    """
    await get_current_username(request, authorization)

    from services.postgres_db import postgres_db
    from services.sandbox_service import get_sandbox_service

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow('''
            SELECT sha256_hash, analysis_result
            FROM alert_attachments
            WHERE attachment_id = $1 AND deleted_at IS NULL
        ''', attachment_id)

        if not row:
            raise HTTPException(status_code=404, detail="Attachment not found")

    # Check if we have sandbox result stored
    import json
    analysis_result = row['analysis_result']
    if analysis_result:
        if isinstance(analysis_result, str):
            analysis_result = json.loads(analysis_result)
        sandbox_info = analysis_result.get('sandbox')
        if sandbox_info:
            # If we have a job_id, check for updated status
            job_id = sandbox_info.get('job_id')
            if job_id and sandbox_info.get('status') != 'completed':
                sandbox = get_sandbox_service()
                sandbox.set_db(postgres_db)
                updated_result = await sandbox.get_result(job_id)

                # Update the stored result if analysis is complete
                if updated_result.get('status') == 'completed':
                    analysis_result['sandbox'] = updated_result
                    async with postgres_db.tenant_acquire() as conn:
                        await conn.execute('''
                            UPDATE alert_attachments
                            SET analysis_result = $2
                            WHERE attachment_id = $1
                        ''', attachment_id, json.dumps(analysis_result))

                return updated_result
            return sandbox_info

    # No sandbox result stored, check by hash
    sandbox = get_sandbox_service()
    sandbox.set_db(postgres_db)

    existing = await sandbox.check_existing_analysis(row['sha256_hash'])
    if existing and existing.get('found'):
        return existing

    return {"status": "not_submitted", "message": "File has not been submitted to sandbox"}


@router.post("/{attachment_id}/sandbox/poll")
async def poll_sandbox_result(
    request: Request,
    attachment_id: str,
    timeout_seconds: int = Query(default=300, le=600),
    authorization: str = Header(None)
):
    """
    Poll for sandbox analysis completion (blocking).

    This endpoint will wait up to the specified timeout for sandbox
    analysis to complete. Use for synchronous workflows where you
    need to wait for the result.
    """
    await require_admin(request, authorization)

    from services.postgres_db import postgres_db
    from services.sandbox_service import get_sandbox_service

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow('''
            SELECT analysis_result
            FROM alert_attachments
            WHERE attachment_id = $1 AND deleted_at IS NULL
        ''', attachment_id)

        if not row:
            raise HTTPException(status_code=404, detail="Attachment not found")

    import json
    analysis_result = row['analysis_result']
    if not analysis_result:
        raise HTTPException(status_code=400, detail="No sandbox submission found for this attachment")

    if isinstance(analysis_result, str):
        analysis_result = json.loads(analysis_result)

    sandbox_info = analysis_result.get('sandbox')
    if not sandbox_info or not sandbox_info.get('job_id'):
        raise HTTPException(status_code=400, detail="No sandbox job ID found")

    job_id = sandbox_info['job_id']

    # Poll for result
    sandbox = get_sandbox_service()
    sandbox.set_db(postgres_db)

    result = await sandbox.poll_result(
        job_id=job_id,
        max_wait_seconds=timeout_seconds,
        poll_interval_seconds=15
    )

    # Update stored result if completed
    if result.get('status') in ['completed', 'error']:
        analysis_result['sandbox'] = result
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute('''
                UPDATE alert_attachments
                SET analysis_result = $2,
                    is_malicious = CASE WHEN $3 THEN true ELSE is_malicious END,
                    threat_score = CASE WHEN $4 IS NOT NULL THEN $4 ELSE threat_score END
                WHERE attachment_id = $1
            ''', attachment_id, json.dumps(analysis_result),
                result.get('verdict') in ['malicious', 'suspicious'],
                result.get('threat_score'))

    return result
