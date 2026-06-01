# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Investigation Notes API

Endpoints for managing investigation notes and file attachments.
Supports CRUD operations on notes and file uploads for embedding in notes.
"""

from fastapi import APIRouter, HTTPException, Request, UploadFile, File, Form, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict
from datetime import datetime
import io
import logging
import uuid

from dependencies.auth import get_current_user
from middleware.tenant_middleware import get_optional_tenant_id
from services.postgres_db import postgres_db
from services.file_storage import get_file_storage

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/investigations",
    tags=["Investigation Notes"],
    dependencies=[Depends(get_current_user)]
)


# ==================== MODELS ====================

class NoteCreate(BaseModel):
    """Request body for creating a note."""
    content: str = Field(..., min_length=1)
    title: Optional[str] = None


class NoteUpdate(BaseModel):
    """Request body for updating a note."""
    content: Optional[str] = None
    title: Optional[str] = None


class NoteResponse(BaseModel):
    """Single note response."""
    id: str
    investigation_id: str
    note_type: str
    author: str
    author_type: str
    title: Optional[str] = None
    content: str
    confidence: Optional[float] = None
    severity: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: str
    updated_at: Optional[str] = None


class NoteListResponse(BaseModel):
    """List of notes response."""
    investigation_id: str
    notes: List[NoteResponse]
    total_count: int


class AttachmentUploadResponse(BaseModel):
    """Upload success response."""
    success: bool
    attachment_id: str
    filename: str
    file_size: int
    mime_type: str
    download_url: str


# ==================== HELPERS ====================

def _format_note(row) -> NoteResponse:
    """Format a database row into a NoteResponse."""
    metadata = row['metadata']
    if isinstance(metadata, str):
        import json
        try:
            metadata = json.loads(metadata)
        except (json.JSONDecodeError, TypeError):
            metadata = None

    return NoteResponse(
        id=str(row['id']),
        investigation_id=str(row['investigation_id']),
        note_type=row['note_type'],
        author=row['author'],
        author_type=row['author_type'],
        title=row['title'],
        content=row['content'],
        confidence=float(row['confidence']) if row['confidence'] is not None else None,
        severity=row['severity'],
        metadata=metadata,
        created_at=row['created_at'].isoformat() if row['created_at'] else None,
        updated_at=row['updated_at'].isoformat() if row['updated_at'] else None,
    )


# ==================== ENDPOINTS ====================

@router.get("/{investigation_id}/notes", response_model=NoteListResponse)
async def list_notes(request: Request, investigation_id: str):
    """
    List all notes for an investigation.

    Returns notes ordered by most recent first, excluding soft-deleted notes.
    """
    async with postgres_db.tenant_acquire() as conn:
        rows = await conn.fetch('''
            SELECT id, investigation_id, note_type, author, author_type,
                   title, content, confidence, severity, metadata,
                   created_at, updated_at
            FROM investigation_notes
            WHERE investigation_id = $1 AND deleted_at IS NULL
            ORDER BY created_at DESC
        ''', investigation_id)

    notes = [_format_note(row) for row in rows]

    return NoteListResponse(
        investigation_id=investigation_id,
        notes=notes,
        total_count=len(notes)
    )


@router.post("/{investigation_id}/notes", response_model=NoteResponse, status_code=201)
async def create_note(
    request: Request,
    investigation_id: str,
    body: NoteCreate
):
    """
    Create a new human note on an investigation.
    """
    user = request.state.user if hasattr(request.state, 'user') else None
    username = user.get('username', 'unknown') if user else 'unknown'

    note_id = str(uuid.uuid4())

    async with postgres_db.tenant_acquire() as conn:
        # Verify investigation exists
        inv = await conn.fetchrow(
            'SELECT investigation_id FROM investigations WHERE investigation_id = $1',
            investigation_id
        )
        if not inv:
            raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")

        row = await conn.fetchrow('''
            INSERT INTO investigation_notes (
                id, investigation_id, note_type, author, author_type,
                title, content, metadata, created_at, updated_at
            ) VALUES ($1, $2, 'HUMAN_NOTE', $3, 'HUMAN', $4, $5, '{}'::jsonb, NOW(), NOW())
            RETURNING id, investigation_id, note_type, author, author_type,
                      title, content, confidence, severity, metadata,
                      created_at, updated_at
        ''', note_id, investigation_id, username, body.title, body.content)

    logger.info(f"[INVESTIGATION_NOTES] Created note {note_id} on investigation {investigation_id} by {username}")
    return _format_note(row)


@router.patch("/{investigation_id}/notes/{note_id}", response_model=NoteResponse)
async def update_note(
    request: Request,
    investigation_id: str,
    note_id: str,
    body: NoteUpdate
):
    """
    Update a note's content or title. Only the original author can edit.
    """
    user = request.state.user if hasattr(request.state, 'user') else None
    username = user.get('username', 'unknown') if user else 'unknown'

    if body.content is None and body.title is None:
        raise HTTPException(status_code=400, detail="At least one of content or title must be provided")

    async with postgres_db.tenant_acquire() as conn:
        # Fetch existing note and verify ownership
        existing = await conn.fetchrow('''
            SELECT id, author FROM investigation_notes
            WHERE id = $1::uuid AND investigation_id = $2 AND deleted_at IS NULL
        ''', uuid.UUID(note_id), investigation_id)

        if not existing:
            raise HTTPException(status_code=404, detail="Note not found")

        if existing['author'] != username:
            raise HTTPException(status_code=403, detail="You can only edit your own notes")

        # Build dynamic update
        set_clauses = ["updated_at = NOW()"]
        params = []
        param_idx = 1

        if body.content is not None:
            set_clauses.append(f"content = ${param_idx}")
            params.append(body.content)
            param_idx += 1

        if body.title is not None:
            set_clauses.append(f"title = ${param_idx}")
            params.append(body.title)
            param_idx += 1

        params.append(uuid.UUID(note_id))
        params.append(investigation_id)

        row = await conn.fetchrow(f'''
            UPDATE investigation_notes
            SET {', '.join(set_clauses)}
            WHERE id = ${param_idx}::uuid AND investigation_id = ${param_idx + 1}
            RETURNING id, investigation_id, note_type, author, author_type,
                      title, content, confidence, severity, metadata,
                      created_at, updated_at
        ''', *params)

    logger.info(f"[INVESTIGATION_NOTES] Updated note {note_id} by {username}")
    return _format_note(row)


@router.delete("/{investigation_id}/notes/{note_id}")
async def delete_note(
    request: Request,
    investigation_id: str,
    note_id: str
):
    """
    Soft-delete a note. Only the original author can delete.
    """
    user = request.state.user if hasattr(request.state, 'user') else None
    username = user.get('username', 'unknown') if user else 'unknown'

    async with postgres_db.tenant_acquire() as conn:
        existing = await conn.fetchrow('''
            SELECT id, author FROM investigation_notes
            WHERE id = $1::uuid AND investigation_id = $2 AND deleted_at IS NULL
        ''', uuid.UUID(note_id), investigation_id)

        if not existing:
            raise HTTPException(status_code=404, detail="Note not found")

        if existing['author'] != username:
            raise HTTPException(status_code=403, detail="You can only delete your own notes")

        await conn.execute('''
            UPDATE investigation_notes
            SET deleted_at = NOW(), deleted_by = $1
            WHERE id = $2::uuid AND investigation_id = $3
        ''', username, uuid.UUID(note_id), investigation_id)

    logger.info(f"[INVESTIGATION_NOTES] Soft-deleted note {note_id} by {username}")
    return {"success": True, "message": "Note deleted"}


@router.post("/{investigation_id}/notes/upload", response_model=AttachmentUploadResponse)
async def upload_note_attachment(
    request: Request,
    investigation_id: str,
    file: UploadFile = File(..., description="File to upload for embedding in notes"),
    description: str = Form(None, description="Optional file description")
):
    """
    Upload a file attachment for embedding in investigation notes.

    Supports images and documents. Returns a download URL that can be
    referenced in note content.
    """
    user = request.state.user if hasattr(request.state, 'user') else None
    username = user.get('username', 'unknown') if user else 'unknown'

    # Read file data
    try:
        file_data = await file.read()
    except Exception as e:
        logger.error(f"[INVESTIGATION_NOTES] Failed to read uploaded file: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

    # Verify investigation exists
    async with postgres_db.tenant_acquire() as conn:
        inv = await conn.fetchrow(
            'SELECT investigation_id FROM investigations WHERE investigation_id = $1',
            investigation_id
        )
        if not inv:
            raise HTTPException(status_code=404, detail=f"Investigation {investigation_id} not found")

    # Store file using existing file storage service
    storage = get_file_storage()
    try:
        stored_file = await storage.store_file(
            file_data=file_data,
            original_filename=file.filename,
            alert_id=investigation_id,  # Reuse alert_id param for storage path organization
            uploaded_by=username,
            description=description
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"[INVESTIGATION_NOTES] Failed to store file: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to store file: {str(e)}")

    # Save attachment record to database with investigation_id
    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute('''
                INSERT INTO alert_attachments (
                    attachment_id, alert_id, investigation_id,
                    filename, original_filename,
                    file_size, mime_type, storage_path, storage_type,
                    md5_hash, sha1_hash, sha256_hash,
                    description, uploaded_by, analysis_status, tenant_id
                ) VALUES ($1, NULL, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            ''',
                stored_file.attachment_id,
                investigation_id,
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
                'complete',
                get_optional_tenant_id()
            )
    except Exception as e:
        logger.error(f"[INVESTIGATION_NOTES] Failed to save attachment record: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save attachment: {str(e)}")

    download_url = f"/api/v1/investigations/{investigation_id}/notes/attachments/{stored_file.attachment_id}/download"

    logger.info(
        f"[INVESTIGATION_NOTES] Uploaded {stored_file.original_filename} "
        f"to investigation {investigation_id} by {username}"
    )

    return AttachmentUploadResponse(
        success=True,
        attachment_id=stored_file.attachment_id,
        filename=stored_file.original_filename,
        file_size=stored_file.file_size,
        mime_type=stored_file.mime_type,
        download_url=download_url
    )


@router.get("/{investigation_id}/notes/attachments/{attachment_id}/download")
async def download_note_attachment(
    request: Request,
    investigation_id: str,
    attachment_id: str
):
    """
    Download an attachment file with correct Content-Type for inline rendering.
    """
    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow('''
            SELECT storage_path, original_filename, mime_type, sha256_hash
            FROM alert_attachments
            WHERE attachment_id = $1 AND investigation_id = $2 AND deleted_at IS NULL
        ''', attachment_id, investigation_id)

    if not row:
        raise HTTPException(status_code=404, detail="Attachment not found")

    storage = get_file_storage()
    file_data = await storage.get_file(row['storage_path'])

    if not file_data:
        raise HTTPException(status_code=404, detail="File not found in storage")

    mime_type = row['mime_type'] or 'application/octet-stream'

    # Use inline disposition for images and PDFs so they render in-browser
    disposition = 'inline' if mime_type.startswith(('image/', 'application/pdf')) else 'attachment'

    logger.info(f"[INVESTIGATION_NOTES] Download: {row['original_filename']} ({attachment_id})")

    return StreamingResponse(
        io.BytesIO(file_data),
        media_type=mime_type,
        headers={
            'Content-Disposition': f'{disposition}; filename="{row["original_filename"]}"',
            'Content-Length': str(len(file_data)),
            'X-SHA256': row['sha256_hash']
        }
    )
