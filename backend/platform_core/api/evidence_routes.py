# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Evidence/Files API Routes

API endpoints for file upload, download, and attachment management.
"""

from typing import Optional, List
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File as FastAPIFile, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

from ..rbac import (
    RequestContext, get_request_context, 
    PermissionChecker, require_permissions
)
from ..database import EntityType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/files", tags=["Evidence"])


# Request/Response Models
class FileUploadResponse(BaseModel):
    file_id: UUID
    filename: str
    size_bytes: int
    sha256: str
    content_type: str


class FileMetadataResponse(BaseModel):
    id: UUID
    filename: str
    original_filename: Optional[str]
    content_type: str
    size_bytes: int
    sha256: str
    status: str
    uploaded_at: str
    uploaded_by: Optional[UUID]
    classification: Optional[str]
    tags: List[str]


class AttachmentRequest(BaseModel):
    file_id: UUID
    entity_type: str  # investigation, alert, note, action_result
    entity_id: UUID
    description: Optional[str] = None
    attachment_type: Optional[str] = None


class AttachmentResponse(BaseModel):
    id: UUID
    file_id: UUID
    entity_type: str
    entity_id: UUID
    description: Optional[str]
    created_at: str


# Routes
@router.post(
    "/upload",
    response_model=FileUploadResponse,
    summary="Upload a file",
    description="Upload a file to evidence storage. Returns file metadata including SHA256 hash."
)
async def upload_file(
    file: UploadFile = FastAPIFile(...),
    classification: Optional[str] = Query(None, description="Security classification"),
    tags: Optional[str] = Query(None, description="Comma-separated tags"),
    entity_type: Optional[str] = Query(None, description="Entity type to attach to"),
    entity_id: Optional[UUID] = Query(None, description="Entity ID to attach to"),
    ctx: RequestContext = Depends(PermissionChecker(['file:upload'])),
):
    """
    Upload a file to the evidence storage system.
    
    Files are stored immutably with SHA256 hash verification.
    Optionally attach to an entity (investigation, alert, etc.) during upload.
    """
    from ..evidence import EvidenceService, StorageConfig
    from ..database import get_async_session
    
    async with get_async_session() as db:
        # Parse tags
        tag_list = [t.strip() for t in tags.split(',')] if tags else None
        
        # Create service
        config = StorageConfig()  # Load from env in production
        service = EvidenceService(config, db, ctx)
        
        # Upload
        file_id, sha256 = await service.upload_file(
            file_data=file.file,
            filename=file.filename,
            content_type=file.content_type,
            classification=classification,
            tags=tag_list,
            entity_type=entity_type,
            entity_id=entity_id,
        )
        
        return FileUploadResponse(
            file_id=file_id,
            filename=file.filename,
            size_bytes=file.size,
            sha256=sha256,
            content_type=file.content_type or 'application/octet-stream',
        )


@router.get(
    "/{file_id}",
    response_model=FileMetadataResponse,
    summary="Get file metadata",
    description="Get metadata for a file without downloading it."
)
async def get_file_metadata(
    file_id: UUID,
    ctx: RequestContext = Depends(PermissionChecker(['file:read'])),
):
    """Get file metadata by ID."""
    from ..evidence import EvidenceService, StorageConfig
    from ..database import get_async_session
    
    async with get_async_session() as db:
        config = StorageConfig()
        service = EvidenceService(config, db, ctx)
        
        file_record = await service.get_file(file_id)
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
        
        return FileMetadataResponse(
            id=file_record.id,
            filename=file_record.filename,
            original_filename=file_record.original_filename,
            content_type=file_record.content_type,
            size_bytes=file_record.size_bytes,
            sha256=file_record.sha256,
            status=file_record.status,
            uploaded_at=file_record.uploaded_at.isoformat(),
            uploaded_by=file_record.uploaded_by,
            classification=file_record.classification,
            tags=file_record.tags or [],
        )


@router.get(
    "/{file_id}/download",
    summary="Download a file",
    description="Get a presigned URL or redirect to download the file."
)
async def download_file(
    file_id: UUID,
    redirect: bool = Query(True, description="If true, redirect to download URL"),
    ctx: RequestContext = Depends(PermissionChecker(['file:download'])),
):
    """
    Get a download URL for a file.
    
    If redirect=True, returns a 302 redirect to the presigned URL.
    If redirect=False, returns the URL in the response body.
    """
    from ..evidence import EvidenceService, StorageConfig
    from ..database import get_async_session
    
    async with get_async_session() as db:
        config = StorageConfig()
        service = EvidenceService(config, db, ctx)
        
        url = await service.get_download_url(file_id)
        if not url:
            raise HTTPException(status_code=404, detail="File not found")
        
        if redirect:
            return RedirectResponse(url=url, status_code=302)
        else:
            return {"download_url": url}


@router.delete(
    "/{file_id}",
    summary="Delete a file",
    description="Soft-delete a file (admin only)."
)
async def delete_file(
    file_id: UUID,
    reason: Optional[str] = Query(None, description="Reason for deletion"),
    ctx: RequestContext = Depends(PermissionChecker(['file:delete'])),
):
    """
    Soft-delete a file.
    
    The file is marked as deleted but not removed from storage until
    retention cleanup runs. Requires admin permissions.
    """
    from ..evidence import EvidenceService, StorageConfig
    from ..database import get_async_session
    
    async with get_async_session() as db:
        config = StorageConfig()
        service = EvidenceService(config, db, ctx)
        
        success = await service.delete_file(file_id, reason)
        if not success:
            raise HTTPException(status_code=404, detail="File not found")
        
        return {"status": "deleted", "file_id": str(file_id)}


@router.post(
    "/attachments",
    response_model=AttachmentResponse,
    summary="Attach a file to an entity",
    description="Link an existing file to an investigation, alert, note, or action result."
)
async def create_attachment(
    request: AttachmentRequest,
    ctx: RequestContext = Depends(PermissionChecker(['file:read'])),
):
    """
    Attach a file to an entity.
    
    A file can be attached to multiple entities. This creates a link,
    not a copy.
    """
    from ..evidence import EvidenceService, StorageConfig
    from ..database import get_async_session
    
    # Validate entity type
    valid_types = [EntityType.INVESTIGATION, EntityType.ALERT, EntityType.NOTE, EntityType.ACTION_RESULT]
    if request.entity_type not in valid_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid entity_type. Must be one of: {valid_types}"
        )
    
    async with get_async_session() as db:
        config = StorageConfig()
        service = EvidenceService(config, db, ctx)
        
        try:
            attachment_id = await service.attach_file(
                file_id=request.file_id,
                entity_type=request.entity_type,
                entity_id=request.entity_id,
                description=request.description,
                attachment_type=request.attachment_type,
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e))
        
        return AttachmentResponse(
            id=attachment_id,
            file_id=request.file_id,
            entity_type=request.entity_type,
            entity_id=request.entity_id,
            description=request.description,
            created_at=datetime.utcnow().isoformat(),
        )


@router.get(
    "/attachments/{entity_type}/{entity_id}",
    response_model=List[FileMetadataResponse],
    summary="Get attachments for an entity",
    description="List all files attached to an entity."
)
async def get_entity_attachments(
    entity_type: str,
    entity_id: UUID,
    ctx: RequestContext = Depends(PermissionChecker(['file:read'])),
):
    """Get all file attachments for an entity."""
    from ..evidence import EvidenceService, StorageConfig
    from ..database import get_async_session
    from datetime import datetime
    
    async with get_async_session() as db:
        config = StorageConfig()
        service = EvidenceService(config, db, ctx)
        
        attachments = await service.get_attachments(entity_type, entity_id)
        
        return [
            FileMetadataResponse(
                id=file.id,
                filename=file.filename,
                original_filename=file.original_filename,
                content_type=file.content_type,
                size_bytes=file.size_bytes,
                sha256=file.sha256,
                status=file.status,
                uploaded_at=file.uploaded_at.isoformat(),
                uploaded_by=file.uploaded_by,
                classification=file.classification,
                tags=file.tags or [],
            )
            for attachment, file in attachments
        ]
