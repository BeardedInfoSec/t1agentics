# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Evidence/File Service

Handles file uploads, downloads, and storage in S3-compatible storage.
Files are immutable - new upload = new record.
"""

import hashlib
import mimetypes
from datetime import datetime, timedelta
from typing import Optional, Tuple, BinaryIO
from uuid import UUID, uuid4
from pathlib import Path
import logging

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..database import (
    File, Attachment, FileStatus, EntityType,
    generate_uuid
)
from ..rbac import RequestContext, check_tenant_access, tenant_filter
from ..audit import AuditLogger, AuditAction

logger = logging.getLogger(__name__)


class StorageConfig:
    """Configuration for S3-compatible storage."""
    
    def __init__(
        self,
        provider: str = 's3',  # s3, minio
        endpoint_url: Optional[str] = None,  # For MinIO
        bucket: str = 'T1 Agentics-evidence',
        region: str = 'us-east-1',
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        presigned_url_expiry: int = 3600,  # seconds
    ):
        self.provider = provider
        self.endpoint_url = endpoint_url
        self.bucket = bucket
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.presigned_url_expiry = presigned_url_expiry


class EvidenceService:
    """
    Service for managing evidence/file uploads and downloads.
    
    Files are stored in S3-compatible storage with metadata in PostgreSQL.
    Files are immutable - once uploaded, they cannot be modified.
    """
    
    def __init__(self, config: StorageConfig, db: AsyncSession, ctx: RequestContext):
        self.config = config
        self.db = db
        self.ctx = ctx
        self.audit = AuditLogger(db, ctx)
        
        # Initialize S3 client
        boto_config = BotoConfig(signature_version='s3v4')
        client_kwargs = {
            'config': boto_config,
            'region_name': config.region,
        }
        
        if config.endpoint_url:
            client_kwargs['endpoint_url'] = config.endpoint_url
        if config.access_key and config.secret_key:
            client_kwargs['aws_access_key_id'] = config.access_key
            client_kwargs['aws_secret_access_key'] = config.secret_key
        
        self.s3_client = boto3.client('s3', **client_kwargs)
    
    async def upload_file(
        self,
        file_data: BinaryIO,
        filename: str,
        content_type: Optional[str] = None,
        classification: Optional[str] = None,
        tags: Optional[list] = None,
        entity_type: Optional[str] = None,
        entity_id: Optional[UUID] = None,
    ) -> Tuple[UUID, str]:
        """
        Upload a file to storage.
        
        Args:
            file_data: File content as binary stream
            filename: Original filename
            content_type: MIME type (auto-detected if not provided)
            classification: Security classification
            tags: Tags for the file
            entity_type: If provided, automatically attach to this entity
            entity_id: ID of the entity to attach to
            
        Returns:
            Tuple of (file_id, sha256_hash)
        """
        tenant_id = self.ctx.tenant.tenant_id
        file_id = uuid4()
        
        # Read file content and compute hash
        content = file_data.read()
        sha256 = hashlib.sha256(content).hexdigest()
        md5 = hashlib.md5(content).hexdigest()
        size_bytes = len(content)
        
        # Auto-detect content type if not provided
        if not content_type:
            content_type, _ = mimetypes.guess_type(filename)
            content_type = content_type or 'application/octet-stream'
        
        # Sanitize filename
        safe_filename = self._sanitize_filename(filename)
        
        # Build storage key: tenant_id/year/month/file_id/filename
        now = datetime.utcnow()
        storage_key = f"{tenant_id}/{now.year}/{now.month:02d}/{file_id}/{safe_filename}"
        
        # Upload to S3
        try:
            self.s3_client.put_object(
                Bucket=self.config.bucket,
                Key=storage_key,
                Body=content,
                ContentType=content_type,
                Metadata={
                    'tenant_id': str(tenant_id),
                    'file_id': str(file_id),
                    'sha256': sha256,
                    'original_filename': filename,
                }
            )
        except ClientError as e:
            logger.error(f"Failed to upload file to S3: {e}")
            raise
        
        # Create file record
        file_record = File(
            id=file_id,
            tenant_id=tenant_id,
            filename=safe_filename,
            original_filename=filename,
            content_type=content_type,
            size_bytes=size_bytes,
            sha256=sha256,
            md5=md5,
            storage_provider=self.config.provider,
            storage_bucket=self.config.bucket,
            storage_key=storage_key,
            storage_region=self.config.region,
            status=FileStatus.ACTIVE,
            uploaded_by=self.ctx.user.user_id if self.ctx.user else None,
            uploaded_at=now,
            upload_source='api',
            classification=classification,
            tags=tags or [],
        )
        
        self.db.add(file_record)
        
        # Create attachment if entity provided
        if entity_type and entity_id:
            attachment = Attachment(
                tenant_id=tenant_id,
                file_id=file_id,
                entity_type=entity_type,
                entity_id=entity_id,
                created_by=self.ctx.user.user_id if self.ctx.user else None,
            )
            self.db.add(attachment)
        
        # Audit log
        await self.audit.log(
            action=AuditAction.FILE_UPLOADED,
            resource_type='file',
            resource_id=file_id,
            resource_display=filename,
            summary=f"Uploaded file: {filename} ({size_bytes} bytes)",
            after={
                'filename': filename,
                'size_bytes': size_bytes,
                'content_type': content_type,
                'sha256': sha256,
            }
        )
        
        await self.db.commit()
        
        return file_id, sha256
    
    async def get_file(self, file_id: UUID) -> Optional[File]:
        """Get file metadata by ID."""
        result = await self.db.execute(
            select(File).where(
                and_(
                    tenant_filter(File, self.ctx.tenant.tenant_id),
                    File.id == file_id,
                    File.status == FileStatus.ACTIVE,
                )
            )
        )
        return result.scalar_one_or_none()
    
    async def get_download_url(self, file_id: UUID, expires_in: Optional[int] = None) -> Optional[str]:
        """
        Get a presigned download URL for a file.
        
        Args:
            file_id: ID of the file
            expires_in: URL expiry in seconds (default from config)
            
        Returns:
            Presigned URL or None if file not found
        """
        file_record = await self.get_file(file_id)
        if not file_record:
            return None
        
        # Generate presigned URL
        expiry = expires_in or self.config.presigned_url_expiry
        
        try:
            url = self.s3_client.generate_presigned_url(
                'get_object',
                Params={
                    'Bucket': file_record.storage_bucket,
                    'Key': file_record.storage_key,
                    'ResponseContentDisposition': f'attachment; filename="{file_record.original_filename or file_record.filename}"',
                },
                ExpiresIn=expiry,
            )
        except ClientError as e:
            logger.error(f"Failed to generate presigned URL: {e}")
            return None
        
        # Audit the download
        await self.audit.log(
            action=AuditAction.FILE_DOWNLOADED,
            resource_type='file',
            resource_id=file_id,
            resource_display=file_record.filename,
            summary=f"Generated download URL for: {file_record.filename}",
        )
        await self.db.commit()
        
        return url
    
    async def delete_file(self, file_id: UUID, reason: Optional[str] = None) -> bool:
        """
        Soft-delete a file (admin only).
        
        The file is marked as deleted but not removed from storage until
        retention cleanup runs.
        """
        file_record = await self.get_file(file_id)
        if not file_record:
            return False
        
        # Mark as deleted
        file_record.status = FileStatus.DELETED
        
        # Audit log
        await self.audit.log(
            action=AuditAction.FILE_DELETED,
            resource_type='file',
            resource_id=file_id,
            resource_display=file_record.filename,
            summary=f"Deleted file: {file_record.filename}",
            metadata={'reason': reason} if reason else None,
        )
        
        await self.db.commit()
        return True
    
    async def attach_file(
        self,
        file_id: UUID,
        entity_type: str,
        entity_id: UUID,
        description: Optional[str] = None,
        attachment_type: Optional[str] = None,
    ) -> UUID:
        """
        Attach a file to an entity (investigation, alert, note, etc.).
        
        Returns the attachment ID.
        """
        tenant_id = self.ctx.tenant.tenant_id
        
        # Verify file exists
        file_record = await self.get_file(file_id)
        if not file_record:
            raise ValueError(f"File {file_id} not found")
        
        # Create attachment
        attachment_id = uuid4()
        attachment = Attachment(
            id=attachment_id,
            tenant_id=tenant_id,
            file_id=file_id,
            entity_type=entity_type,
            entity_id=entity_id,
            description=description,
            attachment_type=attachment_type,
            created_by=self.ctx.user.user_id if self.ctx.user else None,
        )
        
        self.db.add(attachment)
        
        # Audit log
        await self.audit.log(
            action=AuditAction.FILE_ATTACHED,
            resource_type='attachment',
            resource_id=attachment_id,
            summary=f"Attached {file_record.filename} to {entity_type}:{entity_id}",
            after={
                'file_id': str(file_id),
                'entity_type': entity_type,
                'entity_id': str(entity_id),
            }
        )
        
        await self.db.commit()
        return attachment_id
    
    async def get_attachments(
        self,
        entity_type: str,
        entity_id: UUID,
    ) -> list:
        """Get all attachments for an entity."""
        result = await self.db.execute(
            select(Attachment, File)
            .join(File)
            .where(
                and_(
                    tenant_filter(Attachment, self.ctx.tenant.tenant_id),
                    Attachment.entity_type == entity_type,
                    Attachment.entity_id == entity_id,
                    File.status == FileStatus.ACTIVE,
                )
            )
        )
        return result.all()
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for storage."""
        # Remove path components
        name = Path(filename).name
        # Replace dangerous characters
        for char in ['/', '\\', '\0', '..']:
            name = name.replace(char, '_')
        # Limit length
        if len(name) > 255:
            name = name[:255]
        return name
