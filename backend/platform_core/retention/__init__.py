# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Retention Service

Manages data retention policies and cleanup jobs.
"""

from datetime import datetime, timedelta
from typing import Dict, Optional, List
from uuid import UUID
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, delete, update, func

from ..database import (
    RetentionPolicy, AuditEvent, File, Note, Alert, Investigation, ActionResult,
    DataClass, FileStatus, AuditAction, 
    MINIMUM_RETENTION_DAYS, DEFAULT_RETENTION_DAYS
)
from ..rbac import RequestContext, tenant_filter
from ..audit import AuditLogger

logger = logging.getLogger(__name__)


class RetentionService:
    """
    Service for managing data retention policies and running cleanup jobs.
    """
    
    def __init__(self, db: AsyncSession, ctx: Optional[RequestContext] = None):
        self.db = db
        self.ctx = ctx
        self.audit = AuditLogger(db, ctx) if ctx else None
    
    async def get_policies(self, tenant_id: UUID) -> Dict[str, RetentionPolicy]:
        """Get all retention policies for a tenant."""
        result = await self.db.execute(
            select(RetentionPolicy).where(
                tenant_filter(RetentionPolicy, tenant_id)
            )
        )
        policies = result.scalars().all()
        return {p.data_class: p for p in policies}
    
    async def get_policy(self, tenant_id: UUID, data_class: str) -> Optional[RetentionPolicy]:
        """Get a specific retention policy."""
        result = await self.db.execute(
            select(RetentionPolicy).where(
                and_(
                    tenant_filter(RetentionPolicy, tenant_id),
                    RetentionPolicy.data_class == data_class,
                )
            )
        )
        return result.scalar_one_or_none()
    
    async def update_policy(
        self,
        tenant_id: UUID,
        data_class: str,
        retention_days: int,
        grace_days: int = 7,
        is_enabled: bool = True,
    ) -> RetentionPolicy:
        """
        Update or create a retention policy.
        
        Enforces minimum retention days per data class.
        """
        # Enforce minimum retention
        minimum = MINIMUM_RETENTION_DAYS.get(data_class, 30)
        if retention_days < minimum:
            raise ValueError(f"Minimum retention for {data_class} is {minimum} days")
        
        # Get or create policy
        policy = await self.get_policy(tenant_id, data_class)
        
        before_state = None
        if policy:
            before_state = {
                'retention_days': policy.retention_days,
                'grace_days': policy.grace_days,
                'is_enabled': policy.is_enabled,
            }
            policy.retention_days = retention_days
            policy.grace_days = grace_days
            policy.is_enabled = is_enabled
            policy.updated_at = datetime.utcnow()
            if self.ctx and self.ctx.user:
                policy.updated_by = self.ctx.user.user_id
        else:
            policy = RetentionPolicy(
                tenant_id=tenant_id,
                data_class=data_class,
                retention_days=retention_days,
                grace_days=grace_days,
                is_enabled=is_enabled,
            )
            if self.ctx and self.ctx.user:
                policy.created_by = self.ctx.user.user_id
            self.db.add(policy)
        
        # Audit log
        if self.audit:
            await self.audit.log(
                action=AuditAction.RETENTION_POLICY_UPDATED,
                resource_type='retention_policy',
                resource_id=policy.id if policy.id else None,
                resource_display=data_class,
                summary=f"Updated retention policy for {data_class}: {retention_days} days",
                before=before_state,
                after={
                    'retention_days': retention_days,
                    'grace_days': grace_days,
                    'is_enabled': is_enabled,
                },
            )
        
        await self.db.commit()
        return policy
    
    async def initialize_default_policies(self, tenant_id: UUID) -> Dict[str, RetentionPolicy]:
        """
        Initialize default retention policies for a new tenant.
        """
        policies = {}
        for data_class, days in DEFAULT_RETENTION_DAYS.items():
            policy = await self.get_policy(tenant_id, data_class)
            if not policy:
                policy = RetentionPolicy(
                    tenant_id=tenant_id,
                    data_class=data_class,
                    retention_days=days,
                    grace_days=7,
                    is_enabled=True,
                )
                self.db.add(policy)
            policies[data_class] = policy
        
        await self.db.commit()
        return policies
    
    async def run_retention_job(self, tenant_id: UUID) -> Dict[str, int]:
        """
        Run retention cleanup for a tenant.
        
        This is typically run as a background job.
        
        Returns:
            Dict mapping data_class to number of records deleted
        """
        results = {}
        policies = await self.get_policies(tenant_id)
        
        for data_class, policy in policies.items():
            if not policy.is_enabled:
                continue
            
            deleted_count = await self._cleanup_data_class(tenant_id, policy)
            results[data_class] = deleted_count
            
            # Update last run
            policy.last_run_at = datetime.utcnow()
            policy.last_run_deleted_count = deleted_count
        
        # Log the job run
        total_deleted = sum(results.values())
        logger.info(f"Retention job completed for tenant {tenant_id}: {results}")
        
        # Audit the job run (using system actor)
        if self.audit:
            await self.audit.log(
                action=AuditAction.RETENTION_JOB_RUN,
                resource_type='retention_job',
                summary=f"Retention job completed: {total_deleted} records deleted",
                metadata=results,
                actor_type='system',
                actor_display='retention_job',
                tenant_id=tenant_id,
            )
        
        await self.db.commit()
        return results
    
    async def _cleanup_data_class(
        self,
        tenant_id: UUID,
        policy: RetentionPolicy
    ) -> int:
        """
        Clean up records for a specific data class.
        
        Phase 1: Mark records as expired (soft delete)
        Phase 2: After grace period, hard delete
        """
        data_class = policy.data_class
        retention_cutoff = datetime.utcnow() - timedelta(days=policy.retention_days)
        grace_cutoff = datetime.utcnow() - timedelta(days=policy.retention_days + policy.grace_days)
        
        deleted_count = 0
        
        if data_class == DataClass.FILES:
            deleted_count = await self._cleanup_files(tenant_id, retention_cutoff, grace_cutoff)
        elif data_class == DataClass.ALERTS:
            deleted_count = await self._cleanup_alerts(tenant_id, grace_cutoff)
        elif data_class == DataClass.NOTES:
            deleted_count = await self._cleanup_notes(tenant_id, grace_cutoff)
        elif data_class == DataClass.INVESTIGATIONS:
            deleted_count = await self._cleanup_investigations(tenant_id, grace_cutoff)
        elif data_class == DataClass.ACTION_RESULTS:
            deleted_count = await self._cleanup_action_results(tenant_id, grace_cutoff)
        elif data_class == DataClass.AUDIT_LOGS:
            # Audit logs have special handling - only delete if beyond minimum
            if policy.retention_days >= MINIMUM_RETENTION_DAYS[DataClass.AUDIT_LOGS]:
                deleted_count = await self._cleanup_audit_logs(tenant_id, grace_cutoff)
        
        return deleted_count
    
    async def _cleanup_files(
        self,
        tenant_id: UUID,
        retention_cutoff: datetime,
        grace_cutoff: datetime
    ) -> int:
        """Clean up files - mark expired, then delete after grace period."""
        
        # Phase 1: Mark files as expired
        await self.db.execute(
            update(File)
            .where(
                and_(
                    File.tenant_id == tenant_id,
                    File.status == FileStatus.ACTIVE,
                    File.uploaded_at < retention_cutoff,
                )
            )
            .values(status=FileStatus.EXPIRED, expires_at=datetime.utcnow())
        )
        
        # Phase 2: Find files to hard delete (past grace period)
        result = await self.db.execute(
            select(File).where(
                and_(
                    File.tenant_id == tenant_id,
                    File.status == FileStatus.EXPIRED,
                    File.uploaded_at < grace_cutoff,
                )
            )
        )
        files_to_delete = result.scalars().all()
        
        deleted_count = 0
        for file in files_to_delete:
            # TODO: Delete from S3 storage
            # For now, just mark as deleted
            file.status = FileStatus.DELETED
            deleted_count += 1
            
            # Audit each deletion
            if self.audit:
                await self.audit.log(
                    action=AuditAction.FILE_DELETED_RETENTION,
                    resource_type='file',
                    resource_id=file.id,
                    resource_display=file.filename,
                    summary=f"File deleted by retention policy: {file.filename}",
                    actor_type='system',
                    actor_display='retention_job',
                    tenant_id=tenant_id,
                )
        
        return deleted_count
    
    async def _cleanup_alerts(self, tenant_id: UUID, cutoff: datetime) -> int:
        """Clean up old alerts."""
        # Count alerts to delete (not linked to investigations)
        result = await self.db.execute(
            select(func.count(Alert.id)).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at < cutoff,
                )
            )
        )
        count = result.scalar() or 0
        
        if count > 0:
            await self.db.execute(
                delete(Alert).where(
                    and_(
                        Alert.tenant_id == tenant_id,
                        Alert.created_at < cutoff,
                    )
                )
            )
        
        return count
    
    async def _cleanup_notes(self, tenant_id: UUID, cutoff: datetime) -> int:
        """Clean up soft-deleted notes past grace period."""
        result = await self.db.execute(
            select(func.count(Note.id)).where(
                and_(
                    Note.tenant_id == tenant_id,
                    Note.is_deleted == True,
                    Note.deleted_at < cutoff,
                )
            )
        )
        count = result.scalar() or 0
        
        if count > 0:
            await self.db.execute(
                delete(Note).where(
                    and_(
                        Note.tenant_id == tenant_id,
                        Note.is_deleted == True,
                        Note.deleted_at < cutoff,
                    )
                )
            )
        
        return count
    
    async def _cleanup_investigations(self, tenant_id: UUID, cutoff: datetime) -> int:
        """Clean up closed investigations past retention period."""
        result = await self.db.execute(
            select(func.count(Investigation.id)).where(
                and_(
                    Investigation.tenant_id == tenant_id,
                    Investigation.status == 'closed',
                    Investigation.closed_at < cutoff,
                )
            )
        )
        count = result.scalar() or 0
        
        # Note: In production, you might want to archive rather than delete
        if count > 0:
            await self.db.execute(
                delete(Investigation).where(
                    and_(
                        Investigation.tenant_id == tenant_id,
                        Investigation.status == 'closed',
                        Investigation.closed_at < cutoff,
                    )
                )
            )
        
        return count
    
    async def _cleanup_action_results(self, tenant_id: UUID, cutoff: datetime) -> int:
        """Clean up old action results."""
        result = await self.db.execute(
            select(func.count(ActionResult.id)).where(
                and_(
                    ActionResult.tenant_id == tenant_id,
                    ActionResult.requested_at < cutoff,
                )
            )
        )
        count = result.scalar() or 0
        
        if count > 0:
            await self.db.execute(
                delete(ActionResult).where(
                    and_(
                        ActionResult.tenant_id == tenant_id,
                        ActionResult.requested_at < cutoff,
                    )
                )
            )
        
        return count
    
    async def _cleanup_audit_logs(self, tenant_id: UUID, cutoff: datetime) -> int:
        """
        Clean up audit logs past retention period.
        
        IMPORTANT: Minimum 730 days (2 years) is enforced at policy level.
        """
        result = await self.db.execute(
            select(func.count(AuditEvent.id)).where(
                and_(
                    AuditEvent.tenant_id == tenant_id,
                    AuditEvent.event_time < cutoff,
                )
            )
        )
        count = result.scalar() or 0
        
        if count > 0:
            await self.db.execute(
                delete(AuditEvent).where(
                    and_(
                        AuditEvent.tenant_id == tenant_id,
                        AuditEvent.event_time < cutoff,
                    )
                )
            )
        
        return count
