# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Data Retention API Routes

Admin endpoints for managing data retention policies and running cleanup jobs.
"""

import logging
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from typing import Optional, Dict, Any

from services.data_retention import get_retention_service, RETENTION_POLICIES
from services.license_manager import get_license_manager
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/retention", tags=["data-retention"])


class CleanupRequest(BaseModel):
    """Request to run retention cleanup."""
    dry_run: bool = True
    archive_before_delete: bool = False
    archive_bucket: Optional[str] = None


@router.get("/status")
async def get_retention_status(
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get current data retention status.

    Shows storage usage, row counts, and what would be cleaned up.
    """
    try:
        if current_user.get("role") not in ("admin", "super_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")

        license_manager = get_license_manager()
        tier = license_manager.get_license().tier.value

        retention_service = get_retention_service()
        status = await retention_service.get_retention_status(tier)

        return status
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_retention_status: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/policies")
async def get_retention_policies() -> Dict[str, Any]:
    """
    Get retention policies for all license tiers.
    """
    try:
        return {
            "policies": RETENTION_POLICIES,
            "description": {
                "alerts": "Security alerts and their metadata",
                "investigations": "Investigation cases and findings",
                "playbook_executions": "Playbook execution records",
                "playbook_node_results": "Individual node execution results",
                "attachments": "File attachments and evidence",
                "chat_messages": "AI chat history",
                "audit_logs": "User and system audit trails",
                "iocs": "Indicators of Compromise",
                "threat_intel": "Threat intelligence data",
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_retention_policies: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/cleanup")
async def run_retention_cleanup(
    request: CleanupRequest,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Run data retention cleanup.

    By default runs in dry-run mode (no actual deletions).
    Set dry_run=false to actually delete expired data.
    """
    try:
        if current_user.get("role") not in ("admin", "super_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")

        license_manager = get_license_manager()
        tier = license_manager.get_license().tier.value

        retention_service = get_retention_service()

        if request.dry_run:
            # Dry run - execute immediately and return results
            result = await retention_service.run_cleanup(
                tier=tier,
                dry_run=True,
                archive_before_delete=request.archive_before_delete,
                archive_bucket=request.archive_bucket
            )
            return result
        else:
            # Actual cleanup - run in background
            background_tasks.add_task(
                retention_service.run_cleanup,
                tier=tier,
                dry_run=False,
                archive_before_delete=request.archive_before_delete,
                archive_bucket=request.archive_bucket
            )

            logger.info(f"Retention cleanup started by {current_user.get('username')}")

            return {
                "status": "started",
                "message": "Retention cleanup running in background",
                "tier": tier,
                "dry_run": False,
                "archive_enabled": request.archive_before_delete
            }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in run_retention_cleanup: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/estimate")
async def estimate_cleanup(
    current_user: dict = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Estimate what would be deleted in a cleanup run.

    Same as running cleanup with dry_run=true.
    """
    try:
        if current_user.get("role") not in ("admin", "super_admin"):
            raise HTTPException(status_code=403, detail="Admin access required")

        license_manager = get_license_manager()
        tier = license_manager.get_license().tier.value

        retention_service = get_retention_service()
        result = await retention_service.run_cleanup(tier=tier, dry_run=True)

        return {
            "tier": tier,
            "would_delete": result.get("total_rows_deleted", 0),
            "by_table": {
                t["table"]: t["deleted"]
                for t in result.get("tables", [])
            },
            "note": "Run POST /cleanup with dry_run=false to actually delete"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in estimate_cleanup: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
