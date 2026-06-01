# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Alert Deduplication API - Phase 2.4

Manage alert deduplication rules and view grouped alerts.
"I don't want to see the same alert 47 times" - Every analyst, ever
"""

import logging

from fastapi import APIRouter, HTTPException, Header, Query, Request
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from datetime import datetime
from enum import Enum

from services.alert_deduplication import get_dedupe_service, DedupeAction
from routes.admin import require_admin, get_current_username

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/deduplication", tags=["deduplication"])


# ==================== MODELS ====================

class DedupeActionType(str, Enum):
    GROUP = "group"
    SUPPRESS = "suppress"
    MERGE = "merge"
    COUNT_ONLY = "count_only"


class DedupeRuleCreate(BaseModel):
    """Create a new deduplication rule"""
    name: str = Field(..., description="Rule name")
    description: Optional[str] = Field(None, description="Rule description")
    fingerprint_fields: List[str] = Field(
        ...,
        description="Fields to use for fingerprint calculation",
        example=["source", "category", "title"]
    )
    window_minutes: int = Field(
        60,
        ge=1,
        le=10080,  # Max 1 week
        description="Time window for grouping duplicates (minutes)"
    )
    action: DedupeActionType = Field(
        DedupeActionType.GROUP,
        description="Action to take on duplicates"
    )
    source_filter: Optional[str] = Field(
        None,
        description="Filter by source (supports wildcards like 'siem-*')"
    )
    category_filter: Optional[str] = Field(
        None,
        description="Filter by category"
    )
    severity_filter: Optional[List[str]] = Field(
        None,
        description="Filter by severity levels",
        example=["high", "critical"]
    )
    priority: int = Field(
        100,
        ge=1,
        le=1000,
        description="Rule priority (lower = higher priority)"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "name": "Network Scan Dedup",
                "description": "Group repeated network scan alerts from same source",
                "fingerprint_fields": ["source", "source_ip", "category"],
                "window_minutes": 30,
                "action": "group",
                "source_filter": "firewall-*",
                "priority": 50
            }
        }


class DedupeRuleResponse(BaseModel):
    """Deduplication rule response"""
    id: str
    name: str
    description: Optional[str]
    enabled: bool
    fingerprint_fields: List[str]
    window_minutes: int
    action: str
    source_filter: Optional[str]
    category_filter: Optional[str]
    severity_filter: Optional[List[str]]
    priority: int
    total_matches: int
    duplicates_suppressed: int
    created_at: Optional[str]
    created_by: Optional[str]


class FingerprintRequest(BaseModel):
    """Request to calculate fingerprint for alert data"""
    alert_data: Dict[str, Any] = Field(..., description="Alert data to fingerprint")
    fields: Optional[List[str]] = Field(
        None,
        description="Fields to use (uses default if not specified)"
    )


# ==================== ENDPOINTS ====================

@router.get("/rules", response_model=List[DedupeRuleResponse])
async def list_rules(
    request: Request,
    include_disabled: bool = Query(False, description="Include disabled rules"),
    authorization: str = Header(None)
):
    """List all deduplication rules"""
    try:
        await require_admin(request, authorization)

        service = get_dedupe_service()
        rules = await service.list_rules(include_disabled=include_disabled)

        return rules
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in list_rules: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/rules", response_model=Dict[str, Any])
async def create_rule(
    request: Request,
    rule: DedupeRuleCreate,
    authorization: str = Header(None)
):
    """Create a new deduplication rule"""
    try:
        username = await get_current_username(request, authorization)

        service = get_dedupe_service()
        result = await service.add_rule(
            name=rule.name,
            description=rule.description,
            fingerprint_fields=rule.fingerprint_fields,
            window_minutes=rule.window_minutes,
            action=rule.action.value,
            source_filter=rule.source_filter,
            category_filter=rule.category_filter,
            severity_filter=rule.severity_filter,
            priority=rule.priority,
            created_by=username
        )

        return {
            "success": True,
            "rule": result,
            "message": f"Deduplication rule '{rule.name}' created"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in create_rule: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


class DedupeRuleUpdate(BaseModel):
    """Partial update for an existing rule."""
    name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    fingerprint_fields: Optional[List[str]] = None
    window_minutes: Optional[int] = Field(None, ge=1, le=10080)
    action: Optional[DedupeActionType] = None
    source_filter: Optional[str] = None
    category_filter: Optional[str] = None
    severity_filter: Optional[List[str]] = None
    priority: Optional[int] = Field(None, ge=0, le=1000)


@router.patch("/rules/{rule_id}", response_model=Dict[str, Any])
async def update_rule(
    request: Request,
    rule_id: str,
    rule: DedupeRuleUpdate,
    authorization: str = Header(None),
):
    """Update an existing deduplication rule (partial). Returns the updated row."""
    try:
        await require_admin(request, authorization)
        service = get_dedupe_service()
        payload = rule.dict(exclude_unset=True)
        if "action" in payload and payload["action"] is not None:
            payload["action"] = payload["action"].value if hasattr(payload["action"], "value") else payload["action"]
        updated = await service.update_rule(rule_id, **payload)
        if not updated:
            raise HTTPException(status_code=404, detail="rule not found")
        return {"success": True, "rule": updated}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in update_rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/rules/{rule_id}")
async def delete_rule(
    request: Request,
    rule_id: str,
    authorization: str = Header(None),
):
    """Delete a deduplication rule."""
    try:
        await require_admin(request, authorization)
        service = get_dedupe_service()
        ok = await service.delete_rule(rule_id)
        if not ok:
            raise HTTPException(status_code=404, detail="rule not found")
        return {"success": True, "id": rule_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in delete_rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules/reload")
async def reload_rules(request: Request, authorization: str = Header(None)):
    """Force reload rules from database"""
    try:
        await require_admin(request, authorization)

        service = get_dedupe_service()
        await service.load_rules(force=True)

        return {
            "success": True,
            "rules_loaded": len(service._rules),
            "message": "Deduplication rules reloaded"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in reload_rules: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/stats")
async def get_stats(request: Request, authorization: str = Header(None)):
    """Get deduplication statistics"""
    try:
        await require_admin(request, authorization)

        service = get_dedupe_service()
        stats = await service.get_stats()

        return {
            "success": True,
            "stats": stats
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/check")
async def check_duplicate(
    request: Request,
    alert_data: Dict[str, Any],
    authorization: str = Header(None)
):
    """
    Check if an alert would be considered a duplicate.

    Useful for testing rules before enabling them.
    """
    try:
        await require_admin(request, authorization)

        service = get_dedupe_service()
        result = await service.check_duplicate(alert_data)

        return {
            "is_duplicate": result.is_duplicate,
            "action": result.action,
            "fingerprint": result.fingerprint,
            "existing_group_id": result.existing_group_id,
            "existing_alert_id": result.existing_alert_id,
            "group_alert_count": result.group_alert_count,
            "rule_matched": {
                "id": result.rule_matched.id,
                "name": result.rule_matched.name,
                "fingerprint_fields": result.rule_matched.fingerprint_fields,
                "window_minutes": result.rule_matched.window_minutes,
                "action": result.rule_matched.action
            } if result.rule_matched else None
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in check_duplicate: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/fingerprint")
async def calculate_fingerprint(
    request: Request,
    fingerprint_req: FingerprintRequest,
    authorization: str = Header(None)
):
    """
    Calculate the fingerprint for given alert data.

    Useful for understanding how alerts would be grouped.
    """
    try:
        await require_admin(request, authorization)

        service = get_dedupe_service()
        fields = fingerprint_req.fields or service._default_fields
        fingerprint = service.calculate_fingerprint(fingerprint_req.alert_data, fields)

        return {
            "fingerprint": fingerprint,
            "fields_used": fields,
            "field_values": {
                f: service._get_nested_field(fingerprint_req.alert_data, f)
                for f in fields
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in calculate_fingerprint: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/groups/{group_id}")
async def get_group(
    request: Request,
    group_id: str,
    authorization: str = Header(None)
):
    """Get details of an alert group"""
    try:
        await require_admin(request, authorization)

        service = get_dedupe_service()
        group = await service.get_group(group_id)

        if not group:
            raise HTTPException(status_code=404, detail="Alert group not found")

        return {
            "id": group.id,
            "fingerprint": group.fingerprint,
            "primary_alert_id": group.primary_alert_id,
            "dedupe_config_id": group.dedupe_config_id,
            "alert_count": group.alert_count,
            "first_seen": group.first_seen.isoformat() if group.first_seen else None,
            "last_seen": group.last_seen.isoformat() if group.last_seen else None,
            "status": group.status
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_group: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/groups/{group_id}/alerts")
async def get_group_alerts(
    request: Request,
    group_id: str,
    authorization: str = Header(None)
):
    """Get all alerts in a group"""
    try:
        await require_admin(request, authorization)

        service = get_dedupe_service()
        alerts = await service.get_group_alerts(group_id)

        return {
            "group_id": group_id,
            "alert_count": len(alerts),
            "alerts": alerts
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_group_alerts: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ==================== CONVENIENCE ENDPOINTS ====================

@router.post("/rules/quick-add/network-scan")
async def quick_add_network_scan_rule(
    request: Request,
    window_minutes: int = Query(30, ge=5, le=120),
    authorization: str = Header(None)
):
    """
    Quick add a rule for network scan deduplication.

    Groups repeated network scan alerts from the same source IP.
    """
    try:
        username = await get_current_username(request, authorization)

        service = get_dedupe_service()
        result = await service.add_rule(
            name="Network Scan Dedup",
            description="Group repeated network scan alerts from same source",
            fingerprint_fields=["source", "source_ip", "category", "destination_ip"],
            window_minutes=window_minutes,
            action="group",
            category_filter="network_scan",
            priority=50,
            created_by=username
        )

        return {
            "success": True,
            "rule": result,
            "message": "Network scan deduplication rule created"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in quick_add_network_scan_rule: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/rules/quick-add/auth-failure")
async def quick_add_auth_failure_rule(
    request: Request,
    window_minutes: int = Query(15, ge=5, le=60),
    authorization: str = Header(None)
):
    """
    Quick add a rule for authentication failure deduplication.

    Groups repeated auth failures from the same user/IP.
    """
    try:
        username = await get_current_username(request, authorization)

        service = get_dedupe_service()
        result = await service.add_rule(
            name="Auth Failure Dedup",
            description="Group repeated authentication failures from same user/IP",
            fingerprint_fields=["source", "user", "source_ip", "category"],
            window_minutes=window_minutes,
            action="group",
            category_filter="authentication*",
            priority=40,
            created_by=username
        )

        return {
            "success": True,
            "rule": result,
            "message": "Authentication failure deduplication rule created"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in quick_add_auth_failure_rule: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/rules/quick-add/malware-detection")
async def quick_add_malware_rule(
    request: Request,
    window_minutes: int = Query(60, ge=15, le=240),
    authorization: str = Header(None)
):
    """
    Quick add a rule for malware detection deduplication.

    Groups repeated malware detections of the same hash.
    """
    try:
        username = await get_current_username(request, authorization)

        service = get_dedupe_service()
        result = await service.add_rule(
            name="Malware Detection Dedup",
            description="Group repeated malware detections of same file hash",
            fingerprint_fields=["source", "file_hash", "malware_name"],
            window_minutes=window_minutes,
            action="group",
            category_filter="malware*",
            severity_filter=["high", "critical"],
            priority=30,
            created_by=username
        )

        return {
            "success": True,
            "rule": result,
            "message": "Malware detection deduplication rule created"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in quick_add_malware_rule: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
