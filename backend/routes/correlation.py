# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IOC Correlation API Routes

Endpoints for:
- Campaign management
- Correlation rules
- IOC correlation queries
- Correlation statistics
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional, List
from pydantic import BaseModel
import logging
from dependencies.auth import get_current_user
from middleware.tenant_middleware import get_optional_tenant_id

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/correlation", tags=["correlation"], dependencies=[Depends(get_current_user)])


# ============================================================================
# PYDANTIC MODELS
# ============================================================================

class CampaignCreate(BaseModel):
    """Create a new campaign"""
    name: str
    description: Optional[str] = None
    campaign_type: Optional[str] = "unknown"
    threat_actor: Optional[str] = None
    severity: Optional[str] = "medium"
    mitre_techniques: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class CampaignUpdate(BaseModel):
    """Update campaign"""
    name: Optional[str] = None
    description: Optional[str] = None
    campaign_type: Optional[str] = None
    threat_actor: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    notes: Optional[str] = None
    mitre_techniques: Optional[List[str]] = None


class AddCampaignMember(BaseModel):
    """Add member to campaign"""
    member_type: str  # 'alert' or 'investigation'
    alert_id: Optional[str] = None
    investigation_id: Optional[str] = None
    correlation_reason: Optional[str] = None


class AddCampaignIOC(BaseModel):
    """Add IOC to campaign"""
    ioc_value: str
    ioc_type: str
    ioc_role: Optional[str] = "indicator"
    confidence: Optional[float] = 70.0


class RuleCreate(BaseModel):
    """Create correlation rule"""
    rule_id: str
    name: str
    description: Optional[str] = None
    rule_type: str
    parameters: dict
    auto_create_campaign: bool = False
    auto_escalate: bool = False
    priority: int = 5
    enabled: bool = True


class RuleUpdate(BaseModel):
    """Update correlation rule"""
    name: Optional[str] = None
    description: Optional[str] = None
    parameters: Optional[dict] = None
    auto_create_campaign: Optional[bool] = None
    auto_escalate: Optional[bool] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None


# ============================================================================
# CAMPAIGN ENDPOINTS
# ============================================================================

@router.get("/campaigns")
async def list_campaigns(
    status: Optional[str] = Query(None, description="Filter by status"),
    campaign_type: Optional[str] = Query(None, description="Filter by type"),
    limit: int = Query(50, le=200)
):
    """List all campaigns with optional filtering"""
    from services.ioc_correlation_engine import get_correlation_engine

    engine = get_correlation_engine()
    campaigns = await engine.get_campaigns(status=status, campaign_type=campaign_type, limit=limit)

    return {
        "campaigns": campaigns,
        "total": len(campaigns)
    }


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str):
    """Get campaign details including members and IOCs"""
    from services.ioc_correlation_engine import get_correlation_engine

    engine = get_correlation_engine()
    campaign = await engine.get_campaign_details(campaign_id)

    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    return campaign


@router.post("/campaigns")
async def create_campaign(campaign: CampaignCreate):
    """Manually create a new campaign"""
    from services.postgres_db import postgres_db
    import uuid
    from datetime import datetime

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    campaign_id = f"CAMP-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

    try:
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO campaigns (
                    campaign_id, name, description, campaign_type, threat_actor,
                    severity, mitre_techniques, tags, created_by
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'manual')
                RETURNING *
                """,
                campaign_id,
                campaign.name,
                campaign.description,
                campaign.campaign_type,
                campaign.threat_actor,
                campaign.severity,
                campaign.mitre_techniques,
                campaign.tags
            )

            return {"success": True, "campaign": dict(row)}

    except Exception as e:
        logger.error(f"Failed to create campaign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/campaigns/{campaign_id}")
async def update_campaign(campaign_id: str, update: CampaignUpdate):
    """Update campaign details"""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Build dynamic update
            updates = []
            values = [campaign_id]
            idx = 2

            if update.name is not None:
                updates.append(f"name = ${idx}")
                values.append(update.name)
                idx += 1
            if update.description is not None:
                updates.append(f"description = ${idx}")
                values.append(update.description)
                idx += 1
            if update.campaign_type is not None:
                updates.append(f"campaign_type = ${idx}")
                values.append(update.campaign_type)
                idx += 1
            if update.threat_actor is not None:
                updates.append(f"threat_actor = ${idx}")
                values.append(update.threat_actor)
                idx += 1
            if update.severity is not None:
                updates.append(f"severity = ${idx}")
                values.append(update.severity)
                idx += 1
            if update.status is not None:
                updates.append(f"status = ${idx}")
                values.append(update.status)
                idx += 1
            if update.notes is not None:
                updates.append(f"notes = ${idx}")
                values.append(update.notes)
                idx += 1
            if update.mitre_techniques is not None:
                updates.append(f"mitre_techniques = ${idx}")
                values.append(update.mitre_techniques)
                idx += 1

            if not updates:
                raise HTTPException(status_code=400, detail="No updates provided")

            updates.append("updated_at = NOW()")

            query = f"""
                UPDATE campaigns SET {', '.join(updates)}
                WHERE campaign_id = $1
                RETURNING *
            """

            row = await conn.fetchrow(query, *values)

            if not row:
                raise HTTPException(status_code=404, detail="Campaign not found")

            return {"success": True, "campaign": dict(row)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update campaign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/campaigns/{campaign_id}/members")
async def add_campaign_member(campaign_id: str, member: AddCampaignMember):
    """Add alert or investigation to campaign"""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    if member.member_type not in ['alert', 'investigation']:
        raise HTTPException(status_code=400, detail="member_type must be 'alert' or 'investigation'")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get campaign internal ID
            campaign = await conn.fetchrow(
                "SELECT id FROM campaigns WHERE campaign_id = $1",
                campaign_id
            )

            if not campaign:
                raise HTTPException(status_code=404, detail="Campaign not found")

            await conn.execute(
                """
                INSERT INTO campaign_members (campaign_id, member_type, alert_id, investigation_id, added_by, correlation_reason, tenant_id)
                VALUES ($1, $2, $3::uuid, $4::uuid, 'manual', $5, $6)
                ON CONFLICT DO NOTHING
                """,
                campaign['id'],
                member.member_type,
                member.alert_id,
                member.investigation_id,
                member.correlation_reason,
                get_optional_tenant_id()
            )

            # Update campaign counts
            await conn.execute(
                """
                UPDATE campaigns SET
                    alert_count = (SELECT COUNT(*) FROM campaign_members WHERE campaign_id = $1 AND member_type = 'alert'),
                    investigation_count = (SELECT COUNT(*) FROM campaign_members WHERE campaign_id = $1 AND member_type = 'investigation'),
                    last_activity = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                """,
                campaign['id']
            )

            return {"success": True, "message": "Member added to campaign"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to add campaign member: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/campaigns/{campaign_id}/iocs")
async def add_campaign_ioc(campaign_id: str, ioc: AddCampaignIOC):
    """Add IOC to campaign"""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get campaign internal ID
            campaign = await conn.fetchrow(
                "SELECT id FROM campaigns WHERE campaign_id = $1",
                campaign_id
            )

            if not campaign:
                raise HTTPException(status_code=404, detail="Campaign not found")

            await conn.execute(
                """
                INSERT INTO campaign_iocs (campaign_id, ioc_value, ioc_type, ioc_role, confidence, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (campaign_id, ioc_value, ioc_type) DO UPDATE SET
                    occurrence_count = campaign_iocs.occurrence_count + 1,
                    last_seen_in_campaign = NOW()
                """,
                campaign['id'],
                ioc.ioc_value,
                ioc.ioc_type,
                ioc.ioc_role,
                ioc.confidence,
                get_optional_tenant_id()
            )

            # Update campaign IOC count
            await conn.execute(
                """
                UPDATE campaigns SET
                    ioc_count = (SELECT COUNT(*) FROM campaign_iocs WHERE campaign_id = $1),
                    last_activity = NOW(),
                    updated_at = NOW()
                WHERE id = $1
                """,
                campaign['id']
            )

            return {"success": True, "message": "IOC added to campaign"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to add campaign IOC: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: str):
    """Delete a campaign"""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute(
                "DELETE FROM campaigns WHERE campaign_id = $1",
                campaign_id
            )

            if result == "DELETE 0":
                raise HTTPException(status_code=404, detail="Campaign not found")

            return {"success": True, "message": "Campaign deleted"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete campaign: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# CORRELATION RULES ENDPOINTS
# ============================================================================

@router.get("/rules")
async def list_rules(
    enabled: Optional[bool] = Query(None, description="Filter by enabled status"),
    rule_type: Optional[str] = Query(None, description="Filter by rule type")
):
    """List all correlation rules"""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            query = """
                SELECT * FROM correlation_rules
                WHERE ($1::boolean IS NULL OR enabled = $1)
                  AND ($2::text IS NULL OR rule_type = $2)
                ORDER BY priority ASC, name ASC
            """
            rows = await conn.fetch(query, enabled, rule_type)

            return {
                "rules": [dict(r) for r in rows],
                "total": len(rows)
            }

    except Exception as e:
        logger.error(f"Failed to list rules: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str):
    """Get correlation rule details"""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM correlation_rules WHERE rule_id = $1",
                rule_id
            )

            if not row:
                raise HTTPException(status_code=404, detail="Rule not found")

            return dict(row)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rules")
async def create_rule(rule: RuleCreate):
    """Create a new correlation rule"""
    from services.postgres_db import postgres_db
    import json

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    valid_types = ['ioc_match', 'time_window', 'host_pattern', 'user_pattern', 'technique_match', 'severity_chain', 'custom']
    if rule.rule_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid rule_type. Must be one of: {valid_types}")

    try:
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO correlation_rules (
                    rule_id, name, description, rule_type, parameters,
                    auto_create_campaign, auto_escalate, priority, enabled, created_by
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'api')
                RETURNING *
                """,
                rule.rule_id,
                rule.name,
                rule.description,
                rule.rule_type,
                json.dumps(rule.parameters),
                rule.auto_create_campaign,
                rule.auto_escalate,
                rule.priority,
                rule.enabled
            )

            return {"success": True, "rule": dict(row)}

    except Exception as e:
        if "duplicate key" in str(e):
            raise HTTPException(status_code=400, detail="Rule with this ID already exists")
        logger.error(f"Failed to create rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/rules/{rule_id}")
async def update_rule(rule_id: str, update: RuleUpdate):
    """Update a correlation rule"""
    from services.postgres_db import postgres_db
    import json

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            updates = []
            values = [rule_id]
            idx = 2

            if update.name is not None:
                updates.append(f"name = ${idx}")
                values.append(update.name)
                idx += 1
            if update.description is not None:
                updates.append(f"description = ${idx}")
                values.append(update.description)
                idx += 1
            if update.parameters is not None:
                updates.append(f"parameters = ${idx}")
                values.append(json.dumps(update.parameters))
                idx += 1
            if update.auto_create_campaign is not None:
                updates.append(f"auto_create_campaign = ${idx}")
                values.append(update.auto_create_campaign)
                idx += 1
            if update.auto_escalate is not None:
                updates.append(f"auto_escalate = ${idx}")
                values.append(update.auto_escalate)
                idx += 1
            if update.priority is not None:
                updates.append(f"priority = ${idx}")
                values.append(update.priority)
                idx += 1
            if update.enabled is not None:
                updates.append(f"enabled = ${idx}")
                values.append(update.enabled)
                idx += 1

            if not updates:
                raise HTTPException(status_code=400, detail="No updates provided")

            updates.append("updated_at = NOW()")

            query = f"""
                UPDATE correlation_rules SET {', '.join(updates)}
                WHERE rule_id = $1
                RETURNING *
            """

            row = await conn.fetchrow(query, *values)

            if not row:
                raise HTTPException(status_code=404, detail="Rule not found")

            return {"success": True, "rule": dict(row)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str, enabled: bool = Query(..., description="Enable or disable the rule")):
    """Enable or disable a correlation rule"""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                """
                UPDATE correlation_rules SET enabled = $2, updated_at = NOW()
                WHERE rule_id = $1
                RETURNING rule_id, name, enabled
                """,
                rule_id, enabled
            )

            if not row:
                raise HTTPException(status_code=404, detail="Rule not found")

            return {"success": True, "rule": dict(row)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to toggle rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete a correlation rule"""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute(
                "DELETE FROM correlation_rules WHERE rule_id = $1",
                rule_id
            )

            if result == "DELETE 0":
                raise HTTPException(status_code=404, detail="Rule not found")

            return {"success": True, "message": "Rule deleted"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete rule: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# IOC CORRELATION ENDPOINTS
# ============================================================================

@router.get("/ioc/{ioc_value}")
async def get_ioc_correlations(
    ioc_value: str,
    ioc_type: str = Query(..., description="IOC type (ip, domain, hash_sha256, etc)")
):
    """Get all correlations for a specific IOC"""
    from services.ioc_correlation_engine import get_correlation_engine

    engine = get_correlation_engine()
    correlations = await engine.get_ioc_correlations(ioc_value, ioc_type)

    if not correlations:
        raise HTTPException(status_code=404, detail="No correlations found")

    return correlations


@router.get("/stats")
async def get_correlation_stats():
    """Get overall correlation statistics"""
    from services.ioc_correlation_engine import get_correlation_engine

    engine = get_correlation_engine()
    stats = await engine.get_correlation_stats()

    return stats


@router.get("/events")
async def list_correlation_events(
    limit: int = Query(50, le=200),
    rule_id: Optional[str] = Query(None, description="Filter by rule ID"),
    campaign_id: Optional[str] = Query(None, description="Filter by campaign ID")
):
    """List recent correlation events"""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            query = """
                SELECT ce.*, cr.rule_id as rule_code, c.campaign_id as campaign_code
                FROM correlation_events ce
                LEFT JOIN correlation_rules cr ON ce.rule_id = cr.id
                LEFT JOIN campaigns c ON ce.campaign_id = c.id
                WHERE ($1::uuid IS NULL OR ce.rule_id = $1)
                  AND ($2::uuid IS NULL OR ce.campaign_id = $2)
                ORDER BY ce.created_at DESC
                LIMIT $3
            """

            # Convert string IDs to UUIDs if needed
            rule_uuid = None
            campaign_uuid = None

            if rule_id:
                rule_row = await conn.fetchrow(
                    "SELECT id FROM correlation_rules WHERE rule_id = $1", rule_id
                )
                if rule_row:
                    rule_uuid = rule_row['id']

            if campaign_id:
                camp_row = await conn.fetchrow(
                    "SELECT id FROM campaigns WHERE campaign_id = $1", campaign_id
                )
                if camp_row:
                    campaign_uuid = camp_row['id']

            rows = await conn.fetch(query, rule_uuid, campaign_uuid, limit)

            return {
                "events": [dict(r) for r in rows],
                "total": len(rows)
            }

    except Exception as e:
        logger.error(f"Failed to list correlation events: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# MANUAL CORRELATION TRIGGER
# ============================================================================

@router.post("/trigger/{alert_id}")
async def trigger_correlation(alert_id: str):
    """Manually trigger correlation check for an alert"""
    from services.ioc_correlation_engine import get_correlation_engine
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get alert
            alert_row = await conn.fetchrow(
                "SELECT * FROM alerts WHERE id = $1::uuid",
                alert_id
            )

            if not alert_row:
                raise HTTPException(status_code=404, detail="Alert not found")

            alert = dict(alert_row)

        engine = get_correlation_engine()

        # Link IOCs
        linked = await engine.link_alert_iocs(alert_id, alert)

        # Check correlations
        results = await engine.check_correlations(alert_id, alert)

        return {
            "success": True,
            "alert_id": alert_id,
            "iocs_linked": linked,
            "correlations_found": len(results),
            "correlations": [
                {
                    "rule": r.rule_name,
                    "type": r.correlation_type,
                    "score": r.correlation_score,
                    "campaign_id": r.campaign_id,
                    "matched_alerts": len(r.matched_alerts),
                    "matched_iocs": len(r.matched_iocs)
                }
                for r in results
            ]
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to trigger correlation: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# HYPOTHESIS-DRIVEN CORRELATION ENDPOINTS (v3.0)
# ============================================================================

# ============================================================================
# CORRELATION SETTINGS ENDPOINTS
# ============================================================================

class CorrelationSettingsUpdate(BaseModel):
    """Update correlation settings"""
    correlation_enabled: Optional[bool] = None
    ai_hypothesis_enabled: Optional[bool] = None
    entity_risk_enabled: Optional[bool] = None
    allow_cross_domain: Optional[bool] = None
    time_window_hours: Optional[int] = None
    min_evidence_score: Optional[int] = None
    auto_confirm_threshold: Optional[int] = None
    max_alerts_per_investigation: Optional[int] = None
    entity_risk_threshold: Optional[int] = None
    entity_risk_decay_hours: Optional[int] = None
    user_weight: Optional[int] = None
    host_weight: Optional[int] = None
    ip_weight: Optional[int] = None
    ioc_weight: Optional[int] = None


class EntityRiskReset(BaseModel):
    """Reset entity risk"""
    entity_type: str
    entity_value: str


@router.get("/settings")
async def get_correlation_settings(
    user=Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_optional_tenant_id)
):
    """Get correlation settings for the current tenant."""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    if not tenant_id:
        raise HTTPException(status_code=400, detail="Tenant context required")

    try:
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM correlation_settings WHERE tenant_id = $1::uuid",
                tenant_id
            )

            if row:
                result = dict(row)
                # Convert UUID to string for JSON serialization
                result['tenant_id'] = str(result['tenant_id'])
                if result.get('updated_at'):
                    result['updated_at'] = result['updated_at'].isoformat()
                return result

            # Return defaults
            return {
                "tenant_id": tenant_id,
                "correlation_enabled": True,
                "ai_hypothesis_enabled": True,
                "entity_risk_enabled": True,
                "allow_cross_domain": False,
                "time_window_hours": 24,
                "min_evidence_score": 40,
                "auto_confirm_threshold": 100,
                "max_alerts_per_investigation": 25,
                "entity_risk_threshold": 75,
                "entity_risk_decay_hours": 72,
                "user_weight": 30,
                "host_weight": 25,
                "ip_weight": 15,
                "ioc_weight": 20,
                "updated_at": None,
                "updated_by": None,
            }

    except Exception as e:
        logger.error(f"Failed to get correlation settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/settings")
async def update_correlation_settings(
    update: CorrelationSettingsUpdate,
    user=Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_optional_tenant_id)
):
    """Update correlation settings for the current tenant."""
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    if not tenant_id:
        raise HTTPException(status_code=400, detail="Tenant context required")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Collect provided fields
            fields = {}
            for field_name in [
                'correlation_enabled', 'ai_hypothesis_enabled', 'entity_risk_enabled',
                'allow_cross_domain', 'time_window_hours', 'min_evidence_score',
                'auto_confirm_threshold', 'max_alerts_per_investigation',
                'entity_risk_threshold', 'entity_risk_decay_hours',
                'user_weight', 'host_weight', 'ip_weight', 'ioc_weight'
            ]:
                value = getattr(update, field_name, None)
                if value is not None:
                    fields[field_name] = value

            if not fields:
                raise HTTPException(status_code=400, detail="No updates provided")

            updated_by = user.get('email', 'system') if isinstance(user, dict) else 'system'

            # Build INSERT columns and values
            # $1 = tenant_id, then field values, then updated_by
            col_names = list(fields.keys())
            insert_cols = ['tenant_id'] + col_names + ['updated_at', 'updated_by']
            insert_placeholders = ['$1::uuid']
            values = [tenant_id]
            for i, col in enumerate(col_names):
                insert_placeholders.append(f'${i + 2}')
                values.append(fields[col])
            insert_placeholders.append('NOW()')
            next_idx = len(values) + 1
            insert_placeholders.append(f'${next_idx}')
            values.append(updated_by)

            # Build ON CONFLICT SET clause
            set_parts = [f"{col} = EXCLUDED.{col}" for col in col_names]
            set_parts.append("updated_at = NOW()")
            set_parts.append("updated_by = EXCLUDED.updated_by")

            query = f"""
                INSERT INTO correlation_settings ({', '.join(insert_cols)})
                VALUES ({', '.join(insert_placeholders)})
                ON CONFLICT (tenant_id) DO UPDATE SET {', '.join(set_parts)}
                RETURNING *
            """

            row = await conn.fetchrow(query, *values)
            result = dict(row)
            result['tenant_id'] = str(result['tenant_id'])
            if result.get('updated_at'):
                result['updated_at'] = result['updated_at'].isoformat()

            return {"success": True, "settings": result}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update correlation settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/entity-risk")
async def get_entity_risk_list(
    limit: int = Query(50, le=200),
    user=Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_optional_tenant_id)
):
    """Get high-risk entities for the current tenant."""
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Tenant context required")

    from services.entity_risk_service import get_entity_risk_service

    service = get_entity_risk_service()
    entities = await service.get_high_risk_entities(tenant_id, limit)

    # Serialize for JSON
    for e in entities:
        for key in ['id', 'first_seen', 'last_seen', 'threshold_breached_at']:
            if e.get(key) and hasattr(e[key], 'isoformat'):
                e[key] = e[key].isoformat()
            elif e.get(key):
                e[key] = str(e[key])
        if e.get('risk_score') is not None:
            e['risk_score'] = float(e['risk_score'])

    return {"entities": entities, "total": len(entities)}


@router.get("/entity-risk/{entity_type}/{entity_value}")
async def get_entity_risk_detail(
    entity_type: str,
    entity_value: str,
    user=Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_optional_tenant_id)
):
    """Get risk detail and timeline for a specific entity."""
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Tenant context required")

    from services.entity_risk_service import get_entity_risk_service

    service = get_entity_risk_service()
    entity = await service.get_entity_risk(tenant_id, entity_type, entity_value)

    if not entity:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Serialize
    for key in ['id', 'tenant_id', 'first_seen', 'last_seen', 'threshold_breached_at', 'created_at']:
        if entity.get(key) and hasattr(entity[key], 'isoformat'):
            entity[key] = entity[key].isoformat()
        elif entity.get(key):
            entity[key] = str(entity[key])
    if entity.get('risk_score') is not None:
        entity['risk_score'] = float(entity['risk_score'])

    return entity


@router.post("/entity-risk/reset")
async def reset_entity_risk(
    body: EntityRiskReset,
    user=Depends(get_current_user),
    tenant_id: Optional[str] = Depends(get_optional_tenant_id)
):
    """Reset risk score for a specific entity."""
    if not tenant_id:
        raise HTTPException(status_code=400, detail="Tenant context required")

    from services.entity_risk_service import get_entity_risk_service

    service = get_entity_risk_service()
    success = await service.reset_entity_risk(tenant_id, body.entity_type, body.entity_value)

    if not success:
        raise HTTPException(status_code=404, detail="Entity not found or reset failed")

    return {"success": True, "message": f"Risk reset for {body.entity_type}:{body.entity_value}"}


# ============================================================================
# HYPOTHESIS-DRIVEN CORRELATION ENDPOINTS (v3.0)
# ============================================================================

class CorrelationLinkConfirm(BaseModel):
    """Confirm a suggested correlation link"""
    confirmed_by: Optional[str] = None


class CorrelationLinkReject(BaseModel):
    """Reject a suggested correlation link"""
    reason: str
    rejected_by: Optional[str] = None


@router.get("/links/pending")
async def list_pending_correlations(
    investigation_id: Optional[str] = Query(None, description="Filter by investigation"),
    limit: int = Query(50, le=200)
):
    """
    List pending (SUGGESTED) correlation links awaiting review.

    This endpoint supports the soft-join workflow where correlations
    start as SUGGESTED and require analyst confirmation.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            query = """
                SELECT
                    cl.id,
                    cl.alert_id,
                    a.alert_id as alert_number,
                    a.title as alert_title,
                    a.severity as alert_severity,
                    cl.investigation_id,
                    i.investigation_id as investigation_number,
                    i.hypothesis,
                    i.hypothesis_category,
                    cl.link_state,
                    cl.relationship_type,
                    cl.correlation_score,
                    cl.why_correlated,
                    cl.evidence_json,
                    cl.hypothesis_support,
                    cl.suggested_at,
                    EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - cl.suggested_at))/3600 as hours_pending
                FROM correlation_links cl
                JOIN alerts a ON cl.alert_id = a.id
                JOIN investigations i ON cl.investigation_id = i.id
                WHERE cl.link_state = 'SUGGESTED'
                  AND ($1::uuid IS NULL OR cl.investigation_id = $1::uuid)
                ORDER BY cl.correlation_score DESC, cl.suggested_at ASC
                LIMIT $2
            """

            rows = await conn.fetch(query, investigation_id, limit)

            return {
                "pending_links": [
                    {
                        "id": str(r['id']),
                        "alert_id": str(r['alert_id']),
                        "alert_number": r['alert_number'],
                        "alert_title": r['alert_title'],
                        "alert_severity": r['alert_severity'],
                        "investigation_id": str(r['investigation_id']),
                        "investigation_number": r['investigation_number'],
                        "hypothesis": r['hypothesis'],
                        "hypothesis_category": r['hypothesis_category'],
                        "relationship_type": r['relationship_type'],
                        "correlation_score": r['correlation_score'],
                        "why_correlated": r['why_correlated'],
                        "evidence": r['evidence_json'] or [],
                        "hypothesis_support": r['hypothesis_support'],
                        "suggested_at": r['suggested_at'].isoformat() if r['suggested_at'] else None,
                        "hours_pending": round(r['hours_pending'], 1) if r['hours_pending'] else 0,
                    }
                    for r in rows
                ],
                "total": len(rows)
            }

    except Exception as e:
        logger.error(f"Failed to list pending correlations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/links/{link_id}/confirm")
async def confirm_correlation_link(
    link_id: str,
    body: CorrelationLinkConfirm
):
    """
    Confirm a suggested correlation link (soft-join -> hard-join).

    This moves the link from SUGGESTED to CONFIRMED state and
    updates the alert's investigation_id.
    """
    from services.postgres_db import postgres_db
    import json

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get the link
            link = await conn.fetchrow(
                """
                SELECT cl.*, a.alert_id as alert_number
                FROM correlation_links cl
                JOIN alerts a ON cl.alert_id = a.id
                WHERE cl.id = $1::uuid
                """,
                link_id
            )

            if not link:
                raise HTTPException(status_code=404, detail="Correlation link not found")

            if link['link_state'] != 'SUGGESTED':
                raise HTTPException(
                    status_code=400,
                    detail=f"Link is already {link['link_state']}, cannot confirm"
                )

            confirmed_by = body.confirmed_by or 'analyst'

            # Update link to CONFIRMED
            await conn.execute(
                """
                UPDATE correlation_links
                SET link_state = 'CONFIRMED',
                    confirmed_at = CURRENT_TIMESTAMP,
                    confirmed_by = $1
                WHERE id = $2::uuid
                """,
                confirmed_by,
                link_id
            )

            # Update alert's investigation_id
            await conn.execute(
                """
                UPDATE alerts
                SET investigation_id = $1,
                    status = 'investigating',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $2
                """,
                link['investigation_id'],
                link['alert_id']
            )

            # Record audit
            await conn.execute(
                """
                INSERT INTO correlation_audit (
                    alert_id, decision, investigation_id,
                    score, evidence, reason
                ) VALUES ($1, 'CONFIRMED', $2, $3, $4::jsonb, $5)
                """,
                link['alert_id'],
                link['investigation_id'],
                link['correlation_score'],
                json.dumps(link['evidence_json'] or []),
                f"Confirmed by {confirmed_by}"
            )

            logger.info(
                f"Correlation link {link_id} confirmed: "
                f"alert {link['alert_number']} -> investigation"
            )

            return {
                "success": True,
                "link_id": link_id,
                "alert_id": str(link['alert_id']),
                "investigation_id": str(link['investigation_id']),
                "confirmed_by": confirmed_by,
                "message": "Correlation confirmed, alert linked to investigation"
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to confirm correlation link: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/links/{link_id}/reject")
async def reject_correlation_link(
    link_id: str,
    body: CorrelationLinkReject
):
    """
    Reject a suggested correlation link.

    This moves the link from SUGGESTED to REJECTED state.
    The alert remains unlinked to this investigation.
    """
    from services.postgres_db import postgres_db
    import json

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get the link
            link = await conn.fetchrow(
                """
                SELECT cl.*, a.alert_id as alert_number
                FROM correlation_links cl
                JOIN alerts a ON cl.alert_id = a.id
                WHERE cl.id = $1::uuid
                """,
                link_id
            )

            if not link:
                raise HTTPException(status_code=404, detail="Correlation link not found")

            if link['link_state'] != 'SUGGESTED':
                raise HTTPException(
                    status_code=400,
                    detail=f"Link is already {link['link_state']}, cannot reject"
                )

            rejected_by = body.rejected_by or 'analyst'

            # Update link to REJECTED
            await conn.execute(
                """
                UPDATE correlation_links
                SET link_state = 'REJECTED',
                    rejected_at = CURRENT_TIMESTAMP,
                    reject_reason = $1,
                    confirmed_by = $2
                WHERE id = $3::uuid
                """,
                body.reason,
                rejected_by,
                link_id
            )

            # Record audit
            await conn.execute(
                """
                INSERT INTO correlation_audit (
                    alert_id, decision, investigation_id,
                    score, evidence, reason
                ) VALUES ($1, 'REJECTED', $2, $3, $4::jsonb, $5)
                """,
                link['alert_id'],
                link['investigation_id'],
                link['correlation_score'],
                json.dumps(link['evidence_json'] or []),
                f"Rejected by {rejected_by}: {body.reason}"
            )

            logger.info(
                f"Correlation link {link_id} rejected: "
                f"alert {link['alert_number']} - reason: {body.reason}"
            )

            return {
                "success": True,
                "link_id": link_id,
                "alert_id": str(link['alert_id']),
                "investigation_id": str(link['investigation_id']),
                "rejected_by": rejected_by,
                "reason": body.reason,
                "message": "Correlation rejected, alert not linked"
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reject correlation link: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/links/audit/{alert_id}")
async def get_correlation_audit(alert_id: str):
    """
    Get correlation audit history for an alert.

    Shows all correlation decisions made for this alert,
    including blocked attempts and why they were blocked.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.pool:
        raise HTTPException(status_code=500, detail="Database not connected")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Get alert UUID
            alert_row = await conn.fetchrow(
                "SELECT id FROM alerts WHERE alert_id = $1",
                alert_id
            )

            if not alert_row:
                raise HTTPException(status_code=404, detail="Alert not found")

            alert_uuid = alert_row['id']

            # Get audit records
            rows = await conn.fetch(
                """
                SELECT
                    ca.id,
                    ca.decision,
                    ca.investigation_id,
                    ca.investigation_number,
                    ca.score,
                    ca.threshold_used,
                    ca.gates_passed,
                    ca.gates_failed,
                    ca.evidence,
                    ca.hypothesis_support,
                    ca.reason,
                    ca.processing_time_ms,
                    ca.created_at
                FROM correlation_audit ca
                WHERE ca.alert_id = $1
                ORDER BY ca.created_at DESC
                """,
                alert_uuid
            )

            return {
                "alert_id": alert_id,
                "audit_records": [
                    {
                        "id": str(r['id']),
                        "decision": r['decision'],
                        "investigation_id": str(r['investigation_id']) if r['investigation_id'] else None,
                        "investigation_number": r['investigation_number'],
                        "score": r['score'],
                        "threshold": r['threshold_used'],
                        "gates_passed": r['gates_passed'] or [],
                        "gates_failed": r['gates_failed'] or [],
                        "evidence": r['evidence'] or [],
                        "hypothesis_support": r['hypothesis_support'],
                        "reason": r['reason'],
                        "processing_time_ms": r['processing_time_ms'],
                        "timestamp": r['created_at'].isoformat() if r['created_at'] else None,
                    }
                    for r in rows
                ],
                "total": len(rows)
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get correlation audit: {e}")
        raise HTTPException(status_code=500, detail=str(e))
