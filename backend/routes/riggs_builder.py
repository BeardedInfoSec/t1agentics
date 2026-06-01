# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Riggs Playbook Builder API Routes

Endpoints for AI-powered playbook generation and optimization.
"""

import json
import logging
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional
from config.constants import PLATFORM_OWNER_TENANT_ID

from services.riggs_playbook_builder import (
    get_riggs_playbook_builder,
    PlaybookBuildRequest
)
from services.postgres_db import postgres_db
from dependencies.auth import get_current_user
from dependencies.license_checks import enforce_riggs_limit, enforce_feature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/riggs/builder", tags=["riggs-builder"], dependencies=[Depends(get_current_user)])


# ============================================================================
# Request/Response Models
# ============================================================================

class GeneratePlaybookRequest(BaseModel):
    """Request to generate a playbook."""
    requirements: str = Field(..., min_length=10, description="What the playbook should do")
    name: Optional[str] = Field(None, description="Playbook name (auto-generated if not provided)")
    alert_type: Optional[str] = None
    threat_type: Optional[str] = None
    severity: Optional[str] = None
    sample_alert: Optional[Dict[str, Any]] = None
    include_enrichment: bool = True
    include_approval_gates: bool = True
    auto_save: bool = False  # Automatically save to database
    # Tenant context the frontend collects before asking Riggs to generate.
    # Letting Riggs see what is actually configured prevents him from
    # inventing fictitious connectors or padding the playbook with
    # enrichment nodes that the platform already runs automatically.
    available_connectors: Optional[List[Dict[str, Any]]] = Field(
        None,
        description="Configured connector instances (id, name, vendor, category, supported actions)"
    )
    auto_enriched_ioc_types: Optional[List[str]] = Field(
        None,
        description="IOC types automatically enriched by the platform (e.g. ['ip','domain','url','hash'])"
    )


class OptimizePlaybookRequest(BaseModel):
    """Request to optimize an existing playbook."""
    playbook_id: str
    optimization_goals: List[str] = Field(
        default=["add_error_handling", "add_enrichment", "add_approval_gates"],
        description="What to optimize"
    )


class SuggestFromAlertsRequest(BaseModel):
    """Request to suggest playbook from alert patterns."""
    alert_type: str
    limit: int = Field(default=10, ge=5, le=100, description="Number of recent alerts to analyze")


class ConvertSoarRequest(BaseModel):
    """Request to convert a SOAR playbook using Riggs AI."""
    content: str = Field(..., min_length=10, description="Raw playbook content (JSON or YAML)")
    source_platform: str = Field(default="auto", description="Source platform or 'auto' for detection")
    python_code: Optional[str] = Field(None, description="Optional Python code accompanying the playbook")
    name_override: Optional[str] = Field(None, description="Override playbook name")


# ============================================================================
# Routes
# ============================================================================

@router.post("/convert")
async def convert_soar_playbook(
    request: ConvertSoarRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _feature: None = Depends(enforce_feature("soar_converter")),
):
    """
    Convert a SOAR playbook using Riggs AI.

    Instead of mechanical node-by-node mapping, Riggs reads the source
    playbook, understands its intent, and generates an optimal native
    T1 Agentics playbook.

    Supported platforms: XSOAR, Tines, Swimlane,
    Chronicle SOAR, QRadar SOAR (or auto-detect).
    """
    import time
    start_ms = time.time() * 1000

    try:
        builder = get_riggs_playbook_builder()

        # --- resolve tenant ---
        tenant_id = None
        try:
            tid = current_user.get('tenant_id') if isinstance(current_user, dict) else getattr(current_user, 'tenant_id', None)
            if tid:
                import uuid as _uuid
                tenant_id = tid if not isinstance(tid, str) else _uuid.UUID(tid)
        except Exception:
            pass

        # --- extract archives (tgz, gz) ---
        from routes.playbook_converters import extract_playbook_from_archive
        extracted = extract_playbook_from_archive(request.content)
        content = extracted.get('content', request.content) if isinstance(extracted, dict) else request.content
        python_code = extracted.get('python_code') if isinstance(extracted, dict) else None
        if request.python_code:
            python_code = request.python_code

        # --- detect platform ---
        from services.playbook_converters.base import detect_platform, SourcePlatform
        platform_str = request.source_platform.lower().strip()

        if platform_str == "auto":
            detected = detect_platform(content)
            if detected == SourcePlatform.UNKNOWN:
                raise HTTPException(status_code=400, detail="Could not auto-detect source platform. Please specify one.")
            platform_str = detected.value
        else:
            detected = SourcePlatform(platform_str)

        # --- get platform-specific parser ---
        from services.playbook_converters import (
            XSOARConverter, TinesConverter, SwimlaneConverter,
            ChronicleSoarConverter, QRadarSOARConverter, SentinelConverter,
            FortiSOARConverter, InsightConnectConverter, TheHiveConverter,
            ShuffleConverter, TorqConverter, ServiceNowSecOpsConverter,
            ExabeamConverter, BlinkOpsConverter, D3SecurityConverter,
            LogicHubConverter, ResolveConverter,
        )

        converters = {
            "xsoar": XSOARConverter,
            "tines": TinesConverter,
            "swimlane": SwimlaneConverter,
            "chronicle_soar": ChronicleSoarConverter,
            "qradar_soar": QRadarSOARConverter,
            "sentinel": SentinelConverter,
            "fortisoar": FortiSOARConverter,
            "insight_connect": InsightConnectConverter,
            "thehive": TheHiveConverter,
            "shuffle": ShuffleConverter,
            "torq": TorqConverter,
            "servicenow_secops": ServiceNowSecOpsConverter,
            "exabeam": ExabeamConverter,
            "blinkops": BlinkOpsConverter,
            "d3_security": D3SecurityConverter,
            "logichub": LogicHubConverter,
            "resolve": ResolveConverter,
        }

        converter_cls = converters.get(platform_str)
        if not converter_cls:
            raise HTTPException(status_code=400, detail=f"Unsupported platform: {platform_str}")

        converter = converter_cls()

        # --- parse source (get intermediate representation) ---
        if python_code and hasattr(converter, 'set_python_code'):
            converter.set_python_code(python_code)
        parsed = converter.parse(content)

        if not parsed.steps:
            raise HTTPException(status_code=400, detail="No steps found in the uploaded playbook.")

        # --- Riggs converts parsed playbook into native format ---
        playbook_data = await builder.convert_soar_playbook(
            parsed_playbook=parsed,
            source_platform=platform_str,
            raw_content=content,
            name_override=request.name_override,
            tenant_id=tenant_id,
        )

        # --- save to database ---
        async with postgres_db.tenant_acquire() as conn:
            import uuid as _uuid
            playbook_id = _uuid.uuid4()

            creator_id = None
            try:
                username = current_user.get('username') if isinstance(current_user, dict) else getattr(current_user, 'username', None)
                if username:
                    user_row = await conn.fetchrow("SELECT id FROM users WHERE username = $1", username)
                    if user_row:
                        creator_id = user_row["id"]
            except Exception:
                pass

            playbook_tenant_id = tenant_id
            if not playbook_tenant_id:
                playbook_tenant_id = _uuid.UUID(PLATFORM_OWNER_TENANT_ID)

            await conn.execute('''
                INSERT INTO playbooks (
                    id, name, description, canvas_data, tags, alert_types,
                    riggs_confidence, is_enabled, imported_from, import_metadata,
                    created_by, tenant_id, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12, NOW())
            ''',
                playbook_id,
                playbook_data['name'],
                playbook_data['description'],
                json.dumps(playbook_data['canvas_data']),
                playbook_data.get('tags', []),
                playbook_data.get('alert_types', []),
                playbook_data.get('riggs_confidence', 0.90),
                False,
                playbook_data.get('imported_from', platform_str),
                json.dumps(playbook_data.get('import_metadata', {})),
                creator_id,
                playbook_tenant_id,
            )

            playbook_data['id'] = str(playbook_id)
            playbook_data['saved'] = True

        elapsed_ms = time.time() * 1000 - start_ms

        return {
            "success": True,
            "playbook": playbook_data,
            "report": {
                "source_platform": platform_str,
                "original_step_count": len(parsed.steps),
                "conversion_method": "riggs_ai",
                "conversion_time_ms": round(elapsed_ms),
            },
            "message": f"Riggs converted {len(parsed.steps)}-step {platform_str.replace('_', ' ').title()} playbook into a native T1 playbook.",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Riggs SOAR conversion failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate")
async def generate_playbook(
    request: GeneratePlaybookRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _feature: None = Depends(enforce_feature("riggs_playbook_create")),
    _limit: None = Depends(enforce_riggs_limit("riggs_playbook_create")),
):
    """
    Generate a playbook from natural language requirements.

    Riggs uses AI to understand your requirements and create a complete playbook.

    **Examples:**
    - "Create a playbook that blocks phishing emails and notifies the SOC team"
    - "Build an automated response for malware detections that isolates the host"
    - "I need a playbook that enriches suspicious IPs and creates tickets"
    """
    try:
        builder = get_riggs_playbook_builder()

        # Resolve tenant_id from current user for Claude quota/billing
        tenant_id = None
        try:
            tid = current_user.get('tenant_id') if isinstance(current_user, dict) else getattr(current_user, 'tenant_id', None)
            if tid:
                tenant_id = tid if not isinstance(tid, str) else __import__('uuid').UUID(tid)
        except Exception:
            pass

        # Fetch the tenant's OWN SOPs so Riggs mirrors their documented
        # response procedure. Strictly tenant-scoped — platform curriculum
        # content is excluded. We synthesize an alert-shaped dict from the
        # request fields when no sample_alert was provided.
        relevant_sops: List[Dict[str, Any]] = []
        try:
            from services.sop_recommendation_service import get_sop_recommendation_service
            sop_service = get_sop_recommendation_service()
            sop_alert_data = request.sample_alert or {
                "title": request.name or request.requirements[:120],
                "description": request.requirements,
                "alert_type": request.alert_type,
                "type": request.alert_type,
                "severity": request.severity,
                "category": request.threat_type,
            }
            sop_result = await sop_service.recommend_for_alert(
                alert_data=sop_alert_data,
                limit=3,
                min_score=0.2,
            )
            for rec in sop_result.recommendations:
                relevant_sops.append({
                    "title": rec.title,
                    "category": rec.category,
                    "summary": rec.summary or "",
                    "key_steps": rec.key_steps or [],
                    "relevance_score": rec.relevance_score,
                    "match_reasons": rec.match_reasons or [],
                })
        except Exception as exc:
            logger.debug(f"[BUILD_WITH_RIGGS] SOP retrieval failed: {exc}")

        # When the tenant has real connectors, trust the LLM blueprint
        # (which now reads the connector list + SOPs) rather than running
        # the legacy post-processors that inject generic "virustotal" /
        # default approval gates on top.
        has_connectors = bool(request.available_connectors)

        # Build request
        build_request = PlaybookBuildRequest(
            name=request.name,
            requirements=request.requirements,
            alert_type=request.alert_type,
            threat_type=request.threat_type,
            severity=request.severity,
            sample_alert=request.sample_alert,
            include_enrichment=request.include_enrichment and not has_connectors,
            include_approval_gates=request.include_approval_gates and not has_connectors,
            available_connectors=request.available_connectors,
            auto_enriched_ioc_types=request.auto_enriched_ioc_types,
            relevant_sops=relevant_sops or None,
        )

        # Generate playbook
        playbook_data = await builder.generate_playbook_from_requirements(build_request, tenant_id=tenant_id)

        # Always save generated playbooks to database
        async with postgres_db.tenant_acquire() as conn:
            import uuid
            playbook_id = uuid.uuid4()

            # Resolve the user's UUID from their username
            creator_id = None
            try:
                username = current_user.get('username') if isinstance(current_user, dict) else getattr(current_user, 'username', None)
                if username:
                    user_row = await conn.fetchrow(
                        "SELECT id FROM users WHERE username = $1", username
                    )
                    if user_row:
                        creator_id = user_row["id"]
            except Exception:
                pass  # Non-critical — save without creator

            # Resolve tenant_id for the playbook record
            playbook_tenant_id = tenant_id
            if not playbook_tenant_id:
                try:
                    tid = current_user.get('tenant_id') if isinstance(current_user, dict) else getattr(current_user, 'tenant_id', None)
                    if tid:
                        playbook_tenant_id = tid if not isinstance(tid, str) else __import__('uuid').UUID(tid)
                except Exception:
                    pass
            if not playbook_tenant_id:
                playbook_tenant_id = __import__('uuid').UUID(PLATFORM_OWNER_TENANT_ID)

            await conn.execute('''
                INSERT INTO playbooks (
                    id, name, description, canvas_data, tags, alert_types,
                    riggs_confidence, is_enabled,
                    created_by, tenant_id, created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
            ''',
                playbook_id,
                playbook_data['name'],
                playbook_data['description'],
                json.dumps(playbook_data['canvas_data']),
                playbook_data.get('tags', []),
                playbook_data.get('alert_types', []),
                playbook_data.get('riggs_confidence', 0.85),
                False,  # Not enabled by default
                creator_id,
                playbook_tenant_id
            )

            playbook_data['id'] = str(playbook_id)
            playbook_data['saved'] = True

        return {
            "success": True,
            "playbook": playbook_data,
            "message": "Playbook generated successfully by Riggs"
        }

    except Exception as e:
        logger.error(f"Failed to generate playbook: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/optimize")
async def optimize_playbook(
    request: OptimizePlaybookRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _feature: None = Depends(enforce_feature("riggs_playbook_create")),
    _limit: None = Depends(enforce_riggs_limit("riggs_playbook_create")),
):
    """
    Optimize an existing playbook with Riggs's intelligence.

    Riggs will analyze the playbook and suggest/apply improvements:
    - Add error handling
    - Add enrichment nodes
    - Add approval gates for safety
    - Improve flow logic
    - Add best-practice nodes
    """
    try:
        from agents.riggs_playbook import get_riggs_playbook_agent

        agent = get_riggs_playbook_agent()

        # Analyze playbook
        analysis = await agent.analyze_playbook(request.playbook_id)

        if "error" in analysis:
            raise HTTPException(status_code=404, detail=analysis["error"])

        # Get recommendations
        recommendations = await agent.recommend_improvements(request.playbook_id)

        # Apply auto-apply recommendations
        applied = []
        for rec in recommendations:
            if rec.auto_apply and rec.type in request.optimization_goals:
                result = await agent.apply_recommendation(
                    playbook_id=request.playbook_id,
                    recommendation=rec
                )
                if result.get('success'):
                    applied.append(rec.dict())

        return {
            "success": True,
            "analysis": analysis,
            "recommendations": [r.dict() for r in recommendations],
            "applied_optimizations": applied,
            "message": f"Applied {len(applied)} optimizations"
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to optimize playbook: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/suggest-from-alerts")
async def suggest_playbook_from_alerts(
    request: SuggestFromAlertsRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _feature: None = Depends(enforce_feature("riggs_playbook_create")),
    _limit: None = Depends(enforce_riggs_limit("riggs_playbook_create")),
):
    """
    Suggest a playbook based on recurring alert patterns.

    Riggs analyzes recent alerts of a specific type and suggests
    an automated playbook to handle them.

    Useful for:
    - Creating playbooks for new alert types
    - Automating responses to common alerts
    - Learning from alert patterns
    """
    try:
        builder = get_riggs_playbook_builder()

        # Get recent alerts of this type
        async with postgres_db.tenant_acquire() as conn:
            alerts = await conn.fetch('''
                SELECT * FROM alerts
                WHERE type = $1
                OR alert_type = $1
                ORDER BY created_at DESC
                LIMIT $2
            ''', request.alert_type, request.limit)

            if len(alerts) < 5:
                return {
                    "success": False,
                    "message": f"Not enough alerts found ({len(alerts)} < 5). Need more data to suggest playbook."
                }

            alert_dicts = [dict(a) for a in alerts]

        # Analyze pattern and suggest playbook
        suggestion = await builder.suggest_playbook_from_alert_pattern(
            alert_type=request.alert_type,
            sample_alerts=alert_dicts
        )

        if not suggestion:
            return {
                "success": False,
                "message": "Could not identify a clear pattern for playbook suggestion"
            }

        return {
            "success": True,
            "suggestion": {
                "name": suggestion.name,
                "requirements": suggestion.requirements,
                "alert_type": suggestion.alert_type,
                "threat_type": suggestion.threat_type,
                "sample_alert": suggestion.sample_alert,
                "analyzed_count": len(alert_dicts)
            },
            "message": f"Analyzed {len(alert_dicts)} alerts and created playbook suggestion"
        }

    except Exception as e:
        logger.error(f"Failed to suggest playbook: {e}")
        raise HTTPException(status_code=500, detail=str(e))


class SuggestFromIntegrationsRequest(BaseModel):
    """Request for integration-aware playbook suggestions."""
    max_suggestions: int = Field(default=15, ge=1, le=30)
    include_gap_analysis: bool = Field(default=True)


@router.post("/suggest-from-integrations")
async def suggest_from_integrations(
    request: SuggestFromIntegrationsRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _feature: None = Depends(enforce_feature("riggs_suggestions")),
):
    """
    Riggs analyzes the tenant's installed integrations and suggests
    playbooks they can build right now.

    Also provides gap analysis: what integrations they're missing
    and what playbooks they'd unlock by adding them.

    Premium feature (PRO+ subscription required).
    """
    try:
        builder = get_riggs_playbook_builder()

        # Resolve tenant_id
        tenant_id = None
        try:
            tid = current_user.get('tenant_id') if isinstance(current_user, dict) else getattr(current_user, 'tenant_id', None)
            if tid:
                import uuid as _uuid
                tenant_id = tid if not isinstance(tid, str) else _uuid.UUID(tid)
        except Exception:
            pass

        if not tenant_id:
            import uuid as _uuid
            tenant_id = _uuid.UUID(PLATFORM_OWNER_TENANT_ID)

        result = await builder.suggest_from_integrations(
            tenant_id=tenant_id,
            max_suggestions=request.max_suggestions,
            include_gap_analysis=request.include_gap_analysis,
        )

        return {
            "success": True,
            **result,
            "message": f"Riggs generated {len(result.get('suggestions', []))} playbook suggestions based on your integrations.",
        }

    except Exception as e:
        logger.error(f"Failed to suggest from integrations: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/templates")
async def get_playbook_templates(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get common playbook templates.

    These are pre-defined templates for common security scenarios
    that can be customized.
    """
    templates = [
        {
            "id": "phishing_response",
            "name": "Phishing Email Response",
            "description": "Automated response to phishing emails with sender blocking",
            "requirements": "Block sender, quarantine email, enrich URLs, notify SOC team",
            "alert_type": "phishing",
            "complexity": "simple"
        },
        {
            "id": "malware_containment",
            "name": "Malware Containment",
            "description": "Isolate infected hosts and collect forensics",
            "requirements": "Isolate host, enrich file hash, collect forensics, create ticket",
            "alert_type": "malware",
            "complexity": "moderate"
        },
        {
            "id": "suspicious_login_investigation",
            "name": "Suspicious Login Investigation",
            "description": "Investigate and respond to suspicious login attempts",
            "requirements": "Check user context, verify location, check for MFA, notify user",
            "alert_type": "authentication",
            "complexity": "moderate"
        },
        {
            "id": "c2_communication_blocking",
            "name": "C2 Communication Blocking",
            "description": "Block command and control communication",
            "requirements": "Block IP/domain, isolate host, analyze traffic, escalate to SOC",
            "alert_type": "network",
            "complexity": "complex"
        },
        {
            "id": "ransomware_response",
            "name": "Ransomware Response",
            "description": "Emergency response to ransomware detection",
            "requirements": "Immediate isolation, disable user, snapshot backups, escalate to incident response",
            "alert_type": "ransomware",
            "complexity": "complex"
        }
    ]

    return {
        "templates": templates,
        "count": len(templates)
    }


@router.post("/templates/{template_id}/generate")
async def generate_from_template(
    template_id: str,
    customizations: Optional[Dict[str, Any]] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    _feature: None = Depends(enforce_feature("riggs_playbook_create")),
    _limit: None = Depends(enforce_riggs_limit("riggs_playbook_create")),
):
    """
    Generate a playbook from a template with optional customizations.
    """
    try:
        # Get template requirements
        templates_response = await get_playbook_templates(current_user)
        templates = templates_response["templates"]

        template = next((t for t in templates if t["id"] == template_id), None)
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")

        # Build generation request
        requirements = template["requirements"]
        if customizations and customizations.get("additional_requirements"):
            requirements += f"\n\nAdditional requirements: {customizations['additional_requirements']}"

        request = GeneratePlaybookRequest(
            name=template["name"],
            requirements=requirements,
            alert_type=template["alert_type"],
            threat_type=customizations.get("threat_type") if customizations else None,
            include_enrichment=True,
            include_approval_gates=True,
            auto_save=customizations.get("auto_save", False) if customizations else False
        )

        # Generate
        return await generate_playbook(request, current_user)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to generate from template: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/capabilities")
async def get_builder_capabilities():
    """
    Get Riggs playbook builder capabilities.

    Returns information about what Riggs can do when building playbooks.
    """
    return {
        "node_types": [
            {"type": "trigger", "category": "start", "description": "Start playbook on alert/event"},
            {"type": "riggs_analyze", "category": "analysis", "description": "AI-powered investigation"},
            {"type": "enrich", "category": "analysis", "description": "IOC/entity enrichment"},
            {"type": "action", "category": "response", "description": "Response action (block, isolate)"},
            {"type": "condition", "category": "logic", "description": "If/else branching"},
            {"type": "approval_gate", "category": "safety", "description": "Human approval required"},
            {"type": "notify", "category": "communication", "description": "Send notification"},
            {"type": "create_ticket", "category": "communication", "description": "Create ticket"},
            {"type": "python_code", "category": "custom", "description": "Custom Python logic"},
            {"type": "transform", "category": "data", "description": "Data transformation"},
            {"type": "delay", "category": "timing", "description": "Wait for duration"},
            {"type": "end", "category": "end", "description": "Complete playbook"}
        ],
        "integrations": [
            "virustotal", "abuseipdb", "shodan", "urlscan",
            "crowdstrike", "splunk", "slack", "jira"
        ],
        "threat_types": [
            "phishing", "malware", "ransomware", "c2_communication",
            "lateral_movement", "credential_access", "data_exfiltration"
        ],
        "optimization_goals": [
            "add_error_handling",
            "add_enrichment",
            "add_approval_gates",
            "improve_flow",
            "add_notifications"
        ]
    }
