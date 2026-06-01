# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook API Routes

Provides endpoints for:
- Playbook CRUD operations
- Playbook execution and control
- State management (enable/disable, riggs_allowed)
- Tagging and automatic selection
- Form submissions and file uploads
- Custom functions and lists
"""

import json
import uuid
import logging
from collections import Counter, defaultdict
from datetime import datetime
from typing import Dict, List, Optional
from fastapi import APIRouter, HTTPException, Depends, Query, UploadFile, File, Form, Request, Body, BackgroundTasks
from pydantic import BaseModel, Field

from dependencies.auth import require_permission, get_current_user, require_admin
from dependencies.license_checks import enforce_feature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/playbooks", tags=["playbooks"], dependencies=[Depends(get_current_user)])


async def _refresh_playbook_scheduler(req: Request):
    """Refresh playbook cron scheduler after changes."""
    try:
        scheduler = getattr(req.app.state, 'playbook_scheduler', None)
        if scheduler:
            await scheduler.refresh()
    except Exception as e:
        logger.warning(f"Playbook scheduler refresh error: {e}")


def _serialize_record(row):
    """Convert asyncpg record to JSON-friendly dict."""
    if not row:
        return None
    result = dict(row)
    for key, value in list(result.items()):
        if isinstance(value, uuid.UUID):
            result[key] = str(value)
            continue
        if isinstance(value, datetime):
            result[key] = value.isoformat()
            continue
        if isinstance(value, str):
            trimmed = value.strip()
            if trimmed.startswith("{") or trimmed.startswith("["):
                try:
                    result[key] = json.loads(value)
                except Exception:
                    pass
    return result


# ============================================================================
# Analysis Templates (Guardrails)
# ============================================================================

@router.get("/analysis-templates")
async def get_analysis_templates(user=Depends(get_current_user)):
    """Return curated analysis templates for the Analyze node (no system prompts exposed)."""
    from config.analysis_templates import TEMPLATE_LIST, TEMPLATE_CATEGORIES
    return {"templates": TEMPLATE_LIST, "categories": TEMPLATE_CATEGORIES}


# ============================================================================
# Request/Response Models
# ============================================================================

class PlaybookCreate(BaseModel):
    """Create playbook request."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    trigger_conditions: dict = Field(default_factory=dict)
    canvas_data: dict = Field(default_factory=lambda: {"nodes": [], "edges": []})
    tags: List[str] = Field(default_factory=list)
    alert_types: List[str] = Field(default_factory=list)
    severity_filter: List[str] = Field(default_factory=list)
    data_sources: List[str] = Field(default_factory=list)
    priority: int = Field(default=50, ge=1, le=100)
    riggs_allowed: bool = False
    trigger_timing: str = Field(
        default='post_triage', pattern=r'^(pre_triage|post_triage|on_demand|parallel)$'
    )


class PlaybookUpdate(BaseModel):
    """Update playbook request."""
    name: Optional[str] = None
    description: Optional[str] = None
    trigger_conditions: Optional[dict] = None
    canvas_data: Optional[dict] = None
    tags: Optional[List[str]] = None
    alert_types: Optional[List[str]] = None
    severity_filter: Optional[List[str]] = None
    data_sources: Optional[List[str]] = None
    priority: Optional[int] = Field(default=None, ge=1, le=100)
    # When the playbook runs relative to Riggs AI triage. Column is provisioned
    # by migration 016. Allowed values match the orchestrator's filters.
    trigger_timing: Optional[str] = Field(
        default=None, pattern=r'^(pre_triage|post_triage|on_demand|parallel)$'
    )
    # Whether Riggs may auto-execute this playbook. There are dedicated
    # /allow-riggs / /disallow-riggs endpoints, but PUT also accepts it so
    # the toggle persists when included in a full canvas save.
    riggs_allowed: Optional[bool] = None


class PlaybookExecuteRequest(BaseModel):
    """Execute playbook request."""
    trigger_context: dict = Field(default_factory=dict)
    alert_id: Optional[str] = None
    investigation_id: Optional[str] = None


class AutoExecuteRequest(BaseModel):
    """Auto-select and execute playbook request."""
    alert: dict
    alert_id: Optional[str] = None
    investigation_id: Optional[str] = None


class ApprovalAction(BaseModel):
    """Approval action request."""
    notes: Optional[str] = None


class FormSubmission(BaseModel):
    """Form submission request."""
    form_data: dict


class CustomFunctionCreate(BaseModel):
    """Create custom function request."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    code: str
    input_schema: dict = Field(default_factory=dict)
    output_schema: dict = Field(default_factory=dict)


class CustomListCreate(BaseModel):
    """Create custom list request."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    list_type: str = Field(..., pattern="^(allowlist|blocklist|lookup|enum)$")
    items: list = Field(default_factory=list)


class CustomListUpdate(BaseModel):
    """Update custom list request."""
    add_items: Optional[List] = None
    remove_items: Optional[List] = None


class PlaybookFormCreate(BaseModel):
    """Create webform request."""
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    fields: list = Field(default_factory=list)
    submit_action: str = Field(default="continue")
    submit_label: str = Field(default="Submit", max_length=100)
    require_auth: bool = True
    allowed_roles: List[str] = Field(default_factory=list)
    prefill_mapping: Dict[str, str] = Field(default_factory=dict)


# ============================================================================
# Playbook CRUD
# ============================================================================

@router.get("")
async def list_playbooks(
    enabled: Optional[bool] = None,
    riggs_allowed: Optional[bool] = None,
    tag: Optional[str] = None,
    alert_type: Optional[str] = None,
    limit: int = Query(default=50, le=100),
    offset: int = 0,
    user: Dict = Depends(require_permission("playbook:view")),
):
    """
    List playbooks with optional filters.
    """
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            # Build query
            conditions = []
            params = []
            param_idx = 1

            if enabled is not None:
                conditions.append(f"is_enabled = ${param_idx}")
                params.append(enabled)
                param_idx += 1

            if riggs_allowed is not None:
                conditions.append(f"riggs_allowed = ${param_idx}")
                params.append(riggs_allowed)
                param_idx += 1

            if tag:
                conditions.append(f"${param_idx} = ANY(tags)")
                params.append(tag)
                param_idx += 1

            if alert_type:
                conditions.append(f"${param_idx} = ANY(alert_types)")
                params.append(alert_type)
                param_idx += 1

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

            query = f'''
                SELECT id, name, description, is_enabled, riggs_allowed,
                       tags, alert_types, severity_filter, data_sources,
                       priority, trigger_timing, version, created_at, updated_at
                FROM playbooks
                {where_clause}
                ORDER BY priority DESC, updated_at DESC
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
            '''
            params.extend([limit, offset])

            rows = await conn.fetch(query, *params)

            # Get total count
            count_query = f"SELECT COUNT(*) FROM playbooks {where_clause}"
            total = await conn.fetchval(count_query, *params[:-2]) if params[:-2] else await conn.fetchval("SELECT COUNT(*) FROM playbooks")

            playbooks = []
            for row in rows:
                pb = dict(row)
                pb['id'] = str(pb['id'])
                if pb.get('created_at'):
                    pb['created_at'] = pb['created_at'].isoformat()
                if pb.get('updated_at'):
                    pb['updated_at'] = pb['updated_at'].isoformat()
                playbooks.append(pb)

            return {
                "playbooks": playbooks,
                "total": total,
                "limit": limit,
                "offset": offset
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list playbooks: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("")
async def create_playbook(
    request: PlaybookCreate,
    req: Request,
    user: Dict = Depends(require_permission("playbook:create")),
    _gate: None = Depends(enforce_feature("custom_playbooks")),
):
    """
    Create a new playbook. Requires custom_playbooks feature.
    """
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                INSERT INTO playbooks (
                    tenant_id, name, description, trigger_conditions, canvas_data,
                    tags, alert_types, severity_filter, data_sources, priority,
                    riggs_allowed, trigger_timing
                ) VALUES (
                    current_setting('app.current_tenant_id')::uuid,
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
                )
                RETURNING *
            ''',
                request.name,
                request.description,
                json.dumps(request.trigger_conditions),
                json.dumps(request.canvas_data),
                request.tags,
                request.alert_types,
                request.severity_filter,
                request.data_sources,
                request.priority,
                request.riggs_allowed,
                request.trigger_timing,
            )

            result = dict(row)
            result['id'] = str(result['id'])
            if result.get('created_at'):
                result['created_at'] = result['created_at'].isoformat()
            if result.get('updated_at'):
                result['updated_at'] = result['updated_at'].isoformat()

            await _refresh_playbook_scheduler(req)
            return result

    except Exception as e:
        logger.error(f"Failed to create playbook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Static routes (must be defined BEFORE dynamic /{playbook_id} routes)
# ============================================================================

@router.get("/config/integrations")
async def get_playbook_integrations(
    category: Optional[str] = Query(None, description="Filter by category: action, notify, ticket, enrich"),
    user: Dict = Depends(require_permission("playbook:view")),
):
    """
    Get integration instances available for playbook node configuration.
    Returns unified list from both legacy integrations and integrations_v2 framework.
    """
    try:
        from services.postgres_db import postgres_db

        results = []
        connect_results = []

        # 1. Get T1 Connect instances from database (preferred source)
        if postgres_db.connected and postgres_db.pool:
            try:
                async with postgres_db.tenant_acquire() as conn:
                    rows = await conn.fetch("""
                        SELECT
                            i.id as instance_id,
                            i.connector_id as definition_id,
                            i.display_name as instance_name,
                            i.enabled,
                            d.name as definition_name,
                            d.vendor,
                            d.category,
                            d.actions as definition_data
                        FROM connect_instances i
                        JOIN connector_definitions d ON i.connector_id = d.id
                        WHERE i.enabled = true AND d.enabled = true
                    """)

                    for row in rows:
                        row_dict = dict(row)
                        # actions is a JSONB array of action objects from connector_definitions
                        actions_data = row_dict.get('definition_data', [])
                        if isinstance(actions_data, str):
                            actions_data = json.loads(actions_data)
                        if not isinstance(actions_data, list):
                            actions_data = []

                        connect_category = row_dict.get('category', 'custom')
                        if category and connect_category != category:
                            continue

                        # Map T1 Connect actions → VPE endpoints
                        endpoints = []
                        for action in actions_data:
                            params = []
                            for p in (action.get('parameters') or []):
                                params.append({
                                    "name": p.get('name', ''),
                                    "type": p.get('type', 'string'),
                                    "required": p.get('required', False),
                                    "description": p.get('description', ''),
                                    "contains": p.get('contains', []),
                                    "default": p.get('default'),
                                })
                            endpoints.append({
                                "id": action.get('id', action.get('name', '')),
                                "name": action.get('name', action.get('id', '')),
                                "description": action.get('description', ''),
                                "observable_type": action.get('observable_type', ''),
                                "action_type": action.get('action_type', ''),
                                "read_only": action.get('read_only', False),
                                "parameters": params
                            })

                        connect_results.append({
                            "id": row_dict['definition_id'],
                            "instance_id": str(row_dict['instance_id']),
                            "name": row_dict.get('instance_name') or row_dict.get('definition_name'),
                            "type": connect_category,
                            "category": connect_category,
                            "vendor": row_dict.get('vendor'),
                            "enabled": row_dict.get('enabled', True),
                            "source": "connect",
                            "endpoints": endpoints
                        })
            except Exception as e:
                logger.debug(f"T1 Connect integrations not available: {e}")

        if connect_results:
            # T1 Connect has instances — use only those (authoritative source)
            results = connect_results
        else:
            # Fall back to legacy registry only when no T1 Connect instances exist
            try:
                from integrations.registry.integration_registry import get_registry
                registry = get_registry()
                legacy_integrations = registry.list(enabled_only=True)

                for integration in legacy_integrations:
                    int_type = integration.type.value if hasattr(integration.type, 'value') else str(integration.type)
                    int_category = _map_type_to_category(int_type)

                    if category and int_category != category:
                        continue

                    endpoints = []
                    for action in getattr(integration, 'actions', []):
                        endpoints.append({
                            "id": action.id,
                            "name": getattr(action, 'name', None) or action.id,
                            "description": getattr(action, 'description', '') or "",
                            "parameters": []
                        })

                    results.append({
                        "id": integration.id,
                        "instance_id": integration.id,
                        "name": integration.name,
                        "type": int_type,
                        "category": int_category,
                        "vendor": getattr(integration, 'vendor', ''),
                        "enabled": integration.enabled,
                        "source": "legacy",
                        "endpoints": endpoints
                    })
            except Exception as e:
                logger.debug(f"Legacy integrations not available: {e}")

        return {"integrations": results, "total": len(results)}

    except Exception as e:
        logger.error(f"Failed to get playbook integrations: {e}")
        return {"integrations": [], "total": 0}


def _map_type_to_category(int_type: str) -> str:
    """Map integration type to playbook category."""
    mapping = {
        "threat_intel": "enrich", "enrichment": "enrich",
        "edr": "action", "soar": "action", "network": "action",
        "firewall": "action", "siem": "action", "cloud": "action",
        "identity": "action", "custom": "action",
        "chat": "notify", "email": "notify", "communication": "notify",
        "ticketing": "ticket", "itsm": "ticket",
    }
    return mapping.get(int_type.lower(), "action")


# Static routes for lists and functions (must be before /{playbook_id})
@router.get("/lists")
async def get_playbook_lists(user: Dict = Depends(require_permission("playbook:view"))):
    """List all custom lists."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            return {"lists": []}

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, name, description, list_type, item_count, created_at, updated_at
                FROM playbook_lists
                ORDER BY name
            ''')

            lists = []
            for row in rows:
                lst = dict(row)
                lst['id'] = str(lst['id'])
                if lst.get('created_at'):
                    lst['created_at'] = lst['created_at'].isoformat()
                if lst.get('updated_at'):
                    lst['updated_at'] = lst['updated_at'].isoformat()
                lists.append(lst)

            return {"lists": lists}

    except Exception as e:
        error_str = str(e).lower()
        if 'undefined' in error_str or 'does not exist' in error_str or 'playbook_lists' in error_str:
            logger.warning("playbook_lists table missing; returning empty list")
            return {"lists": []}
        logger.error(f"Failed to list lists: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/functions")
async def get_playbook_functions(user: Dict = Depends(require_permission("playbook:view"))):
    """List all custom functions."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            return {"functions": []}

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, name, description, status, created_at
                FROM playbook_functions
                ORDER BY name
            ''')

            functions = []
            for row in rows:
                func = dict(row)
                func['id'] = str(func['id'])
                if func.get('created_at'):
                    func['created_at'] = func['created_at'].isoformat()
                functions.append(func)

            return {"functions": functions}

    except Exception as e:
        error_str = str(e).lower()
        if 'undefined' in error_str or 'does not exist' in error_str or 'playbook_functions' in error_str:
            logger.warning("playbook_functions table missing; returning empty list")
            return {"functions": []}
        logger.error(f"Failed to list functions: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/tags")
async def get_all_tags(user: Dict = Depends(require_permission("playbook:view"))):
    """Get all unique tags used across playbooks."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            return {"tags": []}

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT DISTINCT unnest(tags) as tag
                FROM playbooks
                WHERE tags IS NOT NULL AND tags != '{}'
                ORDER BY tag
            ''')
            return {"tags": [row['tag'] for row in rows]}

    except Exception as e:
        logger.error(f"Failed to get tags: {e}")
        return {"tags": []}


@router.get("/templates")
async def get_playbook_templates(user: Dict = Depends(require_permission("playbook:view"))):
    """Get available playbook templates."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            return {"templates": []}

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, name, description, category, canvas_data, created_at
                FROM playbook_templates
                ORDER BY name
            ''')

            templates = []
            for row in rows:
                t = dict(row)
                t['id'] = str(t['id'])
                if t.get('created_at'):
                    t['created_at'] = t['created_at'].isoformat()
                templates.append(t)

            return {"templates": templates}

    except Exception as e:
        error_str = str(e).lower()
        if 'does not exist' in error_str or 'playbook_templates' in error_str:
            return {"templates": []}
        logger.error(f"Failed to get templates: {e}")
        return {"templates": []}


@router.get("/forms")
async def get_playbook_forms(user: Dict = Depends(require_permission("playbook:view"))):
    """List all playbook forms."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            return {"forms": []}

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, name, description, fields, created_at
                FROM playbook_forms
                ORDER BY name
            ''')

            forms = []
            for row in rows:
                f = dict(row)
                f['id'] = str(f['id'])
                if f.get('created_at'):
                    f['created_at'] = f['created_at'].isoformat()
                forms.append(f)

            return {"forms": forms}

    except Exception as e:
        error_str = str(e).lower()
        if 'does not exist' in error_str or 'playbook_forms' in error_str:
            return {"forms": []}
        logger.error(f"Failed to list forms: {e}")
        return {"forms": []}


# ============================================================================
# Community submission workflow
# (Static routes — must be defined BEFORE /{playbook_id} dynamic routes
#  so FastAPI doesn't treat "community-submissions" as a playbook id.)
# ============================================================================

class PlaybookCommunitySubmitRequest(BaseModel):
    """Submit one of the tenant's own playbooks for community review."""
    playbook_id: str = Field(..., description="The playbook to submit")
    submission_notes: Optional[str] = Field(
        None, max_length=2000,
        description="Optional message to the reviewer (what does this do, who is it for, etc.)"
    )


class PlaybookCommunityReviewRequest(BaseModel):
    """Approve or reject a pending playbook community submission."""
    reviewer_notes: Optional[str] = Field(None, max_length=2000)


async def _playbook_admin_recipients():
    """Resolve platform-admin email recipients. Mirrors the helpers in
    routes/registration.py and services/cost_summary_scheduler.py."""
    from services.postgres_db import postgres_db
    import os
    recipients = []
    try:
        if postgres_db.connected and postgres_db.pool:
            async with postgres_db.pool.acquire() as conn:
                await conn.execute("SET app.is_platform_admin = 'true'")
                rows = await conn.fetch(
                    "SELECT email FROM platform_admins WHERE is_active = true"
                )
                recipients = [r["email"] for r in rows]
    except Exception as exc:
        logger.warning("[PLAYBOOK_SUBMIT] platform_admins lookup failed: %s", exc)
    if not recipients:
        admin_email = os.environ.get("ADMIN_EMAIL")
        if admin_email:
            recipients = [admin_email]
    return recipients


async def _send_playbook_submission_notification(
    *, playbook_name: str, playbook_description: str,
    node_count: int, edge_count: int,
    tenant_slug: str, submitter_username: str, submitter_email: str,
    submission_notes: str, submission_id: str,
):
    """Email platform admins that a new playbook submission needs review."""
    try:
        import os
        from services.email_service import get_email_service
        from services.email_templates import render_admin_playbook_submission

        recipients = await _playbook_admin_recipients()
        if not recipients:
            logger.warning("[PLAYBOOK_SUBMIT] No admin recipients; skipping email")
            return

        site_url = os.environ.get("PUBLIC_SITE_URL", "https://t1agentics.ai").rstrip("/")
        review_url = f"{site_url}/playbooks/community"  # admin lands on the playbook marketplace; submissions surface there

        html = render_admin_playbook_submission(
            playbook_name=playbook_name,
            playbook_description=playbook_description or "",
            node_count=node_count,
            edge_count=edge_count,
            tenant_slug=tenant_slug,
            submitter_username=submitter_username,
            submitter_email=submitter_email or "",
            submission_notes=submission_notes or "",
            review_url=review_url,
        )
        subject = f"[Playbook] {tenant_slug} submitted: {playbook_name[:80]}"
        svc = get_email_service()
        await svc.send_email(recipients, subject, html)
    except Exception as exc:
        logger.error("[PLAYBOOK_SUBMIT] notification email failed: %s", exc)


@router.post("/community-submissions")
async def submit_playbook_to_community(
    request: PlaybookCommunitySubmitRequest,
    background_tasks: BackgroundTasks,
    user: Dict = Depends(require_permission("playbook:edit")),
):
    """
    Submit one of the tenant's playbooks for community marketplace review.
    Notifies platform admins via email.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        playbook_uuid = uuid.UUID(request.playbook_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid playbook_id")

    async with postgres_db.tenant_acquire() as conn:
        # Verify the playbook exists, belongs to this tenant, and pull metadata
        # for the notification email + duplicate check.
        pb = await conn.fetchrow(
            "SELECT id, name, description, canvas_data, tenant_id FROM playbooks WHERE id = $1",
            playbook_uuid,
        )
        if not pb:
            raise HTTPException(status_code=404, detail="Playbook not found")

        # Block resubmits while one is still pending.
        existing = await conn.fetchrow(
            """SELECT id, status FROM playbook_community_submissions
                WHERE playbook_id = $1 AND status = 'pending'""",
            playbook_uuid,
        )
        if existing:
            raise HTTPException(
                status_code=409,
                detail="A submission for this playbook is already pending review.",
            )

        canvas = pb["canvas_data"]
        if isinstance(canvas, str):
            try:
                canvas = json.loads(canvas)
            except Exception:
                canvas = {}
        node_count = len(canvas.get("nodes") or [])
        edge_count = len(canvas.get("edges") or [])

        tenant_row = await conn.fetchrow(
            "SELECT slug FROM tenants WHERE id = $1",
            pb["tenant_id"],
        )
        tenant_slug = tenant_row["slug"] if tenant_row else str(pb["tenant_id"])[:8]

        submitter_username = (user.get("username") or user.get("email") or "unknown")
        submitter_email = user.get("email") or ""

        row = await conn.fetchrow(
            """
            INSERT INTO playbook_community_submissions
                (playbook_id, tenant_id, submitted_by, submitter_email, submission_notes)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, status, created_at
            """,
            playbook_uuid,
            pb["tenant_id"],
            submitter_username,
            submitter_email,
            request.submission_notes,
        )

    # Background: email the admins so review can happen from inbox.
    background_tasks.add_task(
        _send_playbook_submission_notification,
        playbook_name=pb["name"],
        playbook_description=pb["description"] or "",
        node_count=node_count,
        edge_count=edge_count,
        tenant_slug=tenant_slug,
        submitter_username=submitter_username,
        submitter_email=submitter_email,
        submission_notes=request.submission_notes or "",
        submission_id=str(row["id"]),
    )

    return {
        "submission_id": str(row["id"]),
        "playbook_id": str(playbook_uuid),
        "status": row["status"],
        "created_at": row["created_at"].isoformat() if row["created_at"] else None,
    }


@router.get("/community-submissions/mine")
async def list_my_playbook_submissions(
    user: Dict = Depends(get_current_user),
):
    """Return this tenant's playbook submissions so the UI can show
    'Submitted / Approved / Rejected' state next to each playbook."""
    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")
    async with postgres_db.tenant_acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id, playbook_id, status, submission_notes, reviewer_notes,
                   reviewed_by, reviewed_at, template_id, created_at
              FROM playbook_community_submissions
             ORDER BY created_at DESC
            """
        )
    return {
        "submissions": [
            {
                "submission_id": str(r["id"]),
                "playbook_id": str(r["playbook_id"]),
                "status": r["status"],
                "submission_notes": r["submission_notes"],
                "reviewer_notes": r["reviewer_notes"],
                "reviewed_by": r["reviewed_by"],
                "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
                "template_id": str(r["template_id"]) if r["template_id"] else None,
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


@router.get("/community-submissions")
async def list_playbook_submissions(
    status: Optional[str] = Query("pending", description="pending | approved | rejected | all"),
    user: Dict = Depends(require_admin),
):
    """Platform admin: list playbook submissions for review."""
    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")
    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        if status and status != "all":
            rows = await conn.fetch(
                """
                SELECT s.id, s.playbook_id, s.tenant_id, t.slug AS tenant_slug,
                       s.submitted_by, s.submitter_email, s.submission_notes,
                       s.status, s.reviewer_notes, s.reviewed_by, s.reviewed_at,
                       s.template_id, s.created_at,
                       p.name AS playbook_name, p.description AS playbook_description
                  FROM playbook_community_submissions s
                  LEFT JOIN tenants  t ON t.id = s.tenant_id
                  LEFT JOIN playbooks p ON p.id = s.playbook_id
                 WHERE s.status = $1
                 ORDER BY s.created_at DESC
                """,
                status,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT s.id, s.playbook_id, s.tenant_id, t.slug AS tenant_slug,
                       s.submitted_by, s.submitter_email, s.submission_notes,
                       s.status, s.reviewer_notes, s.reviewed_by, s.reviewed_at,
                       s.template_id, s.created_at,
                       p.name AS playbook_name, p.description AS playbook_description
                  FROM playbook_community_submissions s
                  LEFT JOIN tenants  t ON t.id = s.tenant_id
                  LEFT JOIN playbooks p ON p.id = s.playbook_id
                 ORDER BY s.created_at DESC
                """
            )
    return {
        "submissions": [
            {
                "submission_id": str(r["id"]),
                "playbook_id": str(r["playbook_id"]),
                "playbook_name": r["playbook_name"],
                "playbook_description": r["playbook_description"],
                "tenant_slug": r["tenant_slug"],
                "submitted_by": r["submitted_by"],
                "submitter_email": r["submitter_email"],
                "submission_notes": r["submission_notes"],
                "status": r["status"],
                "reviewer_notes": r["reviewer_notes"],
                "reviewed_by": r["reviewed_by"],
                "reviewed_at": r["reviewed_at"].isoformat() if r["reviewed_at"] else None,
                "template_id": str(r["template_id"]) if r["template_id"] else None,
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
            }
            for r in rows
        ]
    }


@router.post("/community-submissions/{submission_id}/approve")
async def approve_playbook_submission(
    submission_id: str,
    request: PlaybookCommunityReviewRequest,
    user: Dict = Depends(require_admin),
):
    """Platform admin: approve a submission. Clones the playbook into
    playbook_templates (source='community') so all tenants can install it."""
    from services.postgres_db import postgres_db
    try:
        sub_uuid = uuid.UUID(submission_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid submission_id")

    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        sub = await conn.fetchrow(
            "SELECT * FROM playbook_community_submissions WHERE id = $1",
            sub_uuid,
        )
        if not sub:
            raise HTTPException(status_code=404, detail="Submission not found")
        if sub["status"] != "pending":
            raise HTTPException(status_code=409, detail=f"Submission already {sub['status']}")

        pb = await conn.fetchrow(
            "SELECT * FROM playbooks WHERE id = $1",
            sub["playbook_id"],
        )
        if not pb:
            raise HTTPException(status_code=404, detail="Original playbook no longer exists")

        # Clone into playbook_templates as a community-source template.
        template_row = await conn.fetchrow(
            """
            INSERT INTO playbook_templates
                (name, description, category, canvas_data, trigger_conditions,
                 tags, alert_types, source, created_by, severity_filter,
                 author, version, tenant_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'community', $8, $9, $10, 1, NULL)
            RETURNING id
            """,
            pb["name"],
            pb["description"],
            "community",
            json.dumps(pb["canvas_data"]) if not isinstance(pb["canvas_data"], str) else pb["canvas_data"],
            json.dumps(pb["trigger_conditions"]) if pb["trigger_conditions"] and not isinstance(pb["trigger_conditions"], str) else (pb["trigger_conditions"] or "{}"),
            pb["tags"] or [],
            pb["alert_types"] or [],
            sub["submitted_by"],
            pb["severity_filter"] or [],
            sub["submitted_by"],
        )

        await conn.execute(
            """
            UPDATE playbook_community_submissions
               SET status='approved', reviewer_notes=$2, reviewed_by=$3,
                   reviewed_at=NOW(), template_id=$4, updated_at=NOW()
             WHERE id=$1
            """,
            sub_uuid, request.reviewer_notes,
            user.get("username") or user.get("email") or "admin",
            template_row["id"],
        )

    return {
        "submission_id": str(sub_uuid),
        "status": "approved",
        "template_id": str(template_row["id"]),
    }


@router.post("/community-submissions/{submission_id}/reject")
async def reject_playbook_submission(
    submission_id: str,
    request: PlaybookCommunityReviewRequest,
    user: Dict = Depends(require_admin),
):
    """Platform admin: reject a submission. No template is created."""
    from services.postgres_db import postgres_db
    try:
        sub_uuid = uuid.UUID(submission_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid submission_id")
    async with postgres_db.pool.acquire() as conn:
        await conn.execute("SET app.is_platform_admin = 'true'")
        result = await conn.execute(
            """
            UPDATE playbook_community_submissions
               SET status='rejected', reviewer_notes=$2, reviewed_by=$3,
                   reviewed_at=NOW(), updated_at=NOW()
             WHERE id=$1 AND status='pending'
            """,
            sub_uuid, request.reviewer_notes,
            user.get("username") or user.get("email") or "admin",
        )
        if result.split()[-1] == "0":
            raise HTTPException(status_code=409, detail="Submission not pending")
    return {"submission_id": str(sub_uuid), "status": "rejected"}


# ============================================================================
# Dynamic routes (with path parameters)
# ============================================================================

@router.get("/{playbook_id}")
async def get_playbook(playbook_id: str, user: Dict = Depends(require_permission("playbook:view"))):
    """
    Get a single playbook by ID.
    """
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM playbooks WHERE id = $1",
                uuid.UUID(playbook_id)
            )

            if not row:
                raise HTTPException(status_code=404, detail="Playbook not found")

            result = dict(row)
            result['id'] = str(result['id'])

            # Parse JSONB fields
            for field in ['trigger_conditions', 'canvas_data', 'riggs_suggestions']:
                if result.get(field) and isinstance(result[field], str):
                    result[field] = json.loads(result[field])

            # Convert timestamps
            for field in ['created_at', 'updated_at', 'last_riggs_review']:
                if result.get(field):
                    result[field] = result[field].isoformat()

            return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get playbook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/{playbook_id}")
async def update_playbook(playbook_id: str, request: PlaybookUpdate, req: Request, user: Dict = Depends(require_permission("playbook:edit"))):
    """
    Update an existing playbook.
    """
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        # Build dynamic update
        updates = []
        params = []
        param_idx = 1

        if request.name is not None:
            updates.append(f"name = ${param_idx}")
            params.append(request.name)
            param_idx += 1

        if request.description is not None:
            updates.append(f"description = ${param_idx}")
            params.append(request.description)
            param_idx += 1

        if request.trigger_conditions is not None:
            updates.append(f"trigger_conditions = ${param_idx}")
            params.append(json.dumps(request.trigger_conditions))
            param_idx += 1

        if request.canvas_data is not None:
            updates.append(f"canvas_data = ${param_idx}")
            params.append(json.dumps(request.canvas_data))
            param_idx += 1

        if request.tags is not None:
            updates.append(f"tags = ${param_idx}")
            params.append(request.tags)
            param_idx += 1

        if request.alert_types is not None:
            updates.append(f"alert_types = ${param_idx}")
            params.append(request.alert_types)
            param_idx += 1

        if request.severity_filter is not None:
            updates.append(f"severity_filter = ${param_idx}")
            params.append(request.severity_filter)
            param_idx += 1

        if request.data_sources is not None:
            updates.append(f"data_sources = ${param_idx}")
            params.append(request.data_sources)
            param_idx += 1

        if request.priority is not None:
            updates.append(f"priority = ${param_idx}")
            params.append(request.priority)
            param_idx += 1

        if request.trigger_timing is not None:
            updates.append(f"trigger_timing = ${param_idx}")
            params.append(request.trigger_timing)
            param_idx += 1

        if request.riggs_allowed is not None:
            updates.append(f"riggs_allowed = ${param_idx}")
            params.append(request.riggs_allowed)
            param_idx += 1

        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")

        updates.append(f"version = version + 1")
        params.append(uuid.UUID(playbook_id))

        async with postgres_db.tenant_acquire() as conn:
            # Snapshot current state as a version before overwriting
            current = await conn.fetchrow(
                "SELECT version, canvas_data, name, description FROM playbooks WHERE id = $1",
                uuid.UUID(playbook_id)
            )
            if current:
                cur_version = current['version'] or 0
                cur_canvas = current['canvas_data']
                if isinstance(cur_canvas, str):
                    cur_canvas = json.loads(cur_canvas) if cur_canvas.strip() else {}
                await conn.execute('''
                    INSERT INTO playbook_versions (playbook_id, version_number, canvas_data, metadata, change_summary, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6)
                ''',
                    uuid.UUID(playbook_id),
                    cur_version,
                    json.dumps(cur_canvas) if isinstance(cur_canvas, dict) else str(cur_canvas),
                    json.dumps({"name": current['name'], "description": current['description'] or ""}),
                    f"Auto-snapshot before update to v{cur_version + 1}",
                    user.get("tenant_id")
                )

            row = await conn.fetchrow(f'''
                UPDATE playbooks
                SET {', '.join(updates)}
                WHERE id = ${param_idx}
                RETURNING *
            ''', *params)

            if not row:
                raise HTTPException(status_code=404, detail="Playbook not found")

            result = dict(row)
            result['id'] = str(result['id'])
            await _refresh_playbook_scheduler(req)
            return {"message": "Playbook updated", "playbook": result}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update playbook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/{playbook_id}")
async def delete_playbook(playbook_id: str, req: Request, user: Dict = Depends(require_permission("playbook:delete"))):
    """
    Delete a playbook.
    """
    try:
        playbook_uuid = uuid.UUID(playbook_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid playbook ID format")
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute(
                "DELETE FROM playbooks WHERE id = $1",
                playbook_uuid
            )

            if result == "DELETE 0":
                raise HTTPException(status_code=404, detail="Playbook not found")

            await _refresh_playbook_scheduler(req)
            return {"message": "Playbook deleted", "id": playbook_id}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete playbook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Revision History
# ============================================================================

@router.get("/{playbook_id}/versions")
async def list_playbook_versions(playbook_id: str, limit: int = Query(50, ge=1, le=200), user: Dict = Depends(require_permission("playbook:view"))):
    """List all saved versions for a playbook."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, playbook_id, version_number, metadata, change_summary,
                       created_by, created_at
                FROM playbook_versions
                WHERE playbook_id = $1
                ORDER BY version_number DESC
                LIMIT $2
            ''', uuid.UUID(playbook_id), limit)

            versions = [_serialize_record(r) for r in rows]
            return {"versions": versions, "count": len(versions)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list versions: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{playbook_id}/versions/{version_id}/restore")
async def restore_playbook_version(playbook_id: str, version_id: str, req: Request, user: Dict = Depends(require_permission("playbook:edit"))):
    """Restore a playbook to a previous version."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            # Get the version to restore
            version = await conn.fetchrow(
                "SELECT * FROM playbook_versions WHERE id = $1 AND playbook_id = $2",
                uuid.UUID(version_id), uuid.UUID(playbook_id)
            )
            if not version:
                raise HTTPException(status_code=404, detail="Version not found")

            # Snapshot current state before restoring
            current = await conn.fetchrow(
                "SELECT version, canvas_data, name, description FROM playbooks WHERE id = $1",
                uuid.UUID(playbook_id)
            )
            if current:
                cur_canvas = current['canvas_data']
                if isinstance(cur_canvas, str):
                    cur_canvas = json.loads(cur_canvas) if cur_canvas.strip() else {}
                await conn.execute('''
                    INSERT INTO playbook_versions (playbook_id, version_number, canvas_data, metadata, change_summary, tenant_id)
                    VALUES ($1, $2, $3, $4, $5, $6)
                ''',
                    uuid.UUID(playbook_id),
                    current['version'] or 0,
                    json.dumps(cur_canvas) if isinstance(cur_canvas, dict) else str(cur_canvas),
                    json.dumps({"name": current['name'], "description": current['description'] or ""}),
                    f"Auto-snapshot before restore to v{version['version_number']}",
                    user.get("tenant_id")
                )

            # Restore canvas_data from the version
            restore_canvas = version['canvas_data']
            if isinstance(restore_canvas, str):
                restore_canvas = json.loads(restore_canvas)

            restore_meta = version['metadata']
            if isinstance(restore_meta, str):
                restore_meta = json.loads(restore_meta)

            # Update the playbook
            updates = ["canvas_data = $1", "version = version + 1"]
            params = [json.dumps(restore_canvas)]
            if restore_meta and restore_meta.get('name'):
                updates.append("name = $2")
                params.append(restore_meta['name'])
                params.append(uuid.UUID(playbook_id))
                row = await conn.fetchrow(
                    f"UPDATE playbooks SET {', '.join(updates)} WHERE id = $3 RETURNING *",
                    *params
                )
            else:
                params.append(uuid.UUID(playbook_id))
                row = await conn.fetchrow(
                    f"UPDATE playbooks SET {', '.join(updates)} WHERE id = $2 RETURNING *",
                    *params
                )

            result = _serialize_record(row)
            await _refresh_playbook_scheduler(req)
            return {
                "message": f"Restored to version {version['version_number']}",
                "playbook": result
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to restore version: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# State Management
# ============================================================================

@router.post("/{playbook_id}/enable")
async def enable_playbook(playbook_id: str, req: Request, user: Dict = Depends(require_permission("playbook:edit"))):
    """Enable a playbook."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE playbooks SET is_enabled = true WHERE id = $1",
                uuid.UUID(playbook_id)
            )

        await _refresh_playbook_scheduler(req)
        return {"message": "Playbook enabled", "id": playbook_id, "is_enabled": True}

    except Exception as e:
        logger.error(f"Failed to enable playbook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{playbook_id}/disable")
async def disable_playbook(playbook_id: str, req: Request, user: Dict = Depends(require_permission("playbook:edit"))):
    """Disable a playbook."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE playbooks SET is_enabled = false WHERE id = $1",
                uuid.UUID(playbook_id)
            )

        await _refresh_playbook_scheduler(req)
        return {"message": "Playbook disabled", "id": playbook_id, "is_enabled": False}

    except Exception as e:
        logger.error(f"Failed to disable playbook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{playbook_id}/allow-riggs")
async def allow_riggs(playbook_id: str, user: Dict = Depends(require_permission("playbook:edit"))):
    """Allow Riggs to execute this playbook autonomously."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE playbooks SET riggs_allowed = true WHERE id = $1",
                uuid.UUID(playbook_id)
            )

        return {"message": "Riggs allowed", "id": playbook_id, "riggs_allowed": True}

    except Exception as e:
        logger.error(f"Failed to allow Riggs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{playbook_id}/disallow-riggs")
async def disallow_riggs(playbook_id: str, user: Dict = Depends(require_permission("playbook:edit"))):
    """Revoke Riggs autonomous execution permission."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE playbooks SET riggs_allowed = false WHERE id = $1",
                uuid.UUID(playbook_id)
            )

        return {"message": "Riggs disallowed", "id": playbook_id, "riggs_allowed": False}

    except Exception as e:
        logger.error(f"Failed to disallow Riggs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Tagging
# ============================================================================

@router.put("/{playbook_id}/tags")
async def update_tags(playbook_id: str, tags: List[str], user: Dict = Depends(require_permission("playbook:edit"))):
    """Update playbook tags."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE playbooks SET tags = $1 WHERE id = $2",
                tags,
                uuid.UUID(playbook_id)
            )

        return {"message": "Tags updated", "tags": tags}

    except Exception as e:
        logger.error(f"Failed to update tags: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/{playbook_id}/alert-types")
async def update_alert_types(playbook_id: str, alert_types: List[str], user: Dict = Depends(require_permission("playbook:edit"))):
    """Update playbook alert types."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "UPDATE playbooks SET alert_types = $1 WHERE id = $2",
                alert_types,
                uuid.UUID(playbook_id)
            )

        return {"message": "Alert types updated", "alert_types": alert_types}

    except Exception as e:
        logger.error(f"Failed to update alert types: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/tags")
async def get_all_tags(user: Dict = Depends(require_permission("playbook:view"))):
    """Get all unique tags in use."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT DISTINCT unnest(tags) as tag FROM playbooks
                ORDER BY tag
            ''')

            return {"tags": [row['tag'] for row in rows]}

    except Exception as e:
        logger.error(f"Failed to get tags: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/by-tag/{tag}")
async def get_playbooks_by_tag(tag: str, user: Dict = Depends(require_permission("playbook:view"))):
    """Find playbooks by tag."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, name, description, is_enabled, tags, priority
                FROM playbooks
                WHERE $1 = ANY(tags)
                ORDER BY priority DESC
            ''', tag)

            playbooks = []
            for row in rows:
                pb = dict(row)
                pb['id'] = str(pb['id'])
                playbooks.append(pb)

            return {"playbooks": playbooks, "tag": tag}

    except Exception as e:
        logger.error(f"Failed to get playbooks by tag: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/for-alert")
async def find_playbooks_for_alert(
    alert_type: Optional[str] = None,
    severity: Optional[str] = None,
    data_source: Optional[str] = None,
    user: Dict = Depends(require_permission("playbook:view"))
):
    """
    Find matching playbooks for an alert based on alert type, severity, etc.
    """
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            conditions = ["is_enabled = true"]
            params = []
            param_idx = 1

            if alert_type:
                conditions.append(f"(${param_idx} = ANY(alert_types) OR array_length(alert_types, 1) IS NULL)")
                params.append(alert_type)
                param_idx += 1

            if severity:
                conditions.append(f"(${param_idx} = ANY(severity_filter) OR array_length(severity_filter, 1) IS NULL)")
                params.append(severity)
                param_idx += 1

            if data_source:
                conditions.append(f"(${param_idx} = ANY(data_sources) OR array_length(data_sources, 1) IS NULL)")
                params.append(data_source)
                param_idx += 1

            rows = await conn.fetch(f'''
                SELECT id, name, description, is_enabled, riggs_allowed,
                       tags, alert_types, severity_filter, priority, trigger_timing
                FROM playbooks
                WHERE {' AND '.join(conditions)}
                ORDER BY priority DESC
                LIMIT 10
            ''', *params)

            playbooks = []
            for row in rows:
                pb = dict(row)
                pb['id'] = str(pb['id'])
                playbooks.append(pb)

            return {"playbooks": playbooks, "count": len(playbooks)}

    except Exception as e:
        logger.error(f"Failed to find playbooks for alert: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Execution
# ============================================================================

@router.post("/{playbook_id}/execute")
async def execute_playbook(playbook_id: str, request: PlaybookExecuteRequest, user: Dict = Depends(require_permission("playbook:execute"))):
    """
    Manually execute a playbook.
    """
    try:
        from services.playbook_engine import get_playbook_engine

        engine = get_playbook_engine()

        trigger_context = request.trigger_context
        if request.alert_id:
            trigger_context['alert_id'] = request.alert_id
        if request.investigation_id:
            trigger_context['investigation_id'] = request.investigation_id

        result = await engine.start_execution(
            playbook_id=playbook_id,
            trigger_context=trigger_context,
            triggered_by="manual",
            allow_disabled=True
        )

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to execute playbook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{playbook_id}/test-node")
async def test_playbook_node(playbook_id: str, request: Dict = Body(...), user: Dict = Depends(require_permission("playbook:execute"))):
    """
    Test a single playbook node in isolation without persisting an execution record.
    Returns the node's output given the provided config and optional sample context.
    """
    try:
        from services.playbook_engine import get_playbook_engine
        engine = get_playbook_engine()
        node_id = request.get('node_id')
        node_config = request.get('node_config', {})
        node_kind = request.get('node_kind', 'respond')
        sample_context = request.get('sample_context') or {}
        result = await engine.test_single_node(
            node_id=node_id or 'test-node',
            node_kind=node_kind,
            node_config=node_config,
            sample_context=sample_context,
            tenant_id=user.get('tenant_id'),
        )
        return result
    except Exception as e:
        logger.error(f"Failed to test node: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/auto-execute")
async def auto_execute_playbook(request: AutoExecuteRequest, user: Dict = Depends(require_permission("playbook:execute"))):
    """
    Auto-select and execute playbook for an alert.
    Riggs uses this endpoint.
    """
    try:
        from services.playbook_engine import get_playbook_engine
        from services.postgres_db import postgres_db

        # Find matching playbook
        alert = request.alert
        alert_type = alert.get('alert_type') or alert.get('type')
        severity = alert.get('severity')
        data_source = alert.get('data_source') or alert.get('source')

        async with postgres_db.tenant_acquire() as conn:
            # Find best matching playbook
            rows = await conn.fetch('''
                SELECT id, name, riggs_allowed, requires_approval
                FROM playbooks
                WHERE is_enabled = true
                  AND (
                    $1 = ANY(alert_types)
                    OR array_length(alert_types, 1) IS NULL
                    OR array_length(alert_types, 1) = 0
                  )
                ORDER BY
                    CASE WHEN $1 = ANY(alert_types) THEN 0 ELSE 1 END,
                    priority DESC
                LIMIT 1
            ''', alert_type or '')

            if not rows:
                return {
                    "message": "No matching playbook found",
                    "alert_type": alert_type,
                    "executed": False
                }

            playbook = dict(rows[0])
            playbook_id = str(playbook['id'])

            # Check if Riggs can auto-execute
            if not playbook['riggs_allowed']:
                return {
                    "message": "Matching playbook found but Riggs not allowed",
                    "playbook_id": playbook_id,
                    "playbook_name": playbook['name'],
                    "requires_manual_trigger": True,
                    "executed": False
                }

        # Execute
        engine = get_playbook_engine()

        trigger_context = {
            "alert": alert,
            "alert_id": request.alert_id,
            "investigation_id": request.investigation_id
        }

        result = await engine.start_execution(
            playbook_id=playbook_id,
            trigger_context=trigger_context,
            triggered_by="riggs"
        )

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        result['playbook_name'] = playbook['name']
        result['executed'] = True
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to auto-execute playbook: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Metrics
# ============================================================================

@router.get("/{playbook_id}/metrics")
async def get_playbook_metrics(
    playbook_id: str,
    limit: int = Query(default=200, ge=1, le=500),
    user: Dict = Depends(require_permission("playbook:view"))
):
    """Get execution metrics for a playbook."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT status, started_at, completed_at, node_results, created_at
                FROM playbook_executions
                WHERE playbook_id = $1
                ORDER BY created_at DESC
                LIMIT $2
            ''', uuid.UUID(playbook_id), limit)

        status_counts = Counter()
        durations = []
        node_stats = defaultdict(lambda: {
            "node_id": None,
            "node_type": None,
            "runs": 0,
            "failures": 0,
            "avg_execution_time_ms": None
        })

        last_execution_at = None

        for row in rows:
            status_counts[row['status']] += 1
            if not last_execution_at and row.get('created_at'):
                last_execution_at = row['created_at'].isoformat()

            if row.get('started_at') and row.get('completed_at'):
                duration = (row['completed_at'] - row['started_at']).total_seconds()
                durations.append(duration)

            node_results = row.get('node_results') or {}
            if isinstance(node_results, str):
                try:
                    node_results = json.loads(node_results)
                except Exception:
                    node_results = {}

            for node_id, result in node_results.items():
                if not isinstance(result, dict):
                    continue
                entry = node_stats[node_id]
                entry["node_id"] = node_id
                entry["node_type"] = result.get("node_type") or result.get("type")
                entry["runs"] += 1
                if result.get("status") == "failed":
                    entry["failures"] += 1
                exec_time = result.get("execution_time_ms")
                if exec_time is not None:
                    entry.setdefault("_total_time_ms", 0.0)
                    entry["_total_time_ms"] += exec_time

        for node_id, entry in node_stats.items():
            total_time = entry.pop("_total_time_ms", None)
            if total_time is not None and entry["runs"] > 0:
                entry["avg_execution_time_ms"] = round(total_time / entry["runs"], 2)

        total = len(rows)
        completed = status_counts.get("completed", 0)
        failed = status_counts.get("failed", 0)
        success_rate = round((completed / total) * 100, 1) if total else 0
        avg_duration = round(sum(durations) / len(durations), 2) if durations else None

        return {
            "playbook_id": playbook_id,
            "total_executions": total,
            "status_counts": dict(status_counts),
            "success_rate": success_rate,
            "avg_duration_seconds": avg_duration,
            "last_execution_at": last_execution_at,
            "node_metrics": sorted(
                node_stats.values(),
                key=lambda x: (x["failures"], x["runs"]),
                reverse=True
            )
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get playbook metrics: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Execution Management
# ============================================================================

@router.get("/{playbook_id}/executions")
async def list_playbook_executions(
    playbook_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
    user: Dict = Depends(require_permission("playbook:view"))
):
    """
    List all executions for a playbook.

    Returns executions sorted by started_at DESC (newest first).
    """
    try:
        from services.postgres_db import postgres_db
        import uuid

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        try:
            pb_uuid = uuid.UUID(playbook_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid playbook ID")

        async with postgres_db.tenant_acquire() as conn:
            # Build query with optional status filter
            base_query = "FROM playbook_executions WHERE playbook_id = $1"
            params = [pb_uuid]

            if status:
                base_query += " AND status = $2"
                params.append(status)

            # Get total count
            count_row = await conn.fetchrow(
                f"SELECT COUNT(*) as total {base_query}",
                *params
            )
            total = count_row['total'] if count_row else 0

            # Get executions
            order_limit = " ORDER BY started_at DESC LIMIT $%d OFFSET $%d" % (len(params) + 1, len(params) + 2)
            rows = await conn.fetch(
                f"SELECT execution_id, status, current_node_id, triggered_by, started_at, completed_at {base_query}{order_limit}",
                *params, limit, offset
            )

            executions = []
            for row in rows:
                duration_ms = None
                if row['started_at'] and row['completed_at']:
                    duration_ms = (row['completed_at'] - row['started_at']).total_seconds() * 1000

                executions.append({
                    "execution_id": row['execution_id'],
                    "status": row['status'],
                    "current_node_id": row['current_node_id'],
                    "triggered_by": row['triggered_by'],
                    "started_at": row['started_at'].isoformat() if row['started_at'] else None,
                    "completed_at": row['completed_at'].isoformat() if row['completed_at'] else None,
                    "duration_ms": duration_ms
                })

            return {
                "executions": executions,
                "total": total,
                "limit": limit,
                "offset": offset
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list executions: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/executions/{execution_id}")
async def get_execution(execution_id: str, user: Dict = Depends(require_permission("playbook:view"))):
    """Get execution details."""
    try:
        from services.playbook_engine import get_playbook_engine

        engine = get_playbook_engine()
        result = await engine.get_execution(execution_id)

        if not result:
            raise HTTPException(status_code=404, detail="Execution not found")

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get execution: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/executions/{execution_id}/submit-form/{node_id}")
async def submit_form_response(
    execution_id: str,
    node_id: str,
    request: Dict = Body(...),
    user: Dict = Depends(require_permission("playbook:execute"))
):
    """Submit form data for a webform node and resume execution."""
    try:
        from services.postgres_db import postgres_db
        from services.playbook_engine import get_playbook_engine
        import json as _json

        form_data = request.get('form_data', {})

        # Store form data in node_results before resuming
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT node_results FROM playbook_executions WHERE execution_id = $1",
                execution_id
            )
            if not row:
                raise HTTPException(status_code=404, detail="Execution not found")

            node_results = row['node_results'] or {}
            if isinstance(node_results, str):
                node_results = _json.loads(node_results)

            # Update node outputs with submitted form data
            if node_id not in node_results:
                node_results[node_id] = {}
            node_results[node_id]['outputs'] = {
                **(node_results[node_id].get('outputs') or {}),
                'form_data': form_data,
                'form_submitted': True,
                'submitted_by': user.get('username') or user.get('email'),
            }

            await conn.execute(
                "UPDATE playbook_executions SET node_results = $1 WHERE execution_id = $2",
                _json.dumps(node_results),
                execution_id
            )

        # Resume execution (moves to next node after the webform)
        engine = get_playbook_engine()
        result = await engine.resume_execution(execution_id, {'form_data': form_data})
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit form: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/executions/{execution_id}/approve/{node_id}")
async def approve_node(execution_id: str, node_id: str, request: ApprovalAction, user: Dict = Depends(require_permission("playbook:execute"))):
    """Approve a pending approval in execution."""
    try:
        from services.postgres_db import postgres_db
        from services.playbook_engine import get_playbook_engine

        # Update approval record
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute('''
                UPDATE playbook_node_approvals
                SET status = 'approved',
                    reviewed_at = NOW(),
                    review_notes = $1
                WHERE execution_id = (
                    SELECT id FROM playbook_executions WHERE execution_id = $2
                ) AND node_id = $3 AND status = 'pending'
            ''', request.notes, execution_id, node_id)

        # Resume execution
        engine = get_playbook_engine()
        result = await engine.resume_execution(
            execution_id,
            {"approved": True, "notes": request.notes}
        )

        return {"message": "Approved", "execution": result}

    except Exception as e:
        logger.error(f"Failed to approve: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/executions/{execution_id}/reject/{node_id}")
async def reject_node(execution_id: str, node_id: str, request: ApprovalAction, user: Dict = Depends(require_permission("playbook:execute"))):
    """Reject a pending approval in execution."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            # Update approval record
            await conn.execute('''
                UPDATE playbook_node_approvals
                SET status = 'rejected',
                    reviewed_at = NOW(),
                    review_notes = $1
                WHERE execution_id = (
                    SELECT id FROM playbook_executions WHERE execution_id = $2
                ) AND node_id = $3 AND status = 'pending'
            ''', request.notes, execution_id, node_id)

            # Fail the execution
            await conn.execute('''
                UPDATE playbook_executions
                SET status = 'failed',
                    completed_at = NOW(),
                    error_message = 'Approval rejected'
                WHERE execution_id = $1
            ''', execution_id)

        return {"message": "Rejected", "execution_id": execution_id}

    except Exception as e:
        logger.error(f"Failed to reject: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/executions/{execution_id}/cancel")
async def cancel_execution(execution_id: str, reason: Optional[str] = None, user: Dict = Depends(require_permission("playbook:execute"))):
    """Cancel a running execution."""
    try:
        from services.playbook_engine import get_playbook_engine

        engine = get_playbook_engine()
        result = await engine.cancel_execution(execution_id, reason)

        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel execution: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Forms
# ============================================================================

@router.get("/forms")
async def list_forms(user: Dict = Depends(require_permission("playbook:view"))):
    """List all webforms."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, name, description, submit_action, require_auth, created_at
                FROM playbook_forms
                ORDER BY created_at DESC
            ''')

            forms = []
            for row in rows:
                form = dict(row)
                form['id'] = str(form['id'])
                if form.get('created_at'):
                    form['created_at'] = form['created_at'].isoformat()
                forms.append(form)

            return {"forms": forms}

    except Exception as e:
        logger.error(f"Failed to list forms: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/forms")
async def create_form(request: PlaybookFormCreate, user: Dict = Depends(require_permission("playbook:edit"))):
    """Create a new webform."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            tenant_id = user.get('tenant_id')
            if not tenant_id:
                raise HTTPException(status_code=400, detail="tenant_id missing from auth context")
            row = await conn.fetchrow('''
                INSERT INTO playbook_forms (tenant_id, name, description, fields, submit_action, submit_label, require_auth, allowed_roles, prefill_mapping)
                VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
                RETURNING *
            ''',
                str(tenant_id),
                request.name,
                request.description,
                json.dumps(request.fields),
                request.submit_action,
                request.submit_label,
                request.require_auth,
                request.allowed_roles,
                json.dumps(request.prefill_mapping),
            )

            result = dict(row)
            result['id'] = str(result['id'])
            return result

    except Exception as e:
        logger.error(f"Failed to create form: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/forms/{form_id}")
async def get_form(form_id: str, user: Dict = Depends(require_permission("playbook:view"))):
    """Get form details."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM playbook_forms WHERE id = $1",
                uuid.UUID(form_id)
            )

            if not row:
                raise HTTPException(status_code=404, detail="Form not found")

            result = dict(row)
            result['id'] = str(result['id'])
            if result.get('fields') and isinstance(result['fields'], str):
                result['fields'] = json.loads(result['fields'])
            if isinstance(result.get('prefill_mapping'), str):
                result['prefill_mapping'] = json.loads(result['prefill_mapping'])
            return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get form: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/forms/{form_id}/submit")
async def submit_form(
    form_id: str,
    execution_id: str,
    node_id: str,
    request: FormSubmission,
    user: Dict = Depends(require_permission("playbook:execute"))
):
    """Submit form data and resume execution."""
    try:
        from services.postgres_db import postgres_db
        from services.playbook_engine import get_playbook_engine

        # Save submission
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute('''
                INSERT INTO playbook_form_submissions (
                    form_id, execution_id, node_id, form_data
                ) VALUES (
                    $1,
                    (SELECT id FROM playbook_executions WHERE execution_id = $2),
                    $3, $4
                )
            ''',
                uuid.UUID(form_id),
                execution_id,
                node_id,
                json.dumps(request.form_data)
            )

        # Resume execution
        engine = get_playbook_engine()
        result = await engine.resume_execution(
            execution_id,
            {"form_data": request.form_data}
        )

        return {"message": "Form submitted", "execution": result}

    except Exception as e:
        logger.error(f"Failed to submit form: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# File Upload
# ============================================================================

@router.post("/executions/{execution_id}/upload")
async def upload_file(
    execution_id: str,
    node_id: str = Form(...),
    file: UploadFile = File(...),
    user: Dict = Depends(require_permission("playbook:execute"))
):
    """Upload file and resume execution."""
    try:
        import os
        from services.postgres_db import postgres_db
        from services.playbook_engine import get_playbook_engine

        # Validate execution_id is a valid UUID to prevent path traversal
        try:
            uuid.UUID(execution_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid execution ID format")

        # Save file
        upload_dir = os.path.join(os.getcwd(), "uploads", "playbooks", execution_id)
        os.makedirs(upload_dir, exist_ok=True)

        file_id = str(uuid.uuid4())
        file_ext = os.path.splitext(file.filename)[1] if file.filename else ""
        saved_filename = f"{file_id}{file_ext}"
        file_path = os.path.join(upload_dir, saved_filename)

        # Path traversal check: ensure file_path is within upload_dir
        if not os.path.realpath(file_path).startswith(os.path.realpath(upload_dir)):
            raise HTTPException(status_code=400, detail="Invalid file path")

        content = await file.read()
        with open(file_path, "wb") as f:
            f.write(content)

        # Record in DB
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute('''
                INSERT INTO playbook_files (
                    execution_id, filename, original_filename, file_type, file_size, storage_path, tenant_id
                ) VALUES (
                    (SELECT id FROM playbook_executions WHERE execution_id = $1),
                    $2, $3, $4, $5, $6, $7
                )
            ''',
                execution_id,
                saved_filename,
                file.filename,
                file.content_type,
                len(content),
                file_path,
                user.get("tenant_id")
            )

        # Resume execution
        engine = get_playbook_engine()
        result = await engine.resume_execution(
            execution_id,
            {
                "file_id": file_id,
                "filename": file.filename,
                "file_path": file_path,
                "file_size": len(content)
            }
        )

        return {"message": "File uploaded", "file_id": file_id, "execution": result}

    except Exception as e:
        logger.error(f"Failed to upload file: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Custom Functions
# ============================================================================

@router.get("/functions")
async def list_functions(user: Dict = Depends(require_permission("playbook:view"))):
    """List all custom functions."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            return {"functions": []}

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, name, description, is_approved, usage_count, created_at
                FROM playbook_functions
                ORDER BY name
            ''')

            functions = []
            for row in rows:
                func = dict(row)
                func['id'] = str(func['id'])
                if func.get('created_at'):
                    func['created_at'] = func['created_at'].isoformat()
                functions.append(func)

            return {"functions": functions}

    except Exception as e:
        error_str = str(e).lower()
        if 'undefined' in error_str or 'does not exist' in error_str or 'playbook_functions' in error_str:
            logger.warning("playbook_functions table missing; returning empty list")
            return {"functions": []}
        logger.error(f"Failed to list functions: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/functions")
async def create_function(request: CustomFunctionCreate, user: Dict = Depends(require_permission("playbook:edit"))):
    """Create a custom Python function (requires approval)."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                INSERT INTO playbook_functions (name, description, code, input_schema, output_schema, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
            ''',
                request.name,
                request.description,
                request.code,
                json.dumps(request.input_schema),
                json.dumps(request.output_schema),
                user.get("tenant_id")
            )

            result = dict(row)
            result['id'] = str(result['id'])
            return {"message": "Function created (pending approval)", "function": result}

    except Exception as e:
        logger.error(f"Failed to create function: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/functions/{function_id}")
async def update_function(function_id: str, request: CustomFunctionCreate, user: Dict = Depends(require_permission("playbook:edit"))):
    """Update a function (resets approval)."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute('''
                UPDATE playbook_functions
                SET name = $1, description = $2, code = $3,
                    input_schema = $4, output_schema = $5,
                    is_approved = false, updated_at = NOW()
                WHERE id = $6
            ''',
                request.name,
                request.description,
                request.code,
                json.dumps(request.input_schema),
                json.dumps(request.output_schema),
                uuid.UUID(function_id)
            )

            return {"message": "Function updated (approval reset)", "id": function_id}

    except Exception as e:
        logger.error(f"Failed to update function: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/functions/{function_id}/approve")
async def approve_function(function_id: str, notes: Optional[str] = None, user: Dict = Depends(require_permission("playbook:edit"))):
    """Approve a function for use in playbooks."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute('''
                UPDATE playbook_functions
                SET is_approved = true, approved_at = NOW(), security_notes = $1
                WHERE id = $2
            ''', notes, uuid.UUID(function_id))

            return {"message": "Function approved", "id": function_id}

    except Exception as e:
        logger.error(f"Failed to approve function: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Custom Lists
# ============================================================================

@router.get("/lists")
async def list_lists(user: Dict = Depends(require_permission("playbook:view"))):
    """List all custom lists."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            return {"lists": []}

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch('''
                SELECT id, name, description, list_type, item_count, created_at, updated_at
                FROM playbook_lists
                ORDER BY name
            ''')

            lists = []
            for row in rows:
                lst = dict(row)
                lst['id'] = str(lst['id'])
                if lst.get('created_at'):
                    lst['created_at'] = lst['created_at'].isoformat()
                if lst.get('updated_at'):
                    lst['updated_at'] = lst['updated_at'].isoformat()
                lists.append(lst)

            return {"lists": lists}

    except Exception as e:
        error_str = str(e).lower()
        if 'undefined' in error_str or 'does not exist' in error_str or 'playbook_lists' in error_str:
            logger.warning("playbook_lists table missing; returning empty list")
            return {"lists": []}
        logger.error(f"Failed to list lists: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/lists")
async def create_list(request: CustomListCreate, user: Dict = Depends(require_permission("playbook:edit"))):
    """Create a custom list."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                INSERT INTO playbook_lists (name, description, list_type, items, item_count, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
            ''',
                request.name,
                request.description,
                request.list_type,
                json.dumps(request.items),
                len(request.items),
                user.get("tenant_id")
            )

            result = dict(row)
            result['id'] = str(result['id'])
            return result

    except Exception as e:
        logger.error(f"Failed to create list: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/lists/{list_id}")
async def get_list(list_id: str, user: Dict = Depends(require_permission("playbook:view"))):
    """Get list details including items."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM playbook_lists WHERE id = $1",
                uuid.UUID(list_id)
            )

            if not row:
                raise HTTPException(status_code=404, detail="List not found")

            result = dict(row)
            result['id'] = str(result['id'])
            if result.get('items') and isinstance(result['items'], str):
                result['items'] = json.loads(result['items'])
            return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get list: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/lists/{list_id}")
async def update_list(list_id: str, request: CustomListUpdate, user: Dict = Depends(require_permission("playbook:edit"))):
    """Add or remove items from a list."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            # Get current list
            row = await conn.fetchrow(
                "SELECT items FROM playbook_lists WHERE id = $1",
                uuid.UUID(list_id)
            )

            if not row:
                raise HTTPException(status_code=404, detail="List not found")

            items = row['items']
            if isinstance(items, str):
                items = json.loads(items)

            # Update items
            if request.add_items:
                for item in request.add_items:
                    if item not in items:
                        items.append(item)

            if request.remove_items:
                items = [i for i in items if i not in request.remove_items]

            # Save
            await conn.execute('''
                UPDATE playbook_lists
                SET items = $1, item_count = $2, updated_at = NOW()
                WHERE id = $3
            ''', json.dumps(items), len(items), uuid.UUID(list_id))

            return {"message": "List updated", "item_count": len(items)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update list: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Data Paths
# ============================================================================

@router.get("/executions/{execution_id}/data-paths")
async def get_data_paths(execution_id: str, node_id: Optional[str] = None, user: Dict = Depends(require_permission("playbook:view"))):
    """Get available data paths for an execution."""
    try:
        from services.playbook_engine import get_playbook_engine
        from services.postgres_db import postgres_db

        # Get playbook_id from execution
        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow(
                "SELECT playbook_id FROM playbook_executions WHERE execution_id = $1",
                execution_id
            )

            if not row:
                raise HTTPException(status_code=404, detail="Execution not found")

            playbook_id = str(row['playbook_id'])

        engine = get_playbook_engine()
        paths = await engine.get_available_data_paths(
            playbook_id,
            node_id or "",
            execution_id
        )

        return {"paths": paths}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get data paths: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{playbook_id}/validate-path")
async def validate_data_path(playbook_id: str, path: str, user: Dict = Depends(require_permission("playbook:execute"))):
    """Validate a data path expression."""
    try:
        # Simple validation - check syntax
        if not path.startswith('$'):
            return {"valid": False, "error": "Path must start with $"}

        # Check for common issues
        if '..' in path:
            return {"valid": False, "error": "Invalid double dot in path"}

        if path.count('[') != path.count(']'):
            return {"valid": False, "error": "Mismatched brackets"}

        return {"valid": True, "path": path}

    except Exception as e:
        return {"valid": False, "error": str(e)}


# ============================================================================
# Context Preview
# ============================================================================

@router.get("/context/alert/{alert_id}")
async def get_alert_context(alert_id: str, user: Dict = Depends(require_permission("playbook:view"))):
    """Fetch an alert payload for playbook preview/mapping, including linked IOCs."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            row = None
            try:
                alert_uuid = uuid.UUID(alert_id)
                row = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", alert_uuid)
            except ValueError:
                row = await conn.fetchrow("SELECT * FROM alerts WHERE alert_id = $1", alert_id)

            if not row:
                raise HTTPException(status_code=404, detail="Alert not found")

            # Pull linked IOCs using the string alert_id
            str_alert_id = row.get("alert_id") or alert_id
            ioc_rows = await conn.fetch(
                "SELECT ioc_type, ioc_value, extraction_method, extraction_source "
                "FROM alert_ioc_links WHERE alert_id = $1 ORDER BY ioc_type, ioc_value",
                str_alert_id
            )

        data = _serialize_record(row)
        data["iocs"] = [dict(r) for r in ioc_rows] if ioc_rows else []
        return data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch alert context: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/context/investigation/{investigation_id}")
async def get_investigation_context(investigation_id: str, user: Dict = Depends(require_permission("playbook:view"))):
    """Fetch an investigation payload for playbook preview/mapping, including linked IOCs."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        async with postgres_db.tenant_acquire() as conn:
            row = None
            try:
                inv_uuid = uuid.UUID(investigation_id)
                row = await conn.fetchrow("SELECT * FROM investigations WHERE id = $1", inv_uuid)
            except ValueError:
                row = await conn.fetchrow(
                    "SELECT * FROM investigations WHERE investigation_id = $1",
                    investigation_id
                )

            if not row:
                raise HTTPException(status_code=404, detail="Investigation not found")

            # Pull linked IOCs from investigation_iocs
            inv_uuid_id = row.get("id")
            ioc_rows = await conn.fetch(
                "SELECT ioc_type, ioc_value, context, confidence_score "
                "FROM investigation_iocs WHERE investigation_id = $1 ORDER BY ioc_type, ioc_value",
                inv_uuid_id
            ) if inv_uuid_id else []

        data = _serialize_record(row)
        data["iocs"] = [_serialize_record(r) for r in ioc_rows] if ioc_rows else []
        return data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch investigation context: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/context/search")
async def search_context(query: str = Query(..., min_length=1), limit: int = Query(10, ge=1, le=50), user: Dict = Depends(require_permission("playbook:view"))):
    """Search alerts and investigations by name or ID."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        like = f"%{query}%"
        async with postgres_db.tenant_acquire() as conn:
            alert_rows = await conn.fetch(
                """
                SELECT id, alert_id, external_id, title, severity, created_at
                FROM alerts
                WHERE alert_id ILIKE $1 OR title ILIKE $1 OR external_id ILIKE $1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                like,
                limit,
            )
            inv_rows = await conn.fetch(
                """
                SELECT id, investigation_id, alert_title, state, severity, created_at
                FROM investigations
                WHERE investigation_id ILIKE $1 OR alert_title ILIKE $1
                ORDER BY created_at DESC
                LIMIT $2
                """,
                like,
                limit,
            )

        results = []
        for row in alert_rows:
            record = _serialize_record(row)
            results.append({
                "type": "alert",
                "id": record.get("id"),
                "alert_id": record.get("alert_id"),
                "external_id": record.get("external_id"),
                "title": record.get("title"),
                "severity": record.get("severity"),
                "created_at": record.get("created_at"),
            })
        for row in inv_rows:
            record = _serialize_record(row)
            results.append({
                "type": "investigation",
                "id": record.get("id"),
                "investigation_id": record.get("investigation_id"),
                "title": record.get("alert_title"),
                "state": record.get("state"),
                "severity": record.get("severity"),
                "created_at": record.get("created_at"),
            })

        results.sort(key=lambda item: item.get("created_at") or "", reverse=True)
        return {"results": results[:limit]}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to search context: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/context/{entity_id}")
async def get_entity_context(entity_id: str, user: Dict = Depends(require_permission("playbook:view"))):
    """Auto-detect alert vs investigation by ID."""
    try:
        from services.postgres_db import postgres_db

        if not postgres_db.connected:
            raise HTTPException(status_code=503, detail="Database not connected")

        alert_row = None
        inv_row = None
        async with postgres_db.tenant_acquire() as conn:
            try:
                entity_uuid = uuid.UUID(entity_id)
                alert_row = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", entity_uuid)
                if not alert_row:
                    inv_row = await conn.fetchrow("SELECT * FROM investigations WHERE id = $1", entity_uuid)
            except ValueError:
                alert_row = await conn.fetchrow("SELECT * FROM alerts WHERE alert_id = $1", entity_id)
                if not alert_row:
                    inv_row = await conn.fetchrow(
                        "SELECT * FROM investigations WHERE investigation_id = $1",
                        entity_id
                    )

        if alert_row:
            return {"type": "alert", "data": _serialize_record(alert_row)}
        if inv_row:
            return {"type": "investigation", "data": _serialize_record(inv_row)}

        raise HTTPException(status_code=404, detail="Alert or investigation not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch entity context: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# Templates
# ============================================================================

@router.get("/templates")
async def list_templates(
    category: Optional[str] = None,
    source: Optional[str] = None,
    user: Dict = Depends(require_permission("playbook:view"))
):
    """List playbook templates."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            conditions = []
            params = []
            param_idx = 1

            if category:
                conditions.append(f"category = ${param_idx}")
                params.append(category)
                param_idx += 1

            if source:
                conditions.append(f"source = ${param_idx}")
                params.append(source)
                param_idx += 1

            where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

            rows = await conn.fetch(f'''
                SELECT id, name, description, category, source, tags, usage_count
                FROM playbook_templates
                {where_clause}
                ORDER BY usage_count DESC, name
            ''', *params)

            templates = []
            for row in rows:
                tpl = dict(row)
                tpl['id'] = str(tpl['id'])
                templates.append(tpl)

            return {"templates": templates}

    except Exception as e:
        logger.error(f"Failed to list templates: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/templates/{template_id}/use")
async def use_template(template_id: str, name: str, user: Dict = Depends(require_permission("playbook:create"))):
    """Create a new playbook from a template."""
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            # Get template
            template = await conn.fetchrow(
                "SELECT * FROM playbook_templates WHERE id = $1",
                uuid.UUID(template_id)
            )

            if not template:
                raise HTTPException(status_code=404, detail="Template not found")

            # Create playbook
            canvas_data = template['canvas_data']
            if isinstance(canvas_data, str):
                canvas_data = json.loads(canvas_data)

            row = await conn.fetchrow('''
                INSERT INTO playbooks (tenant_id, name, description, canvas_data, trigger_conditions, tags, alert_types)
                VALUES (current_setting('app.current_tenant_id')::uuid, $1, $2, $3, $4, $5, $6)
                RETURNING *
            ''',
                name,
                template['description'],
                json.dumps(canvas_data),
                json.dumps(template['trigger_conditions'] if template['trigger_conditions'] else {}),
                template['tags'] or [],
                template['alert_types'] or []
            )

            # Increment usage count
            await conn.execute(
                "UPDATE playbook_templates SET usage_count = usage_count + 1 WHERE id = $1",
                uuid.UUID(template_id)
            )

            result = dict(row)
            result['id'] = str(result['id'])
            return {"message": "Playbook created from template", "playbook": result}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to use template: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# PLAYBOOK VERSION HISTORY
# ============================================================================

@router.get("/{playbook_id}/versions")
async def list_playbook_versions(playbook_id: str, limit: int = 50, offset: int = 0, user: Dict = Depends(require_permission("playbook:view"))):
    """
    List all versions of a playbook.

    Returns versions sorted by version_number DESC (newest first).
    """
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            # Check playbook exists
            playbook = await conn.fetchrow(
                "SELECT id, name, version FROM playbooks WHERE id = $1",
                uuid.UUID(playbook_id)
            )
            if not playbook:
                raise HTTPException(status_code=404, detail="Playbook not found")

            # Get versions
            rows = await conn.fetch('''
                SELECT
                    id,
                    version_number,
                    metadata,
                    change_summary,
                    created_by_email,
                    created_at
                FROM playbook_versions
                WHERE playbook_id = $1
                ORDER BY version_number DESC
                LIMIT $2 OFFSET $3
            ''', uuid.UUID(playbook_id), limit, offset)

            # Get total count
            count_row = await conn.fetchrow(
                "SELECT COUNT(*) as total FROM playbook_versions WHERE playbook_id = $1",
                uuid.UUID(playbook_id)
            )

            versions = []
            for row in rows:
                v = _serialize_record(row)
                # Add node count from metadata
                metadata = v.get('metadata', {})
                if isinstance(metadata, str):
                    try:
                        metadata = json.loads(metadata)
                    except:
                        metadata = {}
                v['node_count'] = metadata.get('node_count', 0)
                v['name'] = metadata.get('name', '')
                versions.append(v)

            return {
                "playbook_id": playbook_id,
                "current_version": playbook['version'],
                "versions": versions,
                "total": count_row['total'],
                "limit": limit,
                "offset": offset
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list versions: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{playbook_id}/versions/{version_id}")
async def get_playbook_version(playbook_id: str, version_id: str, user: Dict = Depends(require_permission("playbook:view"))):
    """
    Get a specific version of a playbook.

    Returns the full canvas_data for that version.
    """
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            row = await conn.fetchrow('''
                SELECT
                    id,
                    playbook_id,
                    version_number,
                    canvas_data,
                    metadata,
                    change_summary,
                    created_by_email,
                    created_at
                FROM playbook_versions
                WHERE id = $1 AND playbook_id = $2
            ''', uuid.UUID(version_id), uuid.UUID(playbook_id))

            if not row:
                raise HTTPException(status_code=404, detail="Version not found")

            return _serialize_record(row)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get version: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{playbook_id}/versions/{version_id}/restore")
async def restore_playbook_version(playbook_id: str, version_id: str, request: Request, user: Dict = Depends(require_permission("playbook:edit"))):
    """
    Restore a playbook to a specific version.

    This creates a new version with the restored canvas_data.
    """
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            # Get the version to restore
            version_row = await conn.fetchrow('''
                SELECT canvas_data, version_number, metadata
                FROM playbook_versions
                WHERE id = $1 AND playbook_id = $2
            ''', uuid.UUID(version_id), uuid.UUID(playbook_id))

            if not version_row:
                raise HTTPException(status_code=404, detail="Version not found")

            # Get current playbook
            playbook = await conn.fetchrow(
                "SELECT * FROM playbooks WHERE id = $1",
                uuid.UUID(playbook_id)
            )
            if not playbook:
                raise HTTPException(status_code=404, detail="Playbook not found")

            # Restore canvas_data (this will trigger the version trigger)
            canvas_data = version_row['canvas_data']
            if isinstance(canvas_data, str):
                canvas_data = json.loads(canvas_data)

            metadata = version_row['metadata']
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except:
                    metadata = {}

            await conn.execute('''
                UPDATE playbooks
                SET canvas_data = $2,
                    name = COALESCE($3, name),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = $1
            ''',
                uuid.UUID(playbook_id),
                json.dumps(canvas_data),
                metadata.get('name')
            )

            # Get updated playbook
            updated = await conn.fetchrow(
                "SELECT * FROM playbooks WHERE id = $1",
                uuid.UUID(playbook_id)
            )

            await _refresh_playbook_scheduler(request)

            return {
                "message": f"Restored to version {version_row['version_number']}",
                "playbook": _serialize_record(updated)
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to restore version: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{playbook_id}/versions")
async def create_manual_version(playbook_id: str, change_summary: str = "Manual checkpoint", user: Dict = Depends(require_permission("playbook:edit"))):
    """
    Create a manual version checkpoint.

    Useful for creating named checkpoints before major changes.
    """
    try:
        from services.postgres_db import postgres_db

        async with postgres_db.tenant_acquire() as conn:
            # Get current playbook
            playbook = await conn.fetchrow(
                "SELECT * FROM playbooks WHERE id = $1",
                uuid.UUID(playbook_id)
            )
            if not playbook:
                raise HTTPException(status_code=404, detail="Playbook not found")

            # Get next version number
            max_version = await conn.fetchrow(
                "SELECT COALESCE(MAX(version_number), 0) as max_v FROM playbook_versions WHERE playbook_id = $1",
                uuid.UUID(playbook_id)
            )
            next_version = max_version['max_v'] + 1

            # Create version
            canvas_data = playbook['canvas_data']
            if isinstance(canvas_data, str):
                canvas_data = json.loads(canvas_data)

            row = await conn.fetchrow('''
                INSERT INTO playbook_versions (
                    playbook_id,
                    version_number,
                    canvas_data,
                    metadata,
                    change_summary,
                    tenant_id
                ) VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING *
            ''',
                uuid.UUID(playbook_id),
                next_version,
                json.dumps(canvas_data),
                json.dumps({
                    'name': playbook['name'],
                    'description': playbook['description'],
                    'is_enabled': playbook['is_enabled'],
                    'node_count': len(canvas_data.get('nodes', []))
                }),
                change_summary,
                user.get("tenant_id")
            )

            return {
                "message": f"Created version {next_version}",
                "version": _serialize_record(row)
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create version: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


# ============================================================================
# PLAYBOOK MARKETPLACE
# ============================================================================

@router.get("/marketplace/browse")
async def browse_marketplace(
    category: Optional[str] = None,
    subcategory: Optional[str] = None,
    difficulty: Optional[str] = None,
    search: Optional[str] = None,
    integration: Optional[str] = None,
    tag: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(24, ge=1, le=100),
    user: Dict = Depends(require_permission("playbook:view")),
):
    """Browse the playbook marketplace with filters."""
    try:
        from services.playbook_catalog_service import playbook_catalog

        result = await playbook_catalog.get_marketplace(
            category=category,
            subcategory=subcategory,
            difficulty=difficulty,
            search=search,
            integration=integration,
            tag=tag,
            page=page,
            per_page=per_page,
        )
        return result
    except Exception as e:
        logger.error(f"Marketplace browse failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/marketplace/categories")
async def marketplace_categories(
    user: Dict = Depends(require_permission("playbook:view")),
):
    """Get all marketplace categories with counts."""
    try:
        from services.playbook_catalog_service import playbook_catalog
        return {"categories": await playbook_catalog.get_categories()}
    except Exception as e:
        logger.error(f"Marketplace categories failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/marketplace/stats")
async def marketplace_stats(
    user: Dict = Depends(require_permission("playbook:view")),
):
    """Get marketplace summary statistics."""
    try:
        from services.playbook_catalog_service import playbook_catalog
        return await playbook_catalog.get_stats()
    except Exception as e:
        logger.error(f"Marketplace stats failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/marketplace/{template_id}")
async def get_marketplace_template(
    template_id: str,
    user: Dict = Depends(require_permission("playbook:view")),
):
    """Get full detail for a marketplace template."""
    try:
        from services.playbook_catalog_service import playbook_catalog

        template = await playbook_catalog.get_template_detail(template_id)
        if not template:
            raise HTTPException(status_code=404, detail="Template not found")
        return template
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Marketplace template detail failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/marketplace/{template_id}/check-integrations")
async def check_template_integrations(
    template_id: str,
    request: Request,
    user: Dict = Depends(require_permission("playbook:view")),
):
    """Check if the tenant has all required integrations configured for a template."""
    try:
        from services.playbook_catalog_service import playbook_catalog

        tenant_id = getattr(request.state, "tenant_id", None) or user.get("tenant_id")
        if not tenant_id:
            raise HTTPException(status_code=400, detail="Tenant context required")

        result = await playbook_catalog.check_integration_deps(template_id, str(tenant_id))
        if "error" in result:
            raise HTTPException(status_code=404, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Integration check failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/marketplace/{template_id}/install")
async def install_marketplace_template(
    template_id: str,
    request: Request,
    user: Dict = Depends(require_permission("playbook:create")),
):
    """Install a marketplace template as a new playbook in the tenant's workspace.

    Optionally accepts a JSON body with integration_map to remap integration
    references (connector slugs -> tenant instance UUIDs).
    """
    try:
        from services.playbook_catalog_service import playbook_catalog

        tenant_id = getattr(request.state, "tenant_id", None) or user.get("tenant_id")
        user_id = user.get("id")
        if not tenant_id or not user_id:
            raise HTTPException(status_code=400, detail="Tenant and user context required")

        # Parse optional body (backwards compatible — no body is fine)
        integration_map = None
        try:
            body = await request.json()
            integration_map = body.get("integration_map")
        except Exception:
            pass

        result = await playbook_catalog.install_template(
            template_id, str(tenant_id), str(user_id),
            integration_map=integration_map,
        )
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Template install failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
