# Copyright (c) 2025-2026 T1 Agentics LLC. SPDX-License-Identifier: Apache-2.0

"""
Intake Forms API Routes

Tenant-scoped, authenticated forms whose submissions become alerts that flow
through the existing Riggs/triage pipeline.

Endpoints:
  Admin CRUD:
    GET    /api/v1/intake-forms
    POST   /api/v1/intake-forms
    GET    /api/v1/intake-forms/{form_id}
    PUT    /api/v1/intake-forms/{form_id}
    DELETE /api/v1/intake-forms/{form_id}

  Submitter:
    GET  /api/v1/intake-forms/by-slug/{slug}
    POST /api/v1/intake-forms/by-slug/{slug}/submit

  Submission browsing (admin):
    GET /api/v1/intake-forms/{form_id}/submissions
    GET /api/v1/intake-forms/submissions/{submission_id}

Tenant isolation is enforced by RLS via postgres_db.tenant_acquire(); a missing
or cross-tenant form id results in a 404 (we never reveal cross-tenant
existence — anti-enumeration).
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from dependencies.auth import get_current_user, require_permission
from services import intake_forms_service as forms_svc
from services import intake_upload_storage as upload_storage
from services import eml_parser

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/intake-forms",
    tags=["intake-forms"],
    dependencies=[Depends(get_current_user)],
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _serialize_form(row) -> Optional[Dict[str, Any]]:
    """asyncpg record → JSON-friendly dict, with JSONB columns parsed."""
    if not row:
        return None
    d = dict(row)
    for k, v in list(d.items()):
        if isinstance(v, uuid.UUID):
            d[k] = str(v)
        elif isinstance(v, datetime):
            d[k] = v.isoformat()
        elif k in ("fields", "alert_template", "payload") and isinstance(v, str):
            try:
                d[k] = json.loads(v)
            except Exception:
                pass
    return d


# ─────────────────────────────────────────────────────────────────────────────
# Request models
# ─────────────────────────────────────────────────────────────────────────────

class FormCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    title: str = Field(..., min_length=1, max_length=255)
    intro: Optional[str] = None
    submit_message: Optional[str] = None
    fields: List[Dict[str, Any]] = Field(default_factory=list)
    alert_template: Dict[str, Any] = Field(default_factory=dict)
    status: str = Field(default="draft", pattern="^(draft|active|archived)$")
    # How a submission gets processed once the alert is created.
    triage_strategy: str = Field(default="enrich", pattern="^(direct|enrich|playbook)$")
    auto_trigger_playbook_id: Optional[str] = None


class FormUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    title: Optional[str] = Field(default=None, min_length=1, max_length=255)
    intro: Optional[str] = None
    submit_message: Optional[str] = None
    fields: Optional[List[Dict[str, Any]]] = None
    alert_template: Optional[Dict[str, Any]] = None
    status: Optional[str] = Field(default=None, pattern="^(draft|active|archived)$")
    triage_strategy: Optional[str] = Field(default=None, pattern="^(direct|enrich|playbook)$")
    auto_trigger_playbook_id: Optional[str] = None


class SubmitRequest(BaseModel):
    payload: Dict[str, Any] = Field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Form CRUD (admin)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("")
async def list_forms(
    status: Optional[str] = Query(default=None, pattern="^(draft|active|archived)$"),
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    user: Dict = Depends(require_permission("playbook:view")),
):
    """List forms in the current tenant. RLS handles tenant filtering."""
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.tenant_acquire() as conn:
        params: List[Any] = []
        where = ""
        if status:
            params.append(status)
            where = f"WHERE status = $1"

        params_for_count = list(params)

        params.extend([limit, offset])
        rows = await conn.fetch(
            f"""
            SELECT id, tenant_id, slug, name, description, title, intro,
                   submit_message, fields, alert_template, status,
                   triage_strategy, auto_trigger_playbook_id,
                   created_by, updated_by, created_at, updated_at
            FROM intake_forms
            {where}
            ORDER BY created_at DESC
            LIMIT ${len(params) - 1} OFFSET ${len(params)}
            """,
            *params,
        )
        total_row = await conn.fetchrow(
            f"SELECT COUNT(*) AS n FROM intake_forms {where}",
            *params_for_count,
        )

    return {
        "items": [_serialize_form(r) for r in rows],
        "total": total_row["n"] if total_row else 0,
        "limit": limit,
        "offset": offset,
    }


@router.post("", status_code=201)
async def create_form(
    body: FormCreate,
    user: Dict = Depends(require_permission("playbook:edit")),
):
    """Create a new form."""
    ok, err = forms_svc.validate_field_schema(body.fields)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Invalid field schema: {err}")

    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    tenant_id = user.get("tenant_id")
    user_id = user.get("user_id") or user.get("id")
    # Slugs are derived from the form's name (e.g. "Phishing Report" ->
    # "phishing-report-a3k7"). The 4-char suffix dodges same-name
    # collisions across tenants and keeps URLs from being trivially
    # guessable. Falls back to fully random if no name was supplied.
    slug = forms_svc.generate_slug(body.name)

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO intake_forms (
                tenant_id, slug, name, description, title, intro, submit_message,
                fields, alert_template, status,
                triage_strategy, auto_trigger_playbook_id,
                created_by, updated_by
            ) VALUES (
                $1::uuid, $2, $3, $4, $5, $6, $7,
                $8::jsonb, $9::jsonb, $10,
                $11, $12,
                $13::uuid, $13::uuid
            )
            RETURNING id, tenant_id, slug, name, description, title, intro,
                      submit_message, fields, alert_template, status,
                      triage_strategy, auto_trigger_playbook_id,
                      created_by, updated_by, created_at, updated_at
            """,
            tenant_id,
            slug,
            body.name,
            body.description,
            body.title,
            body.intro,
            body.submit_message,
            json.dumps(body.fields),
            json.dumps(body.alert_template),
            body.status,
            body.triage_strategy,
            body.auto_trigger_playbook_id,
            user_id,
        )

    return _serialize_form(row)


# Static-path routes must be declared BEFORE the dynamic /{form_id} route
# below — otherwise FastAPI matches them as form_id="templates" etc. and the
# UUID query crashes. See _load_templates() and create_from_template() below
# for the helpers these handlers use; those are defined later in the module
# but resolved at call time.


@router.get("/templates")
async def list_templates(user: Dict = Depends(get_current_user)):
    """
    Return all builtin intake-form templates. Slim list for the picker UI;
    full bodies are stitched in /from-template/{id}.
    """
    items = []
    for tpl in _load_templates():
        items.append({
            "template_id":       tpl.get("template_id"),
            "name":              tpl.get("name"),
            "description":       tpl.get("description"),
            "title":             tpl.get("title"),
            "category":          tpl.get("category", "Other"),
            "icon":              tpl.get("icon"),
            "field_count":       len(tpl.get("fields", [])),
            "estimated_minutes": tpl.get("estimated_minutes", 5),
            "default_severity":  (tpl.get("alert_template") or {}).get("severity", "medium"),
        })
    return {"templates": items, "total": len(items)}


@router.post("/from-template/{template_id}", status_code=201)
async def create_from_template(
    template_id: str,
    user: Dict = Depends(require_permission("playbook:edit")),
):
    """
    Create a draft intake form from a builtin template. Returns the new form
    (same shape as POST /api/v1/intake-forms).
    """
    templates = _load_templates()
    tpl = next((t for t in templates if t.get("template_id") == template_id), None)
    if not tpl:
        raise HTTPException(status_code=404, detail=f"Template not found: {template_id}")

    ok, err = forms_svc.validate_field_schema(tpl.get("fields", []))
    if not ok:
        logger.error(f"Template {template_id} has invalid field schema: {err}")
        raise HTTPException(status_code=500, detail=f"Template is currently invalid: {err}")

    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    tenant_id = user.get("tenant_id")
    user_id = user.get("user_id") or user.get("id")
    new_name = tpl.get("name") or "Form from template"
    slug = forms_svc.generate_slug(new_name)

    payload_for_db = {
        "name":           tpl.get("name", "Untitled form"),
        "description":    tpl.get("description", ""),
        "title":          tpl.get("title", ""),
        "intro":          tpl.get("intro", ""),
        "submit_message": tpl.get("submit_message", ""),
        "fields":         tpl.get("fields", []),
        "alert_template": tpl.get("alert_template") or {},
        "status":         "draft",
    }

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            INSERT INTO intake_forms (
                tenant_id, slug, name, description, title, intro, submit_message,
                fields, alert_template, status, created_by, updated_by
            ) VALUES (
                $1::uuid, $2, $3, $4, $5, $6, $7,
                $8::jsonb, $9::jsonb, $10, $11::uuid, $11::uuid
            )
            RETURNING id, tenant_id, slug, name, description, title, intro,
                      submit_message, fields, alert_template, status,
                      created_at, updated_at, created_by, updated_by
            """,
            tenant_id,
            slug,
            payload_for_db["name"],
            payload_for_db["description"],
            payload_for_db["title"],
            payload_for_db["intro"],
            payload_for_db["submit_message"],
            json.dumps(payload_for_db["fields"]),
            json.dumps(payload_for_db["alert_template"]),
            payload_for_db["status"],
            user_id,
        )

    return _serialize_form(row)


@router.get("/{form_id}")
async def get_form(
    form_id: str,
    user: Dict = Depends(require_permission("playbook:view")),
):
    """Get a single form by id (admin view)."""
    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, tenant_id, slug, name, description, title, intro,
                   submit_message, fields, alert_template, status,
                   triage_strategy, auto_trigger_playbook_id,
                   created_by, updated_by, created_at, updated_at
            FROM intake_forms WHERE id = $1::uuid
            """,
            form_id,
        )
    if not row:
        # 404, never 403 — don't reveal cross-tenant existence
        raise HTTPException(status_code=404, detail="Form not found")
    return _serialize_form(row)


@router.put("/{form_id}")
async def update_form(
    form_id: str,
    body: FormUpdate,
    user: Dict = Depends(require_permission("playbook:edit")),
):
    """Update a form. Slug is immutable (anti-enumeration token)."""
    if body.fields is not None:
        ok, err = forms_svc.validate_field_schema(body.fields)
        if not ok:
            raise HTTPException(status_code=400, detail=f"Invalid field schema: {err}")

    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    user_id = user.get("user_id") or user.get("id")

    sets: List[str] = []
    params: List[Any] = []
    idx = 1

    def add(col: str, value: Any, cast: str = ""):
        nonlocal idx
        sets.append(f"{col} = ${idx}{cast}")
        params.append(value)
        idx += 1

    if body.name is not None:                     add("name", body.name)
    if body.description is not None:              add("description", body.description)
    if body.title is not None:                    add("title", body.title)
    if body.intro is not None:                    add("intro", body.intro)
    if body.submit_message is not None:           add("submit_message", body.submit_message)
    if body.fields is not None:                   add("fields", json.dumps(body.fields), "::jsonb")
    if body.alert_template is not None:           add("alert_template", json.dumps(body.alert_template), "::jsonb")
    if body.status is not None:                   add("status", body.status)
    if body.triage_strategy is not None:          add("triage_strategy", body.triage_strategy)
    if body.auto_trigger_playbook_id is not None: add("auto_trigger_playbook_id", body.auto_trigger_playbook_id)

    if not sets:
        raise HTTPException(status_code=400, detail="No fields to update")

    add("updated_by", user_id, "::uuid")
    sets.append("updated_at = NOW()")

    params.append(form_id)
    where_idx = idx

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            f"""
            UPDATE intake_forms SET {', '.join(sets)}
            WHERE id = ${where_idx}::uuid
            RETURNING id, tenant_id, slug, name, description, title, intro,
                      submit_message, fields, alert_template, status,
                      triage_strategy, auto_trigger_playbook_id,
                      created_by, updated_by, created_at, updated_at
            """,
            *params,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Form not found")
    return _serialize_form(row)


@router.delete("/{form_id}", status_code=204)
async def delete_form(
    form_id: str,
    user: Dict = Depends(require_permission("playbook:edit")),
):
    """Delete a form. Submissions cascade-delete via FK."""
    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.tenant_acquire() as conn:
        result = await conn.execute(
            "DELETE FROM intake_forms WHERE id = $1::uuid",
            form_id,
        )
    # asyncpg returns "DELETE N"
    if result.endswith("0"):
        raise HTTPException(status_code=404, detail="Form not found")
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Submitter endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/by-slug/{slug}")
async def get_form_by_slug(slug: str, user: Dict = Depends(get_current_user)):
    """
    Fetch a form definition for rendering. Any authenticated user in the
    tenant may load an active form. Drafts/archived return 404.
    """
    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, slug, name, title, intro, submit_message, fields, status
            FROM intake_forms
            WHERE slug = $1 AND status = 'active'
            """,
            slug,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Form not found")
    return _serialize_form(row)


@router.post("/by-slug/{slug}/submit", status_code=201)
async def submit_form(
    slug: str,
    body: SubmitRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    user: Dict = Depends(get_current_user),
):
    """
    Submit a form. Validates payload against the field schema, inserts a
    form_submission, then hands off to the alert pipeline so Riggs/triage
    runs as for any other source.
    """
    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    tenant_id = user.get("tenant_id")
    user_id = user.get("user_id") or user.get("id")

    async with postgres_db.tenant_acquire() as conn:
        form_row = await conn.fetchrow(
            """
            SELECT id, tenant_id, slug, name, fields, alert_template, status,
                   triage_strategy, auto_trigger_playbook_id
            FROM intake_forms WHERE slug = $1 AND status = 'active'
            """,
            slug,
        )
        if not form_row:
            raise HTTPException(status_code=404, detail="Form not found")

        form = _serialize_form(form_row)
        # Triage strategy controls what happens after the alert is created:
        #   direct   — alert + investigation in NEW. No enrichment, no Riggs.
        #   enrich   — same + IOC enrichment. (Default)
        #   playbook — same + auto-fire the configured playbook.
        # Riggs LLM triage is unconditionally skipped for intake-form alerts
        # regardless of strategy — see skip_triage=True on enrich_alert_background below.
        triage_strategy = (form_row['triage_strategy'] or 'enrich').lower()
        auto_playbook_id = form_row['auto_trigger_playbook_id']

        # Validate payload against schema
        ok, err = forms_svc.validate_payload(form["fields"], body.payload)
        if not ok:
            raise HTTPException(status_code=400, detail=err)

        # Insert submission as 'submitted'
        sub_row = await conn.fetchrow(
            """
            INSERT INTO intake_form_submissions (
                tenant_id, form_id, submitted_by, payload, status
            ) VALUES (
                $1::uuid, $2::uuid, $3::uuid, $4::jsonb, 'submitted'
            )
            RETURNING id, created_at
            """,
            tenant_id,
            form["id"],
            user_id,
            json.dumps(body.payload),
        )
        submission_id = str(sub_row["id"])

        # Link any attachments referenced by file-type fields to this
        # submission. The payload value for each file field is the
        # attachment id returned by the /upload endpoint. We require the
        # attachment to belong to the same form and tenant (RLS handles
        # tenant; we check form_id explicitly), and to not already be
        # claimed by a different submission.
        attachment_records = []
        file_field_keys = {f["key"] for f in form["fields"] if f.get("type") == "file"}
        for key in file_field_keys:
            attachment_id = body.payload.get(key)
            if not attachment_id or not isinstance(attachment_id, str):
                continue
            try:
                uuid.UUID(attachment_id)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Field '{key}' has an invalid attachment id")
            att_row = await conn.fetchrow(
                """
                UPDATE intake_form_attachments
                   SET submission_id = $1::uuid
                 WHERE id = $2::uuid
                   AND form_id = $3::uuid
                   AND submission_id IS NULL
                   AND deleted_at IS NULL
                RETURNING id, filename, content_type, size_bytes
                """,
                submission_id,
                attachment_id,
                form["id"],
            )
            if not att_row:
                raise HTTPException(
                    status_code=400,
                    detail=f"Field '{key}': attachment not found or already used",
                )
            record = {
                "attachment_id": str(att_row["id"]),
                "field_key": key,
                "filename": att_row["filename"],
                "content_type": att_row["content_type"],
                "size_bytes": att_row["size_bytes"],
                "download_url": f"/api/v1/intake-forms/attachments/{att_row['id']}/download",
            }
            # If the attachment is a .eml (the standard for phishing
            # reports), parse it now and surface the structured headers /
            # body / auth-results on the alert. The original file is still
            # downloadable; this just gives Riggs and the analyst a
            # high-signal summary inline. Failures are non-fatal — the
            # attachment is still attached, just without parsed metadata.
            if eml_parser.is_eml(att_row["filename"], att_row["content_type"]):
                eml_path = upload_storage.get_upload_path(str(att_row["id"]))
                if eml_path:
                    try:
                        parsed = eml_parser.parse_eml_file(eml_path)
                        record["parsed_email"] = parsed
                    except Exception as e:
                        logger.warning(
                            f"eml parse failed for attachment {att_row['id']}: {e}"
                        )
            attachment_records.append(record)

    # Build the Alert payload + hand off to the alert pipeline. We replicate
    # the storage-and-enrichment pattern from app.py:ingest_alert here so we
    # don't introduce a circular import; the same background task chain runs.
    alert_dict = forms_svc.build_alert_dict(
        form=form,
        submission_id=submission_id,
        payload=body.payload,
        submitted_by=str(user_id),
    )

    # Surface attachment metadata to the analyst directly in the alert.
    # Storing the URL means they can click straight to the file from the
    # case view without a second lookup.
    if attachment_records:
        alert_dict.setdefault("metadata", {})["attachments"] = attachment_records
        alert_dict.setdefault("raw_event", {}).setdefault("form_submission", {})["attachments"] = attachment_records

    alert_id = f"alert-{uuid.uuid4().hex[:8]}"
    pg_alert = {
        "alert_id": alert_id,
        "title": alert_dict["title"],
        "description": alert_dict.get("description", ""),
        "severity": alert_dict["severity"],
        "status": "open",
        "source": alert_dict["source"],
        "source_type": "intake_form",
        "raw_event": alert_dict.get("raw_event") or alert_dict,
    }

    try:
        await postgres_db.create_alert(pg_alert)
    except Exception as e:
        logger.exception("Failed to create alert from form submission %s: %s", submission_id, e)
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                UPDATE intake_form_submissions
                   SET status = 'failed',
                       error_message = $1,
                       updated_at = NOW()
                 WHERE id = $2::uuid
                """,
                str(e)[:500],
                submission_id,
            )
        raise HTTPException(status_code=500, detail="Failed to ingest submission")

    # Auto-create the investigation in state=NEW so the submission lands
    # directly in the analyst queue without waiting for downstream Riggs
    # triage (which we skip entirely for intake-form alerts). This is the
    # piece that historically caused submissions to look stuck in limbo.
    investigation_id = None
    try:
        async with postgres_db.tenant_acquire() as conn:
            alert_uuid_row = await conn.fetchrow(
                "SELECT id FROM alerts WHERE alert_id = $1",
                alert_id,
            )
            if alert_uuid_row:
                inv_pretty_id = f"INV-{uuid.uuid4().hex[:8].upper()}"
                inv_row = await conn.fetchrow(
                    """
                    INSERT INTO investigations (
                        tenant_id, investigation_id, alert_id, state, severity,
                        alert_title, executive_summary, priority
                    ) VALUES (
                        $1::uuid, $2, $3::uuid, 'NEW', $4,
                        $5, $6, 'P3'
                    )
                    RETURNING id, investigation_id
                    """,
                    tenant_id,
                    inv_pretty_id,
                    alert_uuid_row['id'],
                    pg_alert.get('severity', 'medium'),
                    pg_alert['title'][:500],
                    # Deterministic executive summary built from the form fields —
                    # no LLM. Riggs won't be looking at this; the analyst will.
                    forms_svc.build_executive_summary(form, body.payload, submitted_by=str(user_id)),
                )
                investigation_id = str(inv_row['investigation_id'])
                # Link the alert to its investigation so the queue dedups them.
                await conn.execute(
                    "UPDATE alerts SET investigation_id = $1 WHERE id = $2",
                    inv_row['id'],
                    alert_uuid_row['id'],
                )
    except Exception as inv_err:
        logger.warning(
            "Form submission %s: investigation auto-create failed: %s",
            submission_id, inv_err,
        )

    # Mark submission as processing and link it to the alert + investigation
    async with postgres_db.tenant_acquire() as conn:
        await conn.execute(
            """
            UPDATE intake_form_submissions
               SET status = 'processing',
                   alert_id = $1,
                   investigation_id = $2,
                   updated_at = NOW()
             WHERE id = $3::uuid
            """,
            alert_id,
            investigation_id,
            submission_id,
        )

    # Branch on the form's triage_strategy:
    #   direct   — no background work; alert + investigation are enough
    #   enrich   — IOC enrichment only (skip_triage=True)
    #   playbook — enrichment + fire the configured playbook
    if triage_strategy in ('enrich', 'playbook'):
        try:
            from services.auto_enrichment import enrich_alert_background
            background_tasks.add_task(
                enrich_alert_background,
                alert_id=alert_id,
                raw_event=pg_alert["raw_event"],
                tenant_id=tenant_id,
                skip_triage=True,  # Riggs has nothing useful to add — user already classified the report
            )
        except Exception as e:
            logger.warning("Form submission %s: enrichment enqueue failed: %s", submission_id, e)

    if triage_strategy == 'playbook' and auto_playbook_id:
        # Run the configured playbook against this submission as the
        # trigger context. Tenant context has to be re-established inside
        # the background task — FastAPI background tasks lose the request
        # contextvar by the time they run.
        async def _fire_intake_playbook(
            playbook_id_str: str,
            tenant_id_str: str,
            trigger_ctx: dict,
            actor: str,
        ):
            try:
                from middleware.tenant_middleware import current_tenant_id as _tenant_ctx_var
                _tenant_ctx_var.set(tenant_id_str)
                from services.playbook_engine import get_playbook_engine
                engine = get_playbook_engine()
                await engine.start_execution(
                    playbook_id=playbook_id_str,
                    trigger_context=trigger_ctx,
                    triggered_by="intake_form",
                    triggered_by_user_id=actor,
                )
            except Exception as e:
                logger.warning(
                    "Intake-form playbook %s execution failed: %s",
                    playbook_id_str, e,
                )

        try:
            background_tasks.add_task(
                _fire_intake_playbook,
                str(auto_playbook_id),
                str(tenant_id),
                {
                    "source": "intake_form",
                    "form_id": str(form["id"]),
                    "form_name": form.get("name"),
                    "submission_id": submission_id,
                    "alert_id": alert_id,
                    "investigation_id": investigation_id,
                    "submitted_by": str(user_id),
                    "payload": body.payload,
                },
                str(user_id),
            )
        except Exception as pb_err:
            logger.warning(
                "Form submission %s: playbook %s enqueue failed: %s",
                submission_id, auto_playbook_id, pb_err,
            )

    return {
        "submission_id": submission_id,
        "alert_id": alert_id,
        "status": "processing",
        "submit_message": form.get("submit_message")
            or "Thanks — your submission was received and is being triaged.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Submission browsing (admin)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/{form_id}/submissions")
async def list_submissions(
    form_id: str,
    status: Optional[str] = Query(default=None, pattern="^(submitted|processing|completed|failed)$"),
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    user: Dict = Depends(require_permission("playbook:view")),
):
    """List submissions for a form."""
    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    params: List[Any] = [form_id]
    where = "WHERE form_id = $1::uuid"
    if status:
        params.append(status)
        where += f" AND status = ${len(params)}"

    params_for_count = list(params)
    params.extend([limit, offset])

    async with postgres_db.tenant_acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT id, form_id, submitted_by, payload, alert_id,
                   investigation_id, status, error_message,
                   created_at, updated_at
            FROM intake_form_submissions
            {where}
            ORDER BY created_at DESC
            LIMIT ${len(params) - 1} OFFSET ${len(params)}
            """,
            *params,
        )
        total_row = await conn.fetchrow(
            f"SELECT COUNT(*) AS n FROM intake_form_submissions {where}",
            *params_for_count,
        )

    return {
        "items": [_serialize_form(r) for r in rows],
        "total": total_row["n"] if total_row else 0,
        "limit": limit,
        "offset": offset,
    }


@router.get("/submissions/{submission_id}")
async def get_submission(
    submission_id: str,
    user: Dict = Depends(require_permission("playbook:view")),
):
    """Fetch one submission with full payload."""
    from services.postgres_db import postgres_db
    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, form_id, submitted_by, payload, alert_id,
                   investigation_id, status, error_message,
                   created_at, updated_at
            FROM intake_form_submissions WHERE id = $1::uuid
            """,
            submission_id,
        )
    if not row:
        raise HTTPException(status_code=404, detail="Submission not found")
    return _serialize_form(row)


# ─────────────────────────────────────────────────────────────────────────────
# AI generation — Riggs designs the form from a natural-language description
# ─────────────────────────────────────────────────────────────────────────────


class GenerateFormRequest(BaseModel):
    description: str = Field(..., min_length=10, max_length=2000)
    # When present, Riggs treats the description as a MODIFICATION to apply
    # to the supplied form, not a from-scratch design. Returns the complete
    # updated schema (not a diff). Frontend sends this whenever the editor
    # already has a draft, so users can say things like "add a checkbox for
    # urgency" or "remove the optional fields" without losing their work.
    current_form: Optional[Dict[str, Any]] = None


_GENERATE_SYSTEM_PROMPT = """You are Riggs, an expert at designing intake forms for security operations.

End users (employees, partners, contractors) submit these forms when they need to report something to the SOC: a phishing email they received, a suspicious file, an incident they witnessed, lost credentials, etc. The submission becomes an alert in the SOC's queue.

Design forms that are:
- Friendly to non-security users — no jargon
- Concise — 5 to 8 fields, never more than 12
- Captures the information the SOC actually needs to triage
- Uses the right field type for each input

Field types available:
- text          — single-line text
- textarea      — multi-line (descriptions, full email bodies)
- email         — email address with validation
- url           — URL with validation
- select        — single-choice dropdown (provide options array)
- multiselect   — multi-choice (provide options array)
- datetime      — date and time picker
- file          — file upload (email attachments, suspicious files)

Every field MUST include a `sample_value` showing what a realistic submission would look like for THIS specific form. Sample values are used by the editor's live preview so admins can see what an analyst would actually receive. Pick realistic, in-character examples — phisher@suspicious-domain.com (not "user@example.com"), an actual-sounding subject line, a believable filename. For select/multiselect, pick one or two of the options you defined. For file fields, suggest a plausible filename including extension.

Every field SHOULD include a `help` line — a one-sentence hint shown under the field that tells the submitter how to fill it in. Keep it short and helpful.

The alert_template uses {{field_key}} substitution to create the SOC alert from submitted values. Fill in ALL FIVE template fields (title, description, severity, source, category) — do not leave any blank. Pick a severity that matches the urgency of the form's purpose: "low" for FYI / awareness, "medium" for routine reports, "high" for active incidents, "critical" for confirmed compromise.

RESPOND WITH JSON ONLY. No prose. No markdown fences. Match this exact schema:

{
  "name": "<internal admin-facing name>",
  "description": "<admin-only description of what this form is for>",
  "title": "<heading the submitter sees on the form>",
  "intro": "<markdown OK, optional context shown above the fields>",
  "submit_message": "<confirmation text shown after submit>",
  "fields": [
    {
      "key": "<snake_case>",
      "label": "<submitter-facing label>",
      "type": "text|textarea|email|url|select|multiselect|datetime|file",
      "required": true|false,
      "help": "<one-sentence hint for the submitter>",
      "placeholder": "<short example text in the empty input>",
      "options": ["only", "for", "select", "and", "multiselect"],
      "sample_value": "<a realistic value for the editor's preview>"
    }
  ],
  "alert_template": {
    "title": "<must use {{field_key}} substitutions — never leave blank>",
    "description": "<multi-line; use {{field_key}} substitutions to surface the submitted data>",
    "severity": "low|medium|high|critical",
    "source": "intake_form",
    "category": "<short tag, e.g. phishing, malware_analysis, credential_theft>"
  }
}

Keys must be snake_case, lowercase, no leading numbers. Do NOT include an "options" key on non-option field types. Do NOT add fields the SOC won't actually use. Do NOT leave alert_template fields blank."""


@router.post("/generate")
async def generate_form_with_riggs(
    body: GenerateFormRequest,
    user: Dict = Depends(require_permission("playbook:edit")),
):
    """
    Use Riggs to draft an intake form from a natural-language description.

    Returns a form schema that the editor preloads into its state. Does NOT
    save — the user reviews, refines, and saves manually.
    """
    from uuid import UUID
    from services.claude_service import get_claude_service, QuotaExceededError

    tenant_id_str = user.get("tenant_id")
    if not tenant_id_str:
        raise HTTPException(status_code=400, detail="No tenant context")
    try:
        tenant_uuid = UUID(str(tenant_id_str))
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid tenant id")

    claude = await get_claude_service()
    if not claude.is_configured:
        raise HTTPException(
            status_code=503,
            detail="Riggs (LLM) is not configured in this environment. Set ANTHROPIC_API_KEY.",
        )

    if body.current_form:
        # Compact the existing form for the prompt — drop fields that don't
        # affect the schema decisions (status, etc.) so we don't waste tokens.
        # The model sees the structural pieces it needs to reason about.
        existing = {
            "name":           body.current_form.get("name", ""),
            "description":    body.current_form.get("description", ""),
            "title":          body.current_form.get("title", ""),
            "intro":          body.current_form.get("intro", ""),
            "submit_message": body.current_form.get("submit_message", ""),
            "fields":         body.current_form.get("fields", []),
            "alert_template": body.current_form.get("alert_template", {}),
        }
        user_prompt = (
            "Here is the existing intake form:\n\n"
            "```json\n"
            f"{json.dumps(existing, indent=2)}\n"
            "```\n\n"
            "Apply this change to it. Return the COMPLETE updated form schema, "
            "not a diff. Preserve fields and copy that aren't affected by the "
            "request.\n\n"
            f"Change requested:\n{body.description.strip()}"
        )
    else:
        user_prompt = f"Design an intake form for this use case:\n\n{body.description.strip()}"

    try:
        response = await claude.complete(
            tenant_id=tenant_uuid,
            prompt=user_prompt,
            system=_GENERATE_SYSTEM_PROMPT,
            max_tokens=2500,
            temperature=0.3,
            request_type="intake_form_generator",
        )
    except QuotaExceededError as qe:
        raise HTTPException(status_code=429, detail=str(qe))
    except RuntimeError as re:
        # claude_service raises RuntimeError for connection / non-200 errors
        logger.error(f"Riggs form-generation API error: {re}")
        raise HTTPException(
            status_code=502,
            detail="Riggs couldn't generate a form right now. Please try again.",
        )

    # Parse the JSON response. The prompt is explicit about format but
    # frontier models sometimes wrap output in markdown fences regardless;
    # strip those defensively before json.loads.
    text = response.text.strip()
    if text.startswith("```"):
        # ```json … ``` or just ``` … ```
        first_newline = text.find("\n")
        if first_newline > 0:
            text = text[first_newline + 1:]
    if text.endswith("```"):
        text = text[:-3].strip()
    text = text.strip()

    try:
        form_schema = json.loads(text)
    except json.JSONDecodeError as jde:
        logger.warning(
            f"Riggs form-gen returned invalid JSON: {jde}. "
            f"Raw output (first 500 chars): {response.text[:500]!r}"
        )
        raise HTTPException(
            status_code=502,
            detail="Riggs returned a malformed form schema. Try simplifying or rewording your description.",
        )

    # Safety defaults — fill in anything the model omitted so the editor
    # doesn't crash on missing keys.
    form_schema.setdefault("name", "Riggs-generated form")
    form_schema.setdefault("description", "")
    form_schema.setdefault("title", form_schema.get("name") or "")
    form_schema.setdefault("intro", "")
    form_schema.setdefault("submit_message", "")
    form_schema.setdefault("fields", [])
    form_schema.setdefault(
        "alert_template",
        {"title": "", "description": "", "severity": "medium", "source": "intake_form", "category": ""},
    )
    form_schema["status"] = "draft"

    # Validate field schema against the same rules used by manual creation,
    # so we surface bad output now rather than at save time.
    ok, err = forms_svc.validate_field_schema(form_schema.get("fields", []))
    if not ok:
        logger.warning(f"Riggs form-gen produced invalid fields: {err}")
        # Don't fail — let the user fix it in the editor. Just attach a warning.
        return {
            "form": form_schema,
            "generated_by": "riggs",
            "warning": f"Riggs's draft has a schema issue you'll need to fix: {err}",
            "tokens": {
                "input": response.input_tokens,
                "output": response.output_tokens,
            },
        }

    return {
        "form": form_schema,
        "generated_by": "riggs",
        "tokens": {
            "input": response.input_tokens,
            "output": response.output_tokens,
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Builtin templates — pre-baked forms tenants can start from
# ─────────────────────────────────────────────────────────────────────────────

import os
from functools import lru_cache
from pathlib import Path

_TEMPLATES_DIR = Path(os.environ.get(
    "INTAKE_TEMPLATES_DIR",
    str(Path(__file__).resolve().parent.parent / "data" / "intake_form_templates"),
))


@lru_cache(maxsize=1)
def _load_templates() -> List[Dict[str, Any]]:
    """
    Read all template JSON files from disk once at first access and cache.

    Templates are versioned with the codebase (drop a new .json file in
    backend/data/intake_form_templates/ and it shows up on next backend
    restart). No per-tenant state.
    """
    if not _TEMPLATES_DIR.exists():
        logger.warning(f"Intake template dir missing: {_TEMPLATES_DIR}")
        return []

    out: List[Dict[str, Any]] = []
    for p in sorted(_TEMPLATES_DIR.glob("*.json")):
        try:
            with open(p, "r", encoding="utf-8") as f:
                tpl = json.load(f)
            tpl.setdefault("template_id", p.stem)
            out.append(tpl)
        except Exception as e:
            logger.error(f"Failed to load intake template {p}: {e}")
    logger.info(f"Loaded {len(out)} builtin intake-form templates")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# File attachments — upload, download, and TTL cleanup
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/by-slug/{slug}/upload", status_code=201)
async def upload_attachment(
    slug: str,
    field_key: str = Form(...),
    file: UploadFile = File(...),
    user: Dict = Depends(get_current_user),
):
    """
    Upload a file attachment for a file-type form field.

    Returns an attachment id. The caller MUST include that id under the
    matching field key in the eventual form-submission payload — otherwise
    the upload TTL-expires after 14 days without ever being linked to a
    submission.

    Validation:
    - The form must be active and the field_key must exist as a file field.
    - Content-type / extension must not be on the executable deny list.
    - Stream size enforced mid-upload against INTAKE_UPLOAD_MAX_BYTES.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    tenant_id = user.get("tenant_id")
    user_id = user.get("user_id") or user.get("id")

    # Look up the form. RLS scopes by tenant automatically.
    async with postgres_db.tenant_acquire() as conn:
        form_row = await conn.fetchrow(
            "SELECT id, fields FROM intake_forms WHERE slug = $1 AND status = 'active'",
            slug,
        )
    if not form_row:
        raise HTTPException(status_code=404, detail="Form not found")

    fields = form_row["fields"]
    if isinstance(fields, str):
        fields = json.loads(fields)

    field_def = next((f for f in (fields or []) if f.get("key") == field_key), None)
    if not field_def:
        raise HTTPException(status_code=400, detail=f"Unknown field: {field_key}")
    if field_def.get("type") != "file":
        raise HTTPException(
            status_code=400,
            detail=f"Field '{field_key}' is not a file upload field",
        )

    # Type / extension deny check before we burn disk on a stream we'd reject.
    content_type = file.content_type or "application/octet-stream"
    original_name = file.filename or "upload"
    if upload_storage.is_denied(original_name, content_type):
        raise HTTPException(
            status_code=415,
            detail=f"File type not allowed ({content_type or 'unknown'}, {original_name})",
        )

    attachment_id = str(uuid.uuid4())
    sanitized_name = upload_storage.sanitize_filename(original_name)

    try:
        size_bytes = upload_storage.store_upload(attachment_id, file.file)
    except ValueError as ve:
        raise HTTPException(status_code=413, detail=str(ve))
    except Exception as e:
        logger.error(f"Upload {attachment_id} failed: {e}")
        raise HTTPException(status_code=500, detail="Upload failed")

    storage_path = str(upload_storage.attachment_storage_path(attachment_id))

    try:
        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                """
                INSERT INTO intake_form_attachments (
                    id, tenant_id, form_id, field_key, filename, content_type,
                    size_bytes, storage_path, uploaded_by
                ) VALUES (
                    $1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9::uuid
                )
                """,
                attachment_id,
                tenant_id,
                form_row["id"],
                field_key,
                sanitized_name,
                content_type,
                size_bytes,
                storage_path,
                user_id,
            )
    except Exception as e:
        # If the row insert fails, drop the disk file — otherwise we leak.
        upload_storage.delete_upload(attachment_id)
        logger.error(f"Failed to record attachment {attachment_id}: {e}")
        raise HTTPException(status_code=500, detail="Upload record failed")

    return {
        "attachment_id": attachment_id,
        "filename": sanitized_name,
        "content_type": content_type,
        "size_bytes": size_bytes,
    }


@router.get("/attachments/{attachment_id}/download")
async def download_attachment(
    attachment_id: str,
    user: Dict = Depends(get_current_user),
):
    """
    Stream an attachment back to the requester for SOC review.

    RLS scopes by tenant — a cross-tenant attachment id returns 404 as if
    it didn't exist. Files whose TTL has been swept return 410 Gone with
    the metadata still readable.
    """
    from services.postgres_db import postgres_db

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    try:
        uuid.UUID(attachment_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid attachment id")

    async with postgres_db.tenant_acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT filename, content_type, storage_path, deleted_at
            FROM intake_form_attachments
            WHERE id = $1::uuid
            """,
            attachment_id,
        )

    if not row:
        raise HTTPException(status_code=404, detail="Attachment not found")
    if row["deleted_at"]:
        raise HTTPException(
            status_code=410,
            detail="Attachment has been deleted (TTL expired)",
        )

    path = upload_storage.get_upload_path(attachment_id)
    if not path:
        # DB says alive but disk is gone — backfill the deleted_at flag so
        # future reads return 410 with no disk hit.
        try:
            async with postgres_db.tenant_acquire() as conn:
                await conn.execute(
                    "UPDATE intake_form_attachments SET deleted_at = NOW() WHERE id = $1::uuid AND deleted_at IS NULL",
                    attachment_id,
                )
        except Exception:
            pass
        raise HTTPException(status_code=410, detail="Underlying file is gone")

    return FileResponse(
        path,
        filename=row["filename"],
        media_type=row["content_type"] or "application/octet-stream",
    )


@router.post("/attachments/_cleanup-expired", include_in_schema=False)
async def cleanup_expired_attachments(
    user: Dict = Depends(require_permission("playbook:edit")),
):
    """
    Internal: sweep attachments past their TTL, delete from disk + mark
    deleted_at. Safe to call repeatedly. Returns counts.

    Wired into agent_scheduler's daily housekeeping. Exposed here for
    manual triggering during ops work; not in the OpenAPI surface.
    """
    from services.postgres_db import postgres_db, set_platform_admin_mode

    if not postgres_db.connected:
        raise HTTPException(status_code=503, detail="Database not connected")

    deleted_count = 0
    set_platform_admin_mode(True)
    try:
        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT id FROM intake_form_attachments
                WHERE expires_at < NOW() AND deleted_at IS NULL
                LIMIT 1000
                """
            )
            for row in rows:
                upload_storage.delete_upload(str(row["id"]))
                await conn.execute(
                    "UPDATE intake_form_attachments SET deleted_at = NOW() WHERE id = $1::uuid",
                    row["id"],
                )
                deleted_count += 1
    finally:
        set_platform_admin_mode(False)

    return {"deleted_count": deleted_count}
