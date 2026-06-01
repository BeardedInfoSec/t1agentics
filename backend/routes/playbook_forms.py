# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Forms API Routes

Endpoints for managing webforms used in playbook execution.
Includes both admin endpoints and public form submission endpoints.

SECURITY: Public form endpoints require HMAC-signed tokens to prevent
URL guessing attacks. Tokens include expiry timestamps.
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Request, Query, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import logging
import json
import hmac
import hashlib
import os
import time
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

# ============================================================================
# SECURITY: Token signing for public form URLs
# ============================================================================

FORM_TOKEN_SECRET = os.environ.get(
    "FORM_TOKEN_SECRET",
    os.environ.get("JWT_SECRET_KEY", "change-me-in-production")
)
FORM_TOKEN_EXPIRY_HOURS = int(os.environ.get("FORM_TOKEN_EXPIRY_HOURS", "72"))


def generate_form_token(execution_id: str, node_id: str, expires_at: Optional[int] = None) -> str:
    """
    Generate an HMAC-signed token for public form access.

    Token format: {expiry_timestamp}:{signature}
    Signature = HMAC-SHA256(secret, execution_id:node_id:expiry)
    """
    if expires_at is None:
        expires_at = int(time.time()) + (FORM_TOKEN_EXPIRY_HOURS * 3600)

    message = f"{execution_id}:{node_id}:{expires_at}"
    signature = hmac.new(
        FORM_TOKEN_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()

    return f"{expires_at}:{signature}"


def verify_form_token(execution_id: str, node_id: str, token: str) -> tuple[bool, str]:
    """
    Verify an HMAC-signed form token.

    Returns: (is_valid, error_message)
    """
    if not token:
        return False, "Missing form token"

    try:
        parts = token.split(":")
        if len(parts) != 2:
            return False, "Invalid token format"

        expires_at = int(parts[0])
        provided_signature = parts[1]

        # Check expiry
        if time.time() > expires_at:
            return False, "Token has expired"

        # Verify signature
        message = f"{execution_id}:{node_id}:{expires_at}"
        expected_signature = hmac.new(
            FORM_TOKEN_SECRET.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(provided_signature, expected_signature):
            return False, "Invalid token signature"

        return True, ""

    except (ValueError, IndexError) as e:
        return False, f"Token verification failed: {e}"

router = APIRouter(prefix="/api/v1/playbook-forms", tags=["Playbook Forms"], dependencies=[Depends(get_current_user)])


# ============================================================================
# Request/Response Models
# ============================================================================

class FormFieldRequest(BaseModel):
    name: str
    label: str
    type: str = "text"  # text, textarea, number, email, select, multiselect, checkbox, radio, date, datetime, file
    required: bool = False
    default: Optional[Any] = None
    placeholder: Optional[str] = None
    help_text: Optional[str] = None
    options: Optional[List[Dict[str, str]]] = None  # For select/radio
    validation: Optional[Dict[str, Any]] = None


class CreateFormRequest(BaseModel):
    name: str
    description: Optional[str] = None
    fields: List[FormFieldRequest]
    submit_label: str = "Submit"


class UpdateFormRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    fields: Optional[List[FormFieldRequest]] = None
    submit_label: Optional[str] = None


class FormSubmissionRequest(BaseModel):
    form_data: Dict[str, Any]
    submitted_by: Optional[str] = None


class FileUploadCompleteRequest(BaseModel):
    files: List[Dict[str, Any]]
    uploaded_by: Optional[str] = None


# ============================================================================
# Admin Form CRUD Endpoints
# ============================================================================

@router.get("")
async def list_forms(
    limit: int = 100,
    offset: int = 0
):
    """List all form templates."""
    from services.webform_service import get_webform_service

    service = get_webform_service()
    forms = await service.list_forms(limit=limit, offset=offset)

    return {
        "forms": forms,
        "count": len(forms),
        "limit": limit,
        "offset": offset
    }


@router.post("")
async def create_form(
    request: CreateFormRequest,
    user: Dict = Depends(get_current_user),
):
    """Create a new form template."""
    from services.webform_service import get_webform_service

    tenant_id = user.get("tenant_id")
    if not tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id missing from auth context")

    service = get_webform_service()
    result = await service.create_form(
        tenant_id=str(tenant_id),
        name=request.name,
        fields=[f.dict() for f in request.fields],
        description=request.description,
        submit_label=request.submit_label,
        created_by=str(user.get("id")) if user.get("id") else None,
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@router.get("/{form_id}")
async def get_form(form_id: str):
    """Get form template by ID."""
    from services.webform_service import get_webform_service

    service = get_webform_service()
    form = await service.get_form(form_id)

    if not form:
        raise HTTPException(status_code=404, detail="Form not found")

    return form


@router.put("/{form_id}")
async def update_form(form_id: str, request: UpdateFormRequest):
    """Update a form template."""
    from services.webform_service import get_webform_service

    service = get_webform_service()
    result = await service.update_form(
        form_id=form_id,
        name=request.name,
        description=request.description,
        fields=[f.dict() for f in request.fields] if request.fields else None,
        submit_label=request.submit_label
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@router.delete("/{form_id}")
async def delete_form(form_id: str):
    """Delete a form template."""
    from services.webform_service import get_webform_service

    service = get_webform_service()
    success = await service.delete_form(form_id)

    if not success:
        raise HTTPException(status_code=404, detail="Form not found or could not be deleted")

    return {"deleted": True}


# ============================================================================
# Public Form Endpoints (No Auth Required)
# ============================================================================

# These endpoints use a separate router for public access
public_router = APIRouter(prefix="/api/v1/public/forms", tags=["Public Forms"])


@public_router.get("/{execution_id}/{node_id}")
async def get_public_form(
    execution_id: str,
    node_id: str,
    token: str = Query(..., description="HMAC-signed access token")
):
    """
    Get form context for public rendering.

    This endpoint is called when a user opens a form URL from a playbook.
    Returns form definition and context for rendering.

    SECURITY: Requires a valid HMAC-signed token to prevent URL guessing.
    """
    # Verify token
    is_valid, error = verify_form_token(execution_id, node_id, token)
    if not is_valid:
        logger.warning(f"Form token verification failed: {error} (exec={execution_id}, node={node_id})")
        raise HTTPException(status_code=403, detail=error)

    from services.webform_service import get_webform_service

    service = get_webform_service()
    context = await service.get_public_form_context(execution_id, node_id)

    if not context:
        raise HTTPException(status_code=404, detail="Form not found or expired")

    if context.is_expired:
        return JSONResponse(
            status_code=410,
            content={"error": "Form has expired", "expired": True}
        )

    if context.already_submitted:
        return JSONResponse(
            status_code=409,
            content={"error": "Form already submitted", "already_submitted": True}
        )

    return {
        "form_id": context.form_id,
        "execution_id": context.execution_id,
        "node_id": context.node_id,
        "form": {
            "name": context.form_definition.name,
            "description": context.form_definition.description,
            "fields": [f.dict() for f in context.form_definition.fields],
            "submit_label": context.form_definition.submit_label
        },
        "prefilled_data": context.prefilled_data,
        "expires_at": context.expires_at.isoformat() if context.expires_at else None
    }


@public_router.post("/{execution_id}/{node_id}/submit")
async def submit_public_form(
    execution_id: str,
    node_id: str,
    request: FormSubmissionRequest,
    token: str = Query(..., description="HMAC-signed access token")
):
    """
    Submit a form and resume playbook execution.

    This is the public endpoint for form submission.

    SECURITY: Requires a valid HMAC-signed token.
    """
    # Verify token
    is_valid, error = verify_form_token(execution_id, node_id, token)
    if not is_valid:
        logger.warning(f"Form submit token verification failed: {error}")
        raise HTTPException(status_code=403, detail=error)

    from services.webform_service import get_webform_service

    service = get_webform_service()
    result = await service.submit_form(
        execution_id=execution_id,
        node_id=node_id,
        form_data=request.form_data,
        submitted_by=request.submitted_by
    )

    if "error" in result:
        if "Validation failed" in result.get("error", ""):
            raise HTTPException(
                status_code=422,
                detail={
                    "error": result["error"],
                    "validation_errors": result.get("validation_errors", {})
                }
            )
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@public_router.post("/{execution_id}/{node_id}/upload")
async def upload_file(
    execution_id: str,
    node_id: str,
    file: UploadFile = File(...),
    token: str = Query(..., description="HMAC-signed access token"),
    uploaded_by: Optional[str] = Form(None)
):
    """
    Upload a file for a form or file_upload node.

    Returns file metadata. Call complete endpoint after all files uploaded.

    SECURITY: Requires a valid HMAC-signed token.
    """
    # Verify token
    is_valid, error = verify_form_token(execution_id, node_id, token)
    if not is_valid:
        logger.warning(f"File upload token verification failed: {error}")
        raise HTTPException(status_code=403, detail=error)

    from services.webform_service import get_webform_service

    # Read file data
    file_data = await file.read()

    service = get_webform_service()
    result = await service.handle_file_upload(
        execution_id=execution_id,
        node_id=node_id,
        filename=file.filename,
        file_data=file_data,
        uploaded_by=uploaded_by
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


@public_router.post("/{execution_id}/{node_id}/upload/complete")
async def complete_file_upload(
    execution_id: str,
    node_id: str,
    request: FileUploadCompleteRequest,
    token: str = Query(..., description="HMAC-signed access token")
):
    """
    Complete file upload and resume playbook execution.

    Call this after all files have been uploaded.

    SECURITY: Requires a valid HMAC-signed token.
    """
    # Verify token
    is_valid, error = verify_form_token(execution_id, node_id, token)
    if not is_valid:
        logger.warning(f"Upload complete token verification failed: {error}")
        raise HTTPException(status_code=403, detail=error)

    from services.webform_service import get_webform_service

    service = get_webform_service()
    result = await service.complete_file_upload(
        execution_id=execution_id,
        node_id=node_id,
        files=request.files,
        uploaded_by=request.uploaded_by
    )

    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])

    return result


# ============================================================================
# Rendered Form Page (HTML)
# ============================================================================

@public_router.get("/{execution_id}/{node_id}/page", response_class=HTMLResponse)
async def render_form_page(
    execution_id: str,
    node_id: str,
    token: str = Query(..., description="HMAC-signed access token")
):
    """
    Render a standalone HTML page for form submission.

    This allows forms to be opened in a browser without requiring
    the full frontend application.

    SECURITY: Requires a valid HMAC-signed token.
    """
    # Verify token
    is_valid, error = verify_form_token(execution_id, node_id, token)
    if not is_valid:
        logger.warning(f"Form page token verification failed: {error}")
        return HTMLResponse(
            content=_render_error_page("Access Denied", error),
            status_code=403
        )

    from services.webform_service import get_webform_service

    service = get_webform_service()
    context = await service.get_public_form_context(execution_id, node_id)

    if not context:
        return HTMLResponse(
            content=_render_error_page("Form not found", "The requested form does not exist or has been removed."),
            status_code=404
        )

    if context.is_expired:
        return HTMLResponse(
            content=_render_error_page("Form Expired", "This form has expired and can no longer be submitted."),
            status_code=410
        )

    if context.already_submitted:
        return HTMLResponse(
            content=_render_success_page("Already Submitted", "This form has already been submitted."),
            status_code=200
        )

    # Render form HTML - pass token so form can submit
    html = _render_form_page(context, execution_id, node_id, token)
    return HTMLResponse(content=html)


def _render_form_page(context, execution_id: str, node_id: str, token: str = "") -> str:
    """Render HTML form page with signed token for secure submission."""
    form = context.form_definition
    prefilled = context.prefilled_data or {}

    fields_html = []
    for field in form.fields:
        field_html = _render_field(field, prefilled.get(field.name))
        fields_html.append(field_html)

    return f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{form.name} - T1 Agentics</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0f172a;
            color: #f0f6fc;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: #1e293b;
            border-radius: 12px;
            padding: 32px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}
        h1 {{
            margin: 0 0 8px 0;
            font-size: 24px;
            color: #f0f6fc;
        }}
        .description {{
            color: #94a3b8;
            margin-bottom: 24px;
        }}
        .field {{
            margin-bottom: 20px;
        }}
        label {{
            display: block;
            font-weight: 500;
            margin-bottom: 6px;
            color: #e2e8f0;
        }}
        .required {{
            color: #ef4444;
        }}
        input[type="text"],
        input[type="email"],
        input[type="number"],
        input[type="date"],
        input[type="datetime-local"],
        textarea,
        select {{
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #334155;
            border-radius: 6px;
            background: #0f172a;
            color: #f0f6fc;
            font-size: 14px;
        }}
        input:focus, textarea:focus, select:focus {{
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }}
        textarea {{
            resize: vertical;
            min-height: 100px;
        }}
        .help-text {{
            font-size: 12px;
            color: #64748b;
            margin-top: 4px;
        }}
        .checkbox-group, .radio-group {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .checkbox-item, .radio-item {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .checkbox-item input, .radio-item input {{
            width: auto;
        }}
        button[type="submit"] {{
            width: 100%;
            padding: 12px;
            background: #3b82f6;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            margin-top: 16px;
        }}
        button[type="submit"]:hover {{
            background: #2563eb;
        }}
        button[type="submit"]:disabled {{
            background: #475569;
            cursor: not-allowed;
        }}
        .error {{
            color: #ef4444;
            font-size: 12px;
            margin-top: 4px;
        }}
        .field-error input,
        .field-error textarea,
        .field-error select {{
            border-color: #ef4444;
        }}
        .success-message {{
            background: #065f46;
            color: #34d399;
            padding: 16px;
            border-radius: 6px;
            text-align: center;
            display: none;
        }}
        .error-message {{
            background: #7f1d1d;
            color: #fca5a5;
            padding: 16px;
            border-radius: 6px;
            margin-bottom: 16px;
            display: none;
        }}
        .spinner {{
            display: none;
            width: 20px;
            height: 20px;
            border: 2px solid #ffffff40;
            border-top-color: white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 8px;
        }}
        @keyframes spin {{
            to {{ transform: rotate(360deg); }}
        }}
        .loading .spinner {{
            display: inline-block;
        }}
        .expires {{
            font-size: 12px;
            color: #64748b;
            text-align: center;
            margin-top: 16px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{form.name}</h1>
        {f'<p class="description">{form.description}</p>' if form.description else ''}

        <div id="success-message" class="success-message">
            Form submitted successfully!
        </div>

        <div id="error-message" class="error-message"></div>

        <form id="playbook-form" onsubmit="submitForm(event)">
            {''.join(fields_html)}
            <button type="submit" id="submit-btn">
                <span class="spinner"></span>
                <span class="btn-text">{form.submit_label}</span>
            </button>
        </form>

        {f'<p class="expires">Expires: {context.expires_at.strftime("%Y-%m-%d %H:%M UTC") if context.expires_at else "Never"}</p>' if context.expires_at else ''}
    </div>

    <script>
        const API_URL = '/api/v1/public/forms/{execution_id}/{node_id}/submit?token={token}';

        async function submitForm(event) {{
            event.preventDefault();

            const form = document.getElementById('playbook-form');
            const submitBtn = document.getElementById('submit-btn');
            const errorDiv = document.getElementById('error-message');
            const successDiv = document.getElementById('success-message');

            // Clear errors
            errorDiv.style.display = 'none';
            document.querySelectorAll('.field-error').forEach(el => el.classList.remove('field-error'));
            document.querySelectorAll('.error').forEach(el => el.remove());

            // Collect form data
            const formData = new FormData(form);
            const data = {{}};

            for (const [key, value] of formData.entries()) {{
                if (data[key]) {{
                    if (Array.isArray(data[key])) {{
                        data[key].push(value);
                    }} else {{
                        data[key] = [data[key], value];
                    }}
                }} else {{
                    data[key] = value;
                }}
            }}

            // Handle checkboxes (unchecked ones won't be in formData)
            document.querySelectorAll('input[type="checkbox"]').forEach(cb => {{
                if (!cb.checked && cb.name) {{
                    data[cb.name] = false;
                }} else if (cb.checked && !data[cb.name]) {{
                    data[cb.name] = true;
                }}
            }});

            // Submit
            submitBtn.classList.add('loading');
            submitBtn.disabled = true;

            try {{
                const response = await fetch(API_URL, {{
                    method: 'POST',
                    headers: {{'Content-Type': 'application/json'}},
                    body: JSON.stringify({{
                        form_data: data,
                        submitted_by: null
                    }})
                }});

                const result = await response.json();

                if (!response.ok) {{
                    if (result.detail && result.detail.validation_errors) {{
                        // Show field-specific errors
                        for (const [field, error] of Object.entries(result.detail.validation_errors)) {{
                            const fieldDiv = document.querySelector(`[data-field="${{field}}"]`);
                            if (fieldDiv) {{
                                fieldDiv.classList.add('field-error');
                                const errorEl = document.createElement('div');
                                errorEl.className = 'error';
                                errorEl.textContent = error;
                                fieldDiv.appendChild(errorEl);
                            }}
                        }}
                        errorDiv.textContent = 'Please fix the errors above';
                        errorDiv.style.display = 'block';
                    }} else {{
                        errorDiv.textContent = result.detail || 'Submission failed';
                        errorDiv.style.display = 'block';
                    }}
                }} else {{
                    // Success
                    form.style.display = 'none';
                    successDiv.style.display = 'block';
                    successDiv.textContent = result.message || 'Form submitted successfully!';
                }}
            }} catch (error) {{
                errorDiv.textContent = 'Network error. Please try again.';
                errorDiv.style.display = 'block';
            }} finally {{
                submitBtn.classList.remove('loading');
                submitBtn.disabled = false;
            }}
        }}
    </script>
</body>
</html>
'''


def _render_field(field, prefilled_value=None) -> str:
    """Render a single form field."""
    required_mark = '<span class="required">*</span>' if field.required else ''
    help_text = f'<div class="help-text">{field.help_text}</div>' if field.help_text else ''
    value = prefilled_value if prefilled_value is not None else (field.default or '')

    if field.type.value == 'textarea':
        return f'''
        <div class="field" data-field="{field.name}">
            <label>{field.label} {required_mark}</label>
            <textarea name="{field.name}" placeholder="{field.placeholder or ''}"
                      {'required' if field.required else ''}>{value}</textarea>
            {help_text}
        </div>
        '''

    elif field.type.value == 'select':
        options_html = ''.join([
            f'<option value="{opt["value"]}" {"selected" if str(opt["value"]) == str(value) else ""}>{opt["label"]}</option>'
            for opt in (field.options or [])
        ])
        return f'''
        <div class="field" data-field="{field.name}">
            <label>{field.label} {required_mark}</label>
            <select name="{field.name}" {'required' if field.required else ''}>
                <option value="">Select...</option>
                {options_html}
            </select>
            {help_text}
        </div>
        '''

    elif field.type.value == 'multiselect':
        options_html = ''.join([
            f'''<label class="checkbox-item">
                <input type="checkbox" name="{field.name}" value="{opt["value"]}"
                       {"checked" if opt["value"] in (value if isinstance(value, list) else []) else ""}>
                {opt["label"]}
            </label>'''
            for opt in (field.options or [])
        ])
        return f'''
        <div class="field" data-field="{field.name}">
            <label>{field.label} {required_mark}</label>
            <div class="checkbox-group">{options_html}</div>
            {help_text}
        </div>
        '''

    elif field.type.value == 'radio':
        options_html = ''.join([
            f'''<label class="radio-item">
                <input type="radio" name="{field.name}" value="{opt["value"]}"
                       {"checked" if str(opt["value"]) == str(value) else ""}
                       {'required' if field.required else ''}>
                {opt["label"]}
            </label>'''
            for opt in (field.options or [])
        ])
        return f'''
        <div class="field" data-field="{field.name}">
            <label>{field.label} {required_mark}</label>
            <div class="radio-group">{options_html}</div>
            {help_text}
        </div>
        '''

    elif field.type.value == 'checkbox':
        return f'''
        <div class="field" data-field="{field.name}">
            <label class="checkbox-item">
                <input type="checkbox" name="{field.name}" {"checked" if value else ""}>
                {field.label}
            </label>
            {help_text}
        </div>
        '''

    elif field.type.value == 'file':
        accept = ''
        if field.validation and field.validation.get('allowed_types'):
            accept = f'accept="{",".join(field.validation["allowed_types"])}"'
        return f'''
        <div class="field" data-field="{field.name}">
            <label>{field.label} {required_mark}</label>
            <input type="file" name="{field.name}" {accept} {'required' if field.required else ''}>
            {help_text}
        </div>
        '''

    elif field.type.value == 'hidden':
        return f'<input type="hidden" name="{field.name}" value="{value}">'

    else:
        # text, email, number, date, datetime
        input_type = field.type.value
        if input_type == 'datetime':
            input_type = 'datetime-local'

        return f'''
        <div class="field" data-field="{field.name}">
            <label>{field.label} {required_mark}</label>
            <input type="{input_type}" name="{field.name}" value="{value}"
                   placeholder="{field.placeholder or ''}"
                   {'required' if field.required else ''}>
            {help_text}
        </div>
        '''


def _render_error_page(title: str, message: str) -> str:
    """Render error page HTML."""
    return f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - T1 Agentics</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #f0f6fc;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }}
        .container {{
            text-align: center;
            padding: 32px;
        }}
        h1 {{
            color: #ef4444;
            margin-bottom: 16px;
        }}
        p {{
            color: #94a3b8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p>{message}</p>
    </div>
</body>
</html>
'''


def _render_success_page(title: str, message: str) -> str:
    """Render success page HTML."""
    return f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title} - T1 Agentics</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f172a;
            color: #f0f6fc;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }}
        .container {{
            text-align: center;
            padding: 32px;
        }}
        h1 {{
            color: #34d399;
            margin-bottom: 16px;
        }}
        p {{
            color: #94a3b8;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p>{message}</p>
    </div>
</body>
</html>
'''


# ============================================================================
# Submission History Endpoints
# ============================================================================

@router.get("/submissions/execution/{execution_id}")
async def get_execution_submissions(execution_id: str):
    """Get all form submissions for a playbook execution."""
    from services.webform_service import get_webform_service

    service = get_webform_service()
    submissions = await service.get_submissions_for_execution(execution_id)

    return {"submissions": submissions, "count": len(submissions)}


@router.get("/files/execution/{execution_id}")
async def get_execution_files(execution_id: str):
    """Get all uploaded files for a playbook execution."""
    from services.webform_service import get_webform_service

    service = get_webform_service()
    files = await service.get_files_for_execution(execution_id)

    return {"files": files, "count": len(files)}
