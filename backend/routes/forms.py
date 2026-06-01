# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Web Forms API Routes
Handle form creation, submission, and management
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Form as FastAPIForm, Request, Depends
from dependencies.auth import get_current_user
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
from datetime import datetime
import uuid
import json

from models.forms import (
    WebForm, FormSubmission, FormField, FormOutputConfig,
    FieldType, FORM_TEMPLATES
)
from services.database import db
from services.alert_id_generator import generate_alert_id_sync

router = APIRouter(prefix="/api/v1/forms", tags=["forms"], dependencies=[Depends(get_current_user)])


# ==================== FORM TEMPLATES ====================

@router.get("/templates")
async def get_form_templates():
    """Get all available form templates"""
    return {
        "templates": FORM_TEMPLATES,
        "count": len(FORM_TEMPLATES)
    }


@router.get("/templates/{template_id}")
async def get_form_template(template_id: str):
    """Get a specific form template"""
    template = next((t for t in FORM_TEMPLATES if t["template_id"] == template_id), None)
    if not template:
        raise HTTPException(404, "Template not found")
    return template


# ==================== FORM MANAGEMENT ====================

@router.post("/create")
async def create_form(form: WebForm):
    """Create a new web form"""
    try:
        # Convert to dict
        if hasattr(form, 'model_dump'):
            form_dict = form.model_dump(mode='json')
        else:
            form_dict = form.dict()
        
        # Generate form_id if not provided
        if not form_dict.get("form_id"):
            form_dict["form_id"] = f"form-{uuid.uuid4().hex[:12]}"
        
        # Save to database
        if db.connected:
            await db.create_form(form_dict)
        
        return {
            "status": "success",
            "form_id": form_dict["form_id"],
            "form": form_dict
        }
        
    except Exception as e:
        raise HTTPException(500, f"Form creation failed: {str(e)}")


@router.get("")
async def list_forms(created_by: Optional[str] = None):
    """List all forms"""
    if not db.connected:
        return {"forms": [], "count": 0}
    
    try:
        forms = await db.get_all_forms(created_by=created_by)
        return {
            "forms": forms,
            "count": len(forms)
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to list forms: {str(e)}")


@router.get("/{form_id}")
async def get_form(form_id: str):
    """Get a specific form by ID"""
    if not db.connected:
        raise HTTPException(503, "Database not connected")
    
    form = await db.get_form(form_id)
    if not form:
        raise HTTPException(404, "Form not found")
    
    return form


@router.put("/{form_id}")
async def update_form(form_id: str, updates: Dict[str, Any]):
    """Update form configuration"""
    if not db.connected:
        raise HTTPException(503, "Database not connected")
    
    # Check if form exists
    existing = await db.get_form(form_id)
    if not existing:
        raise HTTPException(404, "Form not found")
    
    # Update
    success = await db.update_form(form_id, updates)
    if not success:
        raise HTTPException(500, "Update failed")
    
    return {"status": "success", "form_id": form_id}


@router.delete("/{form_id}")
async def delete_form(form_id: str):
    """Delete a form"""
    if not db.connected:
        raise HTTPException(503, "Database not connected")
    
    success = await db.delete_form(form_id)
    if not success:
        raise HTTPException(404, "Form not found or deletion failed")
    
    return {"status": "success", "form_id": form_id}


# ==================== FORM SUBMISSIONS ====================

@router.post("/{form_id}/submit")
async def submit_form(
    form_id: str,
    request: Request,
    data: Dict[str, Any]
):
    """Submit a form with data"""
    try:
        # Get form configuration
        if not db.connected:
            raise HTTPException(503, "Database not connected")
        
        form = await db.get_form(form_id)
        if not form:
            raise HTTPException(404, "Form not found")
        
        if not form.get("is_active", True):
            raise HTTPException(400, "Form is not active")
        
        # Create submission
        submission_id = f"sub-{uuid.uuid4().hex[:12]}"
        
        submission_data = {
            "submission_id": submission_id,
            "form_id": form_id,
            "form_title": form.get("title", "Unknown"),
            "data": data,
            "submitted_at": datetime.utcnow(),
            "ip_address": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "status": "pending"
        }
        
        # Save submission
        await db.create_submission(submission_data)
        
        # Process submission (create alert, send webhook, etc.)
        await process_submission(form, submission_data)
        
        return {
            "status": "success",
            "submission_id": submission_id,
            "message": form.get("success_message", "Form submitted successfully!")
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Submission failed: {str(e)}")


@router.get("/{form_id}/submissions")
async def get_form_submissions(form_id: str, limit: int = 100):
    """Get all submissions for a form"""
    if not db.connected:
        raise HTTPException(503, "Database not connected")
    
    try:
        submissions = await db.get_form_submissions(form_id=form_id, limit=limit)
        return {
            "submissions": submissions,
            "count": len(submissions)
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to get submissions: {str(e)}")


@router.get("/submissions/all")
async def get_all_submissions(limit: int = 100):
    """Get all submissions across all forms"""
    if not db.connected:
        raise HTTPException(503, "Database not connected")
    
    try:
        submissions = await db.get_form_submissions(limit=limit)
        return {
            "submissions": submissions,
            "count": len(submissions)
        }
    except Exception as e:
        raise HTTPException(500, f"Failed to get submissions: {str(e)}")


# ==================== SUBMISSION PROCESSING ====================

async def process_submission(form: Dict[str, Any], submission: Dict[str, Any]):
    """Process form submission - create alert, send webhooks, etc."""
    try:
        output_config = form.get("output_config", {})
        
        # 1. Create Alert in T1 Agentics
        if output_config.get("create_alert", True):
            await create_alert_from_submission(form, submission, output_config)
        
        # 2. Send Webhook
        if output_config.get("webhook_url"):
            await send_webhook_notification(form, submission, output_config)
        
        # 3. Email Notification
        if output_config.get("email_notification"):
            # TODO: Implement email notification
            pass
        
        # Update submission status
        await db.update_submission(
            submission["submission_id"],
            {"status": "processed"}
        )
        
    except Exception as e:
        # Log error and update submission
        await db.update_submission(
            submission["submission_id"],
            {
                "status": "failed",
                "processing_errors": [str(e)]
            }
        )


async def create_alert_from_submission(
    form: Dict[str, Any],
    submission: Dict[str, Any],
    output_config: Dict[str, Any]
):
    """Create an T1 Agentics alert from form submission"""
    try:
        # Build alert title
        title_template = output_config.get("alert_title_template")
        if title_template:
            # Simple template replacement
            title = title_template.format(**submission["data"])
        else:
            title = f"{form['title']} - {submission['submission_id']}"
        
        # Build alert description from form data
        description_parts = []
        for key, value in submission["data"].items():
            description_parts.append(f"{key}: {value}")
        description = "\n".join(description_parts)
        
        # Create alert with systematic ID
        alert_data = {
            "alert_id": generate_alert_id_sync(
                source='form_submission',
                source_type='form',
                category='report',
                title=title
            ),
            "external_id": submission["submission_id"],
            "source": f"Form: {form['title']}",
            "source_type": "form_submission",
            "title": title,
            "description": description,
            "severity": output_config.get("alert_severity", "medium"),
            "status": "open",
            "raw_data": submission["data"],
            "created_at": datetime.utcnow()
        }
        
        # Save alert
        if db.connected:
            pool = db._get_pool()
            if pool:
                async with pool.acquire() as conn:
                    await conn.execute('''
                        INSERT INTO alerts (alert_id, external_id, source, source_type, title,
                            description, severity, status, raw_data, created_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
                        ON CONFLICT (alert_id) DO NOTHING
                    ''',
                        alert_data['alert_id'],
                        alert_data.get('external_id'),
                        alert_data.get('source'),
                        alert_data.get('source_type'),
                        alert_data.get('title'),
                        alert_data.get('description'),
                        alert_data.get('severity', 'medium'),
                        alert_data.get('status', 'open'),
                        json.dumps(alert_data.get('raw_data', {})),
                        alert_data.get('created_at', datetime.utcnow())
                    )
        
        # Update submission with alert_id
        await db.update_submission(
            submission["submission_id"],
            {
                "alert_created": True,
                "alert_id": alert_data["alert_id"]
            }
        )
        
    except Exception as e:
        print(f"Error creating alert from submission: {e}")


async def send_webhook_notification(
    form: Dict[str, Any],
    submission: Dict[str, Any],
    output_config: Dict[str, Any]
):
    """Send webhook notification for form submission"""
    try:
        import httpx
        
        webhook_url = output_config.get("webhook_url")
        webhook_method = output_config.get("webhook_method", "POST")
        webhook_headers = output_config.get("webhook_headers", {})
        
        payload = {
            "form_id": form["form_id"],
            "form_title": form["title"],
            "submission_id": submission["submission_id"],
            "data": submission["data"],
            "submitted_at": submission["submitted_at"].isoformat()
        }
        
        async with httpx.AsyncClient() as client:
            if webhook_method == "POST":
                response = await client.post(
                    webhook_url,
                    json=payload,
                    headers=webhook_headers,
                    timeout=10.0
                )
            else:
                response = await client.put(
                    webhook_url,
                    json=payload,
                    headers=webhook_headers,
                    timeout=10.0
                )
            
            # Update submission
            await db.update_submission(
                submission["submission_id"],
                {
                    "webhook_sent": True,
                    "webhook_response": {
                        "status_code": response.status_code,
                        "body": response.text[:500]
                    }
                }
            )
            
    except Exception as e:
        print(f"Error sending webhook: {e}")
