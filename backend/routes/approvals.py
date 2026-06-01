# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Approval Workflow Routes
API endpoints for managing approval tokens and handling approval actions
"""

from fastapi import APIRouter, HTTPException, Header, Request
from fastapi.responses import HTMLResponse
from typing import Optional, Dict, Any, List
from pydantic import BaseModel
from datetime import datetime
import logging

from services.approval_service import get_approval_service, ApprovalAction
from services.postgres_db import postgres_db
from routes.admin import get_current_username, require_admin

logger = logging.getLogger(__name__)


# ==================== ACTION HANDLERS ====================
# These handle the actual business logic when an approval token is used

async def handle_alert_action(action: str, entity_id: str, action_type: str, used_by: str, metadata: dict) -> dict:
    """Handle alert-related approval actions"""
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Try by alert_id field first (handles short IDs like 'alert-xxx')
            alert = await conn.fetchrow("SELECT * FROM alerts WHERE alert_id = $1", entity_id)
            if not alert:
                # Try by UUID id field
                try:
                    import uuid
                    uuid.UUID(entity_id)  # Validate it's a UUID
                    alert = await conn.fetchrow("SELECT * FROM alerts WHERE id = $1", entity_id)
                except (ValueError, TypeError):
                    pass  # Not a valid UUID, skip this lookup

            if not alert:
                return {"executed": False, "error": f"Alert {entity_id} not found"}

            # Valid statuses: open, investigating, resolved, closed, triaged, enriched
            if action == "approve":
                # Different approve actions based on action_type
                if action_type in ["alert_created", "alert_critical"]:
                    # Acknowledge/triage the alert
                    await conn.execute(
                        "UPDATE alerts SET status = 'triaged', updated_at = NOW() WHERE id = $1",
                        alert['id']
                    )
                    return {"executed": True, "message": f"Alert triaged/acknowledged by {used_by or 'approval link'}"}

                elif action_type == "alert_escalate":
                    # Escalate to investigation
                    await conn.execute(
                        "UPDATE alerts SET status = 'investigating', updated_at = NOW() WHERE id = $1",
                        alert['id']
                    )
                    return {"executed": True, "message": f"Alert escalated to investigation by {used_by or 'approval link'}"}

                elif action_type == "alert_dismiss":
                    # Close the alert
                    await conn.execute(
                        "UPDATE alerts SET status = 'closed', updated_at = NOW() WHERE id = $1",
                        alert['id']
                    )
                    return {"executed": True, "message": f"Alert closed by {used_by or 'approval link'}"}

                else:
                    # Generic approve - mark as resolved
                    await conn.execute(
                        "UPDATE alerts SET status = 'resolved', updated_at = NOW() WHERE id = $1",
                        alert['id']
                    )
                    return {"executed": True, "message": f"Alert approved/resolved by {used_by or 'approval link'}"}

            else:  # reject
                if action_type in ["alert_created", "alert_critical"]:
                    # Dismiss the alert - mark as closed (false positive)
                    await conn.execute(
                        "UPDATE alerts SET status = 'closed', updated_at = NOW() WHERE id = $1",
                        alert['id']
                    )
                    return {"executed": True, "message": f"Alert marked as false positive by {used_by or 'approval link'}"}

                elif action_type == "alert_escalate":
                    # Don't escalate - keep as open
                    await conn.execute(
                        "UPDATE alerts SET status = 'open', updated_at = NOW() WHERE id = $1",
                        alert['id']
                    )
                    return {"executed": True, "message": f"Escalation rejected by {used_by or 'approval link'}"}

                else:
                    # Generic reject - close
                    await conn.execute(
                        "UPDATE alerts SET status = 'closed', updated_at = NOW() WHERE id = $1",
                        alert['id']
                    )
                    return {"executed": True, "message": f"Alert rejected/dismissed by {used_by or 'approval link'}"}

    except Exception as e:
        logger.error(f"Failed to execute alert action: {e}")
        return {"executed": False, "error": str(e)}


async def handle_investigation_action(action: str, entity_id: str, action_type: str, used_by: str, metadata: dict) -> dict:
    """Handle investigation-related approval actions"""
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Try by investigation_id field first (handles short IDs like 'INV-xxx')
            investigation = await conn.fetchrow("SELECT * FROM investigations WHERE investigation_id = $1", entity_id)
            if not investigation:
                # Try by UUID id field
                try:
                    import uuid
                    uuid.UUID(entity_id)  # Validate it's a UUID
                    investigation = await conn.fetchrow("SELECT * FROM investigations WHERE id = $1", entity_id)
                except (ValueError, TypeError):
                    pass  # Not a valid UUID, skip this lookup

            if not investigation:
                return {"executed": False, "error": f"Investigation {entity_id} not found"}

            if action == "approve":
                if action_type == "investigation_close":
                    await conn.execute(
                        "UPDATE investigations SET status = 'closed', updated_at = NOW() WHERE id = $1",
                        investigation['id']
                    )
                    return {"executed": True, "message": f"Investigation closed by {used_by or 'approval link'}"}

                elif action_type == "investigation_escalate":
                    await conn.execute(
                        "UPDATE investigations SET status = 'escalated', escalated = TRUE, updated_at = NOW() WHERE id = $1",
                        investigation['id']
                    )
                    return {"executed": True, "message": f"Investigation escalated by {used_by or 'approval link'}"}

                else:
                    await conn.execute(
                        "UPDATE investigations SET status = 'approved', updated_at = NOW() WHERE id = $1",
                        investigation['id']
                    )
                    return {"executed": True, "message": f"Investigation approved by {used_by or 'approval link'}"}

            else:  # reject
                if action_type == "investigation_close":
                    # Keep investigation open
                    await conn.execute(
                        "UPDATE investigations SET status = 'in_progress', updated_at = NOW() WHERE id = $1",
                        investigation['id']
                    )
                    return {"executed": True, "message": f"Investigation closure rejected by {used_by or 'approval link'}"}

                else:
                    await conn.execute(
                        "UPDATE investigations SET status = 'rejected', updated_at = NOW() WHERE id = $1",
                        investigation['id']
                    )
                    return {"executed": True, "message": f"Investigation rejected by {used_by or 'approval link'}"}

    except Exception as e:
        logger.error(f"Failed to execute investigation action: {e}")
        return {"executed": False, "error": str(e)}


async def handle_case_action(action: str, entity_id: str, action_type: str, used_by: str, metadata: dict) -> dict:
    """Handle case-related approval actions"""
    try:
        async with postgres_db.tenant_acquire() as conn:
            # Try by case_id field first (handles short IDs like 'CASE-xxx')
            case = await conn.fetchrow("SELECT * FROM cases WHERE case_id = $1", entity_id)
            if not case:
                # Try by UUID id field
                try:
                    import uuid
                    uuid.UUID(entity_id)  # Validate it's a UUID
                    case = await conn.fetchrow("SELECT * FROM cases WHERE id = $1", entity_id)
                except (ValueError, TypeError):
                    pass  # Not a valid UUID, skip this lookup

            if not case:
                return {"executed": False, "error": f"Case {entity_id} not found"}

            if action == "approve":
                if action_type == "case_close":
                    await conn.execute(
                        "UPDATE cases SET status = 'closed', updated_at = NOW() WHERE id = $1",
                        case['id']
                    )
                    return {"executed": True, "message": f"Case closed by {used_by or 'approval link'}"}
                else:
                    await conn.execute(
                        "UPDATE cases SET status = 'approved', updated_at = NOW() WHERE id = $1",
                        case['id']
                    )
                    return {"executed": True, "message": f"Case approved by {used_by or 'approval link'}"}

            else:  # reject
                await conn.execute(
                    "UPDATE cases SET status = 'rejected', updated_at = NOW() WHERE id = $1",
                    case['id']
                )
                return {"executed": True, "message": f"Case rejected by {used_by or 'approval link'}"}

    except Exception as e:
        logger.error(f"Failed to execute case action: {e}")
        return {"executed": False, "error": str(e)}


async def execute_approval_action(result: dict) -> dict:
    """
    Execute the actual business logic after a token is used.
    This is called after the token is marked as used.
    """
    if not result.get("success"):
        return result

    action = result.get("action")  # approve or reject
    action_type = result.get("action_type")  # alert_created, escalation, etc.
    entity_type = result.get("entity_type")  # alert, investigation, case
    entity_id = result.get("entity_id")
    metadata = result.get("metadata", {})
    used_by = result.get("used_by", "anonymous")

    # Route to appropriate handler based on entity type
    if entity_type == "alert":
        execution_result = await handle_alert_action(action, entity_id, action_type, used_by, metadata)
    elif entity_type == "investigation":
        execution_result = await handle_investigation_action(action, entity_id, action_type, used_by, metadata)
    elif entity_type == "case":
        execution_result = await handle_case_action(action, entity_id, action_type, used_by, metadata)
    else:
        execution_result = {"executed": False, "error": f"Unknown entity type: {entity_type}"}

    # Add execution result to the response
    result["action_executed"] = execution_result.get("executed", False)
    result["action_message"] = execution_result.get("message") or execution_result.get("error")

    logger.info(f"Approval action executed: {action} {action_type} on {entity_type}/{entity_id} - {execution_result}")

    return result

router = APIRouter(prefix="/api/v1/approval-tokens", tags=["approval-tokens"])


# ==================== MODELS ====================

class CreateApprovalRequest(BaseModel):
    action_type: str  # escalation, investigation_close, alert_dismiss, etc.
    entity_type: str  # alert, investigation, case
    entity_id: str
    ttl_minutes: int = 60
    require_auth: bool = False
    metadata: Optional[Dict[str, Any]] = None


class ApprovalTokenResponse(BaseModel):
    token_id: str
    action: str  # approve or reject
    url: str
    expires_at: str
    require_auth: bool


class ApprovalPairResponse(BaseModel):
    approve: ApprovalTokenResponse
    reject: ApprovalTokenResponse
    entity_type: str
    entity_id: str
    action_type: str
    ttl_minutes: int


class UseApprovalRequest(BaseModel):
    token: str


class ApprovalResult(BaseModel):
    success: bool
    action: Optional[str] = None
    action_type: Optional[str] = None
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    error: Optional[str] = None
    code: Optional[str] = None
    # Action execution results
    action_executed: Optional[bool] = None
    action_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


# ==================== CREATE APPROVAL TOKENS ====================

@router.post("/create", response_model=ApprovalPairResponse)
async def create_approval_tokens(
    request: Request,
    req: CreateApprovalRequest,
    authorization: str = Header(None)
):
    """Create a pair of approval tokens (approve + reject) for an action"""
    username = await get_current_username(request, authorization)

    approval_service = get_approval_service()
    approval_service.set_db(postgres_db)

    # Determine base URL for links
    base_url = "http://localhost:3000"  # Could be configurable

    tokens = await approval_service.create_approval_pair(
        action_type=req.action_type,
        entity_type=req.entity_type,
        entity_id=req.entity_id,
        ttl_minutes=req.ttl_minutes,
        require_auth=req.require_auth,
        created_by=username,
        metadata=req.metadata
    )

    approve_token = tokens['approve']
    reject_token = tokens['reject']

    return ApprovalPairResponse(
        approve=ApprovalTokenResponse(
            token_id=approve_token.token_id,
            action="approve",
            url=approval_service.build_approval_url(approve_token, base_url),
            expires_at=approve_token.expires_at.isoformat(),
            require_auth=approve_token.require_auth
        ),
        reject=ApprovalTokenResponse(
            token_id=reject_token.token_id,
            action="reject",
            url=approval_service.build_approval_url(reject_token, base_url),
            expires_at=reject_token.expires_at.isoformat(),
            require_auth=reject_token.require_auth
        ),
        entity_type=req.entity_type,
        entity_id=req.entity_id,
        action_type=req.action_type,
        ttl_minutes=req.ttl_minutes
    )


# ==================== USE APPROVAL TOKEN ====================

@router.post("/use", response_model=ApprovalResult)
async def use_approval_token(
    request: Request,
    req: UseApprovalRequest,
    authorization: str = Header(None)
):
    """Use (consume) an approval token"""
    # Try to get username if authenticated
    username = None
    try:
        if authorization:
            username = await get_current_username(request, authorization)
    except:
        pass

    approval_service = get_approval_service()
    approval_service.set_db(postgres_db)

    result = await approval_service.use_token(
        token_secret=req.token,
        used_by=username
    )

    # Execute the actual action if token was successfully used
    if result.get("success"):
        result = await execute_approval_action(result)

    return ApprovalResult(**result)


@router.get("/use/{token_secret}", response_model=ApprovalResult)
async def use_approval_token_get(
    request: Request,
    token_secret: str,
    authorization: str = Header(None)
):
    """Use an approval token via GET request (for email links)"""
    # Try to get username if authenticated
    username = None
    try:
        if authorization:
            username = await get_current_username(request, authorization)
    except:
        pass

    approval_service = get_approval_service()
    approval_service.set_db(postgres_db)

    result = await approval_service.use_token(
        token_secret=token_secret,
        used_by=username
    )

    # Execute the actual action if token was successfully used
    if result.get("success"):
        result = await execute_approval_action(result)

    return ApprovalResult(**result)


# ==================== TOKEN INFO ====================

@router.get("/info/{token_secret}")
async def get_token_info(
    request: Request,
    token_secret: str,
    authorization: str = Header(None)
):
    """Get information about an approval token without using it"""
    approval_service = get_approval_service()
    approval_service.set_db(postgres_db)

    token = await approval_service.get_token_by_secret(token_secret)

    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    return {
        "token_id": token.token_id,
        "action": token.action.value if hasattr(token.action, 'value') else token.action,
        "action_type": token.action_type,
        "entity_type": token.entity_type,
        "entity_id": token.entity_id,
        "require_auth": token.require_auth,
        "used": token.used,
        "expired": token.is_expired(),
        "valid": token.is_valid(),
        "expires_at": token.expires_at.isoformat() if token.expires_at else None,
        "used_at": token.used_at.isoformat() if token.used_at else None,
        "used_by": token.used_by
    }


# ==================== HISTORY ====================

@router.get("/history")
async def get_approval_history(
    request: Request,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    limit: int = 50,
    authorization: str = Header(None)
):
    """Get approval token history"""
    await require_admin(request, authorization)

    approval_service = get_approval_service()
    approval_service.set_db(postgres_db)

    history = await approval_service.get_approval_history(
        entity_type=entity_type,
        entity_id=entity_id,
        limit=limit
    )

    return {"history": history}


@router.get("/pending/{entity_type}/{entity_id}")
async def get_pending_approvals(
    request: Request,
    entity_type: str,
    entity_id: str,
    authorization: str = Header(None)
):
    """Get pending (unused) approval tokens for an entity"""
    await get_current_username(request, authorization)

    approval_service = get_approval_service()
    approval_service.set_db(postgres_db)

    tokens = await approval_service.get_pending_tokens_for_entity(
        entity_type=entity_type,
        entity_id=entity_id
    )

    return {
        "tokens": [
            {
                "token_id": t.token_id,
                "action": t.action.value if hasattr(t.action, 'value') else t.action,
                "action_type": t.action_type,
                "expires_at": t.expires_at.isoformat() if t.expires_at else None,
                "require_auth": t.require_auth
            }
            for t in tokens
        ]
    }


# ==================== CLEANUP ====================

@router.post("/cleanup")
async def cleanup_expired_tokens(request: Request, authorization: str = Header(None)):
    """Clean up expired tokens (admin only)"""
    await require_admin(request, authorization)

    approval_service = get_approval_service()
    approval_service.set_db(postgres_db)

    count = await approval_service.cleanup_expired_tokens()

    return {"success": True, "cleaned_up": count}


# ==================== APPROVAL PAGE (HTML) ====================

# This is a simple HTML page for handling approval links
# In production, you'd redirect to the React frontend

@router.get("/page/{token_secret}", response_class=HTMLResponse)
async def approval_page(token_secret: str):
    """
    HTML page for approval links.
    This page handles the approval workflow and displays appropriate messages.
    """
    approval_service = get_approval_service()
    approval_service.set_db(postgres_db)

    token = await approval_service.get_token_by_secret(token_secret)

    if not token:
        return _render_approval_page(
            "Token Not Found",
            "This approval link is invalid or does not exist.",
            "error"
        )

    if token.used:
        return _render_approval_page(
            "Already Used",
            f"This link was already used on {token.used_at.strftime('%Y-%m-%d %H:%M:%S UTC') if token.used_at else 'unknown date'}.",
            "warning",
            used_by=token.used_by
        )

    if token.is_expired():
        return _render_approval_page(
            "Link Expired",
            f"This approval link expired on {token.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if token.expires_at else 'unknown date'}.",
            "error"
        )

    # Token is valid - show confirmation page
    action_label = "Approve" if token.action == ApprovalAction.APPROVE else "Reject"
    action_color = "#22c55e" if token.action == ApprovalAction.APPROVE else "#dc2626"

    return _render_approval_confirmation_page(
        token=token,
        token_secret=token_secret,
        action_label=action_label,
        action_color=action_color
    )


def _render_approval_page(title: str, message: str, status: str, used_by: str = None) -> str:
    """Render a simple approval status page"""
    status_colors = {
        "success": "#22c55e",
        "error": "#dc2626",
        "warning": "#f59e0b"
    }
    color = status_colors.get(status, "#6b7280")

    used_by_html = ""
    if used_by and not used_by.startswith("invalidated_"):
        used_by_html = f'<p style="color: #9ca3af; font-size: 14px;">Used by: {used_by}</p>'

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title} - T1 Agentics</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .container {{
                background: #1f2937;
                border-radius: 16px;
                padding: 40px;
                max-width: 500px;
                width: 100%;
                text-align: center;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                border: 1px solid rgba(255, 255, 255, 0.1);
            }}
            .icon {{
                width: 80px;
                height: 80px;
                border-radius: 50%;
                background: {color}20;
                display: flex;
                align-items: center;
                justify-content: center;
                margin: 0 auto 24px;
                font-size: 40px;
            }}
            h1 {{
                color: {color};
                font-size: 28px;
                margin-bottom: 16px;
            }}
            p {{
                color: #d1d5db;
                font-size: 16px;
                line-height: 1.6;
            }}
            .logo {{
                margin-top: 32px;
                color: #6b7280;
                font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="icon">
                {'OK' if status == 'success' else 'X' if status == 'error' else '!'}
            </div>
            <h1>{title}</h1>
            <p>{message}</p>
            {used_by_html}
            <p class="logo">T1 Agentics SOC Platform</p>
        </div>
    </body>
    </html>
    """


def _render_approval_confirmation_page(
    token,
    token_secret: str,
    action_label: str,
    action_color: str
) -> str:
    """Render the approval confirmation page"""
    action_type_display = token.action_type.replace('_', ' ').title()
    entity_display = f"{token.entity_type.title()} {token.entity_id}"

    auth_notice = ""
    if token.require_auth:
        auth_notice = """
        <div style="background: #f59e0b20; border: 1px solid #f59e0b; border-radius: 8px; padding: 12px; margin-bottom: 24px;">
            <p style="color: #f59e0b; font-size: 14px; margin: 0;">
                [!] Authentication required - You must be logged in to use this link
            </p>
        </div>
        """

    expires_display = token.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if token.expires_at else 'Unknown'

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Confirm {action_label} - T1 Agentics</title>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }}
            .container {{
                background: #1f2937;
                border-radius: 16px;
                padding: 40px;
                max-width: 500px;
                width: 100%;
                text-align: center;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                border: 1px solid rgba(255, 255, 255, 0.1);
            }}
            .action-badge {{
                display: inline-block;
                padding: 8px 24px;
                background: {action_color}20;
                color: {action_color};
                border-radius: 24px;
                font-size: 14px;
                font-weight: 600;
                margin-bottom: 24px;
                border: 1px solid {action_color};
            }}
            h1 {{
                color: #f3f4f6;
                font-size: 24px;
                margin-bottom: 8px;
            }}
            .subtitle {{
                color: #9ca3af;
                font-size: 16px;
                margin-bottom: 24px;
            }}
            .details {{
                background: #374151;
                border-radius: 8px;
                padding: 16px;
                margin-bottom: 24px;
                text-align: left;
            }}
            .detail-row {{
                display: flex;
                justify-content: space-between;
                padding: 8px 0;
                border-bottom: 1px solid #4b5563;
            }}
            .detail-row:last-child {{
                border-bottom: none;
            }}
            .detail-label {{
                color: #9ca3af;
                font-size: 14px;
            }}
            .detail-value {{
                color: #f3f4f6;
                font-size: 14px;
                font-weight: 500;
            }}
            .btn {{
                display: inline-block;
                padding: 14px 32px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                border: none;
                transition: all 0.2s;
            }}
            .btn-confirm {{
                background: {action_color};
                color: white;
            }}
            .btn-confirm:hover {{
                opacity: 0.9;
                transform: translateY(-2px);
            }}
            .btn-cancel {{
                background: transparent;
                color: #9ca3af;
                margin-left: 12px;
            }}
            .btn-cancel:hover {{
                color: #f3f4f6;
            }}
            .logo {{
                margin-top: 32px;
                color: #6b7280;
                font-size: 14px;
            }}
            #result {{
                display: none;
            }}
            .spinner {{
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 2px solid rgba(255,255,255,0.3);
                border-radius: 50%;
                border-top-color: white;
                animation: spin 0.8s linear infinite;
            }}
            @keyframes spin {{
                to {{ transform: rotate(360deg); }}
            }}
        </style>
    </head>
    <body>
        <div class="container" id="confirmation">
            <div class="action-badge">{action_label.upper()}</div>
            <h1>Confirm Action</h1>
            <p class="subtitle">You are about to {action_label.lower()} the following:</p>

            {auth_notice}

            <div class="details">
                <div class="detail-row">
                    <span class="detail-label">Action Type</span>
                    <span class="detail-value">{action_type_display}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Entity</span>
                    <span class="detail-value">{entity_display}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Expires</span>
                    <span class="detail-value">{expires_display}</span>
                </div>
            </div>

            <div>
                <button class="btn btn-confirm" onclick="confirmAction()">
                    Confirm {action_label}
                </button>
                <button class="btn btn-cancel" onclick="window.close()">
                    Cancel
                </button>
            </div>

            <p class="logo">T1 Agentics SOC Platform</p>
        </div>

        <div class="container" id="result" style="display: none;">
            <div id="result-content"></div>
            <p class="logo">T1 Agentics SOC Platform</p>
        </div>

        <script>
            async function confirmAction() {{
                const btn = document.querySelector('.btn-confirm');
                btn.innerHTML = '<span class="spinner"></span> Processing...';
                btn.disabled = true;

                try {{
                    const response = await fetch('/api/v1/approval-tokens/use/{token_secret}');
                    const result = await response.json();

                    document.getElementById('confirmation').style.display = 'none';
                    document.getElementById('result').style.display = 'block';

                    if (result.success) {{
                        const actionMsg = result.action_message || `The ${{result.action}} action has been completed.`;
                        const executedStatus = result.action_executed ?
                            '<span style="color: #22c55e;">[OK] Action executed</span>' :
                            '<span style="color: #f59e0b;">[!] Token used (action pending)</span>';

                        document.getElementById('result-content').innerHTML = `
                            <div style="width: 80px; height: 80px; border-radius: 50%; background: #22c55e20; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; font-size: 40px;">OK</div>
                            <h1 style="color: #22c55e; font-size: 28px; margin-bottom: 16px;">Action Completed</h1>
                            <p style="color: #d1d5db; margin-bottom: 12px;">${{actionMsg}}</p>
                            <p style="font-size: 12px;">${{executedStatus}}</p>
                            <div style="margin-top: 20px; padding: 12px; background: #1e293b; border-radius: 6px; font-size: 12px; text-align: left;">
                                <div style="color: #94a3b8;"><strong>Entity:</strong> ${{result.entity_type}} / ${{result.entity_id}}</div>
                                <div style="color: #94a3b8;"><strong>Action Type:</strong> ${{result.action_type}}</div>
                            </div>
                        `;
                    }} else {{
                        document.getElementById('result-content').innerHTML = `
                            <div style="width: 80px; height: 80px; border-radius: 50%; background: #dc262620; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; font-size: 40px;">X</div>
                            <h1 style="color: #dc2626; font-size: 28px; margin-bottom: 16px;">Action Failed</h1>
                            <p style="color: #d1d5db;">${{result.error || 'An unknown error occurred'}}</p>
                            ${{result.code ? `<p style="font-size: 12px; color: #6b7280;">Error code: ${{result.code}}</p>` : ''}}
                        `;
                    }}
                }} catch (error) {{
                    document.getElementById('confirmation').style.display = 'none';
                    document.getElementById('result').style.display = 'block';
                    document.getElementById('result-content').innerHTML = `
                        <div style="width: 80px; height: 80px; border-radius: 50%; background: #dc262620; display: flex; align-items: center; justify-content: center; margin: 0 auto 24px; font-size: 40px;">X</div>
                        <h1 style="color: #dc2626; font-size: 28px; margin-bottom: 16px;">Error</h1>
                        <p style="color: #d1d5db;">Failed to process the action. Please try again.</p>
                    `;
                }}
            }}
        </script>
    </body>
    </html>
    """
