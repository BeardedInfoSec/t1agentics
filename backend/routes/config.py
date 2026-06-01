# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Configuration Management API Routes
"""
from fastapi import APIRouter, HTTPException, Depends
from dependencies.auth import get_current_user
from typing import Dict, Any, List
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/config", tags=["configuration"], dependencies=[Depends(get_current_user)])

# Import config module (will create this)
import sys
sys.path.append('/app')
from config.system_config import (
    get_config, 
    update_config,
    add_custom_disposition,
    add_custom_severity,
    get_all_dispositions,
    get_all_severities,
    set_confidence_display_mode,
    get_confidence_display_mode
)


# Request Models
class CustomDisposition(BaseModel):
    value: str
    label: str
    color: str = "#6b7280"
    description: str = ""

class CustomSeverity(BaseModel):
    value: str
    label: str
    color: str = "#6b7280"
    threshold: int = 50

class ConfidenceDisplayMode(BaseModel):
    mode: str  # "label" or "numeric"


# Endpoints
@router.get("/")
async def get_system_config():
    """Get full system configuration"""
    return get_config()


@router.get("/dispositions")
async def get_dispositions():
    """Get all available dispositions (built-in + custom)"""
    return {
        "dispositions": get_all_dispositions(),
        "count": len(get_all_dispositions())
    }


@router.post("/dispositions")
async def create_custom_disposition(disposition: CustomDisposition):
    """Add a custom disposition"""
    try:
        result = add_custom_disposition(
            disposition.value,
            disposition.label,
            disposition.color,
            disposition.description
        )
        return {"success": True, "disposition": result}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.delete("/dispositions/{index}")
async def delete_custom_disposition(index: int):
    """Delete a custom disposition by index"""
    try:
        config = get_config()
        if 0 <= index < len(config["dispositions"]["custom"]):
            deleted = config["dispositions"]["custom"].pop(index)
            return {"success": True, "deleted": deleted}
        else:
            raise HTTPException(404, "Custom disposition not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/severities")
async def get_severities():
    """Get all available severity levels (built-in + custom)"""
    return {
        "severities": get_all_severities(),
        "count": len(get_all_severities())
    }


@router.post("/severities")
async def create_custom_severity(severity: CustomSeverity):
    """Add a custom severity level"""
    try:
        result = add_custom_severity(
            severity.value,
            severity.label,
            severity.color,
            severity.threshold
        )
        return {"success": True, "severity": result}
    except Exception as e:
        raise HTTPException(500, str(e))


@router.delete("/severities/{index}")
async def delete_custom_severity(index: int):
    """Delete a custom severity by index"""
    try:
        config = get_config()
        if 0 <= index < len(config["severity_levels"]["custom"]):
            deleted = config["severity_levels"]["custom"].pop(index)
            return {"success": True, "deleted": deleted}
        else:
            raise HTTPException(404, "Custom severity not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


@router.get("/confidence")
async def get_confidence_config():
    """Get confidence display configuration"""
    config = get_config()
    return {
        "display_mode": get_confidence_display_mode(),
        "thresholds": config["confidence"]["thresholds"],
        "labels": config["confidence"]["labels"]
    }


@router.patch("/confidence/display-mode")
async def update_confidence_display(mode_data: ConfidenceDisplayMode):
    """Update confidence display mode"""
    if set_confidence_display_mode(mode_data.mode):
        return {"success": True, "mode": mode_data.mode}
    else:
        raise HTTPException(400, "Invalid display mode. Must be 'label' or 'numeric'")


@router.get("/priorities")
async def get_priorities():
    """Get priority levels with SLA settings"""
    config = get_config()
    return {
        "priorities": config["priorities"]["enabled"] + config["priorities"]["custom"],
        "count": len(config["priorities"]["enabled"]) + len(config["priorities"]["custom"])
    }


@router.patch("/priorities/{priority_value}/sla")
async def update_priority_sla(priority_value: str, sla_data: Dict[str, int]):
    """Update SLA hours for a priority level"""
    try:
        config = get_config()
        sla_hours = sla_data.get("sla_hours")
        
        if not sla_hours or sla_hours < 1:
            raise HTTPException(400, "Invalid SLA hours")
        
        # Update in enabled priorities
        for priority in config["priorities"]["enabled"]:
            if priority["value"] == priority_value.upper():
                priority["sla_hours"] = sla_hours
                return {"success": True, "priority": priority}
        
        # Update in custom priorities
        for priority in config["priorities"]["custom"]:
            if priority["value"] == priority_value.upper():
                priority["sla_hours"] = sla_hours
                return {"success": True, "priority": priority}
        
        raise HTTPException(404, "Priority not found")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))


# =============================================================================
# User Preferences
# =============================================================================

# In-memory store for user preferences (would be DB in production)
_user_preferences: Dict[str, Dict[str, Any]] = {}

class UserPreference(BaseModel):
    key: str
    value: Any
    username: str = "admin"

@router.post("/user/preferences")
async def save_user_preference(pref: UserPreference):
    """Save a user preference"""
    if pref.username not in _user_preferences:
        _user_preferences[pref.username] = {}
    _user_preferences[pref.username][pref.key] = pref.value
    return {"success": True, "key": pref.key}

@router.get("/user/preferences/{username}")
async def get_user_preferences(username: str):
    """Get all preferences for a user"""
    return _user_preferences.get(username, {})

@router.get("/user/preferences/{username}/{key}")
async def get_user_preference(username: str, key: str):
    """Get a specific preference for a user"""
    user_prefs = _user_preferences.get(username, {})
    if key in user_prefs:
        return {"key": key, "value": user_prefs[key]}
    raise HTTPException(404, "Preference not found")

@router.delete("/user/preferences/{username}/{key}")
async def delete_user_preference(username: str, key: str):
    """Delete a specific preference"""
    if username in _user_preferences and key in _user_preferences[username]:
        del _user_preferences[username][key]
        return {"success": True}
    raise HTTPException(404, "Preference not found")
