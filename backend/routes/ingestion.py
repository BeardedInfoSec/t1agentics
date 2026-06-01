# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Ingestion API Routes
Endpoints for managing field extractions and transforms

SECURITY NOTES:
- Pipeline processing endpoints are INTERNAL ONLY
- Rule management requires INGESTION_WRITE permission
- Read operations require INGESTION_READ permission
"""

from fastapi import APIRouter, HTTPException, Body, Request, Depends
from typing import Dict, List, Any, Optional
from pydantic import BaseModel
import logging

from services.ingestion import (
    field_extractor, transform_engine, ingestion_pipeline, rule_parser,
    ExtractionRule, ExtractionMethod, FieldType,
    TransformRule, Condition, ConditionOperator, Action, TransformAction
)
from services.security import (
    AccessContext, AccessControl, Permission, Role,
    require_permission, internal_only, audit_logger
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/ingestion", tags=["ingestion"])


# ==================== SECURITY HELPERS ====================

async def get_access_context(request: Request) -> AccessContext:
    """Get access context from request using JWT auth or internal service header."""
    is_internal = request.headers.get('X-Internal-Service') == 'true'

    # Try JWT/cookie auth first
    user_id = None
    username = "anonymous"
    role = Role.ANALYST
    is_authenticated = False

    if is_internal:
        # Trusted internal service call
        user_id = request.headers.get('X-User-Id')
        username = request.headers.get('X-Username', 'system')
        role = Role.SYSTEM
        is_authenticated = True
    else:
        # Authenticate via JWT token (cookie or Authorization header)
        try:
            from dependencies.auth import get_current_user
            user = await get_current_user(request)
            if user:
                user_id = str(user.get("id", ""))
                username = user.get("username", "unknown")
                role = Role.ADMIN if user.get("role") in ("admin", "platform_owner") else Role.ANALYST
                is_authenticated = True
        except Exception:
            pass

    if not is_authenticated:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Authentication required")

    return AccessContext(
        user_id=user_id,
        username=username,
        role=role,
        is_internal=is_internal,
        is_authenticated=is_authenticated,
        source_ip=request.client.host if request.client else None
    )


def check_permission(context: AccessContext, permission: Permission):
    """Check if context has permission, raise 403 if not"""
    if not context.has_permission(permission):
        raise HTTPException(403, f"Permission denied: {permission.value} required")


# ==================== MODELS ====================

class TestPatternRequest(BaseModel):
    pattern: str
    sample_text: str


class ExtractionRuleCreate(BaseModel):
    id: str
    name: str
    description: str = ""
    source_field: str
    method: str  # "regex", "json_path", "heuristic", "mapping"
    pattern: Optional[str] = None
    target_field: str
    field_type: str = "string"
    multi_value: bool = False
    enabled: bool = True
    priority: int = 100
    vendor_scope: Optional[List[str]] = None
    transform: Optional[str] = None
    default_value: Optional[Any] = None


class TransformRuleCreate(BaseModel):
    id: str
    name: str
    description: str = ""
    conditions: List[Dict[str, Any]]
    condition_logic: str = "all"
    actions: List[Dict[str, Any]]
    enabled: bool = True
    priority: int = 100
    vendor_scope: Optional[List[str]] = None
    stop_processing: bool = False


class ProcessEventRequest(BaseModel):
    event: Dict[str, Any]
    vendor: Optional[str] = None


class PreviewTransformRequest(BaseModel):
    event: Dict[str, Any]
    rule: Dict[str, Any]


# ==================== EXTRACTION ENDPOINTS ====================

@router.get("/extractions/patterns")
async def get_builtin_patterns(request: Request):
    """Get all built-in regex patterns"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    return {
        "patterns": field_extractor.get_builtin_patterns()
    }


@router.get("/extractions/mappings")
async def get_canonical_mappings(request: Request):
    """Get all canonical field mappings"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    return {
        "mappings": field_extractor.CANONICAL_MAPPINGS
    }


@router.post("/extractions/test-pattern")
async def test_pattern(request: Request, req: TestPatternRequest):
    """Test a regex pattern against sample text"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    result = field_extractor.test_pattern(req.pattern, req.sample_text)
    return result


@router.get("/extractions/rules")
async def get_extraction_rules(request: Request):
    """Get all custom extraction rules"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    return {
        "rules": field_extractor.get_rules(),
        "count": len(field_extractor.custom_rules)
    }


@router.post("/extractions/rules")
async def create_extraction_rule(request: Request, rule: ExtractionRuleCreate):
    """Create a new extraction rule"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_WRITE)
    
    try:
        extraction_rule = ExtractionRule(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            source_field=rule.source_field,
            method=ExtractionMethod(rule.method),
            pattern=rule.pattern,
            target_field=rule.target_field,
            field_type=FieldType(rule.field_type),
            multi_value=rule.multi_value,
            enabled=rule.enabled,
            priority=rule.priority,
            vendor_scope=rule.vendor_scope,
            transform=rule.transform,
            default_value=rule.default_value
        )
        field_extractor.add_rule(extraction_rule)
        
        # Audit log
        await audit_logger.log_access(
            context=context,
            action="create",
            resource_type="extraction_rule",
            resource_id=rule.id,
            details={"rule_name": rule.name}
        )
        
        return {"success": True, "rule": extraction_rule.to_dict()}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.delete("/extractions/rules/{rule_id}")
async def delete_extraction_rule(request: Request, rule_id: str):
    """Delete an extraction rule"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_WRITE)
    
    if field_extractor.remove_rule(rule_id):
        await audit_logger.log_access(
            context=context,
            action="delete",
            resource_type="extraction_rule",
            resource_id=rule_id
        )
        return {"success": True}
    raise HTTPException(404, f"Rule {rule_id} not found")


@router.post("/extractions/extract")
async def extract_fields(request: Request, req: ProcessEventRequest):
    """Extract fields from an event (for testing/preview)"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    extracted = field_extractor.extract_all(req.event, req.vendor)
    return {
        "extracted": extracted,
        "field_count": len(extracted)
    }


# ==================== TRANSFORM ENDPOINTS ====================

@router.get("/transforms/rules")
async def get_transform_rules(request: Request):
    """Get all transform rules"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    return {
        "rules": transform_engine.get_rules(),
        "count": len(transform_engine.rules)
    }


@router.post("/transforms/rules")
async def create_transform_rule(request: Request, rule: TransformRuleCreate):
    """Create a new transform rule"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_WRITE)
    
    try:
        conditions = [
            Condition(
                field=c['field'],
                operator=ConditionOperator(c['operator']),
                value=c.get('value')
            ) for c in rule.conditions
        ]
        
        actions = [
            Action(
                action_type=TransformAction(a['action_type']),
                params=a.get('params', {})
            ) for a in rule.actions
        ]
        
        transform_rule = TransformRule(
            id=rule.id,
            name=rule.name,
            description=rule.description,
            conditions=conditions,
            condition_logic=rule.condition_logic,
            actions=actions,
            enabled=rule.enabled,
            priority=rule.priority,
            vendor_scope=rule.vendor_scope,
            stop_processing=rule.stop_processing
        )
        transform_engine.add_rule(transform_rule)
        
        await audit_logger.log_access(
            context=context,
            action="create",
            resource_type="transform_rule",
            resource_id=rule.id,
            details={"rule_name": rule.name}
        )
        
        return {"success": True, "rule": transform_rule.to_dict()}
    except Exception as e:
        raise HTTPException(400, str(e))


@router.put("/transforms/rules/{rule_id}")
async def update_transform_rule(request: Request, rule_id: str, updates: Dict[str, Any] = Body(...)):
    """Update a transform rule"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_WRITE)
    
    if transform_engine.update_rule(rule_id, updates):
        await audit_logger.log_access(
            context=context,
            action="update",
            resource_type="transform_rule",
            resource_id=rule_id
        )
        return {"success": True}
    raise HTTPException(404, f"Rule {rule_id} not found")


@router.delete("/transforms/rules/{rule_id}")
async def delete_transform_rule(request: Request, rule_id: str):
    """Delete a transform rule"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_WRITE)
    
    if transform_engine.remove_rule(rule_id):
        await audit_logger.log_access(
            context=context,
            action="delete",
            resource_type="transform_rule",
            resource_id=rule_id
        )
        return {"success": True}
    raise HTTPException(404, f"Rule {rule_id} not found")


@router.post("/transforms/preview")
async def preview_transform(request: Request, req: PreviewTransformRequest):
    """Preview the result of applying a transform rule to an event"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    try:
        conditions = [
            Condition(
                field=c['field'],
                operator=ConditionOperator(c['operator']),
                value=c.get('value')
            ) for c in req.rule.get('conditions', [])
        ]
        
        actions = [
            Action(
                action_type=TransformAction(a['action_type']),
                params=a.get('params', {})
            ) for a in req.rule.get('actions', [])
        ]
        
        rule = TransformRule(
            id=req.rule.get('id', 'preview'),
            name=req.rule.get('name', 'Preview Rule'),
            description=req.rule.get('description', ''),
            conditions=conditions,
            condition_logic=req.rule.get('condition_logic', 'all'),
            actions=actions
        )
        
        result = transform_engine.preview_transform(req.event, rule)
        return result
    except Exception as e:
        raise HTTPException(400, str(e))


# ==================== INTERNAL PIPELINE ENDPOINTS ====================
# These endpoints are INTERNAL ONLY - not exposed to external API

@router.post("/pipeline/process", include_in_schema=False)
async def process_event_internal(request: Request, req: ProcessEventRequest):
    """
    Process an event through the full ingestion pipeline
    
    INTERNAL ONLY - This endpoint should only be called by internal services
    """
    context = get_access_context(request)
    
    # Require internal context OR system role
    if not context.is_internal and context.role != Role.SYSTEM:
        await audit_logger.log_security_event(
            event_type="unauthorized_access",
            description=f"External access attempt to internal pipeline endpoint",
            severity="warning",
            details={"source_ip": context.source_ip, "user": context.username}
        )
        raise HTTPException(403, "This endpoint is internal-only")
    
    check_permission(context, Permission.INGESTION_PROCESS)
    
    result = ingestion_pipeline.process(req.event, req.vendor)
    return result.to_dict()


@router.post("/pipeline/process-batch", include_in_schema=False)
async def process_batch_internal(request: Request, events: List[Dict[str, Any]] = Body(...), vendor: Optional[str] = None):
    """
    Process a batch of events
    
    INTERNAL ONLY - This endpoint should only be called by internal services
    """
    context = get_access_context(request)
    
    if not context.is_internal and context.role != Role.SYSTEM:
        raise HTTPException(403, "This endpoint is internal-only")
    
    check_permission(context, Permission.INGESTION_PROCESS)
    
    results = ingestion_pipeline.process_batch(events, vendor)
    return {
        "results": [r.to_dict() for r in results],
        "total": len(results),
        "successful": sum(1 for r in results if r.success),
        "dropped": sum(1 for r in results if r.dropped),
        "errored": sum(1 for r in results if not r.success)
    }


@router.get("/pipeline/metrics")
async def get_metrics(request: Request):
    """Get pipeline processing metrics"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    return ingestion_pipeline.get_metrics()


@router.post("/pipeline/reset-metrics", include_in_schema=False)
async def reset_metrics(request: Request):
    """Reset pipeline metrics - Admin only"""
    context = get_access_context(request)
    
    if context.role != Role.ADMIN:
        raise HTTPException(403, "Admin access required")
    
    ingestion_pipeline.reset_metrics()
    
    await audit_logger.log_access(
        context=context,
        action="reset_metrics",
        resource_type="pipeline"
    )
    
    return {"success": True}


# ==================== IMPORT/EXPORT ENDPOINTS ====================

@router.post("/import/yaml")
async def import_yaml(request: Request, content: str = Body(..., media_type="text/plain")):
    """Import rules from YAML"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_WRITE)
    
    rules = rule_parser.parse_yaml(content)
    if not rules:
        raise HTTPException(400, "Failed to parse YAML content")
    
    imported = 0
    for rule_data in rules:
        try:
            if 'source_field' in rule_data:
                rule = ExtractionRule(
                    id=rule_data['id'],
                    name=rule_data['name'],
                    description=rule_data.get('description', ''),
                    source_field=rule_data['source_field'],
                    method=ExtractionMethod(rule_data.get('method', 'regex')),
                    pattern=rule_data.get('pattern'),
                    target_field=rule_data.get('target_field', ''),
                    field_type=FieldType(rule_data.get('field_type', 'string'))
                )
                field_extractor.add_rule(rule)
            elif 'conditions' in rule_data:
                transform_engine.import_rules([rule_data])
            imported += 1
        except Exception as e:
            logger.error(f"Failed to import rule: {e}")
    
    await audit_logger.log_access(
        context=context,
        action="import",
        resource_type="rules",
        details={"format": "yaml", "imported_count": imported}
    )
    
    return {"imported": imported, "total": len(rules)}


@router.post("/import/splunk")
async def import_splunk(request: Request, content: str = Body(..., media_type="text/plain")):
    """Import Splunk-style rules"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_WRITE)
    
    imported = 0
    for line in content.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        if line.startswith('EXTRACT-'):
            rule = rule_parser.parse_splunk_extract(line)
            if rule:
                field_extractor.add_rule(rule)
                imported += 1
    
    await audit_logger.log_access(
        context=context,
        action="import",
        resource_type="rules",
        details={"format": "splunk", "imported_count": imported}
    )
    
    return {"imported": imported}


@router.get("/export/yaml")
async def export_yaml(request: Request):
    """Export all rules as YAML"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    rules = {
        "extraction_rules": field_extractor.get_rules(),
        "transform_rules": transform_engine.get_rules()
    }
    yaml_content = rule_parser.to_yaml(rules)
    return {"content": yaml_content}


@router.get("/export/json")
async def export_json(request: Request):
    """Export all rules as JSON"""
    context = get_access_context(request)
    check_permission(context, Permission.INGESTION_READ)
    
    return {
        "extraction_rules": field_extractor.get_rules(),
        "transform_rules": transform_engine.get_rules()
    }


# ==================== UTILITY ENDPOINTS ====================

@router.get("/field-types")
async def get_field_types():
    """Get available field types - Public"""
    return {"types": [t.value for t in FieldType]}


@router.get("/extraction-methods")
async def get_extraction_methods():
    """Get available extraction methods - Public"""
    return {"methods": [m.value for m in ExtractionMethod]}


@router.get("/transform-actions")
async def get_transform_actions():
    """Get available transform actions - Public"""
    return {"actions": [a.value for a in TransformAction]}


@router.get("/condition-operators")
async def get_condition_operators():
    """Get available condition operators - Public"""
    return {"operators": [o.value for o in ConditionOperator]}
