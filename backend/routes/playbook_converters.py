# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Converter API Routes

Endpoints for importing and converting playbooks from SOAR platforms:
- Splunk SOAR (Phantom)
- Palo Alto XSOAR (Demisto)
- Tines
- Swimlane
- Google Chronicle SOAR (Siemplify)
- IBM QRadar SOAR (Resilient)
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Depends
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from collections import Counter
import re
import logging
import json
import uuid
import tarfile
import gzip
import io
import base64
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/playbooks/import", tags=["Playbook Import"], dependencies=[Depends(get_current_user)])


# ============================================================================
# Platform Catalog
# ============================================================================
# Display + file-input metadata for each registered converter.
# Single source of truth for the import-page UI — the frontend fetches
# /api/v1/playbooks/import/platforms on mount and renders one card per
# entry. Order here is the order shown to the user.
#
# When adding a new converter:
#   1. Create backend/services/playbook_converters/<platform>.py
#   2. Register it in __init__.py and the dispatch map in this file
#   3. Add an entry below — that's what makes it discoverable in the UI

PLATFORM_CATALOG = [
    {"id": "splunk_soar",       "name": "Splunk SOAR",            "formats": ["TGZ", "JSON+PY"], "accept": ".tgz,.tar.gz,.gz,.json", "description": "Phantom-era archive (.tgz) or paired JSON + Python."},
    {"id": "xsoar",             "name": "Cortex XSOAR",           "formats": ["YAML", "JSON"],   "accept": ".yml,.yaml,.json",       "description": "Palo Alto XSOAR / Demisto playbook export."},
    {"id": "sentinel",          "name": "Microsoft Sentinel",     "formats": ["JSON"],           "accept": ".json",                  "description": "Azure Logic Apps automation rule export."},
    {"id": "chronicle_soar",    "name": "Chronicle SOAR",         "formats": ["JSON"],           "accept": ".json",                  "description": "Google Chronicle SOAR (Siemplify) workflow."},
    {"id": "qradar_soar",       "name": "QRadar SOAR",            "formats": ["JSON"],           "accept": ".json",                  "description": "IBM QRadar SOAR (Resilient) playbook."},
    {"id": "servicenow_secops", "name": "ServiceNow SecOps",      "formats": ["JSON"],           "accept": ".json",                  "description": "Flow Designer security automation."},
    {"id": "fortisoar",         "name": "FortiSOAR",              "formats": ["JSON"],           "accept": ".json",                  "description": "Fortinet FortiSOAR playbook export."},
    {"id": "insight_connect",   "name": "Rapid7 InsightConnect",  "formats": ["JSON"],           "accept": ".json",                  "description": "Komand / InsightConnect workflow."},
    {"id": "exabeam",           "name": "Exabeam",                "formats": ["JSON"],           "accept": ".json",                  "description": "Exabeam New-Scale SOAR automation."},
    {"id": "logichub",          "name": "LogicHub",               "formats": ["JSON"],           "accept": ".json",                  "description": "LogicHub SOAR + SIEM flow."},
    {"id": "resolve",           "name": "Resolve",                "formats": ["JSON"],           "accept": ".json",                  "description": "Resolve Systems automation."},
    {"id": "swimlane",          "name": "Swimlane",               "formats": ["JSON"],           "accept": ".json",                  "description": "Swimlane Turbine / SSP workflow export."},
    {"id": "tines",             "name": "Tines",                  "formats": ["JSON"],           "accept": ".json",                  "description": "Tines story export with actions and links."},
    {"id": "torq",              "name": "Torq",                   "formats": ["JSON"],           "accept": ".json",                  "description": "Torq hyperautomation workflow."},
    {"id": "blinkops",          "name": "BlinkOps",               "formats": ["JSON", "YAML"],   "accept": ".json,.yml,.yaml",       "description": "BlinkOps no-code automation."},
    {"id": "shuffle",           "name": "Shuffle",                "formats": ["JSON"],           "accept": ".json",                  "description": "Open-source Shuffle workflow."},
    {"id": "thehive",           "name": "TheHive / Cortex",       "formats": ["JSON"],           "accept": ".json",                  "description": "StrangeBee TheHive responder / Cortex."},
    {"id": "d3_security",       "name": "D3 Security",            "formats": ["JSON"],           "accept": ".json",                  "description": "D3 Smart SOAR playbook export."},
]


@router.get("/platforms")
async def list_supported_platforms():
    """Return the registered SOAR converter platforms with UI metadata.

    Used by the import page to render one card per supported platform.
    All entries listed here are fully implemented in
    backend/services/playbook_converters/ and routable via /preview and
    /upload below.
    """
    return {
        "platforms": [{**p, "status": "ready"} for p in PLATFORM_CATALOG],
        "total": len(PLATFORM_CATALOG),
    }


# ============================================================================
# Request/Response Models
# ============================================================================

class PlaybookImportRequest(BaseModel):
    """Request to import a playbook."""
    content: str = Field(..., description="Raw playbook content (JSON or YAML)")
    python_code: Optional[str] = Field(
        default=None,
        description="Optional Splunk SOAR Python code (when JSON and PY are uploaded separately)"
    )
    source_platform: str = Field(
        default="auto",
        description="Source platform: splunk_soar, xsoar, tines, swimlane, chronicle_soar, qradar_soar, or auto"
    )
    name_override: Optional[str] = Field(
        default=None,
        description="Override the playbook name"
    )
    save: bool = Field(
        default=True,
        description="Save the playbook after conversion"
    )
    review_mode: bool = Field(
        default=True,
        description="Require human review before enabling"
    )


class ConversionPreviewRequest(BaseModel):
    """Request to preview a conversion."""
    content: str
    source_platform: str = "auto"
    python_code: Optional[str] = None


class SkippedStepResponse(BaseModel):
    """Details of a skipped step."""
    original_id: str
    original_name: str
    original_type: str
    reason: str


class ConversionReportResponse(BaseModel):
    """Conversion report."""
    success: bool
    total_steps: int
    converted_steps: int
    skipped_steps: List[SkippedStepResponse]
    warnings: List[str]
    unmapped_actions: List[str]
    requires_review: bool
    conversion_time_ms: float


class ImportResultResponse(BaseModel):
    """Result of a playbook import."""
    success: bool
    playbook_id: Optional[str] = None
    playbook_name: Optional[str] = None
    conversion_report: ConversionReportResponse
    message: str


# ============================================================================
# Archive Extraction
# ============================================================================

def extract_playbook_from_archive(content: str) -> Dict[str, str]:
    """
    Extract playbook content from archive files (.tgz, .tar.gz, .gz).

    For Splunk SOAR: Extracts both .py and .json files (dual-file format)
    For other platforms: Extracts the JSON/YAML file

    Returns:
        Dict with 'content' key (JSON/YAML) and optionally 'python_code' key
        Or just the original content string if not an archive
    """
    try:
        # Try to decode as base64 (frontend sends binary files as base64)
        try:
            binary_data = base64.b64decode(content)
        except:
            # Not base64, might be plain text
            return {'content': content}

        # Try to extract as .tar.gz or .tgz
        try:
            with tarfile.open(fileobj=io.BytesIO(binary_data), mode='r:gz') as tar:
                json_content = None
                python_content = None

                # Extract both Python and JSON files (for Splunk SOAR dual-file format)
                for member in tar.getmembers():
                    if not member.isfile():
                        continue

                    f = tar.extractfile(member)
                    if not f:
                        continue

                    file_content = f.read().decode('utf-8')

                    # Collect JSON/YAML files
                    if member.name.endswith('.json') or member.name.endswith('.yml') or member.name.endswith('.yaml'):
                        json_content = file_content
                    # Collect Python files
                    elif member.name.endswith('.py'):
                        python_content = file_content

                # Return both files if found (Splunk SOAR format)
                if json_content and python_content:
                    return {
                        'content': json_content,
                        'python_code': python_content
                    }
                # Return just JSON if only that was found
                elif json_content:
                    return {'content': json_content}
                # Fallback: return first file found
                else:
                    for member in tar.getmembers():
                        if member.isfile():
                            f = tar.extractfile(member)
                            if f:
                                return {'content': f.read().decode('utf-8')}
        except:
            pass

        # Try to extract as plain gzip
        try:
            with gzip.open(io.BytesIO(binary_data), 'rt') as gz:
                return {'content': gz.read()}
        except:
            pass

        # If all extraction attempts failed, try to decode as UTF-8
        try:
            return {'content': binary_data.decode('utf-8')}
        except:
            pass

    except Exception as e:
        logger.error(f"Archive extraction failed: {e}")

    # Return original content if extraction failed
    return {'content': content}


def _counter_to_list(counter: Counter) -> List[Dict[str, Any]]:
    return [
        {"name": key, "count": value}
        for key, value in sorted(counter.items(), key=lambda item: (-item[1], item[0]))
    ]


def summarize_splunk_soar_source(content: str, python_code: Optional[str]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {"json": {}, "python": {}}

    try:
        data = json.loads(content)
        coa_data = data.get("coa", {}).get("data", {})
        nodes_dict = coa_data.get("nodes", {})
        edges = coa_data.get("edges", [])

        blocks = []
        if isinstance(nodes_dict, dict) and nodes_dict:
            for node_id, node_data in nodes_dict.items():
                block = {"id": node_id}
                if isinstance(node_data, dict):
                    block.update(node_data.get("data", {}))
                    block["type"] = node_data.get("type", block.get("type"))
                blocks.append(block)
        elif isinstance(data.get("blocks"), list):
            blocks = data.get("blocks", [])

        node_types = Counter()
        actions = Counter()
        connectors = Counter()
        connector_configs = Counter()

        for block in blocks:
            block_type = block.get("block_type") or block.get("type") or "unknown"
            node_types[block_type] += 1

            action = block.get("action") or block.get("action_id")
            if action:
                actions[action] += 1

            connector = block.get("connector") or block.get("app") or block.get("app_id")
            if connector:
                connectors[connector] += 1

            configs = block.get("connectorConfigs") or block.get("connector_configs") or []
            if isinstance(configs, list):
                for cfg in configs:
                    connector_configs[cfg] += 1

        summary["json"] = {
            "node_count": len(blocks),
            "edge_count": len(edges),
            "node_types": _counter_to_list(node_types),
            "actions": _counter_to_list(actions),
            "connectors": _counter_to_list(connectors),
            "connector_configs": _counter_to_list(connector_configs),
        }
    except Exception as e:
        summary["json"] = {"error": str(e)}

    if python_code:
        try:
            functions = re.findall(r"@phantom\.playbook_block\(\)\s*\ndef\s+(\w+)\s*\(", python_code)
            act_calls = re.findall(r"phantom\.act\(\s*\"([^\"]+)\"", python_code)
            assets = re.findall(r"assets=\[(.*?)\]", python_code)
            preview_lines = python_code.splitlines()[:140]
            summary["python"] = {
                "function_count": len(functions),
                "functions": functions,
                "action_calls": sorted(set(act_calls)),
                "assets": sorted(set(a.strip().strip("\"'") for a in assets if a.strip())),
                "preview": "\n".join(preview_lines),
            }
        except re.error as exc:
            summary["python"] = {"error": f"Regex parse failed: {exc}"}
        except Exception as exc:
            summary["python"] = {"error": str(exc)}

    return summary


# ============================================================================
# Converter Factory
# ============================================================================

def get_converter(platform: str):
    """Get the appropriate converter for a platform."""
    from services.playbook_converters import (
        SplunkSOARConverter, XSOARConverter, TinesConverter, SwimlaneConverter,
        ChronicleSoarConverter, QRadarSOARConverter, SentinelConverter,
        FortiSOARConverter, InsightConnectConverter, TheHiveConverter,
        ShuffleConverter, TorqConverter, ServiceNowSecOpsConverter,
        ExabeamConverter, BlinkOpsConverter, D3SecurityConverter,
        LogicHubConverter, ResolveConverter,
    )

    converters = {
        'splunk_soar': SplunkSOARConverter(),
        'xsoar': XSOARConverter(),
        'tines': TinesConverter(),
        'swimlane': SwimlaneConverter(),
        'chronicle_soar': ChronicleSoarConverter(),
        'qradar_soar': QRadarSOARConverter(),
        'sentinel': SentinelConverter(),
        'fortisoar': FortiSOARConverter(),
        'insight_connect': InsightConnectConverter(),
        'thehive': TheHiveConverter(),
        'shuffle': ShuffleConverter(),
        'torq': TorqConverter(),
        'servicenow_secops': ServiceNowSecOpsConverter(),
        'exabeam': ExabeamConverter(),
        'blinkops': BlinkOpsConverter(),
        'd3_security': D3SecurityConverter(),
        'logichub': LogicHubConverter(),
        'resolve': ResolveConverter(),
    }

    return converters.get(platform.lower())


def detect_and_get_converter(content: str):
    """Auto-detect platform and return appropriate converter."""
    from services.playbook_converters.base import detect_platform, SourcePlatform
    from services.playbook_converters import (
        SplunkSOARConverter, XSOARConverter, TinesConverter, SwimlaneConverter,
        ChronicleSoarConverter, QRadarSOARConverter, SentinelConverter,
        FortiSOARConverter, InsightConnectConverter, TheHiveConverter,
        ShuffleConverter, TorqConverter, ServiceNowSecOpsConverter,
        ExabeamConverter, BlinkOpsConverter, D3SecurityConverter,
        LogicHubConverter, ResolveConverter,
    )

    platform = detect_platform(content)

    converter_map = {
        SourcePlatform.SPLUNK_SOAR: (SplunkSOARConverter, 'splunk_soar'),
        SourcePlatform.XSOAR: (XSOARConverter, 'xsoar'),
        SourcePlatform.TINES: (TinesConverter, 'tines'),
        SourcePlatform.SWIMLANE: (SwimlaneConverter, 'swimlane'),
        SourcePlatform.CHRONICLE_SOAR: (ChronicleSoarConverter, 'chronicle_soar'),
        SourcePlatform.QRADAR_SOAR: (QRadarSOARConverter, 'qradar_soar'),
        SourcePlatform.SENTINEL: (SentinelConverter, 'sentinel'),
        SourcePlatform.FORTISOAR: (FortiSOARConverter, 'fortisoar'),
        SourcePlatform.INSIGHT_CONNECT: (InsightConnectConverter, 'insight_connect'),
        SourcePlatform.THEHIVE: (TheHiveConverter, 'thehive'),
        SourcePlatform.SHUFFLE: (ShuffleConverter, 'shuffle'),
        SourcePlatform.TORQ: (TorqConverter, 'torq'),
        SourcePlatform.SERVICENOW_SECOPS: (ServiceNowSecOpsConverter, 'servicenow_secops'),
        SourcePlatform.EXABEAM: (ExabeamConverter, 'exabeam'),
        SourcePlatform.BLINKOPS: (BlinkOpsConverter, 'blinkops'),
        SourcePlatform.D3_SECURITY: (D3SecurityConverter, 'd3_security'),
        SourcePlatform.LOGICHUB: (LogicHubConverter, 'logichub'),
        SourcePlatform.RESOLVE: (ResolveConverter, 'resolve'),
    }

    if platform in converter_map:
        cls, name = converter_map[platform]
        return cls(), name

    return None, 'unknown'


# ============================================================================
# API Endpoints
# ============================================================================

@router.post("/detect")
async def detect_platform(request: ConversionPreviewRequest):
    """
    Auto-detect the source platform from playbook content.

    Returns the detected platform or 'unknown'.
    """
    from services.playbook_converters.base import detect_platform as detect

    platform = detect(request.content)

    return {
        "platform": platform.value,
        "detected": platform.value != "unknown"
    }


@router.post("/preview")
async def preview_conversion(request: ConversionPreviewRequest):
    """
    Preview a playbook conversion without saving.

    Returns the converted playbook structure and conversion report.
    """
    # Extract from archive if needed
    extracted = extract_playbook_from_archive(request.content)
    content = extracted.get('content') if isinstance(extracted, dict) else extracted
    python_code = extracted.get('python_code') if isinstance(extracted, dict) else None
    if request.python_code:
        python_code = request.python_code

    # Get converter
    if request.source_platform == "auto":
        converter, platform = detect_and_get_converter(content)
        if not converter:
            raise HTTPException(
                status_code=400,
                detail="Could not detect playbook platform. Please specify source_platform."
            )
    else:
        converter = get_converter(request.source_platform)
        platform = request.source_platform
        if not converter:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported platform: {request.source_platform}"
            )

    # Convert
    try:
        # Pass python_code to converter if available (for Splunk SOAR)
        if python_code and hasattr(converter, 'set_python_code'):
            converter.set_python_code(python_code)

        playbook, report = converter.convert(content)

        # Validate
        validation_errors = converter.validate(playbook)
        if validation_errors:
            report.warnings.extend(validation_errors)

        response = {
            "platform_detected": platform,
            "playbook": {
                "name": playbook.name,
                "description": playbook.description,
                "trigger_conditions": playbook.trigger_conditions,
                "canvas_data": playbook.canvas_data,
                "tags": playbook.tags,
                "alert_types": playbook.alert_types
            },
            "report": {
                "success": report.success,
                "total_steps": report.total_steps,
                "converted_steps": report.converted_steps,
                "skipped_steps": [
                    {
                        "original_id": s.original_id,
                        "original_name": s.original_name,
                        "original_type": s.original_type,
                        "reason": s.reason
                    }
                    for s in report.skipped_steps
                ],
                "warnings": report.warnings,
                "unmapped_actions": report.unmapped_actions,
                "requires_review": report.requires_review,
                "conversion_time_ms": report.conversion_time_ms
            }
        }

        if platform == "splunk_soar":
            response["source_summary"] = summarize_splunk_soar_source(content, python_code)

        return response

    except Exception as e:
        logger.error(f"Preview failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("")
async def import_playbook(request: PlaybookImportRequest) -> ImportResultResponse:
    """
    Import a playbook from a SOAR platform.

    Detects the platform (or uses specified), converts the playbook,
    and optionally saves it.
    """
    # Extract from archive if needed
    extracted = extract_playbook_from_archive(request.content)
    content = extracted.get('content') if isinstance(extracted, dict) else extracted
    python_code = extracted.get('python_code') if isinstance(extracted, dict) else None
    if request.python_code:
        python_code = request.python_code

    # Get converter
    if request.source_platform == "auto":
        converter, platform = detect_and_get_converter(content)
        if not converter:
            raise HTTPException(
                status_code=400,
                detail="Could not detect playbook platform. Please specify source_platform."
            )
    else:
        converter = get_converter(request.source_platform)
        platform = request.source_platform
        if not converter:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported platform: {request.source_platform}"
            )

    # Convert
    try:
        # Pass python_code to converter if available (for Splunk SOAR)
        if python_code and hasattr(converter, 'set_python_code'):
            converter.set_python_code(python_code)

        playbook, report = converter.convert(content, request.name_override)

        # Validate
        validation_errors = converter.validate(playbook)
        if validation_errors:
            report.warnings.extend(validation_errors)

        report_response = ConversionReportResponse(
            success=report.success,
            total_steps=report.total_steps,
            converted_steps=report.converted_steps,
            skipped_steps=[
                SkippedStepResponse(
                    original_id=s.original_id,
                    original_name=s.original_name,
                    original_type=s.original_type,
                    reason=s.reason
                )
                for s in report.skipped_steps
            ],
            warnings=report.warnings,
            unmapped_actions=report.unmapped_actions,
            requires_review=report.requires_review,
            conversion_time_ms=report.conversion_time_ms
        )

        if not report.success:
            return ImportResultResponse(
                success=False,
                conversion_report=report_response,
                message="Conversion failed - no steps could be converted"
            )

        # Save if requested
        if request.save:
            from services.postgres_db import postgres_db

            if not postgres_db.connected:
                raise HTTPException(status_code=500, detail="Database not connected")

            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    INSERT INTO playbooks (
                        name, description, trigger_conditions, canvas_data,
                        is_enabled, riggs_allowed, requires_approval,
                        tags, alert_types, imported_from, import_metadata
                    ) VALUES ($1, $2, $3, $4, FALSE, FALSE, TRUE, $5, $6, $7, $8)
                    RETURNING id
                ''',
                    playbook.name,
                    playbook.description,
                    json.dumps(playbook.trigger_conditions),
                    json.dumps(playbook.canvas_data),
                    playbook.tags,
                    playbook.alert_types,
                    platform,
                    json.dumps(playbook.import_metadata)
                )

                playbook_id = str(row['id'])

            return ImportResultResponse(
                success=True,
                playbook_id=playbook_id,
                playbook_name=playbook.name,
                conversion_report=report_response,
                message=f"Playbook imported successfully from {platform}. "
                        f"{report.converted_steps}/{report.total_steps} steps converted."
            )

        else:
            return ImportResultResponse(
                success=True,
                playbook_name=playbook.name,
                conversion_report=report_response,
                message=f"Conversion successful (not saved). "
                        f"{report.converted_steps}/{report.total_steps} steps converted."
            )

    except Exception as e:
        logger.error(f"Import failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/splunk-soar")
async def import_splunk_soar(request: PlaybookImportRequest) -> ImportResultResponse:
    """
    Import a Splunk SOAR (Phantom) playbook.

    Explicitly uses the Splunk SOAR converter.
    """
    request.source_platform = "splunk_soar"
    return await import_playbook(request)


@router.post("/xsoar")
async def import_xsoar(request: PlaybookImportRequest) -> ImportResultResponse:
    """
    Import a Palo Alto XSOAR (Demisto) playbook.

    Explicitly uses the XSOAR converter.
    """
    request.source_platform = "xsoar"
    return await import_playbook(request)


@router.post("/tines")
async def import_tines(request: PlaybookImportRequest) -> ImportResultResponse:
    """
    Import a Tines story.

    Explicitly uses the Tines converter.
    """
    request.source_platform = "tines"
    return await import_playbook(request)


@router.post("/swimlane")
async def import_swimlane(request: PlaybookImportRequest) -> ImportResultResponse:
    """
    Import a Swimlane Turbine workflow or SSP action package.

    Explicitly uses the Swimlane converter.
    """
    request.source_platform = "swimlane"
    return await import_playbook(request)


@router.post("/chronicle-soar")
async def import_chronicle_soar(request: PlaybookImportRequest) -> ImportResultResponse:
    """
    Import a Google Chronicle SOAR (Siemplify) playbook.

    Explicitly uses the Chronicle SOAR converter.
    """
    request.source_platform = "chronicle_soar"
    return await import_playbook(request)


@router.post("/qradar-soar")
async def import_qradar_soar(request: PlaybookImportRequest) -> ImportResultResponse:
    """
    Import an IBM QRadar SOAR (Resilient) playbook or workflow.

    Explicitly uses the QRadar SOAR converter.
    """
    request.source_platform = "qradar_soar"
    return await import_playbook(request)


@router.post("/file")
async def import_from_file(
    file: UploadFile = File(...),
    source_platform: str = "auto",
    name_override: Optional[str] = None,
    save: bool = True
) -> ImportResultResponse:
    """
    Import a playbook from an uploaded file.

    Accepts JSON or YAML files.
    """
    # Read file content
    content = await file.read()
    content_str = content.decode('utf-8')

    # Create request and process
    request = PlaybookImportRequest(
        content=content_str,
        source_platform=source_platform,
        name_override=name_override,
        save=save
    )

    return await import_playbook(request)


@router.get("/action-mappings/{platform}")
async def get_action_mappings(platform: str):
    """
    Get the action mapping table for a platform.

    Useful for understanding how source actions map to native nodes.
    """
    from services.playbook_converters.action_maps import get_action_map

    action_map = get_action_map(platform)

    if not action_map:
        raise HTTPException(
            status_code=404,
            detail=f"No action mappings for platform: {platform}"
        )

    # Format for display
    mappings = []
    for source_action, (node_type, config) in action_map.items():
        mappings.append({
            "source_action": source_action,
            "native_node_type": node_type,
            "default_config": config
        })

    return {
        "platform": platform,
        "mapping_count": len(mappings),
        "mappings": mappings
    }


@router.get("/templates")
async def get_sample_playbooks():
    """
    Get sample playbook content for each supported platform.

    Useful for testing the import functionality.
    """
    return {
        "platforms": [
            {
                "platform": "splunk_soar",
                "name": "Splunk SOAR (Phantom)",
                "sample": {
                    "name": "Sample Phishing Response",
                    "playbook_type": "automation",
                    "blocks": [
                        {
                            "id": "1",
                            "block_type": "action",
                            "name": "Get IP Reputation",
                            "action": "ip_reputation",
                            "app": "VirusTotal",
                            "outputs": [{"target": "2"}]
                        },
                        {
                            "id": "2",
                            "block_type": "decision",
                            "name": "Check Malicious",
                            "conditions": [
                                {"field": "$.result.malicious", "operator": ">", "value": 0, "target": "3"}
                            ]
                        },
                        {
                            "id": "3",
                            "block_type": "action",
                            "name": "Block IP",
                            "action": "block_ip"
                        }
                    ]
                }
            },
            {
                "platform": "xsoar",
                "name": "Palo Alto XSOAR",
                "sample": {
                    "name": "Sample Malware Investigation",
                    "version": 1,
                    "starttaskid": "0",
                    "tasks": {
                        "0": {
                            "type": "start",
                            "task": {"name": "Start"},
                            "nexttasks": {"#none#": ["1"]}
                        },
                        "1": {
                            "type": "regular",
                            "task": {"name": "File Reputation", "script": "!file"},
                            "nexttasks": {"#none#": ["2"]}
                        },
                        "2": {
                            "type": "condition",
                            "task": {"name": "Check Score"},
                            "conditions": [
                                {"label": "Malicious", "condition": [[{"left": {"value": "${Score}"}, "operator": "greaterThan", "right": {"value": 50}}]]}
                            ],
                            "nexttasks": {"Malicious": ["3"]}
                        },
                        "3": {
                            "type": "regular",
                            "task": {"name": "Isolate Host", "command": "!endpoint_isolate"}
                        }
                    }
                }
            },
            {
                "platform": "tines",
                "name": "Tines",
                "sample": {
                    "name": "Sample Alert Triage",
                    "agents": [
                        {
                            "id": "1",
                            "type": "webhookAgent",
                            "name": "Receive Alert",
                            "options": {"path": "/alerts"}
                        },
                        {
                            "id": "2",
                            "type": "httpRequestAgent",
                            "name": "Enrich IP",
                            "options": {
                                "url": "https://www.virustotal.com/api/v3/ip_addresses/{{ip}}",
                                "method": "GET"
                            }
                        },
                        {
                            "id": "3",
                            "type": "triggerAgent",
                            "name": "Check Malicious",
                            "options": {
                                "rules": [{"path": "$.attributes.last_analysis_stats.malicious", "type": "greater_than", "value": 0}]
                            }
                        },
                        {
                            "id": "4",
                            "type": "slackAgent",
                            "name": "Notify SOC",
                            "options": {"channel": "#alerts", "message": "Malicious IP detected!"}
                        }
                    ],
                    "links": [
                        {"source": "1", "receiver": "2"},
                        {"source": "2", "receiver": "3"},
                        {"source": "3", "receiver": "4"}
                    ]
                }
            },
            {
                "platform": "swimlane",
                "name": "Swimlane",
                "sample": {
                    "name": "Sample Swimlane IP Triage",
                    "playbook": {
                        "nodes": [
                            {"id": "1", "type": "trigger", "name": "Alert Received", "config": {"triggerType": "alert"}},
                            {"id": "2", "type": "action", "name": "IP Lookup", "config": {"action": "ip_lookup", "integration": "GreyNoise"}},
                            {"id": "3", "type": "condition", "name": "Is Malicious?", "config": {"conditions": []}},
                            {"id": "4", "type": "notification", "name": "Notify Analyst", "config": {"channel": "email"}}
                        ],
                        "connections": [
                            {"source": "1", "target": "2"},
                            {"source": "2", "target": "3"},
                            {"source": "3", "target": "4", "label": "Yes"}
                        ]
                    }
                }
            },
            {
                "platform": "chronicle_soar",
                "name": "Google Chronicle SOAR (Siemplify)",
                "sample": {
                    "playbook_name": "Sample Threat Enrichment",
                    "description": "Enrich IP via VirusTotal and notify",
                    "playbook_trigger_type": "ALERT",
                    "steps": {
                        "trigger_1": {"type": "Trigger", "name": "Alert Trigger"},
                        "action_1": {"type": "Action", "name": "Scan IP", "integration": "VirusTotal", "action": "Scan IP"},
                        "condition_1": {"type": "Condition", "name": "Is Malicious?", "expression": "score > 50"},
                        "action_2": {"type": "Action", "name": "Send Notification", "integration": "Slack", "action": "Send Message"}
                    },
                    "connections": [
                        {"source_step": "trigger_1", "target_step": "action_1"},
                        {"source_step": "action_1", "target_step": "condition_1"},
                        {"source_step": "condition_1", "target_step": "action_2", "condition": "True"}
                    ]
                }
            },
            {
                "platform": "qradar_soar",
                "name": "IBM QRadar SOAR (Resilient)",
                "sample": {
                    "export_format_version": 2,
                    "playbooks": [
                        {
                            "name": "sample_ip_block",
                            "display_name": "Sample IP Block Workflow",
                            "description": "Look up and block malicious IP",
                            "activation_type": "manual",
                            "object_type": "incident",
                            "status": "enabled",
                            "content": {"xml": ""}
                        }
                    ],
                    "functions": [
                        {"uuid": "fn-001", "name": "fn_virustotal_ip_lookup", "display_name": "VirusTotal IP Lookup"},
                        {"uuid": "fn-002", "name": "fn_firewall_block_ip", "display_name": "Block IP on Firewall"}
                    ]
                }
            }
        ]
    }
