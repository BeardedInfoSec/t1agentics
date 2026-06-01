# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
File Upload Endpoints for Threat Feeds

Add these to threat_feeds.py or import from here.
"""

import io
import json
import logging
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends
from pydantic import BaseModel, Field

from services.threat_feed_service import (
    get_threat_feed_service,
    ThreatFeedConfig,
    FeedFormat,
    FeedCategory,
)
from services.threat_intel_service import IOCType, ThreatSeverity
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-feeds", tags=["Threat Feed Upload"], dependencies=[Depends(get_current_user)])


class FileUploadResult(BaseModel):
    """Result of file upload IOC ingestion"""
    success: bool
    filename: str
    format: str
    iocs_found: int
    iocs_ingested: int
    iocs_new: int
    iocs_updated: int
    iocs_skipped: int
    error: Optional[str] = None
    sample_iocs: List[str] = Field(default_factory=list)


@router.post("/upload", response_model=FileUploadResult)
async def upload_ioc_file(
    file: UploadFile = File(..., description="IOC file to upload"),
    format: str = Form(default="txt_lines", description="File format: txt_lines, csv, json, json_lines, stix"),
    category: str = Form(default="mixed", description="IOC category: ip_blocklist, domain_blocklist, url_blocklist, hash_list, mixed"),
    ioc_type: Optional[str] = Form(default=None, description="Force IOC type: ip, domain, url, hash_sha256, hash_sha1, hash_md5"),
    source_name: str = Form(default="Manual Upload", description="Source name for tracking"),
    severity: str = Form(default="medium", description="Default severity: critical, high, medium, low"),
    tags: str = Form(default="", description="Comma-separated tags to apply"),
    parser_config: str = Form(default="{}", description="JSON parser configuration"),
    drop_private_ips: bool = Form(default=True, description="Filter out private/internal IPs"),
    drop_internal_domains: bool = Form(default=True, description="Filter out internal domains")
):
    """
    Upload a file containing IOCs (Indicators of Compromise).

    Supported formats:
    - txt_lines: One IOC per line (supports comments with #)
    - csv: Comma-separated values (configure columns with parser_config)
    - json: JSON array of IOCs or objects
    - json_lines: One JSON object per line
    - stix: STIX 2.x format

    The system will:
    1. Parse the file based on format
    2. Auto-detect IOC types if not specified
    3. Add new IOCs to the database
    4. Update existing IOCs with new source info
    5. Mark IOCs as from manual upload
    """
    service = get_threat_feed_service()

    try:
        # Read file content
        content = await file.read()
        try:
            content_str = content.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content_str = content.decode('latin-1')
            except:
                raise HTTPException(status_code=400, detail="Unable to decode file. Please use UTF-8 encoding.")

        # Parse parser_config JSON
        try:
            parser_cfg = json.loads(parser_config) if parser_config else {}
        except json.JSONDecodeError:
            parser_cfg = {}

        # Map string values to enums
        try:
            format_enum = FeedFormat(format)
        except ValueError:
            format_enum = FeedFormat.TXT_LINES

        try:
            category_enum = FeedCategory(category)
        except ValueError:
            category_enum = FeedCategory.MIXED

        try:
            severity_enum = ThreatSeverity(severity)
        except ValueError:
            severity_enum = ThreatSeverity.MEDIUM

        ioc_type_enum = None
        if ioc_type:
            try:
                ioc_type_enum = IOCType(ioc_type)
            except ValueError:
                pass

        # Parse tags
        tag_list = [t.strip() for t in tags.split(',') if t.strip()] if tags else []
        tag_list.append("manual_upload")  # Always mark as manual upload

        # Create a temporary feed config for parsing
        upload_feed = ThreatFeedConfig(
            feed_id=f"upload_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            name=source_name,
            url="file://upload",
            format=format_enum,
            category=category_enum,
            description=f"Manual upload: {file.filename}",
            enabled=True,
            ioc_type=ioc_type_enum,
            default_severity=severity_enum,
            parser_config=parser_cfg,
            drop_private_ips=drop_private_ips,
            drop_internal_domains=drop_internal_domains
        )

        # Parse the file content using the service's parsing logic
        iocs = await service._parse_feed(upload_feed, content_str)

        if not iocs:
            return FileUploadResult(
                success=False,
                filename=file.filename or "unknown",
                format=format,
                iocs_found=0,
                iocs_ingested=0,
                iocs_new=0,
                iocs_updated=0,
                iocs_skipped=0,
                error="No IOCs found in file. Check format and content."
            )

        # Ingest the IOCs
        result = await service._ingest_iocs(upload_feed, iocs)

        # Add custom tags to all uploaded IOCs
        if tag_list:
            from services.threat_intel_service import get_threat_intel_service
            threat_intel = get_threat_intel_service()
            for value, ioc_type_val in iocs[:100]:  # Limit to first 100 for performance
                try:
                    await threat_intel.add_tags_to_ioc(value, tag_list)
                except:
                    pass  # Ignore tag failures

        # Get sample IOCs for preview
        sample = [ioc[0] for ioc in iocs[:10]]

        logger.info(f"File upload complete: {file.filename}, {len(iocs)} IOCs found, {result.iocs_new} new, {result.iocs_updated} updated")

        return FileUploadResult(
            success=True,
            filename=file.filename or "unknown",
            format=format,
            iocs_found=len(iocs),
            iocs_ingested=result.iocs_new + result.iocs_updated,
            iocs_new=result.iocs_new,
            iocs_updated=result.iocs_updated,
            iocs_skipped=result.iocs_skipped,
            sample_iocs=sample
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"File upload error: {e}")
        return FileUploadResult(
            success=False,
            filename=file.filename or "unknown",
            format=format,
            iocs_found=0,
            iocs_ingested=0,
            iocs_new=0,
            iocs_updated=0,
            iocs_skipped=0,
            error=str(e)
        )


@router.post("/upload/preview")
async def preview_ioc_file(
    file: UploadFile = File(..., description="IOC file to preview"),
    format: str = Form(default="txt_lines", description="File format"),
    ioc_type: Optional[str] = Form(default=None, description="Force IOC type"),
    parser_config: str = Form(default="{}", description="JSON parser configuration"),
    max_preview: int = Form(default=50, ge=1, le=500, description="Max IOCs to preview")
):
    """
    Preview IOCs from a file without ingesting them.

    Useful for validating file format and parser configuration before full import.
    Returns detected IOCs and their types.
    """
    service = get_threat_feed_service()

    try:
        # Read file content
        content = await file.read()
        try:
            content_str = content.decode('utf-8')
        except UnicodeDecodeError:
            content_str = content.decode('latin-1')

        # Parse parser_config
        try:
            parser_cfg = json.loads(parser_config) if parser_config else {}
        except json.JSONDecodeError:
            parser_cfg = {}

        # Map format
        try:
            format_enum = FeedFormat(format)
        except ValueError:
            format_enum = FeedFormat.TXT_LINES

        ioc_type_enum = None
        if ioc_type:
            try:
                ioc_type_enum = IOCType(ioc_type)
            except ValueError:
                pass

        # Create temp config for parsing
        preview_feed = ThreatFeedConfig(
            feed_id="preview_temp",
            name="Preview",
            url="file://preview",
            format=format_enum,
            category=FeedCategory.MIXED,
            description="Preview",
            enabled=True,
            ioc_type=ioc_type_enum,
            parser_config=parser_cfg
        )

        # Parse
        iocs = await service._parse_feed(preview_feed, content_str)

        # Group by type
        by_type = {}
        for value, ioc_t in iocs[:max_preview]:
            type_name = ioc_t.value if hasattr(ioc_t, 'value') else str(ioc_t)
            if type_name not in by_type:
                by_type[type_name] = []
            by_type[type_name].append(value)

        return {
            "filename": file.filename,
            "format": format,
            "total_iocs_found": len(iocs),
            "previewed": min(len(iocs), max_preview),
            "by_type": by_type,
            "sample": [{"value": v, "type": t.value if hasattr(t, 'value') else str(t)} for v, t in iocs[:max_preview]]
        }

    except Exception as e:
        logger.error(f"Preview error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
