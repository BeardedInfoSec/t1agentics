# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Report Generation API Routes
Endpoints for generating investigation reports in Markdown and PDF format.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from typing import Optional

from dependencies.auth import get_current_user
from services.report_generator_service import ReportGeneratorService, VALID_TEMPLATES, VALID_FORMATS

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/investigations", tags=["Reports"])

report_service = ReportGeneratorService()


class ReportRequest(BaseModel):
    """Request body for report generation."""
    template: str = "executive_summary"
    format: str = "markdown"


@router.post("/{investigation_id}/report")
async def generate_report(
    investigation_id: str,
    body: ReportRequest,
    user=Depends(get_current_user),
):
    """
    Generate an investigation report.

    Args:
        investigation_id: UUID of the investigation
        body.template: One of 'executive_summary', 'detailed_technical', 'incident_response'
        body.format: 'markdown' or 'pdf'

    Returns:
        JSON with markdown content, or PDF file download
    """
    if body.template not in VALID_TEMPLATES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid template. Choose from: {VALID_TEMPLATES}",
        )

    if body.format not in VALID_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format. Choose from: {VALID_FORMATS}",
        )

    try:
        from services.postgres_db import postgres_db

        result = await report_service.generate_report(
            investigation_id=investigation_id,
            tenant_id=user['tenant_id'],
            template_name=body.template,
            format=body.format,
            db_pool=postgres_db,
        )

        if body.format == 'pdf':
            safe_id = investigation_id.replace('/', '_').replace('\\', '_')
            return Response(
                content=result,
                media_type='application/pdf',
                headers={
                    'Content-Disposition': f'attachment; filename="{safe_id}_{body.template}_report.pdf"'
                },
            )

        return {
            "report": result,
            "format": "markdown",
            "template": body.template,
            "investigation_id": investigation_id,
        }

    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Report generation failed for investigation {investigation_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Report generation failed. Please try again.",
        )
