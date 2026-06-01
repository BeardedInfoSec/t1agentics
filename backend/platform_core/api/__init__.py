# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Platform API Routes

All API routers for the enterprise SOC platform.
"""

from fastapi import APIRouter

from .evidence_routes import router as evidence_router
from .retention_routes import router as retention_router
from .audit_routes import router as audit_router

# Main platform router
platform_router = APIRouter(prefix="/api/v1")

# Include all sub-routers
platform_router.include_router(evidence_router)
platform_router.include_router(retention_router)
platform_router.include_router(audit_router)

__all__ = [
    'platform_router',
    'evidence_router',
    'retention_router',
    'audit_router',
]
