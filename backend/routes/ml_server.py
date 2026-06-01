# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
ML Server Update Distribution Routes
Serves manifest and files for remote ML server auto-updates.
"""

import os
import hashlib
import logging
from pathlib import Path
from typing import Dict, Any

from fastapi import APIRouter, HTTPException, Depends
from dependencies.auth import get_current_user
from fastapi.responses import FileResponse, JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ml-server", tags=["ML Server Updates"], dependencies=[Depends(get_current_user)])

# Path to ml-server directory (relative to backend)
ML_SERVER_DIR = Path(__file__).parent.parent.parent / "ml-server"

# Files to distribute
DISTRIBUTABLE_FILES = [
    "app.py",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml"
]


def compute_file_hash(filepath: Path) -> str:
    """Compute SHA256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256.update(chunk)
    return sha256.hexdigest()


@router.get("/manifest")
async def get_manifest() -> Dict[str, Any]:
    """
    Get the current manifest of ML server files.
    Remote servers poll this to check for updates.
    """
    files = {}
    version = None

    for filename in DISTRIBUTABLE_FILES:
        filepath = ML_SERVER_DIR / filename
        if filepath.exists():
            file_hash = compute_file_hash(filepath)
            files[filename] = file_hash

            # Use app.py hash as version indicator
            if filename == "app.py":
                version = file_hash[:8]

    return {
        "version": version,
        "files": files,
        "server": "t1agentics-backend",
        "ml_server_dir": str(ML_SERVER_DIR)
    }


@router.get("/files/{filename}")
async def get_file(filename: str):
    """
    Download a specific ML server file.
    Used by remote updater to pull updated files.
    """
    # Security: only allow specific files
    if filename not in DISTRIBUTABLE_FILES:
        raise HTTPException(
            status_code=403,
            detail=f"File not distributable: {filename}"
        )

    filepath = ML_SERVER_DIR / filename
    if not filepath.exists():
        raise HTTPException(
            status_code=404,
            detail=f"File not found: {filename}"
        )

    # Return file with appropriate content type
    content_type = "text/plain"
    if filename.endswith(".py"):
        content_type = "text/x-python"
    elif filename.endswith(".yml") or filename.endswith(".yaml"):
        content_type = "text/yaml"
    elif filename.endswith(".txt"):
        content_type = "text/plain"

    return FileResponse(
        path=filepath,
        filename=filename,
        media_type=content_type
    )


@router.get("/status")
async def get_ml_server_status():
    """
    Check status of remote ML server.
    Proxies health check to the ML server.
    """
    from services.ml_client import get_ml_client

    client = get_ml_client()
    health = await client.health_check()

    return {
        "remote_server": f"{client.host}:{client.port}",
        "enabled": client.enabled,
        "health": health,
        "client_stats": client.get_stats()
    }


@router.post("/trigger-update")
async def trigger_remote_update():
    """
    Trigger an immediate update check on the remote ML server.
    Useful after making changes locally.
    """
    import httpx

    from services.ml_client import get_ml_client
    client = get_ml_client()

    try:
        async with httpx.AsyncClient(timeout=5.0) as http:
            # Ping the updater service if running
            response = await http.post(
                f"http://{client.host}:8101/check-now"
            )
            if response.status_code == 200:
                return {"status": "update_triggered", "response": response.json()}
    except Exception as e:
        logger.warning(f"Could not trigger remote update: {e}")

    return {
        "status": "manual_required",
        "message": "Remote updater not responding. SSH and run: python3 updater.py",
        "manifest": await get_manifest()
    }
