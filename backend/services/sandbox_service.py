# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Sandbox Service

Handles file submission to sandboxes (Hybrid Analysis, etc.) and result polling.
Integrates with the file attachment system to automatically sandbox files that
come back clean from threat intel lookups.
"""

import asyncio
import logging
import httpx
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class SandboxProvider(str, Enum):
    """Supported sandbox providers"""
    HYBRID_ANALYSIS = "hybrid_analysis"
    # Add more providers as needed:
    # CUCKOO = "cuckoo"
    # ANY_RUN = "any_run"
    # JOE_SANDBOX = "joe_sandbox"


class SandboxEnvironment(int, Enum):
    """Hybrid Analysis sandbox environments"""
    LINUX_UBUNTU_16_64 = 300
    WINDOWS_7_32 = 100
    WINDOWS_7_64 = 110
    WINDOWS_10_64 = 120
    ANDROID = 200


class AnalysisState(str, Enum):
    """Analysis job states"""
    PENDING = "pending"
    IN_QUEUE = "in_queue"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class SandboxSubmission:
    """Represents a sandbox submission"""
    job_id: str
    sha256: str
    provider: SandboxProvider
    environment: SandboxEnvironment
    submitted_at: datetime
    state: AnalysisState
    verdict: Optional[str] = None
    threat_score: Optional[int] = None
    report_url: Optional[str] = None
    error_message: Optional[str] = None
    completed_at: Optional[datetime] = None


class HybridAnalysisClient:
    """Client for Hybrid Analysis API"""

    BASE_URL = "https://www.hybrid-analysis.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "api-key": api_key,
            "User-Agent": "T1 Agentics-SOC/1.0",
            "accept": "application/json"
        }

    async def submit_file(
        self,
        file_data: bytes,
        filename: str,
        environment: SandboxEnvironment = SandboxEnvironment.WINDOWS_10_64,
        comment: str = None
    ) -> Dict[str, Any]:
        """Submit a file for analysis"""
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
            files = {
                "file": (filename, file_data, "application/octet-stream")
            }
            data = {
                "environment_id": environment.value,
                "no_share_third_party": "false",
                "allow_community_access": "true"
            }
            if comment:
                data["comment"] = comment

            response = await client.post(
                f"{self.BASE_URL}/submit/file",
                headers=self.headers,
                files=files,
                data=data
            )

            if response.status_code == 201:
                return response.json()
            elif response.status_code == 429:
                raise Exception("Rate limit exceeded - try again later")
            else:
                raise Exception(f"Submission failed: {response.status_code} - {response.text}")

    async def get_report_by_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get analysis report by file hash (SHA256, SHA1, or MD5)"""
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(
                f"{self.BASE_URL}/search/hash",
                headers=self.headers,
                params={"hash": file_hash}
            )

            if response.status_code == 200:
                data = response.json()
                # HA returns: {"sha256s": [...], "reports": [...]}
                if isinstance(data, dict):
                    reports = data.get('reports', [])
                    if reports:
                        # Find first successful report
                        for report in reports:
                            if report.get('state') == 'SUCCESS' or report.get('verdict'):
                                return report
                        # If no successful, return first
                        return reports[0]
                # Legacy format - array of results
                elif isinstance(data, list) and len(data) > 0:
                    return data[0]
                return None
            elif response.status_code == 404:
                return None
            else:
                raise Exception(f"Hash lookup failed: {response.status_code} - {response.text}")

    async def get_job_state(self, job_id: str) -> Dict[str, Any]:
        """Check the state of an analysis job"""
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(
                f"{self.BASE_URL}/report/{job_id}/state",
                headers=self.headers
            )

            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"Job state check failed: {response.status_code} - {response.text}")

    async def get_summary(self, job_id: str) -> Dict[str, Any]:
        """Get analysis summary"""
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.get(
                f"{self.BASE_URL}/report/{job_id}/summary",
                headers=self.headers
            )

            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"Summary fetch failed: {response.status_code} - {response.text}")

    async def quick_scan(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Quick scan - check if file was previously analyzed"""
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.post(
                f"{self.BASE_URL}/quick-scan/file",
                headers=self.headers,
                data={
                    "hash": file_hash,
                    "scan_type": "lookup"
                }
            )

            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                raise Exception(f"Quick scan failed: {response.status_code} - {response.text}")


class SandboxService:
    """
    Sandbox orchestration service.

    Handles:
    - Checking if file was previously analyzed
    - Submitting new files for analysis
    - Polling for results
    - Storing sandbox results in database
    """

    def __init__(self):
        self.db = None
        self._clients: Dict[SandboxProvider, Any] = {}

    def set_db(self, db):
        """Set database instance"""
        self.db = db

    async def get_client(self, provider: SandboxProvider) -> Optional[Any]:
        """Get or create a client for the sandbox provider"""
        if provider in self._clients:
            return self._clients[provider]

        # Get credentials from database
        if not self.db or not self.db.pool:
            logger.warning("SandboxService: No database connection")
            return None

        try:
            async with self.db.tenant_acquire() as conn:
                # Look for credential linked to the sandbox integration
                row = await conn.fetchrow('''
                    SELECT c.encrypted_secrets
                    FROM credentials_vault c
                    JOIN integration_state i ON c.credential_id = i.credential_id
                    WHERE i.integration_id = $1 AND i.enabled = true
                ''', provider.value)

                logger.info(f"[SANDBOX] Looking for {provider.value} credential via integration_state: {'found' if row else 'not found'}")

                if not row:
                    # Try by name pattern
                    row = await conn.fetchrow('''
                        SELECT encrypted_secrets
                        FROM credentials_vault
                        WHERE auth_type = 'api_key'
                        AND (name ILIKE $1 OR name ILIKE $2)
                        ORDER BY created_at DESC
                        LIMIT 1
                    ''', f'%{provider.value}%', '%hybrid%')
                    logger.info(f"[SANDBOX] Looking by name pattern: {'found' if row else 'not found'}")

                if row and row['encrypted_secrets']:
                    import json
                    from services.credentials_service import get_credentials_service

                    creds_service = get_credentials_service()
                    # Parse the secrets
                    secrets = row['encrypted_secrets']

                    if isinstance(secrets, str):
                        secrets = json.loads(secrets)

                    logger.info(f"[SANDBOX] Secrets keys: {list(secrets.keys()) if isinstance(secrets, dict) else 'not a dict'}")

                    # Try to decrypt each field, fall back to plain text
                    creds = {}
                    for key, val in secrets.items():
                        logger.info(f"[SANDBOX] Processing key={key}, val type={type(val)}, val preview={str(val)[:30]}")
                        try:
                            # Try decryption first (only if it looks encrypted)
                            if val and isinstance(val, str) and val.startswith('gAAAAA'):
                                decrypted = creds_service.vault.decrypt(val)
                                creds[key] = decrypted
                                logger.info(f"[SANDBOX] Decrypted {key}")
                            else:
                                # Use plain text value
                                creds[key] = val
                                logger.info(f"[SANDBOX] Using plain text for {key}")
                        except Exception as e:
                            # Fall back to plain text if decryption fails
                            logger.warning(f"[SANDBOX] Decrypt failed for {key}: {e}")
                            creds[key] = val

                    logger.info(f"[SANDBOX] Creds keys after processing: {list(creds.keys())}")

                    if provider == SandboxProvider.HYBRID_ANALYSIS:
                        api_key = creds.get('api_key') or creds.get('key') or creds.get('api-key')
                        logger.info(f"[SANDBOX] api_key value type: {type(api_key)}, truthy: {bool(api_key)}")
                        if api_key:
                            logger.info(f"[SANDBOX] Creating Hybrid Analysis client with key length: {len(api_key)}")
                            self._clients[provider] = HybridAnalysisClient(api_key)
                            return self._clients[provider]
                        else:
                            logger.warning(f"[SANDBOX] api_key values: api_key={creds.get('api_key')!r}, key={creds.get('key')!r}")

        except Exception as e:
            logger.error(f"Failed to get sandbox client: {e}")

        return None

    async def check_existing_analysis(
        self,
        sha256_hash: str,
        provider: SandboxProvider = SandboxProvider.HYBRID_ANALYSIS
    ) -> Optional[Dict[str, Any]]:
        """
        Check if a file has already been analyzed in the sandbox.
        Returns existing report if found, None otherwise.
        """
        client = await self.get_client(provider)
        if not client:
            logger.warning(f"No client available for {provider.value}")
            return None

        try:
            if provider == SandboxProvider.HYBRID_ANALYSIS:
                report = await client.get_report_by_hash(sha256_hash)
                if report:
                    return {
                        "found": True,
                        "provider": provider.value,
                        "job_id": report.get("job_id"),
                        "sha256": report.get("sha256"),
                        "verdict": report.get("verdict"),
                        "threat_score": report.get("threat_score"),
                        "threat_level": report.get("threat_level"),
                        "analysis_start_time": report.get("analysis_start_time"),
                        "environment": report.get("environment_description"),
                        "type": report.get("type"),
                        "file_name": report.get("submit_name"),
                        "report_url": f"https://www.hybrid-analysis.com/sample/{sha256_hash}"
                    }
            return None

        except Exception as e:
            logger.error(f"Error checking existing analysis: {e}")
            return None

    async def submit_file(
        self,
        file_data: bytes,
        filename: str,
        sha256_hash: str,
        alert_id: str = None,
        attachment_id: str = None,
        provider: SandboxProvider = SandboxProvider.HYBRID_ANALYSIS,
        environment: SandboxEnvironment = SandboxEnvironment.WINDOWS_10_64
    ) -> Optional[Dict[str, Any]]:
        """
        Submit a file for sandbox analysis.

        Returns submission result with job_id for tracking.
        """
        client = await self.get_client(provider)
        if not client:
            logger.warning(f"No client available for {provider.value}")
            return {"error": f"Sandbox {provider.value} not configured"}

        try:
            # First check if already analyzed
            existing = await self.check_existing_analysis(sha256_hash, provider)
            if existing and existing.get("found"):
                logger.info(f"File {sha256_hash[:16]}... already analyzed in {provider.value}")
                return {
                    "status": "already_analyzed",
                    **existing
                }

            # Submit for analysis
            comment = f"Submitted by T1 Agentics SOC"
            if alert_id:
                comment += f" - Alert: {alert_id}"

            result = await client.submit_file(
                file_data=file_data,
                filename=filename,
                environment=environment,
                comment=comment
            )

            job_id = result.get("job_id") or result.get("id")
            sha256 = result.get("sha256") or sha256_hash

            # Store submission in database
            if self.db and self.db.pool and attachment_id:
                try:
                    async with self.db.tenant_acquire() as conn:
                        await conn.execute('''
                            UPDATE alert_attachments
                            SET sandbox_status = 'submitted',
                                sandbox_job_id = $2,
                                sandbox_provider = $3,
                                sandbox_submitted_at = CURRENT_TIMESTAMP
                            WHERE attachment_id = $1
                        ''', attachment_id, job_id, provider.value)
                except Exception as e:
                    logger.warning(f"Failed to update sandbox status in DB: {e}")

            logger.info(f"Submitted {filename} ({sha256_hash[:16]}...) to {provider.value} - Job ID: {job_id}")

            return {
                "status": "submitted",
                "provider": provider.value,
                "job_id": job_id,
                "sha256": sha256,
                "environment": environment.name,
                "message": "File submitted for sandbox analysis. Results typically available in 5-15 minutes."
            }

        except Exception as e:
            logger.error(f"Sandbox submission failed: {e}")
            return {"error": str(e)}

    async def poll_result(
        self,
        job_id: str,
        provider: SandboxProvider = SandboxProvider.HYBRID_ANALYSIS,
        max_wait_seconds: int = 600,
        poll_interval_seconds: int = 30
    ) -> Dict[str, Any]:
        """
        Poll for analysis results with timeout.

        Args:
            job_id: The sandbox job ID
            provider: Sandbox provider
            max_wait_seconds: Maximum time to wait (default 10 minutes)
            poll_interval_seconds: Time between polls (default 30 seconds)

        Returns:
            Analysis result or timeout error
        """
        client = await self.get_client(provider)
        if not client:
            return {"error": f"Sandbox {provider.value} not configured"}

        start_time = datetime.utcnow()
        elapsed = 0

        while elapsed < max_wait_seconds:
            try:
                state = await client.get_job_state(job_id)
                status = state.get("state", "").lower()

                if status in ["success", "done", "completed"]:
                    # Get full summary
                    summary = await client.get_summary(job_id)
                    return {
                        "status": "completed",
                        "provider": provider.value,
                        "job_id": job_id,
                        "verdict": summary.get("verdict"),
                        "threat_score": summary.get("threat_score"),
                        "threat_level": summary.get("threat_level"),
                        "av_detect": summary.get("av_detect"),
                        "vx_family": summary.get("vx_family"),
                        "total_network_connections": summary.get("total_network_connections"),
                        "total_processes": summary.get("total_processes"),
                        "total_signatures": summary.get("total_signatures"),
                        "mitre_attcks": summary.get("mitre_attcks"),
                        "analysis_time": summary.get("analysis_time"),
                        "report_url": f"https://www.hybrid-analysis.com/sample/{summary.get('sha256', job_id)}"
                    }

                elif status in ["error", "failed"]:
                    return {
                        "status": "error",
                        "provider": provider.value,
                        "job_id": job_id,
                        "error": state.get("error_message", "Analysis failed")
                    }

                # Still in progress
                logger.debug(f"Job {job_id} status: {status}, waiting...")
                await asyncio.sleep(poll_interval_seconds)
                elapsed = (datetime.utcnow() - start_time).total_seconds()

            except Exception as e:
                logger.error(f"Error polling job {job_id}: {e}")
                return {"error": str(e)}

        return {
            "status": "timeout",
            "provider": provider.value,
            "job_id": job_id,
            "message": f"Analysis did not complete within {max_wait_seconds} seconds. Check back later."
        }

    async def get_result(
        self,
        job_id: str,
        provider: SandboxProvider = SandboxProvider.HYBRID_ANALYSIS
    ) -> Dict[str, Any]:
        """Get analysis result for a job (non-blocking)"""
        client = await self.get_client(provider)
        if not client:
            return {"error": f"Sandbox {provider.value} not configured"}

        try:
            state = await client.get_job_state(job_id)
            status = state.get("state", "").lower()

            if status in ["success", "done", "completed"]:
                summary = await client.get_summary(job_id)
                return {
                    "status": "completed",
                    "provider": provider.value,
                    "job_id": job_id,
                    "verdict": summary.get("verdict"),
                    "threat_score": summary.get("threat_score"),
                    "threat_level": summary.get("threat_level"),
                    "av_detect": summary.get("av_detect"),
                    "vx_family": summary.get("vx_family"),
                    "analysis_time": summary.get("analysis_time"),
                    "report_url": f"https://www.hybrid-analysis.com/sample/{summary.get('sha256', job_id)}"
                }
            elif status in ["error", "failed"]:
                return {
                    "status": "error",
                    "provider": provider.value,
                    "job_id": job_id,
                    "error": state.get("error_message", "Analysis failed")
                }
            else:
                return {
                    "status": "in_progress",
                    "provider": provider.value,
                    "job_id": job_id,
                    "state": status
                }

        except Exception as e:
            logger.error(f"Error getting result for job {job_id}: {e}")
            return {"error": str(e)}


# Singleton instance
_sandbox_service: Optional[SandboxService] = None


def get_sandbox_service() -> SandboxService:
    """Get the sandbox service singleton"""
    global _sandbox_service
    if _sandbox_service is None:
        _sandbox_service = SandboxService()
    return _sandbox_service
