# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
IOC Management Routes

Handles:
- Whitelist/Do-Not-Enrich management (CRUD, bulk, CSV upload)
- User IOC submissions (manual, bulk, CSV upload)
"""

import csv
import io
import re
import logging
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form
from pydantic import BaseModel, Field

from services.postgres_db import postgres_db
from services.threat_intel_service import (
    get_threat_intel_service,
    IOCType,
    IOCSourceType,
    ThreatSeverity
)
# Import working auth from admin routes (uses database, not in-memory)
from routes.admin import get_current_username
from middleware.tenant_middleware import get_optional_tenant_id
from dependencies.auth import get_current_user
from services.ioc_enforcement import enforce_ioc_limit, check_ioc_quota

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/ioc-management", tags=["IOC Management"], dependencies=[Depends(get_current_user)])


# ============================================================================
# MODELS
# ============================================================================

class WhitelistEntry(BaseModel):
    """Single whitelist entry"""
    ioc_value: str
    ioc_type: Optional[str] = None  # Auto-detect if not provided
    reason: Optional[str] = None
    category: Optional[str] = "other"
    is_pattern: bool = False
    pattern_type: Optional[str] = "exact"
    notes: Optional[str] = None
    expires_at: Optional[datetime] = None


class BulkWhitelistRequest(BaseModel):
    """Bulk whitelist request (newline or comma separated)"""
    values: str  # Newline or comma separated IOC values
    ioc_type: Optional[str] = None  # Auto-detect if not provided
    reason: Optional[str] = None
    category: Optional[str] = "other"


class IOCSubmission(BaseModel):
    """Single IOC submission"""
    value: str
    ioc_type: Optional[str] = None  # Auto-detect if not provided
    severity: Optional[str] = "medium"
    tags: Optional[List[str]] = None
    notes: Optional[str] = None
    enrich: bool = True  # Whether to enrich after submission


class BulkIOCSubmission(BaseModel):
    """Bulk IOC submission"""
    values: str  # Newline or comma separated IOC values
    ioc_type: Optional[str] = None
    severity: Optional[str] = "medium"
    tags: Optional[List[str]] = None
    notes: Optional[str] = None  # Reason for blocking
    enrich: bool = False  # Bulk default to no-enrich to avoid API exhaustion


# ============================================================================
# HELPERS
# ============================================================================

# IOC detection patterns
IOC_PATTERNS = {
    'ip': re.compile(r'^(\d{1,3}\.){3}\d{1,3}$'),
    'domain': re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$'),
    'url': re.compile(r'^https?://'),
    'hash_sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
    'hash_sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
    'hash_md5': re.compile(r'^[a-fA-F0-9]{32}$'),
    'cve': re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE),
    'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
}


def detect_ioc_type(value: str) -> Optional[str]:
    """Auto-detect IOC type from value"""
    value = value.strip()

    if IOC_PATTERNS['cve'].match(value):
        return 'cve'
    if IOC_PATTERNS['url'].match(value):
        return 'url'
    if IOC_PATTERNS['hash_sha256'].match(value):
        return 'hash_sha256'
    if IOC_PATTERNS['hash_sha1'].match(value):
        return 'hash_sha1'
    if IOC_PATTERNS['hash_md5'].match(value):
        return 'hash_md5'
    if IOC_PATTERNS['email'].match(value):
        return 'email'
    if IOC_PATTERNS['ip'].match(value):
        return 'ip'
    if IOC_PATTERNS['domain'].match(value):
        return 'domain'

    return None


def parse_ioc_values(raw_values: str) -> List[str]:
    """Parse raw values string into list of IOCs (handles newlines, commas, spaces)"""
    # Split by newlines first, then by commas
    values = []
    for line in raw_values.strip().split('\n'):
        for part in line.split(','):
            cleaned = part.strip()
            if cleaned and not cleaned.startswith('#'):  # Skip comments
                values.append(cleaned)
    return list(set(values))  # Dedupe


# ============================================================================
# WHITELIST ROUTES
# ============================================================================

@router.get("/whitelist")
async def list_whitelist(
    page: int = 1,
    limit: int = 50,
    search: Optional[str] = None,
    category: Optional[str] = None,
    ioc_type: Optional[str] = None,
    current_user: str = Depends(get_current_username)
):
    """List all whitelist entries with pagination and filtering"""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    offset = (page - 1) * limit

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Build query
            where_clauses = ["(expires_at IS NULL OR expires_at > NOW())"]
            params = []
            param_idx = 1

            if search:
                where_clauses.append(f"ioc_value ILIKE ${param_idx}")
                params.append(f"%{search}%")
                param_idx += 1

            if category:
                where_clauses.append(f"category = ${param_idx}")
                params.append(category)
                param_idx += 1

            if ioc_type:
                where_clauses.append(f"ioc_type = ${param_idx}")
                params.append(ioc_type)
                param_idx += 1

            where_clause = " AND ".join(where_clauses)

            # Get total count
            count = await conn.fetchval(
                f"SELECT COUNT(*) FROM ioc_whitelist WHERE {where_clause}",
                *params
            )

            # Get entries
            params.extend([limit, offset])
            rows = await conn.fetch(
                f"""
                SELECT * FROM ioc_whitelist
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
                """,
                *params
            )

            entries = [dict(row) for row in rows]

            return {
                "entries": entries,
                "total": count,
                "page": page,
                "limit": limit,
                "pages": (count + limit - 1) // limit
            }

    except Exception as e:
        logger.error(f"Failed to list whitelist: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def check_blocklist_conflict(conn, ioc_value: str, ioc_type: str) -> Optional[dict]:
    """Check if IOC exists in blocklist (malicious/suspicious IOCs, threat feeds, or manual submissions)"""
    row = await conn.fetchrow(
        """
        SELECT ioc_value, ioc_type, severity, reputation, source, source_type, feed_name
        FROM iocs
        WHERE ioc_value = $1
          AND (ioc_type = $2 OR $2 IS NULL)
          AND (
              reputation IN ('malicious', 'suspicious')
              OR source_type = 'threat_feed'
              OR source_type = 'manual'
              OR severity IN ('high', 'critical')
          )
        """,
        ioc_value,
        ioc_type
    )
    if row:
        return dict(row)
    return None


async def check_whitelist_conflict(conn, ioc_value: str, ioc_type: str) -> Optional[dict]:
    """Check if IOC exists in whitelist"""
    row = await conn.fetchrow(
        """
        SELECT * FROM ioc_whitelist
        WHERE ioc_value = $1
          AND (ioc_type = $2 OR $2 IS NULL)
          AND (expires_at IS NULL OR expires_at > NOW())
        """,
        ioc_value,
        ioc_type
    )
    if row:
        return dict(row)
    return None


@router.post("/whitelist")
async def add_to_whitelist(
    entry: WhitelistEntry,
    force: bool = False,  # Force add even if on blocklist
    current_user: str = Depends(get_current_username)
):
    """Add a single entry to the whitelist"""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    # Auto-detect type if not provided
    ioc_type = entry.ioc_type or detect_ioc_type(entry.ioc_value)
    if not ioc_type:
        raise HTTPException(status_code=400, detail=f"Could not detect IOC type for: {entry.ioc_value}")

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Check for blocklist conflict
            blocklist_entry = await check_blocklist_conflict(conn, entry.ioc_value, ioc_type)
            if blocklist_entry and not force:
                return {
                    "success": False,
                    "conflict": "blocklist",
                    "message": f"This IOC is currently on the blocklist as {blocklist_entry.get('reputation', 'suspicious')}",
                    "blocklist_entry": blocklist_entry,
                    "action_required": "Set force=true to whitelist anyway, or remove from blocklist first"
                }

            # If force=true and there was a blocklist conflict, remove from blocklist first
            if blocklist_entry and force:
                await conn.execute(
                    """
                    DELETE FROM iocs
                    WHERE ioc_value = $1
                      AND (ioc_type = $2 OR $2 IS NULL)
                    """,
                    entry.ioc_value,
                    ioc_type
                )
                logger.info(f"Removed {entry.ioc_value} from blocklist (force whitelist by {current_user})")

            row = await conn.fetchrow(
                """
                INSERT INTO ioc_whitelist (
                    ioc_value, ioc_type, reason, category, is_pattern, pattern_type,
                    notes, expires_at, added_by, tenant_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (ioc_value, ioc_type) DO UPDATE SET
                    reason = COALESCE($3, ioc_whitelist.reason),
                    category = COALESCE($4, ioc_whitelist.category),
                    notes = COALESCE($7, ioc_whitelist.notes),
                    updated_at = NOW()
                RETURNING *
                """,
                entry.ioc_value,
                ioc_type,
                entry.reason,
                entry.category,
                entry.is_pattern,
                entry.pattern_type,
                entry.notes,
                entry.expires_at,
                current_user,
                get_optional_tenant_id()
            )

            result = {"success": True, "entry": dict(row)}

            # Add warning if there was a blocklist conflict that was forced (and removed)
            if blocklist_entry:
                result["warning"] = f"IOC was removed from blocklist (was {blocklist_entry.get('reputation', 'blocked')}) and added to whitelist"
                result["removed_from_blocklist"] = blocklist_entry

            return result

    except Exception as e:
        logger.error(f"Failed to add to whitelist: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/whitelist/bulk")
async def bulk_add_to_whitelist(
    request: BulkWhitelistRequest,
    current_user: str = Depends(get_current_username)
):
    """Add multiple entries to the whitelist (newline or comma separated)"""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    values = parse_ioc_values(request.values)
    if not values:
        raise HTTPException(status_code=400, detail="No valid IOC values provided")

    added = 0
    skipped = 0
    errors = []

    try:
        async with postgres_db.tenant_acquire() as conn:
            for value in values:
                try:
                    ioc_type = request.ioc_type or detect_ioc_type(value)
                    if not ioc_type:
                        errors.append(f"Could not detect type: {value}")
                        skipped += 1
                        continue

                    await conn.execute(
                        """
                        INSERT INTO ioc_whitelist (ioc_value, ioc_type, reason, category, added_by, tenant_id)
                        VALUES ($1, $2, $3, $4, $5, $6)
                        ON CONFLICT (ioc_value, ioc_type) DO NOTHING
                        """,
                        value,
                        ioc_type,
                        request.reason,
                        request.category,
                        current_user,
                        get_optional_tenant_id()
                    )
                    added += 1

                except Exception as e:
                    errors.append(f"{value}: {str(e)}")
                    skipped += 1

            return {
                "success": True,
                "added": added,
                "skipped": skipped,
                "total": len(values),
                "errors": errors[:10]  # Limit errors shown
            }

    except Exception as e:
        logger.error(f"Bulk whitelist failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/whitelist/upload")
async def upload_whitelist_csv(
    file: UploadFile = File(...),
    category: str = Form("other"),
    reason: Optional[str] = Form(None),
    current_user: str = Depends(get_current_username)
):
    """Upload CSV file to add to whitelist"""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")

    try:
        content = await file.read()
        decoded = content.decode('utf-8')

        # Try to detect if it has headers
        reader = csv.reader(io.StringIO(decoded))
        rows = list(reader)

        if not rows:
            raise HTTPException(status_code=400, detail="CSV file is empty")

        # Check if first row looks like a header and build column mapping
        first_row = rows[0]
        header_keywords = ['ioc', 'value', 'indicator', 'ioc_value', 'type', 'ioc_type', 'confidence', 'source', 'notes', 'reason']
        has_header = any(h.lower().strip() in header_keywords for h in first_row)

        # Column mapping for flexible CSV parsing
        col_map = {'value': 0, 'type': 1, 'reason': 2}

        if has_header:
            header_lower = [h.lower().strip() for h in first_row]
            # Find value column
            for name in ['indicator', 'ioc', 'value', 'ioc_value']:
                if name in header_lower:
                    col_map['value'] = header_lower.index(name)
                    break
            # Find type column
            for name in ['indicator_type', 'ioc_type', 'type']:
                if name in header_lower:
                    col_map['type'] = header_lower.index(name)
                    break
            # Find reason/notes column (prefer notes, then source, then reason)
            for name in ['notes', 'reason', 'source']:
                if name in header_lower:
                    col_map['reason'] = header_lower.index(name)
                    break
            # Also look for source to combine with notes
            source_col = header_lower.index('source') if 'source' in header_lower else None
            col_map['source'] = source_col

            rows = rows[1:]

        added = 0
        skipped = 0
        errors = []

        async with postgres_db.tenant_acquire() as conn:
            for row in rows:
                if not row:
                    continue

                # Use column mapping
                value = row[col_map['value']].strip() if len(row) > col_map['value'] else None
                row_type = row[col_map['type']].strip() if len(row) > col_map['type'] else None
                row_reason = row[col_map['reason']].strip() if len(row) > col_map['reason'] else reason

                # Combine source and notes if both present
                if has_header and col_map.get('source') is not None and col_map['source'] != col_map['reason']:
                    source_val = row[col_map['source']].strip() if len(row) > col_map['source'] else ''
                    if source_val and row_reason:
                        row_reason = f"{source_val}: {row_reason}"
                    elif source_val:
                        row_reason = source_val

                if not value:
                    continue

                try:
                    ioc_type = row_type or detect_ioc_type(value)
                    if not ioc_type:
                        errors.append(f"Could not detect type: {value}")
                        skipped += 1
                        continue

                    await conn.execute(
                        """
                        INSERT INTO ioc_whitelist (ioc_value, ioc_type, reason, category, added_by, tenant_id)
                        VALUES ($1, $2, $3, $4, $5, $6)
                        ON CONFLICT (ioc_value, ioc_type) DO NOTHING
                        """,
                        value,
                        ioc_type,
                        row_reason,
                        category,
                        current_user,
                        get_optional_tenant_id()
                    )
                    added += 1

                except Exception as e:
                    errors.append(f"{value}: {str(e)}")
                    skipped += 1

        return {
            "success": True,
            "filename": file.filename,
            "added": added,
            "skipped": skipped,
            "total": len(rows),
            "errors": errors[:10]
        }

    except Exception as e:
        logger.error(f"CSV upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/whitelist/{entry_id}")
async def remove_from_whitelist(
    entry_id: str,
    current_user: str = Depends(get_current_username)
):
    """Remove an entry from the whitelist"""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    try:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute(
                "DELETE FROM ioc_whitelist WHERE id = $1",
                entry_id
            )
            deleted = result.split()[-1]

            return {"success": True, "deleted": int(deleted) if deleted.isdigit() else 0}

    except Exception as e:
        logger.error(f"Failed to delete whitelist entry: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/whitelist/bulk")
async def bulk_remove_from_whitelist(
    entry_ids: List[str],
    current_user: str = Depends(get_current_username)
):
    """Remove multiple entries from the whitelist"""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    try:
        async with postgres_db.tenant_acquire() as conn:
            result = await conn.execute(
                "DELETE FROM ioc_whitelist WHERE id = ANY($1::uuid[])",
                entry_ids
            )
            deleted = result.split()[-1]

            return {"success": True, "deleted": int(deleted) if deleted.isdigit() else 0}

    except Exception as e:
        logger.error(f"Failed to bulk delete whitelist entries: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/whitelist/check/{ioc_value}")
async def check_whitelist(
    ioc_value: str,
    ioc_type: Optional[str] = None,
    current_user: str = Depends(get_current_username)
):
    """Check if an IOC is whitelisted"""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    detected_type = ioc_type or detect_ioc_type(ioc_value)

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Check exact match first
            row = await conn.fetchrow(
                """
                SELECT * FROM ioc_whitelist
                WHERE ioc_value = $1
                  AND (ioc_type = $2 OR $2 IS NULL)
                  AND (expires_at IS NULL OR expires_at > NOW())
                  AND is_pattern = FALSE
                """,
                ioc_value,
                detected_type
            )

            if row:
                return {
                    "whitelisted": True,
                    "match_type": "exact",
                    "entry": dict(row)
                }

            # Check pattern matches
            patterns = await conn.fetch(
                """
                SELECT * FROM ioc_whitelist
                WHERE is_pattern = TRUE
                  AND (ioc_type = $1 OR $1 IS NULL)
                  AND (expires_at IS NULL OR expires_at > NOW())
                """,
                detected_type
            )

            for pattern in patterns:
                if pattern['pattern_type'] == 'prefix':
                    if ioc_value.startswith(pattern['ioc_value']):
                        return {"whitelisted": True, "match_type": "prefix", "entry": dict(pattern)}
                elif pattern['pattern_type'] == 'suffix':
                    if ioc_value.endswith(pattern['ioc_value']):
                        return {"whitelisted": True, "match_type": "suffix", "entry": dict(pattern)}
                elif pattern['pattern_type'] == 'contains':
                    if pattern['ioc_value'] in ioc_value:
                        return {"whitelisted": True, "match_type": "contains", "entry": dict(pattern)}
                elif pattern['pattern_type'] == 'regex':
                    try:
                        if re.match(pattern['ioc_value'], ioc_value):
                            return {"whitelisted": True, "match_type": "regex", "entry": dict(pattern)}
                    except:
                        pass

            return {"whitelisted": False}

    except Exception as e:
        logger.error(f"Whitelist check failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# IOC SUBMISSION ROUTES
# ============================================================================

@router.post("/submit")
async def submit_ioc(
    submission: IOCSubmission,
    force: bool = False,  # Force submit even if whitelisted
    current_user: str = Depends(get_current_username)
):
    """Submit a single IOC for tracking (adds to blocklist/IOC database)"""
    threat_intel = get_threat_intel_service()

    # Auto-detect type if not provided
    ioc_type = submission.ioc_type or detect_ioc_type(submission.value)
    if not ioc_type:
        raise HTTPException(status_code=400, detail=f"Could not detect IOC type for: {submission.value}")

    # Check whitelist conflict
    whitelist_entry = None
    if postgres_db.pool:
        async with postgres_db.tenant_acquire() as conn:
            whitelist_entry = await check_whitelist_conflict(conn, submission.value, ioc_type)
            if whitelist_entry and not force:
                return {
                    "success": False,
                    "conflict": "whitelist",
                    "message": f"This IOC is currently whitelisted: {whitelist_entry.get('reason', 'No reason provided')}",
                    "whitelist_entry": whitelist_entry,
                    "action_required": "Set force=true to add anyway, or remove from whitelist first"
                }

            # If force=true and there was a whitelist conflict, remove from whitelist first
            if whitelist_entry and force:
                await conn.execute(
                    """
                    DELETE FROM ioc_whitelist
                    WHERE ioc_value = $1
                      AND (ioc_type = $2 OR $2 IS NULL)
                    """,
                    submission.value,
                    ioc_type
                )
                logger.info(f"Removed {submission.value} from whitelist (force submit by {current_user})")

    try:
        # Add IOC with source tracking
        ioc = await threat_intel.add_ioc(
            value=submission.value,
            ioc_type=IOCType(ioc_type),
            severity=ThreatSeverity(submission.severity) if submission.severity else ThreatSeverity.MEDIUM,
            tags=submission.tags or [],
            source=f"user:{current_user}",
            source_type=IOCSourceType.MANUAL,
            source_id=current_user
        )

        result = {
            "success": True,
            "ioc": {
                "value": ioc.value,
                "type": ioc.type,
                "severity": ioc.severity,
                "source_type": "manual",
                "source_id": current_user
            }
        }

        # Add warning if there was a whitelist conflict that was forced (and removed)
        if whitelist_entry:
            result["warning"] = f"IOC was removed from whitelist (was: {whitelist_entry.get('reason', 'no reason')}) and added to blocklist"
            result["removed_from_whitelist"] = whitelist_entry

        # Optionally enrich
        if submission.enrich:
            try:
                report = await threat_intel.enrich_ioc(
                    submission.value,
                    IOCType(ioc_type)
                )
                result["enrichment"] = {
                    "verdict": report.overall_verdict,
                    "confidence": report.confidence,
                    "severity": report.severity
                }
            except Exception as e:
                result["enrichment_error"] = str(e)

        # Enforce IOC limit — evict oldest if over cap
        if postgres_db.pool:
            try:
                async with postgres_db.tenant_acquire() as conn:
                    eviction = await enforce_ioc_limit(conn)
                    if eviction.get("enforced"):
                        result["eviction"] = eviction
            except Exception as e:
                logger.warning(f"IOC limit enforcement failed (non-fatal): {e}")

        return result

    except Exception as e:
        logger.error(f"IOC submission failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/submit/bulk")
async def bulk_submit_iocs(
    submission: BulkIOCSubmission,
    current_user: str = Depends(get_current_username)
):
    """Submit multiple IOCs (newline or comma separated)"""
    threat_intel = get_threat_intel_service()

    values = parse_ioc_values(submission.values)
    if not values:
        raise HTTPException(status_code=400, detail="No valid IOC values provided")

    added = 0
    skipped = 0
    whitelisted = 0
    errors = []

    for value in values:
        try:
            ioc_type = submission.ioc_type or detect_ioc_type(value)
            if not ioc_type:
                errors.append(f"Could not detect type: {value}")
                skipped += 1
                continue

            # Check whitelist
            whitelist_check = await check_whitelist(value, ioc_type, current_user)
            if whitelist_check.get('whitelisted'):
                whitelisted += 1
                continue

            # Add IOC
            await threat_intel.add_ioc(
                value=value,
                ioc_type=IOCType(ioc_type),
                severity=ThreatSeverity(submission.severity) if submission.severity else ThreatSeverity.MEDIUM,
                tags=submission.tags or [],
                source=f"user:{current_user}",
                source_type=IOCSourceType.MANUAL,
                source_id=current_user
            )
            added += 1

        except Exception as e:
            errors.append(f"{value}: {str(e)}")
            skipped += 1

    result = {
        "success": True,
        "added": added,
        "skipped": skipped,
        "whitelisted": whitelisted,
        "total": len(values),
        "errors": errors[:10]
    }

    # Enforce IOC limit — evict oldest if over cap
    if postgres_db.pool:
        try:
            async with postgres_db.tenant_acquire() as conn:
                eviction = await enforce_ioc_limit(conn)
                if eviction.get("enforced"):
                    result["eviction"] = eviction
        except Exception as e:
            logger.warning(f"IOC limit enforcement failed (non-fatal): {e}")

    return result


@router.post("/submit/upload")
async def upload_ioc_csv(
    file: UploadFile = File(...),
    severity: str = Form("medium"),
    tags: Optional[str] = Form(None),
    enrich: bool = Form(False),
    current_user: str = Depends(get_current_username)
):
    """Upload CSV file to submit IOCs"""
    threat_intel = get_threat_intel_service()

    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="File must be a CSV")

    try:
        content = await file.read()
        decoded = content.decode('utf-8')

        reader = csv.reader(io.StringIO(decoded))
        rows = list(reader)

        if not rows:
            raise HTTPException(status_code=400, detail="CSV file is empty")

        # Check if first row looks like a header and build column mapping
        first_row = rows[0]
        header_keywords = ['ioc', 'value', 'indicator', 'ioc_value', 'type', 'ioc_type', 'confidence', 'source', 'notes', 'severity']
        has_header = any(h.lower().strip() in header_keywords for h in first_row)

        # Column mapping for flexible CSV parsing
        col_map = {'value': 0, 'type': 1, 'severity': 2, 'source': None, 'notes': None}

        if has_header:
            header_lower = [h.lower().strip() for h in first_row]
            # Find value column
            for name in ['indicator', 'ioc', 'value', 'ioc_value']:
                if name in header_lower:
                    col_map['value'] = header_lower.index(name)
                    break
            # Find type column
            for name in ['indicator_type', 'ioc_type', 'type']:
                if name in header_lower:
                    col_map['type'] = header_lower.index(name)
                    break
            # Find severity/confidence column
            for name in ['severity', 'confidence']:
                if name in header_lower:
                    col_map['severity'] = header_lower.index(name)
                    break
            # Find source and notes for tags
            if 'source' in header_lower:
                col_map['source'] = header_lower.index('source')
            if 'notes' in header_lower:
                col_map['notes'] = header_lower.index('notes')

            rows = rows[1:]

        added = 0
        skipped = 0
        whitelisted = 0
        errors = []

        tag_list = [t.strip() for t in (tags or "").split(',')] if tags else []

        for row in rows:
            if not row:
                continue

            # Use column mapping
            value = row[col_map['value']].strip() if len(row) > col_map['value'] else None
            row_type = row[col_map['type']].strip() if len(row) > col_map['type'] else None
            row_severity = row[col_map['severity']].strip() if len(row) > col_map['severity'] else severity

            # Map confidence levels to severity
            if row_severity and row_severity.lower() in ['high', 'medium', 'low', 'unknown']:
                # confidence -> severity mapping
                confidence_map = {'high': 'high', 'medium': 'medium', 'low': 'low', 'unknown': 'unknown'}
                row_severity = confidence_map.get(row_severity.lower(), severity)

            # Add source/notes as tags if present
            row_tags = list(tag_list)
            if col_map.get('source') is not None and len(row) > col_map['source']:
                source_val = row[col_map['source']].strip()
                if source_val:
                    row_tags.append(f"source:{source_val}")

            if not value:
                continue

            try:
                ioc_type = row_type or detect_ioc_type(value)
                if not ioc_type:
                    errors.append(f"Could not detect type: {value}")
                    skipped += 1
                    continue

                # Check whitelist
                whitelist_check = await check_whitelist(value, ioc_type, current_user)
                if whitelist_check.get('whitelisted'):
                    whitelisted += 1
                    continue

                # Add IOC
                await threat_intel.add_ioc(
                    value=value,
                    ioc_type=IOCType(ioc_type),
                    severity=ThreatSeverity(row_severity) if row_severity else ThreatSeverity.MEDIUM,
                    tags=row_tags,
                    source=f"csv:{file.filename}",
                    source_type=IOCSourceType.MANUAL,
                    source_id=current_user
                )
                added += 1

            except Exception as e:
                errors.append(f"{value}: {str(e)}")
                skipped += 1

        result = {
            "success": True,
            "filename": file.filename,
            "added": added,
            "skipped": skipped,
            "whitelisted": whitelisted,
            "total": len(rows),
            "errors": errors[:10]
        }

        # Enforce IOC limit — evict oldest if over cap
        if postgres_db.pool:
            try:
                async with postgres_db.tenant_acquire() as conn:
                    eviction = await enforce_ioc_limit(conn)
                    if eviction.get("enforced"):
                        result["eviction"] = eviction
            except Exception as e:
                logger.warning(f"IOC limit enforcement failed (non-fatal): {e}")

        return result

    except Exception as e:
        logger.error(f"CSV upload failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# WHITELIST CHECK HELPER FOR ENRICHMENT
# ============================================================================

async def is_whitelisted(ioc_value: str, ioc_type: Optional[str] = None) -> bool:
    """Check if an IOC is whitelisted (for use by enrichment pipeline)"""
    if not postgres_db.pool:
        return False

    detected_type = ioc_type or detect_ioc_type(ioc_value)

    try:
        async with postgres_db.tenant_acquire() as conn:
            # Check exact match
            row = await conn.fetchrow(
                """
                SELECT 1 FROM ioc_whitelist
                WHERE ioc_value = $1
                  AND (ioc_type = $2 OR $2 IS NULL)
                  AND (expires_at IS NULL OR expires_at > NOW())
                  AND is_pattern = FALSE
                LIMIT 1
                """,
                ioc_value,
                detected_type
            )

            if row:
                return True

            # Check pattern matches (simplified for performance)
            patterns = await conn.fetch(
                """
                SELECT ioc_value, pattern_type FROM ioc_whitelist
                WHERE is_pattern = TRUE
                  AND (ioc_type = $1 OR $1 IS NULL)
                  AND (expires_at IS NULL OR expires_at > NOW())
                """,
                detected_type
            )

            for pattern in patterns:
                if pattern['pattern_type'] == 'prefix':
                    if ioc_value.startswith(pattern['ioc_value']):
                        return True
                elif pattern['pattern_type'] == 'suffix':
                    if ioc_value.endswith(pattern['ioc_value']):
                        return True
                elif pattern['pattern_type'] == 'contains':
                    if pattern['ioc_value'] in ioc_value:
                        return True

            return False

    except Exception as e:
        logger.error(f"Whitelist check error: {e}")
        return False


# ============================================================================
# IOC QUOTA ENDPOINT
# ============================================================================

@router.get("/quota")
async def get_ioc_quota(
    current_user: str = Depends(get_current_username)
):
    """Get current IOC storage quota status for the tenant."""
    if not postgres_db.pool:
        raise HTTPException(status_code=503, detail="Database not available")

    try:
        async with postgres_db.tenant_acquire() as conn:
            quota = await check_ioc_quota(conn)
            return quota
    except Exception as e:
        logger.error(f"Failed to check IOC quota: {e}")
        raise HTTPException(status_code=500, detail=str(e))
