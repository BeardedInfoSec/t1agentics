# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Threat Feeds API Routes

Manage threat intelligence feeds:
- List available feeds (preconfigured + custom)
- Enable/disable feeds
- Add custom feeds (TAXII, STIX, plain URL, etc.)
- Trigger manual poll
- View feed statistics
"""

import asyncio
import io
import logging
import uuid
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends
from config.constants import PLATFORM_OWNER_TENANT_ID
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

from services.threat_feed_service import (
    get_threat_feed_service,
    ThreatFeedConfig,
    FeedFormat,
    FeedCategory,
    FeedPollResult,
    PRECONFIGURED_FEEDS
)
from services.threat_intel_service import IOCType, ThreatSeverity
from services.license_manager import get_license_manager
from dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/threat-feeds", tags=["Threat Feeds"], dependencies=[Depends(get_current_user)])


# =============================================================================
# MODELS
# =============================================================================

class FeedResponse(BaseModel):
    """Response model for a threat feed"""
    feed_id: str
    name: str
    description: str
    url: str
    format: str
    category: str
    poll_interval_minutes: int
    enabled: bool
    is_preconfigured: bool = True
    default_severity: str = "medium"
    ioc_type: Optional[str] = None
    last_poll_at: Optional[datetime] = None
    last_poll_status: Optional[str] = None
    last_poll_ioc_count: Optional[int] = None
    total_iocs_ingested: Optional[int] = None
    next_poll_at: Optional[datetime] = None


class FeedListResponse(BaseModel):
    """Response for listing feeds"""
    feeds: List[FeedResponse]
    total: int
    enabled_count: int


class EnableFeedRequest(BaseModel):
    """Request to enable/disable a feed"""
    enabled: bool


class CreateFeedRequest(BaseModel):
    """Request to create a custom feed"""
    name: str = Field(..., min_length=1, max_length=100)
    url: str = Field(..., min_length=1)
    description: str = Field(default="")
    format: str = Field(default="txt_lines")  # txt_lines, csv, json, json_lines, stix, taxii
    category: str = Field(default="mixed")  # ip_blocklist, domain_blocklist, url_blocklist, hash_list, mixed, cve
    poll_interval_minutes: int = Field(default=60, ge=5, le=10080)  # 5 min to 1 week
    default_severity: str = Field(default="medium")
    ioc_type: Optional[str] = None  # ip, domain, url, hash_sha256, hash_sha1, hash_md5, cve
    parser_config: Dict[str, Any] = Field(default_factory=dict)
    drop_private_ips: bool = True
    drop_internal_domains: bool = True


class UpdateFeedRequest(BaseModel):
    """Request to update a custom feed"""
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    poll_interval_minutes: Optional[int] = None
    default_severity: Optional[str] = None
    parser_config: Optional[Dict[str, Any]] = None


class PollResultResponse(BaseModel):
    """Response from polling a feed"""
    feed_id: str
    success: bool
    iocs_fetched: int
    iocs_new: int
    iocs_updated: int
    iocs_skipped: int
    iocs_for_reenrichment: int
    error: Optional[str] = None
    duration_ms: int


class FeedStatsResponse(BaseModel):
    """Statistics for threat feeds"""
    total_feeds: int
    enabled_feeds: int
    preconfigured_feeds: int
    custom_feeds: int
    total_iocs_today: int
    feeds_polled_today: int
    last_poll_time: Optional[datetime] = None


# =============================================================================
# ROUTES
# =============================================================================

@router.get("", response_model=FeedListResponse)
async def list_feeds():
    """List all threat feeds (preconfigured and custom)"""
    service = get_threat_feed_service()
    feeds = service.list_feeds()

    # Get stats and enabled states from database for each feed
    feed_stats = await _get_feed_stats_from_db()

    # Also sync in-memory enabled states from database
    await _sync_enabled_states_from_db(service)

    feed_responses = []
    for feed in feeds:
        stats = feed_stats.get(feed.feed_id, {})
        # Use database enabled state if available, otherwise use in-memory
        db_enabled = stats.get('enabled')
        enabled = db_enabled if db_enabled is not None else feed.enabled

        feed_responses.append(FeedResponse(
            feed_id=feed.feed_id,
            name=feed.name,
            description=feed.description,
            url=feed.url,
            format=feed.format.value,
            category=feed.category.value,
            poll_interval_minutes=feed.poll_interval_minutes,
            enabled=enabled,
            is_preconfigured=feed.feed_id in [f.feed_id for f in PRECONFIGURED_FEEDS],
            default_severity=feed.default_severity.value if hasattr(feed.default_severity, 'value') else str(feed.default_severity),
            ioc_type=feed.ioc_type.value if feed.ioc_type else None,
            last_poll_at=stats.get('last_poll_at'),
            last_poll_status=stats.get('last_poll_status'),
            last_poll_ioc_count=stats.get('last_poll_ioc_count'),
            total_iocs_ingested=stats.get('total_iocs_ingested'),
            next_poll_at=stats.get('next_poll_at')
        ))

    enabled_count = sum(1 for f in feed_responses if f.enabled)

    return FeedListResponse(
        feeds=feed_responses,
        total=len(feed_responses),
        enabled_count=enabled_count
    )


@router.get("/stats", response_model=FeedStatsResponse)
async def get_feed_stats():
    """Get overall threat feed statistics"""
    service = get_threat_feed_service()
    feeds = service.list_feeds()

    preconfigured_ids = {f.feed_id for f in PRECONFIGURED_FEEDS}

    # Query actual metrics from DB
    total_iocs_today = 0
    feeds_polled_today = 0
    last_poll_time = None

    try:
        from services.postgres_db import postgres_db
        if postgres_db.pool:
            today = datetime.utcnow().date()
            async with postgres_db.tenant_acquire() as conn:
                # Count IOCs first seen today
                total_iocs_today = await conn.fetchval(
                    "SELECT COUNT(*) FROM iocs WHERE first_seen::date = $1",
                    today
                ) or 0

                # Count distinct feeds polled today (using last_poll_at from threat_feeds)
                feeds_polled_today = await conn.fetchval(
                    "SELECT COUNT(DISTINCT feed_id) FROM threat_feeds "
                    "WHERE last_poll_at IS NOT NULL AND last_poll_at::date = $1",
                    today
                ) or 0

                # Get the most recent poll time across all feeds
                last_poll_time = await conn.fetchval(
                    "SELECT MAX(last_poll_at) FROM threat_feeds WHERE last_poll_at IS NOT NULL"
                )
    except Exception as e:
        logger.warning(f"Failed to query feed metrics from DB: {e}")

    stats = FeedStatsResponse(
        total_feeds=len(feeds),
        enabled_feeds=sum(1 for f in feeds if f.enabled),
        preconfigured_feeds=sum(1 for f in feeds if f.feed_id in preconfigured_ids),
        custom_feeds=sum(1 for f in feeds if f.feed_id not in preconfigured_ids),
        total_iocs_today=total_iocs_today,
        feeds_polled_today=feeds_polled_today,
        last_poll_time=last_poll_time
    )

    return stats


@router.get("/{feed_id}", response_model=FeedResponse)
async def get_feed(feed_id: str):
    """Get details for a specific feed"""
    service = get_threat_feed_service()
    feed = service.get_feed(feed_id)

    if not feed:
        raise HTTPException(status_code=404, detail=f"Feed not found: {feed_id}")

    feed_stats = await _get_feed_stats_from_db()
    stats = feed_stats.get(feed_id, {})

    return FeedResponse(
        feed_id=feed.feed_id,
        name=feed.name,
        description=feed.description,
        url=feed.url,
        format=feed.format.value,
        category=feed.category.value,
        poll_interval_minutes=feed.poll_interval_minutes,
        enabled=feed.enabled,
        is_preconfigured=feed.feed_id in [f.feed_id for f in PRECONFIGURED_FEEDS],
        default_severity=feed.default_severity.value if hasattr(feed.default_severity, 'value') else str(feed.default_severity),
        ioc_type=feed.ioc_type.value if feed.ioc_type else None,
        last_poll_at=stats.get('last_poll_at'),
        last_poll_status=stats.get('last_poll_status'),
        last_poll_ioc_count=stats.get('last_poll_ioc_count'),
        total_iocs_ingested=stats.get('total_iocs_ingested'),
        next_poll_at=stats.get('next_poll_at')
    )


@router.patch("/{feed_id}/enable")
async def enable_feed(
    feed_id: str,
    request: EnableFeedRequest
):
    """Enable or disable a feed"""
    service = get_threat_feed_service()

    if not service.get_feed(feed_id):
        raise HTTPException(status_code=404, detail=f"Feed not found: {feed_id}")

    # Enforce feed limit when enabling (not when disabling)
    if request.enabled:
        manager = get_license_manager()
        # Count currently enabled feeds to sync usage before checking
        enabled_count = sum(1 for f in service.list_feeds() if f.enabled and f.feed_id != feed_id)
        manager.update_counts(feeds=enabled_count)
        allowed, msg = manager.check_limit("feeds", increment=1)
        if not allowed:
            raise HTTPException(status_code=403, detail=msg)

    success = service.enable_feed(feed_id, request.enabled)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to update feed")

    # Also update in database
    await _update_feed_enabled_in_db(feed_id, request.enabled)

    # Update feed count in license manager
    manager = get_license_manager()
    enabled_count = sum(1 for f in service.list_feeds() if f.enabled)
    manager.update_counts(feeds=enabled_count)

    return {"success": True, "feed_id": feed_id, "enabled": request.enabled}


@router.post("", response_model=FeedResponse)
async def create_feed(
    request: CreateFeedRequest
):
    """Create a custom threat feed"""
    service = get_threat_feed_service()

    # Enforce feed limit (custom feeds are created enabled by default)
    manager = get_license_manager()
    enabled_count = sum(1 for f in service.list_feeds() if f.enabled)
    manager.update_counts(feeds=enabled_count)
    allowed, msg = manager.check_limit("feeds", increment=1)
    if not allowed:
        raise HTTPException(status_code=403, detail=msg)

    # Generate feed ID from name
    feed_id = f"custom_{request.name.lower().replace(' ', '_').replace('-', '_')}"

    # Check if feed already exists
    if service.get_feed(feed_id):
        raise HTTPException(status_code=400, detail=f"Feed already exists: {feed_id}")

    # Map string values to enums
    try:
        format_enum = FeedFormat(request.format)
    except ValueError:
        format_enum = FeedFormat.TXT_LINES

    try:
        category_enum = FeedCategory(request.category)
    except ValueError:
        category_enum = FeedCategory.MIXED

    try:
        severity_enum = ThreatSeverity(request.default_severity)
    except ValueError:
        severity_enum = ThreatSeverity.MEDIUM

    ioc_type_enum = None
    if request.ioc_type:
        try:
            ioc_type_enum = IOCType(request.ioc_type)
        except ValueError:
            pass

    # Create feed config
    config = ThreatFeedConfig(
        feed_id=feed_id,
        name=request.name,
        url=request.url,
        format=format_enum,
        category=category_enum,
        description=request.description,
        poll_interval_minutes=request.poll_interval_minutes,
        enabled=True,
        ioc_type=ioc_type_enum,
        default_severity=severity_enum,
        parser_config=request.parser_config,
        drop_private_ips=request.drop_private_ips,
        drop_internal_domains=request.drop_internal_domains
    )

    service.add_feed(config)

    # Save to database
    await _save_custom_feed_to_db(config)

    # Update feed count in license manager
    enabled_count = sum(1 for f in service.list_feeds() if f.enabled)
    manager.update_counts(feeds=enabled_count)

    return FeedResponse(
        feed_id=config.feed_id,
        name=config.name,
        description=config.description,
        url=config.url,
        format=config.format.value,
        category=config.category.value,
        poll_interval_minutes=config.poll_interval_minutes,
        enabled=config.enabled,
        is_preconfigured=False,
        default_severity=config.default_severity.value,
        ioc_type=config.ioc_type.value if config.ioc_type else None
    )


@router.delete("/{feed_id}")
async def delete_feed(feed_id: str):
    """Delete a custom feed (cannot delete preconfigured feeds)"""
    service = get_threat_feed_service()

    # Check if preconfigured
    if feed_id in [f.feed_id for f in PRECONFIGURED_FEEDS]:
        raise HTTPException(status_code=400, detail="Cannot delete preconfigured feeds")

    if not service.get_feed(feed_id):
        raise HTTPException(status_code=404, detail=f"Feed not found: {feed_id}")

    success = service.remove_feed(feed_id)

    if success:
        await _delete_feed_from_db(feed_id)

    return {"success": success, "feed_id": feed_id}


@router.post("/{feed_id}/poll", response_model=PollResultResponse)
async def poll_feed(feed_id: str):
    """Manually trigger a feed poll for the requesting user's tenant.

    Manual polls work even if the feed is disabled (one-time override),
    but do NOT permanently change the feed's enabled state.
    """
    service = get_threat_feed_service()

    feed = service.get_feed(feed_id)
    if not feed:
        raise HTTPException(status_code=404, detail=f"Feed not found: {feed_id}")

    # For manual polls, temporarily enable the feed, poll, then restore
    was_disabled = not feed.enabled
    if was_disabled:
        feed.enabled = True  # Direct attribute set (no DB side-effect)

    try:
        result = await service.poll_feed(feed_id)
    finally:
        if was_disabled:
            feed.enabled = False  # Restore without DB side-effect

    return PollResultResponse(
        feed_id=result.feed_id,
        success=result.success,
        iocs_fetched=result.iocs_fetched,
        iocs_new=result.iocs_new,
        iocs_updated=result.iocs_updated,
        iocs_skipped=result.iocs_skipped,
        iocs_for_reenrichment=result.iocs_for_reenrichment,
        error=result.error,
        duration_ms=result.duration_ms
    )


@router.get("/formats/available")
async def get_available_formats():
    """Get available feed formats"""
    return {
        "formats": [
            {"id": "txt_lines", "name": "Plain Text (one IOC per line)", "description": "Simple text file with one indicator per line"},
            {"id": "csv", "name": "CSV", "description": "Comma-separated values"},
            {"id": "json", "name": "JSON", "description": "JSON array or object"},
            {"id": "json_lines", "name": "JSON Lines", "description": "One JSON object per line"},
            {"id": "stix", "name": "STIX 2.x", "description": "Structured Threat Information Expression"},
            {"id": "misp", "name": "MISP", "description": "Malware Information Sharing Platform format"},
            {"id": "taxii", "name": "TAXII", "description": "Trusted Automated Exchange of Intelligence Information"},
        ],
        "categories": [
            {"id": "ip_blocklist", "name": "IP Blocklist"},
            {"id": "domain_blocklist", "name": "Domain Blocklist"},
            {"id": "url_blocklist", "name": "URL Blocklist"},
            {"id": "hash_list", "name": "Hash List"},
            {"id": "mixed", "name": "Mixed IOCs"},
            {"id": "cve", "name": "CVE/Vulnerabilities"},
        ],
        "ioc_types": [
            {"id": "ip", "name": "IP Address"},
            {"id": "domain", "name": "Domain"},
            {"id": "url", "name": "URL"},
            {"id": "hash_sha256", "name": "SHA256 Hash"},
            {"id": "hash_sha1", "name": "SHA1 Hash"},
            {"id": "hash_md5", "name": "MD5 Hash"},
            {"id": "cve", "name": "CVE"},
        ],
        "severities": [
            {"id": "critical", "name": "Critical"},
            {"id": "high", "name": "High"},
            {"id": "medium", "name": "Medium"},
            {"id": "low", "name": "Low"},
        ]
    }


# =============================================================================
# SCHEDULER ENDPOINTS
# =============================================================================

# Module-level scheduler state
_scheduler_state = {
    "running": False,
    "task": None,
    "current_feed": None,
    "last_run_at": None,
    "feeds_polled": 0,
    "feeds_failed": 0,
    "interval_minutes": 60,  # Default polling interval between full cycles
    "delay_between_feeds": 5,  # Seconds between each feed poll (rate limiting)
    "max_feeds_per_cycle": 10,  # Max feeds to poll per cycle (prevents system overload)
    "skip_recently_failed": True,  # Skip feeds that failed in last hour
    "failed_feeds": {}  # Track failed feeds with timestamps
}


class SchedulerStatusResponse(BaseModel):
    """Scheduler status response"""
    running: bool
    current_feed: Optional[str] = None
    last_run_at: Optional[datetime] = None
    feeds_polled: int = 0
    feeds_failed: int = 0
    interval_minutes: int = 60
    delay_between_feeds: int = 5
    max_feeds_per_cycle: int = 10


class SchedulerConfigRequest(BaseModel):
    """Scheduler configuration request"""
    interval_minutes: int = 60  # Minutes between full polling cycles
    delay_between_feeds: int = 5  # Seconds between each feed (rate limiting)
    max_feeds_per_cycle: int = 10  # Max feeds to poll per cycle


@router.get("/scheduler/status", response_model=SchedulerStatusResponse)
async def get_scheduler_status():
    """Get the current scheduler status.

    Reports running=True if EITHER the route-level scheduler or the
    service-level background polling loop is active.
    """
    service = get_threat_feed_service()
    is_running = _scheduler_state["running"] or service._running

    return SchedulerStatusResponse(
        running=is_running,
        current_feed=_scheduler_state["current_feed"],
        last_run_at=_scheduler_state["last_run_at"],
        feeds_polled=_scheduler_state["feeds_polled"],
        feeds_failed=_scheduler_state["feeds_failed"],
        interval_minutes=_scheduler_state["interval_minutes"],
        delay_between_feeds=_scheduler_state["delay_between_feeds"],
        max_feeds_per_cycle=_scheduler_state["max_feeds_per_cycle"]
    )


@router.post("/scheduler/start")
async def start_scheduler(config: Optional[SchedulerConfigRequest] = None):
    """Start the feed polling scheduler with rate limiting.

    Controls both the route-level scheduler loop and the service-level
    background polling loop to ensure all polling is started.
    """
    import asyncio

    if _scheduler_state["running"]:
        return {"success": False, "message": "Scheduler is already running"}

    if config:
        _scheduler_state["interval_minutes"] = config.interval_minutes
        _scheduler_state["delay_between_feeds"] = config.delay_between_feeds
        _scheduler_state["max_feeds_per_cycle"] = config.max_feeds_per_cycle

    _scheduler_state["running"] = True
    _scheduler_state["feeds_polled"] = 0
    _scheduler_state["feeds_failed"] = 0
    _scheduler_state["failed_feeds"] = {}

    # Start the route-level scheduler loop in the background
    _scheduler_state["task"] = asyncio.create_task(_scheduler_loop())

    # Also start the service-level background polling loop
    service = get_threat_feed_service()
    if not service._running:
        await service.start_polling()

    return {
        "success": True,
        "message": "Scheduler started",
        "interval_minutes": _scheduler_state["interval_minutes"],
        "delay_between_feeds": _scheduler_state["delay_between_feeds"],
        "max_feeds_per_cycle": _scheduler_state["max_feeds_per_cycle"]
    }


@router.post("/scheduler/stop")
async def stop_scheduler():
    """Stop the feed polling scheduler.

    Stops both the route-level scheduler loop AND the service-level
    background polling loop so that no polling occurs when the user
    toggles the scheduler off.
    """
    if not _scheduler_state["running"]:
        # Even if our state says not running, still stop the service-level
        # polling in case it was started at app boot
        service = get_threat_feed_service()
        if service._running:
            await service.stop_polling()
            return {"success": True, "message": "Background polling stopped"}
        return {"success": False, "message": "Scheduler is not running"}

    _scheduler_state["running"] = False

    if _scheduler_state["task"]:
        _scheduler_state["task"].cancel()
        try:
            await _scheduler_state["task"]
        except asyncio.CancelledError:
            pass
        _scheduler_state["task"] = None

    _scheduler_state["current_feed"] = None

    # Stop the service-level background polling loop
    service = get_threat_feed_service()
    if service._running:
        await service.stop_polling()

    return {"success": True, "message": "Scheduler stopped"}


@router.post("/scheduler/poll-all")
async def poll_all_enabled_feeds():
    """Manually trigger polling of all enabled feeds for the requesting user's tenant"""
    service = get_threat_feed_service()

    # Sync enabled states from database
    await _sync_enabled_states_from_db(service)

    results = []
    feeds = service.list_feeds()

    for feed in feeds:
        if feed.enabled:
            result = await service.poll_feed(feed.feed_id)
            results.append({
                "feed_id": result.feed_id,
                "success": result.success,
                "iocs_fetched": result.iocs_fetched,
                "iocs_new": result.iocs_new,
                "error": result.error
            })

    return {
        "success": True,
        "feeds_polled": len(results),
        "results": results
    }


async def _scheduler_loop():
    """Background scheduler loop that polls feeds sequentially with rate limiting"""
    import asyncio
    from datetime import timedelta

    service = get_threat_feed_service()

    while _scheduler_state["running"]:
        try:
            # Sync enabled states from database
            await _sync_enabled_states_from_db(service)

            feeds = service.list_feeds()
            enabled_feeds = [f for f in feeds if f.enabled]

            # Apply max feeds per cycle limit
            max_feeds = _scheduler_state["max_feeds_per_cycle"]
            delay_seconds = _scheduler_state["delay_between_feeds"]

            # Filter out recently failed feeds (within last hour)
            now = datetime.utcnow()
            if _scheduler_state["skip_recently_failed"]:
                feeds_to_poll = []
                for feed in enabled_feeds:
                    last_fail = _scheduler_state["failed_feeds"].get(feed.feed_id)
                    if last_fail and (now - last_fail) < timedelta(hours=1):
                        print(f"[SKIP] Skipping {feed.feed_id} - failed recently")
                        continue
                    feeds_to_poll.append(feed)
            else:
                feeds_to_poll = enabled_feeds

            # Limit to max feeds per cycle
            feeds_to_poll = feeds_to_poll[:max_feeds]

            print(f"[POLL] Scheduler: Polling {len(feeds_to_poll)} of {len(enabled_feeds)} enabled feeds (max: {max_feeds})")

            polled_this_cycle = 0
            for feed in feeds_to_poll:
                if not _scheduler_state["running"]:
                    break

                _scheduler_state["current_feed"] = feed.name

                try:
                    result = await service.poll_feed(feed.feed_id)
                    if result.success:
                        _scheduler_state["feeds_polled"] += 1
                        polled_this_cycle += 1
                        # Clear from failed list on success
                        _scheduler_state["failed_feeds"].pop(feed.feed_id, None)
                        print(f"[OK] {feed.feed_id}: {result.iocs_new} new, {result.iocs_updated} updated")
                    else:
                        _scheduler_state["feeds_failed"] += 1
                        _scheduler_state["failed_feeds"][feed.feed_id] = now
                        print(f"[FAIL] {feed.feed_id} failed: {result.error}")
                except Exception as e:
                    _scheduler_state["feeds_failed"] += 1
                    _scheduler_state["failed_feeds"][feed.feed_id] = now
                    print(f"[ERROR] Scheduler error polling {feed.feed_id}: {e}")

                # Rate limiting delay between feeds
                if _scheduler_state["running"] and polled_this_cycle < len(feeds_to_poll):
                    print(f"[WAIT] Waiting {delay_seconds}s before next feed...")
                    await asyncio.sleep(delay_seconds)

            _scheduler_state["current_feed"] = None
            _scheduler_state["last_run_at"] = datetime.utcnow()

            print(f"[CYCLE] Cycle complete: {polled_this_cycle} feeds polled. Next cycle in {_scheduler_state['interval_minutes']} minutes.")

            # Wait for the configured interval before next run
            if _scheduler_state["running"]:
                await asyncio.sleep(_scheduler_state["interval_minutes"] * 60)

        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"Scheduler loop error: {e}")
            if _scheduler_state["running"]:
                await asyncio.sleep(60)  # Wait 1 minute on error


# =============================================================================
# HELPERS
# =============================================================================

async def _get_feed_stats_from_db() -> Dict[str, Dict]:
    """Get feed stats from database"""
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected or not postgres_db.pool:
            return {}

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT feed_id, last_poll_at, last_poll_status,
                       last_poll_ioc_count, total_iocs_ingested, next_poll_at, enabled
                FROM threat_feeds
            """)

            return {
                row['feed_id']: {
                    'last_poll_at': row['last_poll_at'],
                    'last_poll_status': row['last_poll_status'],
                    'last_poll_ioc_count': row['last_poll_ioc_count'],
                    'total_iocs_ingested': row['total_iocs_ingested'],
                    'next_poll_at': row['next_poll_at'],
                    'enabled': row['enabled']
                }
                for row in rows
            }
    except Exception as e:
        print(f"Error getting feed stats: {e}")
        return {}


async def _sync_enabled_states_from_db(service):
    """Sync enabled states from database to in-memory service"""
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected or not postgres_db.pool:
            return

        async with postgres_db.tenant_acquire() as conn:
            rows = await conn.fetch("""
                SELECT feed_id, enabled FROM threat_feeds
            """)

            for row in rows:
                feed_id = row['feed_id']
                enabled = row['enabled']
                if enabled is not None:
                    service.enable_feed(feed_id, enabled)
    except Exception as e:
        print(f"Error syncing feed enabled states: {e}")


async def _update_feed_enabled_in_db(feed_id: str, enabled: bool):
    """Update feed enabled status in database - uses UPSERT"""
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected or not postgres_db.pool:
            return

        # Get feed config for name and category
        service = get_threat_feed_service()
        feed = service.get_feed(feed_id)

        async with postgres_db.tenant_acquire() as conn:
            # UPSERT - insert if not exists, update if exists
            await conn.execute(
                """
                INSERT INTO threat_feeds (feed_id, name, url, format, category, enabled, poll_interval_minutes, description, tenant_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (feed_id) DO UPDATE SET
                    enabled = $6,
                    updated_at = CURRENT_TIMESTAMP
                """,
                feed_id,
                feed.name if feed else feed_id,
                feed.url if feed else '',
                feed.format.value if feed and hasattr(feed.format, 'value') else 'txt_lines',
                feed.category.value if feed and hasattr(feed.category, 'value') else 'mixed',
                enabled,
                feed.poll_interval_minutes if feed else 60,
                feed.description if feed else '',
                uuid.UUID(PLATFORM_OWNER_TENANT_ID)
            )
    except Exception as e:
        print(f"Error updating feed enabled: {e}")


async def _save_custom_feed_to_db(config: ThreatFeedConfig):
    """Save custom feed to database"""
    try:
        from services.postgres_db import postgres_db
        import json

        if not postgres_db.connected or not postgres_db.pool:
            return

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute("""
                INSERT INTO threat_feeds (
                    feed_id, name, description, category, url, format,
                    poll_interval_minutes, enabled, is_custom, parser_config, tenant_id
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9, $10)
                ON CONFLICT (feed_id) DO UPDATE SET
                    name = $2, description = $3, url = $5,
                    poll_interval_minutes = $7, parser_config = $9
            """,
                config.feed_id,
                config.name,
                config.description,
                config.category.value,
                config.url,
                config.format.value,
                config.poll_interval_minutes,
                config.enabled,
                json.dumps(config.parser_config),
                uuid.UUID(PLATFORM_OWNER_TENANT_ID)
            )
    except Exception as e:
        print(f"Error saving custom feed: {e}")


async def _delete_feed_from_db(feed_id: str):
    """Delete feed from database"""
    try:
        from services.postgres_db import postgres_db
        if not postgres_db.connected or not postgres_db.pool:
            return

        async with postgres_db.tenant_acquire() as conn:
            await conn.execute(
                "DELETE FROM threat_feeds WHERE feed_id = $1 AND is_custom = TRUE",
                feed_id
            )
    except Exception as e:
        print(f"Error deleting feed: {e}")
