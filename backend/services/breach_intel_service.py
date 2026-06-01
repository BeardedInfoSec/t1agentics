# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Breach Intelligence Service

Platform-level service for aggregating breach and vulnerability intelligence
from public sources (CISA KEV, security news RSS feeds, NCSC advisories).

This is a PLATFORM service -- breach data is shared across all tenants.
No tenant_id columns, no RLS filtering. Uses set_platform_admin_mode(True)
for all database access.

Sources:
- CISA Known Exploited Vulnerabilities (JSON)
- CISA Cybersecurity Advisories (RSS)
- BleepingComputer (RSS)
- KrebsOnSecurity (RSS)
- The Record (RSS)
- The Hacker News (RSS)
- NCSC UK (RSS)
"""

import asyncio
import aiohttp
import feedparser
import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# MODELS
# ============================================================================

class SourceType(str, Enum):
    """Source feed type"""
    RSS = "rss"
    JSON = "json"


class IncidentType(str, Enum):
    """Breach incident type"""
    VULNERABILITY = "vulnerability"
    BREACH = "breach"
    ADVISORY = "advisory"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    GENERAL = "general"


class IncidentSeverity(str, Enum):
    """Incident severity"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class BreachSource:
    """Configuration for a breach intelligence source"""
    source_id: str
    name: str
    url: str
    source_type: SourceType
    description: str = ""
    poll_interval_minutes: int = 60
    enabled: bool = True
    default_incident_type: IncidentType = IncidentType.GENERAL
    default_severity: IncidentSeverity = IncidentSeverity.MEDIUM


@dataclass
class PollResult:
    """Result of polling a single source"""
    source_id: str
    success: bool
    items_fetched: int = 0
    items_new: int = 0
    items_skipped: int = 0
    error: Optional[str] = None
    duration_ms: int = 0


# ============================================================================
# PRECONFIGURED SOURCES
# ============================================================================

PRECONFIGURED_SOURCES: List[BreachSource] = [

    # --- CISA ---
    BreachSource(
        source_id="cisa_kev",
        name="CISA Known Exploited Vulnerabilities",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        source_type=SourceType.JSON,
        description="CISA catalog of known exploited vulnerabilities with remediation deadlines",
        poll_interval_minutes=360,
        default_incident_type=IncidentType.VULNERABILITY,
        default_severity=IncidentSeverity.HIGH,
    ),
    BreachSource(
        source_id="cisa_alerts",
        name="CISA Cybersecurity Advisories",
        url="https://www.cisa.gov/cybersecurity-advisories/all.xml",
        source_type=SourceType.RSS,
        description="CISA cybersecurity advisories and alerts",
        poll_interval_minutes=60,
        default_incident_type=IncidentType.ADVISORY,
        default_severity=IncidentSeverity.HIGH,
    ),

    # --- Security News ---
    BreachSource(
        source_id="bleepingcomputer",
        name="BleepingComputer",
        url="https://www.bleepingcomputer.com/feed/",
        source_type=SourceType.RSS,
        description="BleepingComputer security news and breach reports",
        poll_interval_minutes=30,
        default_incident_type=IncidentType.GENERAL,
        default_severity=IncidentSeverity.MEDIUM,
    ),
    BreachSource(
        source_id="krebsonsecurity",
        name="KrebsOnSecurity",
        url="https://krebsonsecurity.com/feed/",
        source_type=SourceType.RSS,
        description="Brian Krebs investigative cybersecurity journalism",
        poll_interval_minutes=60,
        default_incident_type=IncidentType.BREACH,
        default_severity=IncidentSeverity.MEDIUM,
    ),
    BreachSource(
        source_id="therecord",
        name="The Record",
        url="https://therecord.media/feed",
        source_type=SourceType.RSS,
        description="Recorded Future news on cybercrime and nation-state threats",
        poll_interval_minutes=30,
        default_incident_type=IncidentType.GENERAL,
        default_severity=IncidentSeverity.MEDIUM,
    ),
    BreachSource(
        source_id="thehackernews",
        name="The Hacker News",
        url="https://feeds.feedburner.com/TheHackersNews",
        source_type=SourceType.RSS,
        description="The Hacker News cybersecurity news and analysis",
        poll_interval_minutes=30,
        default_incident_type=IncidentType.GENERAL,
        default_severity=IncidentSeverity.MEDIUM,
    ),

    # --- Government / CERT ---
    BreachSource(
        source_id="ncsc_uk",
        name="NCSC UK",
        url="https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
        source_type=SourceType.RSS,
        description="UK National Cyber Security Centre advisories and reports",
        poll_interval_minutes=120,
        default_incident_type=IncidentType.ADVISORY,
        default_severity=IncidentSeverity.HIGH,
    ),
]

# Index by source_id for fast lookup
_SOURCES_BY_ID: Dict[str, BreachSource] = {s.source_id: s for s in PRECONFIGURED_SOURCES}


# ============================================================================
# SERVICE
# ============================================================================

class BreachIntelService:
    """
    Platform-level breach intelligence aggregation service.

    Polls public breach/vulnerability/advisory feeds and stores incidents
    in a shared (non-tenant) table for cross-tenant visibility.
    """

    def __init__(self):
        self.db = None
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None
        self._http_timeout = aiohttp.ClientTimeout(total=60)
        self._user_agent = "T1-Agentics-BreachIntel/1.0"

    # ------------------------------------------------------------------
    # Database helper
    # ------------------------------------------------------------------

    def _get_db(self):
        """Get database connection, lazily initialized."""
        if self.db is None:
            try:
                from services.postgres_db import postgres_db
                if postgres_db.connected:
                    self.db = postgres_db
            except Exception as e:
                logger.error(f"Failed to get database connection: {e}")
        return self.db

    # ------------------------------------------------------------------
    # Fingerprinting / dedup
    # ------------------------------------------------------------------

    @staticmethod
    def _fingerprint(source_id: str, external_id: str) -> str:
        """
        Generate a SHA-256 fingerprint for deduplication.
        Combines source_id and external_id (or title) into a stable hash.
        """
        raw = f"{source_id}:{external_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Source seeding
    # ------------------------------------------------------------------

    async def _seed_sources(self) -> None:
        """Seed preconfigured sources into the breach_intel_sources table."""
        db = self._get_db()
        if not db or not db.pool:
            logger.warning("Database not available -- skipping source seeding")
            return

        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)

        try:
            async with db.tenant_acquire() as conn:
                for src in PRECONFIGURED_SOURCES:
                    await conn.execute(
                        """
                        INSERT INTO breach_intel_sources (
                            id, source_id, name, url, source_type,
                            description, poll_interval_minutes, enabled,
                            default_incident_type, default_severity,
                            created_at
                        ) VALUES (
                            $1, $2, $3, $4, $5,
                            $6, $7, $8,
                            $9, $10,
                            NOW()
                        )
                        ON CONFLICT (source_id) DO UPDATE SET
                            name = EXCLUDED.name,
                            url = EXCLUDED.url,
                            description = EXCLUDED.description,
                            poll_interval_minutes = EXCLUDED.poll_interval_minutes,
                            default_incident_type = EXCLUDED.default_incident_type,
                            default_severity = EXCLUDED.default_severity
                        """,
                        str(uuid.uuid4()),
                        src.source_id,
                        src.name,
                        src.url,
                        src.source_type.value,
                        src.description,
                        src.poll_interval_minutes,
                        src.enabled,
                        src.default_incident_type.value,
                        src.default_severity.value,
                    )
                logger.info(f"Seeded {len(PRECONFIGURED_SOURCES)} breach intel sources")
        except Exception as e:
            logger.error(f"Failed to seed breach intel sources: {e}")

    # ------------------------------------------------------------------
    # HTTP fetching
    # ------------------------------------------------------------------

    async def _fetch_url(self, url: str) -> Optional[bytes]:
        """Fetch URL content with timeout and error handling."""
        try:
            async with aiohttp.ClientSession(
                timeout=self._http_timeout,
                headers={"User-Agent": self._user_agent},
            ) as session:
                async with session.get(url) as resp:
                    if resp.status != 200:
                        logger.warning(f"HTTP {resp.status} fetching {url}")
                        return None
                    return await resp.read()
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching {url}")
            return None
        except aiohttp.ClientError as e:
            logger.warning(f"HTTP error fetching {url}: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}")
            return None

    # ------------------------------------------------------------------
    # RSS parsing
    # ------------------------------------------------------------------

    def _parse_rss(self, content: bytes, source: BreachSource) -> List[Dict[str, Any]]:
        """Parse RSS feed content into a list of incident dicts."""
        incidents = []
        try:
            feed = feedparser.parse(content)
        except Exception as e:
            logger.error(f"Failed to parse RSS for {source.source_id}: {e}")
            return incidents

        for entry in feed.entries:
            title = getattr(entry, "title", "").strip()
            if not title:
                continue

            link = getattr(entry, "link", "")
            summary = getattr(entry, "summary", "") or getattr(entry, "description", "")
            # Truncate summary to a reasonable length
            if len(summary) > 4000:
                summary = summary[:4000] + "..."

            # Parse published date
            published_at = None
            published_parsed = getattr(entry, "published_parsed", None)
            if published_parsed:
                try:
                    from time import mktime
                    published_at = datetime.fromtimestamp(mktime(published_parsed), tz=timezone.utc)
                except Exception:
                    pass
            if not published_at:
                updated_parsed = getattr(entry, "updated_parsed", None)
                if updated_parsed:
                    try:
                        from time import mktime
                        published_at = datetime.fromtimestamp(mktime(updated_parsed), tz=timezone.utc)
                    except Exception:
                        pass

            # Use link or title as external ID for fingerprinting
            external_id = link or title
            fingerprint = self._fingerprint(source.source_id, external_id)

            incidents.append({
                "title": title,
                "external_id": external_id,
                "url": link,
                "summary": summary,
                "published_at": published_at,
                "incident_type": source.default_incident_type.value,
                "severity": source.default_severity.value,
                "fingerprint": fingerprint,
                "raw_data": None,  # RSS entries are lightweight, skip raw storage
            })

        return incidents

    # ------------------------------------------------------------------
    # CISA KEV parsing
    # ------------------------------------------------------------------

    def _parse_cisa_kev(self, content: bytes, source: BreachSource) -> List[Dict[str, Any]]:
        """Parse CISA KEV JSON into a list of incident dicts."""
        incidents = []
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse CISA KEV JSON: {e}")
            return incidents

        vulnerabilities = data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            cve_id = vuln.get("cveID", "")
            if not cve_id:
                continue

            vendor = vuln.get("vendorProject", "")
            product = vuln.get("product", "")
            name = vuln.get("vulnerabilityName", "")
            description = vuln.get("shortDescription", "")
            date_added = vuln.get("dateAdded", "")
            due_date = vuln.get("dueDate", "")
            known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")
            required_action = vuln.get("requiredAction", "")

            title = f"{cve_id}: {name}" if name else f"{cve_id}: {vendor} {product}"
            summary_parts = []
            if description:
                summary_parts.append(description)
            if vendor and product:
                summary_parts.append(f"Vendor: {vendor}, Product: {product}")
            if required_action:
                summary_parts.append(f"Required Action: {required_action}")
            if due_date:
                summary_parts.append(f"Remediation Due: {due_date}")
            if known_ransomware and known_ransomware.lower() != "unknown":
                summary_parts.append(f"Known Ransomware Use: {known_ransomware}")

            summary = " | ".join(summary_parts)
            if len(summary) > 4000:
                summary = summary[:4000] + "..."

            # Parse date_added as published_at
            published_at = None
            if date_added:
                try:
                    published_at = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except ValueError:
                    pass

            # Determine severity -- KEV entries with ransomware use are critical
            severity = source.default_severity.value
            if known_ransomware and known_ransomware.lower() == "known":
                severity = IncidentSeverity.CRITICAL.value

            fingerprint = self._fingerprint(source.source_id, cve_id)

            incidents.append({
                "title": title,
                "external_id": cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": summary,
                "published_at": published_at,
                "incident_type": IncidentType.VULNERABILITY.value,
                "severity": severity,
                "fingerprint": fingerprint,
                "raw_data": json.dumps(vuln),
            })

        return incidents

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    async def _ingest_incidents(
        self, conn, source_id: str, incidents: List[Dict[str, Any]]
    ) -> int:
        """
        Insert incidents into breach_intel_incidents, deduplicating by fingerprint.
        Returns the number of newly inserted rows.
        """
        if not incidents:
            return 0

        new_count = 0
        for inc in incidents:
            try:
                result = await conn.execute(
                    """
                    INSERT INTO breach_intel_incidents (
                        id, source_id, title, external_id, url,
                        summary, published_at, incident_type, severity,
                        fingerprint, raw_data, created_at
                    ) VALUES (
                        $1, $2, $3, $4, $5,
                        $6, $7, $8, $9,
                        $10, $11, NOW()
                    )
                    ON CONFLICT (fingerprint) DO NOTHING
                    """,
                    str(uuid.uuid4()),
                    source_id,
                    inc["title"][:500],
                    inc["external_id"][:500],
                    inc.get("url", "")[:2000],
                    inc.get("summary", ""),
                    inc.get("published_at"),
                    inc["incident_type"],
                    inc["severity"],
                    inc["fingerprint"],
                    inc.get("raw_data"),
                )
                # asyncpg returns e.g. "INSERT 0 1" or "INSERT 0 0"
                if result and result.endswith("1"):
                    new_count += 1
            except Exception as e:
                logger.error(f"Failed to insert incident '{inc.get('title', '?')}': {e}")

        return new_count

    # ------------------------------------------------------------------
    # Poll single source
    # ------------------------------------------------------------------

    async def poll_source(self, source_id: str) -> dict:
        """
        Poll a single source by ID. Returns a PollResult-like dict.
        """
        import time
        start = time.monotonic()

        source = _SOURCES_BY_ID.get(source_id)
        if not source:
            return {
                "source_id": source_id,
                "success": False,
                "error": f"Unknown source: {source_id}",
                "items_fetched": 0,
                "items_new": 0,
                "items_skipped": 0,
                "duration_ms": 0,
            }

        db = self._get_db()
        if not db or not db.pool:
            return {
                "source_id": source_id,
                "success": False,
                "error": "Database not available",
                "items_fetched": 0,
                "items_new": 0,
                "items_skipped": 0,
                "duration_ms": 0,
            }

        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)

        # Fetch content
        content = await self._fetch_url(source.url)
        if content is None:
            elapsed = int((time.monotonic() - start) * 1000)
            # Update source error status
            try:
                async with db.tenant_acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE breach_intel_sources
                        SET last_error = $1, last_poll_at = NOW()
                        WHERE source_id = $2
                        """,
                        f"Failed to fetch URL",
                        source_id,
                    )
            except Exception:
                pass
            return {
                "source_id": source_id,
                "success": False,
                "error": "Failed to fetch URL",
                "items_fetched": 0,
                "items_new": 0,
                "items_skipped": 0,
                "duration_ms": elapsed,
            }

        # Parse based on source type
        if source.source_type == SourceType.RSS:
            incidents = self._parse_rss(content, source)
        elif source.source_type == SourceType.JSON:
            incidents = self._parse_cisa_kev(content, source)
        else:
            incidents = []

        items_fetched = len(incidents)

        # Ingest into database
        try:
            async with db.tenant_acquire() as conn:
                items_new = await self._ingest_incidents(conn, source_id, incidents)
                items_skipped = items_fetched - items_new

                # Update source stats
                await conn.execute(
                    """
                    UPDATE breach_intel_sources
                    SET last_poll_at = NOW(),
                        last_success_at = NOW(),
                        last_error = NULL,
                        total_items = COALESCE(total_items, 0) + $1,
                        next_poll_at = NOW() + ($2 || ' minutes')::interval
                    WHERE source_id = $3
                    """,
                    items_new,
                    str(source.poll_interval_minutes),
                    source_id,
                )

            elapsed = int((time.monotonic() - start) * 1000)
            logger.info(
                f"Polled {source.name}: {items_fetched} fetched, "
                f"{items_new} new, {items_skipped} skipped ({elapsed}ms)"
            )
            return {
                "source_id": source_id,
                "success": True,
                "error": None,
                "items_fetched": items_fetched,
                "items_new": items_new,
                "items_skipped": items_skipped,
                "duration_ms": elapsed,
            }

        except Exception as e:
            elapsed = int((time.monotonic() - start) * 1000)
            logger.error(f"Failed to ingest incidents for {source_id}: {e}")
            try:
                async with db.tenant_acquire() as conn:
                    await conn.execute(
                        """
                        UPDATE breach_intel_sources
                        SET last_error = $1, last_poll_at = NOW(),
                            next_poll_at = NOW() + ($2 || ' minutes')::interval
                        WHERE source_id = $3
                        """,
                        str(e)[:500],
                        str(source.poll_interval_minutes),
                        source_id,
                    )
            except Exception:
                pass
            return {
                "source_id": source_id,
                "success": False,
                "error": str(e),
                "items_fetched": items_fetched,
                "items_new": 0,
                "items_skipped": 0,
                "duration_ms": elapsed,
            }

    # ------------------------------------------------------------------
    # Poll all sources
    # ------------------------------------------------------------------

    async def poll_all_sources(self) -> list:
        """Poll all enabled sources sequentially with a delay between each."""
        results = []
        for source in PRECONFIGURED_SOURCES:
            if not source.enabled:
                continue
            result = await self.poll_source(source.source_id)
            results.append(result)
            # Brief delay between sources to avoid hammering
            await asyncio.sleep(5)
        return results

    # ------------------------------------------------------------------
    # Background polling loop
    # ------------------------------------------------------------------

    async def start_polling(self) -> None:
        """Start the background polling loop."""
        if self._running:
            logger.warning("Breach intel polling already running")
            return

        self._running = True
        self._poll_task = asyncio.create_task(self._polling_loop())
        logger.info("Breach intel background polling started")

    async def stop_polling(self) -> None:
        """Stop the background polling loop."""
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
            self._poll_task = None
        logger.info("Breach intel background polling stopped")

    async def _polling_loop(self) -> None:
        """
        Main background loop. Each cycle:
        1. Seed sources if needed
        2. Find sources where next_poll_at <= NOW() or next_poll_at IS NULL
        3. Poll each due source
        4. Sleep 60 seconds
        """
        from services.postgres_db import set_platform_admin_mode

        # Initial seed
        set_platform_admin_mode(True)
        await self._seed_sources()

        while self._running:
            try:
                db = self._get_db()
                if not db or not db.pool:
                    logger.debug("Database not available, retrying in 60s")
                    await asyncio.sleep(60)
                    continue

                set_platform_admin_mode(True)

                # Find due sources
                async with db.tenant_acquire() as conn:
                    due_rows = await conn.fetch(
                        """
                        SELECT source_id FROM breach_intel_sources
                        WHERE enabled = TRUE
                          AND (next_poll_at IS NULL OR next_poll_at <= NOW())
                        ORDER BY last_poll_at ASC NULLS FIRST
                        """
                    )

                if due_rows:
                    logger.info(f"Breach intel: {len(due_rows)} source(s) due for polling")
                    for row in due_rows:
                        if not self._running:
                            break
                        await self.poll_source(row["source_id"])
                        # Delay between sources
                        await asyncio.sleep(5)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Breach intel polling loop error: {e}")

            # Sleep between cycles
            await asyncio.sleep(60)

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    async def search_incidents(
        self,
        query: Optional[str] = None,
        incident_type: Optional[str] = None,
        severity: Optional[str] = None,
        source_id: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        Search breach intel incidents with filtering and pagination.
        Returns { items: [...], total: int }.
        """
        db = self._get_db()
        if not db or not db.pool:
            return {"items": [], "total": 0}

        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)

        where_clauses = []
        params = []
        param_idx = 1

        if query:
            where_clauses.append(
                f"(title ILIKE ${param_idx} OR summary ILIKE ${param_idx} OR external_id ILIKE ${param_idx})"
            )
            params.append(f"%{query}%")
            param_idx += 1

        if incident_type:
            where_clauses.append(f"incident_type = ${param_idx}")
            params.append(incident_type)
            param_idx += 1

        if severity:
            # Accept either a single value or a comma-separated list — the
            # frontend ticker passes "critical,high" expecting either-or.
            # Previously this matched the literal string and returned zero
            # rows, which is why the ticker has been silent.
            sev_list = [s.strip().lower() for s in str(severity).split(',') if s.strip()]
            if len(sev_list) == 1:
                where_clauses.append(f"LOWER(severity) = ${param_idx}")
                params.append(sev_list[0])
            else:
                where_clauses.append(f"LOWER(severity) = ANY(${param_idx}::text[])")
                params.append(sev_list)
            param_idx += 1

        if source_id:
            where_clauses.append(f"source_id = ${param_idx}")
            params.append(source_id)
            param_idx += 1

        if date_from:
            where_clauses.append(f"published_at >= ${param_idx}")
            params.append(date_from)
            param_idx += 1

        if date_to:
            where_clauses.append(f"published_at <= ${param_idx}")
            params.append(date_to)
            param_idx += 1

        where_sql = " AND ".join(where_clauses) if where_clauses else "1=1"

        try:
            async with db.tenant_acquire() as conn:
                # Get total count
                total = await conn.fetchval(
                    f"SELECT COUNT(*) FROM breach_intel_incidents WHERE {where_sql}",
                    *params,
                )

                # Get page of results
                rows = await conn.fetch(
                    f"""
                    SELECT id, source_id, title, external_id, url,
                           summary, published_at, incident_type, severity,
                           created_at
                    FROM breach_intel_incidents
                    WHERE {where_sql}
                    ORDER BY published_at DESC NULLS LAST, created_at DESC
                    LIMIT ${param_idx} OFFSET ${param_idx + 1}
                    """,
                    *params,
                    limit,
                    offset,
                )

                items = [dict(row) for row in rows]
                # Serialize for JSON / Pydantic compatibility
                for item in items:
                    # UUID -> str
                    if item.get("id") and not isinstance(item["id"], str):
                        item["id"] = str(item["id"])
                    # Map DB column names to response model names
                    if "source_id" in item:
                        item["source"] = item.pop("source_id")
                    if "url" in item and "source_url" not in item:
                        item["source_url"] = item.pop("url")
                    for key in ("published_at", "created_at"):
                        if item.get(key) and isinstance(item[key], datetime):
                            item[key] = item[key].isoformat()

                return {"items": items, "total": total}

        except Exception as e:
            logger.error(f"Failed to search breach intel incidents: {e}")
            return {"items": [], "total": 0}

    async def list_incidents(self, **kwargs) -> Dict[str, Any]:
        """Alias for search_incidents — used by the breach-intel list endpoint."""
        # Map 'search' kwarg to 'query' for search_incidents
        if "search" in kwargs:
            kwargs["query"] = kwargs.pop("search")
        # Parse date strings to datetime objects
        for key in ("date_from", "date_to"):
            if key in kwargs and kwargs[key] and isinstance(kwargs[key], str):
                try:
                    kwargs[key] = datetime.fromisoformat(kwargs[key])
                except ValueError:
                    kwargs.pop(key)
        return await self.search_incidents(**kwargs)

    async def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get a single incident by ID."""
        db = self._get_db()
        if not db or not db.pool:
            return None

        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)

        try:
            async with db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT i.*, s.name as source_name
                    FROM breach_intel_incidents i
                    LEFT JOIN breach_intel_sources s ON s.source_id = i.source_id
                    WHERE i.id = $1
                    """,
                    incident_id,
                )
                if not row:
                    return None
                result = dict(row)
                for key in ("published_at", "created_at"):
                    if result.get(key) and isinstance(result[key], datetime):
                        result[key] = result[key].isoformat()
                return result
        except Exception as e:
            logger.error(f"Failed to get breach intel incident {incident_id}: {e}")
            return None

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get dashboard statistics:
        - Total incidents
        - Counts by type
        - Counts by severity
        - Counts from last 24h, 7d, 30d
        - Source statuses
        """
        db = self._get_db()
        if not db or not db.pool:
            return {}

        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)

        try:
            async with db.tenant_acquire() as conn:
                # Total count
                total = await conn.fetchval(
                    "SELECT COUNT(*) FROM breach_intel_incidents"
                )

                # By type
                type_rows = await conn.fetch(
                    """
                    SELECT incident_type, COUNT(*) as count
                    FROM breach_intel_incidents
                    GROUP BY incident_type
                    ORDER BY count DESC
                    """
                )

                # By severity
                severity_rows = await conn.fetch(
                    """
                    SELECT severity, COUNT(*) as count
                    FROM breach_intel_incidents
                    GROUP BY severity
                    ORDER BY count DESC
                    """
                )

                # Recent counts (use created_at = when ingested into platform)
                last_24h = await conn.fetchval(
                    "SELECT COUNT(*) FROM breach_intel_incidents WHERE created_at >= NOW() - INTERVAL '24 hours'"
                )
                last_7d = await conn.fetchval(
                    "SELECT COUNT(*) FROM breach_intel_incidents WHERE created_at >= NOW() - INTERVAL '7 days'"
                )
                last_30d = await conn.fetchval(
                    "SELECT COUNT(*) FROM breach_intel_incidents WHERE created_at >= NOW() - INTERVAL '30 days'"
                )

                # Source statuses
                source_rows = await conn.fetch(
                    """
                    SELECT source_id, name, enabled, last_poll_at, last_success_at,
                           last_error, total_items, next_poll_at
                    FROM breach_intel_sources
                    ORDER BY name
                    """
                )

                sources = []
                for sr in source_rows:
                    s = dict(sr)
                    for key in ("last_poll_at", "last_success_at", "next_poll_at"):
                        if s.get(key) and isinstance(s[key], datetime):
                            s[key] = s[key].isoformat()
                    sources.append(s)

                return {
                    "total_incidents": total or 0,
                    "by_type": {row["incident_type"]: row["count"] for row in type_rows},
                    "by_severity": {row["severity"]: row["count"] for row in severity_rows},
                    "last_24h": last_24h or 0,
                    "last_7d": last_7d or 0,
                    "last_30d": last_30d or 0,
                    "sources": sources,
                }

        except Exception as e:
            logger.error(f"Failed to get breach intel stats: {e}")
            return {}

    async def get_timeline(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Get time series data for the last N days.
        Returns a list of { date, count, by_type: { ... } } entries.
        """
        db = self._get_db()
        if not db or not db.pool:
            return []

        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)

        try:
            async with db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT
                        DATE(COALESCE(published_at, created_at)) as date,
                        incident_type,
                        COUNT(*) as count
                    FROM breach_intel_incidents
                    WHERE COALESCE(published_at, created_at) >= NOW() - ($1 || ' days')::interval
                    GROUP BY date, incident_type
                    ORDER BY date ASC
                    """,
                    str(days),
                )

                # Pivot into { date -> { total, by_type } }
                timeline_map: Dict[str, Dict[str, Any]] = {}
                for row in rows:
                    date_str = row["date"].isoformat() if row["date"] else "unknown"
                    if date_str not in timeline_map:
                        timeline_map[date_str] = {"date": date_str, "count": 0, "by_type": {}}
                    entry = timeline_map[date_str]
                    entry["count"] += row["count"]
                    entry["by_type"][row["incident_type"]] = row["count"]

                # Fill in missing days with zeros
                result = []
                today = datetime.now(timezone.utc).date()
                for i in range(days - 1, -1, -1):
                    d = (today - timedelta(days=i)).isoformat()
                    if d in timeline_map:
                        result.append(timeline_map[d])
                    else:
                        result.append({"date": d, "count": 0, "by_type": {}})

                return result

        except Exception as e:
            logger.error(f"Failed to get breach intel timeline: {e}")
            return []

    # ------------------------------------------------------------------
    # Source management helpers
    # ------------------------------------------------------------------

    async def get_sources(self) -> List[Dict[str, Any]]:
        """Get all configured sources with their status."""
        db = self._get_db()
        if not db or not db.pool:
            return []

        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)

        try:
            async with db.tenant_acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT source_id, name, url, source_type, description,
                           poll_interval_minutes, enabled, default_incident_type,
                           default_severity, last_poll_at, last_success_at,
                           last_error, total_items, next_poll_at
                    FROM breach_intel_sources
                    ORDER BY name
                    """
                )
                results = []
                for row in rows:
                    d = dict(row)
                    for key in ("last_poll_at", "last_success_at", "next_poll_at"):
                        if d.get(key) and isinstance(d[key], datetime):
                            d[key] = d[key].isoformat()
                    results.append(d)
                return results
        except Exception as e:
            logger.error(f"Failed to get breach intel sources: {e}")
            return []

    async def set_source_enabled(self, source_id: str, enabled: bool) -> bool:
        """Enable or disable a source."""
        db = self._get_db()
        if not db or not db.pool:
            return False

        from services.postgres_db import set_platform_admin_mode
        set_platform_admin_mode(True)

        try:
            async with db.tenant_acquire() as conn:
                result = await conn.execute(
                    "UPDATE breach_intel_sources SET enabled = $1 WHERE source_id = $2",
                    enabled,
                    source_id,
                )
                return result == "UPDATE 1"
        except Exception as e:
            logger.error(f"Failed to update source {source_id}: {e}")
            return False


# ============================================================================
# SINGLETON
# ============================================================================

_breach_intel_service: Optional[BreachIntelService] = None


def get_breach_intel_service() -> BreachIntelService:
    """Get the global breach intel service instance."""
    global _breach_intel_service
    if _breach_intel_service is None:
        _breach_intel_service = BreachIntelService()
    return _breach_intel_service
