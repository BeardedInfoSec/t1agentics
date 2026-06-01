# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Threat Feed Poller Service

Manages polling of external threat intelligence feeds:
- Configurable polling intervals per feed
- Multiple feed formats (txt, csv, json, stix)
- Smart re-enrichment logic (only enrich if IOC reappears)
- Guardrails to prevent API exhaustion
- Feed appearance tracking for deduplication
"""

import asyncio
import aiohttp
import csv
import io
import json
import logging
import re
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple, Set
from enum import Enum
from dataclasses import dataclass, field

from services.threat_intel_service import (
    get_threat_intel_service,
    IOCType,
    IOCSourceType,
    EnrichmentTrigger,
    ThreatSeverity
)
from services.ioc_enforcement import enforce_ioc_limit

logger = logging.getLogger(__name__)


# ============================================================================
# MODELS
# ============================================================================

class FeedFormat(str, Enum):
    """Supported threat feed formats"""
    TXT_LINES = "txt_lines"      # Plain text, one IOC per line
    CSV = "csv"                   # CSV format
    JSON = "json"                 # JSON format
    JSON_LINES = "json_lines"     # JSON Lines (one JSON object per line)
    STIX = "stix"                 # STIX 2.x format
    MISP = "misp"                 # MISP format
    CUSTOM = "custom"             # Requires custom parser


class FeedCategory(str, Enum):
    """Feed categories"""
    IP_BLOCKLIST = "ip_blocklist"
    DOMAIN_BLOCKLIST = "domain_blocklist"
    URL_BLOCKLIST = "url_blocklist"
    HASH_LIST = "hash_list"
    MIXED = "mixed"
    CVE = "cve"
    OTHER = "other"


@dataclass
class ThreatFeedConfig:
    """Configuration for a threat feed"""
    feed_id: str
    name: str
    url: str
    format: FeedFormat
    category: FeedCategory
    description: str = ""
    poll_interval_minutes: int = 60
    enabled: bool = True
    max_iocs_per_poll: int = 10000

    # Parser config
    parser_config: Dict[str, Any] = field(default_factory=dict)

    # Guardrails
    drop_private_ips: bool = True
    drop_internal_domains: bool = True
    dedupe_window_hours: int = 24

    # IOC type override (for single-type feeds)
    ioc_type: Optional[IOCType] = None

    # Severity to assign to IOCs from this feed
    default_severity: ThreatSeverity = ThreatSeverity.MEDIUM


@dataclass
class FeedPollResult:
    """Result of polling a feed"""
    feed_id: str
    success: bool
    iocs_fetched: int = 0
    iocs_new: int = 0
    iocs_updated: int = 0
    iocs_skipped: int = 0
    iocs_for_reenrichment: int = 0
    error: Optional[str] = None
    duration_ms: int = 0


# ============================================================================
# PRECONFIGURED FEEDS
# ============================================================================

# Comprehensive free threat intel feeds for SOC operations
PRECONFIGURED_FEEDS: List[ThreatFeedConfig] = [

    # =========================================================================
    # IP REPUTATION / NETWORK THREATS
    # =========================================================================

    # --- Abuse.ch (Highly Recommended) ---
    ThreatFeedConfig(
        feed_id="abuse_ch_feodo_ips",
        name="Abuse.ch Feodo Tracker IPs",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="Feodo Tracker botnet C2 IP addresses - highly reliable",
        poll_interval_minutes=60,
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.HIGH,
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),
    ThreatFeedConfig(
        feed_id="abuse_ch_feodo_json",
        name="Abuse.ch Feodo Tracker JSON",
        url="https://feodotracker.abuse.ch/downloads/ipblocklist.json",
        format=FeedFormat.JSON,
        category=FeedCategory.IP_BLOCKLIST,
        description="Feodo Tracker C2 IPs with metadata (JSON format)",
        poll_interval_minutes=60,
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.HIGH,
        enabled=False,  # Disabled by default (redundant with txt version)
        parser_config={"ip_field": "ip_address"}
    ),
    ThreatFeedConfig(
        feed_id="abuse_ch_sslbl",
        name="Abuse.ch SSL Blacklist",
        url="https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
        format=FeedFormat.CSV,
        category=FeedCategory.HASH_LIST,
        description="Malicious SSL certificate SHA1 fingerprints",
        poll_interval_minutes=360,
        ioc_type=IOCType.HASH_SHA1,
        default_severity=ThreatSeverity.HIGH,
        parser_config={"hash_column": 1, "has_header": True}
    ),
    ThreatFeedConfig(
        feed_id="abuse_ch_threatfox",
        name="ThreatFox IOCs",
        url="https://threatfox.abuse.ch/export/json/recent/",
        format=FeedFormat.JSON,
        category=FeedCategory.MIXED,
        description="Mixed IOCs (IPs, domains, hashes) from ThreatFox",
        poll_interval_minutes=60,
        default_severity=ThreatSeverity.HIGH,
        parser_config={"ioc_field": "ioc", "type_field": "ioc_type"}
    ),

    # --- Blocklist.de ---
    ThreatFeedConfig(
        feed_id="blocklist_de_all",
        name="Blocklist.de All Attacks",
        url="https://lists.blocklist.de/lists/all.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="IPs involved in brute force, abuse, and scans",
        poll_interval_minutes=360,  # Every 6 hours
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.MEDIUM,
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),

    # --- Spamhaus ---
    ThreatFeedConfig(
        feed_id="spamhaus_drop",
        name="Spamhaus DROP List",
        url="https://www.spamhaus.org/drop/drop.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="Don't Route Or Peer - worst known hijacked netblocks",
        poll_interval_minutes=720,  # Every 12 hours
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.CRITICAL,
        parser_config={"skip_comments": True, "comment_char": ";", "extract_cidr": True}
    ),
    ThreatFeedConfig(
        feed_id="spamhaus_edrop",
        name="Spamhaus EDROP List",
        url="https://www.spamhaus.org/drop/edrop.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="Extended DROP list - additional worst offenders",
        poll_interval_minutes=720,  # Every 12 hours
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.CRITICAL,
        parser_config={"skip_comments": True, "comment_char": ";", "extract_cidr": True}
    ),

    # --- CrowdSec --- (REMOVED: requires API authentication, DNS fails without key)

    # =========================================================================
    # DOMAINS / URLs / PHISHING
    # =========================================================================

    # --- OpenPhish ---
    ThreatFeedConfig(
        feed_id="openphish_free",
        name="OpenPhish Free Feed",
        url="https://openphish.com/feed.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.URL_BLOCKLIST,
        description="Live phishing URLs - extremely common in SOCs",
        poll_interval_minutes=15,
        ioc_type=IOCType.URL,
        default_severity=ThreatSeverity.HIGH,
        parser_config={}
    ),

    # --- PhishTank --- (REMOVED: returns 403 Forbidden, requires API key registration)

    # --- URLhaus ---
    ThreatFeedConfig(
        feed_id="urlhaus_online",
        name="URLhaus Online Malware URLs",
        url="https://urlhaus.abuse.ch/downloads/text_online/",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.URL_BLOCKLIST,
        description="Currently online malware hosting URLs",
        poll_interval_minutes=15,
        ioc_type=IOCType.URL,
        default_severity=ThreatSeverity.HIGH,
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),
    # URLhaus Full Feed (JSON) - REMOVED: returns binary/gzip response causing decode errors

    # =========================================================================
    # FILE HASHES / MALWARE SAMPLES
    # =========================================================================

    # --- MalwareBazaar ---
    ThreatFeedConfig(
        feed_id="malwarebazaar_recent",
        name="MalwareBazaar Recent Hashes",
        url="https://bazaar.abuse.ch/export/txt/sha256/recent/",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.HASH_LIST,
        description="Recently submitted malware SHA256 hashes with family names",
        poll_interval_minutes=60,
        ioc_type=IOCType.HASH_SHA256,
        default_severity=ThreatSeverity.HIGH,
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),
    ThreatFeedConfig(
        feed_id="malwarebazaar_md5",
        name="MalwareBazaar MD5 Hashes",
        url="https://bazaar.abuse.ch/export/txt/md5/recent/",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.HASH_LIST,
        description="Recent malware MD5 hashes",
        poll_interval_minutes=60,
        ioc_type=IOCType.HASH_MD5,
        default_severity=ThreatSeverity.HIGH,
        enabled=False,  # Disabled by default
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),

    # =========================================================================
    # VULNERABILITY / EXPLOITATION FEEDS
    # =========================================================================

    # --- CISA KEV ---
    ThreatFeedConfig(
        feed_id="cisa_kev",
        name="CISA Known Exploited Vulnerabilities",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        format=FeedFormat.JSON,
        category=FeedCategory.CVE,
        description="CISA catalog of actively exploited CVEs - high-value intel",
        poll_interval_minutes=1440,  # Daily
        ioc_type=IOCType.CVE,
        default_severity=ThreatSeverity.CRITICAL,
        parser_config={"vulnerabilities_key": "vulnerabilities", "cve_field": "cveID"}
    ),

    # =========================================================================
    # AGGREGATORS / MIXED FEEDS
    # =========================================================================

    # --- ThreatFeeds.io --- (REMOVED: API returns 404, service appears dead)

    # --- GitHub Open IOC Repos ---
    ThreatFeedConfig(
        feed_id="github_open_iocs_ips",
        name="GitHub Open IOC IPs",
        url="https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="IP reputation from stamparm/ipsum - aggregated blocklist",
        poll_interval_minutes=360,
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.MEDIUM,
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),

    # --- Emerging Threats ---
    ThreatFeedConfig(
        feed_id="emergingthreats_compromised",
        name="Emerging Threats Compromised IPs",
        url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="Compromised IPs from Emerging Threats (ProofPoint)",
        poll_interval_minutes=360,
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.HIGH,
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),

    # --- C2 Intel Feeds ---
    ThreatFeedConfig(
        feed_id="c2_tracker_all",
        name="C2 Tracker All",
        url="https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="Known C2 server IPs from montysecurity C2-Tracker",
        poll_interval_minutes=120,
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.CRITICAL,
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),

    # --- Botvrij ---
    ThreatFeedConfig(
        feed_id="botvrij_dst_ip",
        name="Botvrij Destination IPs",
        url="https://www.botvrij.eu/data/ioclist.ip-dst.raw",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="Malicious destination IPs from Botvrij.eu",
        poll_interval_minutes=360,
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.HIGH,
        parser_config={}
    ),
    # Botvrij Domains - REMOVED: feed returns empty response (0 lines)

    # --- DShield ---
    ThreatFeedConfig(
        feed_id="dshield_top_attackers",
        name="DShield Top Attackers",
        url="https://www.dshield.org/block.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="SANS Internet Storm Center top attacking networks",
        poll_interval_minutes=1440,  # Daily
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.HIGH,
        parser_config={"skip_comments": True, "comment_char": "#", "extract_cidr": True}
    ),

    # --- Cinsscore ---
    ThreatFeedConfig(
        feed_id="cinsscore_badguys",
        name="CI Army Bad Guys",
        url="https://cinsscore.com/list/ci-badguys.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="CI Army list of malicious IPs",
        poll_interval_minutes=360,
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.MEDIUM,
        parser_config={}
    ),

    # --- Ransomware Tracker --- (REMOVED: returns 503, service deprecated)

    # --- Alienvault OTX (Public Pulse) ---
    ThreatFeedConfig(
        feed_id="alienvault_reputation",
        name="AlienVault IP Reputation",
        url="https://reputation.alienvault.com/reputation.generic",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="AlienVault OTX IP reputation data",
        poll_interval_minutes=1440,  # Daily
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.MEDIUM,
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),

    # --- Binary Defense ---
    ThreatFeedConfig(
        feed_id="binarydefense_banlist",
        name="Binary Defense IP Banlist",
        url="https://www.binarydefense.com/banlist.txt",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="Binary Defense Artillery Threat Intelligence",
        poll_interval_minutes=360,
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.HIGH,
        parser_config={"skip_comments": True, "comment_char": "#"}
    ),

    # --- Tor Exit Nodes (for context, not necessarily malicious) ---
    ThreatFeedConfig(
        feed_id="tor_exit_nodes",
        name="Tor Exit Nodes",
        url="https://check.torproject.org/torbulkexitlist",
        format=FeedFormat.TXT_LINES,
        category=FeedCategory.IP_BLOCKLIST,
        description="Current Tor exit node IPs - for situational awareness",
        poll_interval_minutes=60,
        ioc_type=IOCType.IP,
        default_severity=ThreatSeverity.LOW,  # Not malicious by default
        enabled=False,  # Disabled by default - enable for context
        parser_config={}
    ),
]


# ============================================================================
# SERVICE
# ============================================================================

class ThreatFeedService:
    """
    Threat Feed Poller Service

    Polls external threat intel feeds and ingests IOCs with proper
    source tracking and smart re-enrichment logic.
    """

    # Patterns for IOC detection
    IP_PATTERN = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$')
    URL_PATTERN = re.compile(r'^https?://')
    SHA256_PATTERN = re.compile(r'^[a-fA-F0-9]{64}$')
    SHA1_PATTERN = re.compile(r'^[a-fA-F0-9]{40}$')
    MD5_PATTERN = re.compile(r'^[a-fA-F0-9]{32}$')
    CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d+$', re.IGNORECASE)

    # Private IP ranges to filter
    PRIVATE_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('224.0.0.0/4'),
        ipaddress.ip_network('240.0.0.0/4'),
    ]

    # Internal domain suffixes to filter
    INTERNAL_DOMAINS = {'.local', '.internal', '.corp', '.lan', '.home', '.localdomain'}

    # Re-enrichment lookback window (days)
    REENRICHMENT_LOOKBACK_DAYS = 30

    def __init__(self):
        self.db = None
        self._feeds: Dict[str, ThreatFeedConfig] = {}
        self._running = False
        self._poll_task: Optional[asyncio.Task] = None

        # Load preconfigured feeds
        for feed in PRECONFIGURED_FEEDS:
            self._feeds[feed.feed_id] = feed

    def _get_db(self):
        """Get database connection"""
        if self.db is None:
            try:
                from services.postgres_db import postgres_db
                if postgres_db.connected:
                    self.db = postgres_db
            except Exception as e:
                logger.error(f"Failed to connect to database: {e}")
        return self.db

    # ========================================================================
    # FEED MANAGEMENT
    # ========================================================================

    def get_feed(self, feed_id: str) -> Optional[ThreatFeedConfig]:
        """Get a feed configuration by ID"""
        return self._feeds.get(feed_id)

    def list_feeds(self) -> List[ThreatFeedConfig]:
        """List all configured feeds"""
        return list(self._feeds.values())

    def add_feed(self, config: ThreatFeedConfig) -> None:
        """Add a new feed configuration"""
        self._feeds[config.feed_id] = config

    def remove_feed(self, feed_id: str) -> bool:
        """Remove a feed configuration"""
        if feed_id in self._feeds:
            del self._feeds[feed_id]
            return True
        return False

    def enable_feed(self, feed_id: str, enabled: bool = True) -> bool:
        """Enable or disable a feed"""
        if feed_id in self._feeds:
            self._feeds[feed_id].enabled = enabled
            return True
        return False

    # ========================================================================
    # POLLING
    # ========================================================================

    async def poll_feed(self, feed_id: str) -> FeedPollResult:
        """Poll a single feed and ingest IOCs"""
        feed = self.get_feed(feed_id)
        if not feed:
            return FeedPollResult(
                feed_id=feed_id,
                success=False,
                error=f"Feed not found: {feed_id}"
            )

        if not feed.enabled:
            return FeedPollResult(
                feed_id=feed_id,
                success=False,
                error="Feed is disabled"
            )

        start_time = datetime.utcnow()

        try:
            # Fetch feed content
            content = await self._fetch_feed(feed.url)
            if not content:
                return FeedPollResult(
                    feed_id=feed_id,
                    success=False,
                    error="Failed to fetch feed content"
                )

            # Parse IOCs from content
            raw_iocs = await self._parse_feed(feed, content)

            # Apply guardrails
            filtered_iocs = self._apply_guardrails(feed, raw_iocs)

            # Limit IOCs per poll
            if len(filtered_iocs) > feed.max_iocs_per_poll:
                filtered_iocs = filtered_iocs[:feed.max_iocs_per_poll]
                logger.warning(f"Feed {feed_id} truncated to {feed.max_iocs_per_poll} IOCs")

            # Ingest IOCs with source tracking
            result = await self._ingest_iocs(feed, filtered_iocs)

            # Update feed stats in database
            await self._update_feed_stats(feed, result)

            # Enforce IOC storage limit — evict oldest if over cap
            try:
                from services.postgres_db import postgres_db
                if postgres_db.pool:
                    async with postgres_db.tenant_acquire() as conn:
                        eviction = await enforce_ioc_limit(conn)
                        if eviction.get("enforced"):
                            logger.info(
                                f"Feed {feed_id}: IOC eviction triggered, "
                                f"deleted {eviction['deleted']} oldest IOCs"
                            )
            except Exception as e:
                logger.warning(f"IOC limit enforcement after feed poll failed (non-fatal): {e}")

            duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
            result.duration_ms = duration_ms

            logger.info(
                f"Feed {feed_id} polled: {result.iocs_new} new, "
                f"{result.iocs_updated} updated, {result.iocs_skipped} skipped, "
                f"{result.iocs_for_reenrichment} for re-enrichment"
            )

            return result

        except Exception as e:
            logger.error(f"Error polling feed {feed_id}: {e}")
            return FeedPollResult(
                feed_id=feed_id,
                success=False,
                error=str(e),
                duration_ms=int((datetime.utcnow() - start_time).total_seconds() * 1000)
            )

    async def poll_all_feeds(self) -> Dict[str, FeedPollResult]:
        """Poll all enabled feeds"""
        results = {}
        for feed_id, feed in self._feeds.items():
            if feed.enabled:
                results[feed_id] = await self.poll_feed(feed_id)
        return results

    async def _fetch_feed(self, url: str, timeout: int = 60) -> Optional[str]:
        """Fetch feed content from URL"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    if response.status == 200:
                        return await response.text()
                    else:
                        logger.error(f"Feed fetch failed: {response.status}")
                        return None
        except Exception as e:
            logger.error(f"Feed fetch error: {e}")
            return None

    async def _parse_feed(
        self,
        feed: ThreatFeedConfig,
        content: str
    ) -> List[Tuple[str, IOCType]]:
        """Parse feed content into list of (ioc_value, ioc_type) tuples"""
        if feed.format == FeedFormat.TXT_LINES:
            return self._parse_txt_lines(feed, content)
        elif feed.format == FeedFormat.CSV:
            return self._parse_csv(feed, content)
        elif feed.format == FeedFormat.JSON:
            return self._parse_json(feed, content)
        elif feed.format == FeedFormat.JSON_LINES:
            return self._parse_json_lines(feed, content)
        elif feed.format == FeedFormat.STIX:
            return self._parse_stix(feed, content)
        elif feed.format == FeedFormat.MISP:
            return self._parse_misp(feed, content)
        else:
            logger.warning(f"Unsupported feed format: {feed.format}")
            return []

    def _parse_txt_lines(
        self,
        feed: ThreatFeedConfig,
        content: str
    ) -> List[Tuple[str, IOCType]]:
        """Parse plain text feed with one IOC per line"""
        iocs = []
        skip_comments = feed.parser_config.get('skip_comments', True)
        comment_char = feed.parser_config.get('comment_char', '#')
        extract_cidr = feed.parser_config.get('extract_cidr', False)
        # For tab/space separated formats, take first column only
        first_column_only = feed.parser_config.get('first_column_only', False)

        for line in content.split('\n'):
            line = line.strip()

            # Skip empty lines and comments
            if not line:
                continue
            if skip_comments and line.startswith(comment_char):
                continue

            # Handle tab/space separated values - extract first column (the IOC)
            # This handles formats like "IP\tcount" or "IP score" (e.g., ipsum feed)
            if first_column_only or '\t' in line:
                line = line.split('\t')[0].strip()
                if not line:
                    continue

            # Handle CIDR notation (e.g., Spamhaus DROP)
            if extract_cidr and '/' in line:
                # Extract the network address
                parts = line.split(';')[0].strip().split('/')
                if len(parts) == 2:
                    line = parts[0]  # Just the IP

            # Detect IOC type
            ioc_type = feed.ioc_type or self._detect_ioc_type(line)
            if ioc_type:
                iocs.append((line, ioc_type))

        return iocs

    def _parse_csv(
        self,
        feed: ThreatFeedConfig,
        content: str
    ) -> List[Tuple[str, IOCType]]:
        """Parse CSV feed"""
        iocs = []
        has_header = feed.parser_config.get('has_header', True)
        ioc_column = feed.parser_config.get('ioc_column', 0)
        url_column = feed.parser_config.get('url_column')
        hash_column = feed.parser_config.get('hash_column')
        type_column = feed.parser_config.get('type_column')

        # Determine which column to use
        if url_column is not None:
            ioc_column = url_column
        elif hash_column is not None:
            ioc_column = hash_column

        try:
            reader = csv.reader(io.StringIO(content))

            if has_header:
                next(reader, None)  # Skip header

            for row in reader:
                if len(row) <= ioc_column:
                    continue

                value = row[ioc_column].strip().strip('"')
                if not value:
                    continue

                # Try to get type from type column
                if type_column is not None and len(row) > type_column:
                    type_str = row[type_column].strip().lower()
                    ioc_type = self._map_type_string(type_str) or feed.ioc_type
                else:
                    ioc_type = feed.ioc_type or self._detect_ioc_type(value)

                if ioc_type:
                    iocs.append((value, ioc_type))

        except Exception as e:
            logger.error(f"CSV parsing error: {e}")

        return iocs

    def _parse_json(
        self,
        feed: ThreatFeedConfig,
        content: str
    ) -> List[Tuple[str, IOCType]]:
        """Parse JSON feed"""
        iocs = []

        try:
            data = json.loads(content)

            # Handle CISA KEV format
            if feed.feed_id == "cisa_kev":
                vulnerabilities_key = feed.parser_config.get('vulnerabilities_key', 'vulnerabilities')
                cve_field = feed.parser_config.get('cve_field', 'cveID')

                items = data.get(vulnerabilities_key, [])
                for item in items:
                    cve = item.get(cve_field)
                    if cve:
                        iocs.append((cve.upper(), IOCType.CVE))

            # Generic JSON array handling
            elif isinstance(data, list):
                ip_field = feed.parser_config.get('ip_field', 'ip')
                for item in data:
                    if isinstance(item, dict):
                        value = item.get(ip_field)
                        if value:
                            ioc_type = feed.ioc_type or self._detect_ioc_type(value)
                            if ioc_type:
                                iocs.append((value, ioc_type))
                    elif isinstance(item, str):
                        ioc_type = feed.ioc_type or self._detect_ioc_type(item)
                        if ioc_type:
                            iocs.append((item, ioc_type))

        except Exception as e:
            logger.error(f"JSON parsing error: {e}")

        return iocs

    def _parse_json_lines(
        self,
        feed: ThreatFeedConfig,
        content: str
    ) -> List[Tuple[str, IOCType]]:
        """Parse JSON Lines feed"""
        iocs = []
        ip_field = feed.parser_config.get('ip_field', 'ip')

        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue

            try:
                item = json.loads(line)
                value = item.get(ip_field) if isinstance(item, dict) else item
                if value:
                    ioc_type = feed.ioc_type or self._detect_ioc_type(str(value))
                    if ioc_type:
                        iocs.append((str(value), ioc_type))
            except:
                continue

        return iocs

    def _parse_stix(
        self,
        feed: ThreatFeedConfig,
        content: str
    ) -> List[Tuple[str, IOCType]]:
        """
        Parse STIX 2.x bundle format.

        STIX bundles contain objects like:
        - indicator: Contains patterns for IOCs
        - malware: Malware definitions
        - threat-actor: Threat actor info

        We extract indicators and parse their patterns for IOC values.
        """
        iocs = []

        try:
            bundle = json.loads(content)

            # STIX 2.x bundles have type "bundle" and contain objects array
            if bundle.get('type') != 'bundle':
                logger.warning("STIX content is not a bundle, attempting direct object parsing")
                objects = [bundle] if bundle.get('type') else []
            else:
                objects = bundle.get('objects', [])

            logger.info(f"Parsing STIX bundle with {len(objects)} objects")

            for obj in objects:
                obj_type = obj.get('type', '')

                # Parse indicators - these contain the actual IOC patterns
                if obj_type == 'indicator':
                    ioc_list = self._parse_stix_indicator(obj)
                    iocs.extend(ioc_list)

                # Parse observables (STIX 2.1 observed-data)
                elif obj_type == 'observed-data':
                    ioc_list = self._parse_stix_observed_data(obj)
                    iocs.extend(ioc_list)

                # Parse SCO (STIX Cyber Observables) directly
                elif obj_type in ('ipv4-addr', 'ipv6-addr', 'domain-name', 'url', 'file', 'email-addr'):
                    ioc_list = self._parse_stix_sco(obj)
                    iocs.extend(ioc_list)

            logger.info(f"Extracted {len(iocs)} IOCs from STIX bundle")

        except json.JSONDecodeError as e:
            logger.error(f"STIX JSON parsing error: {e}")
        except Exception as e:
            logger.error(f"STIX parsing error: {e}")

        return iocs

    def _parse_stix_indicator(self, indicator: dict) -> List[Tuple[str, IOCType]]:
        """
        Parse a STIX indicator object to extract IOCs.

        Indicator patterns use STIX patterning language, e.g.:
        - [ipv4-addr:value = '192.168.1.1']
        - [domain-name:value = 'evil.com']
        - [file:hashes.'SHA-256' = 'abc123...']
        """
        iocs = []
        pattern = indicator.get('pattern', '')

        if not pattern:
            return iocs

        # Extract values from STIX pattern syntax
        # Pattern format: [type:property = 'value']
        import re

        # Match patterns like: [ipv4-addr:value = '1.2.3.4']
        ipv4_matches = re.findall(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", pattern)
        for ip in ipv4_matches:
            iocs.append((ip, IOCType.IP))

        # Match patterns like: [ipv6-addr:value = '::1']
        ipv6_matches = re.findall(r"\[ipv6-addr:value\s*=\s*'([^']+)'\]", pattern)
        for ip in ipv6_matches:
            iocs.append((ip, IOCType.IP))

        # Match patterns like: [domain-name:value = 'evil.com']
        domain_matches = re.findall(r"\[domain-name:value\s*=\s*'([^']+)'\]", pattern)
        for domain in domain_matches:
            iocs.append((domain, IOCType.DOMAIN))

        # Match patterns like: [url:value = 'http://evil.com/malware']
        url_matches = re.findall(r"\[url:value\s*=\s*'([^']+)'\]", pattern)
        for url in url_matches:
            iocs.append((url, IOCType.URL))

        # Match patterns like: [file:hashes.'SHA-256' = 'abc123']
        sha256_matches = re.findall(r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for hash_val in sha256_matches:
            iocs.append((hash_val, IOCType.HASH_SHA256))

        # Match patterns like: [file:hashes.'SHA-1' = 'abc123']
        sha1_matches = re.findall(r"\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for hash_val in sha1_matches:
            iocs.append((hash_val, IOCType.HASH_SHA1))

        # Match patterns like: [file:hashes.'MD5' = 'abc123']
        md5_matches = re.findall(r"\[file:hashes\.'MD5'\s*=\s*'([^']+)'\]", pattern, re.IGNORECASE)
        for hash_val in md5_matches:
            iocs.append((hash_val, IOCType.HASH_MD5))

        # Match patterns like: [email-addr:value = 'bad@evil.com']
        email_matches = re.findall(r"\[email-addr:value\s*=\s*'([^']+)'\]", pattern)
        for email in email_matches:
            iocs.append((email, IOCType.EMAIL))

        return iocs

    def _parse_stix_observed_data(self, observed_data: dict) -> List[Tuple[str, IOCType]]:
        """Parse STIX 2.1 observed-data objects"""
        iocs = []
        objects = observed_data.get('objects', {})

        # STIX 2.0 uses dict with string keys, STIX 2.1 uses object_refs
        if isinstance(objects, dict):
            for obj_id, obj in objects.items():
                ioc_list = self._parse_stix_sco(obj)
                iocs.extend(ioc_list)

        return iocs

    def _parse_stix_sco(self, sco: dict) -> List[Tuple[str, IOCType]]:
        """Parse a STIX Cyber Observable (SCO) object"""
        iocs = []
        sco_type = sco.get('type', '')

        if sco_type == 'ipv4-addr':
            value = sco.get('value')
            if value:
                iocs.append((value, IOCType.IP))

        elif sco_type == 'ipv6-addr':
            value = sco.get('value')
            if value:
                iocs.append((value, IOCType.IP))

        elif sco_type == 'domain-name':
            value = sco.get('value')
            if value:
                iocs.append((value, IOCType.DOMAIN))

        elif sco_type == 'url':
            value = sco.get('value')
            if value:
                iocs.append((value, IOCType.URL))

        elif sco_type == 'email-addr':
            value = sco.get('value')
            if value:
                iocs.append((value, IOCType.EMAIL))

        elif sco_type == 'file':
            # Extract file hashes
            hashes = sco.get('hashes', {})
            if 'SHA-256' in hashes:
                iocs.append((hashes['SHA-256'], IOCType.HASH_SHA256))
            if 'SHA-1' in hashes:
                iocs.append((hashes['SHA-1'], IOCType.HASH_SHA1))
            if 'MD5' in hashes:
                iocs.append((hashes['MD5'], IOCType.HASH_MD5))

        return iocs

    def _parse_misp(
        self,
        feed: ThreatFeedConfig,
        content: str
    ) -> List[Tuple[str, IOCType]]:
        """
        Parse MISP JSON export format.

        MISP exports contain events with attributes, where attributes
        contain the actual IOC values with type information.
        """
        iocs = []

        try:
            data = json.loads(content)

            # MISP can export as single event or event collection
            events = []
            if isinstance(data, dict):
                if 'Event' in data:
                    events = [data['Event']]
                elif 'response' in data:
                    # MISP API response format
                    events = [item.get('Event', item) for item in data.get('response', [])]
                elif 'Attribute' in data:
                    # Single event with attributes
                    events = [data]
            elif isinstance(data, list):
                events = [item.get('Event', item) for item in data]

            logger.info(f"Parsing {len(events)} MISP events")

            for event in events:
                attributes = event.get('Attribute', [])

                for attr in attributes:
                    ioc_list = self._parse_misp_attribute(attr)
                    iocs.extend(ioc_list)

                # Also check for Object attributes (galaxies, etc.)
                objects = event.get('Object', [])
                for obj in objects:
                    obj_attrs = obj.get('Attribute', [])
                    for attr in obj_attrs:
                        ioc_list = self._parse_misp_attribute(attr)
                        iocs.extend(ioc_list)

            logger.info(f"Extracted {len(iocs)} IOCs from MISP events")

        except json.JSONDecodeError as e:
            logger.error(f"MISP JSON parsing error: {e}")
        except Exception as e:
            logger.error(f"MISP parsing error: {e}")

        return iocs

    def _parse_misp_attribute(self, attr: dict) -> List[Tuple[str, IOCType]]:
        """Parse a MISP attribute to extract IOCs"""
        iocs = []
        attr_type = attr.get('type', '')
        value = attr.get('value', '')

        if not value:
            return iocs

        # Map MISP types to IOCType
        type_mapping = {
            'ip-src': IOCType.IP,
            'ip-dst': IOCType.IP,
            'ip-src|port': IOCType.IP,
            'ip-dst|port': IOCType.IP,
            'domain': IOCType.DOMAIN,
            'domain|ip': IOCType.DOMAIN,
            'hostname': IOCType.DOMAIN,
            'url': IOCType.URL,
            'link': IOCType.URL,
            'uri': IOCType.URL,
            'md5': IOCType.HASH_MD5,
            'sha1': IOCType.HASH_SHA1,
            'sha256': IOCType.HASH_SHA256,
            'sha512': IOCType.HASH_SHA256,  # Map to SHA256 as closest
            'ssdeep': IOCType.HASH_SHA256,
            'filename|md5': IOCType.HASH_MD5,
            'filename|sha1': IOCType.HASH_SHA1,
            'filename|sha256': IOCType.HASH_SHA256,
            'malware-sample': IOCType.HASH_SHA256,
            'email-src': IOCType.EMAIL,
            'email-dst': IOCType.EMAIL,
            'email': IOCType.EMAIL,
            'email-subject': None,  # Skip these
            'email-body': None,
            'vulnerability': IOCType.CVE,
            'cve': IOCType.CVE,
        }

        ioc_type = type_mapping.get(attr_type)

        if ioc_type:
            # Handle composite types (e.g., 'ip-src|port' -> extract just IP)
            if '|' in attr_type and '|' in value:
                value = value.split('|')[0]

            iocs.append((value, ioc_type))

        return iocs

    def _detect_ioc_type(self, value: str) -> Optional[IOCType]:
        """Detect the type of an IOC from its value"""
        value = value.strip()

        if self.CVE_PATTERN.match(value):
            return IOCType.CVE
        if self.URL_PATTERN.match(value):
            return IOCType.URL
        if self.SHA256_PATTERN.match(value):
            return IOCType.HASH_SHA256
        if self.SHA1_PATTERN.match(value):
            return IOCType.HASH_SHA1
        if self.MD5_PATTERN.match(value):
            return IOCType.HASH_MD5
        if self.IP_PATTERN.match(value):
            return IOCType.IP
        if self.DOMAIN_PATTERN.match(value):
            return IOCType.DOMAIN

        return None

    def _map_type_string(self, type_str: str) -> Optional[IOCType]:
        """Map type string from feeds to IOCType"""
        type_map = {
            'ip': IOCType.IP,
            'ip:port': IOCType.IP,
            'domain': IOCType.DOMAIN,
            'url': IOCType.URL,
            'sha256': IOCType.HASH_SHA256,
            'sha256_hash': IOCType.HASH_SHA256,
            'sha1': IOCType.HASH_SHA1,
            'sha1_hash': IOCType.HASH_SHA1,
            'md5': IOCType.HASH_MD5,
            'md5_hash': IOCType.HASH_MD5,
            'hash': IOCType.HASH_SHA256,
            'file_hash': IOCType.HASH_SHA256,
        }
        return type_map.get(type_str.lower())

    def _apply_guardrails(
        self,
        feed: ThreatFeedConfig,
        iocs: List[Tuple[str, IOCType]]
    ) -> List[Tuple[str, IOCType]]:
        """Apply guardrails to filter out unwanted IOCs"""
        filtered = []

        for value, ioc_type in iocs:
            # Drop private IPs
            if feed.drop_private_ips and ioc_type == IOCType.IP:
                if self._is_private_ip(value):
                    continue

            # Drop internal domains
            if feed.drop_internal_domains and ioc_type == IOCType.DOMAIN:
                if self._is_internal_domain(value):
                    continue

            # Extract IP from IP:port format
            if ioc_type == IOCType.IP and ':' in value:
                value = value.split(':')[0]

            filtered.append((value, ioc_type))

        return filtered

    def _is_private_ip(self, ip_str: str) -> bool:
        """Check if IP is in private/reserved range"""
        try:
            ip = ipaddress.ip_address(ip_str)
            for network in self.PRIVATE_NETWORKS:
                if ip in network:
                    return True
            return False
        except:
            return False

    def _is_internal_domain(self, domain: str) -> bool:
        """Check if domain is an internal domain"""
        domain_lower = domain.lower()
        for suffix in self.INTERNAL_DOMAINS:
            if domain_lower.endswith(suffix):
                return True
        return False

    async def _ingest_iocs(
        self,
        feed: ThreatFeedConfig,
        iocs: List[Tuple[str, IOCType]]
    ) -> FeedPollResult:
        """Ingest IOCs into the database with smart re-enrichment logic"""
        threat_intel = get_threat_intel_service()

        result = FeedPollResult(
            feed_id=feed.feed_id,
            success=True,
            iocs_fetched=len(iocs)
        )

        for value, ioc_type in iocs:
            try:
                # Check if IOC already exists
                existing = await threat_intel.get_ioc(value, ioc_type)

                if existing:
                    result.iocs_updated += 1

                    # DISABLED: Don't auto-enrich feed IOCs to avoid API quota exhaustion
                    # Feed IOCs are already classified as malicious from trusted sources
                    # Enrichment should only happen for manual IOC submissions or alerts
                    #
                    # Previous logic (disabled):
                    # should_reenrich = self._should_reenrich(existing)
                    # if should_reenrich:
                    #     result.iocs_for_reenrichment += 1
                    #     await self._queue_for_reenrichment(existing)
                    pass  # Skip enrichment for feed IOCs
                else:
                    result.iocs_new += 1

                # Add/update IOC with feed tracking
                # Default tags: blocklist, feed name (human-readable), category
                ioc_tags = ["blocklist", feed.name, feed.category.value]

                # IOCs from threat feeds are considered malicious by default
                await threat_intel.add_ioc(
                    value=value,
                    ioc_type=ioc_type,
                    source=feed.name,
                    severity=feed.default_severity,
                    tags=ioc_tags,
                    source_type=IOCSourceType.THREAT_FEED,
                    source_id=feed.feed_id,
                    feed_name=feed.name,  # Use human-readable name
                    is_from_feed=True,
                    reputation='malicious'  # Feed IOCs are malicious
                )

            except Exception as e:
                logger.warning(f"Failed to ingest IOC {value}: {e}")
                result.iocs_skipped += 1

        return result

    def _should_reenrich(self, ioc) -> bool:
        """Determine if an IOC should be re-enriched"""
        # Never enriched - always enrich
        if not ioc.last_enriched_at:
            return True

        # Check if last enrichment was within lookback window
        lookback = datetime.utcnow() - timedelta(days=self.REENRICHMENT_LOOKBACK_DAYS)
        if ioc.last_enriched_at < lookback:
            return True

        return False

    async def _queue_for_reenrichment(self, ioc) -> None:
        """Queue an IOC for re-enrichment (using job queue)"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            async with db.tenant_acquire() as conn:
                # Add to job queue for background processing
                await conn.execute(
                    """
                    INSERT INTO job_queue (queue_name, job_type, payload, priority)
                    VALUES ('threat_intel', 'reenrich_ioc', $1::jsonb, 5)
                    ON CONFLICT DO NOTHING
                    """,
                    json.dumps({
                        "ioc_value": ioc.value,
                        "ioc_type": ioc.type,
                        "trigger": "feed_reappear"
                    })
                )
        except Exception as e:
            logger.warning(f"Failed to queue IOC for re-enrichment: {e}")

    async def _update_feed_stats(
        self,
        feed: ThreatFeedConfig,
        result: FeedPollResult,
        tenant_id=None
    ) -> None:
        """Update feed stats in database for a specific tenant"""
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            import uuid as _uuid

            # Resolve tenant_id: explicit param > ContextVar > platform owner
            if tenant_id is None:
                from middleware.tenant_middleware import get_current_tenant_id
                try:
                    tenant_id = _uuid.UUID(get_current_tenant_id())
                except Exception:
                    from config.constants import PLATFORM_OWNER_TENANT_ID
                    tenant_id = _uuid.UUID(PLATFORM_OWNER_TENANT_ID)
            elif not isinstance(tenant_id, _uuid.UUID):
                tenant_id = _uuid.UUID(str(tenant_id))

            async with db.tenant_acquire() as conn:
                # Get the actual count of IOCs from this feed for this tenant
                ioc_count_row = await conn.fetchrow(
                    "SELECT COUNT(*) as cnt FROM iocs WHERE feed_name = $1",
                    feed.name
                )
                total_iocs = ioc_count_row['cnt'] if ioc_count_row else 0

                await conn.execute(
                    """
                    INSERT INTO threat_feeds (
                        feed_id, name, description, category, url, format,
                        poll_interval_minutes, enabled, last_poll_at,
                        last_poll_status, last_poll_ioc_count, total_iocs_ingested,
                        tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                    ON CONFLICT (feed_id, tenant_id) DO UPDATE SET
                        last_poll_at = $9,
                        last_poll_status = $10,
                        last_poll_ioc_count = $11,
                        total_iocs_ingested = $12,
                        next_poll_at = $9 + ($7 || ' minutes')::interval
                    """,
                    feed.feed_id,
                    feed.name,
                    feed.description,
                    feed.category.value,
                    feed.url,
                    feed.format.value,
                    feed.poll_interval_minutes,
                    feed.enabled,
                    datetime.utcnow(),
                    'success' if result.success else 'failed',
                    result.iocs_fetched,
                    total_iocs,
                    tenant_id
                )

                # Log the ingestion
                await conn.execute(
                    """
                    INSERT INTO threat_feed_ingestion_log (
                        feed_id, started_at, completed_at, duration_ms,
                        status, iocs_fetched, iocs_new, iocs_updated, iocs_skipped
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                    """,
                    feed.feed_id,
                    datetime.utcnow() - timedelta(milliseconds=result.duration_ms),
                    datetime.utcnow(),
                    result.duration_ms,
                    'success' if result.success else 'failed',
                    result.iocs_fetched,
                    result.iocs_new,
                    result.iocs_updated,
                    result.iocs_skipped
                )

        except Exception as e:
            logger.warning(f"Failed to update feed stats: {e}")

    # ========================================================================
    # BACKGROUND POLLING
    # ========================================================================

    async def start_polling(self) -> None:
        """Start background polling of all feeds"""
        if self._running:
            return

        self._running = True
        self._poll_task = asyncio.create_task(self._polling_loop())
        logger.info("Threat feed polling started")

    async def stop_polling(self) -> None:
        """Stop background polling"""
        self._running = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        logger.info("Threat feed polling stopped")

    async def _seed_feeds_to_db(self) -> None:
        """
        Seed enabled preconfigured feeds into the threat_feeds database table
        for EVERY tenant. Each tenant gets their own copy of all enabled feeds.
        """
        db = self._get_db()
        if not db or not db.pool:
            return

        try:
            import uuid as _uuid

            async with db.tenant_acquire() as conn:
                # Get all tenant IDs
                tenant_rows = await conn.fetch("SELECT id FROM tenants")
                if not tenant_rows:
                    logger.warning("No tenants found — skipping feed seeding")
                    return

                total_seeded = 0
                for tenant_row in tenant_rows:
                    tid = tenant_row['id']
                    seeded = 0
                    for feed in self._feeds.values():
                        if not feed.enabled:
                            continue
                        try:
                            await conn.execute(
                                """
                                INSERT INTO threat_feeds (
                                    feed_id, name, description, category, url, format,
                                    poll_interval_minutes, enabled, tenant_id
                                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                                ON CONFLICT (feed_id, tenant_id) DO NOTHING
                                """,
                                feed.feed_id,
                                feed.name,
                                feed.description,
                                feed.category.value,
                                feed.url,
                                feed.format.value,
                                feed.poll_interval_minutes,
                                feed.enabled,
                                tid
                            )
                            seeded += 1
                        except Exception as e:
                            logger.warning(f"Failed to seed feed {feed.feed_id} for tenant {tid}: {e}")
                    total_seeded += seeded

                logger.info(f"Seeded {total_seeded} enabled feeds across {len(tenant_rows)} tenants")

        except Exception as e:
            logger.error(f"Failed to seed feeds to database: {e}")

    async def _polling_loop(self) -> None:
        """
        Main polling loop — per-tenant architecture.

        Each feed URL is fetched ONCE, then IOCs are ingested separately
        for every tenant that has that feed enabled.
        """
        from services.postgres_db import set_platform_admin_mode
        from middleware.tenant_middleware import current_tenant_id
        from collections import defaultdict

        # Platform admin mode for seeding (cross-tenant writes)
        set_platform_admin_mode(True)
        await self._seed_feeds_to_db()

        while self._running:
            try:
                db = self._get_db()
                if not db or not db.pool:
                    await asyncio.sleep(60)
                    continue

                # --- Phase 1: Cross-tenant query for all due feeds ---
                set_platform_admin_mode(True)
                async with db.tenant_acquire() as conn:
                    due_feeds = await conn.fetch(
                        """
                        SELECT feed_id, tenant_id FROM threat_feeds
                        WHERE enabled = TRUE
                          AND (next_poll_at IS NULL OR next_poll_at <= NOW())
                        """
                    )

                if not due_feeds:
                    await asyncio.sleep(60)
                    continue

                # Group by feed_id so we fetch each URL only once
                feed_tenants = defaultdict(list)
                for row in due_feeds:
                    feed_tenants[row['feed_id']].append(row['tenant_id'])

                # --- Phase 2: For each unique feed, fetch once, ingest per tenant ---
                for feed_id, tenant_ids in feed_tenants.items():
                    if not self._running:
                        break

                    feed = self.get_feed(feed_id)
                    if not feed or not feed.enabled:
                        continue

                    # Fetch + parse + filter ONCE (no tenant context needed)
                    set_platform_admin_mode(True)
                    content = await self._fetch_feed(feed.url)
                    if not content:
                        # Mark feed as failed for all tenants
                        fail_result = FeedPollResult(
                            feed_id=feed_id, success=False, error="Failed to fetch"
                        )
                        for tid in tenant_ids:
                            current_tenant_id.set(str(tid))
                            set_platform_admin_mode(False)
                            await self._update_feed_stats(feed, fail_result, tid)
                        set_platform_admin_mode(True)
                        await asyncio.sleep(2)
                        continue

                    raw_iocs = await self._parse_feed(feed, content)
                    filtered_iocs = self._apply_guardrails(feed, raw_iocs)
                    if len(filtered_iocs) > feed.max_iocs_per_poll:
                        filtered_iocs = filtered_iocs[:feed.max_iocs_per_poll]

                    # Ingest for EACH tenant
                    start_time = datetime.utcnow()
                    for tid in tenant_ids:
                        if not self._running:
                            break

                        # Switch to tenant context (RLS filters naturally)
                        set_platform_admin_mode(False)
                        current_tenant_id.set(str(tid))

                        result = await self._ingest_iocs(feed, filtered_iocs)
                        duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
                        result.duration_ms = duration_ms

                        await self._update_feed_stats(feed, result, tid)

                        # IOC limit enforcement per tenant
                        try:
                            async with db.tenant_acquire() as conn:
                                eviction = await enforce_ioc_limit(conn)
                                if eviction.get("enforced"):
                                    logger.info(
                                        f"Feed {feed_id} tenant {tid}: "
                                        f"evicted {eviction['deleted']} IOCs"
                                    )
                        except Exception as e:
                            logger.warning(f"IOC limit enforcement failed: {e}")

                        logger.info(
                            f"Feed {feed_id} polled: {result.iocs_new} new, "
                            f"{result.iocs_updated} updated, {result.iocs_skipped} skipped, "
                            f"{result.iocs_for_reenrichment} for re-enrichment"
                        )

                    # Small delay between feeds to be nice to APIs
                    set_platform_admin_mode(True)
                    await asyncio.sleep(2)

                # Sleep before next cycle
                await asyncio.sleep(60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Polling loop error: {e}")
                await asyncio.sleep(60)


# ============================================================================
# SINGLETON
# ============================================================================

_threat_feed_service: Optional[ThreatFeedService] = None


def get_threat_feed_service() -> ThreatFeedService:
    """Get the global threat feed service instance"""
    global _threat_feed_service
    if _threat_feed_service is None:
        _threat_feed_service = ThreatFeedService()
    return _threat_feed_service
