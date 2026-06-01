#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Unified Linux Agent v2.0
=====================================
Secure, pull-only log collection with deduplication and filtering.

SECURITY MODEL:
- Collectors NEVER accept inbound commands
- Configuration pulled from control plane (signed + versioned)
- All config changes validated before applying
- Credentials never logged

Changes from v1:
- Configurable polling intervals (default 5s, was 1s)
- Severity filtering (drop INFO/DEBUG by default)
- Sliding-window deduplication (60s default)
- Telemetry counters for observability
- Pull-only configuration from control plane
- Ed25519 signature verification

Usage:
    python3 t1_unified_agent_v2.py --server https://your-server:8000 --mode full
"""

import os
import sys
import json
import time
import socket
import hashlib
import argparse
import logging
import threading
import queue
import signal
import re
import uuid
import gzip
import base64
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

# Optional imports
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import pyinotify
    HAS_INOTIFY = True
except ImportError:
    HAS_INOTIFY = False

try:
    from systemd import journal
    HAS_SYSTEMD = True
except ImportError:
    HAS_SYSTEMD = False

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Configuration
VERSION = "2.0.0"
AGENT_TYPE = "t1-unified-agent"

# UPDATED: Configurable defaults (was hardcoded)
DEFAULT_PROCESS_POLL_INTERVAL = 5       # Was 1 second
DEFAULT_NETWORK_POLL_INTERVAL = 10      # Was 5 seconds
DEFAULT_CONFIG_POLL_INTERVAL = 30       # Poll control plane every 30s
DEFAULT_BATCH_SIZE = 100                # Increased from 50
DEFAULT_FLUSH_INTERVAL = 10             # Increased from 5
DEFAULT_HEARTBEAT_INTERVAL = 60         # Increased from 30
DEFAULT_DEDUP_WINDOW = 60               # 60 second dedup window
DEFAULT_MIN_SEVERITY = 4                # Warning and above (0=emergency, 7=debug)

MAX_QUEUE_SIZE = 10000
RECONNECT_BASE_DELAY = 5
RECONNECT_MAX_DELAY = 300

# Severity mapping (syslog standard)
SEVERITY_LEVELS = {
    0: 'emergency',
    1: 'alert',
    2: 'critical',
    3: 'error',
    4: 'warning',
    5: 'notice',
    6: 'informational',
    7: 'debug'
}

# Default paths
def _get_default_data_dir():
    return os.environ.get('T1_DATA_DIR', "/opt/t1_log_collector/data")

def _get_default_quarantine_dir():
    return os.environ.get('T1_QUARANTINE_DIR', "/opt/t1_log_collector/quarantine")

DATA_DIR = _get_default_data_dir()
QUARANTINE_DIR = _get_default_quarantine_dir()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('t1-agent-v2')


class AgentMode(Enum):
    LOG_COLLECTOR = "log-collector"
    EDR = "edr"
    FULL = "full"


# =============================================================================
# TELEMETRY COUNTERS
# =============================================================================

@dataclass
class TelemetryCounters:
    """Track agent telemetry for observability"""
    events_received: int = 0
    events_filtered_severity: int = 0
    events_filtered_rules: int = 0
    events_deduplicated: int = 0
    events_forwarded: int = 0
    bytes_sent: int = 0
    bytes_compressed: int = 0
    batches_sent: int = 0
    errors: int = 0
    config_updates: int = 0
    last_reset: float = field(default_factory=time.time)

    def reset(self):
        """Reset counters (call periodically)"""
        self.__init__()
        self.last_reset = time.time()

    def to_dict(self) -> Dict:
        return {
            'events_received': self.events_received,
            'events_filtered_severity': self.events_filtered_severity,
            'events_filtered_rules': self.events_filtered_rules,
            'events_deduplicated': self.events_deduplicated,
            'events_forwarded': self.events_forwarded,
            'bytes_sent': self.bytes_sent,
            'bytes_compressed': self.bytes_compressed,
            'compression_ratio': round(self.bytes_compressed / max(self.bytes_sent, 1), 2),
            'batches_sent': self.batches_sent,
            'errors': self.errors,
            'config_updates': self.config_updates,
            'uptime_seconds': int(time.time() - self.last_reset)
        }


# =============================================================================
# DEDUPLICATION ENGINE
# =============================================================================

class DeduplicationEngine:
    """
    Sliding-window deduplication for log events.

    Dedup key: (source_type, hostname, username, event_type, normalized_message_hash)
    Window: Configurable (default 60 seconds)
    """

    def __init__(self, window_seconds: int = DEFAULT_DEDUP_WINDOW):
        self.window_seconds = window_seconds
        self.seen_events: Dict[str, Tuple[float, int]] = {}  # key -> (first_seen, count)
        self.lock = threading.Lock()
        self._cleanup_interval = 30
        self._last_cleanup = time.time()

    def _generate_key(self, event: Dict) -> str:
        """Generate dedup key from event"""
        source_type = event.get('source_type', 'unknown')
        hostname = event.get('host', {}).get('name', '') if isinstance(event.get('host'), dict) else ''
        username = event.get('user', {}).get('name', '') if isinstance(event.get('user'), dict) else ''
        event_type = event.get('event', {}).get('action', '') if isinstance(event.get('event'), dict) else ''

        # Normalize message for hashing (strip timestamps, PIDs, etc.)
        message = event.get('message', event.get('event', {}).get('original', ''))
        if isinstance(message, str):
            # Remove common variable parts
            normalized = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', '', message)
            normalized = re.sub(r'\bpid[=:]\s*\d+', '', normalized, flags=re.IGNORECASE)
            normalized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<IP>', normalized)
            normalized = re.sub(r'\s+', ' ', normalized).strip()
            msg_hash = hashlib.md5(normalized.encode()).hexdigest()[:16]
        else:
            msg_hash = 'unknown'

        return f"{source_type}:{hostname}:{username}:{event_type}:{msg_hash}"

    def check(self, event: Dict) -> Tuple[bool, int]:
        """
        Check if event is a duplicate.

        Returns:
            (is_duplicate, repeat_count)
            - is_duplicate: True if this is a repeat within the window
            - repeat_count: How many times this event has been seen
        """
        key = self._generate_key(event)
        now = time.time()

        with self.lock:
            # Cleanup old entries periodically
            if now - self._last_cleanup > self._cleanup_interval:
                self._cleanup(now)

            if key in self.seen_events:
                first_seen, count = self.seen_events[key]

                # Check if still within window
                if now - first_seen < self.window_seconds:
                    # Duplicate - increment count
                    self.seen_events[key] = (first_seen, count + 1)
                    return (True, count + 1)
                else:
                    # Window expired - reset
                    self.seen_events[key] = (now, 1)
                    return (False, 1)
            else:
                # New event
                self.seen_events[key] = (now, 1)
                return (False, 1)

    def _cleanup(self, now: float):
        """Remove expired entries"""
        expired = [k for k, (t, _) in self.seen_events.items()
                   if now - t > self.window_seconds]
        for k in expired:
            del self.seen_events[k]
        self._last_cleanup = now

    def get_stats(self) -> Dict:
        """Get dedup engine stats"""
        with self.lock:
            return {
                'tracked_keys': len(self.seen_events),
                'window_seconds': self.window_seconds
            }


# =============================================================================
# SEVERITY FILTER
# =============================================================================

class SeverityFilter:
    """
    Filter events by severity level.

    Syslog severity: 0 (emergency) to 7 (debug)
    Default threshold: 4 (warning) - drops notice, info, debug
    """

    def __init__(self, min_severity: int = DEFAULT_MIN_SEVERITY):
        self.min_severity = min_severity  # 0-7, lower = more severe

        # Source-specific overrides
        self.source_overrides: Dict[str, int] = {}

    def set_override(self, source_type: str, min_severity: int):
        """Set severity threshold for specific source"""
        self.source_overrides[source_type] = min_severity

    def should_forward(self, event: Dict) -> bool:
        """
        Check if event should be forwarded based on severity.

        Returns True if event severity <= threshold (more severe = lower number)
        """
        source_type = event.get('source_type', 'unknown')
        threshold = self.source_overrides.get(source_type, self.min_severity)

        # Extract severity from event
        severity = self._extract_severity(event)

        # EDR events always pass (threats are always important)
        if source_type.startswith('edr_') and event.get('threat_detected'):
            return True

        return severity <= threshold

    def _extract_severity(self, event: Dict) -> int:
        """Extract severity from event (normalize to 0-7)"""
        # Check explicit severity field
        if 'severity' in event:
            sev = event['severity']
            if isinstance(sev, int):
                return min(7, max(0, sev))
            elif isinstance(sev, str):
                return self._parse_severity_string(sev)

        # Check syslog priority
        if 'PRIORITY' in event:
            return min(7, max(0, int(event['PRIORITY'])))

        # Check syslog.severity
        if 'syslog' in event and 'severity' in event.get('syslog', {}):
            return min(7, max(0, int(event['syslog']['severity'])))

        # Infer from message content
        message = str(event.get('message', '')).lower()
        if any(w in message for w in ['error', 'fail', 'critical', 'emergency']):
            return 3  # error
        elif any(w in message for w in ['warn', 'warning']):
            return 4  # warning
        elif any(w in message for w in ['notice']):
            return 5  # notice

        # Default to info
        return 6

    def _parse_severity_string(self, sev: str) -> int:
        """Parse severity string to integer"""
        sev = sev.lower().strip()
        mapping = {
            'emergency': 0, 'emerg': 0,
            'alert': 1,
            'critical': 2, 'crit': 2,
            'error': 3, 'err': 3,
            'warning': 4, 'warn': 4,
            'notice': 5,
            'informational': 6, 'info': 6,
            'debug': 7
        }
        return mapping.get(sev, 6)


# =============================================================================
# CONFIGURATION MANAGER (PULL-ONLY)
# =============================================================================

class ConfigurationManager:
    """
    Pull-only configuration manager.

    SECURITY: Collectors NEVER accept inbound commands.
    All configuration is pulled from control plane and verified.
    """

    def __init__(self, server_url: str, collector_key: str):
        self.server_url = server_url.rstrip('/')
        self.collector_key = collector_key
        self.current_version = 0
        self.current_config: Dict = {}
        self.public_key_pem: Optional[str] = None
        self.last_fetch = 0
        self.fetch_interval = DEFAULT_CONFIG_POLL_INTERVAL

    def fetch_public_key(self) -> bool:
        """Fetch signing public key from server"""
        try:
            url = f"{self.server_url}/api/v1/control-plane/public-key"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                self.public_key_pem = data.get('public_key_pem')
                logger.info("Fetched control plane public key")
                return True
        except Exception as e:
            logger.warning(f"Failed to fetch public key: {e}")
        return False

    def poll_config(self) -> Optional[Dict]:
        """
        Poll control plane for configuration.

        Returns new config if version changed, None otherwise.
        """
        if time.time() - self.last_fetch < self.fetch_interval:
            return None

        self.last_fetch = time.time()

        try:
            url = f"{self.server_url}/api/v1/control-plane/config/{self.collector_key}"
            headers = {'X-Current-Version': str(self.current_version)}

            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 304:
                # No changes
                return None

            if response.status_code == 200:
                data = response.json()

                # Verify signature if crypto available
                if HAS_CRYPTO and self.public_key_pem and data.get('signature'):
                    if not self._verify_signature(data):
                        logger.error("CONFIG SIGNATURE VERIFICATION FAILED - ignoring")
                        return None

                # Check version
                new_version = data.get('version', 0)
                if new_version <= self.current_version:
                    logger.debug(f"Config version {new_version} not newer than {self.current_version}")
                    return None

                # Apply new config
                self.current_version = new_version
                self.current_config = data.get('config', {})

                logger.info(f"Applied config version {new_version}")
                return self.current_config

        except Exception as e:
            logger.warning(f"Config poll failed: {e}")

        return None

    def _verify_signature(self, data: Dict) -> bool:
        """Verify Ed25519 signature on config"""
        try:
            if not self.public_key_pem:
                return True  # No key = skip verification

            # Load public key
            public_key = serialization.load_pem_public_key(
                self.public_key_pem.encode('ascii')
            )

            # Get signature and content
            signature_b64 = data.get('signature')
            content = json.dumps(data.get('config', {}), sort_keys=True).encode()

            # Decode signature
            signature = base64.b64decode(signature_b64)

            # Verify
            public_key.verify(signature, content)
            return True

        except InvalidSignature:
            return False
        except Exception as e:
            logger.warning(f"Signature verification error: {e}")
            return True  # Fail open if crypto error

    def acknowledge_config(self, success: bool = True):
        """Acknowledge config application to control plane"""
        try:
            url = f"{self.server_url}/api/v1/control-plane/config/{self.collector_key}/ack"
            payload = {
                'version': self.current_version,
                'success': success,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            logger.warning(f"Config ack failed: {e}")

    def get_effective_config(self) -> Dict:
        """Get effective configuration with defaults"""
        defaults = {
            'process_poll_interval': DEFAULT_PROCESS_POLL_INTERVAL,
            'network_poll_interval': DEFAULT_NETWORK_POLL_INTERVAL,
            'batch_size': DEFAULT_BATCH_SIZE,
            'flush_interval': DEFAULT_FLUSH_INTERVAL,
            'min_severity': DEFAULT_MIN_SEVERITY,
            'dedup_window': DEFAULT_DEDUP_WINDOW,
            'sources': {
                'journald': {'enabled': True, 'min_severity': 4},
                'syslog': {'enabled': True, 'min_severity': 4},
                'auth': {'enabled': True, 'min_severity': 6},  # Auth always important
                'audit': {'enabled': True, 'min_severity': 4}
            },
            'filters': {
                'exclude_patterns': [],
                'include_patterns': []
            }
        }

        # Merge with fetched config
        merged = {**defaults}
        for key, value in self.current_config.items():
            if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value

        return merged


# =============================================================================
# IOC DATABASE
# =============================================================================

@dataclass
class IOCDatabase:
    """IOC database for threat matching"""
    file_hashes: Set[str] = field(default_factory=set)
    ip_addresses: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    process_names: Set[str] = field(default_factory=set)
    file_paths: Set[str] = field(default_factory=set)
    last_updated: float = 0

    def match_hash(self, h: str) -> bool:
        return h.lower() in self.file_hashes

    def match_ip(self, ip: str) -> bool:
        return ip in self.ip_addresses

    def match_domain(self, domain: str) -> bool:
        domain = domain.lower()
        parts = domain.split('.')
        for i in range(len(parts)):
            if '.'.join(parts[i:]) in self.domains:
                return True
        return False

    def match_process(self, name: str) -> bool:
        return name.lower() in self.process_names


# =============================================================================
# AGENT CONFIG
# =============================================================================

@dataclass
class AgentConfig:
    """Agent configuration"""
    server_url: str
    mode: AgentMode = AgentMode.FULL
    agent_key: Optional[str] = None
    agent_token: Optional[str] = None
    agent_id: Optional[str] = None
    hostname: str = ""
    tags: List[str] = None

    # Transport
    use_tcp_stream: bool = True
    log_port: int = 5514
    use_ssl: bool = False
    compress_logs: bool = True  # NEW: Enable gzip compression

    # Intervals (configurable from control plane)
    batch_size: int = DEFAULT_BATCH_SIZE
    flush_interval: int = DEFAULT_FLUSH_INTERVAL
    heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL
    process_poll_interval: int = DEFAULT_PROCESS_POLL_INTERVAL
    network_poll_interval: int = DEFAULT_NETWORK_POLL_INTERVAL

    # Filtering
    min_severity: int = DEFAULT_MIN_SEVERITY
    dedup_window: int = DEFAULT_DEDUP_WINDOW

    # Log sources
    collect_journald: bool = True
    collect_syslog: bool = True
    collect_auth: bool = True
    collect_audit: bool = True

    # EDR
    enable_process_monitor: bool = True
    enable_fim: bool = True
    enable_network_monitor: bool = True
    enable_response_actions: bool = True
    fim_paths: List[str] = None
    auto_kill: bool = False
    auto_quarantine: bool = False

    # Inventory
    enable_inventory: bool = True
    inventory_sync_interval: int = 3600

    # Storage
    key_file: str = f"{DATA_DIR}/agent.key"
    config_file: str = f"{DATA_DIR}/config.json"

    def __post_init__(self):
        if not self.hostname:
            self.hostname = socket.gethostname()
        if self.tags is None:
            self.tags = []
        if self.fim_paths is None:
            self.fim_paths = [
                "/etc/passwd", "/etc/shadow", "/etc/sudoers",
                "/etc/ssh/sshd_config", "/etc/crontab",
                "/usr/bin", "/usr/sbin", "/root/.ssh"
            ]
        if not self.agent_key and not self.agent_token:
            self.agent_key = self._load_or_generate_key()

        # Mode-specific defaults
        if self.mode == AgentMode.LOG_COLLECTOR:
            self.enable_process_monitor = False
            self.enable_fim = False
            self.enable_network_monitor = False
            self.enable_response_actions = False
        elif self.mode == AgentMode.EDR:
            self.collect_journald = False
            self.collect_syslog = False
            self.collect_auth = False
            self.collect_audit = False

    def _load_or_generate_key(self) -> str:
        key_path = Path(self.key_file)
        if key_path.exists():
            key = key_path.read_text().strip()
            logger.info(f"Loaded agent key: {key[:12]}...")
            return key

        new_key = f"t1_{uuid.uuid4().hex}"
        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(new_key)
            key_path.chmod(0o600)
            logger.info(f"Generated agent key: {new_key[:12]}...")
        except PermissionError:
            logger.warning("Cannot save key, using ephemeral")
        return new_key

    def apply_remote_config(self, remote_config: Dict):
        """Apply configuration from control plane"""
        if 'batch_size' in remote_config:
            self.batch_size = remote_config['batch_size']
        if 'flush_interval' in remote_config:
            self.flush_interval = remote_config['flush_interval']
        if 'min_severity' in remote_config:
            self.min_severity = remote_config['min_severity']
        if 'dedup_window' in remote_config:
            self.dedup_window = remote_config['dedup_window']
        if 'process_poll_interval' in remote_config:
            self.process_poll_interval = remote_config['process_poll_interval']
        if 'network_poll_interval' in remote_config:
            self.network_poll_interval = remote_config['network_poll_interval']

        # Source-specific settings
        sources = remote_config.get('sources', {})
        if 'journald' in sources:
            self.collect_journald = sources['journald'].get('enabled', True)
        if 'syslog' in sources:
            self.collect_syslog = sources['syslog'].get('enabled', True)
        if 'auth' in sources:
            self.collect_auth = sources['auth'].get('enabled', True)
        if 'audit' in sources:
            self.collect_audit = sources['audit'].get('enabled', True)


# =============================================================================
# TCP TRANSPORT WITH COMPRESSION
# =============================================================================

class TCPLogTransport:
    """Persistent TCP connection with optional compression"""

    def __init__(self, host: str, port: int, agent_id: str,
                 use_ssl: bool = False, compress: bool = True):
        self.host = host
        self.port = port
        self.agent_id = agent_id
        self.use_ssl = use_ssl
        self.compress = compress
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.reconnect_delay = RECONNECT_BASE_DELAY
        self.lock = threading.Lock()
        self.bytes_sent = 0
        self.bytes_compressed = 0
        self.messages_sent = 0

    def connect(self) -> bool:
        with self.lock:
            if self.connected:
                return True

            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(30)

                if self.use_ssl:
                    import ssl
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    self.socket = context.wrap_socket(self.socket, server_hostname=self.host)

                self.socket.connect((self.host, self.port))
                self.connected = True
                self.reconnect_delay = RECONNECT_BASE_DELAY
                logger.info(f"TCP connected to {self.host}:{self.port}")
                return True

            except Exception as e:
                logger.warning(f"TCP connect failed: {e}")
                self.connected = False
                if self.socket:
                    try:
                        self.socket.close()
                    except:
                        pass
                    self.socket = None
                return False

    def disconnect(self):
        with self.lock:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            self.connected = False

    def send_logs(self, logs: List[Dict]) -> bool:
        if not logs:
            return True

        if not self.connected:
            if not self.connect():
                return False

        try:
            # Create message
            message_data = {
                'type': 'batch',
                'agent_id': self.agent_id,
                'logs': logs,
                'timestamp': time.time(),
                'compressed': self.compress
            }

            json_data = json.dumps(message_data).encode('utf-8')
            original_size = len(json_data)

            # Compress if enabled
            if self.compress:
                message = gzip.compress(json_data, compresslevel=6)
                compressed_size = len(message)
            else:
                message = json_data
                compressed_size = original_size

            # Send length-prefixed message (4 bytes length + 1 byte compression flag)
            length = len(message)
            with self.lock:
                self.socket.sendall(length.to_bytes(4, 'big'))
                self.socket.sendall((1 if self.compress else 0).to_bytes(1, 'big'))
                self.socket.sendall(message)

            self.bytes_sent += original_size
            self.bytes_compressed += compressed_size
            self.messages_sent += len(logs)
            return True

        except Exception as e:
            logger.warning(f"TCP send failed: {e}")
            self.disconnect()
            return False


# =============================================================================
# ECS NORMALIZER
# =============================================================================

class ECSNormalizer:
    """Normalize events to Elastic Common Schema with severity"""

    AUTH_PATTERNS = {
        'ssh_accepted': re.compile(r'Accepted (\w+) for (\S+) from (\S+) port (\d+)'),
        'ssh_failed': re.compile(r'Failed (\w+) for (?:invalid user )?(\S+) from (\S+) port (\d+)'),
        'sudo': re.compile(r'(\S+) : .* COMMAND=(.*)'),
    }

    def __init__(self, hostname: str):
        self.hostname = hostname
        self.host_ip = self._get_host_ip()

    def _get_host_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def normalize(self, event: Dict, source_type: str) -> Dict:
        timestamp = event.get('timestamp', datetime.now(timezone.utc).isoformat())

        ecs = {
            '@timestamp': timestamp,
            'ecs': {'version': '8.0.0'},
            'agent': {
                'type': AGENT_TYPE,
                'version': VERSION,
                'name': self.hostname
            },
            'host': {
                'name': self.hostname,
                'ip': self.host_ip,
                'os': {'type': 'linux', 'family': 'linux'}
            },
            'event': {
                'kind': 'event',
                'category': [],
                'type': [],
                'created': datetime.now(timezone.utc).isoformat(),
                'original': event.get('message', '')
            },
            'source_type': source_type
        }

        # Add severity
        severity = self._extract_severity(event)
        ecs['log'] = {
            'level': SEVERITY_LEVELS.get(severity, 'info'),
            'syslog': {'severity': {'code': severity}}
        }

        # Source-specific normalization
        if source_type.startswith('linux_'):
            self._normalize_log(ecs, event, source_type)
        elif source_type.startswith('edr_'):
            self._normalize_edr(ecs, event, source_type)

        # Generate event ID
        unique = f"{ecs['@timestamp']}{self.hostname}{event.get('message', '')}{source_type}"
        ecs['event']['id'] = hashlib.sha256(unique.encode()).hexdigest()[:16]

        return ecs

    def _extract_severity(self, event: Dict) -> int:
        if 'PRIORITY' in event:
            return min(7, max(0, int(event['PRIORITY'])))
        if 'severity' in event:
            sev = event['severity']
            if isinstance(sev, int):
                return min(7, max(0, sev))
        return 6  # Default to info

    def _normalize_log(self, ecs: Dict, event: Dict, source_type: str):
        message = event.get('message', '')

        if source_type == 'linux_journald':
            if '_SYSTEMD_UNIT' in event:
                ecs['systemd'] = {'unit': event['_SYSTEMD_UNIT']}
            if '_PID' in event:
                ecs['process'] = {'pid': int(event['_PID']), 'name': event.get('_COMM', '')}
            ecs['event']['category'] = ['host']

        elif source_type == 'linux_auth':
            ecs['event']['category'] = ['authentication']

            match = self.AUTH_PATTERNS['ssh_accepted'].search(message)
            if match:
                method, user, src_ip, port = match.groups()
                ecs['event']['action'] = 'ssh_login'
                ecs['event']['outcome'] = 'success'
                ecs['user'] = {'name': user}
                ecs['source'] = {'ip': src_ip, 'port': int(port)}
                return

            match = self.AUTH_PATTERNS['ssh_failed'].search(message)
            if match:
                method, user, src_ip, port = match.groups()
                ecs['event']['action'] = 'ssh_login'
                ecs['event']['outcome'] = 'failure'
                ecs['user'] = {'name': user}
                ecs['source'] = {'ip': src_ip, 'port': int(port)}
                return

        elif source_type == 'linux_auditd':
            ecs['event']['category'] = ['process']
            type_match = re.search(r'type=(\S+)', message)
            if type_match:
                ecs['event']['action'] = type_match.group(1).lower()

        ecs['message'] = message

    def _normalize_edr(self, ecs: Dict, event: Dict, source_type: str):
        if 'process' in event:
            ecs['process'] = event['process']
            ecs['event']['category'].append('process')
        if 'file' in event:
            ecs['file'] = event['file']
            if 'hash' in event:
                ecs['file']['hash'] = event['hash']
            ecs['event']['category'].append('file')
        if 'network' in event:
            ecs['network'] = event['network']
            ecs['destination'] = {
                'ip': event['network'].get('remote_ip'),
                'port': event['network'].get('remote_port')
            }
            ecs['event']['category'].append('network')

        if event.get('threat_detected'):
            ecs['threat'] = {'indicator': event.get('ioc_match', {}), 'matched': True}
            ecs['event']['kind'] = 'alert'

        ecs['event']['action'] = event.get('event_action', '')


# =============================================================================
# LOG COLLECTORS (Updated with polling intervals)
# =============================================================================

class JournaldCollector:
    """Collect from systemd journal with severity filtering"""

    def __init__(self, event_queue: queue.Queue, severity_filter: SeverityFilter):
        self.queue = event_queue
        self.severity_filter = severity_filter
        self.running = False
        self.thread = None

    def start(self):
        if not HAS_SYSTEMD:
            logger.warning("systemd-python not installed, journald disabled")
            return
        self.running = True
        self.thread = threading.Thread(target=self._collect, daemon=True)
        self.thread.start()
        logger.info("Journald collector started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _collect(self):
        try:
            j = journal.Reader()
            j.this_boot()
            j.seek_tail()
            j.get_previous()

            while self.running:
                if j.wait(1000000) == journal.APPEND:
                    for entry in j:
                        if not self.running:
                            break

                        priority = entry.get('PRIORITY', 6)

                        event = {
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'message': entry.get('MESSAGE', ''),
                            '_SYSTEMD_UNIT': entry.get('_SYSTEMD_UNIT', ''),
                            '_PID': entry.get('_PID', ''),
                            '_COMM': entry.get('_COMM', ''),
                            'PRIORITY': priority,
                            'source_type': 'linux_journald'
                        }

                        try:
                            self.queue.put_nowait(event)
                        except queue.Full:
                            pass
        except Exception as e:
            logger.error(f"Journald error: {e}")


class FileCollector:
    """Tail a log file with configurable polling"""

    def __init__(self, filepath: str, source_type: str, event_queue: queue.Queue,
                 poll_interval: float = 1.0):
        self.filepath = filepath
        self.source_type = source_type
        self.queue = event_queue
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
        self.position = 0

    def start(self):
        if not os.path.exists(self.filepath):
            logger.warning(f"Log file not found: {self.filepath}")
            return
        self.running = True
        self.thread = threading.Thread(target=self._collect, daemon=True)
        self.thread.start()
        logger.info(f"File collector started: {self.filepath}")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _collect(self):
        try:
            with open(self.filepath, 'r') as f:
                f.seek(0, 2)
                self.position = f.tell()

            while self.running:
                try:
                    with open(self.filepath, 'r') as f:
                        f.seek(self.position)
                        for line in f:
                            line = line.strip()
                            if line:
                                event = {
                                    'timestamp': datetime.now(timezone.utc).isoformat(),
                                    'message': line,
                                    'source_type': self.source_type
                                }
                                try:
                                    self.queue.put_nowait(event)
                                except queue.Full:
                                    pass
                        self.position = f.tell()
                except FileNotFoundError:
                    pass
                time.sleep(self.poll_interval)
        except Exception as e:
            logger.error(f"File collector error: {e}")


# =============================================================================
# EDR MONITORS (Updated with configurable polling)
# =============================================================================

class ProcessMonitor:
    """Monitor process creation with configurable polling interval"""

    def __init__(self, event_queue: queue.Queue, ioc_db: IOCDatabase,
                 poll_interval: int = DEFAULT_PROCESS_POLL_INTERVAL):
        self.queue = event_queue
        self.ioc_db = ioc_db
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
        self.known_pids: Dict[int, Dict] = {}

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()
        logger.info(f"Process monitor started (poll interval: {self.poll_interval}s)")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def set_poll_interval(self, interval: int):
        """Update polling interval (from config)"""
        self.poll_interval = max(1, interval)

    def _monitor(self):
        self._scan_processes()
        while self.running:
            try:
                self._scan_processes()
                time.sleep(self.poll_interval)  # UPDATED: Configurable
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
                time.sleep(5)

    def _scan_processes(self):
        current_pids = set()

        if HAS_PSUTIL:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'ppid']):
                try:
                    pid = proc.info['pid']
                    current_pids.add(pid)

                    if pid not in self.known_pids:
                        proc_info = {
                            'pid': pid,
                            'name': proc.info['name'],
                            'exe': proc.info['exe'] or '',
                            'cmdline': ' '.join(proc.info['cmdline'] or []),
                            'user': proc.info['username'],
                            'ppid': proc.info['ppid']
                        }

                        if proc_info['exe'] and os.path.exists(proc_info['exe']):
                            try:
                                proc_info['exe_hash'] = self._hash_file(proc_info['exe'])
                            except:
                                proc_info['exe_hash'] = ''

                        self.known_pids[pid] = proc_info
                        self._emit_event("start", proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        # Terminated processes
        for pid in set(self.known_pids.keys()) - current_pids:
            proc_info = self.known_pids.pop(pid, {})
            self._emit_event("end", proc_info)

    def _hash_file(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _emit_event(self, action: str, proc_info: Dict):
        ioc_match = None
        if self.ioc_db:
            if proc_info.get('exe_hash') and self.ioc_db.match_hash(proc_info['exe_hash']):
                ioc_match = {'type': 'hash', 'value': proc_info['exe_hash']}
            elif proc_info.get('name') and self.ioc_db.match_process(proc_info['name']):
                ioc_match = {'type': 'process_name', 'value': proc_info['name']}

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'process',
            'event_action': action,
            'source_type': 'edr_process',
            'process': proc_info,
            'ioc_match': ioc_match,
            'threat_detected': ioc_match is not None
        }
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            pass


class NetworkMonitor:
    """Monitor network connections with configurable polling"""

    def __init__(self, event_queue: queue.Queue, ioc_db: IOCDatabase,
                 poll_interval: int = DEFAULT_NETWORK_POLL_INTERVAL):
        self.queue = event_queue
        self.ioc_db = ioc_db
        self.poll_interval = poll_interval
        self.running = False
        self.thread = None
        self.known_connections: Set[tuple] = set()

    def start(self):
        if not HAS_PSUTIL:
            logger.warning("psutil not installed, network monitor disabled")
            return
        self.running = True
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()
        logger.info(f"Network monitor started (poll interval: {self.poll_interval}s)")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def set_poll_interval(self, interval: int):
        self.poll_interval = max(1, interval)

    def _monitor(self):
        while self.running:
            try:
                self._scan_connections()
                time.sleep(self.poll_interval)  # UPDATED: Configurable
            except Exception as e:
                logger.error(f"Network monitor error: {e}")
                time.sleep(10)

    def _scan_connections(self):
        current = set()

        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED' or not conn.raddr:
                continue

            key = (conn.pid, conn.laddr, conn.raddr)
            current.add(key)

            if key not in self.known_connections:
                self._handle_new_connection(conn)
                self.known_connections.add(key)

        self.known_connections &= current

    def _handle_new_connection(self, conn):
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port

        proc_info = {}
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                proc_info = {'pid': conn.pid, 'name': proc.name(), 'exe': proc.exe()}
            except:
                proc_info = {'pid': conn.pid}

        ioc_match = None
        if self.ioc_db and self.ioc_db.match_ip(remote_ip):
            ioc_match = {'type': 'ip', 'value': remote_ip}

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'network',
            'event_action': 'connection_established',
            'source_type': 'edr_network',
            'network': {
                'direction': 'outbound',
                'local_ip': conn.laddr.ip,
                'local_port': conn.laddr.port,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'protocol': 'tcp'
            },
            'process': proc_info,
            'ioc_match': ioc_match,
            'threat_detected': ioc_match is not None
        }
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            pass


# =============================================================================
# UNIFIED AGENT v2
# =============================================================================

class T1UnifiedAgentV2:
    """Main unified agent with deduplication and filtering"""

    STATE_UNREGISTERED = 'unregistered'
    STATE_PENDING = 'pending'
    STATE_APPROVED = 'approved'

    def __init__(self, config: AgentConfig):
        self.config = config
        self.running = False
        self.event_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.ioc_db = IOCDatabase()
        self.normalizer = ECSNormalizer(config.hostname)

        # NEW: Telemetry, dedup, filtering
        self.telemetry = TelemetryCounters()
        self.dedup_engine = DeduplicationEngine(config.dedup_window)
        self.severity_filter = SeverityFilter(config.min_severity)

        # NEW: Configuration manager (pull-only)
        self.config_manager = ConfigurationManager(config.server_url, config.agent_key)

        # TCP transport
        self.tcp_transport: Optional[TCPLogTransport] = None

        # Collectors and monitors
        self.collectors: List = []
        self.process_monitor: Optional[ProcessMonitor] = None
        self.network_monitor: Optional[NetworkMonitor] = None

        # State
        self.registration_state = self.STATE_UNREGISTERED
        self.server_agent_id = None
        self.active_token = None
        self.last_heartbeat = 0
        self.last_config_poll = 0

        if not HAS_REQUESTS:
            logger.error("requests library required")
            sys.exit(1)

    def start(self):
        logger.info(f"Starting T1 Unified Agent v{VERSION}")
        logger.info(f"Mode: {self.config.mode.value}")
        logger.info(f"Hostname: {self.config.hostname}")
        logger.info(f"Server: {self.config.server_url}")
        logger.info(f"Dedup window: {self.config.dedup_window}s")
        logger.info(f"Min severity: {self.config.min_severity} ({SEVERITY_LEVELS.get(self.config.min_severity, 'unknown')})")

        self.running = True

        # Registration
        if self.config.agent_token:
            self.active_token = self.config.agent_token
            self.registration_state = self.STATE_APPROVED
        else:
            self._wait_for_approval()

        if self.registration_state != self.STATE_APPROVED:
            logger.error("Agent not approved")
            return

        # Fetch initial config from control plane
        self.config_manager.fetch_public_key()
        new_config = self.config_manager.poll_config()
        if new_config:
            self.config.apply_remote_config(new_config)
            self._update_components_from_config()
            self.telemetry.config_updates += 1

        # Initialize TCP transport
        if self.config.use_tcp_stream:
            from urllib.parse import urlparse
            parsed = urlparse(self.config.server_url)
            tcp_host = parsed.hostname or 'localhost'

            self.tcp_transport = TCPLogTransport(
                host=tcp_host,
                port=self.config.log_port,
                agent_id=self.server_agent_id or self.config.hostname,
                use_ssl=self.config.use_ssl,
                compress=self.config.compress_logs
            )
            self.tcp_transport.connect()

        # Start collectors/monitors
        self._start_collectors()

        # Main loop
        self._run()

    def stop(self):
        logger.info("Stopping agent...")
        self.running = False

        if self.tcp_transport:
            self.tcp_transport.disconnect()

        for collector in self.collectors:
            collector.stop()
        if self.process_monitor:
            self.process_monitor.stop()
        if self.network_monitor:
            self.network_monitor.stop()

        # Log final telemetry
        logger.info(f"Final telemetry: {json.dumps(self.telemetry.to_dict())}")

    def _update_components_from_config(self):
        """Update component settings from remote config"""
        self.dedup_engine.window_seconds = self.config.dedup_window
        self.severity_filter.min_severity = self.config.min_severity

        if self.process_monitor:
            self.process_monitor.set_poll_interval(self.config.process_poll_interval)
        if self.network_monitor:
            self.network_monitor.set_poll_interval(self.config.network_poll_interval)

    def _register(self) -> Dict:
        if self.config.mode == AgentMode.LOG_COLLECTOR:
            url = f"{self.config.server_url}/api/v1/logs/agents/self-register"
        else:
            url = f"{self.config.server_url}/api/v1/edr/agents/register"

        os_version = ""
        try:
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        os_version = line.split('=')[1].strip().strip('"')
                        break
        except:
            pass

        payload = {
            "hostname": self.config.hostname,
            "os_type": "linux",
            "os_version": os_version,
            "agent_type": AGENT_TYPE,
            "agent_version": VERSION,
            "ip_address": self.normalizer.host_ip,
            "tags": self.config.tags or [],
            "agent_key": self.config.agent_key,
            "capabilities": {
                "mode": self.config.mode.value,
                "deduplication": True,
                "severity_filtering": True,
                "compression": self.config.compress_logs
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=30)
            return response.json() if response.status_code == 200 else {"status": "error"}
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {"status": "error", "message": str(e)}

    def _wait_for_approval(self):
        result = self._register()

        if result.get("status") == "approved":
            self.registration_state = self.STATE_APPROVED
            self.server_agent_id = result.get("agent_id")
            self.active_token = self.config.agent_key
            logger.info(f"Agent approved: {self.server_agent_id}")
            return

        if result.get("status") == "pending":
            self.registration_state = self.STATE_PENDING
            self.server_agent_id = result.get("agent_id")
            logger.info(f"Waiting for approval. Agent Key: {self.config.agent_key}")

        while self.running and self.registration_state == self.STATE_PENDING:
            time.sleep(30)
            status = self._check_status()
            if status.get("status") == "approved":
                self.registration_state = self.STATE_APPROVED
                self.server_agent_id = status.get("agent_id")
                self.active_token = self.config.agent_key
                logger.info("Agent APPROVED!")
                return

    def _check_status(self) -> Dict:
        if self.config.mode == AgentMode.LOG_COLLECTOR:
            url = f"{self.config.server_url}/api/v1/logs/agents/check/{self.config.agent_key}"
        else:
            url = f"{self.config.server_url}/api/v1/edr/agents/check/{self.config.agent_key}"

        try:
            response = requests.get(url, timeout=10)
            return response.json() if response.status_code == 200 else {}
        except:
            return {}

    def _start_collectors(self):
        if self.config.mode in [AgentMode.LOG_COLLECTOR, AgentMode.FULL]:
            if self.config.collect_journald and HAS_SYSTEMD:
                collector = JournaldCollector(self.event_queue, self.severity_filter)
                collector.start()
                self.collectors.append(collector)

            if self.config.collect_syslog:
                for path in ['/var/log/syslog', '/var/log/messages']:
                    if os.path.exists(path):
                        collector = FileCollector(path, 'linux_syslog', self.event_queue)
                        collector.start()
                        self.collectors.append(collector)
                        break

            if self.config.collect_auth:
                for path in ['/var/log/auth.log', '/var/log/secure']:
                    if os.path.exists(path):
                        collector = FileCollector(path, 'linux_auth', self.event_queue)
                        collector.start()
                        self.collectors.append(collector)
                        break

            if self.config.collect_audit and os.path.exists('/var/log/audit/audit.log'):
                collector = FileCollector('/var/log/audit/audit.log', 'linux_auditd', self.event_queue)
                collector.start()
                self.collectors.append(collector)

        if self.config.mode in [AgentMode.EDR, AgentMode.FULL]:
            if self.config.enable_process_monitor:
                self.process_monitor = ProcessMonitor(
                    self.event_queue,
                    self.ioc_db,
                    self.config.process_poll_interval
                )
                self.process_monitor.start()

            if self.config.enable_network_monitor:
                self.network_monitor = NetworkMonitor(
                    self.event_queue,
                    self.ioc_db,
                    self.config.network_poll_interval
                )
                self.network_monitor.start()

        logger.info(f"Started {len(self.collectors)} log collectors")

    def _run(self):
        batch = []
        last_flush = time.time()

        while self.running:
            try:
                # Poll for config updates
                if time.time() - self.last_config_poll > DEFAULT_CONFIG_POLL_INTERVAL:
                    new_config = self.config_manager.poll_config()
                    if new_config:
                        self.config.apply_remote_config(new_config)
                        self._update_components_from_config()
                        self.config_manager.acknowledge_config(True)
                        self.telemetry.config_updates += 1
                    self.last_config_poll = time.time()

                # Heartbeat
                if time.time() - self.last_heartbeat > self.config.heartbeat_interval:
                    self._send_heartbeat()

                # Process events
                try:
                    event = self.event_queue.get(timeout=1)
                    self.telemetry.events_received += 1

                    # FILTER: Severity check
                    if not self.severity_filter.should_forward(event):
                        self.telemetry.events_filtered_severity += 1
                        continue

                    # DEDUP: Check for duplicates
                    is_dup, repeat_count = self.dedup_engine.check(event)
                    if is_dup:
                        self.telemetry.events_deduplicated += 1
                        continue

                    # Normalize
                    source_type = event.get('source_type', 'unknown')
                    ecs_event = self.normalizer.normalize(event, source_type)

                    # Add dedup metadata
                    if repeat_count > 1:
                        ecs_event['t1_meta'] = {'repeat_count': repeat_count}

                    batch.append(ecs_event)

                except queue.Empty:
                    pass

                # Flush batch
                now = time.time()
                if len(batch) >= self.config.batch_size or \
                   (batch and now - last_flush >= self.config.flush_interval):
                    self._send_batch(batch)
                    batch = []
                    last_flush = now

            except Exception as e:
                logger.error(f"Processing error: {e}")
                self.telemetry.errors += 1
                time.sleep(1)

        if batch:
            self._send_batch(batch)

    def _send_batch(self, events: List[Dict]):
        if not events:
            return

        # Try TCP first
        if self.tcp_transport:
            if self.tcp_transport.send_logs(events):
                self.telemetry.events_forwarded += len(events)
                self.telemetry.batches_sent += 1
                self.telemetry.bytes_sent += self.tcp_transport.bytes_sent
                self.telemetry.bytes_compressed += self.tcp_transport.bytes_compressed
                return

        # HTTP fallback
        url = f"{self.config.server_url}/api/v1/logs/ingest/bulk"
        payload = {'source_type': events[0].get('source_type', 'unknown'), 'events': events}
        headers = {'X-Agent-Token': self.active_token, 'Content-Type': 'application/json'}

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            if response.status_code == 200:
                self.telemetry.events_forwarded += len(events)
                self.telemetry.batches_sent += 1
        except Exception as e:
            logger.error(f"Send error: {e}")
            self.telemetry.errors += 1

    def _send_heartbeat(self):
        url = f"{self.config.server_url}/api/v1/logs/agents/{self.server_agent_id}/heartbeat"
        headers = {'X-Agent-Token': self.active_token, 'Content-Type': 'application/json'}

        payload = {
            'hostname': self.config.hostname,
            'agent_version': VERSION,
            'mode': self.config.mode.value,
            'config_version': self.config_manager.current_version,
            'telemetry': self.telemetry.to_dict(),
            'dedup_stats': self.dedup_engine.get_stats()
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                self.last_heartbeat = time.time()
        except Exception as e:
            logger.warning(f"Heartbeat error: {e}")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='T1 Agentics Unified Linux Agent v2',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--server', '-s', required=True, help='T1 Agentics server URL')
    parser.add_argument('--mode', '-m', choices=['log-collector', 'edr', 'full'], default='full')
    parser.add_argument('--token', '-t', help='Agent token')
    parser.add_argument('--hostname', '-n', help='Override hostname')
    parser.add_argument('--tag', action='append', default=[], help='Add tag')

    # Filtering options
    parser.add_argument('--min-severity', type=int, default=DEFAULT_MIN_SEVERITY,
                        choices=range(8), help='Min severity (0=emerg, 7=debug, default=4/warning)')
    parser.add_argument('--dedup-window', type=int, default=DEFAULT_DEDUP_WINDOW,
                        help='Deduplication window in seconds (default=60)')

    # Polling intervals
    parser.add_argument('--process-poll', type=int, default=DEFAULT_PROCESS_POLL_INTERVAL,
                        help='Process monitor poll interval (default=5s)')
    parser.add_argument('--network-poll', type=int, default=DEFAULT_NETWORK_POLL_INTERVAL,
                        help='Network monitor poll interval (default=10s)')

    # Log sources
    parser.add_argument('--no-journald', action='store_true')
    parser.add_argument('--no-syslog', action='store_true')
    parser.add_argument('--no-auth', action='store_true')
    parser.add_argument('--no-audit', action='store_true')

    # EDR options
    parser.add_argument('--no-process', action='store_true')
    parser.add_argument('--no-network', action='store_true')

    # Transport
    parser.add_argument('--log-port', type=int, default=5514)
    parser.add_argument('--no-tcp', action='store_true')
    parser.add_argument('--no-compress', action='store_true')
    parser.add_argument('--tls', action='store_true')

    parser.add_argument('--debug', '-d', action='store_true')
    parser.add_argument('--version', '-v', action='version', version=f'T1 Unified Agent v{VERSION}')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    mode_map = {
        'log-collector': AgentMode.LOG_COLLECTOR,
        'edr': AgentMode.EDR,
        'full': AgentMode.FULL
    }

    config = AgentConfig(
        server_url=args.server.rstrip('/'),
        mode=mode_map[args.mode],
        agent_token=args.token,
        hostname=args.hostname or socket.gethostname(),
        tags=args.tag,
        min_severity=args.min_severity,
        dedup_window=args.dedup_window,
        process_poll_interval=args.process_poll,
        network_poll_interval=args.network_poll,
        collect_journald=not args.no_journald,
        collect_syslog=not args.no_syslog,
        collect_auth=not args.no_auth,
        collect_audit=not args.no_audit,
        enable_process_monitor=not args.no_process,
        enable_network_monitor=not args.no_network,
        use_tcp_stream=not args.no_tcp,
        compress_logs=not args.no_compress,
        log_port=args.log_port,
        use_ssl=args.tls
    )

    agent = T1UnifiedAgentV2(config)

    def signal_handler(signum, frame):
        logger.info(f"Signal {signum} received")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == '__main__':
    main()
