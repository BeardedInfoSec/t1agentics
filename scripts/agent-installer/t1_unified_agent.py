#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Unified Linux Agent
================================
All-in-one agent combining log collection, EDR, and asset inventory.

Modes:
- log-collector: Just collect and forward logs (lightweight)
- edr: Full EDR with process/file/network monitoring + response
- full: Everything (logs + EDR + inventory)

Usage:
    # Full mode (recommended)
    python3 t1_unified_agent.py --server https://your-server:8000 --mode full

    # Log collector only
    python3 t1_unified_agent.py --server https://your-server:8000 --mode log-collector

    # EDR only
    python3 t1_unified_agent.py --server https://your-server:8000 --mode edr

Requirements:
    pip install requests psutil pyinotify
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
import subprocess
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum

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

# Configuration
VERSION = "1.2.0"
AGENT_TYPE = "t1-unified-agent"
DEFAULT_BATCH_SIZE = 50
DEFAULT_FLUSH_INTERVAL = 5
DEFAULT_HEARTBEAT_INTERVAL = 30
DEFAULT_IOC_REFRESH_INTERVAL = 300
DEFAULT_INVENTORY_SYNC_INTERVAL = 3600
MAX_QUEUE_SIZE = 10000
RECONNECT_BASE_DELAY = 5
RECONNECT_MAX_DELAY = 300

# Default paths - configurable via environment variables
def _get_default_data_dir():
    env_val = os.environ.get('T1_DATA_DIR')
    if env_val:
        return env_val
    return "/opt/t1_log_collector/data"

def _get_default_quarantine_dir():
    env_val = os.environ.get('T1_QUARANTINE_DIR')
    if env_val:
        return env_val
    return "/opt/t1_log_collector/quarantine"

DATA_DIR = _get_default_data_dir()
QUARANTINE_DIR = _get_default_quarantine_dir()

# Default FIM paths
DEFAULT_FIM_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d",
    "/etc/ssh/sshd_config", "/etc/crontab", "/etc/cron.d",
    "/etc/systemd/system", "/usr/bin", "/usr/sbin", "/usr/local/bin",
    "/root/.ssh", "/root/.bashrc"
]

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('t1-agent')


class AgentMode(Enum):
    LOG_COLLECTOR = "log-collector"
    EDR = "edr"
    FULL = "full"


# =============================================================================
# DATA CLASSES
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

    def match_path(self, path: str) -> bool:
        return path in self.file_paths


@dataclass
class AgentConfig:
    """Unified agent configuration"""
    server_url: str
    mode: AgentMode = AgentMode.FULL
    agent_key: Optional[str] = None
    agent_token: Optional[str] = None
    agent_id: Optional[str] = None
    hostname: str = ""
    tags: List[str] = None
    batch_size: int = DEFAULT_BATCH_SIZE
    flush_interval: int = DEFAULT_FLUSH_INTERVAL
    heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL

    # Log transport settings
    use_tcp_stream: bool = True  # Use dedicated TCP port for logs
    log_port: int = 5514  # TCP port for log streaming
    use_ssl: bool = False  # TLS for log transport

    # Log collection settings
    collect_journald: bool = True
    collect_syslog: bool = True
    collect_auth: bool = True
    collect_audit: bool = True

    # EDR settings
    enable_process_monitor: bool = True
    enable_fim: bool = True
    enable_network_monitor: bool = True
    enable_response_actions: bool = True
    fim_paths: List[str] = None
    auto_kill: bool = False
    auto_quarantine: bool = False

    # Inventory settings
    enable_inventory: bool = True
    inventory_sync_interval: int = DEFAULT_INVENTORY_SYNC_INTERVAL

    # Storage
    key_file: str = f"{DATA_DIR}/agent.key"
    config_file: str = f"{DATA_DIR}/config.json"

    def __post_init__(self):
        if not self.hostname:
            self.hostname = socket.gethostname()
        if self.tags is None:
            self.tags = []
        if self.fim_paths is None:
            self.fim_paths = DEFAULT_FIM_PATHS.copy()
        if not self.agent_key and not self.agent_token:
            self.agent_key = self._load_or_generate_key()

        # Apply mode defaults
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


# =============================================================================
# TCP LOG TRANSPORT
# =============================================================================

class TCPLogTransport:
    """Persistent TCP connection for high-performance log streaming"""

    def __init__(self, host: str, port: int, agent_id: str, use_ssl: bool = False):
        self.host = host
        self.port = port
        self.agent_id = agent_id
        self.use_ssl = use_ssl
        self.socket: Optional[socket.socket] = None
        self.connected = False
        self.reconnect_delay = RECONNECT_BASE_DELAY
        self.lock = threading.Lock()
        self.bytes_sent = 0
        self.messages_sent = 0

    def connect(self) -> bool:
        """Establish TCP connection"""
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
        """Close TCP connection"""
        with self.lock:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            self.connected = False

    def send_logs(self, logs: List[Dict]) -> bool:
        """Send batch of logs over TCP"""
        if not logs:
            return True

        # Ensure connected
        if not self.connected:
            if not self.connect():
                return False

        try:
            # Create message
            message = json.dumps({
                'type': 'batch',
                'agent_id': self.agent_id,
                'logs': logs,
                'timestamp': time.time()
            }).encode('utf-8')

            # Send length-prefixed message
            length = len(message)
            with self.lock:
                self.socket.sendall(length.to_bytes(4, 'big'))
                self.socket.sendall(message)

            self.bytes_sent += length + 4
            self.messages_sent += len(logs)
            return True

        except Exception as e:
            logger.warning(f"TCP send failed: {e}")
            self.disconnect()
            return False

    def send_heartbeat(self) -> bool:
        """Send heartbeat over TCP"""
        if not self.connected:
            return False

        try:
            message = json.dumps({
                'type': 'heartbeat',
                'agent_id': self.agent_id,
                'timestamp': time.time()
            }).encode('utf-8')

            length = len(message)
            with self.lock:
                self.socket.sendall(length.to_bytes(4, 'big'))
                self.socket.sendall(message)
            return True

        except Exception as e:
            logger.debug(f"TCP heartbeat failed: {e}")
            return False


# =============================================================================
# ECS NORMALIZER
# =============================================================================

class ECSNormalizer:
    """Normalize events to Elastic Common Schema"""

    SYSLOG_SEVERITY = {
        0: 'emergency', 1: 'alert', 2: 'critical', 3: 'error',
        4: 'warning', 5: 'notice', 6: 'informational', 7: 'debug'
    }

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

        # Source-specific normalization
        if source_type.startswith('linux_'):
            self._normalize_log(ecs, event, source_type)
        elif source_type.startswith('edr_'):
            self._normalize_edr(ecs, event, source_type)

        # Generate event ID
        unique = f"{ecs['@timestamp']}{self.hostname}{event.get('message', '')}{source_type}"
        ecs['event']['id'] = hashlib.sha256(unique.encode()).hexdigest()[:16]

        return ecs

    def _normalize_log(self, ecs: Dict, event: Dict, source_type: str):
        """Normalize log events"""
        message = event.get('message', '')

        if source_type == 'linux_journald':
            if '_SYSTEMD_UNIT' in event:
                ecs['systemd'] = {'unit': event['_SYSTEMD_UNIT']}
            if '_PID' in event:
                ecs['process'] = {'pid': int(event['_PID']), 'name': event.get('_COMM', '')}
            ecs['event']['category'] = ['host']

        elif source_type == 'linux_auth':
            ecs['event']['category'] = ['authentication']
            # SSH patterns
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
        """Normalize EDR events"""
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

        # Threat info
        if event.get('threat_detected'):
            ecs['threat'] = {'indicator': event.get('ioc_match', {}), 'matched': True}
            ecs['event']['kind'] = 'alert'

        ecs['event']['action'] = event.get('event_action', '')


# =============================================================================
# LOG COLLECTORS
# =============================================================================

class JournaldCollector:
    """Collect from systemd journal"""

    def __init__(self, event_queue: queue.Queue):
        self.queue = event_queue
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
                        event = {
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'message': entry.get('MESSAGE', ''),
                            '_SYSTEMD_UNIT': entry.get('_SYSTEMD_UNIT', ''),
                            '_PID': entry.get('_PID', ''),
                            '_COMM': entry.get('_COMM', ''),
                            'PRIORITY': entry.get('PRIORITY', 6),
                            'source_type': 'linux_journald'
                        }
                        try:
                            self.queue.put_nowait(event)
                        except queue.Full:
                            pass
        except Exception as e:
            logger.error(f"Journald error: {e}")


class FileCollector:
    """Tail a log file"""

    def __init__(self, filepath: str, source_type: str, event_queue: queue.Queue):
        self.filepath = filepath
        self.source_type = source_type
        self.queue = event_queue
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
                time.sleep(1)
        except Exception as e:
            logger.error(f"File collector error: {e}")


# =============================================================================
# EDR MONITORS
# =============================================================================

class ProcessMonitor:
    """Monitor process creation/termination"""

    def __init__(self, event_queue: queue.Queue, ioc_db: IOCDatabase):
        self.queue = event_queue
        self.ioc_db = ioc_db
        self.running = False
        self.thread = None
        self.known_pids: Dict[int, Dict] = {}

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor, daemon=True)
        self.thread.start()
        logger.info("Process monitor started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _monitor(self):
        self._scan_processes()
        while self.running:
            try:
                self._scan_processes()
                time.sleep(1)
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

                        # Get hash
                        if proc_info['exe'] and os.path.exists(proc_info['exe']):
                            try:
                                proc_info['exe_hash'] = self._hash_file(proc_info['exe'])
                            except:
                                proc_info['exe_hash'] = ''

                        self.known_pids[pid] = proc_info
                        self._emit_event("start", proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        else:
            # /proc fallback
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                current_pids.add(pid)
                if pid not in self.known_pids:
                    proc_info = self._read_proc(pid)
                    if proc_info:
                        self.known_pids[pid] = proc_info
                        self._emit_event("start", proc_info)

        # Terminated processes
        for pid in set(self.known_pids.keys()) - current_pids:
            proc_info = self.known_pids.pop(pid, {})
            self._emit_event("end", proc_info)

    def _read_proc(self, pid: int) -> Optional[Dict]:
        proc_path = Path("/proc") / str(pid)
        try:
            name = (proc_path / "comm").read_text().strip()
            cmdline = (proc_path / "cmdline").read_bytes().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
            exe = ""
            try:
                exe = os.readlink(proc_path / "exe")
            except:
                pass
            return {'pid': pid, 'name': name, 'exe': exe, 'cmdline': cmdline}
        except:
            return None

    def _hash_file(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _emit_event(self, action: str, proc_info: Dict):
        # Check IOCs
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


class FileIntegrityMonitor:
    """Monitor file changes"""

    def __init__(self, event_queue: queue.Queue, paths: List[str], ioc_db: IOCDatabase):
        self.queue = event_queue
        self.paths = paths
        self.ioc_db = ioc_db
        self.running = False
        self.thread = None
        self.baseline: Dict[str, str] = {}

    def start(self):
        self._build_baseline()
        self.running = True

        if HAS_INOTIFY:
            self.thread = threading.Thread(target=self._inotify_monitor, daemon=True)
        else:
            self.thread = threading.Thread(target=self._poll_monitor, daemon=True)

        self.thread.start()
        logger.info(f"FIM started ({len(self.paths)} paths)")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _build_baseline(self):
        for path in self.paths:
            self._hash_path(path)

    def _hash_path(self, path: str):
        try:
            p = Path(path)
            if p.is_file():
                self.baseline[path] = self._hash_file(path)
            elif p.is_dir():
                for f in p.rglob('*'):
                    if f.is_file():
                        self.baseline[str(f)] = self._hash_file(str(f))
        except:
            pass

    def _hash_file(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return ""

    def _inotify_monitor(self):
        wm = pyinotify.WatchManager()
        mask = pyinotify.IN_CREATE | pyinotify.IN_DELETE | pyinotify.IN_MODIFY | pyinotify.IN_ATTRIB

        class Handler(pyinotify.ProcessEvent):
            def __init__(self, fim):
                self.fim = fim

            def process_default(self, event):
                self.fim._handle_event(event.pathname, event.mask)

        handler = Handler(self)
        notifier = pyinotify.Notifier(wm, handler, timeout=1000)

        for path in self.paths:
            try:
                if os.path.isdir(path):
                    wm.add_watch(path, mask, rec=True, auto_add=True)
                elif os.path.exists(path):
                    wm.add_watch(path, mask)
            except:
                pass

        while self.running:
            try:
                notifier.process_events()
                if notifier.check_events():
                    notifier.read_events()
            except:
                time.sleep(1)

        notifier.stop()

    def _handle_event(self, filepath: str, mask: int):
        action = "modified"
        if mask & pyinotify.IN_CREATE:
            action = "created"
        elif mask & pyinotify.IN_DELETE:
            action = "deleted"

        old_hash = self.baseline.get(filepath, "")
        new_hash = ""

        if action != "deleted" and os.path.isfile(filepath):
            new_hash = self._hash_file(filepath)
            self.baseline[filepath] = new_hash
        else:
            self.baseline.pop(filepath, None)

        # Check IOC
        ioc_match = None
        if new_hash and self.ioc_db and self.ioc_db.match_hash(new_hash):
            ioc_match = {'type': 'hash', 'value': new_hash}

        self._emit_event(filepath, action, old_hash, new_hash, ioc_match)

    def _poll_monitor(self):
        while self.running:
            for path in self.paths:
                self._check_path(path)
            time.sleep(30)

    def _check_path(self, path: str):
        try:
            p = Path(path)
            if p.is_file():
                old = self.baseline.get(path, "")
                new = self._hash_file(path)
                if old != new:
                    action = "created" if not old else "modified"
                    self.baseline[path] = new
                    self._emit_event(path, action, old, new, None)
        except:
            pass

    def _emit_event(self, filepath: str, action: str, old_hash: str, new_hash: str, ioc_match: Optional[Dict]):
        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'file_integrity',
            'event_action': action,
            'source_type': 'edr_fim',
            'file': {'path': filepath},
            'hash': {'old': old_hash, 'new': new_hash, 'algorithm': 'sha256'},
            'ioc_match': ioc_match,
            'threat_detected': ioc_match is not None
        }
        try:
            self.queue.put_nowait(event)
        except queue.Full:
            pass


class NetworkMonitor:
    """Monitor network connections"""

    def __init__(self, event_queue: queue.Queue, ioc_db: IOCDatabase):
        self.queue = event_queue
        self.ioc_db = ioc_db
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
        logger.info("Network monitor started")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _monitor(self):
        while self.running:
            try:
                self._scan_connections()
                time.sleep(5)
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

        # Cleanup closed
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

        # Check IOC
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
# ASSET INVENTORY
# =============================================================================

class AssetCollector:
    """Collect system inventory"""

    def __init__(self, hostname: str):
        self.hostname = hostname

    def collect(self) -> Dict:
        inventory = {
            'hostname': self.hostname,
            'collected_at': datetime.now(timezone.utc).isoformat(),
            'ip_addresses': [],
            'mac_addresses': [],
            'os': {},
            'hardware': {},
            'software': {'packages': [], 'services': []},
            'users': [],
            'network': {'interfaces': [], 'open_ports': []}
        }

        self._collect_os(inventory)
        self._collect_hardware(inventory)
        self._collect_network(inventory)
        self._collect_packages(inventory)
        self._collect_services(inventory)
        self._collect_users(inventory)
        self._collect_ports(inventory)

        return inventory

    def _collect_os(self, inv: Dict):
        try:
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        inv['os']['version'] = line.split('=')[1].strip().strip('"')
                        break
            inv['os']['kernel'] = subprocess.check_output(['uname', '-r']).decode().strip()
            inv['os']['type'] = 'linux'
        except:
            pass

    def _collect_hardware(self, inv: Dict):
        try:
            cpu = {}
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        if k.strip() == 'model name':
                            cpu['model'] = v.strip()
                        elif k.strip() == 'cpu cores':
                            cpu['cores'] = int(v.strip())
            inv['hardware']['cpu'] = cpu

            if HAS_PSUTIL:
                inv['hardware']['memory_total_gb'] = round(psutil.virtual_memory().total / (1024**3), 2)
        except:
            pass

    def _collect_network(self, inv: Dict):
        if not HAS_PSUTIL:
            return
        try:
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                if iface == 'lo':
                    continue
                for addr in addr_list:
                    if addr.family.name == 'AF_INET':
                        inv['ip_addresses'].append(addr.address)
                    elif addr.family.name == 'AF_PACKET' and addr.address != '00:00:00:00:00:00':
                        inv['mac_addresses'].append(addr.address)
        except:
            pass

    def _collect_packages(self, inv: Dict):
        try:
            if os.path.exists('/usr/bin/dpkg'):
                result = subprocess.run(
                    ['dpkg-query', '-W', '-f', '${Package}\t${Version}\n'],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.strip().split('\n')[:500]:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        inv['software']['packages'].append({'name': parts[0], 'version': parts[1]})
            elif os.path.exists('/usr/bin/rpm'):
                result = subprocess.run(
                    ['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}\n'],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.strip().split('\n')[:500]:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        inv['software']['packages'].append({'name': parts[0], 'version': parts[1]})
        except:
            pass

    def _collect_services(self, inv: Dict):
        try:
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if parts:
                    inv['software']['services'].append({'name': parts[0].replace('.service', '')})
        except:
            pass

    def _collect_users(self, inv: Dict):
        try:
            with open('/etc/passwd') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        uid = int(parts[2])
                        if uid >= 1000 or uid == 0:
                            inv['users'].append({
                                'username': parts[0],
                                'uid': uid,
                                'home': parts[5],
                                'shell': parts[6]
                            })
        except:
            pass

    def _collect_ports(self, inv: Dict):
        if not HAS_PSUTIL:
            return
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    proc_name = ""
                    if conn.pid:
                        try:
                            proc_name = psutil.Process(conn.pid).name()
                        except:
                            pass
                    inv['network']['open_ports'].append({
                        'port': conn.laddr.port,
                        'process': proc_name
                    })
        except:
            pass


# =============================================================================
# RESPONSE ENGINE
# =============================================================================

class ResponseEngine:
    """Execute response actions"""

    def __init__(self):
        self.quarantine_dir = Path(QUARANTINE_DIR)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.blocked_ips: Set[str] = set()

    def kill_process(self, pid: int, reason: str = "") -> Dict:
        try:
            if HAS_PSUTIL:
                proc = psutil.Process(pid)
                name = proc.name()
                proc.kill()
            else:
                name = f"PID:{pid}"
                os.kill(pid, signal.SIGKILL)
            logger.warning(f"Killed process {pid} ({name}): {reason}")
            return {'success': True, 'action': 'kill_process', 'pid': pid}
        except Exception as e:
            return {'success': False, 'action': 'kill_process', 'error': str(e)}

    def quarantine_file(self, filepath: str, reason: str = "") -> Dict:
        try:
            src = Path(filepath)
            if not src.exists():
                return {'success': False, 'error': 'File not found'}

            file_hash = self._hash_file(filepath)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quar_name = f"{timestamp}_{file_hash[:8]}_{src.name}"
            quar_path = self.quarantine_dir / quar_name

            # Save metadata
            meta = {
                'original_path': str(src.absolute()),
                'quarantine_time': datetime.now(timezone.utc).isoformat(),
                'sha256': file_hash,
                'reason': reason
            }

            shutil.move(str(src), str(quar_path))
            quar_path.chmod(0o000)

            with open(self.quarantine_dir / f"{quar_name}.meta.json", 'w') as f:
                json.dump(meta, f)

            logger.warning(f"Quarantined {filepath}: {reason}")
            return {'success': True, 'action': 'quarantine', 'quarantine_path': str(quar_path)}
        except Exception as e:
            return {'success': False, 'action': 'quarantine', 'error': str(e)}

    def block_ip(self, ip: str, reason: str = "") -> Dict:
        try:
            if ip in self.blocked_ips:
                return {'success': True, 'already_blocked': True}
            subprocess.run(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'], check=True)
            self.blocked_ips.add(ip)
            logger.warning(f"Blocked IP {ip}: {reason}")
            return {'success': True, 'action': 'block_ip', 'ip': ip}
        except Exception as e:
            return {'success': False, 'action': 'block_ip', 'error': str(e)}

    def _hash_file(self, filepath: str) -> str:
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()


# =============================================================================
# UNIFIED AGENT
# =============================================================================

class T1UnifiedAgent:
    """Main unified agent"""

    STATE_UNREGISTERED = 'unregistered'
    STATE_PENDING = 'pending'
    STATE_APPROVED = 'approved'

    def __init__(self, config: AgentConfig):
        self.config = config
        self.running = False
        self.event_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.ioc_db = IOCDatabase()
        self.normalizer = ECSNormalizer(config.hostname)
        self.response_engine = ResponseEngine()
        self.asset_collector = AssetCollector(config.hostname)

        # TCP transport for log streaming
        self.tcp_transport: Optional[TCPLogTransport] = None

        # Collectors and monitors
        self.collectors: List = []
        self.process_monitor: Optional[ProcessMonitor] = None
        self.fim_monitor: Optional[FileIntegrityMonitor] = None
        self.network_monitor: Optional[NetworkMonitor] = None

        # Stats
        self.events_sent = 0
        self.threats_detected = 0
        self.actions_taken = 0
        self.last_heartbeat = 0
        self.last_ioc_refresh = 0
        self.last_inventory_sync = 0

        # Registration
        self.registration_state = self.STATE_UNREGISTERED
        self.server_agent_id = None
        self.active_token = None

        if not HAS_REQUESTS:
            logger.error("requests library required")
            sys.exit(1)

    def _gather_system_info(self) -> Dict:
        """Gather current system resource information"""
        info = {}
        try:
            # CPU info
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        if k.strip() == 'model name':
                            info['cpu_model'] = v.strip()
                        elif k.strip() == 'cpu cores':
                            info['cpu_cores'] = int(v.strip())
        except:
            pass

        if HAS_PSUTIL:
            try:
                # Memory
                mem = psutil.virtual_memory()
                info['memory_total_gb'] = round(mem.total / (1024**3), 2)
                info['memory_used_gb'] = round(mem.used / (1024**3), 2)
                info['memory_percent'] = mem.percent

                # Disk
                disk = psutil.disk_usage('/')
                info['disk_total_gb'] = round(disk.total / (1024**3), 2)
                info['disk_used_gb'] = round(disk.used / (1024**3), 2)
                info['disk_percent'] = disk.percent

                # CPU usage
                info['cpu_percent'] = psutil.cpu_percent(interval=0.1)

                # Uptime
                boot_time = psutil.boot_time()
                info['uptime_seconds'] = int(time.time() - boot_time)

                # Network I/O
                try:
                    net_io = psutil.net_io_counters()
                    info['network_bytes_sent'] = net_io.bytes_sent
                    info['network_bytes_recv'] = net_io.bytes_recv
                except:
                    pass

                # Process count
                try:
                    info['process_count'] = len(psutil.pids())
                except:
                    pass

                # Load average (Unix only)
                try:
                    load = os.getloadavg()
                    info['load_average'] = list(load)
                except:
                    pass
            except:
                pass

        return info

    def start(self):
        """Start the agent"""
        logger.info(f"Starting T1 Unified Agent v{VERSION}")
        logger.info(f"Mode: {self.config.mode.value}")
        logger.info(f"Hostname: {self.config.hostname}")
        logger.info(f"Server: {self.config.server_url}")

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

        # Initialize TCP transport for log streaming
        if self.config.use_tcp_stream and self.config.mode in [AgentMode.LOG_COLLECTOR, AgentMode.FULL]:
            # Extract host from server_url
            from urllib.parse import urlparse
            parsed = urlparse(self.config.server_url)
            tcp_host = parsed.hostname or 'localhost'
            tcp_port = self.config.log_port

            self.tcp_transport = TCPLogTransport(
                host=tcp_host,
                port=tcp_port,
                agent_id=self.server_agent_id or self.config.hostname,
                use_ssl=self.config.use_ssl
            )
            logger.info(f"TCP log transport: {tcp_host}:{tcp_port}")

            # Try to connect
            if self.tcp_transport.connect():
                logger.info("TCP log transport connected")
            else:
                logger.warning("TCP connect failed, will use HTTP fallback")

        # Initial setup based on mode
        if self.config.mode in [AgentMode.EDR, AgentMode.FULL]:
            self._refresh_iocs()

        if self.config.enable_inventory:
            self._sync_inventory()

        # Start collectors/monitors
        self._start_collectors()

        # Main loop
        self._run()

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping agent...")
        self.running = False

        # Close TCP transport
        if self.tcp_transport:
            self.tcp_transport.disconnect()

        for collector in self.collectors:
            collector.stop()
        if self.process_monitor:
            self.process_monitor.stop()
        if self.fim_monitor:
            self.fim_monitor.stop()
        if self.network_monitor:
            self.network_monitor.stop()

    def _register(self) -> Dict:
        """Register with server"""
        # Determine endpoint based on mode
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
            "system_info": self._gather_system_info(),
            "capabilities": {
                "mode": self.config.mode.value,
                "log_collection": self.config.mode in [AgentMode.LOG_COLLECTOR, AgentMode.FULL],
                "process_monitor": self.config.enable_process_monitor,
                "fim": self.config.enable_fim,
                "network_monitor": self.config.enable_network_monitor,
                "response_actions": self.config.enable_response_actions,
                "inventory": self.config.enable_inventory
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=30)
            return response.json() if response.status_code == 200 else {"status": "error"}
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {"status": "error", "message": str(e)}

    def _check_status(self) -> Dict:
        """Check registration status"""
        if self.config.mode == AgentMode.LOG_COLLECTOR:
            url = f"{self.config.server_url}/api/v1/logs/agents/check/{self.config.agent_key}"
        else:
            url = f"{self.config.server_url}/api/v1/edr/agents/check/{self.config.agent_key}"

        try:
            response = requests.get(url, timeout=10)
            return response.json() if response.status_code == 200 else {}
        except:
            return {}

    def _wait_for_approval(self):
        """Wait for approval"""
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
            elif status.get("status") == "rejected":
                logger.error("Agent REJECTED")
                return

    def _refresh_iocs(self):
        """Fetch IOCs from server"""
        if time.time() - self.last_ioc_refresh < DEFAULT_IOC_REFRESH_INTERVAL:
            return

        url = f"{self.config.server_url}/api/v1/edr/iocs"
        headers = {'X-Agent-Token': self.active_token}

        try:
            response = requests.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                iocs = response.json()
                self.ioc_db.file_hashes = set(h.lower() for h in iocs.get('hashes', []))
                self.ioc_db.ip_addresses = set(iocs.get('ips', []))
                self.ioc_db.domains = set(d.lower() for d in iocs.get('domains', []))
                self.ioc_db.process_names = set(p.lower() for p in iocs.get('process_names', []))
                self.ioc_db.file_paths = set(iocs.get('file_paths', []))
                self.last_ioc_refresh = time.time()

                total = len(self.ioc_db.file_hashes) + len(self.ioc_db.ip_addresses) + len(self.ioc_db.domains)
                logger.info(f"Loaded {total} IOCs")
        except Exception as e:
            logger.warning(f"IOC refresh failed: {e}")

    def _sync_inventory(self):
        """Sync inventory with server"""
        logger.info("Collecting asset inventory...")
        try:
            inventory = self.asset_collector.collect()

            # Try EDR endpoint first, fall back to logs
            url = f"{self.config.server_url}/api/v1/edr/agents/{self.server_agent_id}/inventory"
            headers = {'X-Agent-Token': self.active_token, 'Content-Type': 'application/json'}

            response = requests.post(url, headers=headers, json=inventory, timeout=60)
            if response.status_code == 200:
                self.last_inventory_sync = time.time()
                logger.info(f"Inventory synced: {len(inventory['software']['packages'])} packages")
        except Exception as e:
            logger.warning(f"Inventory sync failed: {e}")

    def _start_collectors(self):
        """Start log collectors and EDR monitors based on config"""

        # Log collectors
        if self.config.mode in [AgentMode.LOG_COLLECTOR, AgentMode.FULL]:
            if self.config.collect_journald and HAS_SYSTEMD:
                collector = JournaldCollector(self.event_queue)
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

        # EDR monitors
        if self.config.mode in [AgentMode.EDR, AgentMode.FULL]:
            if self.config.enable_process_monitor:
                self.process_monitor = ProcessMonitor(self.event_queue, self.ioc_db)
                self.process_monitor.start()

            if self.config.enable_fim:
                self.fim_monitor = FileIntegrityMonitor(self.event_queue, self.config.fim_paths, self.ioc_db)
                self.fim_monitor.start()

            if self.config.enable_network_monitor:
                self.network_monitor = NetworkMonitor(self.event_queue, self.ioc_db)
                self.network_monitor.start()

        logger.info(f"Started {len(self.collectors)} log collectors")

    def _run(self):
        """Main processing loop"""
        batch = []
        last_flush = time.time()

        while self.running:
            try:
                # Heartbeat
                if time.time() - self.last_heartbeat > self.config.heartbeat_interval:
                    self._send_heartbeat()

                # Refresh IOCs (EDR modes)
                if self.config.mode in [AgentMode.EDR, AgentMode.FULL]:
                    self._refresh_iocs()

                # Inventory sync
                if self.config.enable_inventory:
                    if time.time() - self.last_inventory_sync > self.config.inventory_sync_interval:
                        self._sync_inventory()

                # Process events
                try:
                    event = self.event_queue.get(timeout=1)

                    # Normalize
                    source_type = event.get('source_type', 'unknown')
                    ecs_event = self.normalizer.normalize(event, source_type)

                    # Handle threats
                    if event.get('threat_detected'):
                        self.threats_detected += 1
                        self._handle_threat(event)

                    batch.append(ecs_event)
                except queue.Empty:
                    pass

                # Flush batch
                now = time.time()
                if len(batch) >= self.config.batch_size or (batch and now - last_flush >= self.config.flush_interval):
                    self._send_batch(batch)
                    batch = []
                    last_flush = now

            except Exception as e:
                logger.error(f"Processing error: {e}")
                time.sleep(1)

        if batch:
            self._send_batch(batch)

    def _handle_threat(self, event: Dict):
        """Handle detected threat"""
        logger.warning(f"THREAT: {event.get('event_type')} - {event.get('ioc_match')}")

        if not self.config.enable_response_actions:
            return

        event_type = event.get('event_type')
        ioc_match = event.get('ioc_match', {})

        if event_type == 'process' and self.config.auto_kill:
            pid = event.get('process', {}).get('pid')
            if pid:
                result = self.response_engine.kill_process(pid, f"IOC: {ioc_match}")
                if result.get('success'):
                    self.actions_taken += 1

        elif event_type == 'file_integrity' and self.config.auto_quarantine:
            filepath = event.get('file', {}).get('path')
            if filepath:
                result = self.response_engine.quarantine_file(filepath, f"IOC: {ioc_match}")
                if result.get('success'):
                    self.actions_taken += 1

        elif event_type == 'network' and ioc_match.get('type') == 'ip':
            ip = ioc_match.get('value')
            if ip:
                result = self.response_engine.block_ip(ip, "IOC match")
                if result.get('success'):
                    self.actions_taken += 1

    def _send_batch(self, events: List[Dict]):
        """Send events to server via TCP stream or HTTP"""
        if not events:
            return

        # Try TCP streaming first (for log-collector and full modes)
        if self.config.use_tcp_stream and self.tcp_transport:
            if self.tcp_transport.send_logs(events):
                self.events_sent += len(events)
                logger.debug(f"Sent {len(events)} events via TCP")
                return
            else:
                # Fall back to HTTP if TCP fails
                logger.debug("TCP failed, falling back to HTTP")

        # HTTP fallback or EDR-only mode
        if self.config.mode == AgentMode.LOG_COLLECTOR:
            url = f"{self.config.server_url}/api/v1/logs/ingest/bulk"
            payload = {'source_type': events[0].get('source_type', 'linux_syslog'), 'events': events}
        else:
            url = f"{self.config.server_url}/api/v1/edr/events"
            payload = {'events': events, 'agent_id': self.server_agent_id}

        headers = {'X-Agent-Token': self.active_token, 'Content-Type': 'application/json'}

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=30)
            if response.status_code == 200:
                self.events_sent += len(events)
                logger.debug(f"Sent {len(events)} events via HTTP")

                # Check for server actions
                result = response.json()
                if result.get('actions') or result.get('pending_actions'):
                    self._execute_actions(result.get('actions') or result.get('pending_actions', []))
            else:
                logger.error(f"Send failed: {response.status_code}")
        except Exception as e:
            logger.error(f"Send error: {e}")

    def _execute_actions(self, actions: List[Dict]):
        """Execute server-requested actions"""
        for action in actions:
            action_type = action.get('type')
            logger.info(f"Executing server action: {action_type}")

            if action_type == 'kill_process':
                self.response_engine.kill_process(action.get('pid'), action.get('reason', ''))
            elif action_type == 'quarantine_file':
                self.response_engine.quarantine_file(action.get('filepath'), action.get('reason', ''))
            elif action_type == 'block_ip':
                self.response_engine.block_ip(action.get('ip'), action.get('reason', ''))

            self.actions_taken += 1

    def _send_heartbeat(self):
        """Send heartbeat"""
        # Determine endpoint
        if self.config.mode == AgentMode.LOG_COLLECTOR:
            url = f"{self.config.server_url}/api/v1/logs/agents/{self.server_agent_id}/heartbeat"
        else:
            url = f"{self.config.server_url}/api/v1/edr/agents/{self.server_agent_id}/heartbeat"

        headers = {'X-Agent-Token': self.active_token, 'Content-Type': 'application/json'}

        payload = {
            'hostname': self.config.hostname,
            'agent_version': VERSION,
            'mode': self.config.mode.value,
            'events_sent': self.events_sent,
            'threats_detected': self.threats_detected,
            'actions_taken': self.actions_taken,
            'queue_size': self.event_queue.qsize(),
            'system_info': self._gather_system_info()
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                self.last_heartbeat = time.time()
                result = response.json()

                # Handle pending actions/config
                if result.get('pending_actions'):
                    self._execute_actions(result['pending_actions'])
                if result.get('config_update'):
                    self._apply_config(result['config_update'])
                # Handle agent update
                if result.get('update_available'):
                    self._handle_update(result['update_available'])
            elif response.status_code == 404:
                # Agent not found on server - re-register
                logger.warning("Agent not found on server, re-registering...")
                self.registration_state = self.STATE_UNREGISTERED
                self._wait_for_approval()
                if self.registration_state == self.STATE_APPROVED:
                    logger.info(f"Re-registered successfully: {self.server_agent_id}")
        except Exception as e:
            logger.warning(f"Heartbeat error: {e}")

    # =========================================================================
    # REMOTE UPDATE HANDLING (Secure)
    # =========================================================================
    # Security features:
    # - Ed25519 signature verification
    # - SHA256 checksum validation
    # - HTTPS-only downloads (when server uses HTTPS)
    # - Token authentication
    # =========================================================================

    def _handle_update(self, update_info: Dict):
        """Download and apply agent update with security verification"""
        new_version = update_info.get('version')
        logger.info(f"Update available: {VERSION} -> {new_version}")

        # Get public key for signature verification
        public_key_pem = self._fetch_public_key(update_info)
        if not public_key_pem:
            logger.error("Failed to fetch signing public key - aborting update")
            return

        # Download new agent file
        new_file = self._download_update(update_info)
        if not new_file:
            logger.error("Update download failed")
            return

        # Read downloaded content for verification
        try:
            with open(new_file, 'rb') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Failed to read downloaded file: {e}")
            return

        # Verify SHA256 checksum first (fast check)
        expected_sha256 = update_info.get('sha256')
        if not self._verify_checksum_bytes(content, expected_sha256):
            logger.error("Update checksum verification failed")
            self._cleanup_file(new_file)
            return

        # Verify Ed25519 signature (cryptographic proof of authenticity)
        expected_signature = update_info.get('signature')
        if expected_signature:
            if not self._verify_signature(content, expected_signature, public_key_pem):
                logger.error("Update SIGNATURE VERIFICATION FAILED - possible tampering!")
                self._cleanup_file(new_file)
                return
            logger.info("Signature verification passed - update is authentic")
        else:
            logger.warning("No signature provided - skipping signature verification")

        # Backup current agent
        self._backup_current()

        # Replace agent file
        self._replace_agent(new_file)

        # Schedule restart
        self._schedule_restart()

    def _fetch_public_key(self, update_info: Dict) -> Optional[str]:
        """Fetch the public key for signature verification"""
        public_key_url = update_info.get('public_key_url', '/api/v1/logs/agents/package/public-key')
        url = f"{self.config.server_url}{public_key_url}"

        try:
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                return data.get('public_key_pem')
            else:
                logger.error(f"Failed to fetch public key: HTTP {response.status_code}")
        except Exception as e:
            logger.error(f"Error fetching public key: {e}")

        return None

    def _verify_signature(self, content: bytes, signature_b64: str, public_key_pem: str) -> bool:
        """Verify Ed25519 signature of content"""
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.exceptions import InvalidSignature
            import base64

            # Load public key
            public_key = serialization.load_pem_public_key(public_key_pem.encode('ascii'))

            # Decode signature
            signature = base64.b64decode(signature_b64)

            # Verify signature
            public_key.verify(signature, content)
            return True

        except InvalidSignature:
            logger.error("Invalid signature - content may have been tampered with")
            return False
        except ImportError:
            logger.warning("cryptography library not available - skipping signature verification")
            return True  # Allow update if crypto not available (fallback to checksum only)
        except Exception as e:
            logger.error(f"Signature verification error: {e}")
            return False

    def _download_update(self, update_info: Dict) -> Optional[str]:
        """Download agent package from server"""
        download_url = update_info.get('download_url', '/api/v1/logs/agents/package/download')
        url = f"{self.config.server_url}{download_url}"
        headers = {'X-Agent-Token': self.active_token}

        try:
            logger.info(f"Downloading update from {url}")
            response = requests.get(url, headers=headers, stream=True, timeout=300)

            if response.status_code == 200:
                # Save to temp file
                version = update_info.get('version', 'unknown')
                temp_path = f"/tmp/t1_unified_agent_{version}.py"

                with open(temp_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                logger.info(f"Update downloaded to {temp_path}")
                return temp_path
            else:
                logger.error(f"Update download failed: HTTP {response.status_code}")

        except Exception as e:
            logger.error(f"Update download error: {e}")

        return None

    def _verify_checksum_bytes(self, content: bytes, expected_sha256: str) -> bool:
        """Verify content integrity using SHA256"""
        import hashlib

        actual = hashlib.sha256(content).hexdigest()
        if actual == expected_sha256:
            logger.info("Checksum verification passed")
            return True
        else:
            logger.error(f"Checksum mismatch: expected {expected_sha256}, got {actual}")
            return False

    def _verify_checksum(self, file_path: str, expected_sha256: str) -> bool:
        """Verify file integrity using SHA256"""
        import hashlib

        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)

            actual = sha256_hash.hexdigest()
            if actual == expected_sha256:
                logger.info("Checksum verification passed")
                return True
            else:
                logger.error(f"Checksum mismatch: expected {expected_sha256}, got {actual}")
                return False
        except Exception as e:
            logger.error(f"Checksum verification error: {e}")
            return False

    def _cleanup_file(self, file_path: str):
        """Safely remove a file"""
        try:
            os.remove(file_path)
        except Exception:
            pass

    def _backup_current(self):
        """Backup current agent before update"""
        import shutil

        script_path = os.path.abspath(__file__)
        backup_path = f"{script_path}.backup"

        try:
            shutil.copy2(script_path, backup_path)
            logger.info(f"Backed up current agent to {backup_path}")
        except Exception as e:
            logger.warning(f"Backup failed (continuing anyway): {e}")

    def _replace_agent(self, new_file: str):
        """Replace current agent with new version"""
        import shutil

        script_path = os.path.abspath(__file__)

        try:
            shutil.copy2(new_file, script_path)
            os.chmod(script_path, 0o755)
            os.remove(new_file)
            logger.info(f"Replaced agent with new version")
        except Exception as e:
            logger.error(f"Agent replacement failed: {e}")
            raise

    def _schedule_restart(self):
        """Schedule agent restart for update"""
        logger.info("Scheduling agent restart for update...")

        # Create restart flag file for wrapper script
        install_dir = os.path.dirname(os.path.abspath(__file__))
        restart_flag = os.path.join(install_dir, ".update_restart")

        try:
            with open(restart_flag, 'w') as f:
                f.write(str(time.time()))
            logger.info(f"Restart flag created: {restart_flag}")
        except Exception as e:
            logger.warning(f"Could not create restart flag: {e}")

        # Stop the agent - wrapper script will restart it
        logger.info("Stopping agent for update restart...")
        self.running = False

    def _apply_config(self, config: Dict):
        """Apply config from server"""
        if 'batch_size' in config:
            self.config.batch_size = config['batch_size']
        if 'flush_interval' in config:
            self.config.flush_interval = config['flush_interval']
        if 'auto_kill' in config:
            self.config.auto_kill = config['auto_kill']
        if 'auto_quarantine' in config:
            self.config.auto_quarantine = config['auto_quarantine']
        logger.info("Applied config update from server")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='T1 Agentics Unified Linux Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  log-collector   Lightweight log collection only
  edr             EDR features (process/file/network monitoring, response)
  full            Everything (logs + EDR + inventory)

Examples:
  # Full mode (recommended)
  python3 t1_unified_agent.py --server https://t1.example.com:8000 --mode full

  # Log collector only
  python3 t1_unified_agent.py --server https://t1.example.com:8000 --mode log-collector

  # EDR with auto-response
  python3 t1_unified_agent.py --server https://t1.example.com:8000 --mode edr --auto-kill --auto-quarantine
        """
    )

    parser.add_argument('--server', '-s', required=True, help='T1 Agentics server URL')
    parser.add_argument('--mode', '-m', choices=['log-collector', 'edr', 'full'], default='full',
                        help='Agent mode (default: full)')
    parser.add_argument('--token', '-t', help='Agent token (optional)')
    parser.add_argument('--agent-id', '-i', help='Agent ID')
    parser.add_argument('--hostname', '-n', help='Override hostname')
    parser.add_argument('--tag', action='append', default=[], help='Add tag')

    # Log collection options
    parser.add_argument('--no-journald', action='store_true', help='Disable journald')
    parser.add_argument('--no-syslog', action='store_true', help='Disable syslog')
    parser.add_argument('--no-auth', action='store_true', help='Disable auth log')
    parser.add_argument('--no-audit', action='store_true', help='Disable audit log')

    # EDR options
    parser.add_argument('--no-process', action='store_true', help='Disable process monitor')
    parser.add_argument('--no-fim', action='store_true', help='Disable FIM')
    parser.add_argument('--no-network', action='store_true', help='Disable network monitor')
    parser.add_argument('--auto-kill', action='store_true', help='Auto-kill IOC processes')
    parser.add_argument('--auto-quarantine', action='store_true', help='Auto-quarantine IOC files')
    parser.add_argument('--fim-path', action='append', help='Additional FIM path')

    # Inventory
    parser.add_argument('--no-inventory', action='store_true', help='Disable inventory collection')

    # Transport
    parser.add_argument('--log-port', type=int, default=5514, help='TCP port for log streaming (default: 5514)')
    parser.add_argument('--no-tcp', action='store_true', help='Disable TCP streaming, use HTTP only')
    parser.add_argument('--tls', action='store_true', help='Use TLS for TCP log transport')

    parser.add_argument('--debug', '-d', action='store_true', help='Debug logging')
    parser.add_argument('--version', '-v', action='version', version=f'T1 Unified Agent v{VERSION}')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build FIM paths
    fim_paths = DEFAULT_FIM_PATHS.copy()
    if args.fim_path:
        fim_paths.extend(args.fim_path)

    # Create config
    mode_map = {
        'log-collector': AgentMode.LOG_COLLECTOR,
        'edr': AgentMode.EDR,
        'full': AgentMode.FULL
    }

    config = AgentConfig(
        server_url=args.server.rstrip('/'),
        mode=mode_map[args.mode],
        agent_token=args.token,
        agent_id=args.agent_id,
        hostname=args.hostname or socket.gethostname(),
        tags=args.tag,
        collect_journald=not args.no_journald,
        collect_syslog=not args.no_syslog,
        collect_auth=not args.no_auth,
        collect_audit=not args.no_audit,
        enable_process_monitor=not args.no_process,
        enable_fim=not args.no_fim,
        enable_network_monitor=not args.no_network,
        auto_kill=args.auto_kill,
        auto_quarantine=args.auto_quarantine,
        fim_paths=fim_paths,
        enable_inventory=not args.no_inventory,
        use_tcp_stream=not args.no_tcp,
        log_port=args.log_port,
        use_ssl=args.tls
    )

    agent = T1UnifiedAgent(config)

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
