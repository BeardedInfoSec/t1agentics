#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Linux EDR Agent
============================
Endpoint Detection and Response agent for Linux systems.

Extends log collection with:
- Process monitoring (execve via auditd/proc)
- File Integrity Monitoring (inotify)
- Network connection tracking
- Response actions (kill, block, quarantine)
- IOC matching (hashes, IPs, domains)

Usage:
    # Auto-registration mode
    python3 t1_edr.py --server https://your-server:8000

    # With token
    python3 t1_edr.py --server https://your-server:8000 --token YOUR_TOKEN

Requirements:
    pip install requests pyinotify psutil
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
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

# Optional imports with availability flags
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

# Configuration
VERSION = "1.0.0"
AGENT_TYPE = "t1-linux-edr"
DEFAULT_BATCH_SIZE = 50
DEFAULT_FLUSH_INTERVAL = 5  # Faster for EDR
DEFAULT_HEARTBEAT_INTERVAL = 30  # More frequent heartbeat
DEFAULT_IOC_REFRESH_INTERVAL = 300  # Refresh IOCs every 5 minutes
MAX_QUEUE_SIZE = 10000
RECONNECT_BASE_DELAY = 5
RECONNECT_MAX_DELAY = 300

# Default FIM paths to monitor
DEFAULT_FIM_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/systemd/system",
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/root/.ssh",
    "/root/.bashrc",
    "/root/.bash_profile",
]

# Quarantine directory
QUARANTINE_DIR = "/var/lib/t1-edr/quarantine"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('t1-edr')


@dataclass
class AssetInventory:
    """System asset inventory"""
    hostname: str = ""
    ip_addresses: List[str] = field(default_factory=list)
    mac_addresses: List[str] = field(default_factory=list)
    os_type: str = "linux"
    os_version: str = ""
    os_kernel: str = ""
    cpu_info: Dict = field(default_factory=dict)
    memory_total_gb: float = 0.0
    disk_info: List[Dict] = field(default_factory=list)
    network_interfaces: List[Dict] = field(default_factory=list)
    installed_packages: List[Dict] = field(default_factory=list)
    running_services: List[Dict] = field(default_factory=list)
    local_users: List[Dict] = field(default_factory=list)
    open_ports: List[Dict] = field(default_factory=list)
    last_boot: str = ""
    collected_at: str = ""

    def to_dict(self) -> Dict:
        return {
            'hostname': self.hostname,
            'ip_addresses': self.ip_addresses,
            'mac_addresses': self.mac_addresses,
            'os': {
                'type': self.os_type,
                'version': self.os_version,
                'kernel': self.os_kernel
            },
            'hardware': {
                'cpu': self.cpu_info,
                'memory_total_gb': self.memory_total_gb,
                'disks': self.disk_info
            },
            'network': {
                'interfaces': self.network_interfaces,
                'open_ports': self.open_ports
            },
            'software': {
                'packages': self.installed_packages,
                'services': self.running_services
            },
            'users': self.local_users,
            'last_boot': self.last_boot,
            'collected_at': self.collected_at
        }


@dataclass
class IOCDatabase:
    """In-memory IOC database for fast matching"""
    file_hashes: Set[str] = field(default_factory=set)  # SHA256 hashes
    ip_addresses: Set[str] = field(default_factory=set)
    domains: Set[str] = field(default_factory=set)
    process_names: Set[str] = field(default_factory=set)
    file_paths: Set[str] = field(default_factory=set)
    last_updated: float = 0

    def match_hash(self, hash_value: str) -> bool:
        return hash_value.lower() in self.file_hashes

    def match_ip(self, ip: str) -> bool:
        return ip in self.ip_addresses

    def match_domain(self, domain: str) -> bool:
        domain = domain.lower()
        # Check exact match and parent domains
        parts = domain.split('.')
        for i in range(len(parts)):
            check = '.'.join(parts[i:])
            if check in self.domains:
                return True
        return False

    def match_process(self, name: str) -> bool:
        return name.lower() in self.process_names

    def match_path(self, path: str) -> bool:
        return path in self.file_paths


@dataclass
class EDRConfig:
    """EDR agent configuration"""
    server_url: str
    agent_key: Optional[str] = None
    agent_token: Optional[str] = None
    agent_id: Optional[str] = None
    hostname: str = ""
    batch_size: int = DEFAULT_BATCH_SIZE
    flush_interval: int = DEFAULT_FLUSH_INTERVAL
    heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL

    # EDR-specific settings
    enable_process_monitor: bool = True
    enable_fim: bool = True
    enable_network_monitor: bool = True
    enable_response_actions: bool = True
    fim_paths: List[str] = None
    auto_quarantine: bool = False  # Auto-quarantine IOC matches
    auto_kill: bool = False  # Auto-kill malicious processes

    # Storage paths
    key_file: str = "/var/lib/t1-edr/agent.key"
    config_file: str = "/var/lib/t1-edr/config.json"
    state_file: str = "/var/lib/t1-edr/state.json"
    tags: List[str] = None

    def __post_init__(self):
        if not self.hostname:
            self.hostname = socket.gethostname()
        if self.tags is None:
            self.tags = []
        if self.fim_paths is None:
            self.fim_paths = DEFAULT_FIM_PATHS.copy()
        if not self.agent_key and not self.agent_token:
            self.agent_key = self._load_or_generate_key()

    def _load_or_generate_key(self) -> str:
        """Load existing key or generate new one"""
        key_path = Path(self.key_file)

        if key_path.exists():
            key = key_path.read_text().strip()
            logger.info(f"Loaded agent key: {key[:12]}...")
            return key

        # Generate new key
        new_key = f"edr_{uuid.uuid4().hex}"

        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(new_key)
            key_path.chmod(0o600)
            logger.info(f"Generated new agent key: {new_key[:12]}...")
        except PermissionError:
            logger.warning(f"Cannot save key to {key_path}, using ephemeral key")

        return new_key


class ProcessMonitor:
    """Monitor process creation and termination"""

    def __init__(self, event_queue: queue.Queue, ioc_db: IOCDatabase):
        self.queue = event_queue
        self.ioc_db = ioc_db
        self.running = False
        self.thread = None
        self.known_pids: Dict[int, Dict] = {}
        self.proc_path = Path("/proc")

    def start(self):
        """Start process monitoring"""
        if not HAS_PSUTIL:
            logger.warning("psutil not installed, using /proc polling (less efficient)")

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Process monitor started")

    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _monitor_loop(self):
        """Main monitoring loop"""
        # Initial process scan
        self._scan_processes()

        while self.running:
            try:
                self._scan_processes()
                time.sleep(1)  # Poll every second
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
                time.sleep(5)

    def _scan_processes(self):
        """Scan for new/terminated processes"""
        current_pids = set()

        if HAS_PSUTIL:
            self._scan_with_psutil(current_pids)
        else:
            self._scan_with_proc(current_pids)

        # Detect terminated processes
        terminated = set(self.known_pids.keys()) - current_pids
        for pid in terminated:
            proc_info = self.known_pids.pop(pid, {})
            self._emit_process_event("end", pid, proc_info)

    def _scan_with_psutil(self, current_pids: set):
        """Scan processes using psutil"""
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'ppid', 'create_time']):
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
                        'ppid': proc.info['ppid'],
                        'create_time': proc.info['create_time']
                    }

                    # Get file hash if executable exists
                    if proc_info['exe'] and os.path.exists(proc_info['exe']):
                        try:
                            proc_info['exe_hash'] = self._hash_file(proc_info['exe'])
                        except:
                            proc_info['exe_hash'] = ''

                    self.known_pids[pid] = proc_info
                    self._emit_process_event("start", pid, proc_info)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _scan_with_proc(self, current_pids: set):
        """Scan processes using /proc filesystem"""
        for entry in self.proc_path.iterdir():
            if not entry.name.isdigit():
                continue

            pid = int(entry.name)
            current_pids.add(pid)

            if pid not in self.known_pids:
                proc_info = self._read_proc_info(pid)
                if proc_info:
                    self.known_pids[pid] = proc_info
                    self._emit_process_event("start", pid, proc_info)

    def _read_proc_info(self, pid: int) -> Optional[Dict]:
        """Read process info from /proc"""
        proc_path = self.proc_path / str(pid)
        try:
            # Read comm (process name)
            name = (proc_path / "comm").read_text().strip()

            # Read cmdline
            cmdline_raw = (proc_path / "cmdline").read_bytes()
            cmdline = cmdline_raw.replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()

            # Read exe symlink
            exe = ""
            try:
                exe = os.readlink(proc_path / "exe")
            except:
                pass

            # Read status for ppid and uid
            status = {}
            for line in (proc_path / "status").read_text().split('\n'):
                if ':' in line:
                    key, val = line.split(':', 1)
                    status[key.strip()] = val.strip()

            ppid = int(status.get('PPid', 0))
            uid = int(status.get('Uid', '0').split()[0])

            # Get username from uid
            user = str(uid)
            try:
                import pwd
                user = pwd.getpwuid(uid).pw_name
            except:
                pass

            proc_info = {
                'pid': pid,
                'name': name,
                'exe': exe,
                'cmdline': cmdline,
                'user': user,
                'ppid': ppid,
                'uid': uid
            }

            # Get file hash
            if exe and os.path.exists(exe):
                try:
                    proc_info['exe_hash'] = self._hash_file(exe)
                except:
                    proc_info['exe_hash'] = ''

            return proc_info

        except (FileNotFoundError, PermissionError):
            return None

    def _hash_file(self, filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return ""

    def _emit_process_event(self, event_type: str, pid: int, proc_info: Dict):
        """Emit a process event"""
        # Check for IOC matches
        ioc_match = None
        if self.ioc_db:
            if proc_info.get('exe_hash') and self.ioc_db.match_hash(proc_info['exe_hash']):
                ioc_match = {'type': 'hash', 'value': proc_info['exe_hash']}
            elif proc_info.get('name') and self.ioc_db.match_process(proc_info['name']):
                ioc_match = {'type': 'process_name', 'value': proc_info['name']}
            elif proc_info.get('exe') and self.ioc_db.match_path(proc_info['exe']):
                ioc_match = {'type': 'file_path', 'value': proc_info['exe']}

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'process',
            'event_action': event_type,
            'source_type': 'edr_process',
            'process': proc_info,
            'ioc_match': ioc_match,
            'threat_detected': ioc_match is not None
        }

        try:
            self.queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue full, dropping process event")


class FileIntegrityMonitor:
    """Monitor file system changes using inotify"""

    def __init__(self, event_queue: queue.Queue, paths: List[str], ioc_db: IOCDatabase):
        self.queue = event_queue
        self.paths = paths
        self.ioc_db = ioc_db
        self.running = False
        self.thread = None
        self.baseline: Dict[str, str] = {}  # path -> hash
        self.wm = None  # inotify watch manager

    def start(self):
        """Start FIM"""
        if not HAS_INOTIFY:
            logger.warning("pyinotify not installed, using polling FIM (less efficient)")
            self.running = True
            self.thread = threading.Thread(target=self._poll_loop, daemon=True)
        else:
            self.running = True
            self.thread = threading.Thread(target=self._inotify_loop, daemon=True)

        # Build baseline
        self._build_baseline()

        self.thread.start()
        logger.info(f"File Integrity Monitor started ({len(self.paths)} paths)")

    def stop(self):
        """Stop FIM"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _build_baseline(self):
        """Build hash baseline of monitored paths"""
        for path in self.paths:
            self._hash_path(path)

    def _hash_path(self, path: str):
        """Hash a file or directory"""
        try:
            p = Path(path)
            if p.is_file():
                self.baseline[path] = self._hash_file(path)
            elif p.is_dir():
                for f in p.rglob('*'):
                    if f.is_file():
                        self.baseline[str(f)] = self._hash_file(str(f))
        except (PermissionError, FileNotFoundError):
            pass

    def _hash_file(self, filepath: str) -> str:
        """Calculate SHA256 hash"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return ""

    def _inotify_loop(self):
        """Monitor using inotify"""
        self.wm = pyinotify.WatchManager()
        mask = (pyinotify.IN_CREATE | pyinotify.IN_DELETE |
                pyinotify.IN_MODIFY | pyinotify.IN_MOVED_FROM |
                pyinotify.IN_MOVED_TO | pyinotify.IN_ATTRIB)

        class EventHandler(pyinotify.ProcessEvent):
            def __init__(self, fim):
                self.fim = fim

            def process_default(self, event):
                self.fim._handle_inotify_event(event)

        handler = EventHandler(self)
        notifier = pyinotify.Notifier(self.wm, handler, timeout=1000)

        # Add watches
        for path in self.paths:
            try:
                if os.path.isdir(path):
                    self.wm.add_watch(path, mask, rec=True, auto_add=True)
                elif os.path.exists(path):
                    self.wm.add_watch(path, mask)
            except Exception as e:
                logger.warning(f"Cannot watch {path}: {e}")

        while self.running:
            try:
                notifier.process_events()
                if notifier.check_events():
                    notifier.read_events()
            except Exception as e:
                logger.error(f"inotify error: {e}")
                time.sleep(1)

        notifier.stop()

    def _handle_inotify_event(self, event):
        """Handle inotify event"""
        filepath = event.pathname
        action = self._get_action_name(event.mask)

        # Calculate new hash for modifications
        new_hash = ""
        old_hash = self.baseline.get(filepath, "")

        if event.mask & (pyinotify.IN_CREATE | pyinotify.IN_MODIFY | pyinotify.IN_MOVED_TO):
            if os.path.isfile(filepath):
                new_hash = self._hash_file(filepath)
                self.baseline[filepath] = new_hash

        if event.mask & (pyinotify.IN_DELETE | pyinotify.IN_MOVED_FROM):
            self.baseline.pop(filepath, None)

        # Check IOC match
        ioc_match = None
        if new_hash and self.ioc_db and self.ioc_db.match_hash(new_hash):
            ioc_match = {'type': 'hash', 'value': new_hash}
        elif self.ioc_db and self.ioc_db.match_path(filepath):
            ioc_match = {'type': 'file_path', 'value': filepath}

        self._emit_fim_event(filepath, action, old_hash, new_hash, ioc_match)

    def _get_action_name(self, mask: int) -> str:
        """Convert inotify mask to action name"""
        if mask & pyinotify.IN_CREATE:
            return "created"
        if mask & pyinotify.IN_DELETE:
            return "deleted"
        if mask & pyinotify.IN_MODIFY:
            return "modified"
        if mask & pyinotify.IN_MOVED_FROM:
            return "moved_from"
        if mask & pyinotify.IN_MOVED_TO:
            return "moved_to"
        if mask & pyinotify.IN_ATTRIB:
            return "attributes_changed"
        return "unknown"

    def _poll_loop(self):
        """Fallback polling-based FIM"""
        while self.running:
            try:
                for path in self.paths:
                    self._check_path_changes(path)
                time.sleep(30)  # Poll every 30 seconds
            except Exception as e:
                logger.error(f"FIM poll error: {e}")

    def _check_path_changes(self, path: str):
        """Check a path for changes"""
        try:
            p = Path(path)
            if p.is_file():
                self._check_file_change(path)
            elif p.is_dir():
                # Check for new files
                current_files = set(str(f) for f in p.rglob('*') if f.is_file())
                known_files = set(k for k in self.baseline.keys() if k.startswith(path))

                # New files
                for f in current_files - known_files:
                    new_hash = self._hash_file(f)
                    self.baseline[f] = new_hash
                    self._emit_fim_event(f, "created", "", new_hash, None)

                # Deleted files
                for f in known_files - current_files:
                    old_hash = self.baseline.pop(f, "")
                    self._emit_fim_event(f, "deleted", old_hash, "", None)

                # Modified files
                for f in current_files & known_files:
                    self._check_file_change(f)

        except (PermissionError, FileNotFoundError):
            pass

    def _check_file_change(self, filepath: str):
        """Check single file for changes"""
        old_hash = self.baseline.get(filepath, "")
        new_hash = self._hash_file(filepath)

        if old_hash != new_hash:
            self.baseline[filepath] = new_hash
            action = "created" if not old_hash else "modified"

            ioc_match = None
            if new_hash and self.ioc_db and self.ioc_db.match_hash(new_hash):
                ioc_match = {'type': 'hash', 'value': new_hash}

            self._emit_fim_event(filepath, action, old_hash, new_hash, ioc_match)

    def _emit_fim_event(self, filepath: str, action: str, old_hash: str, new_hash: str, ioc_match: Optional[Dict]):
        """Emit a FIM event"""
        # Get file metadata
        file_info = {'path': filepath}
        try:
            stat = os.stat(filepath)
            file_info.update({
                'size': stat.st_size,
                'mode': oct(stat.st_mode),
                'uid': stat.st_uid,
                'gid': stat.st_gid,
                'mtime': datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat()
            })
        except:
            pass

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'file_integrity',
            'event_action': action,
            'source_type': 'edr_fim',
            'file': file_info,
            'hash': {
                'old': old_hash,
                'new': new_hash,
                'algorithm': 'sha256'
            },
            'ioc_match': ioc_match,
            'threat_detected': ioc_match is not None
        }

        try:
            self.queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue full, dropping FIM event")


class NetworkMonitor:
    """Monitor network connections"""

    def __init__(self, event_queue: queue.Queue, ioc_db: IOCDatabase):
        self.queue = event_queue
        self.ioc_db = ioc_db
        self.running = False
        self.thread = None
        self.known_connections: Dict[tuple, Dict] = {}

    def start(self):
        """Start network monitoring"""
        if not HAS_PSUTIL:
            logger.warning("psutil not installed, network monitoring disabled")
            return

        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logger.info("Network monitor started")

    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._scan_connections()
                time.sleep(5)  # Poll every 5 seconds
            except Exception as e:
                logger.error(f"Network monitor error: {e}")
                time.sleep(10)

    def _scan_connections(self):
        """Scan for new network connections"""
        current_connections = {}

        for conn in psutil.net_connections(kind='inet'):
            if conn.status != 'ESTABLISHED':
                continue

            key = (conn.pid, conn.laddr, conn.raddr)
            current_connections[key] = conn

            if key not in self.known_connections:
                self._handle_new_connection(conn)
                self.known_connections[key] = {'conn': conn, 'first_seen': time.time()}

        # Detect closed connections
        closed = set(self.known_connections.keys()) - set(current_connections.keys())
        for key in closed:
            self._handle_closed_connection(self.known_connections.pop(key))

    def _handle_new_connection(self, conn):
        """Handle a new connection"""
        remote_ip = conn.raddr.ip if conn.raddr else ""
        remote_port = conn.raddr.port if conn.raddr else 0

        # Get process info
        proc_info = {}
        if conn.pid:
            try:
                proc = psutil.Process(conn.pid)
                proc_info = {
                    'pid': conn.pid,
                    'name': proc.name(),
                    'exe': proc.exe()
                }
            except:
                proc_info = {'pid': conn.pid}

        # Check IOC match
        ioc_match = None
        if remote_ip and self.ioc_db and self.ioc_db.match_ip(remote_ip):
            ioc_match = {'type': 'ip', 'value': remote_ip}

        # Try to resolve hostname and check domain IOCs
        remote_domain = ""
        try:
            remote_domain = socket.gethostbyaddr(remote_ip)[0]
            if not ioc_match and self.ioc_db and self.ioc_db.match_domain(remote_domain):
                ioc_match = {'type': 'domain', 'value': remote_domain}
        except:
            pass

        event = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'network',
            'event_action': 'connection_established',
            'source_type': 'edr_network',
            'network': {
                'direction': 'outbound',
                'local_ip': conn.laddr.ip if conn.laddr else "",
                'local_port': conn.laddr.port if conn.laddr else 0,
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'remote_domain': remote_domain,
                'protocol': 'tcp'
            },
            'process': proc_info,
            'ioc_match': ioc_match,
            'threat_detected': ioc_match is not None
        }

        try:
            self.queue.put_nowait(event)
        except queue.Full:
            logger.warning("Event queue full, dropping network event")

    def _handle_closed_connection(self, conn_info: Dict):
        """Handle a closed connection"""
        # Optional: emit connection closed events
        pass


class AssetCollector:
    """Collect system asset inventory"""

    def __init__(self, hostname: str):
        self.hostname = hostname

    def collect(self) -> AssetInventory:
        """Collect full system inventory"""
        inventory = AssetInventory(
            hostname=self.hostname,
            collected_at=datetime.now(timezone.utc).isoformat()
        )

        # Collect all components
        self._collect_os_info(inventory)
        self._collect_hardware_info(inventory)
        self._collect_network_info(inventory)
        self._collect_packages(inventory)
        self._collect_services(inventory)
        self._collect_users(inventory)
        self._collect_open_ports(inventory)
        self._collect_boot_time(inventory)

        return inventory

    def _collect_os_info(self, inventory: AssetInventory):
        """Collect OS information"""
        # Get OS version from /etc/os-release
        try:
            with open('/etc/os-release') as f:
                for line in f:
                    if line.startswith('PRETTY_NAME='):
                        inventory.os_version = line.split('=')[1].strip().strip('"')
                        break
        except:
            pass

        # Get kernel version
        try:
            inventory.os_kernel = subprocess.check_output(['uname', '-r']).decode().strip()
        except:
            pass

    def _collect_hardware_info(self, inventory: AssetInventory):
        """Collect hardware information"""
        # CPU info
        try:
            cpu_info = {}
            with open('/proc/cpuinfo') as f:
                for line in f:
                    if ':' in line:
                        key, val = line.split(':', 1)
                        key = key.strip()
                        if key == 'model name':
                            cpu_info['model'] = val.strip()
                        elif key == 'cpu cores':
                            cpu_info['cores'] = int(val.strip())
                        elif key == 'processor':
                            cpu_info['threads'] = cpu_info.get('threads', 0) + 1

            if HAS_PSUTIL:
                cpu_info['usage_percent'] = psutil.cpu_percent(interval=1)

            inventory.cpu_info = cpu_info
        except:
            pass

        # Memory info
        try:
            if HAS_PSUTIL:
                mem = psutil.virtual_memory()
                inventory.memory_total_gb = round(mem.total / (1024**3), 2)
            else:
                with open('/proc/meminfo') as f:
                    for line in f:
                        if line.startswith('MemTotal:'):
                            kb = int(line.split()[1])
                            inventory.memory_total_gb = round(kb / (1024**2), 2)
                            break
        except:
            pass

        # Disk info
        try:
            if HAS_PSUTIL:
                disks = []
                for part in psutil.disk_partitions(all=False):
                    try:
                        usage = psutil.disk_usage(part.mountpoint)
                        disks.append({
                            'device': part.device,
                            'mountpoint': part.mountpoint,
                            'fstype': part.fstype,
                            'total_gb': round(usage.total / (1024**3), 2),
                            'used_gb': round(usage.used / (1024**3), 2),
                            'free_gb': round(usage.free / (1024**3), 2),
                            'percent_used': usage.percent
                        })
                    except:
                        pass
                inventory.disk_info = disks
        except:
            pass

    def _collect_network_info(self, inventory: AssetInventory):
        """Collect network interface information"""
        ip_addresses = []
        mac_addresses = []
        interfaces = []

        try:
            if HAS_PSUTIL:
                addrs = psutil.net_if_addrs()
                stats = psutil.net_if_stats()

                for iface, addr_list in addrs.items():
                    if iface == 'lo':
                        continue

                    iface_info = {
                        'name': iface,
                        'is_up': stats[iface].isup if iface in stats else False
                    }

                    for addr in addr_list:
                        if addr.family.name == 'AF_INET':
                            iface_info['ipv4'] = addr.address
                            iface_info['netmask'] = addr.netmask
                            ip_addresses.append(addr.address)
                        elif addr.family.name == 'AF_INET6':
                            iface_info['ipv6'] = addr.address
                        elif addr.family.name == 'AF_PACKET':
                            iface_info['mac'] = addr.address
                            if addr.address != '00:00:00:00:00:00':
                                mac_addresses.append(addr.address)

                    interfaces.append(iface_info)
            else:
                # Fallback: parse ip addr output
                result = subprocess.run(['ip', 'addr'], capture_output=True, text=True)
                # Simple parsing (not as complete as psutil)
                for line in result.stdout.split('\n'):
                    if 'inet ' in line and '127.0.0.1' not in line:
                        parts = line.strip().split()
                        ip = parts[1].split('/')[0]
                        ip_addresses.append(ip)

        except Exception as e:
            logger.debug(f"Network collection error: {e}")

        inventory.ip_addresses = ip_addresses
        inventory.mac_addresses = mac_addresses
        inventory.network_interfaces = interfaces

    def _collect_packages(self, inventory: AssetInventory):
        """Collect installed packages"""
        packages = []

        try:
            # Try dpkg (Debian/Ubuntu)
            if os.path.exists('/usr/bin/dpkg'):
                result = subprocess.run(
                    ['dpkg-query', '-W', '-f', '${Package}\t${Version}\t${Status}\n'],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.strip().split('\n')[:500]:  # Limit to 500
                    parts = line.split('\t')
                    if len(parts) >= 2 and 'installed' in parts[-1]:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'manager': 'dpkg'
                        })

            # Try rpm (RHEL/CentOS)
            elif os.path.exists('/usr/bin/rpm'):
                result = subprocess.run(
                    ['rpm', '-qa', '--queryformat', '%{NAME}\t%{VERSION}-%{RELEASE}\n'],
                    capture_output=True, text=True, timeout=30
                )
                for line in result.stdout.strip().split('\n')[:500]:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        packages.append({
                            'name': parts[0],
                            'version': parts[1],
                            'manager': 'rpm'
                        })

        except Exception as e:
            logger.debug(f"Package collection error: {e}")

        inventory.installed_packages = packages

    def _collect_services(self, inventory: AssetInventory):
        """Collect running services"""
        services = []

        try:
            # Use systemctl
            result = subprocess.run(
                ['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager', '--no-legend'],
                capture_output=True, text=True, timeout=30
            )

            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 4:
                    services.append({
                        'name': parts[0].replace('.service', ''),
                        'state': parts[2],
                        'status': parts[3]
                    })

        except Exception as e:
            logger.debug(f"Service collection error: {e}")

        inventory.running_services = services

    def _collect_users(self, inventory: AssetInventory):
        """Collect local user accounts"""
        users = []

        try:
            with open('/etc/passwd') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        uid = int(parts[2])
                        # Only human users (typically UID >= 1000) and root
                        if uid >= 1000 or uid == 0:
                            users.append({
                                'username': parts[0],
                                'uid': uid,
                                'gid': int(parts[3]),
                                'home': parts[5],
                                'shell': parts[6]
                            })

            # Check for sudo access
            try:
                with open('/etc/group') as f:
                    for line in f:
                        if line.startswith('sudo:') or line.startswith('wheel:'):
                            group_users = line.strip().split(':')[-1].split(',')
                            for user in users:
                                if user['username'] in group_users:
                                    user['sudo_access'] = True
            except:
                pass

        except Exception as e:
            logger.debug(f"User collection error: {e}")

        inventory.local_users = users

    def _collect_open_ports(self, inventory: AssetInventory):
        """Collect open listening ports"""
        ports = []

        try:
            if HAS_PSUTIL:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status == 'LISTEN':
                        proc_name = ""
                        if conn.pid:
                            try:
                                proc_name = psutil.Process(conn.pid).name()
                            except:
                                pass

                        ports.append({
                            'port': conn.laddr.port,
                            'address': conn.laddr.ip,
                            'protocol': 'tcp',
                            'pid': conn.pid,
                            'process': proc_name
                        })
            else:
                # Fallback: parse netstat or ss
                result = subprocess.run(
                    ['ss', '-tlnp'],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.strip().split('\n')[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        addr = parts[3]
                        if ':' in addr:
                            port = int(addr.rsplit(':', 1)[1])
                            ports.append({
                                'port': port,
                                'address': addr.rsplit(':', 1)[0],
                                'protocol': 'tcp'
                            })

        except Exception as e:
            logger.debug(f"Port collection error: {e}")

        inventory.open_ports = ports

    def _collect_boot_time(self, inventory: AssetInventory):
        """Get system boot time"""
        try:
            if HAS_PSUTIL:
                boot_time = datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
                inventory.last_boot = boot_time.isoformat()
            else:
                with open('/proc/uptime') as f:
                    uptime_seconds = float(f.read().split()[0])
                    boot_time = datetime.now(timezone.utc) - timedelta(seconds=uptime_seconds)
                    inventory.last_boot = boot_time.isoformat()
        except:
            pass


class ResponseEngine:
    """Execute response actions"""

    def __init__(self, config: EDRConfig):
        self.config = config
        self.quarantine_dir = Path(QUARANTINE_DIR)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.blocked_ips: Set[str] = set()

    def kill_process(self, pid: int, reason: str = "") -> Dict:
        """Kill a process by PID"""
        try:
            if HAS_PSUTIL:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.kill()
            else:
                proc_name = f"PID:{pid}"
                os.kill(pid, signal.SIGKILL)

            logger.warning(f"Killed process {pid} ({proc_name}): {reason}")
            return {
                'success': True,
                'action': 'kill_process',
                'pid': pid,
                'process_name': proc_name,
                'reason': reason
            }
        except Exception as e:
            logger.error(f"Failed to kill process {pid}: {e}")
            return {
                'success': False,
                'action': 'kill_process',
                'pid': pid,
                'error': str(e)
            }

    def quarantine_file(self, filepath: str, reason: str = "") -> Dict:
        """Move a file to quarantine"""
        try:
            src = Path(filepath)
            if not src.exists():
                return {'success': False, 'action': 'quarantine', 'error': 'File not found'}

            # Calculate hash before moving
            file_hash = self._hash_file(filepath)

            # Generate quarantine filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_name = src.name.replace('/', '_')
            quar_name = f"{timestamp}_{file_hash[:8]}_{safe_name}"
            quar_path = self.quarantine_dir / quar_name

            # Create metadata file
            metadata = {
                'original_path': str(src.absolute()),
                'quarantine_time': datetime.now(timezone.utc).isoformat(),
                'sha256': file_hash,
                'reason': reason,
                'original_mode': oct(src.stat().st_mode),
                'original_uid': src.stat().st_uid,
                'original_gid': src.stat().st_gid
            }

            # Move file to quarantine
            shutil.move(str(src), str(quar_path))
            quar_path.chmod(0o000)  # Remove all permissions

            # Write metadata
            meta_path = self.quarantine_dir / f"{quar_name}.meta.json"
            with open(meta_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            logger.warning(f"Quarantined {filepath} -> {quar_path}: {reason}")
            return {
                'success': True,
                'action': 'quarantine',
                'original_path': filepath,
                'quarantine_path': str(quar_path),
                'sha256': file_hash,
                'reason': reason
            }

        except Exception as e:
            logger.error(f"Failed to quarantine {filepath}: {e}")
            return {
                'success': False,
                'action': 'quarantine',
                'filepath': filepath,
                'error': str(e)
            }

    def block_ip(self, ip: str, reason: str = "") -> Dict:
        """Block an IP address using iptables"""
        try:
            if ip in self.blocked_ips:
                return {'success': True, 'action': 'block_ip', 'ip': ip, 'already_blocked': True}

            # Add iptables rule
            cmd = ['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                self.blocked_ips.add(ip)
                logger.warning(f"Blocked IP {ip}: {reason}")
                return {
                    'success': True,
                    'action': 'block_ip',
                    'ip': ip,
                    'reason': reason
                }
            else:
                return {
                    'success': False,
                    'action': 'block_ip',
                    'ip': ip,
                    'error': result.stderr
                }

        except Exception as e:
            logger.error(f"Failed to block IP {ip}: {e}")
            return {
                'success': False,
                'action': 'block_ip',
                'ip': ip,
                'error': str(e)
            }

    def unblock_ip(self, ip: str) -> Dict:
        """Unblock an IP address"""
        try:
            cmd = ['iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP']
            result = subprocess.run(cmd, capture_output=True, text=True)

            self.blocked_ips.discard(ip)
            logger.info(f"Unblocked IP {ip}")
            return {
                'success': True,
                'action': 'unblock_ip',
                'ip': ip
            }

        except Exception as e:
            return {
                'success': False,
                'action': 'unblock_ip',
                'ip': ip,
                'error': str(e)
            }

    def isolate_host(self) -> Dict:
        """Isolate this host from the network (except server)"""
        try:
            # This is a drastic action - only allow traffic to T1 server
            # Would need to parse server URL to get IP
            logger.warning("Host isolation requested - this is a placeholder")
            return {
                'success': False,
                'action': 'isolate_host',
                'error': 'Not implemented - requires careful configuration'
            }
        except Exception as e:
            return {
                'success': False,
                'action': 'isolate_host',
                'error': str(e)
            }

    def _hash_file(self, filepath: str) -> str:
        """Calculate SHA256 hash"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()


class T1EDRAgent:
    """Main EDR agent class"""

    STATE_UNREGISTERED = 'unregistered'
    STATE_PENDING = 'pending'
    STATE_APPROVED = 'approved'

    def __init__(self, config: EDRConfig):
        self.config = config
        self.running = False
        self.event_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.ioc_db = IOCDatabase()
        self.response_engine = ResponseEngine(config)
        self.asset_collector = AssetCollector(config.hostname)

        # Monitors
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
        self.inventory_sync_interval = 3600  # Sync inventory every hour

        # Registration
        self.registration_state = self.STATE_UNREGISTERED
        self.server_agent_id = None
        self.active_token = None

        # Get host info
        self.hostname = config.hostname
        self.host_ip = self._get_host_ip()

        if not HAS_REQUESTS:
            logger.error("requests library not installed")
            sys.exit(1)

    def _get_host_ip(self) -> str:
        """Get host IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def start(self):
        """Start the EDR agent"""
        logger.info(f"Starting T1 EDR Agent v{VERSION}")
        logger.info(f"Hostname: {self.hostname}")
        logger.info(f"Server: {self.config.server_url}")

        self.running = True

        # Registration
        if self.config.agent_token:
            logger.info("Using pre-configured token")
            self.active_token = self.config.agent_token
            self.registration_state = self.STATE_APPROVED
        else:
            logger.info("Starting auto-registration...")
            self._wait_for_approval()

        if self.registration_state != self.STATE_APPROVED:
            logger.error("Agent not approved")
            return

        # Initial IOC fetch
        self._refresh_iocs()

        # Initial asset inventory sync
        self._sync_inventory()

        # Start monitors
        self._start_monitors()

        # Main loop
        self._run()

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping EDR agent...")
        self.running = False

        if self.process_monitor:
            self.process_monitor.stop()
        if self.fim_monitor:
            self.fim_monitor.stop()
        if self.network_monitor:
            self.network_monitor.stop()

    def _register_with_server(self) -> Dict:
        """Register with server"""
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
            "hostname": self.hostname,
            "os_type": "linux",
            "os_version": os_version,
            "agent_type": AGENT_TYPE,
            "agent_version": VERSION,
            "ip_address": self.host_ip,
            "tags": self.config.tags or [],
            "agent_key": self.config.agent_key,
            "capabilities": {
                "process_monitor": self.config.enable_process_monitor,
                "fim": self.config.enable_fim,
                "network_monitor": self.config.enable_network_monitor,
                "response_actions": self.config.enable_response_actions
            }
        }

        try:
            response = requests.post(url, json=payload, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Registration failed: {response.status_code}")
                return {"status": "error", "message": response.text}
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {"status": "error", "message": str(e)}

    def _wait_for_approval(self):
        """Wait for approval"""
        result = self._register_with_server()

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

        # Poll for approval
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

    def _check_status(self) -> Dict:
        """Check registration status"""
        url = f"{self.config.server_url}/api/v1/edr/agents/check/{self.config.agent_key}"
        try:
            response = requests.get(url, timeout=10)
            return response.json() if response.status_code == 200 else {}
        except:
            return {}

    def _sync_inventory(self):
        """Sync asset inventory with server"""
        logger.info("Collecting asset inventory...")
        try:
            inventory = self.asset_collector.collect()
            inventory_data = inventory.to_dict()

            url = f"{self.config.server_url}/api/v1/edr/agents/{self.server_agent_id}/inventory"
            headers = {
                'X-Agent-Token': self.active_token,
                'Content-Type': 'application/json'
            }

            response = requests.post(url, headers=headers, json=inventory_data, timeout=60)
            if response.status_code == 200:
                self.last_inventory_sync = time.time()
                logger.info(f"Asset inventory synced: {len(inventory.installed_packages)} packages, "
                           f"{len(inventory.running_services)} services, "
                           f"{len(inventory.local_users)} users, "
                           f"{len(inventory.open_ports)} open ports")
            else:
                logger.warning(f"Inventory sync failed: {response.status_code}")

        except Exception as e:
            logger.warning(f"Inventory sync error: {e}")

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
                self.ioc_db.last_updated = time.time()

                total = (len(self.ioc_db.file_hashes) + len(self.ioc_db.ip_addresses) +
                        len(self.ioc_db.domains) + len(self.ioc_db.process_names) +
                        len(self.ioc_db.file_paths))
                logger.info(f"Loaded {total} IOCs from server")

            self.last_ioc_refresh = time.time()

        except Exception as e:
            logger.warning(f"Failed to fetch IOCs: {e}")

    def _start_monitors(self):
        """Start all monitors"""
        if self.config.enable_process_monitor:
            self.process_monitor = ProcessMonitor(self.event_queue, self.ioc_db)
            self.process_monitor.start()

        if self.config.enable_fim:
            self.fim_monitor = FileIntegrityMonitor(
                self.event_queue, self.config.fim_paths, self.ioc_db
            )
            self.fim_monitor.start()

        if self.config.enable_network_monitor:
            self.network_monitor = NetworkMonitor(self.event_queue, self.ioc_db)
            self.network_monitor.start()

    def _run(self):
        """Main loop"""
        batch = []
        last_flush = time.time()

        while self.running:
            try:
                # Heartbeat
                if time.time() - self.last_heartbeat > self.config.heartbeat_interval:
                    self._send_heartbeat()

                # Refresh IOCs
                self._refresh_iocs()

                # Periodic inventory sync
                if time.time() - self.last_inventory_sync > self.inventory_sync_interval:
                    self._sync_inventory()

                # Process events
                try:
                    event = self.event_queue.get(timeout=1)

                    # Normalize to ECS
                    ecs_event = self._normalize_event(event)

                    # Handle threats
                    if event.get('threat_detected'):
                        self.threats_detected += 1
                        self._handle_threat(event)

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
                time.sleep(1)

        if batch:
            self._send_batch(batch)

    def _normalize_event(self, event: Dict) -> Dict:
        """Normalize event to ECS format"""
        source_type = event.get('source_type', 'edr')

        ecs = {
            '@timestamp': event.get('timestamp', datetime.now(timezone.utc).isoformat()),
            'ecs': {'version': '8.0.0'},
            'agent': {
                'type': AGENT_TYPE,
                'version': VERSION,
                'name': self.hostname
            },
            'host': {
                'name': self.hostname,
                'ip': self.host_ip,
                'os': {'type': 'linux'}
            },
            'event': {
                'kind': 'event',
                'module': 'edr',
                'category': [],
                'type': [],
                'action': event.get('event_action', '')
            },
            'source_type': source_type
        }

        # Add process info
        if 'process' in event:
            ecs['process'] = event['process']
            ecs['event']['category'].append('process')

        # Add file info
        if 'file' in event:
            ecs['file'] = event['file']
            if 'hash' in event:
                ecs['file']['hash'] = event['hash']
            ecs['event']['category'].append('file')

        # Add network info
        if 'network' in event:
            ecs['network'] = event['network']
            ecs['destination'] = {
                'ip': event['network'].get('remote_ip'),
                'port': event['network'].get('remote_port'),
                'domain': event['network'].get('remote_domain')
            }
            ecs['source'] = {
                'ip': event['network'].get('local_ip'),
                'port': event['network'].get('local_port')
            }
            ecs['event']['category'].append('network')

        # Add threat info
        if event.get('threat_detected'):
            ecs['threat'] = {
                'indicator': event.get('ioc_match', {}),
                'matched': True
            }
            ecs['event']['kind'] = 'alert'

        # Generate event ID
        unique = f"{ecs['@timestamp']}{self.hostname}{event.get('event_type', '')}"
        ecs['event']['id'] = hashlib.sha256(unique.encode()).hexdigest()[:16]

        return ecs

    def _handle_threat(self, event: Dict):
        """Handle a detected threat"""
        logger.warning(f"THREAT DETECTED: {event.get('event_type')} - {event.get('ioc_match')}")

        if not self.config.enable_response_actions:
            return

        ioc_match = event.get('ioc_match', {})
        event_type = event.get('event_type')

        # Auto-responses (if enabled)
        if event_type == 'process' and self.config.auto_kill:
            pid = event.get('process', {}).get('pid')
            if pid:
                result = self.response_engine.kill_process(pid, f"IOC match: {ioc_match}")
                if result['success']:
                    self.actions_taken += 1

        elif event_type == 'file_integrity' and self.config.auto_quarantine:
            filepath = event.get('file', {}).get('path')
            if filepath:
                result = self.response_engine.quarantine_file(filepath, f"IOC match: {ioc_match}")
                if result['success']:
                    self.actions_taken += 1

        elif event_type == 'network':
            remote_ip = event.get('network', {}).get('remote_ip')
            if remote_ip and ioc_match.get('type') == 'ip':
                result = self.response_engine.block_ip(remote_ip, f"IOC match")
                if result['success']:
                    self.actions_taken += 1

    def _send_batch(self, events: List[Dict]):
        """Send events to server"""
        if not events:
            return

        url = f"{self.config.server_url}/api/v1/edr/events"
        headers = {
            'X-Agent-Token': self.active_token,
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(
                url,
                headers=headers,
                json={'events': events, 'agent_id': self.server_agent_id},
                timeout=30
            )

            if response.status_code == 200:
                self.events_sent += len(events)
                logger.debug(f"Sent {len(events)} events")

                # Check for response actions from server
                result = response.json()
                if result.get('actions'):
                    self._execute_server_actions(result['actions'])

            elif response.status_code == 401:
                logger.error("Authentication failed")
            else:
                logger.error(f"Failed to send: {response.status_code}")

        except Exception as e:
            logger.error(f"Send error: {e}")

    def _execute_server_actions(self, actions: List[Dict]):
        """Execute response actions from server"""
        for action in actions:
            action_type = action.get('type')
            logger.info(f"Executing server action: {action_type}")

            if action_type == 'kill_process':
                self.response_engine.kill_process(
                    action.get('pid'),
                    action.get('reason', 'Server requested')
                )
            elif action_type == 'quarantine_file':
                self.response_engine.quarantine_file(
                    action.get('filepath'),
                    action.get('reason', 'Server requested')
                )
            elif action_type == 'block_ip':
                self.response_engine.block_ip(
                    action.get('ip'),
                    action.get('reason', 'Server requested')
                )
            elif action_type == 'unblock_ip':
                self.response_engine.unblock_ip(action.get('ip'))

            self.actions_taken += 1

    def _send_heartbeat(self):
        """Send heartbeat"""
        url = f"{self.config.server_url}/api/v1/edr/agents/{self.server_agent_id}/heartbeat"
        headers = {'X-Agent-Token': self.active_token}

        payload = {
            'hostname': self.hostname,
            'agent_version': VERSION,
            'events_sent': self.events_sent,
            'threats_detected': self.threats_detected,
            'actions_taken': self.actions_taken,
            'queue_size': self.event_queue.qsize(),
            'monitors': {
                'process': self.process_monitor is not None,
                'fim': self.fim_monitor is not None,
                'network': self.network_monitor is not None
            },
            'ioc_count': (len(self.ioc_db.file_hashes) + len(self.ioc_db.ip_addresses) +
                         len(self.ioc_db.domains))
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                self.last_heartbeat = time.time()
                result = response.json()

                # Handle pending actions
                if result.get('pending_actions'):
                    self._execute_server_actions(result['pending_actions'])

                # Handle config update
                if result.get('config'):
                    self._apply_config(result['config'])

        except Exception as e:
            logger.warning(f"Heartbeat error: {e}")

    def _apply_config(self, config: Dict):
        """Apply config from server"""
        if 'batch_size' in config:
            self.config.batch_size = config['batch_size']
        if 'flush_interval' in config:
            self.config.flush_interval = config['flush_interval']
        if 'auto_quarantine' in config:
            self.config.auto_quarantine = config['auto_quarantine']
        if 'auto_kill' in config:
            self.config.auto_kill = config['auto_kill']
        logger.info("Applied config update from server")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='T1 Agentics Linux EDR Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-registration
  python3 t1_edr.py --server https://t1.example.com:8000

  # With token
  python3 t1_edr.py --server https://t1.example.com:8000 --token abc123

  # Enable auto-response
  python3 t1_edr.py --server https://t1.example.com:8000 --auto-kill --auto-quarantine
        """
    )

    parser.add_argument('--server', '-s', required=True,
                        help='T1 Agentics server URL')
    parser.add_argument('--token', '-t',
                        help='Agent token (optional)')
    parser.add_argument('--agent-id', '-i', help='Agent ID')
    parser.add_argument('--hostname', '-n', help='Override hostname')
    parser.add_argument('--tag', action='append', default=[], help='Add tag')

    # EDR options
    parser.add_argument('--no-process', action='store_true',
                        help='Disable process monitoring')
    parser.add_argument('--no-fim', action='store_true',
                        help='Disable file integrity monitoring')
    parser.add_argument('--no-network', action='store_true',
                        help='Disable network monitoring')
    parser.add_argument('--auto-kill', action='store_true',
                        help='Auto-kill processes matching IOCs')
    parser.add_argument('--auto-quarantine', action='store_true',
                        help='Auto-quarantine files matching IOCs')
    parser.add_argument('--fim-path', action='append',
                        help='Additional FIM path')

    parser.add_argument('--debug', '-d', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--version', '-v', action='version',
                        version=f'T1 EDR v{VERSION}')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build FIM paths
    fim_paths = DEFAULT_FIM_PATHS.copy()
    if args.fim_path:
        fim_paths.extend(args.fim_path)

    config = EDRConfig(
        server_url=args.server.rstrip('/'),
        agent_token=args.token,
        agent_id=args.agent_id,
        hostname=args.hostname or socket.gethostname(),
        tags=args.tag,
        enable_process_monitor=not args.no_process,
        enable_fim=not args.no_fim,
        enable_network_monitor=not args.no_network,
        auto_kill=args.auto_kill,
        auto_quarantine=args.auto_quarantine,
        fim_paths=fim_paths
    )

    agent = T1EDRAgent(config)

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
