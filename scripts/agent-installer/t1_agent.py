#!/usr/bin/env python3
# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
T1 Agentics Linux Log Collection Agent
=======================================
Lightweight agent for collecting and forwarding security logs to T1 Agentics.

Features:
- Auto-registration with server (no pre-configured token needed)
- Server-pushed configuration updates
- Journald (systemd) log collection
- Syslog file tailing (/var/log/syslog, /var/log/messages)
- Auth log collection (/var/log/auth.log, /var/log/secure)
- Auditd log collection (if available)
- ECS normalization
- Automatic reconnection with exponential backoff
- Heartbeat monitoring

Usage:
    # Auto-registration mode (recommended for deployment)
    python3 t1_agent.py --server https://your-server:8000

    # Token mode (for pre-approved agents)
    python3 t1_agent.py --server https://your-server:8000 --token YOUR_AGENT_TOKEN

Requirements:
    pip install requests systemd-python (optional)
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Generator
from dataclasses import dataclass, asdict

# Optional imports
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from systemd import journal
    HAS_SYSTEMD = True
except ImportError:
    HAS_SYSTEMD = False

# Configuration
VERSION = "1.0.0"
DEFAULT_BATCH_SIZE = 50
DEFAULT_FLUSH_INTERVAL = 10  # seconds
DEFAULT_HEARTBEAT_INTERVAL = 60  # seconds
DEFAULT_REGISTRATION_CHECK_INTERVAL = 30  # seconds
MAX_QUEUE_SIZE = 10000
RECONNECT_BASE_DELAY = 5
RECONNECT_MAX_DELAY = 300
CONFIG_CHECK_INTERVAL = 300  # Check for config updates every 5 minutes

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('t1-agent')


@dataclass
class AgentConfig:
    """Agent configuration"""
    server_url: str
    agent_key: Optional[str] = None  # Generated or loaded from file
    agent_token: Optional[str] = None  # Pre-configured token (optional)
    agent_id: Optional[str] = None
    hostname: str = ""
    batch_size: int = DEFAULT_BATCH_SIZE
    flush_interval: int = DEFAULT_FLUSH_INTERVAL
    heartbeat_interval: int = DEFAULT_HEARTBEAT_INTERVAL
    collect_journald: bool = True
    collect_syslog: bool = True
    collect_auth: bool = True
    collect_audit: bool = True
    key_file: str = "/var/lib/t1-agent/agent.key"
    config_file: str = "/var/lib/t1-agent/config.json"
    tags: List[str] = None

    def __post_init__(self):
        if not self.hostname:
            self.hostname = socket.gethostname()
        if self.tags is None:
            self.tags = []
        if not self.agent_key and not self.agent_token:
            self.agent_key = self._load_or_generate_key()
        # Load any saved server config
        self._load_server_config()

    def _load_or_generate_key(self) -> str:
        """Load existing key or generate new one"""
        key_path = Path(self.key_file)

        if key_path.exists():
            key = key_path.read_text().strip()
            logger.info(f"Loaded agent key: {key[:12]}...")
            return key

        # Generate new key
        new_key = f"ak_{uuid.uuid4().hex}"

        # Try to save it
        try:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_text(new_key)
            key_path.chmod(0o600)
            logger.info(f"Generated new agent key: {new_key[:12]}...")
        except PermissionError:
            logger.warning(f"Cannot save key to {key_path}, using ephemeral key")

        return new_key

    def _load_server_config(self):
        """Load configuration pushed from server"""
        config_path = Path(self.config_file)
        if config_path.exists():
            try:
                with open(config_path) as f:
                    server_config = json.load(f)
                # Apply server config (but don't override CLI args)
                if 'batch_size' in server_config and self.batch_size == DEFAULT_BATCH_SIZE:
                    self.batch_size = server_config['batch_size']
                if 'flush_interval' in server_config and self.flush_interval == DEFAULT_FLUSH_INTERVAL:
                    self.flush_interval = server_config['flush_interval']
                if 'collect_journald' in server_config:
                    self.collect_journald = server_config['collect_journald']
                if 'collect_syslog' in server_config:
                    self.collect_syslog = server_config['collect_syslog']
                if 'collect_auth' in server_config:
                    self.collect_auth = server_config['collect_auth']
                if 'collect_audit' in server_config:
                    self.collect_audit = server_config['collect_audit']
                logger.info("Loaded server configuration")
            except Exception as e:
                logger.warning(f"Failed to load server config: {e}")

    def save_server_config(self, config: Dict[str, Any]):
        """Save configuration received from server"""
        config_path = Path(self.config_file)
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
            config_path.chmod(0o600)
            logger.info("Saved server configuration")
        except Exception as e:
            logger.warning(f"Failed to save server config: {e}")


class ECSNormalizer:
    """Normalize Linux logs to ECS (Elastic Common Schema) format"""

    # Syslog priority to severity mapping
    SYSLOG_SEVERITY = {
        0: 'emergency',
        1: 'alert',
        2: 'critical',
        3: 'error',
        4: 'warning',
        5: 'notice',
        6: 'informational',
        7: 'debug'
    }

    # Common auth patterns
    AUTH_PATTERNS = {
        'ssh_accepted': re.compile(r'Accepted (\w+) for (\S+) from (\S+) port (\d+)'),
        'ssh_failed': re.compile(r'Failed (\w+) for (?:invalid user )?(\S+) from (\S+) port (\d+)'),
        'sudo': re.compile(r'(\S+) : .* COMMAND=(.*)'),
        'su': re.compile(r"su\[\d+\]: (?:Successful|FAILED) su for (\S+) by (\S+)"),
        'pam': re.compile(r'pam_unix\((\S+):(\S+)\): (.*)'),
    }

    def __init__(self, hostname: str):
        self.hostname = hostname
        self.host_ip = self._get_host_ip()

    def _get_host_ip(self) -> str:
        """Get host IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def normalize(self, raw_event: Dict[str, Any], source_type: str) -> Dict[str, Any]:
        """Normalize a raw event to ECS format"""
        timestamp = raw_event.get('timestamp', datetime.now(timezone.utc).isoformat())

        # Base ECS structure
        ecs_event = {
            '@timestamp': timestamp,
            'ecs': {'version': '8.0.0'},
            'agent': {
                'type': 't1-linux-agent',
                'version': VERSION,
                'name': self.hostname
            },
            'host': {
                'name': self.hostname,
                'ip': self.host_ip,
                'os': {
                    'type': 'linux',
                    'family': 'linux'
                }
            },
            'event': {
                'kind': 'event',
                'category': [],
                'type': [],
                'created': datetime.now(timezone.utc).isoformat(),
                'original': raw_event.get('message', '')
            },
            'source_type': source_type,
            'labels': {
                'collector': 't1-agent'
            }
        }

        # Source-specific normalization
        if source_type == 'linux_journald':
            ecs_event = self._normalize_journald(ecs_event, raw_event)
        elif source_type == 'linux_syslog':
            ecs_event = self._normalize_syslog(ecs_event, raw_event)
        elif source_type == 'linux_auth':
            ecs_event = self._normalize_auth(ecs_event, raw_event)
        elif source_type == 'linux_auditd':
            ecs_event = self._normalize_auditd(ecs_event, raw_event)

        # Generate event ID
        ecs_event['event']['id'] = self._generate_event_id(ecs_event)

        return ecs_event

    def _normalize_journald(self, ecs: Dict, raw: Dict) -> Dict:
        """Normalize systemd journal entry"""
        message = raw.get('MESSAGE', raw.get('message', ''))

        # Extract systemd fields
        if '_SYSTEMD_UNIT' in raw:
            ecs['systemd'] = {'unit': raw['_SYSTEMD_UNIT']}

        if '_PID' in raw:
            ecs['process'] = {
                'pid': int(raw['_PID']),
                'name': raw.get('_COMM', raw.get('SYSLOG_IDENTIFIER', ''))
            }

        if '_UID' in raw:
            ecs['user'] = {'id': str(raw['_UID'])}

        # Set priority/severity
        priority = raw.get('PRIORITY', 6)
        if isinstance(priority, str):
            priority = int(priority)
        ecs['log'] = {
            'syslog': {
                'priority': priority,
                'severity': {'name': self.SYSLOG_SEVERITY.get(priority, 'informational')}
            }
        }

        # Categorize based on unit
        unit = raw.get('_SYSTEMD_UNIT', '')
        if 'ssh' in unit.lower():
            ecs['event']['category'] = ['authentication']
            ecs['event']['type'] = ['info']
        elif 'audit' in unit.lower():
            ecs['event']['category'] = ['process']
            ecs['event']['type'] = ['info']
        else:
            ecs['event']['category'] = ['host']
            ecs['event']['type'] = ['info']

        ecs['message'] = message
        return ecs

    def _normalize_syslog(self, ecs: Dict, raw: Dict) -> Dict:
        """Normalize syslog entry"""
        message = raw.get('message', '')

        # Parse syslog format: "Mon DD HH:MM:SS hostname process[pid]: message"
        syslog_pattern = re.compile(
            r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$'
        )
        match = syslog_pattern.match(message)

        if match:
            timestamp_str, host, process, pid, msg = match.groups()
            ecs['process'] = {'name': process}
            if pid:
                ecs['process']['pid'] = int(pid)
            ecs['message'] = msg
        else:
            ecs['message'] = message

        ecs['event']['category'] = ['host']
        ecs['event']['type'] = ['info']
        ecs['log'] = {'syslog': {}}

        return ecs

    def _normalize_auth(self, ecs: Dict, raw: Dict) -> Dict:
        """Normalize auth log entry"""
        message = raw.get('message', '')
        ecs['event']['category'] = ['authentication']

        # Check for SSH events
        if 'sshd' in message:
            # Successful login
            match = self.AUTH_PATTERNS['ssh_accepted'].search(message)
            if match:
                method, user, src_ip, port = match.groups()
                ecs['event']['type'] = ['start']
                ecs['event']['action'] = 'ssh_login'
                ecs['event']['outcome'] = 'success'
                ecs['user'] = {'name': user}
                ecs['source'] = {'ip': src_ip, 'port': int(port)}
                ecs['authentication'] = {'method': method}
                return ecs

            # Failed login
            match = self.AUTH_PATTERNS['ssh_failed'].search(message)
            if match:
                method, user, src_ip, port = match.groups()
                ecs['event']['type'] = ['start']
                ecs['event']['action'] = 'ssh_login'
                ecs['event']['outcome'] = 'failure'
                ecs['user'] = {'name': user}
                ecs['source'] = {'ip': src_ip, 'port': int(port)}
                ecs['authentication'] = {'method': method}
                return ecs

        # Check for sudo events
        if 'sudo' in message:
            match = self.AUTH_PATTERNS['sudo'].search(message)
            if match:
                user, command = match.groups()
                ecs['event']['type'] = ['info']
                ecs['event']['action'] = 'sudo_command'
                ecs['event']['category'] = ['process']
                ecs['user'] = {'name': user}
                ecs['process'] = {'command_line': command.strip()}
                return ecs

        # Check for su events
        if 'su[' in message or 'su:' in message:
            ecs['event']['type'] = ['start']
            ecs['event']['action'] = 'su'
            if 'FAILED' in message:
                ecs['event']['outcome'] = 'failure'
            elif 'Successful' in message:
                ecs['event']['outcome'] = 'success'

        ecs['event']['type'] = ecs['event'].get('type', ['info'])
        ecs['message'] = message
        return ecs

    def _normalize_auditd(self, ecs: Dict, raw: Dict) -> Dict:
        """Normalize auditd log entry"""
        message = raw.get('message', '')
        ecs['event']['category'] = ['process']

        # Parse audit message type
        type_match = re.search(r'type=(\S+)', message)
        if type_match:
            audit_type = type_match.group(1)
            ecs['event']['action'] = audit_type.lower()

            if audit_type in ['EXECVE', 'SYSCALL']:
                ecs['event']['category'] = ['process']
                ecs['event']['type'] = ['start']
            elif audit_type in ['USER_AUTH', 'USER_LOGIN', 'USER_START']:
                ecs['event']['category'] = ['authentication']
                ecs['event']['type'] = ['start']
            elif audit_type in ['USER_END', 'USER_LOGOUT']:
                ecs['event']['category'] = ['authentication']
                ecs['event']['type'] = ['end']

        # Extract common audit fields
        pid_match = re.search(r'pid=(\d+)', message)
        if pid_match:
            ecs['process'] = {'pid': int(pid_match.group(1))}

        uid_match = re.search(r'uid=(\d+)', message)
        if uid_match:
            ecs['user'] = {'id': uid_match.group(1)}

        exe_match = re.search(r'exe="([^"]+)"', message)
        if exe_match:
            if 'process' not in ecs:
                ecs['process'] = {}
            ecs['process']['executable'] = exe_match.group(1)

        ecs['message'] = message
        return ecs

    def _generate_event_id(self, ecs: Dict) -> str:
        """Generate unique event ID"""
        unique_str = f"{ecs['@timestamp']}{ecs['host']['name']}{ecs.get('message', '')}"
        return hashlib.sha256(unique_str.encode()).hexdigest()[:16]


class JournaldCollector:
    """Collect logs from systemd journal"""

    def __init__(self, event_queue: queue.Queue):
        self.queue = event_queue
        self.running = False
        self.thread = None

    def start(self):
        """Start collecting from journald"""
        if not HAS_SYSTEMD:
            logger.warning("systemd-python not installed, journald collection disabled")
            return

        self.running = True
        self.thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.thread.start()
        logger.info("Journald collector started")

    def stop(self):
        """Stop collecting"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _collect_loop(self):
        """Main collection loop"""
        try:
            j = journal.Reader()
            j.this_boot()
            j.seek_tail()
            j.get_previous()  # Position at end

            while self.running:
                # Wait for new entries (1 second timeout)
                if j.wait(1000000) == journal.APPEND:
                    for entry in j:
                        if not self.running:
                            break

                        event = {
                            'timestamp': entry.get('__REALTIME_TIMESTAMP', datetime.now(timezone.utc)).isoformat() if hasattr(entry.get('__REALTIME_TIMESTAMP', ''), 'isoformat') else datetime.now(timezone.utc).isoformat(),
                            'message': entry.get('MESSAGE', ''),
                            'MESSAGE': entry.get('MESSAGE', ''),
                            '_SYSTEMD_UNIT': entry.get('_SYSTEMD_UNIT', ''),
                            '_PID': entry.get('_PID', ''),
                            '_UID': entry.get('_UID', ''),
                            '_COMM': entry.get('_COMM', ''),
                            'SYSLOG_IDENTIFIER': entry.get('SYSLOG_IDENTIFIER', ''),
                            'PRIORITY': entry.get('PRIORITY', 6),
                            'source_type': 'linux_journald'
                        }

                        try:
                            self.queue.put_nowait(event)
                        except queue.Full:
                            logger.warning("Event queue full, dropping journald event")

        except Exception as e:
            logger.error(f"Journald collector error: {e}")


class FileCollector:
    """Collect logs from file (tail -f style)"""

    def __init__(self, filepath: str, source_type: str, event_queue: queue.Queue):
        self.filepath = filepath
        self.source_type = source_type
        self.queue = event_queue
        self.running = False
        self.thread = None
        self.position = 0

    def start(self):
        """Start collecting from file"""
        if not os.path.exists(self.filepath):
            logger.warning(f"Log file not found: {self.filepath}")
            return

        self.running = True
        self.thread = threading.Thread(target=self._collect_loop, daemon=True)
        self.thread.start()
        logger.info(f"File collector started: {self.filepath}")

    def stop(self):
        """Stop collecting"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)

    def _collect_loop(self):
        """Main collection loop"""
        try:
            # Start at end of file
            with open(self.filepath, 'r') as f:
                f.seek(0, 2)  # Seek to end
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
                                    'source_type': self.source_type,
                                    'log_file': self.filepath
                                }

                                try:
                                    self.queue.put_nowait(event)
                                except queue.Full:
                                    logger.warning(f"Event queue full, dropping {self.source_type} event")

                        self.position = f.tell()

                except FileNotFoundError:
                    logger.warning(f"Log file disappeared: {self.filepath}")

                time.sleep(1)  # Poll interval

        except Exception as e:
            logger.error(f"File collector error ({self.filepath}): {e}")


class T1Agent:
    """Main agent class"""

    # Registration states
    STATE_UNREGISTERED = 'unregistered'
    STATE_PENDING = 'pending'
    STATE_APPROVED = 'approved'
    STATE_REJECTED = 'rejected'

    def __init__(self, config: AgentConfig):
        self.config = config
        self.running = False
        self.event_queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self.collectors: List = []
        self.normalizer = ECSNormalizer(config.hostname)
        self.events_sent = 0
        self.last_heartbeat = 0
        self.last_config_check = 0
        self.reconnect_delay = RECONNECT_BASE_DELAY
        self.registration_state = self.STATE_UNREGISTERED
        self.server_agent_id = None  # Agent ID assigned by server
        self.active_token = None  # Token to use for API calls

        # Verify requests is available
        if not HAS_REQUESTS:
            logger.error("requests library not installed. Run: pip install requests")
            sys.exit(1)

    def start(self):
        """Start the agent"""
        logger.info(f"Starting T1 Agent v{VERSION}")
        logger.info(f"Hostname: {self.config.hostname}")
        logger.info(f"Server: {self.config.server_url}")

        self.running = True

        # If we have a pre-configured token, use it directly
        if self.config.agent_token:
            logger.info("Using pre-configured agent token")
            self.active_token = self.config.agent_token
            self.registration_state = self.STATE_APPROVED
        else:
            # Auto-registration flow
            logger.info("Starting auto-registration flow...")
            self._wait_for_approval()

        if self.registration_state != self.STATE_APPROVED:
            logger.error("Agent not approved, cannot start collection")
            return

        # Start collectors
        self._start_collectors()

        # Main loop
        self._run()

    def stop(self):
        """Stop the agent"""
        logger.info("Stopping agent...")
        self.running = False

        # Stop collectors
        for collector in self.collectors:
            collector.stop()

    def _register_with_server(self) -> Dict[str, Any]:
        """Register this agent with the server"""
        url = f"{self.config.server_url}/api/v1/logs/agents/self-register"

        # Get OS info
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
            "agent_version": VERSION,
            "ip_address": self.normalizer.host_ip,
            "tags": self.config.tags or [],
            "agent_key": self.config.agent_key
        }

        try:
            response = requests.post(url, json=payload, timeout=30)
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"Registration failed: {response.status_code} - {response.text}")
                return {"status": "error", "message": response.text}
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return {"status": "error", "message": str(e)}

    def _check_registration_status(self) -> Dict[str, Any]:
        """Check if this agent has been approved"""
        url = f"{self.config.server_url}/api/v1/logs/agents/check/{self.config.agent_key}"

        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {"status": "error", "message": response.text}
        except Exception as e:
            logger.error(f"Status check error: {e}")
            return {"status": "error", "message": str(e)}

    def _wait_for_approval(self):
        """Wait for admin approval"""
        # First, register with server
        result = self._register_with_server()

        if result.get("status") == "approved":
            # Already approved (re-registration)
            self.registration_state = self.STATE_APPROVED
            self.server_agent_id = result.get("agent_id")
            self.active_token = self.config.agent_key  # Use agent_key as token
            logger.info(f"Agent already approved: {self.server_agent_id}")
            return

        if result.get("status") == "pending":
            self.registration_state = self.STATE_PENDING
            self.server_agent_id = result.get("agent_id")
            logger.info(f"Registration pending approval. Agent ID: {self.server_agent_id}")
            logger.info(f"Agent Key: {self.config.agent_key}")
            logger.info("Waiting for admin to approve in the T1 Agentics UI...")
        elif result.get("status") == "error":
            logger.error(f"Registration failed: {result.get('message')}")
            return

        # Poll for approval
        while self.running and self.registration_state == self.STATE_PENDING:
            time.sleep(DEFAULT_REGISTRATION_CHECK_INTERVAL)

            status = self._check_registration_status()

            if status.get("status") == "approved":
                self.registration_state = self.STATE_APPROVED
                self.server_agent_id = status.get("agent_id")
                self.active_token = self.config.agent_key  # Use agent_key as token
                logger.info(f"Agent APPROVED! Agent ID: {self.server_agent_id}")

                # Save any config from server
                if "config" in status:
                    self.config.save_server_config(status["config"])
                    self._apply_server_config(status["config"])

                return

            elif status.get("status") == "rejected":
                self.registration_state = self.STATE_REJECTED
                logger.error("Agent registration was REJECTED by admin")
                return

            elif status.get("status") == "pending":
                logger.debug("Still waiting for approval...")

            else:
                logger.warning(f"Unexpected status: {status}")

    def _apply_server_config(self, config: Dict[str, Any]):
        """Apply configuration received from server"""
        if 'batch_size' in config:
            self.config.batch_size = config['batch_size']
            logger.info(f"Set batch_size to {config['batch_size']}")
        if 'flush_interval_seconds' in config:
            self.config.flush_interval = config['flush_interval_seconds']
            logger.info(f"Set flush_interval to {config['flush_interval_seconds']}")
        if 'heartbeat_interval_seconds' in config:
            self.config.heartbeat_interval = config['heartbeat_interval_seconds']
            logger.info(f"Set heartbeat_interval to {config['heartbeat_interval_seconds']}")

    def _check_for_config_updates(self):
        """Periodically check server for config updates"""
        if time.time() - self.last_config_check < CONFIG_CHECK_INTERVAL:
            return

        self.last_config_check = time.time()

        url = f"{self.config.server_url}/api/v1/logs/agents/{self.server_agent_id}/config"
        headers = {'X-Agent-Token': self.active_token}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                server_config = response.json()
                if server_config.get('config'):
                    self._apply_server_config(server_config['config'])
                    self.config.save_server_config(server_config['config'])
        except Exception as e:
            logger.debug(f"Config check failed: {e}")

    def _start_collectors(self):
        """Start all configured collectors"""

        # Journald collector
        if self.config.collect_journald and HAS_SYSTEMD:
            collector = JournaldCollector(self.event_queue)
            collector.start()
            self.collectors.append(collector)

        # Syslog collector
        if self.config.collect_syslog:
            syslog_paths = ['/var/log/syslog', '/var/log/messages']
            for path in syslog_paths:
                if os.path.exists(path):
                    collector = FileCollector(path, 'linux_syslog', self.event_queue)
                    collector.start()
                    self.collectors.append(collector)
                    break  # Only collect from one

        # Auth log collector
        if self.config.collect_auth:
            auth_paths = ['/var/log/auth.log', '/var/log/secure']
            for path in auth_paths:
                if os.path.exists(path):
                    collector = FileCollector(path, 'linux_auth', self.event_queue)
                    collector.start()
                    self.collectors.append(collector)
                    break

        # Audit log collector
        if self.config.collect_audit:
            audit_path = '/var/log/audit/audit.log'
            if os.path.exists(audit_path):
                collector = FileCollector(audit_path, 'linux_auditd', self.event_queue)
                collector.start()
                self.collectors.append(collector)

        logger.info(f"Started {len(self.collectors)} collectors")

    def _run(self):
        """Main processing loop"""
        batch = []
        last_flush = time.time()

        while self.running:
            try:
                # Check for heartbeat
                if time.time() - self.last_heartbeat > self.config.heartbeat_interval:
                    self._send_heartbeat()

                # Check for config updates from server
                self._check_for_config_updates()

                # Collect events from queue
                try:
                    event = self.event_queue.get(timeout=1)

                    # Normalize event
                    source_type = event.get('source_type', 'linux_syslog')
                    normalized = self.normalizer.normalize(event, source_type)
                    batch.append(normalized)

                except queue.Empty:
                    pass

                # Flush batch if needed
                now = time.time()
                if len(batch) >= self.config.batch_size or \
                   (batch and now - last_flush >= self.config.flush_interval):
                    self._send_batch(batch)
                    batch = []
                    last_flush = now

            except Exception as e:
                logger.error(f"Processing error: {e}")
                time.sleep(1)

        # Final flush
        if batch:
            self._send_batch(batch)

    def _send_batch(self, events: List[Dict]):
        """Send a batch of events to the server"""
        if not events:
            return

        url = f"{self.config.server_url}/api/v1/logs/ingest/bulk"
        headers = {
            'X-Agent-Token': self.active_token,
            'Content-Type': 'application/json'
        }

        # Determine source type from first event
        source_type = events[0].get('source_type', 'linux_syslog')

        try:
            response = requests.post(
                url,
                headers=headers,
                json={'source_type': source_type, 'events': events},
                timeout=30
            )

            if response.status_code == 200:
                result = response.json()
                self.events_sent += result.get('success', len(events))
                self.reconnect_delay = RECONNECT_BASE_DELAY  # Reset delay on success
                logger.debug(f"Sent {len(events)} events, total: {self.events_sent}")
            elif response.status_code == 401:
                logger.error("Authentication failed - agent may need re-registration")
            else:
                logger.error(f"Failed to send events: {response.status_code} - {response.text}")

        except requests.exceptions.ConnectionError:
            logger.error(f"Connection failed, will retry in {self.reconnect_delay}s")
            time.sleep(self.reconnect_delay)
            self.reconnect_delay = min(self.reconnect_delay * 2, RECONNECT_MAX_DELAY)
        except Exception as e:
            logger.error(f"Error sending events: {e}")

    def _send_heartbeat(self):
        """Send heartbeat to server"""
        agent_id = self.server_agent_id or self.config.agent_id or self.config.hostname
        url = f"{self.config.server_url}/api/v1/logs/agents/{agent_id}/heartbeat"
        headers = {
            'X-Agent-Token': self.active_token,
            'Content-Type': 'application/json'
        }

        payload = {
            'hostname': self.config.hostname,
            'agent_version': VERSION,
            'os_type': 'linux',
            'events_sent': self.events_sent,
            'queue_size': self.event_queue.qsize(),
            'collectors_active': len(self.collectors)
        }

        try:
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            if response.status_code == 200:
                self.last_heartbeat = time.time()
                result = response.json()
                # Check if server pushed any config updates
                if result.get('config_update'):
                    self._apply_server_config(result['config_update'])
                    self.config.save_server_config(result['config_update'])
                logger.debug("Heartbeat sent")
            else:
                logger.warning(f"Heartbeat failed: {response.status_code}")
        except Exception as e:
            logger.warning(f"Heartbeat error: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='T1 Agentics Linux Log Collection Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-registration (recommended for deployment scripts/golden images)
  python3 t1_agent.py --server https://t1.example.com:8000

  # With pre-configured token (skips registration)
  python3 t1_agent.py --server https://t1.example.com:8000 --token abc123

  # With tags for organization
  python3 t1_agent.py --server https://t1.example.com:8000 --tag production --tag webserver

  # Disable specific collectors
  python3 t1_agent.py --server https://t1.example.com:8000 --no-audit
        """
    )

    parser.add_argument('--server', '-s', required=True,
                        help='T1 Agentics server URL (e.g., https://t1.example.com:8000)')
    parser.add_argument('--token', '-t',
                        help='Agent authentication token (optional - will auto-register if not provided)')
    parser.add_argument('--agent-id', '-i',
                        help='Agent ID (defaults to hostname)')
    parser.add_argument('--hostname', '-n',
                        help='Override hostname')
    parser.add_argument('--tag', action='append', default=[],
                        help='Add tag to agent (can be used multiple times)')
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE,
                        help=f'Events per batch (default: {DEFAULT_BATCH_SIZE})')
    parser.add_argument('--flush-interval', type=int, default=DEFAULT_FLUSH_INTERVAL,
                        help=f'Flush interval in seconds (default: {DEFAULT_FLUSH_INTERVAL})')
    parser.add_argument('--no-journald', action='store_true',
                        help='Disable journald collection')
    parser.add_argument('--no-syslog', action='store_true',
                        help='Disable syslog collection')
    parser.add_argument('--no-auth', action='store_true',
                        help='Disable auth log collection')
    parser.add_argument('--no-audit', action='store_true',
                        help='Disable auditd collection')
    parser.add_argument('--debug', '-d', action='store_true',
                        help='Enable debug logging')
    parser.add_argument('--version', '-v', action='version',
                        version=f'T1 Agent v{VERSION}')

    args = parser.parse_args()

    # Set log level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Create config
    config = AgentConfig(
        server_url=args.server.rstrip('/'),
        agent_token=args.token,  # Optional - will auto-register if None
        agent_id=args.agent_id,
        hostname=args.hostname or socket.gethostname(),
        tags=args.tag,
        batch_size=args.batch_size,
        flush_interval=args.flush_interval,
        collect_journald=not args.no_journald,
        collect_syslog=not args.no_syslog,
        collect_auth=not args.no_auth,
        collect_audit=not args.no_audit
    )

    # Create and start agent
    agent = T1Agent(config)

    # Handle signals
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start agent
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == '__main__':
    main()
