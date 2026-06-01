# T1 Agentics Linux EDR Agent

Endpoint Detection and Response (EDR) agent for Linux systems with built-in asset inventory collection.

## Features

### Detection Capabilities
- **Process Monitoring** - Track process creation/termination, command lines, parent-child relationships
- **File Integrity Monitoring (FIM)** - Watch critical system files for changes using inotify
- **Network Connection Tracking** - Monitor outbound connections and DNS lookups
- **IOC Matching** - Real-time matching against server-distributed indicators

### Response Actions
- **Kill Process** - Terminate malicious processes by PID
- **Quarantine File** - Move malicious files to secure quarantine
- **Block IP** - Add iptables rules to block malicious IPs
- **Host Isolation** - (Planned) Isolate compromised hosts

### Asset Inventory
Automatically collects and syncs:
- Hardware info (CPU, RAM, disk)
- OS version and kernel
- Installed packages (dpkg/rpm)
- Running services (systemd)
- Local user accounts (with sudo access detection)
- Network interfaces and open ports
- MAC addresses for network discovery

## Requirements

- Python 3.8+
- `requests` library
- `psutil` (recommended - for process/network monitoring)
- `pyinotify` (recommended - for inotify-based FIM)
- Root privileges (for process killing, file quarantine, network blocking)

## Quick Installation

```bash
# Download files
curl -O https://your-server/agents/linux/t1_edr.py
curl -O https://your-server/agents/linux/install_edr.sh
chmod +x install_edr.sh

# Basic installation (auto-registration)
sudo ./install_edr.sh --server https://your-server:8000

# With auto-response enabled (use with caution!)
sudo ./install_edr.sh --server https://your-server:8000 --auto-kill --auto-quarantine

# With tags for organization
sudo ./install_edr.sh --server https://your-server:8000 --tag production --tag webserver
```

## Usage

```
python3 t1_edr.py --server https://t1.example.com:8000

Options:
  --server, -s         T1 Agentics server URL (required)
  --token, -t          Agent authentication token (optional)
  --agent-id, -i       Agent ID (defaults to hostname)
  --hostname, -n       Override hostname
  --tag                Add tag to agent (can use multiple times)
  --no-process         Disable process monitoring
  --no-fim             Disable file integrity monitoring
  --no-network         Disable network monitoring
  --auto-kill          Auto-kill processes matching IOCs
  --auto-quarantine    Auto-quarantine files matching IOCs
  --fim-path           Additional path to monitor for FIM
  --debug, -d          Enable debug logging
  --version, -v        Show version
```

## IOC Types Supported

| Type | Description | Example |
|------|-------------|---------|
| Hash | SHA256 file hash | `a1b2c3d4e5f6...` |
| IP | IPv4 address | `192.168.1.100` |
| Domain | Malicious domain | `evil.com` |
| Process Name | Malicious process | `cryptominer` |
| File Path | Malicious file location | `/tmp/.hidden/malware` |

## Default FIM Paths

The agent monitors these paths by default:

```
/etc/passwd
/etc/shadow
/etc/sudoers
/etc/sudoers.d
/etc/ssh/sshd_config
/etc/crontab
/etc/cron.d
/etc/cron.daily
/etc/cron.hourly
/etc/systemd/system
/usr/bin
/usr/sbin
/usr/local/bin
/root/.ssh
/root/.bashrc
/root/.bash_profile
```

Add custom paths with `--fim-path /path/to/watch`.

## API Endpoints

### Agent Management
- `POST /api/v1/edr/agents/register` - Self-register agent
- `GET /api/v1/edr/agents/check/{key}` - Check registration status
- `GET /api/v1/edr/agents` - List all agents
- `GET /api/v1/edr/agents/{id}` - Get agent details
- `POST /api/v1/edr/agents/{id}/heartbeat` - Agent heartbeat

### Events
- `POST /api/v1/edr/events` - Submit events
- `GET /api/v1/edr/events` - Query events

### IOC Management
- `GET /api/v1/edr/iocs` - Get IOC database
- `PUT /api/v1/edr/iocs` - Update IOCs
- `POST /api/v1/edr/iocs/bulk-import` - Bulk import IOCs

### Response Actions
- `POST /api/v1/edr/agents/{id}/action` - Queue action
- `GET /api/v1/edr/agents/{id}/actions` - Get pending actions

### Asset Inventory
- `POST /api/v1/edr/agents/{id}/inventory` - Submit inventory
- `GET /api/v1/edr/inventory` - Get all inventories
- `GET /api/v1/edr/inventory/search` - Search across inventories

## Asset Inventory Search Examples

```bash
# Find all hosts with Apache installed
curl "https://server:8000/api/v1/edr/inventory/search?package=apache"

# Find hosts with SSH service running
curl "https://server:8000/api/v1/edr/inventory/search?service=sshd"

# Find hosts with port 22 open
curl "https://server:8000/api/v1/edr/inventory/search?port=22"

# Find hosts with specific user
curl "https://server:8000/api/v1/edr/inventory/search?user=admin"
```

## Response Action Examples

```bash
# Kill a process
curl -X POST "https://server:8000/api/v1/edr/agents/edr-host-abc123/action" \
  -H "Content-Type: application/json" \
  -d '{"action": {"type": "kill_process", "target": "12345", "reason": "Cryptominer"}}'

# Quarantine a file
curl -X POST "https://server:8000/api/v1/edr/agents/edr-host-abc123/action" \
  -H "Content-Type: application/json" \
  -d '{"action": {"type": "quarantine_file", "target": "/tmp/malware.bin", "reason": "IOC match"}}'

# Block an IP
curl -X POST "https://server:8000/api/v1/edr/agents/edr-host-abc123/action" \
  -H "Content-Type: application/json" \
  -d '{"action": {"type": "block_ip", "target": "10.0.0.50", "reason": "C2 communication"}}'
```

## Service Management

```bash
# Check status
sudo systemctl status t1-edr

# View real-time logs
sudo journalctl -u t1-edr -f

# Restart agent
sudo systemctl restart t1-edr

# Stop agent
sudo systemctl stop t1-edr

# Disable on boot
sudo systemctl disable t1-edr
```

## Quarantine

Quarantined files are stored in `/var/lib/t1-edr/quarantine/` with:
- Original file (permissions removed)
- Metadata file (.meta.json) with original path, hash, timestamp

To restore a quarantined file (admin only):
```bash
# View quarantine
ls -la /var/lib/t1-edr/quarantine/

# Check metadata
cat /var/lib/t1-edr/quarantine/20250110_123456_a1b2c3d4_malware.bin.meta.json

# Restore (careful!)
chmod 644 /var/lib/t1-edr/quarantine/20250110_123456_a1b2c3d4_malware.bin
mv /var/lib/t1-edr/quarantine/20250110_123456_a1b2c3d4_malware.bin /original/path
```

## Uninstallation

```bash
sudo systemctl stop t1-edr
sudo systemctl disable t1-edr
sudo rm -rf /opt/t1-edr
sudo rm -rf /var/lib/t1-edr
sudo rm /etc/systemd/system/t1-edr.service
sudo systemctl daemon-reload
sudo userdel t1edr
```

## Security Considerations

- EDR agent runs as **root** (required for process killing, file quarantine, iptables)
- Agent token stored in `/opt/t1-edr/config.env` with 600 permissions
- Quarantine directory has restricted permissions
- Auto-kill/auto-quarantine disabled by default (enable with caution)
- All response actions are logged

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│  T1 EDR Agent   │────▶│   T1 Backend    │
│                 │◀────│                 │
│  - Process Mon  │     │  - IOC Database │
│  - FIM          │     │  - Event Store  │
│  - Network Mon  │     │  - Asset Store  │
│  - Response     │     │  - Actions      │
│  - Inventory    │     │                 │
└─────────────────┘     └─────────────────┘
        │
        ▼
  ┌───────────┐
  │ Quarantine│
  │   /var/   │
  │lib/t1-edr │
  └───────────┘
```

## License

Part of T1 Agentics - See main project license.
