# T1 Agentics Linux Log Collection Agent

Lightweight Python agent for collecting and forwarding security logs to T1 Agentics.

## Features

- **Auto-Registration** - No pre-configured tokens needed, perfect for golden images and deployment scripts
- **Server-Pushed Config** - Server can push configuration updates to agents remotely
- **Journald Collection** - Collects from systemd journal (requires `systemd-python`)
- **Syslog Collection** - Tails `/var/log/syslog` or `/var/log/messages`
- **Auth Log Collection** - Monitors `/var/log/auth.log` or `/var/log/secure`
- **Auditd Collection** - Monitors `/var/log/audit/audit.log` if available
- **ECS Normalization** - Converts all logs to Elastic Common Schema format
- **Automatic Reconnection** - Exponential backoff on connection failures
- **Heartbeat Monitoring** - Regular status updates to server
- **Low Resource Usage** - Efficient batching and queue management

## Requirements

- Python 3.8+
- `requests` library
- `systemd-python` (optional, for journald collection)
- Root or appropriate permissions to read log files

## Quick Installation (Auto-Registration)

This is the recommended method for deployment scripts and golden images:

```bash
# Download the agent
curl -O https://your-server/agents/linux/t1_agent.py
curl -O https://your-server/agents/linux/install.sh
chmod +x install.sh

# Install with auto-registration (no token needed)
sudo ./install.sh --server https://your-server:8000

# Optional: Add tags for organization
sudo ./install.sh --server https://your-server:8000 --tag production --tag webserver
```

After installation, the agent will:
1. Generate a unique agent key
2. Register with the T1 Agentics server
3. Wait for admin approval in the UI
4. Start collecting logs once approved

## Installation with Pre-Configured Token

If you already have a token from the UI:

```bash
sudo ./install.sh --server https://your-server:8000 --token YOUR_AGENT_TOKEN
```

## Manual Installation

```bash
# Install dependencies
pip3 install requests
pip3 install systemd-python  # Optional, for journald

# Run with auto-registration
python3 t1_agent.py --server https://your-server:8000

# Or run with token
python3 t1_agent.py --server https://your-server:8000 --token YOUR_TOKEN
```

## Usage

```
python3 t1_agent.py --server https://t1.example.com:8000

Options:
  --server, -s        T1 Agentics server URL (required)
  --token, -t         Agent authentication token (optional - auto-registers if not provided)
  --agent-id, -i      Agent ID (defaults to hostname)
  --hostname, -n      Override hostname
  --tag               Add tag to agent (can use multiple times)
  --batch-size        Events per batch (default: 50)
  --flush-interval    Flush interval in seconds (default: 10)
  --no-journald       Disable journald collection
  --no-syslog         Disable syslog collection
  --no-auth           Disable auth log collection
  --no-audit          Disable auditd collection
  --debug, -d         Enable debug logging
  --version, -v       Show version
```

## Approving Pending Agents

When using auto-registration:

1. Log in to T1 Agentics web UI
2. Navigate to **Security Events > Agents**
3. Click the **Pending** tab
4. Review and approve/reject agents

## Server-Pushed Configuration

Admins can push configuration updates to agents from the UI or API:

```bash
# Update single agent
curl -X PUT https://your-server:8000/api/v1/logs/agents/AGENT_ID/config \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"batch_size": 100, "flush_interval_seconds": 5}'

# Bulk update multiple agents
curl -X POST https://your-server:8000/api/v1/logs/agents/bulk-config \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"agent_ids": ["agent-1", "agent-2"], "config": {"batch_size": 100}}'
```

Configuration is delivered on the agent's next heartbeat (default: every 60 seconds).

## Log Sources

| Source | File/Method | Events |
|--------|-------------|--------|
| Journald | systemd journal | All systemd service logs |
| Syslog | `/var/log/syslog` or `/var/log/messages` | System messages |
| Auth | `/var/log/auth.log` or `/var/log/secure` | SSH, sudo, PAM events |
| Auditd | `/var/log/audit/audit.log` | Kernel audit events |

## ECS Field Mapping

The agent normalizes all logs to [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html) format:

```json
{
  "@timestamp": "2025-01-10T12:00:00.000Z",
  "ecs": {"version": "8.0.0"},
  "agent": {"type": "t1-linux-agent", "version": "1.0.0"},
  "host": {"name": "server-01", "ip": "192.168.1.100"},
  "event": {
    "category": ["authentication"],
    "type": ["start"],
    "action": "ssh_login",
    "outcome": "success"
  },
  "user": {"name": "admin"},
  "source": {"ip": "10.0.0.5", "port": 52431}
}
```

## Service Management

```bash
# Check status
sudo systemctl status t1-agent

# View real-time logs
sudo journalctl -u t1-agent -f

# Restart agent
sudo systemctl restart t1-agent

# Stop agent
sudo systemctl stop t1-agent

# Disable on boot
sudo systemctl disable t1-agent
```

## Troubleshooting

### Agent won't start
```bash
# Check logs
sudo journalctl -u t1-agent --no-pager -n 50

# Verify config
cat /opt/t1-agent/config.env

# Test manually
sudo -u t1agent python3 /opt/t1-agent/t1_agent.py --server URL --token TOKEN --debug
```

### No journald events
```bash
# Check if systemd-python is installed
python3 -c "from systemd import journal; print('OK')"

# Install if missing
pip3 install systemd-python
```

### Permission denied on log files
```bash
# Add user to required groups
sudo usermod -a -G adm t1agent
sudo usermod -a -G systemd-journal t1agent

# Restart service
sudo systemctl restart t1-agent
```

### Connection refused
- Verify server URL is correct
- Check firewall allows outbound HTTPS (port 8000 or your configured port)
- Verify token is valid

## Uninstallation

```bash
sudo systemctl stop t1-agent
sudo systemctl disable t1-agent
sudo rm -rf /opt/t1-agent
sudo rm /etc/systemd/system/t1-agent.service
sudo systemctl daemon-reload
sudo userdel t1agent
```

## Security Considerations

- Agent runs as unprivileged user `t1agent`
- Token stored in `/opt/t1-agent/config.env` with 600 permissions
- Systemd service hardened with `NoNewPrivileges`, `ProtectSystem`, etc.
- Only reads from log files, never writes

## License

Part of T1 Agentics - See main project license.
