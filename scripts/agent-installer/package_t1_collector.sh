#!/bin/bash
# =============================================================================
# T1 Log Collector Packager
# =============================================================================
# Creates a distributable tarball of the T1 Log Collector
#
# Output: t1-collector-v1.0.0.tar.gz
#
# =============================================================================

set -e

VERSION="1.2.0"
PACKAGE_NAME="t1-collector-v${VERSION}"
OUTPUT_DIR="dist"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║            T1 Log Collector Packager                          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Clean previous builds
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/$PACKAGE_NAME"

echo "[+] Packaging T1 Log Collector v${VERSION}..."

# Copy files
echo "    [*] Copying agent files..."
cp t1_unified_agent.py "$OUTPUT_DIR/$PACKAGE_NAME/"
cp t1_edr.py "$OUTPUT_DIR/$PACKAGE_NAME/"
cp install_t1_collector.sh "$OUTPUT_DIR/$PACKAGE_NAME/"
cp uninstall_t1_collector.sh "$OUTPUT_DIR/$PACKAGE_NAME/"
cp fix_t1_collector.sh "$OUTPUT_DIR/$PACKAGE_NAME/"

# Create main README
cat > "$OUTPUT_DIR/$PACKAGE_NAME/README.md" << 'EOF'
# T1 Log Collector

Unified agent for log collection, EDR, and asset inventory.

## Quick Install

```bash
# Extract
tar -xzf t1-collector-v1.0.0.tar.gz
cd t1-collector-v1.0.0

# Install (log collector mode - default)
./install_t1_collector.sh --server https://your-server:8000

# Install (full mode - logs + EDR + inventory)
./install_t1_collector.sh --server https://your-server:8000 --mode full

# Install (EDR only)
./install_t1_collector.sh --server https://your-server:8000 --mode edr
```

## Modes

| Mode | Description |
|------|-------------|
| log-collector | Lightweight log forwarding (default) |
| edr | Process/file/network monitoring + response |
| full | Everything: logs + EDR + inventory |

## Installation Directory

Default: `/opt/t1_log_collector`

## Options

```
--server, -s        Server URL (required)
--mode, -m          Agent mode: full, edr, log-collector
--token, -t         Pre-configured token (optional)
--tag               Add tag for organization
--auto-kill         Auto-kill IOC processes (EDR/full)
--auto-quarantine   Auto-quarantine IOC files (EDR/full)
--service           Run as systemd user service
```

## Requirements

- Python 3.8+
- requests (auto-installed)
- psutil (optional - for process monitoring)
- pyinotify (optional - for inotify FIM)

## Commands After Install

```bash
# Start
/opt/t1_log_collector/run.sh

# Stop
/opt/t1_log_collector/stop.sh

# Status
/opt/t1_log_collector/status.sh

# Logs
tail -f /opt/t1_log_collector/logs/collector.log

# Config
cat /opt/t1_log_collector/config.env

# Check what's running
ps aux | grep t1_unified
```

## Troubleshooting

If the agent fails to start:
```bash
# Check the log
cat /opt/t1_log_collector/logs/collector.log

# Try running manually to see errors
/opt/t1_log_collector/run.sh

# Check if venv python works
/opt/t1_log_collector/venv/bin/python3 --version
```

## Uninstall

```bash
/opt/t1_log_collector/stop.sh
rm -rf /opt/t1_log_collector
```
EOF

# Make scripts executable
chmod +x "$OUTPUT_DIR/$PACKAGE_NAME/"*.sh
chmod +x "$OUTPUT_DIR/$PACKAGE_NAME/"*.py

# Create tarball
echo "    [*] Creating tarball..."
cd "$OUTPUT_DIR"
tar -czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"
cd ..

# Create checksum
echo "    [*] Generating checksum..."
cd "$OUTPUT_DIR"
sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"
cd ..

# Show results
TARBALL_SIZE=$(du -h "$OUTPUT_DIR/${PACKAGE_NAME}.tar.gz" | cut -f1)
CHECKSUM=$(cat "$OUTPUT_DIR/${PACKAGE_NAME}.tar.gz.sha256" | cut -d' ' -f1)

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Package created successfully!${NC}"
echo ""
echo -e "Package:  ${CYAN}$OUTPUT_DIR/${PACKAGE_NAME}.tar.gz${NC}"
echo -e "Size:     ${CYAN}${TARBALL_SIZE}${NC}"
echo -e "SHA256:   ${CYAN}${CHECKSUM}${NC}"
echo ""
echo "Contents:"
tar -tzf "$OUTPUT_DIR/${PACKAGE_NAME}.tar.gz" | sed 's/^/  /'
echo ""
echo "Distribution:"
echo "  1. Copy $OUTPUT_DIR/${PACKAGE_NAME}.tar.gz to target machine"
echo "  2. tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "  3. cd ${PACKAGE_NAME}"
echo "  4. ./install_t1_collector.sh --server https://your-server:8000"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
