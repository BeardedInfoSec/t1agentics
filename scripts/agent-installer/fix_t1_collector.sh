#!/bin/bash
# =============================================================================
# T1 Log Collector Service Fix
# =============================================================================
# Fixes the systemd service file for existing installations
#
# Usage:
#   sudo ./fix_t1_collector.sh
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Installation paths
INSTALL_DIR="/opt/t1_log_collector"
LOG_DIR="/opt/t1_log_collector/logs"
SERVICE_NAME="t1-collector"

print_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
print_success() { echo -e "${GREEN}[OK] $1${NC}"; }
print_info() { echo -e "${YELLOW}[INFO] $1${NC}"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

fix_service() {
    print_info "Fixing systemd service file..."

    # Check if installation exists
    if [ ! -d "$INSTALL_DIR" ]; then
        print_error "Installation directory not found: $INSTALL_DIR"
        print_error "Please run the installer first"
        exit 1
    fi

    # Check if run.sh exists
    if [ ! -f "$INSTALL_DIR/run.sh" ]; then
        print_error "run.sh not found in $INSTALL_DIR"
        exit 1
    fi

    # Ensure logs directory exists
    mkdir -p "$LOG_DIR"

    # Stop service if running
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        print_info "Stopping service..."
        systemctl stop "$SERVICE_NAME"
    fi

    # Create correct service file
    cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=T1 Log Collector Agent
Documentation=https://github.com/your-org/t1-agentics
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStart=$INSTALL_DIR/run.sh
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/collector.log
StandardError=append:$LOG_DIR/collector.log

# Security hardening
NoNewPrivileges=false
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF

    print_success "Service file created"

    # Reload systemd
    systemctl daemon-reload
    print_success "Systemd daemon reloaded"

    # Enable and start service
    systemctl enable "$SERVICE_NAME"
    print_success "Service enabled"

    systemctl start "$SERVICE_NAME"
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "T1 Log Collector is now running!"
        echo ""
        systemctl status "$SERVICE_NAME" --no-pager
    else
        print_error "Service failed to start. Check: journalctl -u $SERVICE_NAME -n 50"
        exit 1
    fi
}

# Main
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║            T1 Log Collector Service Fix                       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

check_root
fix_service

echo ""
echo -e "${GREEN}Service fix complete!${NC}"
echo ""
