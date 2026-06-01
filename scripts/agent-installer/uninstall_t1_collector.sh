#!/bin/bash
# =============================================================================
# T1 Log Collector Uninstaller
# =============================================================================
# Completely removes the T1 collector from the system
#
# Usage:
#   sudo ./uninstall_t1_collector.sh
#   sudo ./uninstall_t1_collector.sh --keep-logs
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
SERVICE_NAME="t1-collector"
KEEP_LOGS=false

print_banner() {
    echo -e "${RED}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║            T1 Log Collector Uninstaller                       ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_error() { echo -e "${RED}[ERROR] $1${NC}" >&2; }
print_success() { echo -e "${GREEN}[OK] $1${NC}"; }
print_info() { echo -e "${YELLOW}[INFO] $1${NC}"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

stop_service() {
    print_info "Stopping T1 Log Collector service..."

    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
        print_success "Service stopped"
    else
        print_info "Service is not running"
    fi

    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME"
        print_success "Service disabled"
    fi
}

remove_service_file() {
    print_info "Removing systemd service file..."

    SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
    if [ -f "$SERVICE_FILE" ]; then
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        print_success "Service file removed"
    else
        print_info "Service file not found (already removed)"
    fi
}

remove_installation() {
    print_info "Removing installation directory..."

    if [ -d "$INSTALL_DIR" ]; then
        if [ "$KEEP_LOGS" = true ]; then
            # Keep logs directory
            print_info "Keeping logs directory..."
            find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 ! -name 'logs' -exec rm -rf {} +
            print_success "Installation removed (logs kept at $INSTALL_DIR/logs)"
        else
            rm -rf "$INSTALL_DIR"
            print_success "Installation directory removed"
        fi
    else
        print_info "Installation directory not found (already removed)"
    fi
}

show_usage() {
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --keep-logs    Keep the logs directory after uninstall"
    echo "  --help, -h     Show this help"
    echo ""
    echo "This script will:"
    echo "  1. Stop the t1-collector service"
    echo "  2. Disable the service from auto-start"
    echo "  3. Remove the systemd service file"
    echo "  4. Remove all files from /opt/t1_log_collector"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --keep-logs)
            KEEP_LOGS=true
            shift
            ;;
        --help|-h)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main
print_banner
check_root

echo ""
echo -e "${YELLOW}This will completely remove the T1 Log Collector from this system.${NC}"
echo ""
read -p "Are you sure you want to continue? (y/N) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Uninstall cancelled"
    exit 0
fi

echo ""
stop_service
remove_service_file
remove_installation

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         T1 Log Collector Uninstalled Successfully             ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
