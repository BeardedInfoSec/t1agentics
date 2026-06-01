#!/bin/bash
# =============================================================================
# T1 Agentics Unified Agent Installer
# =============================================================================
# Installs the all-in-one T1 agent with configurable modes
#
# Usage:
#   # Full mode (logs + EDR + inventory)
#   sudo ./install_unified.sh --server https://your-server:8000 --mode full
#
#   # Log collector only
#   sudo ./install_unified.sh --server https://your-server:8000 --mode log-collector
#
#   # EDR only
#   sudo ./install_unified.sh --server https://your-server:8000 --mode edr
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Defaults
INSTALL_DIR="/opt/t1-agent"
DATA_DIR="/var/lib/t1-agent"
SERVICE_NAME="t1-agent"
QUARANTINE_DIR="/var/lib/t1-agent/quarantine"

# Arguments
SERVER_URL=""
AGENT_TOKEN=""
AGENT_MODE="full"
AGENT_TAGS=""
AUTO_KILL="false"
AUTO_QUARANTINE="false"

print_banner() {
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║          T1 Agentics Unified Agent Installer                  ║"
    echo "║                     v1.0.0                                    ║"
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

check_python() {
    print_info "Checking Python version..."

    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        print_success "Python $PYTHON_VERSION found"

        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
            return 0
        else
            print_error "Python 3.8 or higher required"
            exit 1
        fi
    else
        print_error "Python 3 not found"
        exit 1
    fi
}

install_dependencies() {
    print_info "Installing Python dependencies..."

    # Ensure pip
    if ! python3 -m pip --version &> /dev/null; then
        print_info "Installing pip..."
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            yum install -y python3-pip
        elif command -v dnf &> /dev/null; then
            dnf install -y python3-pip
        fi
    fi

    # Core
    python3 -m pip install --quiet requests
    print_success "requests installed"

    # Optional but recommended
    if python3 -m pip install --quiet psutil 2>/dev/null; then
        print_success "psutil installed (process/network monitoring)"
    else
        print_info "psutil not available"
    fi

    if python3 -m pip install --quiet pyinotify 2>/dev/null; then
        print_success "pyinotify installed (inotify FIM)"
    else
        print_info "pyinotify not available (polling FIM)"
    fi

    if python3 -m pip install --quiet systemd-python 2>/dev/null; then
        print_success "systemd-python installed (journald)"
    else
        print_info "systemd-python not available"
    fi
}

install_agent() {
    print_info "Installing agent to $INSTALL_DIR..."

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$QUARANTINE_DIR"

    # Copy agent
    cp t1_unified_agent.py "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/t1_unified_agent.py"

    # Create config
    cat > "$INSTALL_DIR/config.env" << EOF
# T1 Unified Agent Configuration
T1_SERVER_URL=$SERVER_URL
T1_AGENT_TOKEN=${AGENT_TOKEN:-}
T1_AGENT_MODE=$AGENT_MODE
T1_AGENT_TAGS=${AGENT_TAGS:-}
T1_AUTO_KILL=$AUTO_KILL
T1_AUTO_QUARANTINE=$AUTO_QUARANTINE
EOF
    chmod 600 "$INSTALL_DIR/config.env"

    print_success "Agent installed to $INSTALL_DIR"
}

create_systemd_service() {
    print_info "Creating systemd service..."

    # Build ExecStart
    EXEC_START="/usr/bin/python3 $INSTALL_DIR/t1_unified_agent.py --server \${T1_SERVER_URL} --mode \${T1_AGENT_MODE}"

    if [ -n "$AGENT_TOKEN" ]; then
        EXEC_START="$EXEC_START --token \${T1_AGENT_TOKEN}"
    fi

    if [ "$AUTO_KILL" = "true" ]; then
        EXEC_START="$EXEC_START --auto-kill"
    fi

    if [ "$AUTO_QUARANTINE" = "true" ]; then
        EXEC_START="$EXEC_START --auto-quarantine"
    fi

    # Service file
    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=T1 Agentics Unified Agent
Documentation=https://github.com/your-org/t1-agentics
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EnvironmentFile=$INSTALL_DIR/config.env
ExecStart=$EXEC_START
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=t1-agent

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Systemd service created"
}

start_service() {
    print_info "Starting T1 Agent service..."

    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    sleep 3

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "T1 Agent is running"
    else
        print_error "Failed to start. Check: journalctl -u $SERVICE_NAME"
        exit 1
    fi
}

show_usage() {
    echo "Usage: $0 --server SERVER_URL [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --server, -s        T1 Agentics server URL (required)"
    echo "  --mode, -m          Agent mode: full, edr, log-collector (default: full)"
    echo "  --token, -t         Agent token (optional - auto-registers if not provided)"
    echo "  --tag               Add tag (can use multiple times)"
    echo "  --auto-kill         Enable auto-kill of IOC processes (EDR/full modes)"
    echo "  --auto-quarantine   Enable auto-quarantine of IOC files (EDR/full modes)"
    echo "  --help, -h          Show this help"
    echo ""
    echo "Modes:"
    echo "  full           Everything: logs + EDR + inventory (default)"
    echo "  edr            EDR only: process/file/network monitoring + response"
    echo "  log-collector  Logs only: lightweight log forwarding"
    echo ""
    echo "Examples:"
    echo "  # Full agent"
    echo "  sudo $0 --server https://t1.example.com:8000"
    echo ""
    echo "  # EDR with auto-response"
    echo "  sudo $0 --server https://t1.example.com:8000 --mode edr --auto-kill"
    echo ""
    echo "  # Lightweight log collector"
    echo "  sudo $0 --server https://t1.example.com:8000 --mode log-collector"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server|-s)
            SERVER_URL="$2"
            shift 2
            ;;
        --mode|-m)
            AGENT_MODE="$2"
            shift 2
            ;;
        --token|-t)
            AGENT_TOKEN="$2"
            shift 2
            ;;
        --tag)
            if [ -z "$AGENT_TAGS" ]; then
                AGENT_TAGS="$2"
            else
                AGENT_TAGS="$AGENT_TAGS,$2"
            fi
            shift 2
            ;;
        --auto-kill)
            AUTO_KILL="true"
            shift
            ;;
        --auto-quarantine)
            AUTO_QUARANTINE="true"
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

# Validate
if [ -z "$SERVER_URL" ]; then
    print_error "Server URL is required"
    show_usage
    exit 1
fi

if [[ ! "$AGENT_MODE" =~ ^(full|edr|log-collector)$ ]]; then
    print_error "Invalid mode: $AGENT_MODE"
    show_usage
    exit 1
fi

# Install
print_banner
check_root
check_python
install_dependencies
install_agent
create_systemd_service
start_service

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo -e "${CYAN}Mode: $AGENT_MODE${NC}"
echo ""

case $AGENT_MODE in
    full)
        echo "Enabled features:"
        echo "  - Log collection (journald, syslog, auth, audit)"
        echo "  - Process monitoring"
        echo "  - File integrity monitoring (FIM)"
        echo "  - Network connection tracking"
        echo "  - Asset inventory"
        echo "  - Response actions"
        ;;
    edr)
        echo "Enabled features:"
        echo "  - Process monitoring"
        echo "  - File integrity monitoring (FIM)"
        echo "  - Network connection tracking"
        echo "  - Asset inventory"
        echo "  - Response actions"
        ;;
    log-collector)
        echo "Enabled features:"
        echo "  - Log collection (journald, syslog, auth, audit)"
        echo "  - Asset inventory"
        ;;
esac

if [ "$AUTO_KILL" = "true" ]; then
    echo -e "  - ${RED}Auto-kill: ENABLED${NC}"
fi
if [ "$AUTO_QUARANTINE" = "true" ]; then
    echo -e "  - ${RED}Auto-quarantine: ENABLED${NC}"
fi

echo ""
if [ -z "$AGENT_TOKEN" ]; then
    echo "Agent will auto-register. Approve in T1 Agentics UI."
    echo "To find agent key:"
    echo "  sudo journalctl -u $SERVICE_NAME | grep 'agent key'"
fi
echo ""
echo "Commands:"
echo "  Status:     sudo systemctl status $SERVICE_NAME"
echo "  Logs:       sudo journalctl -u $SERVICE_NAME -f"
echo "  Restart:    sudo systemctl restart $SERVICE_NAME"
echo "  Uninstall:  sudo systemctl stop $SERVICE_NAME && sudo rm -rf $INSTALL_DIR $DATA_DIR /etc/systemd/system/${SERVICE_NAME}.service"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
