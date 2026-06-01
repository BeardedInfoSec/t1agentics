#!/bin/bash
# =============================================================================
# T1 Agentics Linux EDR Agent Installer
# =============================================================================
# Installs the T1 EDR agent as a systemd service
#
# Usage (auto-registration - recommended):
#   sudo ./install_edr.sh --server https://your-server:8000
#
# Usage (with pre-configured token):
#   sudo ./install_edr.sh --server https://your-server:8000 --token YOUR_TOKEN
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
INSTALL_DIR="/opt/t1-edr"
DATA_DIR="/var/lib/t1-edr"
SERVICE_NAME="t1-edr"
SERVICE_USER="t1edr"
QUARANTINE_DIR="/var/lib/t1-edr/quarantine"

# Parse arguments
SERVER_URL=""
AGENT_TOKEN=""
AGENT_ID=""
AGENT_TAGS=""
AUTO_KILL="false"
AUTO_QUARANTINE="false"

print_banner() {
    echo -e "${GREEN}"
    echo "   _____ _   _____ ____  ____  "
    echo "  |_   _/ | | ____|  _ \|  _ \ "
    echo "    | | | | |  _| | | | | |_) |"
    echo "    | | | | | |___| |_| |  _ < "
    echo "    |_| |_| |_____|____/|_| \_\\"
    echo ""
    echo "  T1 Agentics Linux EDR Agent"
    echo "         Installer v1.0.0"
    echo -e "${NC}"
}

print_error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

print_success() {
    echo -e "${GREEN}[OK] $1${NC}"
}

print_info() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

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
        print_error "Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
}

install_dependencies() {
    print_info "Installing Python dependencies..."

    # Ensure pip is available
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

    # Install required packages
    python3 -m pip install --quiet requests

    # Install psutil for process/network monitoring
    if python3 -m pip install --quiet psutil; then
        print_success "psutil installed (process/network monitoring enabled)"
    else
        print_info "psutil not available (will use /proc fallback)"
    fi

    # Install pyinotify for FIM
    if python3 -m pip install --quiet pyinotify; then
        print_success "pyinotify installed (inotify FIM enabled)"
    else
        print_info "pyinotify not available (will use polling FIM)"
    fi

    print_success "Dependencies installed"
}

create_user() {
    print_info "Creating service user..."

    if id "$SERVICE_USER" &>/dev/null; then
        print_info "User $SERVICE_USER already exists"
    else
        useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
        print_success "Created user $SERVICE_USER"
    fi

    # Add to necessary groups
    usermod -a -G adm "$SERVICE_USER" 2>/dev/null || true
    usermod -a -G systemd-journal "$SERVICE_USER" 2>/dev/null || true
}

install_agent() {
    print_info "Installing EDR agent to $INSTALL_DIR..."

    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$QUARANTINE_DIR"

    # Copy agent script
    cp t1_edr.py "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/t1_edr.py"

    # Create config file
    cat > "$INSTALL_DIR/config.env" << EOF
# T1 EDR Agent Configuration
T1_SERVER_URL=$SERVER_URL
T1_AGENT_TOKEN=${AGENT_TOKEN:-}
T1_AGENT_ID=${AGENT_ID:-$(hostname)}
T1_AGENT_TAGS=${AGENT_TAGS:-}
T1_AUTO_KILL=${AUTO_KILL}
T1_AUTO_QUARANTINE=${AUTO_QUARANTINE}
EOF
    chmod 600 "$INSTALL_DIR/config.env"

    # Set ownership
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"

    print_success "EDR agent installed to $INSTALL_DIR"
}

create_systemd_service() {
    print_info "Creating systemd service..."

    # Build ExecStart command
    EXEC_START="/usr/bin/python3 $INSTALL_DIR/t1_edr.py --server \${T1_SERVER_URL}"

    if [ -n "$AGENT_TOKEN" ]; then
        EXEC_START="$EXEC_START --token \${T1_AGENT_TOKEN}"
    fi

    if [ "$AUTO_KILL" = "true" ]; then
        EXEC_START="$EXEC_START --auto-kill"
    fi

    if [ "$AUTO_QUARANTINE" = "true" ]; then
        EXEC_START="$EXEC_START --auto-quarantine"
    fi

    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=T1 Agentics EDR Agent
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
SyslogIdentifier=t1-edr

# EDR requires elevated privileges for:
# - Process monitoring/killing
# - File quarantine
# - Network blocking (iptables)
# Running as root is necessary for full functionality

# Security hardening (limited for EDR needs)
NoNewPrivileges=false
ProtectHome=read-only
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    print_success "Systemd service created"
}

start_service() {
    print_info "Starting T1 EDR service..."

    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    sleep 3

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "T1 EDR Agent is running"
    else
        print_error "Failed to start service. Check: journalctl -u $SERVICE_NAME"
        exit 1
    fi
}

show_usage() {
    echo "Usage: $0 --server SERVER_URL [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --server, -s        T1 Agentics server URL (required)"
    echo "  --token, -t         Agent authentication token (optional)"
    echo "  --agent-id, -i      Agent ID (defaults to hostname)"
    echo "  --tag               Add a tag (can be used multiple times)"
    echo "  --auto-kill         Enable automatic killing of malicious processes"
    echo "  --auto-quarantine   Enable automatic file quarantine"
    echo "  --help, -h          Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Basic installation (auto-registration)"
    echo "  sudo $0 --server https://t1.example.com:8000"
    echo ""
    echo "  # With auto-response enabled"
    echo "  sudo $0 --server https://t1.example.com:8000 --auto-kill --auto-quarantine"
    echo ""
    echo "  # With pre-configured token"
    echo "  sudo $0 --server https://t1.example.com:8000 --token abc123"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --server|-s)
            SERVER_URL="$2"
            shift 2
            ;;
        --token|-t)
            AGENT_TOKEN="$2"
            shift 2
            ;;
        --agent-id|-i)
            AGENT_ID="$2"
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

# Validate required arguments
if [ -z "$SERVER_URL" ]; then
    print_error "Server URL is required"
    show_usage
    exit 1
fi

# Main installation
print_banner
check_root
check_python
install_dependencies
create_user
install_agent
create_systemd_service
start_service

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}EDR Installation complete!${NC}"
echo ""

if [ -z "$AGENT_TOKEN" ]; then
    echo -e "${CYAN}AUTO-REGISTRATION MODE${NC}"
    echo ""
    echo "The agent will automatically register with the T1 Agentics server."
    echo "Approve the agent in the T1 Agentics UI to activate it."
    echo ""
    echo "To find the agent key:"
    echo "  sudo journalctl -u $SERVICE_NAME | grep 'Agent Key'"
    echo ""
fi

echo "EDR Capabilities:"
echo "  - Process monitoring and response"
echo "  - File integrity monitoring (FIM)"
echo "  - Network connection tracking"
echo "  - IOC matching from server"
echo "  - Asset inventory collection"
if [ "$AUTO_KILL" = "true" ]; then
    echo -e "  - ${RED}Auto-kill malicious processes: ENABLED${NC}"
fi
if [ "$AUTO_QUARANTINE" = "true" ]; then
    echo -e "  - ${RED}Auto-quarantine malicious files: ENABLED${NC}"
fi
echo ""
echo "Useful commands:"
echo "  Check status:     sudo systemctl status $SERVICE_NAME"
echo "  View logs:        sudo journalctl -u $SERVICE_NAME -f"
echo "  Restart:          sudo systemctl restart $SERVICE_NAME"
echo "  Stop:             sudo systemctl stop $SERVICE_NAME"
echo ""
echo "Quarantine location: $QUARANTINE_DIR"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
