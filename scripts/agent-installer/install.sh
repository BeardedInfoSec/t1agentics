#!/bin/bash
# =============================================================================
# T1 Agentics Linux Agent Installer
# =============================================================================
# Installs the T1 log collection agent as a systemd service
#
# Usage (auto-registration - recommended for golden images/deployment scripts):
#   sudo ./install.sh --server https://your-server:8000
#
# Usage (with pre-configured token):
#   sudo ./install.sh --server https://your-server:8000 --token YOUR_TOKEN
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Defaults
INSTALL_DIR="/opt/t1-agent"
DATA_DIR="/var/lib/t1-agent"
SERVICE_NAME="t1-agent"
SERVICE_USER="t1agent"
PYTHON_MIN_VERSION="3.8"

# Parse arguments
SERVER_URL=""
AGENT_TOKEN=""
AGENT_ID=""
AGENT_TAGS=""

print_banner() {
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           T1 Agentics Linux Log Collection Agent              ║"
    echo "║                     Installer v1.0.0                          ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
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

        # Check minimum version
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

    # Try to install systemd-python (optional)
    if python3 -m pip install --quiet systemd-python 2>/dev/null; then
        print_success "systemd-python installed (journald collection enabled)"
    else
        print_info "systemd-python not available (will use file-based collection)"
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

    # Add to necessary groups for log access
    usermod -a -G adm "$SERVICE_USER" 2>/dev/null || true
    usermod -a -G systemd-journal "$SERVICE_USER" 2>/dev/null || true
}

install_agent() {
    print_info "Installing agent to $INSTALL_DIR..."

    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"

    # Copy agent script
    cp t1_agent.py "$INSTALL_DIR/"
    chmod 755 "$INSTALL_DIR/t1_agent.py"

    # Create config file
    cat > "$INSTALL_DIR/config.env" << EOF
# T1 Agent Configuration
T1_SERVER_URL=$SERVER_URL
T1_AGENT_TOKEN=${AGENT_TOKEN:-}
T1_AGENT_ID=${AGENT_ID:-$(hostname)}
T1_AGENT_TAGS=${AGENT_TAGS:-}
T1_BATCH_SIZE=50
T1_FLUSH_INTERVAL=10
EOF
    chmod 600 "$INSTALL_DIR/config.env"

    # Set ownership
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"

    print_success "Agent installed to $INSTALL_DIR"
}

create_systemd_service() {
    print_info "Creating systemd service..."

    # Build ExecStart command based on whether token is provided
    if [ -n "$AGENT_TOKEN" ]; then
        EXEC_START="/usr/bin/python3 $INSTALL_DIR/t1_agent.py \\
    --server \${T1_SERVER_URL} \\
    --token \${T1_AGENT_TOKEN} \\
    --agent-id \${T1_AGENT_ID} \\
    --batch-size \${T1_BATCH_SIZE:-50} \\
    --flush-interval \${T1_FLUSH_INTERVAL:-10}"
    else
        EXEC_START="/usr/bin/python3 $INSTALL_DIR/t1_agent.py \\
    --server \${T1_SERVER_URL} \\
    --agent-id \${T1_AGENT_ID} \\
    --batch-size \${T1_BATCH_SIZE:-50} \\
    --flush-interval \${T1_FLUSH_INTERVAL:-10}"
    fi

    cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=T1 Agentics Log Collection Agent
Documentation=https://github.com/your-org/t1-agentics
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
EnvironmentFile=$INSTALL_DIR/config.env
ExecStart=$EXEC_START
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=t1-agent

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/
ReadWritePaths=/var/log $DATA_DIR

# Allow reading log files
CapabilityBoundingSet=CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    print_success "Systemd service created"
}

start_service() {
    print_info "Starting T1 Agent service..."

    systemctl enable "$SERVICE_NAME"
    systemctl start "$SERVICE_NAME"

    # Wait a moment and check status
    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "T1 Agent is running"
    else
        print_error "Failed to start service. Check: journalctl -u $SERVICE_NAME"
        exit 1
    fi
}

show_usage() {
    echo "Usage: $0 --server SERVER_URL [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --server, -s    T1 Agentics server URL (required)"
    echo "  --token, -t     Agent authentication token (optional - will auto-register if not provided)"
    echo "  --agent-id, -i  Agent ID (defaults to hostname)"
    echo "  --tag           Add a tag to the agent (can be used multiple times)"
    echo "  --help, -h      Show this help message"
    echo ""
    echo "Examples:"
    echo "  # Auto-registration (recommended for golden images)"
    echo "  sudo $0 --server https://t1.example.com:8000"
    echo ""
    echo "  # With tags"
    echo "  sudo $0 --server https://t1.example.com:8000 --tag production --tag webserver"
    echo ""
    echo "  # With pre-configured token"
    echo "  sudo $0 --server https://t1.example.com:8000 --token abc123xyz"
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
echo -e "${GREEN}Installation complete!${NC}"
echo ""

if [ -z "$AGENT_TOKEN" ]; then
    echo -e "${CYAN}AUTO-REGISTRATION MODE${NC}"
    echo ""
    echo "The agent will automatically register with the T1 Agentics server."
    echo "You need to approve the agent in the T1 Agentics UI before it can send logs."
    echo ""
    echo "To find the agent key, check the logs:"
    echo "  sudo journalctl -u $SERVICE_NAME | grep 'Agent Key'"
    echo ""
fi

echo "Useful commands:"
echo "  Check status:     sudo systemctl status $SERVICE_NAME"
echo "  View logs:        sudo journalctl -u $SERVICE_NAME -f"
echo "  Restart:          sudo systemctl restart $SERVICE_NAME"
echo "  Stop:             sudo systemctl stop $SERVICE_NAME"
echo "  Uninstall:        sudo systemctl stop $SERVICE_NAME && sudo rm -rf $INSTALL_DIR $DATA_DIR /etc/systemd/system/${SERVICE_NAME}.service"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
