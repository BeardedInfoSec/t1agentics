#!/bin/bash
# =============================================================================
# T1 Log Collector Installer
# =============================================================================
# Installs the T1 unified agent to ~/opt/t1_log_collector
#
# Usage:
#   ./install_t1_collector.sh --server https://your-server:8000
#   ./install_t1_collector.sh --server https://your-server:8000 --mode full
#
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Installation paths - Uses /opt/t1_log_collector (system-wide)
INSTALL_DIR="/opt/t1_log_collector"
DATA_DIR="/opt/t1_log_collector/data"
QUARANTINE_DIR="/opt/t1_log_collector/quarantine"
LOG_DIR="/opt/t1_log_collector/logs"
VENV_DIR="/opt/t1_log_collector/venv"
SERVICE_NAME="t1-collector"

# Arguments
SERVER_URL=""
AGENT_TOKEN=""
AGENT_MODE="log-collector"
AGENT_TAGS=""
AUTO_KILL="false"
AUTO_QUARANTINE="false"
RUN_AS_SERVICE="false"

print_banner() {
    echo -e "${GREEN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║            T1 Log Collector Installer                         ║"
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

install_python() {
    print_info "Python 3 not found. Attempting to install..."

    if command -v apt-get &> /dev/null; then
        print_info "Detected Debian/Ubuntu system"
        sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip
    elif command -v dnf &> /dev/null; then
        print_info "Detected Fedora/RHEL system"
        sudo dnf install -y python3 python3-pip
    elif command -v yum &> /dev/null; then
        print_info "Detected CentOS/RHEL system"
        sudo yum install -y python3 python3-pip
    elif command -v pacman &> /dev/null; then
        print_info "Detected Arch system"
        sudo pacman -S --noconfirm python python-pip
    elif command -v zypper &> /dev/null; then
        print_info "Detected openSUSE system"
        sudo zypper install -y python3 python3-pip
    else
        print_error "Could not detect package manager. Please install Python 3.8+ manually."
        exit 1
    fi

    # Verify installation
    if ! command -v python3 &> /dev/null; then
        print_error "Python installation failed"
        exit 1
    fi
    print_success "Python installed successfully"
}

check_python() {
    print_info "Checking Python version..."

    if ! command -v python3 &> /dev/null; then
        install_python
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    print_success "Python $PYTHON_VERSION found"

    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
        # Also ensure venv module is available
        if ! python3 -m venv --help &> /dev/null; then
            print_info "Installing python3-venv..."
            if command -v apt-get &> /dev/null; then
                sudo apt-get install -y python3-venv
            fi
        fi
        return 0
    else
        print_error "Python 3.8 or higher required (found $PYTHON_VERSION)"
        exit 1
    fi
}

install_dependencies() {
    print_info "Setting up Python virtual environment..."

    # Create virtual environment
    if [ ! -d "$VENV_DIR" ]; then
        python3 -m venv "$VENV_DIR"
        print_success "Virtual environment created at $VENV_DIR"
    else
        print_info "Virtual environment already exists"
    fi

    # Activate venv and install dependencies
    source "$VENV_DIR/bin/activate"

    print_info "Installing Python dependencies in venv..."

    # Upgrade pip first
    pip install --quiet --upgrade pip 2>/dev/null || true

    # Core dependency
    pip install --quiet requests
    print_success "requests installed"

    # Optional but recommended
    if pip install --quiet psutil 2>/dev/null; then
        print_success "psutil installed (process/network monitoring)"
    else
        print_info "psutil not available"
    fi

    if pip install --quiet pyinotify 2>/dev/null; then
        print_success "pyinotify installed (inotify FIM)"
    else
        print_info "pyinotify not available (polling FIM)"
    fi

    if pip install --quiet systemd-python 2>/dev/null; then
        print_success "systemd-python installed (journald)"
    else
        print_info "systemd-python not available"
    fi

    deactivate
}

install_agent() {
    print_info "Installing agent to $INSTALL_DIR..."

    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$QUARANTINE_DIR"
    mkdir -p "$LOG_DIR"

    # Copy agent - check if we're running from the same directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [ -f "$SCRIPT_DIR/t1_unified_agent.py" ]; then
        cp "$SCRIPT_DIR/t1_unified_agent.py" "$INSTALL_DIR/"
    elif [ -f "t1_unified_agent.py" ]; then
        cp "t1_unified_agent.py" "$INSTALL_DIR/"
    else
        print_error "t1_unified_agent.py not found!"
        exit 1
    fi

    chmod 755 "$INSTALL_DIR/t1_unified_agent.py"

    # Create config
    cat > "$INSTALL_DIR/config.env" << EOF
# T1 Log Collector Configuration
T1_SERVER_URL=$SERVER_URL
T1_AGENT_TOKEN=${AGENT_TOKEN:-}
T1_AGENT_MODE=$AGENT_MODE
T1_AGENT_TAGS=${AGENT_TAGS:-}
T1_AUTO_KILL=$AUTO_KILL
T1_AUTO_QUARANTINE=$AUTO_QUARANTINE
T1_DATA_DIR=$DATA_DIR
T1_QUARANTINE_DIR=$QUARANTINE_DIR
T1_LOG_DIR=$LOG_DIR
EOF
    chmod 600 "$INSTALL_DIR/config.env"

    # Create run script (uses venv Python)
    # Note: Using single quotes in heredoc delimiter to prevent variable expansion
    cat > "$INSTALL_DIR/run.sh" << RUNEOF
#!/bin/bash
# T1 Log Collector Runner with Update Support
# This script runs the agent in a loop, automatically restarting after updates

INSTALL_DIR="$INSTALL_DIR"
VENV_PYTHON="$VENV_DIR/bin/python3"
RESTART_FLAG="\$INSTALL_DIR/.update_restart"

cd "\$INSTALL_DIR"
source "\$INSTALL_DIR/config.env"

# Export paths for Python to use
export T1_DATA_DIR
export T1_QUARANTINE_DIR

# Build arguments
ARGS="--server \$T1_SERVER_URL --mode \$T1_AGENT_MODE"

if [ -n "\$T1_AGENT_TOKEN" ]; then
    ARGS="\$ARGS --token \$T1_AGENT_TOKEN"
fi

if [ "\$T1_AUTO_KILL" = "true" ]; then
    ARGS="\$ARGS --auto-kill"
fi

if [ "\$T1_AUTO_QUARANTINE" = "true" ]; then
    ARGS="\$ARGS --auto-quarantine"
fi

# Run agent in a loop for update support
while true; do
    echo "[T1] Starting T1 Log Collector..."
    echo "[T1] Command: \$VENV_PYTHON \$INSTALL_DIR/t1_unified_agent.py \$ARGS"

    # Run the agent
    \$VENV_PYTHON "\$INSTALL_DIR/t1_unified_agent.py" \$ARGS
    EXIT_CODE=\$?

    # Check if restart was requested for update
    if [ -f "\$RESTART_FLAG" ]; then
        echo "[T1] Update restart requested"
        rm -f "\$RESTART_FLAG"
        sleep 2
        continue  # Restart the agent
    fi

    # Normal exit (code 0) - stop the loop
    if [ \$EXIT_CODE -eq 0 ]; then
        echo "[T1] Agent exited normally"
        break
    fi

    # Error exit - wait and retry
    echo "[T1] Agent exited with code \$EXIT_CODE, restarting in 30s..."
    sleep 30
done

echo "[T1] Run script exiting"
RUNEOF
    chmod 755 "$INSTALL_DIR/run.sh"

    # Create stop script
    cat > "$INSTALL_DIR/stop.sh" << EOF
#!/bin/bash
# Stop T1 Log Collector
pkill -f "t1_unified_agent.py" 2>/dev/null || true
echo "T1 Log Collector stopped"
EOF
    chmod 755 "$INSTALL_DIR/stop.sh"

    # Create status script
    cat > "$INSTALL_DIR/status.sh" << EOF
#!/bin/bash
# Check T1 Log Collector status
if pgrep -f "t1_unified_agent.py" > /dev/null; then
    echo "T1 Log Collector is running (PID: \$(pgrep -f 't1_unified_agent.py'))"
    exit 0
else
    echo "T1 Log Collector is not running"
    exit 1
fi
EOF
    chmod 755 "$INSTALL_DIR/status.sh"

    print_success "Agent installed to $INSTALL_DIR"
}

create_systemd_service() {
    print_info "Creating systemd service..."

    # Create system-wide systemd service (requires root)
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

    # Reload systemd daemon
    systemctl daemon-reload

    print_success "Systemd service created at /etc/systemd/system/${SERVICE_NAME}.service"
}

start_service() {
    print_info "Starting T1 Log Collector..."

    # Enable service for auto-start on boot
    systemctl enable "$SERVICE_NAME"
    print_success "Service enabled for auto-start on boot"

    # Start the service
    systemctl start "$SERVICE_NAME"

    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "T1 Log Collector is running as systemd service"
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
    echo "  --mode, -m          Agent mode: full, edr, log-collector (default: log-collector)"
    echo "  --token, -t         Agent token (optional - auto-registers if not provided)"
    echo "  --tag               Add tag (can use multiple times)"
    echo "  --auto-kill         Enable auto-kill of IOC processes (EDR/full modes)"
    echo "  --auto-quarantine   Enable auto-quarantine of IOC files (EDR/full modes)"
    echo "  --service           Run as systemd user service"
    echo "  --help, -h          Show this help"
    echo ""
    echo "Modes:"
    echo "  log-collector  Logs only: lightweight log forwarding (default)"
    echo "  edr            EDR only: process/file/network monitoring + response"
    echo "  full           Everything: logs + EDR + inventory"
    echo ""
    echo "Examples:"
    echo "  # Log collector (default)"
    echo "  $0 --server https://t1.example.com:8000"
    echo ""
    echo "  # Full agent with auto-response"
    echo "  $0 --server https://t1.example.com:8000 --mode full --auto-kill"
    echo ""
    echo "Installation directory: ~/opt/t1_log_collector"
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
        --service)
            RUN_AS_SERVICE="true"
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
echo -e "Install directory: ${CYAN}$INSTALL_DIR${NC}"
echo -e "Mode: ${CYAN}$AGENT_MODE${NC}"
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
fi
echo ""
echo "Service: ${SERVICE_NAME} (auto-starts on boot)"
echo ""
echo "Commands:"
echo "  Status:     systemctl status $SERVICE_NAME"
echo "  Start:      systemctl start $SERVICE_NAME"
echo "  Stop:       systemctl stop $SERVICE_NAME"
echo "  Restart:    systemctl restart $SERVICE_NAME"
echo "  Logs:       journalctl -u $SERVICE_NAME -f"
echo "  Config:     $INSTALL_DIR/config.env"
echo ""
echo "Uninstall:"
echo "  systemctl stop $SERVICE_NAME && systemctl disable $SERVICE_NAME"
echo "  rm /etc/systemd/system/${SERVICE_NAME}.service && systemctl daemon-reload"
echo "  rm -rf $INSTALL_DIR"
echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
