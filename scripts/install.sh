#!/bin/bash

# T1 Agentics - Full Installation Script
# This script will install all dependencies and set up the platform automatically

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "╔════════════════════════════════════════╗"
echo "║   T1 Agentics - Auto Installation     ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "This script will:"
echo "  1. Check system requirements"
echo "  2. Install missing dependencies"
echo "  3. Configure Docker access"
echo "  4. Install Python and requirements"
echo "  5. Build and start all services"
echo ""

# Function to detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        VER=$(lsb_release -sr)
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
        VER=$(uname -r)
    fi
    echo "$OS"
}

# Detect OS
OS_TYPE=$(detect_os)
echo "🖥️  Detected OS: $OS_TYPE"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "⚠️  WARNING: Running as root is not recommended"
    echo "   Please run as a normal user"
    echo ""
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# ============================================================================
# 1. SYSTEM REQUIREMENTS CHECK
# ============================================================================
echo "📋 Step 1: Checking system requirements..."
echo ""

# Check RAM
TOTAL_RAM=$(free -m | awk '/^Mem:/{print $2}')
if [ $TOTAL_RAM -lt 8000 ]; then
    echo "⚠️  WARNING: System has less than 8GB RAM ($TOTAL_RAM MB)"
    echo "   Platform may run slowly"
else
    echo "✅ RAM: $TOTAL_RAM MB (sufficient)"
fi

# Check disk space
AVAILABLE_SPACE=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
if [ $AVAILABLE_SPACE -lt 20 ]; then
    echo "⚠️  WARNING: Less than 20GB free disk space ($AVAILABLE_SPACE GB)"
    echo "   Docker images and data require at least 20GB"
else
    echo "✅ Disk space: $AVAILABLE_SPACE GB (sufficient)"
fi

# Check CPU cores
CPU_CORES=$(nproc)
if [ $CPU_CORES -lt 4 ]; then
    echo "⚠️  WARNING: System has less than 4 CPU cores ($CPU_CORES)"
    echo "   Performance may be limited"
else
    echo "✅ CPU cores: $CPU_CORES (sufficient)"
fi

echo ""

# ============================================================================
# 2. DOCKER INSTALLATION
# ============================================================================
echo "📦 Step 2: Checking Docker installation..."
echo ""

if ! command -v docker &> /dev/null; then
    echo "⚠️  Docker is not installed"
    echo ""
    read -p "Install Docker automatically? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "📦 Installing Docker..."

        if [[ "$OS_TYPE" == "ubuntu" ]] || [[ "$OS_TYPE" == "debian" ]]; then
            # Ubuntu/Debian installation
            sudo apt-get update
            sudo apt-get install -y ca-certificates curl gnupg lsb-release

            # Add Docker's official GPG key
            sudo mkdir -p /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$OS_TYPE/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

            # Set up repository
            echo \
              "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS_TYPE \
              $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

            # Install Docker Engine
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

            echo "✅ Docker installed successfully"

        elif [[ "$OS_TYPE" == "fedora" ]] || [[ "$OS_TYPE" == "rhel" ]] || [[ "$OS_TYPE" == "centos" ]]; then
            # Fedora/RHEL/CentOS installation
            sudo dnf -y install dnf-plugins-core
            sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
            sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            sudo systemctl start docker
            sudo systemctl enable docker

            echo "✅ Docker installed successfully"
        else
            echo "❌ Automatic installation not supported for $OS_TYPE"
            echo "   Please install Docker manually: https://docs.docker.com/engine/install/"
            exit 1
        fi
    else
        echo "❌ Docker is required. Please install it manually."
        exit 1
    fi
else
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | sed 's/,//')
    echo "✅ Docker is installed: $DOCKER_VERSION"
fi

echo ""

# ============================================================================
# 3. DOCKER COMPOSE CHECK
# ============================================================================
echo "📦 Step 3: Checking Docker Compose..."
echo ""

if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
    COMPOSE_VERSION=$(docker compose version | awk '{print $4}')
    echo "✅ Docker Compose v2 is installed: $COMPOSE_VERSION"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
    COMPOSE_VERSION=$(docker-compose --version | awk '{print $4}')
    echo "✅ Docker Compose v1 is installed: $COMPOSE_VERSION"
else
    echo "⚠️  Docker Compose is not installed"
    echo ""
    read -p "Install Docker Compose plugin? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [[ "$OS_TYPE" == "ubuntu" ]] || [[ "$OS_TYPE" == "debian" ]]; then
            sudo apt-get update
            sudo apt-get install -y docker-compose-plugin
        elif [[ "$OS_TYPE" == "fedora" ]] || [[ "$OS_TYPE" == "rhel" ]]; then
            sudo dnf install -y docker-compose-plugin
        fi
        DOCKER_COMPOSE="docker compose"
        echo "✅ Docker Compose installed"
    else
        echo "❌ Docker Compose is required"
        exit 1
    fi
fi

echo ""

# ============================================================================
# 4. DOCKER PERMISSIONS
# ============================================================================
echo "🔐 Step 4: Configuring Docker permissions..."
echo ""

if ! docker ps &> /dev/null; then
    echo "⚠️  Current user cannot access Docker daemon"
    echo ""
    read -p "Add $USER to docker group? (requires logout/login) (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo usermod -aG docker $USER
        echo "✅ Added $USER to docker group"
        echo ""
        echo "⚠️  IMPORTANT: You must log out and log back in for this to take effect"
        echo ""
        read -p "Start a new shell session now? (y/n): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "🔄 Starting new shell session..."
            echo "   After the session starts, run this script again: ./install.sh"
            echo ""
            exec sg docker "$0"
            exit 0
        else
            echo "Please log out and log back in, then run: ./install.sh"
            exit 0
        fi
    else
        echo "⚠️  Continuing without Docker group membership"
        echo "   You may need to run docker commands with sudo"
    fi
else
    echo "✅ Docker daemon is accessible"
fi

echo ""

# ============================================================================
# 5. PYTHON INSTALLATION
# ============================================================================
echo "🐍 Step 5: Checking Python installation..."
echo ""

if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

    if [ $PYTHON_MAJOR -eq 3 ] && [ $PYTHON_MINOR -ge 8 ]; then
        echo "✅ Python 3 is installed: $PYTHON_VERSION"
    else
        echo "⚠️  Python $PYTHON_VERSION is too old (need 3.8+)"
        INSTALL_PYTHON=1
    fi
else
    echo "⚠️  Python 3 is not installed"
    INSTALL_PYTHON=1
fi

if [ "${INSTALL_PYTHON:-0}" -eq 1 ]; then
    echo ""
    read -p "Install Python 3? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "📦 Installing Python 3..."
        if [[ "$OS_TYPE" == "ubuntu" ]] || [[ "$OS_TYPE" == "debian" ]]; then
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
        elif [[ "$OS_TYPE" == "fedora" ]] || [[ "$OS_TYPE" == "rhel" ]]; then
            sudo dnf install -y python3 python3-pip
        fi
        echo "✅ Python 3 installed"
    else
        echo "⚠️  Skipping Python installation"
        echo "   Note: Python is optional for Docker-based deployment"
    fi
fi

echo ""

# ============================================================================
# 6. PYTHON REQUIREMENTS (OPTIONAL)
# ============================================================================
if command -v python3 &> /dev/null && [ -f backend/requirements.txt ]; then
    echo "📦 Step 6: Python requirements (optional for local development)"
    echo ""
    read -p "Install Python requirements in virtual environment? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "📦 Setting up Python virtual environment..."

        # Create venv if it doesn't exist
        if [ ! -d venv ]; then
            python3 -m venv venv
        fi

        # Install requirements
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r backend/requirements.txt
        deactivate

        echo "✅ Python requirements installed"
        echo "   Activate with: source venv/bin/activate"
    else
        echo "⏭️  Skipping Python requirements"
    fi
    echo ""
fi

# ============================================================================
# 7. ENVIRONMENT CONFIGURATION
# ============================================================================
echo "⚙️  Step 7: Creating configuration..."
echo ""

if [ ! -f .env ]; then
    cat > .env << 'EOF'
# T1 Agentics Configuration
# Generated by install.sh

# Admin credentials
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@t1agentics.ai

# Database
POSTGRES_PASSWORD=agentcore_dev_password

# JWT
JWT_SECRET_KEY=your-secret-key-change-in-production
JWT_EXPIRE_MINUTES=1440

# Encryption
CREDENTIALS_ENCRYPTION_KEY=zB4xkJPQW7nR9tYwLmN2dVoKjX5gHcE8sA1qF6iU3pM=

# URLs
BASE_URL=http://localhost:8000
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000

# AI Provider
AI_PROVIDER=lm_studio
EOF
    echo "✅ Created .env file with default values"
else
    echo "✅ .env file already exists"
fi

echo ""

# ============================================================================
# 8. BUILD AND START SERVICES
# ============================================================================
echo "🚀 Step 8: Building and starting services..."
echo ""

echo "🔨 Building frontend container (this may take 5-10 minutes)..."
$DOCKER_COMPOSE build --no-cache frontend

echo ""
echo "🔨 Building backend container..."
$DOCKER_COMPOSE build backend

echo ""
echo "🚀 Starting all services..."
$DOCKER_COMPOSE up -d

echo ""
echo "⏳ Waiting for services to initialize (30 seconds)..."
sleep 30

echo ""

# ============================================================================
# 9. HEALTH CHECKS
# ============================================================================
echo "🏥 Step 9: Running health checks..."
echo ""

# PostgreSQL
if docker exec t1agentics-postgres pg_isready -U agentcore &> /dev/null; then
    echo "✅ PostgreSQL: Running"
else
    echo "⚠️  PostgreSQL: Not ready yet (may need more time)"
fi

# Backend
if curl -sf http://localhost:8000/api/v1/health > /dev/null 2>&1; then
    echo "✅ Backend: Running"
else
    echo "⚠️  Backend: Not ready yet (may need more time)"
fi

# Frontend
if curl -sf http://localhost:3000 > /dev/null 2>&1; then
    echo "✅ Frontend: Running"
else
    echo "⚠️  Frontend: Not ready yet (may need more time)"
fi

# OpenSearch
if curl -sku admin:admin https://localhost:9200 > /dev/null 2>&1; then
    echo "✅ OpenSearch: Running"
else
    echo "⚠️  OpenSearch: Not ready yet (may need more time)"
fi

echo ""

# ============================================================================
# 10. COMPLETION
# ============================================================================
echo "╔════════════════════════════════════════╗"
echo "║   Installation Complete! ✅            ║"
echo "╚════════════════════════════════════════╝"
echo ""
echo "🎉 T1 Agentics is running!"
echo ""
echo "📍 Access URLs:"
echo "   Frontend:   http://localhost:3000"
echo "   Backend:    http://localhost:8000"
echo "   API Docs:   http://localhost:8000/docs"
echo "   OpenSearch: https://localhost:9200 (admin/admin)"
echo ""
echo "🔑 Default Login:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "📚 Useful Commands:"
echo "   View logs:     $DOCKER_COMPOSE logs -f"
echo "   Stop:          $DOCKER_COMPOSE down"
echo "   Restart:       $DOCKER_COMPOSE restart <service>"
echo "   Status:        docker ps"
echo ""
echo "⚠️  Production Deployment:"
echo "   - Change default passwords in .env"
echo "   - Generate secure JWT_SECRET_KEY"
echo "   - Configure HTTPS/TLS"
echo "   - Set up backups"
echo ""
echo "📖 Documentation: See QUICK-START.md for more information"
echo ""

# Save installation log
echo "💾 Saving installation log to install.log"
echo "Installation completed at $(date)" >> install.log
echo "OS: $OS_TYPE" >> install.log
echo "Docker: $DOCKER_VERSION" >> install.log
echo "Docker Compose: $COMPOSE_VERSION" >> install.log
if command -v python3 &> /dev/null; then
    echo "Python: $(python3 --version)" >> install.log
fi
echo "" >> install.log

echo "✅ Installation log saved"
echo ""
