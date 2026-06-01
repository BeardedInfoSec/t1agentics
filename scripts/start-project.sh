#!/bin/bash

# T1 Agentics - Startup Script
# This script will check dependencies, install requirements, and start all services

set -e

echo "================================"
echo "T1 Agentics - Startup Script"
echo "================================"
echo ""

# Determine docker-compose command (new vs old)
if command -v docker &> /dev/null && docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
    echo "✅ Using 'docker compose' (Docker Compose v2)"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
    echo "✅ Using 'docker-compose' (Docker Compose v1)"
else
    echo "❌ ERROR: Docker Compose is not installed"
    echo ""
    echo "Please install Docker Compose:"
    echo "  Ubuntu/Debian: sudo apt-get install docker-compose-plugin"
    echo "  Or visit: https://docs.docker.com/compose/install/"
    echo ""
    exit 1
fi

echo ""

# Check if docker is accessible
if ! docker ps &> /dev/null; then
    echo "❌ ERROR: Cannot access Docker daemon"
    echo ""
    echo "You need to add yourself to the docker group:"
    echo "  sudo usermod -aG docker $USER"
    echo ""
    echo "Then log out and log back in, or run:"
    echo "  newgrp docker"
    echo ""
    exit 1
fi

echo "✅ Docker daemon is accessible"
echo ""

# Check Python installation
echo "🐍 Checking Python installation..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo "✅ Python 3 is installed: $PYTHON_VERSION"
else
    echo "⚠️  Python 3 is not installed"
    echo ""
    read -p "Would you like to install Python 3? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "📦 Installing Python 3..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y python3 python3-pip python3-venv
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3 python3-pip
        elif command -v brew &> /dev/null; then
            brew install python3
        else
            echo "❌ Could not detect package manager. Please install Python 3 manually."
            exit 1
        fi
        echo "✅ Python 3 installed successfully"
    else
        echo "⚠️  Skipping Python installation. Note: Some features may not work."
    fi
fi

echo ""

# Check pip installation
if command -v pip3 &> /dev/null || command -v pip &> /dev/null; then
    echo "✅ pip is installed"
else
    echo "⚠️  pip is not installed"
    echo "📦 Installing pip..."
    if command -v apt-get &> /dev/null; then
        sudo apt-get install -y python3-pip
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3-pip
    else
        echo "❌ Could not install pip. Please install manually."
        exit 1
    fi
fi

echo ""

# Install Python requirements (optional - for local development)
if [ -f backend/requirements.txt ]; then
    echo "📦 Python requirements found. Do you want to install them locally?"
    echo "   (This is optional - Docker containers have their own dependencies)"
    echo ""
    read -p "Install Python requirements for local development? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "📦 Installing Python requirements..."

        # Create virtual environment if it doesn't exist
        if [ ! -d venv ]; then
            echo "🔧 Creating virtual environment..."
            python3 -m venv venv
        fi

        # Activate virtual environment and install requirements
        echo "🔧 Installing dependencies in virtual environment..."
        source venv/bin/activate
        pip install --upgrade pip
        pip install -r backend/requirements.txt
        deactivate

        echo "✅ Python requirements installed in virtual environment"
        echo "   Activate with: source venv/bin/activate"
    else
        echo "⏭️  Skipping local Python requirements installation"
    fi
fi

echo ""

# Check if .env file exists
if [ ! -f .env ]; then
    echo "⚠️  No .env file found. Creating default configuration..."
    cat > .env << 'EOF'
# Admin credentials (REQUIRED - change these!)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@t1agentics.ai

# Database password
POSTGRES_PASSWORD=agentcore_dev_password

# JWT secret (change in production!)
JWT_SECRET_KEY=your-secret-key-change-in-production
JWT_EXPIRE_MINUTES=1440

# Credentials encryption key (change in production!)
CREDENTIALS_ENCRYPTION_KEY=zB4xkJPQW7nR9tYwLmN2dVoKjX5gHcE8sA1qF6iU3pM=

# Base URL
BASE_URL=http://localhost:8000

# AI Provider (vllm, lm_studio, or anthropic)
AI_PROVIDER=lm_studio

# Allowed origins for CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000
EOF
    echo "✅ Created .env file with default values"
    echo ""
else
    echo "✅ .env file already exists"
    echo ""
fi

# Ask about rebuilding frontend
echo "🔨 Frontend Container Build"
echo "   The frontend needs to be built with npm before starting."
echo ""
read -p "Rebuild frontend container? (recommended on first run) (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🔨 Rebuilding frontend container (npm build)..."
    $DOCKER_COMPOSE build --no-cache frontend
    echo "✅ Frontend container rebuilt"
else
    echo "⏭️  Skipping frontend rebuild"
fi

echo ""
echo "🔄 Starting Docker containers..."
$DOCKER_COMPOSE up -d

echo ""
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check service status
echo ""
echo "📊 Service Status:"
echo "================================"

# Check PostgreSQL
if docker exec t1agentics-postgres pg_isready -U agentcore &> /dev/null; then
    echo "✅ PostgreSQL: Running"
else
    echo "❌ PostgreSQL: Not ready"
fi

# Check Backend
if curl -sf http://localhost:8000/api/v1/health > /dev/null 2>&1; then
    echo "✅ Backend: Running"
else
    echo "⚠️  Backend: Starting (may take 30-60 seconds)"
fi

# Check Frontend
if curl -sf http://localhost:3000 > /dev/null 2>&1; then
    echo "✅ Frontend: Running"
else
    echo "⚠️  Frontend: Starting (may take 30-60 seconds)"
fi

# Check OpenSearch
if curl -sku admin:admin https://localhost:9200 > /dev/null 2>&1; then
    echo "✅ OpenSearch: Running"
else
    echo "⚠️  OpenSearch: Starting (may take 60-90 seconds)"
fi

# Check vLLM (optional)
if docker ps | grep -q t1agentics-vllm; then
    if curl -sf http://localhost:8001/health > /dev/null 2>&1; then
        echo "✅ vLLM: Running"
    else
        echo "⚠️  vLLM: Starting (may take 2-5 minutes - downloads model)"
    fi
else
    echo "ℹ️  vLLM: Not started (optional - requires GPU)"
fi

echo ""
echo "================================"
echo "✅ T1 Agentics is starting up!"
echo "================================"
echo ""
echo "Access the platform:"
echo "  Frontend:  http://localhost:3000"
echo "  Backend:   http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo "  OpenSearch: https://localhost:9200"
echo ""
echo "Default login:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "Useful commands:"
echo "  View logs:        $DOCKER_COMPOSE logs -f"
echo "  Stop services:    $DOCKER_COMPOSE down"
echo "  Restart service:  $DOCKER_COMPOSE restart <service>"
echo "  Check status:     docker ps"
echo ""
echo "If services aren't ready yet, wait 1-2 minutes and check again"
echo ""
