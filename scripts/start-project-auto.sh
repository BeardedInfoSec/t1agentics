#!/bin/bash

# T1 Agentics - Automated Startup Script (No Prompts)
# This script will automatically start all services without asking questions

set -e

echo "================================"
echo "T1 Agentics - Auto Startup"
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
    echo "Run this first: newgrp docker"
    echo "Or log out and log back in after running: sudo usermod -aG docker $USER"
    echo ""
    exit 1
fi

echo "✅ Docker daemon is accessible"
echo ""

# Check Python installation
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo "✅ Python 3 is installed: $PYTHON_VERSION"
else
    echo "⚠️  Python 3 is not installed - some features may not work"
fi

echo ""

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file with default configuration..."
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
    echo "✅ Created .env file"
else
    echo "✅ .env file already exists"
fi

echo ""
echo "🔨 Rebuilding frontend container (npm build)..."
$DOCKER_COMPOSE build --no-cache frontend

echo ""
echo "🔄 Starting Docker containers..."
$DOCKER_COMPOSE up -d

echo ""
echo "⏳ Waiting for services to initialize..."
sleep 15

echo ""
echo "================================"
echo "✅ T1 Agentics is running!"
echo "================================"
echo ""
echo "Access the platform:"
echo "  Frontend:  http://localhost:3000"
echo "  Backend:   http://localhost:8000"
echo "  API Docs:  http://localhost:8000/docs"
echo ""
echo "Default login:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "View logs:"
echo "  $DOCKER_COMPOSE logs -f"
echo ""
