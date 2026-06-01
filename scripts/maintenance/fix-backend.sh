#!/bin/bash

# Backend Troubleshooting and Fix Script

echo "========================================"
echo "T1 Agentics - Backend Fix Script"
echo "========================================"
echo ""

# Determine if we need sudo
if ! docker ps &> /dev/null; then
    echo "⚠️  Cannot access Docker without sudo"
    echo "   Using sudo for Docker commands..."
    echo ""
    USE_SUDO="sudo"
    DOCKER_COMPOSE="sudo docker compose"
else
    USE_SUDO=""
    if command -v docker &> /dev/null && docker compose version &> /dev/null; then
        DOCKER_COMPOSE="docker compose"
    else
        DOCKER_COMPOSE="docker-compose"
    fi
fi

echo "Step 1: Checking backend container status..."
echo "----------------------------------------"
BACKEND_STATUS=$($USE_SUDO docker ps -a | grep t1agentics-backend | awk '{print $7}')
echo "Backend status: $BACKEND_STATUS"
echo ""

if [ -z "$BACKEND_STATUS" ]; then
    echo "❌ Backend container does not exist!"
    echo "   Running docker compose up to create it..."
    $DOCKER_COMPOSE up -d backend
    sleep 5
fi

echo "Step 2: Checking backend logs for errors..."
echo "----------------------------------------"
echo "Last 30 lines of backend logs:"
$USE_SUDO docker logs t1agentics-backend --tail 30
echo ""

echo "Step 3: Checking PostgreSQL connection..."
echo "----------------------------------------"
if $USE_SUDO docker exec t1agentics-postgres pg_isready -U agentcore &> /dev/null; then
    echo "✅ PostgreSQL is ready"
else
    echo "❌ PostgreSQL is not ready - backend needs this to start!"
    echo "   Restarting PostgreSQL..."
    $DOCKER_COMPOSE restart postgres
    sleep 10
fi
echo ""

echo "Step 4: Checking .env file..."
echo "----------------------------------------"
if [ -f .env ]; then
    echo "✅ .env file exists"
    echo "Checking required variables..."
    for var in ADMIN_USERNAME ADMIN_PASSWORD POSTGRES_PASSWORD JWT_SECRET_KEY; do
        if grep -q "^$var=" .env; then
            echo "  ✅ $var is set"
        else
            echo "  ❌ $var is missing!"
        fi
    done
else
    echo "❌ .env file is missing!"
    echo "   Creating default .env file..."
    cat > .env << 'EOF'
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin123
ADMIN_EMAIL=admin@t1agentics.ai
POSTGRES_PASSWORD=agentcore_dev_password
JWT_SECRET_KEY=your-secret-key-change-in-production
JWT_EXPIRE_MINUTES=1440
CREDENTIALS_ENCRYPTION_KEY=zB4xkJPQW7nR9tYwLmN2dVoKjX5gHcE8sA1qF6iU3pM=
BASE_URL=http://localhost:8000
AI_PROVIDER=lm_studio
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8000
EOF
    echo "   ✅ Created .env file"
fi
echo ""

echo "Step 5: Restarting backend container..."
echo "----------------------------------------"
$DOCKER_COMPOSE restart backend
echo "Waiting 15 seconds for backend to start..."
sleep 15
echo ""

echo "Step 6: Checking backend health..."
echo "----------------------------------------"
HEALTH_CHECK=$(curl -s http://localhost:8000/api/v1/health 2>&1)
if [ $? -eq 0 ]; then
    echo "✅ Backend is responding!"
    echo "   Response: $HEALTH_CHECK"
else
    echo "❌ Backend is still not responding"
    echo "   Error: $HEALTH_CHECK"
    echo ""
    echo "📋 Recent backend logs:"
    $USE_SUDO docker logs t1agentics-backend --tail 50
fi
echo ""

echo "Step 7: Checking all services..."
echo "----------------------------------------"
echo "Container status:"
$USE_SUDO docker ps | grep -E "NAMES|t1agentics"
echo ""

echo "========================================"
echo "Troubleshooting Complete"
echo "========================================"
echo ""
echo "Try accessing the platform now:"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8000"
echo "  Login:    admin / admin123"
echo ""
echo "If backend is still not working, check logs:"
echo "  $DOCKER_COMPOSE logs -f backend"
echo ""
