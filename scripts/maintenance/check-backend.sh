#!/bin/bash

# Backend Diagnostics Script

echo "========================================"
echo "T1 Agentics - Backend Diagnostics"
echo "========================================"
echo ""

# Check if we can access docker
if ! docker ps &> /dev/null; then
    echo "⚠️  Running with sudo to check Docker containers..."
    echo ""
    USE_SUDO="sudo"
else
    USE_SUDO=""
fi

echo "📊 Container Status:"
echo "----------------------------------------"
$USE_SUDO docker ps -a | grep -E "CONTAINER|t1agentics-backend|t1agentics-postgres"
echo ""

echo "📊 Backend Container Logs (last 100 lines):"
echo "----------------------------------------"
$USE_SUDO docker logs t1agentics-backend --tail 100
echo ""

echo "📊 PostgreSQL Container Status:"
echo "----------------------------------------"
$USE_SUDO docker exec t1agentics-postgres pg_isready -U agentcore
echo ""

echo "📊 Network Connectivity:"
echo "----------------------------------------"
echo "Checking if backend is listening on port 8000..."
ss -tlnp | grep 8000 || echo "Port 8000 is not listening"
echo ""

echo "📊 Environment Variables:"
echo "----------------------------------------"
$USE_SUDO docker exec t1agentics-backend env | grep -E "POSTGRES|JWT|ADMIN"
echo ""

echo "========================================"
echo "Diagnostic check complete"
echo "========================================"
