#!/bin/bash

echo "========================================"
echo "T1 Agentics - Database Fix Script"
echo "========================================"
echo ""

# Determine if we need sudo
if ! docker ps &> /dev/null; then
    USE_SUDO="sudo"
else
    USE_SUDO=""
fi

echo "Step 1: Stopping backend to prevent connection issues..."
$USE_SUDO docker compose stop backend
sleep 2

echo ""
echo "Step 2: Dropping and recreating database..."
$USE_SUDO docker exec t1agentics-postgres psql -U agentcore -c "DROP DATABASE IF EXISTS agentcore;"
$USE_SUDO docker exec t1agentics-postgres psql -U agentcore -c "CREATE DATABASE agentcore;"

echo ""
echo "Step 3: Running init-db.sql to create schema..."
$USE_SUDO docker exec -i t1agentics-postgres psql -U agentcore -d agentcore < backend/init-db.sql

echo ""
echo "Step 4: Verifying critical tables exist..."
TABLES="users alerts investigations webhooks iocs threat_feeds job_queue"
for table in $TABLES; do
    if $USE_SUDO docker exec t1agentics-postgres psql -U agentcore -d agentcore -tc "SELECT 1 FROM pg_tables WHERE tablename='$table'" | grep -q 1; then
        echo "  ✅ $table exists"
    else
        echo "  ❌ $table is missing!"
    fi
done

echo ""
echo "Step 5: Verifying claim_job function exists..."
if $USE_SUDO docker exec t1agentics-postgres psql -U agentcore -d agentcore -tc "SELECT 1 FROM pg_proc WHERE proname='claim_job'" | grep -q 1; then
    echo "  ✅ claim_job function exists"
else
    echo "  ❌ claim_job function is missing!"
fi

echo ""
echo "Step 6: Restarting backend..."
$USE_SUDO docker compose start backend
sleep 10

echo ""
echo "Step 7: Testing backend health..."
if curl -s http://localhost:8000/api/v1/health | grep -q "healthy"; then
    echo "  ✅ Backend is healthy"
else
    echo "  ❌ Backend is not responding"
fi

echo ""
echo "========================================"
echo "Database fix complete!"
echo "========================================"
echo ""
echo "You can now try creating webhooks and using the vLLM Mesh UI."
echo ""
