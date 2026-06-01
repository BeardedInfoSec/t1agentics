#!/bin/bash
# T1 Agentics - One-Command Quick Start
# Target: 60 seconds to "wow moment"

set -e

echo "🚀 T1 Agentics - Quick Start Deployment"
echo "========================================"
echo ""
echo "This will:"
echo "  1. Start all services (PostgreSQL, OpenSearch, Backend, Frontend)"
echo "  2. Wait for health checks"
echo "  3. Seed demo data (20 alerts, 5 investigations, 100 IOCs)"
echo "  4. Open browser to dashboard"
echo ""
read -p "Continue? (y/n) " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Change to project root
cd "$(dirname "$0")/.."

echo ""
echo "📦 Step 1/4: Starting containers..."
docker-compose up -d

echo ""
echo "⏳ Step 2/4: Waiting for services to be healthy (30s)..."
sleep 30

# Check backend health
echo "   Checking backend..."
until curl -s http://localhost:8000/api/v1/health > /dev/null 2>&1; do
    echo "   Waiting for backend..."
    sleep 5
done
echo "   ✓ Backend ready"

echo ""
echo "🌱 Step 3/4: Seeding demo data..."
python3 scripts/seed-demo-data.py --clean

echo ""
echo "🌐 Step 4/4: Opening browser..."

# Detect OS and open browser
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    xdg-open http://localhost:3000 2>/dev/null || echo "   ℹ️  Please open http://localhost:3000 manually"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    open http://localhost:3000
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    start http://localhost:3000
else
    echo "   ℹ️  Please open http://localhost:3000 manually"
fi

echo ""
echo "✅ T1 Agentics is ready!"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 QUICK START"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🌐 Frontend:     http://localhost:3000"
echo "🔧 Backend API:  http://localhost:8000/docs"
echo "📊 OpenSearch:   http://localhost:5601"
echo ""
echo "👤 Login:"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "📋 Demo Data:"
echo "   • 20 diverse security alerts"
echo "   • 5 sample investigations"
echo "   • 100 threat IOCs"
echo ""
echo "🎯 Try This:"
echo "   1. View alerts on dashboard"
echo "   2. Click any alert to investigate"
echo "   3. Run fast triage on an alert"
echo "   4. Escalate to Riggs for deep analysis"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📚 Docs:         ./docs/"
echo "🛠️  Logs:         docker-compose logs -f backend"
echo "🧹 Cleanup:      docker-compose down -v"
echo ""
