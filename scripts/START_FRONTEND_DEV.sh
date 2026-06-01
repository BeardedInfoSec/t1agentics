#!/bin/bash
# Start Frontend in Development Mode
# Live reload enabled, connects to Docker backend

echo "🚀 Starting T1 Agentics Frontend (Development Mode)"
echo "=================================================="
echo ""

# Change to frontend directory
cd "$(dirname "$0")/frontend"

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "📦 Installing dependencies (first time setup)..."
    npm install
    echo ""
fi

# Check if backend is running
echo "🔍 Checking backend status..."
if curl -s http://localhost:8000/api/v1/health > /dev/null 2>&1; then
    echo "✅ Backend is running at http://localhost:8000"
else
    echo "⚠️  WARNING: Backend not responding"
    echo "    Start backend: cd .. && sudo docker compose up -d backend postgres opensearch"
fi

echo ""
echo "🌐 Starting development server..."
echo "   Frontend: http://localhost:3000 (live reload)"
echo "   Backend:  http://localhost:8000"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start dev server
npm start
