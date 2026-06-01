#!/bin/bash
# Database Rebuild Script
# Use this to reset PostgreSQL and start fresh

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║         T1 Agentics Database Rebuild Script                   ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "⚠️  WARNING: This will DELETE all data in PostgreSQL!"
echo ""
read -p "Are you sure you want to continue? (yes/N): " -r
echo
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]
then
    echo "❌ Aborted"
    exit 1
fi

echo ""
echo "🔄 Starting database rebuild process..."
echo ""

# Stop containers
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1️⃣  Stopping containers..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker-compose down

# Remove PostgreSQL volume (this deletes all data!)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2️⃣  Removing PostgreSQL volume..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker volume rm source_postgres-data 2>/dev/null && echo "   ✓ PostgreSQL volume removed" || echo "   ℹ Volume already removed"

# Optional: Remove MongoDB volume too
echo ""
read -p "Do you want to also reset MongoDB? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    echo "   Removing MongoDB volume..."
    docker volume rm source_mongodb-data 2>/dev/null && echo "   ✓ MongoDB volume removed" || echo "   ℹ Volume already removed"
fi

# Rebuild backend (includes database schema)
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3️⃣  Rebuilding backend container (no cache)..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker-compose build --no-cache backend

# Start all services
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4️⃣  Starting all services..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker-compose up -d

# Wait for services to initialize
echo ""
echo "⏳ Waiting for services to initialize (30 seconds)..."
for i in {1..30}; do
    echo -n "."
    sleep 1
done
echo " Done!"

# Verify PostgreSQL is running
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 Verifying PostgreSQL..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Tables created:"
docker exec t1agentics-postgres psql -U t1agentics -d t1agentics -c "\dt" || echo "❌ Failed to connect to PostgreSQL"

# Check default users
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "👥 Default users created:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker exec t1agentics-postgres psql -U t1agentics -d t1agentics -c "SELECT username, email, role, disabled FROM users;" || echo "❌ No users found"

# Check backend logs
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 Backend startup logs (last 20 lines):"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
docker logs t1agentics-backend --tail 20

# Success message
echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    ✅ Rebuild Complete!                        ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Access T1 Agentics:"
echo "   URL:      http://localhost:3000"
echo "   Username: admin"
echo "   Password: admin123"
echo ""
echo "📊 Additional test accounts:"
echo "   analyst / analyst123"
echo "   viewer  / viewer123"
echo ""
echo "🔧 Useful commands:"
echo "   docker-compose logs -f backend   # Watch backend logs"
echo "   docker-compose logs -f postgres  # Watch database logs"
echo "   docker-compose ps                # Check service status"
echo "   ./rebuild-db.sh                  # Run this script again"
echo ""
echo "🎉 Your database is fresh and ready!"
echo ""
