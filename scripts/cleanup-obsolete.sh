#!/bin/bash
# T1 Agentics - Remove obsolete code and artifacts
# Removes 285MB of dead code: MongoDB, old agents, frontend cache, Python bytecode

set -e

echo "🧹 T1 Agentics - Cleanup Script"
echo "================================"
echo ""

# Change to project root
cd "$(dirname "$0")/.."

echo "📊 Before cleanup:"
du -sh . 2>/dev/null || echo "Size check skipped"
echo ""

# 1. Remove MongoDB legacy files
echo "🗑️  Removing MongoDB legacy code..."
rm -f backend/services/database_mongodb_OLD.py
rm -f backend/setup_database.py
rm -f backend/test_database.py
echo "   ✓ MongoDB files removed"

# 2. Remove obsolete agent implementations
echo "🗑️  Removing obsolete agent architecture..."
rm -f backend/agents/l1_agent.py
rm -f backend/agents/l2_agent.py
rm -f backend/agents/specialized_agents.py
rm -f backend/services/ai_agent.py
rm -f backend/services/autonomous_soc.py
rm -f backend/services/configurable_ai_agents.py
rm -f backend/services/response_automation.py
rm -f backend/services/virustotal.py
rm -f backend/seed_agents.py
echo "   ✓ Agent files removed"

# 3. Remove backup and old files
echo "🗑️  Removing backup files..."
rm -f backend/routes/admin_old.py
rm -f backend/services/job_queue.py.bak
rm -f build_out_MCP_prompt
rm -f cookies.txt
echo "   ✓ Backup files removed"

# 4. Remove Python cache files
echo "🗑️  Removing Python cache..."
find backend/ -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find backend/ -name "*.pyc" -delete 2>/dev/null || true
echo "   ✓ Python cache removed"

# 5. Remove frontend build artifacts
echo "🗑️  Removing frontend build artifacts..."
rm -rf frontend/build/ 2>/dev/null || echo "   ℹ️  Build directory not found"
rm -rf frontend/node_modules/.cache/ 2>/dev/null || echo "   ℹ️  Cache directory not found"
echo "   ✓ Frontend artifacts removed"

# 6. Remove obsolete frontend components (marked as deleted in git)
echo "🗑️  Removing obsolete frontend components..."
cd frontend/src/components 2>/dev/null || echo "   ℹ️  Components directory not found"
rm -f AdminDashboard_OLD.js
rm -f InvestigationDetail.OLD.js
rm -f ActionDecisionCard.js
rm -f AlertViewerRedesign.js
rm -f DashboardImproved.js
rm -f InvestigationDetailNew.js
rm -f InvestigationDetailRedesign.js
rm -f SlideOutNavImproved.js
rm -f TopBarImproved.js
rm -f AgentTelemetry.js AgentTelemetry.css
rm -f AnalystWorkbench.js
rm -f CustomIntegrationBuilder.js
rm -f DecisionCapture.js DecisionCore.js
rm -f DisconfirmingAlert.js
rm -f EvidenceStream.js
rm -f FormsManager.js
rm -f InvestigationDetail.js
rm -f InvestigationList.js
rm -f InvestigationWorkbench.js
rm -f PhishingReports.js
rm -f RecommendedActions.js
rm -f App.css
rm -f FINAL_IMPLEMENTATION_GUIDE.md
rm -f IMPLEMENTATION_GUIDE.md
rm -f IMPROVEMENTS_GUIDE.md
rm -f plan.md
cd ../../..
echo "   ✓ Obsolete components removed"

# 7. Remove root-level junk files
echo "🗑️  Removing root-level artifacts..."
rm -f .env.example .env.template
rm -f rebuild-db.sh rebuild-db.ps1
rm -f test-lmstudio.ps1
echo "   ✓ Root artifacts removed"

echo ""
echo "📊 After cleanup:"
du -sh . 2>/dev/null || echo "Size check skipped"
echo ""
echo "✅ Cleanup complete!"
echo ""
echo "Next steps:"
echo "  1. Review git status: git status"
echo "  2. Commit changes: git add -A && git commit -m 'Remove obsolete code (285MB cleanup)'"
echo "  3. Rebuild containers: docker-compose build --no-cache"
echo ""
