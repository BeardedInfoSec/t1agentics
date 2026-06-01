#!/bin/bash
# T1 Agentics - Health Check Script
# Run via cron: */5 * * * * /opt/t1agentics/scripts/healthcheck.sh
set -euo pipefail

BACKEND_URL="http://localhost:8000/api/v1/health"
ALERT_EMAIL="${ALERT_EMAIL:-admin@example.com}"
LOG_FILE="/var/log/t1agentics-health.log"

check_service() {
    local name="$1"
    local url="$2"
    local timeout="${3:-10}"

    if response=$(curl -sf --max-time "$timeout" "$url" 2>&1); then
        echo "[$(date)] OK: $name" >> "$LOG_FILE"
        return 0
    else
        echo "[$(date)] FAIL: $name - $response" >> "$LOG_FILE"
        return 1
    fi
}

# Check backend API
if ! check_service "Backend API" "$BACKEND_URL"; then
    echo "T1 Agentics ALERT: Backend API is down!" | mail -s "T1 Agentics: Backend Down" "$ALERT_EMAIL" 2>/dev/null || true
fi

# Check PostgreSQL
if ! docker exec t1agentics-postgres pg_isready -U agentcore -d agentcore > /dev/null 2>&1; then
    echo "[$(date)] FAIL: PostgreSQL" >> "$LOG_FILE"
    echo "T1 Agentics ALERT: PostgreSQL is down!" | mail -s "T1 Agentics: DB Down" "$ALERT_EMAIL" 2>/dev/null || true
fi

# Check disk space (alert at 90%)
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
if [ "$DISK_USAGE" -gt 90 ]; then
    echo "[$(date)] WARN: Disk usage at ${DISK_USAGE}%" >> "$LOG_FILE"
    echo "T1 Agentics WARNING: Disk usage at ${DISK_USAGE}%" | mail -s "T1 Agentics: Disk Space Low" "$ALERT_EMAIL" 2>/dev/null || true
fi

# Check container status
for container in t1agentics-postgres t1agentics-backend t1agentics-frontend; do
    if ! docker inspect --format='{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
        echo "[$(date)] FAIL: Container $container not running" >> "$LOG_FILE"
    fi
done

# Rotate log (keep last 10000 lines)
if [ -f "$LOG_FILE" ]; then
    tail -n 10000 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
fi
