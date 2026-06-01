#!/bin/bash
# T1 Agentics Health Monitor
# Add to crontab: */5 * * * * /opt/t1agentics/scripts/health-monitor.sh
#
# Checks backend health every 5 minutes.
# Restarts containers if unhealthy. Sends email alert if configured.

LOG_FILE="/var/log/t1-health-monitor.log"
COMPOSE_DIR="/opt/t1agentics"
COMPOSE_FILE="docker-compose.yml"
HEALTH_URL="http://localhost:8000/api/v1/health"
MAX_RETRIES=3
RETRY_DELAY=10

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}

check_health() {
    local response
    response=$(curl -sf -w "%{http_code}" -o /tmp/health_response.json "$HEALTH_URL" 2>/dev/null)
    echo "$response"
}

restart_backend() {
    log "ALERT: Backend unhealthy — restarting containers"
    cd "$COMPOSE_DIR" || exit 1
    docker compose -f "$COMPOSE_FILE" restart backend
    sleep 15

    # Verify restart worked
    local status
    status=$(check_health)
    if [ "$status" = "200" ]; then
        log "RECOVERED: Backend healthy after restart"
    else
        log "CRITICAL: Backend still unhealthy after restart (HTTP $status)"
        # Send email if SMTP is configured
        if command -v mail &> /dev/null && [ -n "$ALERT_EMAIL" ]; then
            echo "T1 Agentics backend is unhealthy and restart failed. Check the droplet immediately." | \
                mail -s "CRITICAL: T1 Agentics Backend Down" "$ALERT_EMAIL"
        fi
    fi
}

# Check disk space
DISK_USAGE=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_USAGE" -gt 85 ]; then
    log "WARNING: Disk usage at ${DISK_USAGE}%"
    # Clean up Docker resources
    docker system prune -f --volumes --filter "until=168h" >> "$LOG_FILE" 2>&1
fi

# Check memory
MEM_AVAILABLE=$(free -m | awk '/^Mem:/ {print $7}')
if [ "$MEM_AVAILABLE" -lt 256 ]; then
    log "WARNING: Low memory — only ${MEM_AVAILABLE}MB available"
fi

# Health check with retries
for i in $(seq 1 $MAX_RETRIES); do
    STATUS=$(check_health)
    if [ "$STATUS" = "200" ]; then
        # Healthy — check postgres connection from response
        PG_CONNECTED=$(cat /tmp/health_response.json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('postgres_connected', False))" 2>/dev/null)
        if [ "$PG_CONNECTED" = "False" ]; then
            log "WARNING: Backend healthy but PostgreSQL disconnected"
        fi
        exit 0
    fi

    if [ "$i" -lt "$MAX_RETRIES" ]; then
        sleep "$RETRY_DELAY"
    fi
done

# All retries failed
restart_backend
