#!/bin/bash
# T1 Agentics - Cron Job Setup
# Run once on the droplet to install automated tasks
set -euo pipefail

SCRIPTS_DIR="/opt/t1agentics/scripts"

# Make scripts executable
chmod +x "$SCRIPTS_DIR"/*.sh

# Install crontab
(crontab -l 2>/dev/null || true; cat <<'CRON'
# T1 Agentics Automated Tasks
# Database backup - daily at 2 AM UTC
0 2 * * * /opt/t1agentics/scripts/backup-db.sh >> /var/log/t1agentics-backup.log 2>&1

# Health check - every 5 minutes
*/5 * * * * /opt/t1agentics/scripts/healthcheck.sh 2>&1

# Docker cleanup - weekly on Sunday at 3 AM
0 3 * * 0 docker system prune -f >> /var/log/t1agentics-docker-cleanup.log 2>&1

# Log rotation - daily at midnight
0 0 * * * find /var/log/t1agentics-*.log -size +100M -exec truncate -s 10M {} \;
CRON
) | sort -u | crontab -

echo "Cron jobs installed successfully:"
crontab -l
