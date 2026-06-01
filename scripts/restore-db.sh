#!/bin/bash
# T1 Agentics - Database Restore Script
set -euo pipefail

if [ $# -eq 0 ]; then
    echo "Usage: $0 <backup_file.sql.gz>"
    echo "Available backups:"
    ls -la /opt/t1agentics/backups/t1agentics_*.sql.gz 2>/dev/null || echo "  No backups found"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Error: Backup file not found: $BACKUP_FILE"
    exit 1
fi

echo "WARNING: This will overwrite the current database!"
echo "Backup file: $BACKUP_FILE"
read -p "Are you sure? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 0
fi

echo "[$(date)] Restoring database from $BACKUP_FILE..."

gunzip -c "$BACKUP_FILE" | docker exec -i t1agentics-postgres psql -U agentcore -d agentcore

echo "[$(date)] Database restored successfully."
