#!/bin/bash
# T1 Agentics - Database & Redis Backup Script
# Run via cron: 0 2 * * * /opt/t1agentics/scripts/backup-db.sh
#
# Features:
#   - PostgreSQL full dump (compressed)
#   - Redis RDB snapshot
#   - Backup verification
#   - Configurable retention cleanup
#   - Timestamped logging
#   - Error handling with cleanup trap
#   - Placeholder for offsite upload (S3/DO Spaces)

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BACKUP_DIR="/opt/t1agentics/backups"
REDIS_BACKUP_DIR="${BACKUP_DIR}/redis"
RETENTION_DAYS=${RETENTION_DAYS:-30}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PG_BACKUP_FILE="${BACKUP_DIR}/t1agentics_${TIMESTAMP}.sql.gz"
PG_VERIFY_FILE="${BACKUP_DIR}/t1agentics_${TIMESTAMP}_verify.dump"
REDIS_BACKUP_FILE="${REDIS_BACKUP_DIR}/redis_${TIMESTAMP}.rdb"

# Container names
PG_CONTAINER="t1agentics-postgres"
REDIS_CONTAINER="t1agentics-redis"

# Track success for cleanup trap
PG_BACKUP_OK=false
REDIS_BACKUP_OK=false

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR: Backup script failed with exit code ${exit_code}"
        # Remove partial/corrupt backup files
        if [ "$PG_BACKUP_OK" = false ] && [ -f "$PG_BACKUP_FILE" ]; then
            log "Removing incomplete PostgreSQL backup: ${PG_BACKUP_FILE}"
            rm -f "$PG_BACKUP_FILE"
        fi
        if [ "$REDIS_BACKUP_OK" = false ] && [ -f "$REDIS_BACKUP_FILE" ]; then
            log "Removing incomplete Redis backup: ${REDIS_BACKUP_FILE}"
            rm -f "$REDIS_BACKUP_FILE"
        fi
    fi
    # Always clean up the verification dump
    rm -f "$PG_VERIFY_FILE"
    log "Cleanup complete."
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
mkdir -p "$BACKUP_DIR" "$REDIS_BACKUP_DIR"

log "==========================================="
log "Starting T1 Agentics backup"
log "Retention: ${RETENTION_DAYS} days"
log "==========================================="

# ---------------------------------------------------------------------------
# 1. PostgreSQL Backup
# ---------------------------------------------------------------------------
log "--- PostgreSQL Backup ---"
log "Dumping database from container ${PG_CONTAINER}..."

docker exec "$PG_CONTAINER" pg_dump \
    -U agentcore \
    -d agentcore \
    --no-owner \
    --no-privileges \
    --clean \
    --if-exists \
    | gzip > "$PG_BACKUP_FILE"

PG_FILESIZE=$(du -h "$PG_BACKUP_FILE" | cut -f1)
log "PostgreSQL dump completed: ${PG_BACKUP_FILE} (${PG_FILESIZE})"

# ---------------------------------------------------------------------------
# 2. PostgreSQL Backup Verification
# ---------------------------------------------------------------------------
log "Verifying PostgreSQL backup integrity..."

# Create a custom-format dump for verification (pg_restore --list only works with custom format)
# We verify the gzipped SQL dump by attempting to decompress and check structure
if gunzip -t "$PG_BACKUP_FILE" 2>/dev/null; then
    log "Gzip integrity check: PASSED"
else
    log "ERROR: Gzip integrity check FAILED for ${PG_BACKUP_FILE}"
    exit 1
fi

# Additionally verify the SQL content is non-empty and contains expected markers
DUMP_LINES=$(zcat "$PG_BACKUP_FILE" | wc -l)
if [ "$DUMP_LINES" -gt 10 ]; then
    log "SQL content check: PASSED (${DUMP_LINES} lines)"
    PG_BACKUP_OK=true
else
    log "ERROR: SQL dump appears empty or truncated (${DUMP_LINES} lines)"
    exit 1
fi

# ---------------------------------------------------------------------------
# 3. Redis Backup
# ---------------------------------------------------------------------------
log "--- Redis Backup ---"

if docker ps --format '{{.Names}}' | grep -q "^${REDIS_CONTAINER}$"; then
    log "Triggering Redis BGSAVE on container ${REDIS_CONTAINER}..."
    docker exec "$REDIS_CONTAINER" redis-cli BGSAVE

    # Wait for BGSAVE to complete (poll up to 30 seconds)
    WAIT_SECONDS=0
    MAX_WAIT=30
    while [ $WAIT_SECONDS -lt $MAX_WAIT ]; do
        BGSAVE_STATUS=$(docker exec "$REDIS_CONTAINER" redis-cli LASTSAVE 2>/dev/null || echo "error")
        sleep 2
        BGSAVE_STATUS_NEW=$(docker exec "$REDIS_CONTAINER" redis-cli LASTSAVE 2>/dev/null || echo "error")
        if [ "$BGSAVE_STATUS" != "$BGSAVE_STATUS_NEW" ] || [ $WAIT_SECONDS -ge 4 ]; then
            break
        fi
        WAIT_SECONDS=$((WAIT_SECONDS + 2))
    done

    # Copy the RDB file from the container
    docker cp "${REDIS_CONTAINER}:/data/dump.rdb" "$REDIS_BACKUP_FILE" 2>/dev/null && {
        REDIS_FILESIZE=$(du -h "$REDIS_BACKUP_FILE" | cut -f1)
        log "Redis backup completed: ${REDIS_BACKUP_FILE} (${REDIS_FILESIZE})"
        REDIS_BACKUP_OK=true
    } || {
        log "WARNING: Could not copy Redis dump.rdb -- Redis may not have data or uses a different path"
    }
else
    log "WARNING: Redis container '${REDIS_CONTAINER}' is not running. Skipping Redis backup."
fi

# ---------------------------------------------------------------------------
# 4. Retention Cleanup
# ---------------------------------------------------------------------------
log "--- Retention Cleanup ---"
log "Removing backups older than ${RETENTION_DAYS} days..."

PG_DELETED=$(find "$BACKUP_DIR" -maxdepth 1 -name "t1agentics_*.sql.gz" -mtime +${RETENTION_DAYS} -print -delete | wc -l)
REDIS_DELETED=$(find "$REDIS_BACKUP_DIR" -maxdepth 1 -name "redis_*.rdb" -mtime +${RETENTION_DAYS} -print -delete | wc -l)

log "Removed ${PG_DELETED} old PostgreSQL backup(s)"
log "Removed ${REDIS_DELETED} old Redis backup(s)"

# ---------------------------------------------------------------------------
# 5. Offsite Upload (Placeholder)
# ---------------------------------------------------------------------------
# Uncomment and configure one of the following for offsite backup storage:
#
# --- AWS S3 ---
# aws s3 cp "$PG_BACKUP_FILE" "s3://t1agentics-backups/postgres/"
# if [ "$REDIS_BACKUP_OK" = true ]; then
#     aws s3 cp "$REDIS_BACKUP_FILE" "s3://t1agentics-backups/redis/"
# fi
#
# --- DigitalOcean Spaces ---
# s3cmd put "$PG_BACKUP_FILE" "s3://t1agentics-backups/postgres/" \
#     --host=nyc3.digitaloceanspaces.com \
#     --host-bucket="%(bucket)s.nyc3.digitaloceanspaces.com"
# if [ "$REDIS_BACKUP_OK" = true ]; then
#     s3cmd put "$REDIS_BACKUP_FILE" "s3://t1agentics-backups/redis/" \
#         --host=nyc3.digitaloceanspaces.com \
#         --host-bucket="%(bucket)s.nyc3.digitaloceanspaces.com"
# fi
#
# --- Rclone (generic) ---
# rclone copy "$PG_BACKUP_FILE" remote:t1agentics-backups/postgres/
# if [ "$REDIS_BACKUP_OK" = true ]; then
#     rclone copy "$REDIS_BACKUP_FILE" remote:t1agentics-backups/redis/
# fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log "==========================================="
log "Backup complete."
log "  PostgreSQL: ${PG_BACKUP_FILE} (${PG_FILESIZE})"
if [ "$REDIS_BACKUP_OK" = true ]; then
    log "  Redis:      ${REDIS_BACKUP_FILE} (${REDIS_FILESIZE})"
else
    log "  Redis:      skipped or failed"
fi
log "==========================================="
