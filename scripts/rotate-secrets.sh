#!/bin/bash
# T1 Agentics - Credential Rotation Script
# Generates strong secrets and updates the production .env file
set -euo pipefail

ENV_FILE="/opt/t1agentics/.env.production"
BACKUP_FILE="${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"

echo "=== T1 Agentics Credential Rotation ==="
echo "Environment file: $ENV_FILE"

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found"
    exit 1
fi

# Backup current env
cp "$ENV_FILE" "$BACKUP_FILE"
echo "Backup saved to: $BACKUP_FILE"

# Generate new secrets
NEW_JWT_SECRET=$(openssl rand -hex 32)
NEW_PLATFORM_JWT_SECRET=$(openssl rand -hex 32)
NEW_POSTGRES_PASSWORD=$(openssl rand -base64 24 | tr -d '/+=')
NEW_FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || openssl rand -base64 32)
NEW_LICENSE_KEY=$(openssl rand -hex 32)

echo ""
echo "New secrets generated. Review before applying:"
echo "  JWT_SECRET_KEY: ${NEW_JWT_SECRET:0:8}..."
echo "  PLATFORM_JWT_SECRET: ${NEW_PLATFORM_JWT_SECRET:0:8}..."
echo "  POSTGRES_PASSWORD: ${NEW_POSTGRES_PASSWORD:0:8}..."
echo "  CREDENTIALS_ENCRYPTION_KEY: ${NEW_FERNET_KEY:0:8}..."
echo ""

read -p "Apply these secrets? WARNING: Requires service restart and re-encryption of stored credentials. (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted. Backup removed."
    rm "$BACKUP_FILE"
    exit 0
fi

# Update env file
sed -i "s|^JWT_SECRET_KEY=.*|JWT_SECRET_KEY=${NEW_JWT_SECRET}|" "$ENV_FILE"
sed -i "s|^PLATFORM_JWT_SECRET=.*|PLATFORM_JWT_SECRET=${NEW_PLATFORM_JWT_SECRET}|" "$ENV_FILE"
sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${NEW_POSTGRES_PASSWORD}|" "$ENV_FILE"
sed -i "s|^CREDENTIALS_ENCRYPTION_KEY=.*|CREDENTIALS_ENCRYPTION_KEY=${NEW_FERNET_KEY}|" "$ENV_FILE"
sed -i "s|^LICENSE_SECRET_KEY=.*|LICENSE_SECRET_KEY=${NEW_LICENSE_KEY}|" "$ENV_FILE"

echo ""
echo "Secrets updated in $ENV_FILE"
echo ""
echo "IMPORTANT: You must now:"
echo "  1. Update PostgreSQL password: docker exec -it t1agentics-postgres psql -U agentcore -c \"ALTER USER agentcore PASSWORD '${NEW_POSTGRES_PASSWORD}';\""
echo "  2. Restart services: docker compose -f docker-compose.yml down && docker compose -f docker-compose.yml up -d"
echo "  3. Re-encrypt stored credentials (they will be unreadable with the new key)"
echo ""
echo "Previous config backed up to: $BACKUP_FILE"
