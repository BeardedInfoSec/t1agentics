#!/usr/bin/env bash
# T1 Agentics - One-command installer
# Target: fresh Ubuntu 22.04+ with Docker already installed.
# Idempotent: rerunning will not clobber an existing .env unless --reset.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN  %s\n' "$*" >&2; }
fail() { printf '[install] ERROR %s\n' "$*" >&2; exit 1; }

banner() {
  cat <<'BANNER'
================================================================
                       T1 Agentics
            Open-source self-hosted SOC platform
================================================================
BANNER
}

is_domain() {
  [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

is_email() {
  [[ "$1" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

port_in_use() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH "sport = :$p" 2>/dev/null | grep -q .
  elif command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"$p" -sTCP:LISTEN -Pn >/dev/null 2>&1
  else
    return 1
  fi
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
preflight() {
  log "Running preflight checks..."

  case "$(uname -s)" in
    Linux*) : ;;
    Darwin*) warn "macOS detected. Installer is tested on Linux; proceed at your own risk." ;;
    MINGW*|MSYS*|CYGWIN*) fail "Windows is not supported. Use WSL2 or a Linux VM." ;;
    *) warn "Unknown OS $(uname -s); proceeding." ;;
  esac

  command -v docker >/dev/null 2>&1 || fail "docker is not installed. See https://docs.docker.com/engine/install/"
  docker info >/dev/null 2>&1 || fail "Cannot reach the Docker daemon. Is it running? Are you in the docker group?"
  docker compose version >/dev/null 2>&1 || fail "docker compose v2 plugin missing. Install docker-compose-plugin."
  command -v openssl >/dev/null 2>&1 || fail "openssl is required."
  command -v curl    >/dev/null 2>&1 || fail "curl is required."

  if command -v free >/dev/null 2>&1; then
    local ram_mb
    ram_mb=$(free -m | awk '/^Mem:/{print $2}')
    if [[ "$ram_mb" -lt 7800 ]]; then
      fail "Need >= 8 GB RAM. Detected ${ram_mb} MB."
    fi
    log "RAM ok: ${ram_mb} MB"
  else
    warn "free(1) not available; skipping RAM check."
  fi

  if command -v df >/dev/null 2>&1; then
    local disk_gb
    disk_gb=$(df -BG --output=avail . | tail -1 | tr -dc '0-9')
    if [[ "${disk_gb:-0}" -lt 500 ]]; then
      fail "Need >= 500 GB free at $REPO_DIR. Detected ${disk_gb} GB."
    fi
    log "Disk ok: ${disk_gb} GB free"
  fi

  for p in 80 443; do
    if port_in_use "$p"; then
      fail "Port $p is already in use. Free it before running the installer (Caddy needs 80 and 443)."
    fi
  done
  log "Ports 80 and 443 are free."
}

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------
prompts() {
  if [[ -f .env && "${1:-}" != "--reset" ]]; then
    log ".env already exists. Reusing it. Run with --reset to regenerate."
    return 0
  fi

  echo
  echo "Configure your install. Press enter to keep the default in [brackets]."
  echo

  while :; do
    read -rp "Domain (e.g. soc.example.com): " DOMAIN
    [[ -n "$DOMAIN" ]] && is_domain "$DOMAIN" && break
    echo "  -> not a valid domain, try again."
  done

  while :; do
    read -rp "Admin email (used for Let's Encrypt and first login): " ADMIN_EMAIL
    [[ -n "$ADMIN_EMAIL" ]] && is_email "$ADMIN_EMAIL" && break
    echo "  -> not a valid email, try again."
  done

  while :; do
    read -rsp "Admin password (min 12 chars): " ADMIN_PASSWORD; echo
    if [[ "${#ADMIN_PASSWORD}" -lt 12 ]]; then
      echo "  -> password is too short, try again."
      continue
    fi
    read -rsp "Confirm admin password:        " ADMIN_PASSWORD2; echo
    [[ "$ADMIN_PASSWORD" == "$ADMIN_PASSWORD2" ]] && break
    echo "  -> passwords do not match, try again."
  done

  echo
  echo "Anthropic API key (BYO). Leave EMPTY to install without AI features."
  read -rsp "ANTHROPIC_API_KEY [empty]: " ANTHROPIC_API_KEY; echo
  if [[ -z "$ANTHROPIC_API_KEY" ]]; then
    warn "No API key provided. AI features will be DISABLED. Set ANTHROPIC_API_KEY"
    warn "in .env and run 'docker compose up -d' to enable them later."
  fi

  echo
  echo "SMTP (optional - for password resets and notifications). Leave blank to skip."
  read -rp  "SMTP host [skip]: " SMTP_HOST
  if [[ -n "$SMTP_HOST" ]]; then
    read -rp  "SMTP port [587]: "        SMTP_PORT;        SMTP_PORT="${SMTP_PORT:-587}"
    read -rp  "SMTP username: "          SMTP_USERNAME
    read -rsp "SMTP password: "          SMTP_PASSWORD; echo
    read -rp  "From address [${ADMIN_EMAIL}]: " SMTP_FROM_EMAIL
    SMTP_FROM_EMAIL="${SMTP_FROM_EMAIL:-$ADMIN_EMAIL}"
  else
    SMTP_PORT="" SMTP_USERNAME="" SMTP_PASSWORD="" SMTP_FROM_EMAIL=""
  fi
}

# ---------------------------------------------------------------------------
# Secret generation + .env
# ---------------------------------------------------------------------------
gen_hex()    { openssl rand -hex 32; }
gen_pwhex()  { openssl rand -hex 16; }
gen_fernet() {
  if command -v python3 >/dev/null 2>&1 \
     && python3 -c "from cryptography.fernet import Fernet" >/dev/null 2>&1; then
    python3 -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
  else
    warn "python3+cryptography unavailable; falling back to openssl-derived Fernet key."
    # Fernet keys are 32 random bytes, urlsafe-base64-encoded (no padding strip).
    openssl rand 32 | base64 | tr '+/' '-_' | tr -d '\n='
    printf '=\n'
  fi
}

write_env() {
  if [[ -f .env && "${1:-}" != "--reset" ]]; then
    return 0
  fi

  log "Generating secrets and writing .env..."
  local JWT_SECRET_KEY PLATFORM_JWT_SECRET CREDENTIALS_ENCRYPTION_KEY
  local POSTGRES_PASSWORD LEAD_DRAFT_SIGNING_SECRET
  JWT_SECRET_KEY="$(gen_hex)"
  PLATFORM_JWT_SECRET="$(gen_hex)"
  CREDENTIALS_ENCRYPTION_KEY="$(gen_fernet)"
  POSTGRES_PASSWORD="$(gen_pwhex)"
  LEAD_DRAFT_SIGNING_SECRET="$(gen_hex)"

  umask 077
  cat > .env <<ENV
# T1 Agentics - generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Treat this file as sensitive. Mode 600.

ENVIRONMENT=production

# Public
DOMAIN=${DOMAIN}
ADMIN_EMAIL=${ADMIN_EMAIL}
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}

# Database
POSTGRES_USER=agentcore
POSTGRES_DB=agentcore
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}

# ClickHouse
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=
CLICKHOUSE_DATABASE=t1_telemetry

# Secrets
JWT_SECRET_KEY=${JWT_SECRET_KEY}
PLATFORM_JWT_SECRET=${PLATFORM_JWT_SECRET}
CREDENTIALS_ENCRYPTION_KEY=${CREDENTIALS_ENCRYPTION_KEY}
LEAD_DRAFT_SIGNING_SECRET=${LEAD_DRAFT_SIGNING_SECRET}

# AI provider - BYO API key. Leave empty to disable AI features.
AI_PROVIDER=claude
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
CLAUDE_DEFAULT_MODEL=claude-sonnet-4-5-20250929
CLAUDE_MAX_DAILY_USD=25

# SMTP (optional)
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USERNAME=${SMTP_USERNAME}
SMTP_PASSWORD=${SMTP_PASSWORD}
SMTP_FROM_EMAIL=${SMTP_FROM_EMAIL}
SMTP_FROM_NAME=T1 Agentics
SMTP_USE_TLS=true
ENV
  chmod 600 .env
  log ".env written ($(wc -l < .env) lines, mode 600)."
}

# ---------------------------------------------------------------------------
# Compose + bootstrap
# ---------------------------------------------------------------------------
compose() { docker compose --env-file "$REPO_DIR/.env" "$@"; }

bring_up() {
  log "Pulling base images (build-only images may not exist yet; that is ok)..."
  compose pull --ignore-pull-failures || true

  log "Building backend + frontend images (this may take several minutes)..."
  compose build backend frontend

  log "Starting services..."
  compose up -d

  log "Waiting for postgres to become healthy (up to 60s)..."
  local i
  for i in $(seq 1 30); do
    if compose exec -T postgres pg_isready -U "${POSTGRES_USER:-agentcore}" >/dev/null 2>&1; then
      log "Postgres is healthy."
      break
    fi
    sleep 2
    if [[ "$i" -eq 30 ]]; then
      fail "Postgres did not become healthy within 60s. Check: docker compose logs postgres"
    fi
  done

  log "Waiting for backend health endpoint (migrations run on first connect)..."
  for i in $(seq 1 60); do
    if compose exec -T backend curl -fsS http://localhost:8000/api/v1/health >/dev/null 2>&1; then
      log "Backend is healthy."
      break
    fi
    sleep 3
    if [[ "$i" -eq 60 ]]; then
      warn "Backend did not respond within 3 minutes. Check: docker compose logs backend"
      warn "Continuing - it may finish booting in the background."
    fi
  done

  log "Bootstrapping first platform admin..."
  if ! compose exec -T backend python scripts/bootstrap_platform_admin.py; then
    warn "bootstrap_platform_admin.py exited non-zero. You may need to run it manually:"
    warn "  docker compose exec backend python scripts/bootstrap_platform_admin.py"
  fi

  log "Giving Caddy 20s to negotiate a Let's Encrypt certificate..."
  sleep 20
}

# ---------------------------------------------------------------------------
# Success banner
# ---------------------------------------------------------------------------
done_msg() {
  cat <<DONE

================================================================
                       Install complete
================================================================
  URL:    https://${DOMAIN}
  Login:  ${ADMIN_EMAIL}

  Useful commands:
    docker compose ps              - service status
    docker compose logs -f         - tail all logs
    ./bin/t1 logs backend          - tail one service
    ./bin/t1 backup                - snapshot db + caddy data

  Cert provisioning can take up to a minute on first boot.
  If https://${DOMAIN} does not load, check 'docker compose logs caddy'
  and confirm the domain's DNS A record points at this host.
DONE
  if [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    cat <<DONEAI

  AI features are OFF. Add ANTHROPIC_API_KEY to .env and run
  'docker compose up -d backend' to enable them.
DONEAI
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  banner
  preflight
  prompts "${1:-}"
  write_env "${1:-}"

  # Load whatever we just wrote so the success banner can reference it.
  # shellcheck disable=SC1091
  set -a; . ./.env; set +a

  bring_up
  done_msg
}

main "$@"
