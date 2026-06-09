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
    Darwin*) log "macOS detected - using Docker Desktop." ;;
    MINGW*|MSYS*|CYGWIN*) fail "Native Windows shells are not supported. Open a WSL2 (Ubuntu) terminal and run this there; Docker Desktop's WSL2 backend runs the containers." ;;
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
    if [[ "${disk_gb:-0}" -lt 120 ]]; then
      fail "Need >= 120 GB free at $REPO_DIR. Detected ${disk_gb} GB."
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
  read -rp "Organization name [T1 Agentics]: " ORG_NAME
  ORG_NAME="${ORG_NAME:-T1 Agentics}"
  read -rp "Organization slug [t1-agentics]: " ORG_SLUG
  ORG_SLUG="${ORG_SLUG:-t1-agentics}"

  echo
  echo "License tier. Self-hosted installs are unlimited (platform)."
  read -rp "License tier [platform]: " LICENSE_TIER
  LICENSE_TIER="${LICENSE_TIER:-platform}"

  echo
  echo "AI chat provider. For a local Ollama / LM Studio, give the OpenAI-"
  echo "compatible base URL (e.g. http://host.docker.internal:11434)."
  read -rp "AI provider [self_hosted]: " AI_CHAT_PROVIDER
  AI_CHAT_PROVIDER="${AI_CHAT_PROVIDER:-self_hosted}"
  read -rp "AI api style (openai|anthropic) [openai]: " AI_CHAT_API_STYLE
  AI_CHAT_API_STYLE="${AI_CHAT_API_STYLE:-openai}"
  read -rp "AI base URL [http://host.docker.internal:11434]: " AI_CHAT_BASE_URL
  AI_CHAT_BASE_URL="${AI_CHAT_BASE_URL:-http://host.docker.internal:11434}"
  read -rp "AI model [qwen2.5:7b-instruct]: " AI_CHAT_MODEL
  AI_CHAT_MODEL="${AI_CHAT_MODEL:-qwen2.5:7b-instruct}"
  read -rsp "AI api key [empty for keyless local servers]: " AI_CHAT_API_KEY; echo

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
SMTP_FROM_NAME="T1 Agentics"
SMTP_USE_TLS=true

# Referenced by t1.config.yaml (\${AI_CHAT_API_KEY}). Empty for keyless local AI.
AI_CHAT_API_KEY=${AI_CHAT_API_KEY}
ENV
  chmod 600 .env
  log ".env written ($(wc -l < .env) lines, mode 600)."
}

# ---------------------------------------------------------------------------
# t1.config.yaml  (single-file app configuration, applied on backend startup)
# ---------------------------------------------------------------------------
write_config_yaml() {
  if [[ -f t1.config.yaml && "${1:-}" != "--reset" ]]; then
    log "t1.config.yaml already exists. Reusing it. Run with --reset to regenerate."
    return 0
  fi
  log "Writing t1.config.yaml..."
  local SMTP_SECTION=""
  if [[ -n "${SMTP_HOST:-}" ]]; then
    SMTP_SECTION=$(cat <<SMTP

smtp:
  host: "${SMTP_HOST}"
  port: ${SMTP_PORT:-587}
  username: "\${SMTP_USERNAME}"
  password: "\${SMTP_PASSWORD}"
  from_email: "${SMTP_FROM_EMAIL}"
  from_name: "T1 Agentics SOC"
  use_tls: true
  enabled: true
SMTP
)
  fi
  cat > t1.config.yaml <<CFG
# T1 Agentics - generated by install.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Single-file app config. Secrets are referenced from .env as \${ENV_VAR}.
# See t1.config.yaml.example for the fully-commented reference.

org:
  name: "${ORG_NAME}"
  slug: "${ORG_SLUG}"

license:
  tier: "${LICENSE_TIER}"

ai:
  chat:
    provider: "${AI_CHAT_PROVIDER}"
    api_style: "${AI_CHAT_API_STYLE}"
    base_url: "${AI_CHAT_BASE_URL}"
    model: "${AI_CHAT_MODEL}"
    api_key: "\${AI_CHAT_API_KEY}"
    max_tokens: 4096
  embeddings:
    provider: "disabled"

admin:
  username: "admin"
  email: "${ADMIN_EMAIL}"
  name: "Platform Admin"

triage:
  dispositions: []
  severity_levels: []
  priorities: []
${SMTP_SECTION}
CFG
  log "t1.config.yaml written."
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

  seed_content

  log "Giving Caddy 20s to negotiate a Let's Encrypt certificate..."
  sleep 20
}

# ---------------------------------------------------------------------------
# Content seeding (playbook marketplace + knowledge base)
# ---------------------------------------------------------------------------
# The catalog and KB content live at the repo root, but the backend image is
# built from ./backend, so neither the seed scripts nor the content ship inside
# the container. Copy them in, then run the seeders. Best-effort and idempotent:
# the playbook loader upserts (ON CONFLICT) and the KB loader skips existing
# rows by title, so reruns are safe. Failures here never abort the install -
# the app is usable without seed content and you can rerun the commands below.
seed_content() {
  log "Seeding playbook marketplace + knowledge base..."

  # Stage the root-level seed scripts and content inside the backend container.
  if ! compose cp scripts/load-playbook-catalog.py backend:/app/scripts/load-playbook-catalog.py \
     || ! compose cp scripts/load-kb-direct.py backend:/app/scripts/load-kb-direct.py \
     || ! compose cp playbook-store-output backend:/app/playbook-store-output \
     || ! compose cp kb-content-output backend:/app/kb-content-output; then
    warn "Could not copy seed scripts/content into the backend container. Skipping seeding."
    warn "Seed manually later (see INSTALL.md > Seeding built-in content)."
    return 0
  fi

  # Playbook marketplace: 200 builtin templates (tenant-NULL, visible to all).
  if compose exec -T backend python scripts/load-playbook-catalog.py; then
    log "Playbook marketplace seeded."
  else
    warn "Playbook catalog loader exited non-zero. Rerun manually:"
    warn "  docker compose exec -T backend python scripts/load-playbook-catalog.py"
  fi

  # Knowledge base: ~349 articles. A handful (~49) use content_type values
  # ('guide'/'checklist') that the DB CHECK constraint rejects; those rows are
  # skipped individually and the rest (~300) load fine. This is expected and
  # not fatal.
  if compose exec -T backend python scripts/load-kb-direct.py kb-content-output/articles; then
    log "Knowledge base seeded (a few articles with unsupported content_type may be skipped)."
  else
    warn "KB loader exited non-zero. Rerun manually:"
    warn "  docker compose exec -T backend python scripts/load-kb-direct.py kb-content-output/articles"
  fi

  log "Content seeding done. Intake-form templates are built in (served from"
  log "the API) and need no seeding."
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
  write_config_yaml "${1:-}"

  # Load whatever we just wrote so the success banner can reference it.
  # shellcheck disable=SC1091
  set -a; . ./.env; set +a

  bring_up
  done_msg
}

main "$@"
