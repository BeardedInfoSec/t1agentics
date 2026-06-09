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

# Run privileged commands with sudo only when not already root.
SUDO=""
if [[ "$(id -u)" -ne 0 ]] && command -v sudo >/dev/null 2>&1; then SUDO="sudo"; fi

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

  # Unattended / one-shot mode: take every answer from T1_* env vars instead of
  # prompting. Required: T1_DOMAIN, T1_ADMIN_EMAIL, T1_ADMIN_PASSWORD. Everything
  # else has a sensible self-hosted default (local Ollama, platform tier).
  if [[ "${T1_UNATTENDED:-}" == "1" ]]; then
    log "Unattended mode: reading configuration from T1_* environment variables."
    DOMAIN="${T1_DOMAIN:?T1_DOMAIN is required in unattended mode}"
    ADMIN_EMAIL="${T1_ADMIN_EMAIL:?T1_ADMIN_EMAIL is required in unattended mode}"
    ADMIN_PASSWORD="${T1_ADMIN_PASSWORD:?T1_ADMIN_PASSWORD is required (min 12 chars)}"
    ANTHROPIC_API_KEY="${T1_ANTHROPIC_API_KEY:-}"
    ORG_NAME="${T1_ORG_NAME:-T1 Agentics}"
    ORG_SLUG="${T1_ORG_SLUG:-t1-agentics}"
    LICENSE_TIER="${T1_LICENSE_TIER:-platform}"
    AI_CHAT_PROVIDER="${T1_AI_CHAT_PROVIDER:-self_hosted}"
    AI_CHAT_API_STYLE="${T1_AI_CHAT_API_STYLE:-openai}"
    AI_CHAT_BASE_URL="${T1_AI_CHAT_BASE_URL:-http://host.docker.internal:11434}"
    AI_CHAT_MODEL="${T1_AI_CHAT_MODEL:-qwen2.5:7b-instruct}"
    AI_CHAT_API_KEY="${T1_AI_CHAT_API_KEY:-}"
    SMTP_HOST="${T1_SMTP_HOST:-}"
    SMTP_PORT="${T1_SMTP_PORT:-587}"
    SMTP_USERNAME="${T1_SMTP_USERNAME:-}"
    SMTP_PASSWORD="${T1_SMTP_PASSWORD:-}"
    SMTP_FROM_EMAIL="${T1_SMTP_FROM_EMAIL:-}"
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

  # TLS mode - ask, defaulting to whatever the domain looks like.
  local _tls_default; _tls_default="$(detect_tls_default)"
  echo
  if [[ "$_tls_default" == "internal" ]]; then
    echo "  '$DOMAIN' looks like an internal/LAN name."
  else
    echo "  '$DOMAIN' looks like a public domain."
  fi
  echo "    internal = Caddy's own CA; works on a LAN with no public DNS (clients"
  echo "               get a self-signed cert until they trust the root CA)."
  echo "    public   = Let's Encrypt; needs a public domain + ports 80/443 open."
  while :; do
    read -rp "TLS mode (internal/public) [$_tls_default]: " TLS_MODE
    TLS_MODE="$(printf '%s' "${TLS_MODE:-$_tls_default}" | tr '[:upper:]' '[:lower:]')"
    [[ "$TLS_MODE" == internal || "$TLS_MODE" == public ]] && break
    echo "  -> enter 'internal' or 'public'."
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
  read -rp "Organization name [T1 Agentics]: " ORG_NAME
  ORG_NAME="${ORG_NAME:-T1 Agentics}"
  read -rp "Organization slug [t1-agentics]: " ORG_SLUG
  ORG_SLUG="${ORG_SLUG:-t1-agentics}"

  echo
  echo "License tier. Self-hosted installs are unlimited (platform)."
  read -rp "License tier [platform]: " LICENSE_TIER
  LICENSE_TIER="${LICENSE_TIER:-platform}"

  echo
  echo "AI assistant (Riggs triage + analysis). Where should the model run?"
  echo "    1) Local LLM   - Ollama / LM Studio on this host. Private, no API key;"
  echo "                     the installer sets up Ollama and pulls the model."
  echo "    2) Third-party - a cloud API (Anthropic or OpenAI). Bring your own key."
  echo "    3) None        - install without AI; enable later in Settings."
  local _ai
  while :; do
    read -rp "AI option [1]: " _ai; _ai="${_ai:-1}"
    [[ "$_ai" =~ ^[123]$ ]] && break
    echo "  -> enter 1, 2, or 3."
  done

  ANTHROPIC_API_KEY=""
  if [[ "$_ai" == "1" ]]; then
    AI_CHAT_PROVIDER="self_hosted"; AI_CHAT_API_STYLE="openai"; AI_CHAT_API_KEY=""
    echo "  Local server (OpenAI-compatible). Default is Ollama on this host."
    read -rp "  Base URL [http://host.docker.internal:11434]: " AI_CHAT_BASE_URL
    AI_CHAT_BASE_URL="${AI_CHAT_BASE_URL:-http://host.docker.internal:11434}"
    read -rp "  Model [qwen2.5:7b-instruct]: " AI_CHAT_MODEL
    AI_CHAT_MODEL="${AI_CHAT_MODEL:-qwen2.5:7b-instruct}"
  elif [[ "$_ai" == "2" ]]; then
    local _vendor
    while :; do
      read -rp "  Vendor (anthropic/openai) [anthropic]: " _vendor
      _vendor="$(printf '%s' "${_vendor:-anthropic}" | tr '[:upper:]' '[:lower:]')"
      [[ "$_vendor" == anthropic || "$_vendor" == openai ]] && break
      echo "    -> enter 'anthropic' or 'openai'."
    done
    read -rsp "  API key: " AI_CHAT_API_KEY; echo
    if [[ "$_vendor" == "anthropic" ]]; then
      AI_CHAT_PROVIDER="anthropic"; AI_CHAT_API_STYLE="anthropic"; AI_CHAT_BASE_URL=""
      read -rp "  Model [claude-sonnet-4-5-20250929]: " AI_CHAT_MODEL
      AI_CHAT_MODEL="${AI_CHAT_MODEL:-claude-sonnet-4-5-20250929}"
      ANTHROPIC_API_KEY="$AI_CHAT_API_KEY"
    else
      AI_CHAT_PROVIDER="openai"; AI_CHAT_API_STYLE="openai"
      AI_CHAT_BASE_URL="https://api.openai.com/v1"
      read -rp "  Model [gpt-4o]: " AI_CHAT_MODEL
      AI_CHAT_MODEL="${AI_CHAT_MODEL:-gpt-4o}"
    fi
  else
    AI_CHAT_PROVIDER="none"; AI_CHAT_API_STYLE=""; AI_CHAT_BASE_URL=""
    AI_CHAT_MODEL=""; AI_CHAT_API_KEY=""
    warn "AI disabled. Configure ai.chat in t1.config.yaml later, then 'docker compose up -d backend'."
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

# Pure domain heuristic: echo "internal" for a private/LAN name, else "public".
# Used as the smart default for the interactive prompt and for auto mode.
detect_tls_default() {
  local d; d="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
  if [[ "$d" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ "$d" != *.* ]] \
     || [[ "$d" == *.lan || "$d" == *.local || "$d" == *.localdomain \
        || "$d" == *.internal || "$d" == *.intranet || "$d" == *.home \
        || "$d" == *.lab || "$d" == *.corp || "$d" == *.test ]]; then
    echo internal
  else
    echo public
  fi
}

# Resolve the final TLS mode and set CADDY_TLS. Precedence: an explicit choice
# (the interactive prompt or T1_TLS_MODE) wins; otherwise auto-detect from the
# domain. Public ACME only works for a publicly-resolvable domain; a LAN host
# must use Caddy's own CA or HTTPS never comes up. CADDY_TLS is "internal"
# (Caddy's CA) or the admin email (which switches Caddy to public ACME).
determine_tls_mode() {
  local mode
  mode="$(printf '%s' "${TLS_MODE:-${T1_TLS_MODE:-auto}}" | tr '[:upper:]' '[:lower:]')"
  [[ "$mode" == "auto" ]] && mode="$(detect_tls_default)"
  case "$mode" in
    public|acme|letsencrypt) CADDY_TLS="$ADMIN_EMAIL" ;;
    *)                       CADDY_TLS="internal" ;;
  esac
}

write_env() {
  if [[ -f .env && "${1:-}" != "--reset" ]]; then
    return 0
  fi

  determine_tls_mode
  if [[ "$CADDY_TLS" == "internal" ]]; then
    log "TLS: '$DOMAIN' looks internal -> using Caddy's built-in CA (no public cert)."
  else
    log "TLS: '$DOMAIN' looks public -> using Let's Encrypt (ACME)."
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
# TLS: "internal" = Caddy's own CA (LAN/private domains); an email = public ACME.
CADDY_TLS=${CADDY_TLS}
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

  local AI_SECTION
  if [[ -n "${AI_CHAT_PROVIDER:-}" && "${AI_CHAT_PROVIDER}" != "none" ]]; then
    AI_SECTION=$(cat <<AICFG
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
AICFG
)
  else
    AI_SECTION=$(cat <<AICFG
ai:
  chat:
    provider: "none"
  embeddings:
    provider: "disabled"
AICFG
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

${AI_SECTION}

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
  # World-readable so the backend container (different uid) can read it on
  # startup. It holds no secrets - those are ${ENV_VAR} references into .env.
  chmod 644 t1.config.yaml
  log "t1.config.yaml written."
}

# ---------------------------------------------------------------------------
# Compose + bootstrap
# ---------------------------------------------------------------------------
compose() { docker compose --env-file "$REPO_DIR/.env" "$@"; }

bring_up() {
  log "Pulling base images..."
  # --ignore-buildable skips backend/frontend (built locally from ./), so we
  # don't try to pull t1agentics/*:local from a registry that has no such image.
  # --ignore-pull-failures keeps a flaky base-image mirror from aborting install.
  compose pull --ignore-buildable --ignore-pull-failures || true

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

  # The base schema (init-db.sql) already creates the current schema, so the
  # historical migrations conflict with it and the runner warns about them on
  # every connect. Mark them applied now so the steps below (and future
  # restarts) are quiet. Harmless if it no-ops.
  log "Reconciling migration tracking..."
  compose exec -T backend python scripts/fix_migration_tracking.py 2>/dev/null || \
    warn "Could not reconcile migration tracking (non-fatal)."

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
  Login:  username 'admin', organization '${ORG_SLUG:-t1-agentics}'
          (admin email on file: ${ADMIN_EMAIL})

  Useful commands:
    docker compose ps              - service status
    docker compose logs -f         - tail all logs
    ./bin/t1 logs backend          - tail one service
    ./bin/t1 backup                - snapshot db + caddy data

DONE
  if [[ "${CADDY_TLS:-internal}" == "internal" ]]; then
    local host_ip
    host_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    cat <<DONETLS

  TLS: '${DOMAIN}' is a private/internal name, so HTTPS uses Caddy's built-in
  CA (no public certificate). To reach it from another machine:
    1. Make '${DOMAIN}' resolve to this host - e.g. add to the client's hosts
       file:   ${host_ip:-<this-host-ip>}  ${DOMAIN}
    2. The browser will warn about the self-signed cert - accept it, or trust
       the root CA to silence the warning:
         docker compose exec caddy cat \\
           /data/caddy/pki/authorities/local/root.crt > t1-root-ca.crt
       then import t1-root-ca.crt into the client's OS/browser trust store.
DONETLS
  else
    cat <<DONETLS

  Cert provisioning can take up to a minute on first boot.
  If https://${DOMAIN} does not load, check 'docker compose logs caddy'
  and confirm the domain's public DNS A record points at this host.
DONETLS
  fi
  if [[ -n "${AI_CHAT_PROVIDER:-}" && "${AI_CHAT_PROVIDER}" != "none" ]]; then
    cat <<DONEAI

  AI is configured via t1.config.yaml: provider '${AI_CHAT_PROVIDER}',
  model '${AI_CHAT_MODEL:-}' at '${AI_CHAT_BASE_URL:-}'.
  Edit t1.config.yaml and run 'docker compose up -d backend' to change it.
DONEAI
  elif [[ -z "${ANTHROPIC_API_KEY:-}" ]]; then
    cat <<DONEAI

  AI features are OFF. Configure an AI provider in t1.config.yaml (ai.chat)
  and run 'docker compose up -d backend' to enable them.
DONEAI
  fi
}

# ---------------------------------------------------------------------------
# Local AI (Ollama) - turnkey setup so AI works on first boot
# ---------------------------------------------------------------------------
setup_ollama() {
  # Only when the configured chat provider is a local Ollama endpoint (:11434).
  case "${AI_CHAT_PROVIDER:-}" in
    self_hosted|local|ollama) : ;;
    *) return 0 ;;
  esac
  case "${AI_CHAT_BASE_URL:-}" in
    *11434*) : ;;
    *) log "AI base URL '${AI_CHAT_BASE_URL:-}' is not a local Ollama; skipping Ollama setup."; return 0 ;;
  esac

  log "Setting up local Ollama (turnkey AI)..."

  # 1) Install Ollama if it is not already present.
  if ! command -v ollama >/dev/null 2>&1; then
    log "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh || fail "Ollama install failed. See https://ollama.com/download"
  else
    log "Ollama already installed."
  fi

  # 2) Bind Ollama on all interfaces so the backend container can reach it via
  #    host.docker.internal. No-op if it is already bound to 0.0.0.0.
  if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^ollama\.service'; then
    if ! systemctl show ollama -p Environment 2>/dev/null | grep -q 'OLLAMA_HOST=0\.0\.0\.0'; then
      log "Binding Ollama to 0.0.0.0:11434..."
      $SUDO mkdir -p /etc/systemd/system/ollama.service.d
      printf '[Service]\nEnvironment="OLLAMA_HOST=0.0.0.0:11434"\n' | $SUDO tee /etc/systemd/system/ollama.service.d/override.conf >/dev/null
      $SUDO systemctl daemon-reload
      $SUDO systemctl restart ollama
    fi
    $SUDO systemctl enable ollama >/dev/null 2>&1 || true
  fi

  # 3) Wait for the Ollama API to come up.
  log "Waiting for Ollama to respond on :11434..."
  local i
  for i in $(seq 1 30); do
    curl -fsS http://localhost:11434/api/tags >/dev/null 2>&1 && break
    sleep 1
  done

  # 4) Pull the configured model (idempotent).
  local model="${AI_CHAT_MODEL:-qwen2.5:7b-instruct}"
  if ollama list 2>/dev/null | awk 'NR>1{print $1}' | grep -qx "$model"; then
    log "Model '$model' already present."
  else
    log "Pulling model '$model' (this can take several minutes)..."
    ollama pull "$model" || warn "Could not pull '$model'. Pull it later with: ollama pull $model"
  fi
  log "Ollama is ready."
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

  setup_ollama

  bring_up
  done_msg
}

main "$@"
