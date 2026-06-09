# Installing T1 Agentics

This is the full install reference. For the short version, see the Quick start section in [README.md](README.md). For the config-file reference see [CONFIGURATION.md](CONFIGURATION.md); for problems see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Requirements

Recap from the README — install fails fast if these are not met:

- 8 GB RAM minimum (16 GB recommended)
- 120 GB disk minimum
- Docker 20.10+ and Docker Compose v2
- A Docker host on Linux, macOS (Docker Desktop), or Windows (Docker Desktop + WSL2). Linux is recommended for production.
- A domain name with DNS pointing to your host (for automatic TLS in production)
- An LLM provider API key (optional, AI features are off without it)

---

## Option A: guided installer

On Linux, macOS, or Windows with Docker installed:

```bash
git clone https://github.com/BeardedInfoSec/t1agentics
cd t1agentics
./install.sh
```

Per-OS prerequisites:

- **Linux** — Docker Engine 20.10+ and the Compose plugin.
- **macOS** — Docker Desktop for Mac. Run the commands in Terminal.
- **Windows** — Docker Desktop with the WSL2 backend enabled. Run the commands inside a WSL2 (Ubuntu) shell, not PowerShell or `cmd` — `install.sh` is a bash script and the WSL2 backend is what runs the containers.

What it does, in order:

1. Runs preflight checks (supported OS, Docker daemon reachable, RAM ≥ 8 GB, disk ≥ 120 GB, ports 80/443 free)
2. Prompts for your domain, admin email + password, an optional AI provider, organization name/slug, license tier, and optional SMTP
3. Generates random values for every required secret and writes **`.env`** (mode 600)
4. Writes **`t1.config.yaml`** from your answers — the single-file app config the backend applies on startup (see [CONFIGURATION.md](CONFIGURATION.md))
5. Builds the images and brings the stack up with `docker compose up -d`. Postgres initializes its schema from `native-schema.sql` on first boot
6. Bootstraps the first platform admin (`scripts/bootstrap_platform_admin.py`; password from `ADMIN_PASSWORD`)
7. Seeds the built-in content libraries — playbook marketplace and knowledge base (best-effort; see [Seeding built-in content](#seeding-built-in-content))
8. Prints the URL and next-step pointers

It expects Docker already installed (it will not install Docker for you). Re-running is safe: it reuses an existing `.env`/`t1.config.yaml` unless you pass `--reset`. Read `install.sh` in the repo first if you want to see exactly what runs.

---

## Option B: manual install

Three steps. No installer.

```bash
# 1. Clone
git clone https://github.com/BeardedInfoSec/t1agentics.git /opt/t1agentics
cd /opt/t1agentics

# 2. Configure
cp .env.example .env
# Generate secrets and edit values:
#   JWT_SECRET_KEY=$(openssl rand -hex 32)
#   INTEGRATION_ENCRYPTION_KEY=$(openssl rand -hex 32)
#   FORM_TOKEN_SECRET=$(openssl rand -hex 32)
#   POSTGRES_PASSWORD=<a strong password>
#   BASE_URL=https://your-domain.com
nano .env

# 3. Start
docker compose up -d
```

Migrations apply on backend startup; no separate step.

Watch the logs while it warms up:

```bash
docker compose logs -f backend
```

The backend is ready when you see `Application startup complete`.

**Optional: app config file.** Copy the template to drive org identity, license tier, AI provider, admin, triage taxonomy, and SMTP from one place (applied idempotently on every backend startup):

```bash
cp t1.config.yaml.example t1.config.yaml
nano t1.config.yaml          # set org/license/ai; secrets stay in .env as ${ENV_VAR}
docker compose up -d backend
```

See [CONFIGURATION.md](CONFIGURATION.md) for the full reference. The file is optional — absent, startup is a clean no-op.

A manual install does **not** seed the content libraries or bootstrap the admin. After the backend is up, run:

```bash
docker compose exec -T backend python scripts/bootstrap_platform_admin.py
```

then seed content as described in [Seeding built-in content](#seeding-built-in-content) below.

---

## Option C: native mode (no Docker, experimental)

A single-process mode that boots an **embedded PostgreSQL** (shipped as a pip wheel — no system Postgres, no admin rights) and serves the whole app (UI + API + WebSocket) on one port. Good for trying it on a laptop. Needs **Python 3.11 or 3.12** and Node (to build the frontend once). Redis and ClickHouse are off in this mode; the app falls back gracefully.

```bash
git clone https://github.com/BeardedInfoSec/t1agentics
cd t1agentics
./run-native.sh            # Linux / macOS
# .\run-native.ps1         # Windows PowerShell
```

The script creates a virtualenv under `./.native/`, installs `backend/requirements.txt` + `requirements-native.txt`, builds the frontend if `frontend/build/` is missing, starts the embedded Postgres, and opens `http://localhost:8000`. Docker Compose remains the path for production multi-tenant deployments with automatic TLS.

---

## Seeding built-in content

The repo ships two content libraries: a 200-template **playbook marketplace** and a ~349-article **knowledge base**. The guided installer seeds both automatically (step 6). They come up empty if you ran a manual `docker compose up -d`, and you can always re-seed.

Both seeders are idempotent — the playbook loader upserts on conflict, and the KB loader skips articles that already exist by title.

The content and seed scripts live at the **repo root** (`playbook-store-output/`, `kb-content-output/`, `scripts/`), but the backend image is built from `./backend`, so they are not inside the container by default. Copy them in first, then run the loaders:

```bash
# Stage the seed scripts and content inside the backend container
docker compose cp scripts/load-playbook-catalog.py backend:/app/scripts/load-playbook-catalog.py
docker compose cp scripts/load-kb-direct.py        backend:/app/scripts/load-kb-direct.py
docker compose cp playbook-store-output            backend:/app/playbook-store-output
docker compose cp kb-content-output                backend:/app/kb-content-output

# Playbook marketplace: 200 builtin templates (visible to every tenant)
docker compose exec -T backend python scripts/load-playbook-catalog.py

# Knowledge base: loads from kb-content-output/articles
docker compose exec -T backend python scripts/load-kb-direct.py kb-content-output/articles
```

**Expected KB caveat.** Roughly 49 of the 349 articles use a `content_type` (`guide` or `checklist`) that the current database CHECK constraint does not allow. Those rows are skipped individually — the loader reports them as `FAIL` and continues — so about 300 articles load. This is expected and harmless; the playbook marketplace is unaffected.

**Intake forms are built in.** The 20 intake-form templates are bundled in the backend (`backend/data/intake_form_templates/*.json`) and served live from the API. They need no seeding; the `intake_forms` table stays empty until a tenant instantiates a form.

---

## First login

Default admin credentials are written to `.env` during install (look for `ADMIN_USERNAME` and `ADMIN_PASSWORD`). If you used the one-command installer, the values are printed at the end of the install output.

1. Open `https://your-domain.com` (or `http://localhost:3000` for a local dev setup)
2. Log in as the admin user
3. **Immediately change the admin password** under your profile menu
4. Create your first tenant from the platform admin view

If you forget the admin password before changing it, reset it directly in the database:

```bash
docker compose exec postgres psql -U agentcore -d agentcore -c \
  "UPDATE users SET failed_login_attempts=0, locked_until=NULL WHERE username='admin';"
```

Then use the **Forgot password** flow or reset the bcrypt hash with the admin CLI.

---

## DNS and TLS

T1 Agentics ships with Caddy fronting the stack. Caddy obtains a Let's Encrypt certificate automatically when:

1. Your domain's A record (and AAAA if you use IPv6) points to the host's public IP
2. Ports 80 and 443 are reachable from the public internet
3. `BASE_URL` in `.env` matches the domain you are using

Verify DNS resolves to the right host:

```bash
dig +short your-domain.com
```

If Caddy cannot get a certificate, check `docker compose logs caddy` — the most common causes are unresolved DNS, a firewall blocking port 80, or a stale A record from a previous host.

For internal-only deployments (no public DNS), use your own reverse proxy with an internal certificate authority and point the stack at it instead.

---

## Adding an AI provider after install

The platform comes up with no AI provider configured — AI-assisted triage, the Riggs assistant, and recommended actions are disabled until you set one. Everything else works without it.

Configure the provider in the `ai.chat` section of `t1.config.yaml`, then apply:

```bash
nano t1.config.yaml
docker compose up -d backend     # a bare 'restart' does NOT reload .env
```

Three supported shapes:

- **Local OpenAI-compatible (Ollama / vLLM / LM Studio)** — `provider: self_hosted`, `api_style: openai`, `base_url: http://host.docker.internal:<port>`. The backend reaches the host via `extra_hosts: host.docker.internal:host-gateway` (set in the shipped compose); start Ollama with `OLLAMA_HOST=0.0.0.0` so the container can reach it.
- **Anthropic cloud** — `provider: anthropic`, `api_style: anthropic`, key from `${ANTHROPIC_API_KEY}` in `.env`.
- **OpenAI cloud** — `provider: openai`, `api_style: openai`, key from `.env`.

You can also set the provider in **Settings → AI** in the UI. Full worked examples (including embeddings) are in [CONFIGURATION.md → Configure AI](CONFIGURATION.md#configure-ai).

---

## Adding tenants

From the command line:

```bash
t1 tenant create --name "Acme Corp" --slug acme --admin-email admin@acme.com
```

The command creates the tenant, provisions the schema, generates an initial admin user, and prints a one-time invite link.

From the UI: log in as the platform admin, open **Platform to Tenants**, click **New Tenant**, and fill in the form. The same invite link appears in the success modal.

---

## Upgrading

```bash
t1 upgrade
```

This:

1. Pulls the latest images
2. Runs `docker compose up -d` so any pending migrations apply
3. Tails logs until the backend reports ready

Add `--dry-run` to see which images would change without pulling.

If you prefer to drive Docker Compose directly:

```bash
cd /opt/t1agentics
git pull
docker compose pull
docker compose up -d
docker compose logs -f backend
```

We try hard to keep migrations forward-compatible, but always run `t1 backup` first.

---

## Backup and restore

```bash
# Make a backup
t1 backup

# Restore from a backup
t1 restore /var/lib/t1agentics/backups/2026-05-23T1200Z.tar.gz
```

`t1 backup` writes a timestamped tarball containing:

- Postgres dump (`pg_dump`, custom format)
- ClickHouse data directory
- Encrypted credentials vault
- `.env` and any custom Caddy config

Default destination is `/var/lib/t1agentics/backups/`. Override with `--output /path/`.

For offsite backups, schedule it from cron:

```cron
0 3 * * * /usr/local/bin/t1 backup --output /mnt/backups/
```

Manual Postgres-only fallback (if the helper script is unavailable):

```bash
docker compose exec postgres pg_dump -U agentcore -Fc agentcore > backup.dump
```

Restore:

```bash
docker compose exec -T postgres pg_restore -U agentcore -d agentcore --clean --if-exists < backup.dump
```

---

## Troubleshooting

For the full symptom → cause → fix guide (AI not configured, mixed-content behind a proxy, empty marketplace/KB, missing deep analysis, GPU/AVX, LAN TLS, admin-password resets, and more) see **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)**. A few install-time issues:

**Caddy cannot get a certificate.** Check DNS first: `dig +short your-domain.com` should print your host's public IP. Check that ports 80 and 443 are reachable from the public internet (not just the LAN). Inspect logs with `docker compose logs caddy`.

**RAM check fails during install.** The platform needs 8 GB. Resize the VM and retry. If you really must run on less, you can bypass the check with `T1_SKIP_RAM_CHECK=1 bash install.sh` but expect slow performance, OOM kills under load, and no support.

**Port conflicts.** If port 80 or 443 is already in use, the install fails with an explicit message. Stop the conflicting service:

```bash
sudo systemctl stop nginx apache2
```

Or change the published ports in `docker-compose.yml` and re-run `docker compose up -d`.

**Backend keeps restarting.** Almost always a missing required secret in `.env`. Check `docker compose logs backend` for the specific variable name and set it.

**Frontend loads but APIs return 401.** Likely a cookie domain mismatch — `BASE_URL` in `.env` must match the URL you are actually visiting (including the scheme).

**Migrations fail on first start.** Check `docker compose logs backend` for the failing migration number. If the database is empty, it is usually safe to `docker compose down -v` and start over. If you have data, file an issue with the migration number and the full error.

---

## Uninstalling

```bash
cd /opt/t1agentics
docker compose down -v
cd ..
rm -rf t1agentics
```

`docker compose down -v` removes the named volumes, which destroys all data. There is no second confirmation. Make a backup first if you might want it back.
