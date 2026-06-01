# T1 Agentics

> Open-source, self-hosted, multi-tenant SOC platform with AI-assisted triage.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-informational.svg)](#)
[![GitHub](https://img.shields.io/badge/GitHub-t1agentics-181717.svg)](https://github.com/BeardedInfoSec/t1agentics)

T1 Agentics is a security operations platform you run on your own infrastructure. It ingests alerts from your existing tools, triages them with an AI assistant of your choice, walks investigations through a structured workbench, and runs remediation through 700+ pre-built connectors. It is multi-tenant from the database up, which makes it useful for MSPs, security consultancies, and in-house teams that operate more than one environment.

---

## Quick install

Runs on **Linux, macOS, or Windows** — anywhere Docker runs. With Docker installed:

```bash
git clone https://github.com/BeardedInfoSec/t1agentics
cd t1agentics
./install.sh
```

- **Linux** — Docker Engine 20.10+ and the Compose plugin.
- **macOS** — Docker Desktop for Mac.
- **Windows** — Docker Desktop with the WSL2 backend; run the commands inside your WSL2 (Ubuntu) shell.

`install.sh` runs preflight checks, prompts for your domain and an optional LLM provider key, generates secrets, writes a `.env`, builds the images, and starts the stack. The web UI comes up on port 443 once DNS resolves. For a production deployment with automatic TLS, use a Linux host with a public domain. See [INSTALL.md](INSTALL.md) for the step-by-step flow.

---

## Run without Docker (experimental)

Don't want to run Docker? There's a single-process native mode that boots an embedded PostgreSQL (shipped as a pip wheel — no system Postgres, no admin rights) and serves the whole app (UI + API + WebSocket) on one port. Needs **Python 3.11 or 3.12** and Node (to build the frontend once).

```bash
git clone https://github.com/BeardedInfoSec/t1agentics
cd t1agentics
./run-native.sh            # Linux / macOS
#   .\run-native.ps1       # Windows PowerShell
```

It creates a virtualenv, installs dependencies, builds the frontend, starts a local Postgres under `./.native/`, and opens `http://localhost:8000`. Redis and ClickHouse are off in this mode (the app falls back gracefully). This is the easiest way to try it on a laptop — no Docker Desktop, no WSL2. Docker Compose remains the path for production multi-tenant deployments with automatic TLS.

---

## What you get

- **Multi-tenant from day one.** Row-level security enforced at the database layer. A tenant context is set on every connection acquire; cross-tenant leaks require defeating both the app-layer auth check and the database policy.
- **700+ pre-built connectors** across SIEM, EDR, firewall, cloud, ticketing, email security, deception, and threat intel categories.
- **200 playbook templates** covering 13 SOC domains. Visual editor on a node-graph canvas. Import/export converters for several legacy SOAR formats.
- **349 knowledge-base articles** with full-text search and optional semantic search (pgvector).
- **AI-assisted triage** that reads the alert, correlates entities, scores the verdict, and proposes concrete actions mapped to connectors you actually have installed. Bring your own LLM provider API key.
- **Investigation workbench** with inline classification (disposition, priority, severity, assignee), a unified queue, and customizable per-dashboard columns.
- **Pause-and-collect playbook forms** for analyst input mid-flow, with HMAC-signed public URLs for external participants.
- **RBAC, RLS, audit logs.** Every privileged operation is logged. Every tenant-scoped query is gated.
- **All in Docker Compose.** One file, one stack, no Kubernetes required.

---

## Requirements

- 8 GB RAM minimum (16 GB recommended for multi-tenant workloads)
- 500 GB disk (event history, alert raw payloads, and knowledge-base index grow over time)
- Docker 20.10+ and Docker Compose v2
- Docker host: Linux (Ubuntu 22.04 LTS+ is the tested baseline; recent Debian, Fedora, RHEL work), macOS (Docker Desktop), or Windows (Docker Desktop + WSL2). Linux is recommended for production.
- A domain name with DNS pointing to your host (required for automatic TLS)
- An LLM provider API key (optional but strongly recommended — AI features are off without one)

The installer enforces the RAM and disk checks and prints a clear error if your host is under-provisioned.

---

## Bring your own API key

T1 Agentics does not ship with a default LLM provider key. You supply your own.

- If no key is configured, the AI triage, investigation assistant, and recommended-actions features are disabled. Everything else (ingestion, queue, manual investigation, playbook execution, connectors) works fine.
- To enable AI features, set your key in `.env` and bring the stack up:

  ```bash
  # Edit .env, set the provider key for your chosen provider
  nano .env

  # Apply
  docker compose up -d
  ```

- To rotate a key: edit `.env`, run `docker compose up -d` (a `restart` alone will not reload env vars).
- Per-tenant keys can be configured from the admin UI under **Settings to AI Provider** if you want each tenant to bill against its own account.

The provider you choose is up to you. The platform speaks to several common providers through a vendor-neutral wrapper; pick the one your organization is comfortable with.

---

## Architecture

```
                       Caddy (TLS, reverse proxy)
                                |
            +-------------------+--------------------+
            |                                        |
        Frontend                                  Backend
        (React, nginx)                       (FastAPI, Python 3.11)
                                                  |
            +-------------+----------+-------------+
            |             |          |             |
        PostgreSQL     Redis     ClickHouse    Connectors
        (primary)    (sessions,  (telemetry,   (outbound to
                      queue)     event volume) your stack)
```

- **Backend** — FastAPI on Python 3.11, asyncpg, asyncio throughout. Migrations apply on startup; no separate migrate step.
- **Frontend** — React 18 single-page app served by nginx. Visual playbook editor built on a node-graph canvas.
- **Databases** — PostgreSQL 15 (primary, with RLS), Redis 7 (sessions, rate limiting, queue), ClickHouse (UX telemetry, high-volume event ingest).
- **TLS** — Caddy fronts the stack and obtains Let's Encrypt certificates automatically when your domain DNS resolves to the host.
- **Everything in Docker Compose.** One stack file, one `up -d`.

For a deeper tour, see [OVERVIEW.md](OVERVIEW.md) and the engineering docs under [docs/](docs/).

---

## Configuration

All configuration is driven by environment variables in `.env` at the repo root. Copy `.env.example` and edit:

```bash
cp .env.example .env
nano .env
```

The most important variables:

- `JWT_SECRET_KEY` — required, generate with `openssl rand -hex 32`
- `INTEGRATION_ENCRYPTION_KEY` — required, encrypts tenant credentials at rest
- `POSTGRES_PASSWORD` — required, set a strong value
- `BASE_URL` — required, the public URL of your install
- LLM provider key — optional but recommended for AI features

Full reference and post-install tuning live in [INSTALL.md](INSTALL.md).

---

## Upgrading

```bash
t1 upgrade
```

The `t1` helper script pulls the latest images, applies any pending migrations, and restarts the stack with zero data loss. Run `t1 upgrade --dry-run` first if you want to see what would change.

If you prefer to drive Docker Compose directly:

```bash
docker compose pull
docker compose up -d
```

---

## Backup

```bash
t1 backup
```

Writes a timestamped archive containing a Postgres dump, the ClickHouse data directory, the credentials vault, and the configuration files. Restore with `t1 restore <path>`.

For offsite backups, schedule `t1 backup --output /mnt/your-mount/` from cron.

---

## Community and support

- **Bugs:** [GitHub Issues](https://github.com/BeardedInfoSec/t1agentics/issues)
- **Questions, ideas, show-and-tell:** [GitHub Discussions](https://github.com/BeardedInfoSec/t1agentics/discussions)
- **Security disclosures:** see [SECURITY.md](SECURITY.md) — please do not file public issues for vulnerabilities

---

## License

Apache License 2.0. See [LICENSE](LICENSE).

You can use T1 Agentics for any purpose, modify it, and redistribute it. We ask that you keep the attribution and license headers intact.

---

## Contributing

We accept bug fixes, connector additions, playbook templates, knowledge-base articles, documentation improvements, and well-scoped feature work. See [CONTRIBUTING.md](CONTRIBUTING.md) for the workflow.
