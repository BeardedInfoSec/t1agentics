# T1 Agentics — Architecture Overview

A short orientation for anyone landing in this repo for the first time. If you want to install, read [README.md](README.md) and [INSTALL.md](INSTALL.md) instead.

## What this is

T1 Agentics is a self-hosted, multi-tenant SOC platform. An alert comes in from one of your security tools, the platform triages it (with help from an AI assistant if you have configured one), routes it through an investigation workbench, and runs containment or remediation through 700+ pre-built connectors.

It is built for environments where one operator manages more than one customer or tenant — MSPs, security consultancies, in-house teams running multiple business units. Tenants are isolated at the database layer with Row-Level Security, not just at the application layer.

## High-level layout

```
                       Internet
                          |
                       Caddy
                  (TLS, reverse proxy)
                          |
            +-------------+-------------+
            |                           |
        Frontend                     Backend
        React 18 SPA               FastAPI / Python 3.11
        served by nginx           async, asyncpg, RLS-aware
                                       |
            +------------+--------------+------------+
            |            |              |            |
        PostgreSQL    Redis        ClickHouse    Outbound
        primary,      sessions,    UX telemetry, connectors
        RLS-enforced  rate limit,  event volume  (700+)
                      job queue
```

All four data services run in Docker Compose. Caddy obtains TLS certificates from Let's Encrypt automatically once DNS resolves.

## Repository layout

The high-traffic subsystems live in predictable places.

### Backend (`backend/`)

```
backend/
├── app.py                  FastAPI app entrypoint, startup hooks, migration runner
├── agents/                 AI assistant (alert triage, deep investigation)
├── reasoning_engine/       Multi-step reasoning loops, hypothesis testing, tool brokering
├── services/               ~50 service modules — auth, billing, integrations, playbook engine
├── routes/                 HTTP route handlers, grouped by domain
├── middleware/             Tenant context, CSRF, security headers, rate limiting
├── migrations/             Numbered SQL migrations, applied automatically on startup
├── integrations/           Connector engines, credential vault, polling/webhook ingest
├── platform_core/          Audit, retention, RBAC (uses SQLAlchemy; everything else is asyncpg)
└── dependencies/           FastAPI dependencies — auth, license gates, tenant resolution
```

The AI assistant code paths all flow through a single service wrapper that enforces per-tenant token quotas, a daily spend kill-switch, and sensitive-field redaction before any outbound call. If you are looking for "where does the AI call actually happen," start at `backend/services/` and follow the wrapper.

### Frontend (`frontend/`)

```
frontend/
├── src/components/         Reusable UI components
│   ├── SecurityQueue/      Unified triage queue
│   ├── Investigation/      Workbench, action bar, classification controls
│   ├── PlaybookCanvas/     Visual playbook editor (node-graph canvas)
│   └── ...
├── src/pages/              Top-level routes
│   ├── public/             Marketing / docs / contact (served at the root domain)
│   └── tenant/             Authenticated tenant-scoped pages
├── public/                 Static assets, SEO files (sitemap.xml, robots.txt)
└── nginx.prod.conf         Production nginx config
```

The frontend is a single-page React 18 app. No global state management library — local state plus a small number of contexts. Code-split with `React.lazy`.

### Content (`integration-store-output/`, `playbook-store-output/`, `kb-content-output/`)

These three directories ship the built-in content packs that come with a fresh install:

- **Connectors** — 700+ integrations across 30 categories, each a directory with a manifest, action handlers, and credential schema.
- **Playbooks** — 200 templates across 13 SOC domains, each a JSON file describing a canvas graph.
- **Knowledge base** — 349 markdown articles with YAML frontmatter, indexed at install time.

These are versioned content, not application code. Adding to any of them is a friendly first contribution — see [CONTRIBUTING.md](CONTRIBUTING.md).

### Other things to know about

- `docker-compose.yml` — local development stack.
- `docker-compose.yml` — production stack with TLS via Caddy. `docker-compose.dev.yml` is the local development stack.
- `scripts/` — backup, restore, maintenance, and developer utilities. `install.sh` at the repo root is what `curl | bash` runs.
- `docs/` — engineering and operator documentation; see below.

## Documentation

The `docs/` directory contains the operator and engineering guides that ship with the project:

- `docs/ADMIN-GUIDE.md` — platform administration.
- `docs/USER-GUIDE.md` — analyst workflows.
- `docs/API-REFERENCE.md` — REST API surface.
- `docs/multi-tenant-architecture.md` — how tenancy and RLS fit together.
- `docs/SECURITY.md` and `docs/AI-DATA-GOVERNANCE.md` — security model and data handling.
- `docs/guides/` — focused setup guides (HTTPS, frontend dev, API auth, security developer notes).

Pick the file relevant to what you are working on. There is no need to read them in order.

## Stack at a glance

- **Backend** — Python 3.11, FastAPI, asyncpg, asyncio. Migrations apply on startup.
- **Frontend** — React 18, React Flow for the playbook canvas, react-grid-layout for the workbench.
- **Database** — PostgreSQL 15 with Row-Level Security; ClickHouse for event volume and telemetry; Redis for sessions and the job queue.
- **TLS** — Caddy fronts the stack and gets Let's Encrypt certificates automatically.
- **AI** — vendor-neutral wrapper. You bring your own LLM provider API key; without one, AI features are off and everything else works.
- **Packaging** — Docker Compose. No Kubernetes required.

## Where to go next

- Operator first time? Start at [INSTALL.md](INSTALL.md).
- Engineer first time? Skim this file for the request lifecycle and where things live, then dive into whichever subsystem you are touching under `docs/`.
- Contributor first time? Start at [CONTRIBUTING.md](CONTRIBUTING.md).
