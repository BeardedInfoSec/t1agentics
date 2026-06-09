# Configuring T1 Agentics

T1 Agentics is configured by a single file at the repo root: **`t1.config.yaml`**. The backend reads it on every startup, expands `${ENV_VAR}` references from its environment, and applies each section **idempotently** to the database. There is no UI clicking and no manual SQL for the common cases.

This is the reference for that file. For installing, see [INSTALL.md](INSTALL.md); for fixing problems, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

---

## How it works

1. Copy the template and edit it:

   ```bash
   cp t1.config.yaml.example t1.config.yaml
   nano t1.config.yaml
   ```

2. Apply your changes by restarting the backend:

   ```bash
   docker compose up -d backend
   ```

Key rules:

- **The file is optional.** If it is absent, startup is a clean no-op. The guided `install.sh` writes one for you.
- **Sections are independent.** Omit a whole section to leave it untouched.
- **Re-applying is safe.** Every section upserts — re-running the same file never creates duplicates.
- **Secrets never live in the file.** Reference them from `.env` with `${ENV_VAR}`. The backend expands them from its environment at load time. Example: `api_key: "${AI_CHAT_API_KEY}"`.
- **The admin password is never in the file.** It is read from `${ADMIN_PASSWORD}` in `.env`, exactly like `scripts/bootstrap_platform_admin.py`. Re-running with a new `ADMIN_PASSWORD` rotates it.

The file is mounted read-only into the backend container at `/app/t1.config.yaml` (see `docker-compose.yml`).

---

## Sections

### `org` — organization identity

Applied to the platform-owner tenant (`tenants.name` / `tenants.slug`). The slug is what you type in the **Organization** field at login.

```yaml
org:
  name: "Acme Security"          # display name
  slug: "acme-security"          # lowercase, url-safe
```

### `license` — license tier

Sets the platform tenant's plan and an active license row. Self-hosted installs should use `platform` (unlimited). Premium features — Riggs deep analysis and recommended actions — require a paid tier; on `free`/`community` they stay disabled.

```yaml
license:
  tier: "platform"
```

Accepted values (friendly aliases on the left, DB plan on the right):

| You write | Maps to |
| --- | --- |
| `free`, `community` | `community` |
| `starter` | `starter` |
| `pro`, `professional` | `professional` |
| `enterprise` | `enterprise` |
| `enterprise_plus` | `enterprise_plus` |
| `platform`, `unlimited` | `platform` (recommended for self-host) |

### `ai` — AI providers

Configures the chat/triage model and, optionally, an embeddings model. This section is applied to both the inference endpoint used by the agent executor and Riggs, and the per-tenant BYO config (API keys are encrypted at rest before storage).

```yaml
ai:
  chat:
    provider: "self_hosted"      # self_hosted | anthropic | openai
    api_style: "openai"          # openai | anthropic  (how the endpoint speaks)
    base_url: "http://host.docker.internal:11434"
    model: "qwen2.5:7b-instruct"
    api_key: "${AI_CHAT_API_KEY}"  # reference from .env; blank for keyless local servers
    max_tokens: 4096

  embeddings:
    provider: "disabled"         # openai | self_hosted | disabled
    base_url: ""
    model: ""
    api_key: "${AI_EMBED_API_KEY}"
```

- `provider` — `anthropic` and `openai` are cloud; `self_hosted` is any OpenAI-compatible server you run (Ollama, vLLM, LM Studio).
- `api_style` — the wire protocol the endpoint speaks (`openai` or `anthropic`), independent of where it runs.
- `base_url` — store it **without** a trailing `/v1`; the resolver appends the right path. For a local server on the Docker host, use `http://host.docker.internal:<port>`.
- `api_key` — a `${ENV_VAR}` reference. Leave the referenced env var empty for keyless local servers.

Embeddings power knowledge-base **semantic** search and are optional. Leaving `provider: "disabled"` falls back to Postgres full-text search. Semantic search additionally needs `pgvector` (the shipped `postgres` image includes it) and a configured embedding model.

See [Configure AI](#configure-ai) below for three worked examples.

### `admin` — platform admin

Upserts the first admin into `users` + `platform_admins` (mirrors `scripts/bootstrap_platform_admin.py`). The **password is not here** — set `ADMIN_PASSWORD` in `.env`.

```yaml
admin:
  username: "admin"
  email: "admin@acme-security.example"
  name: "Platform Admin"
```

### `triage` — triage taxonomy

Dispositions, severity levels, and priorities surfaced by the API. Built-in values (`MALICIOUS`, `BENIGN`, `critical`/`high`/`medium`/`low`, `P1`–`P4`, …) are always present. Entries here are **added as custom** — except a priority whose `value` matches a built-in, which **overrides that priority's `sla_hours`**.

```yaml
triage:
  dispositions:
    - value: "ESCALATED"
      label: "Escalated to IR"
      color: "#9333ea"
      description: "Handed off to incident response"
  severity_levels:
    - value: "informational"
      label: "Informational"
      color: "#3b82f6"
      threshold: 0
  priorities:
    - value: "P1"            # built-in -> overrides its SLA
      label: "P1 - Critical"
      sla_hours: 2
      color: "#dc2626"
    - value: "P5"            # new -> added as custom
      label: "P5 - Deferred"
      sla_hours: 336
      color: "#6b7280"
```

To leave the taxonomy at its built-in defaults, set the lists to `[]` or omit the section.

### `smtp` — outbound email

Applied to the `email_config` table, which the email service reads before falling back to `SMTP_*` environment variables. Omit this section to leave email purely env-driven.

```yaml
smtp:
  host: "smtp.example.com"
  port: 587
  username: "${SMTP_USERNAME}"
  password: "${SMTP_PASSWORD}"
  from_email: "soc@acme-security.example"
  from_name: "Acme SOC"
  use_tls: true
  use_ssl: false
  enabled: true
```

> Note: `email-validator` rejects `.local` addresses. Use a real TLD (e.g. `.com`, `.ai`) for `from_email` and admin email.

---

## Configure AI

T1 Agentics ships with **no AI provider configured**. Until you set one, AI-assisted triage, the Riggs assistant, and recommended actions are disabled — everything else (ingestion, queue, manual investigation, playbook execution, connectors) works fine. After editing the `ai` section, apply with `docker compose up -d backend`.

### (a) Anthropic cloud

```yaml
ai:
  chat:
    provider: "anthropic"
    api_style: "anthropic"
    base_url: "https://api.anthropic.com"
    model: "claude-sonnet-4-5-20250929"
    api_key: "${ANTHROPIC_API_KEY}"
    max_tokens: 4096
```

Set the key in `.env`:

```bash
ANTHROPIC_API_KEY=sk-ant-...
```

### (b) Local Ollama

Run Ollama on the Docker host, then point the backend at it. The backend reaches the host through `host.docker.internal`, which the shipped `docker-compose.yml` maps with `extra_hosts: ["host.docker.internal:host-gateway"]`.

Two host-side requirements:

1. Pull a model: `ollama pull qwen2.5:7b-instruct`
2. Bind Ollama to all interfaces so the container can reach it: start it with `OLLAMA_HOST=0.0.0.0` (otherwise it listens only on `127.0.0.1` inside the host and the container's request is refused).

```yaml
ai:
  chat:
    provider: "self_hosted"
    api_style: "openai"
    base_url: "http://host.docker.internal:11434"
    model: "qwen2.5:7b-instruct"
    api_key: "${AI_CHAT_API_KEY}"   # local servers ignore it; leave the env var empty or a placeholder
    max_tokens: 4096
```

### (c) vLLM or LM Studio

Both expose the same OpenAI-compatible shape — only the port and model name differ. Use `provider: self_hosted`, `api_style: openai`, and the server's base URL (without `/v1`):

```yaml
ai:
  chat:
    provider: "self_hosted"
    api_style: "openai"
    base_url: "http://host.docker.internal:8000"   # vLLM default; LM Studio defaults to :1234
    model: "Qwen/Qwen2.5-7B-Instruct"              # whatever your server is serving
    api_key: "${AI_CHAT_API_KEY}"
    max_tokens: 4096
```

For GPU and AVX requirements when running these locally, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md#local-model-runs-on-cpu-not-gpu).

### Embeddings (optional)

To enable knowledge-base semantic search, point `ai.embeddings` at an embedding model and ensure `pgvector` is available (it ships in the `postgres` image):

```yaml
ai:
  embeddings:
    provider: "self_hosted"
    base_url: "http://host.docker.internal:11434"
    model: "nomic-embed-text"
    api_key: "${AI_EMBED_API_KEY}"
```

With embeddings disabled, KB search degrades gracefully to Postgres full-text search.

---

## Applying changes

Any time you edit `t1.config.yaml`:

```bash
docker compose up -d backend
```

A bare `docker compose restart backend` does **not** reload `.env`, so use `up -d`. Watch it apply:

```bash
docker compose logs -f backend
```

The loader logs one line per section it touched (e.g. `ai_providers: base_url=... model=...`).
