# Troubleshooting T1 Agentics

Symptom → cause → fix for the issues self-hosters hit most often. For install steps see [INSTALL.md](INSTALL.md); for the config file see [CONFIGURATION.md](CONFIGURATION.md).

## How to get logs first

Almost every fix starts with the backend log:

```bash
docker compose logs -f backend          # tail the backend
docker compose logs -f caddy            # TLS / reverse proxy
docker compose logs -f postgres         # database
docker compose ps                       # what is up / restarting
./bin/t1 logs backend                   # same as the first line, via the helper
```

---

## Quick reference

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| "Mixed Content" errors / backend redirects to `http://` behind a proxy | Backend not trusting the forwarded protocol | Ensure the proxy sends `X-Forwarded-Proto` and `FORWARDED_ALLOW_IPS` is set (the shipped compose sets `*`) |
| "No AI provider configured or available" | No AI provider set | Configure `ai.chat` and restart the backend |
| Deep analysis / Recommended Actions never appear | License tier too low | Set a paid `license.tier` and confirm AI works |
| Playbook Marketplace / Knowledge Base empty | Content not seeded | Run the seed scripts |
| `relation "tenants" does not exist` | Schema didn't load | Re-run on a fresh volume |
| Local model uses CPU not GPU | Missing host GPU driver / toolkit / AVX | Install driver / `nvidia-container-toolkit`; enable AVX |
| Can't get TLS on a LAN box | No public domain for ACME | Use Caddy internal cert or DNS-01 ACME |
| Login asks for "Organization" | Tenant slug required | Enter your `org.slug` |
| `redis package not installed` warning | Optional dependency note | Harmless — in-memory fallback |
| `email-validator` rejects `.local` | Non-routable TLD | Use a real TLD |
| Changing `ADMIN_PASSWORD` doesn't change login | Admin created once | Re-apply via config or reset in DB |

---

## API calls fail with "Mixed Content" / backend redirects to `http://`

**Cause.** The app is behind a TLS-terminating reverse proxy. The browser loads the page over `https://`, but the backend — not knowing TLS was terminated upstream — builds `http://` URLs, which the browser blocks as mixed content (or it issues an `http://` redirect that breaks the session).

**Fix.** The backend must trust the forwarded protocol. The shipped `docker-compose.yml` already sets `FORWARDED_ALLOW_IPS=*` on the backend, and the shipped `Caddyfile` forwards `X-Forwarded-Proto {scheme}`. If you front the stack with your **own** proxy:

1. Make it send `X-Forwarded-Proto: https` (and `X-Forwarded-For`).
2. Keep `FORWARDED_ALLOW_IPS=*` (or set it to your proxy's IP) on the backend service.
3. Apply: `docker compose up -d backend`.

---

## Riggs / AI says "No AI provider configured or available"

**Cause.** No AI provider is configured. T1 Agentics ships with AI off.

**Fix.** Set `ai.chat` in `t1.config.yaml` (or **Settings → AI** in the UI) and restart the backend:

```bash
docker compose up -d backend
```

For self-hosted models you also need a **reachable** OpenAI-compatible endpoint — verify it from inside the container:

```bash
docker compose exec backend curl -s http://host.docker.internal:11434/v1/models
```

See [CONFIGURATION.md → Configure AI](CONFIGURATION.md#configure-ai) for worked examples.

---

## Deep analysis / Recommended Actions never appear on investigations

**Cause.** These are premium features gated on the license tier. On `free`/`community` they are disabled.

**Fix.** Set a paid tier in `t1.config.yaml`:

```yaml
license:
  tier: "platform"
```

Apply with `docker compose up -d backend`, then confirm your AI provider actually works (previous section) — deep analysis needs both the tier **and** a working model.

---

## Playbook Marketplace / Knowledge Base empty after install

**Cause.** The content libraries were not seeded. `install.sh` seeds them automatically; a manual `docker compose up -d` does not.

**Fix.** The content and seed scripts live at the repo root but are not inside the backend image, so copy them in first, then run the loaders:

```bash
docker compose cp scripts/load-playbook-catalog.py backend:/app/scripts/load-playbook-catalog.py
docker compose cp scripts/load-kb-direct.py        backend:/app/scripts/load-kb-direct.py
docker compose cp playbook-store-output            backend:/app/playbook-store-output
docker compose cp kb-content-output                backend:/app/kb-content-output

docker compose exec -T backend python scripts/load-playbook-catalog.py
docker compose exec -T backend python scripts/load-kb-direct.py kb-content-output/articles
```

Both seeders are idempotent (playbooks upsert, KB skips existing titles), so it is safe to rerun. A handful of KB articles use a content type the schema rejects and are skipped — expected.

---

## Backend up but errors / `relation "tenants" does not exist`

**Cause.** The database schema didn't fully load. The installer initializes the database from the complete `native-schema.sql` on the **first** boot of an empty Postgres volume; if that volume was created by an older build or a partial init, core tables can be missing.

**Fix.** If the database is empty (no data you care about), re-initialize on a fresh volume:

```bash
docker compose down -v          # destroys the DB volume — back up first if needed
docker compose up -d
```

The schema is applied by Postgres on first init (`./native-schema.sql` is mounted into `/docker-entrypoint-initdb.d/`). If you have data you cannot lose, file an issue with the exact error instead of wiping the volume.

---

## Local model runs on CPU, not GPU

**Cause.** The GPU path is not wired up. There are three distinct requirements depending on how you run the model.

**Fix.**

1. **Host driver.** Install the NVIDIA driver on the host; `nvidia-smi` must work. Ollama uses the host driver directly — if `nvidia-smi` works, Ollama uses the GPU.
2. **GPU inside Docker.** If you run the model server *inside a container*, install the [`nvidia-container-toolkit`](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html) and pass `--gpus all` (or the compose `deploy.resources` GPU reservation) to that container.
3. **vLLM AVX.** vLLM additionally requires the CPU to expose **AVX**. On a VM this is often hidden — set the hypervisor CPU type to **host-passthrough** (e.g. `host-passthrough` in libvirt/KVM, "host" CPU mode) so AVX is visible, then restart vLLM.

---

## Can't reach the site from another machine / TLS errors on a LAN domain

**Cause.** Public ACME (Let's Encrypt/ZeroSSL) can't issue a certificate for a private name like `soc.lan` (`DNS identifier is invalid`) or for an `example.com` admin email. If Caddy was pointed at public ACME for such a domain it never gets a cert, and **HTTPS fails for everyone** — even the host itself.

**The installer now auto-detects this:** internal/LAN domains (private TLDs like `.lan`/`.local`/`.internal`, a single-label host, or an IP) get Caddy's **built-in CA** automatically — no public DNS needed. Override with `T1_TLS_MODE=internal|public`.

**If you're on an internal domain and can't connect from another machine:**

1. **Name resolution.** The cert is issued for the name, so the raw IP won't validate. Point the domain at the host via local DNS, or add a hosts-file entry on the client:
   ```
   192.168.1.50   soc.lan
   ```
2. **Trust.** Accept the browser's self-signed warning, or install Caddy's root CA for warning-free TLS:
   ```bash
   docker compose exec caddy cat /data/caddy/pki/authorities/local/root.crt > t1-root-ca.crt
   # import t1-root-ca.crt into the client's OS / browser trust store
   ```
3. **Already installed with the wrong mode?** Set `CADDY_TLS=internal` in `.env` (or `T1_TLS_MODE=internal ./install.sh --reset`) and `docker compose up -d caddy`.

**Want a publicly-trusted cert without exposing port 80?** Use a real domain with an ACME DNS-01 challenge (e.g. a Cloudflare API token) — works even with no inbound public reachability.

---

## Login asks for an "Organization"

**Cause.** The login form is tenant-scoped. The **Organization** field is your tenant slug.

**Fix.** Enter your `org.slug` — the value set at install (`org.slug` in `t1.config.yaml`, e.g. `t1-agentics`).

---

## `redis package not installed` warnings

**Cause.** A startup note when the optional `redis` client isn't importable.

**Fix.** Harmless — rate limiting falls back to an in-memory limiter. The `redis` package is in `requirements.txt` on current builds, so a fresh build clears the warning. No action needed for a working install.

---

## `email-validator` rejects `.local` addresses

**Cause.** The `.local` TLD is not a routable public TLD and `email-validator` rejects it.

**Fix.** Use a real TLD (e.g. `.com`, `.ai`) for the admin email, `from_email`, and any user emails.

---

## Changing `ADMIN_PASSWORD` env doesn't change the login

**Cause.** The platform admin is created **once**, on first bootstrap. Editing `ADMIN_PASSWORD` afterward does not retroactively change an existing user.

**Fix.** Use the config-file path: the `admin` section in `t1.config.yaml` re-applies on startup and the password is read from `${ADMIN_PASSWORD}` in `.env`, so:

```bash
# set the new value in .env
ADMIN_PASSWORD=<new strong password>
# re-apply (the admin section rotates the password)
docker compose up -d backend
```

If you prefer to reset directly in the database, clear any lockout and reset the bcrypt hash:

```bash
docker compose exec postgres psql -U agentcore -d agentcore -c \
  "UPDATE users SET failed_login_attempts=0, locked_until=NULL WHERE username='admin';"
```
