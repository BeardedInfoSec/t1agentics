#!/usr/bin/env python3
"""
Native single-node runner for T1 Agentics -- no Docker.

What it does:
  1. Boots an embedded PostgreSQL via `pgserver` (binaries ship as pip wheels;
     no system Postgres, no admin rights, data lives in ./.native/pgdata).
  2. On first run, applies the base schema (backend/init-db.sql) and generates
     + persists secrets and an admin login to ./.native/config.json.
  3. Starts the FastAPI backend, which also serves the built React frontend, so
     a single port (default 8000) handles the UI, REST API, and WebSocket.
     Redis and ClickHouse are left off -- the app falls back to in-process
     behaviour for both.

Requirements:
  - Python 3.11 (the backend's pinned deps + pgserver target 3.11)
  - pip install -r backend/requirements.txt -r requirements-native.txt
  - A built frontend at frontend/build  (npm --prefix frontend run build)

Usage:
  python run_native.py            # -> http://localhost:8000
  PORT=9000 python run_native.py

Status: EXPERIMENTAL. The no-Docker path is new; test in a Python 3.11 env.
"""
import os
import sys
import json
import secrets
import getpass
import webbrowser
from pathlib import Path
from urllib.parse import urlparse, unquote

REPO = Path(__file__).resolve().parent
BACKEND = REPO / "backend"
FRONTEND_BUILD = REPO / "frontend" / "build"
STATE = REPO / ".native"
PGDATA = STATE / "pgdata"
CONFIG = STATE / "config.json"
SCHEMA_SENTINEL = STATE / "schema_applied"
INIT_SQL = BACKEND / "init-db.sql"


def log(msg):
    print(f"[native] {msg}", flush=True)


def load_or_create_config():
    """Generate secrets + an admin login on first run; reuse them after."""
    STATE.mkdir(parents=True, exist_ok=True)
    if CONFIG.exists():
        return json.loads(CONFIG.read_text())

    log("First run -- generating secrets and an admin login.")
    from cryptography.fernet import Fernet

    pw = os.getenv("ADMIN_PASSWORD", "")
    if not pw:
        try:
            pw = getpass.getpass("Choose an admin password (min 12 chars) [blank = auto-generate]: ").strip()
        except Exception:
            pw = ""
    if len(pw) < 12:
        pw = secrets.token_urlsafe(16)
        log(f"Generated admin password: {pw}")

    cfg = {
        "JWT_SECRET_KEY": secrets.token_hex(32),
        "PLATFORM_JWT_SECRET": secrets.token_hex(32),
        "CREDENTIALS_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "ADMIN_USERNAME": os.getenv("ADMIN_USERNAME", "admin"),
        "ADMIN_PASSWORD": pw,
        "ADMIN_EMAIL": os.getenv("ADMIN_EMAIL", "admin@localhost"),
    }
    CONFIG.write_text(json.dumps(cfg, indent=2))
    try:
        os.chmod(CONFIG, 0o600)
    except Exception:
        pass
    log(f"Saved config to {CONFIG} (treat as sensitive).")
    return cfg


def start_postgres():
    """Start the embedded server and apply the base schema once."""
    import pgserver

    PGDATA.mkdir(parents=True, exist_ok=True)
    log(f"Starting embedded PostgreSQL (data dir: {PGDATA}) ...")
    db = pgserver.get_server(str(PGDATA))
    uri = db.get_uri()

    if not SCHEMA_SENTINEL.exists():
        log("Applying base schema (backend/init-db.sql) ...")
        db.psql(INIT_SQL.read_text(encoding="utf-8"))
        SCHEMA_SENTINEL.write_text("ok")
        log("Base schema applied.")
    return db, uri


def env_from_uri(uri):
    """Translate pgserver's libpq URI into the POSTGRES_* vars the app reads.

    On POSIX, pgserver listens on a Unix socket (host is a directory path);
    asyncpg accepts a directory as `host`. On Windows it uses TCP on localhost.
    """
    p = urlparse(uri)
    return {
        "POSTGRES_HOST": unquote(p.hostname or "localhost"),
        "POSTGRES_PORT": str(p.port or 5432),
        "POSTGRES_USER": unquote(p.username or getpass.getuser()),
        "POSTGRES_PASSWORD": unquote(p.password or ""),
        "POSTGRES_DB": (p.path or "/postgres").lstrip("/") or "postgres",
    }


def main():
    if not (FRONTEND_BUILD / "index.html").exists():
        log(f"WARNING: no frontend build at {FRONTEND_BUILD}.")
        log("Build it once:  npm --prefix frontend install && npm --prefix frontend run build")

    cfg = load_or_create_config()
    db, uri = start_postgres()

    os.environ.update(cfg)
    os.environ.update(env_from_uri(uri))
    # Single-node: relax the production-fatal checks, disable Redis + ClickHouse
    # (both have graceful in-process fallbacks), and let the backend serve the UI.
    os.environ.setdefault("ENVIRONMENT", "development")
    os.environ["REDIS_URL"] = ""
    os.environ["CLICKHOUSE_HOST"] = ""
    os.environ["SERVE_FRONTEND"] = "1"
    os.environ.setdefault("FRONTEND_DIR", str(FRONTEND_BUILD))

    port = int(os.getenv("PORT", "8000"))

    # The backend imports modules as top-level (`from services import ...`),
    # so it must run with backend/ as the working dir + on sys.path.
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)

    log(f"Starting T1 Agentics at http://localhost:{port}  (Ctrl+C to stop)")
    try:
        webbrowser.open(f"http://localhost:{port}")
    except Exception:
        pass

    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=port, log_level="info")


if __name__ == "__main__":
    main()
