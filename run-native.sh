#!/usr/bin/env bash
# Native (no-Docker) launcher for T1 Agentics -- Linux / macOS.
# Creates a venv, installs deps, builds the frontend if needed, then runs the
# embedded-Postgres single-node app on http://localhost:8000.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] in [(3,11),(3,12)] else 1)' 2>/dev/null; then
  echo "Python 3.11 or 3.12 is required (the backend's pinned deps target it)."
  echo "Found: $("$PY" --version 2>&1). Set PYTHON=/path/to/python3.11 to override."
  exit 1
fi

if [ ! -d .native/venv ]; then
  echo "Creating virtualenv (.native/venv) ..."
  "$PY" -m venv .native/venv
fi
# shellcheck disable=SC1091
source .native/venv/bin/activate

echo "Installing Python dependencies ..."
pip install --quiet --upgrade pip
pip install --quiet -r backend/requirements.txt -r requirements-native.txt

if [ ! -f frontend/build/index.html ]; then
  echo "Building frontend (one-time) ..."
  ( cd frontend && npm install && npm run build )
fi

exec python run_native.py
