#!/usr/bin/env bash
#
# Bulk-IOC-Scanner one-command launcher (development mode).
# Bootstraps dependencies on first run, then starts the backend (FastAPI) and
# frontend (Vite) together with live reload. Ctrl+C stops both.
#
# Usage:
#   ./run.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
VENV="$BACKEND/.venv"

BACKEND_HOST="127.0.0.1"
BACKEND_PORT="8000"
FRONTEND_PORT="5173"

cyan() { printf '\033[36m%s\033[0m\n' "$1"; }
yellow() { printf '\033[33m%s\033[0m\n' "$1"; }
red() { printf '\033[31m%s\033[0m\n' "$1"; }

PY="$VENV/bin/python"

# True only if the venv has a working python + pip
venv_ok() {
  [ -x "$PY" ] && "$PY" -m pip --version >/dev/null 2>&1
}

# ── Prerequisites ─────────────────────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
  red "[error] python3 is not installed. Install it with: sudo apt install python3 python3-venv python3-pip"
  exit 1
fi
if ! command -v npm >/dev/null 2>&1; then
  red "[error] npm is not installed. Install Node.js (which includes npm) from https://nodejs.org or: sudo apt install nodejs npm"
  exit 1
fi

# ── Backend bootstrap ─────────────────────────────────────────────────────────
if [ ! -d "$VENV" ]; then
  cyan "[setup] Creating Python virtual environment..."
  python3 -m venv "$VENV" || true
fi

# A venv can exist but be missing pip (common on Debian/Kali when python3-venv
# is absent and ensurepip fails). Repair it, recreating from scratch if needed.
if [ -x "$PY" ] && ! "$PY" -m pip --version >/dev/null 2>&1; then
  cyan "[setup] Bootstrapping pip in the virtual environment..."
  "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi

if ! venv_ok; then
  cyan "[setup] Virtual environment incomplete — recreating..."
  rm -rf "$VENV"
  python3 -m venv "$VENV" || true
  [ -x "$PY" ] && "$PY" -m ensurepip --upgrade >/dev/null 2>&1 || true
fi

if ! venv_ok; then
  red "[error] Could not create a working Python virtual environment with pip."
  red "        Your system is likely missing the venv module. Install it with:"
  red "            sudo apt install python3-venv python3-pip"
  red "        then re-run ./run.sh"
  exit 1
fi

cyan "[setup] Installing/verifying backend dependencies..."
"$PY" -m pip install -q --upgrade pip
"$PY" -m pip install -q -r "$BACKEND/requirements.txt"

# ── Frontend bootstrap ────────────────────────────────────────────────────────
if [ ! -d "$FRONTEND/node_modules" ]; then
  cyan "[setup] Installing frontend dependencies (first run)..."
  (cd "$FRONTEND" && npm install)
fi

# ── Start both servers ────────────────────────────────────────────────────────
PIDS=()

# Recursively kill a process and all its descendants (uvicorn --reload and vite
# each fork children that must be cleaned up too).
kill_tree() {
  local pid=$1
  for child in $(pgrep -P "$pid" 2>/dev/null); do
    kill_tree "$child"
  done
  kill "$pid" 2>/dev/null || true
}

cleanup() {
  trap - INT TERM EXIT
  echo ""
  yellow "[stop] Shutting down Bulk-IOC-Scanner..."
  for pid in "${PIDS[@]}"; do
    kill_tree "$pid"
  done
  wait 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM EXIT

cyan "[start] Backend  -> http://$BACKEND_HOST:$BACKEND_PORT  (API docs at /docs)"
(cd "$BACKEND" && "$PY" -m uvicorn app.main:app --host "$BACKEND_HOST" --port "$BACKEND_PORT" --reload) &
PIDS+=($!)

cyan "[start] Frontend -> http://localhost:$FRONTEND_PORT"
(cd "$FRONTEND" && npm run dev -- --port "$FRONTEND_PORT") &
PIDS+=($!)

echo ""
yellow "Bulk-IOC-Scanner is running. Open http://localhost:$FRONTEND_PORT  —  press Ctrl+C to stop."
echo ""

# Wait on both; if either exits, tear everything down.
wait -n
cleanup
