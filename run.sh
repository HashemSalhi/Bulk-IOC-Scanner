#!/usr/bin/env bash
#
# IOC-Radar one-command launcher (development mode).
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

# ── Backend bootstrap ─────────────────────────────────────────────────────────
if [ ! -d "$VENV" ]; then
  cyan "[setup] Creating Python virtual environment..."
  python3 -m venv "$VENV"
fi

cyan "[setup] Installing/verifying backend dependencies..."
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -r "$BACKEND/requirements.txt"

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
  yellow "[stop] Shutting down IOC-Radar..."
  for pid in "${PIDS[@]}"; do
    kill_tree "$pid"
  done
  wait 2>/dev/null || true
  exit 0
}
trap cleanup INT TERM EXIT

cyan "[start] Backend  -> http://$BACKEND_HOST:$BACKEND_PORT  (API docs at /docs)"
(cd "$BACKEND" && "$VENV/bin/uvicorn" app.main:app --host "$BACKEND_HOST" --port "$BACKEND_PORT" --reload) &
PIDS+=($!)

cyan "[start] Frontend -> http://localhost:$FRONTEND_PORT"
(cd "$FRONTEND" && npm run dev -- --port "$FRONTEND_PORT") &
PIDS+=($!)

echo ""
yellow "IOC-Radar is running. Open http://localhost:$FRONTEND_PORT  —  press Ctrl+C to stop."
echo ""

# Wait on both; if either exits, tear everything down.
wait -n
cleanup
