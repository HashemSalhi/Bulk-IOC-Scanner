#!/usr/bin/env python3
"""Run the backend and the Vite dev server together, with live reload.

For contributors working on the UI. Everyone else should install the package
and run `bulk-ioc-scanner`, which serves a prebuilt interface on one port and
needs no Node at all.

    python scripts/dev.py

Stdlib only, so it runs on Windows, macOS, and Linux with no bootstrapping.
"""
import argparse
import os
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8000
FRONTEND_PORT = 5173


def fail(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(1)


def npm_command() -> str:
    """npm is a .cmd shim on Windows, which subprocess will not find unaided."""
    for name in ("npm.cmd", "npm") if os.name == "nt" else ("npm",):
        found = shutil.which(name)
        if found:
            return found
    fail("npm was not found. Install Node.js from https://nodejs.org to work on the UI.")


def ensure_backend_importable() -> None:
    try:
        import bulk_ioc_scanner  # noqa: F401
    except ImportError:
        fail(
            "the backend is not installed in this environment. Run:\n"
            f"    {sys.executable} -m pip install -e \"{ROOT}[dev]\""
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--backend-port", type=int, default=BACKEND_PORT)
    parser.add_argument("--frontend-port", type=int, default=FRONTEND_PORT)
    args = parser.parse_args()

    ensure_backend_importable()
    npm = npm_command()

    if not (FRONTEND / "node_modules").is_dir():
        print("Installing frontend dependencies (first run)...")
        subprocess.check_call([npm, "install"], cwd=FRONTEND)

    procs = [
        subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "bulk_ioc_scanner.main:app",
             "--host", BACKEND_HOST, "--port", str(args.backend_port), "--reload"],
            cwd=ROOT,
        ),
        subprocess.Popen(
            [npm, "run", "dev", "--", "--port", str(args.frontend_port)],
            cwd=FRONTEND,
        ),
    ]

    print(f"\n  UI:  http://localhost:{args.frontend_port}   (live reload)")
    print(f"  API: http://{BACKEND_HOST}:{args.backend_port}/docs\n")
    print("  Ctrl+C to stop both.\n")

    def shutdown(*_):
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    # If either process exits, stop the other so the terminal is not left with
    # half a stack running.
    done = threading.Event()

    def watch(proc):
        proc.wait()
        done.set()

    for proc in procs:
        threading.Thread(target=watch, args=(proc,), daemon=True).start()

    try:
        done.wait()
    except KeyboardInterrupt:
        pass
    shutdown()
    for proc in procs:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    return 0


if __name__ == "__main__":
    sys.exit(main())
