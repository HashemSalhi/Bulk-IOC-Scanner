"""Command line entry point: ``bulk-ioc-scanner``.

Starts the server, prints where things are, and opens a browser. It replaces
the old shell launcher, so Windows, macOS, and Linux all use the same command
and nothing needs bash.
"""
import argparse
import os
import socket
import sys
import threading
import webbrowser

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
_PORT_SEARCH_LIMIT = 20


def _port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def find_port(host: str, preferred: int) -> int:
    """Return the first free port at or after `preferred`.

    Analysts often have something on 8000 already, and "address already in
    use" is a poor first experience. Give up after a short search rather than
    scanning the whole range.
    """
    for candidate in range(preferred, preferred + _PORT_SEARCH_LIMIT):
        if _port_is_free(host, candidate):
            return candidate
    raise SystemExit(
        f"No free port between {preferred} and {preferred + _PORT_SEARCH_LIMIT - 1} on "
        f"{host}. Free one up, or pass --port with a port you know is available."
    )


def _open_browser_when_ready(url: str, host: str, port: int, timeout: float = 20.0) -> None:
    """Poll the port in a background thread, then open the browser once."""
    import time

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        return  # server never came up; the error is already on screen

    try:
        webbrowser.open(url)
    except Exception:  # headless box, no default browser, WSL without wslu
        pass


def _banner(url: str, data_dir) -> str:
    return "\n".join([
        "",
        "  Bulk-IOC-Scanner",
        f"  Open:      {url}",
        f"  Your data: {data_dir}",
        "  API keys:  optional — add them on the Settings page to enable more providers",
        "",
        "  Press Ctrl+C to stop.",
        "",
    ])


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bulk-ioc-scanner",
        description="Bulk IOC threat intelligence scanner. Runs locally and opens in your browser.",
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help="Address to listen on (default: %(default)s, reachable only from this machine). "
             "Use 0.0.0.0 to share on your network — there is no authentication, so only do "
             "that on a network you trust.",
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT,
        help="Port to listen on (default: %(default)s). If it is taken, the next free port is used.",
    )
    parser.add_argument(
        "--no-browser", action="store_true",
        help="Do not open a browser window on start.",
    )
    parser.add_argument(
        "--data-dir",
        help="Where to keep the database and settings (default: your OS user data directory).",
    )
    parser.add_argument(
        "--log-level", default="info",
        choices=["critical", "error", "warning", "info", "debug", "trace"],
        help="Server log verbosity (default: %(default)s).",
    )
    parser.add_argument("--version", action="store_true", help="Print the version and exit.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        from importlib.metadata import PackageNotFoundError, version

        try:
            print(version("bulk-ioc-scanner"))
        except PackageNotFoundError:
            print("unknown (running from a source checkout)")
        return 0

    # Must be set before anything reads the configuration, since the database
    # URL and the optional .env are both resolved from the data directory.
    if args.data_dir:
        from bulk_ioc_scanner.paths import ENV_VAR

        os.environ[ENV_VAR] = os.path.abspath(os.path.expanduser(args.data_dir))

    import uvicorn

    from bulk_ioc_scanner.paths import data_dir

    port = find_port(args.host, args.port)
    if port != args.port:
        print(f"Port {args.port} is in use; using {port} instead.", flush=True)

    # 0.0.0.0 is not a browsable address; point the browser at the loopback.
    browse_host = "localhost" if args.host in ("0.0.0.0", "::") else args.host
    url = f"http://{browse_host}:{port}"

    # flush: stdout is block-buffered when piped, and the URL is the one thing
    # the user actually needs to see before the server takes over the terminal.
    print(_banner(url, data_dir()), flush=True)

    if not args.no_browser:
        threading.Thread(
            target=_open_browser_when_ready, args=(url, args.host, port), daemon=True
        ).start()

    try:
        uvicorn.run(
            "bulk_ioc_scanner.main:app",
            host=args.host,
            port=port,
            log_level=args.log_level,
        )
    except KeyboardInterrupt:  # pragma: no cover - depends on a real signal
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
