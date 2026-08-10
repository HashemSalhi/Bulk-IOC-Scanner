"""Where Bulk-IOC-Scanner keeps its data on each operating system.

The database holds saved API keys, so it must never live inside the install
folder: that folder may be read-only (a wheel in site-packages), wiped on
upgrade, or — worst case — a git checkout that someone later pushes.

Everything lands in one directory per user:

    Windows   %LOCALAPPDATA%\\BulkIOCScanner
    macOS     ~/Library/Application Support/BulkIOCScanner
    Linux     ${XDG_DATA_HOME:-~/.local/share}/bulk-ioc-scanner

Set BULK_IOC_SCANNER_DATA_DIR to override (used by Docker and the tests).
"""
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

ENV_VAR = "BULK_IOC_SCANNER_DATA_DIR"
DB_FILENAME = "bulk_ioc_scanner.db"


def _default_data_dir() -> Path:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local"
        return Path(base) / "BulkIOCScanner"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "BulkIOCScanner"
    base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
    return Path(base) / "bulk-ioc-scanner"


def data_dir() -> Path:
    """Return the user data directory, creating it if needed.

    Not cached: the tests and the --data-dir flag set the environment variable
    after import, and a stale cache would silently write to the wrong place.
    """
    override = os.environ.get(ENV_VAR, "").strip()
    path = Path(override).expanduser() if override else _default_data_dir()
    path.mkdir(parents=True, exist_ok=True)
    _restrict(path, 0o700)
    return path


def db_path() -> Path:
    return data_dir() / DB_FILENAME


def env_file_path() -> Path:
    """Optional .env in the data directory, for people who prefer a file to the UI."""
    return data_dir() / ".env"


def _restrict(path: Path, mode: int) -> None:
    """Tighten permissions on POSIX. Windows inherits per-user ACLs already."""
    if os.name == "nt":
        return
    try:
        path.chmod(mode)
    except OSError as e:  # unusual filesystem; not worth failing startup over
        logger.warning("Could not set permissions on %s: %s", path, e)


def protect_db_file() -> None:
    """Make the database owner-only. It stores API keys in plain text."""
    path = db_path()
    if path.exists():
        _restrict(path, 0o600)


def migrate_legacy_db() -> None:
    """Move a pre-1.1 database out of the install folder, once.

    Earlier versions resolved the SQLite path relative to the working
    directory, so the database usually ended up in the checkout next to the
    code. Copy it across on first run so upgrading keeps history and keys.
    """
    target = db_path()
    if target.exists():
        return

    legacy = Path(__file__).resolve().parent.parent / DB_FILENAME
    if not legacy.is_file():
        return

    import shutil

    try:
        shutil.copy2(legacy, target)
    except OSError as e:
        logger.warning("Could not migrate the existing database from %s: %s", legacy, e)
        return

    protect_db_file()
    logger.info("Moved your existing database from %s to %s", legacy, target)
