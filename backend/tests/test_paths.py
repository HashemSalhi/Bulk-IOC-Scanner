"""Data directory resolution, permissions, and the legacy database migration."""
import os
import stat
import sys

import pytest

from bulk_ioc_scanner import paths


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    target = tmp_path / "data"
    monkeypatch.setenv(paths.ENV_VAR, str(target))
    return target


def test_override_is_created_on_demand(data_dir):
    assert not data_dir.exists()
    assert paths.data_dir() == data_dir
    assert data_dir.is_dir()


def test_db_and_env_live_in_the_data_dir(data_dir):
    assert paths.db_path() == data_dir / paths.DB_FILENAME
    assert paths.env_file_path() == data_dir / ".env"


def test_override_is_read_each_call(tmp_path, monkeypatch):
    """No caching: --data-dir sets the variable after the module is imported."""
    monkeypatch.setenv(paths.ENV_VAR, str(tmp_path / "one"))
    assert paths.data_dir() == tmp_path / "one"
    monkeypatch.setenv(paths.ENV_VAR, str(tmp_path / "two"))
    assert paths.data_dir() == tmp_path / "two"


def test_blank_override_falls_back_to_the_platform_default(monkeypatch):
    monkeypatch.setenv(paths.ENV_VAR, "   ")
    assert paths.data_dir() == paths._default_data_dir()


@pytest.mark.parametrize(
    "platform,env,expected_tail",
    [
        ("win32", {"LOCALAPPDATA": "C:\\Users\\a\\AppData\\Local"}, "BulkIOCScanner"),
        ("darwin", {}, "Library/Application Support/BulkIOCScanner"),
        ("linux", {"XDG_DATA_HOME": "/home/a/.share"}, ".share/bulk-ioc-scanner"),
    ],
)
def test_platform_defaults(monkeypatch, platform, env, expected_tail):
    monkeypatch.setattr(sys, "platform", platform)
    for key in ("LOCALAPPDATA", "XDG_DATA_HOME"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    resolved = paths._default_data_dir().as_posix()
    assert resolved.endswith(expected_tail)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_data_dir_is_owner_only(data_dir):
    assert stat.S_IMODE(paths.data_dir().stat().st_mode) == 0o700


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_db_file_is_owner_only(data_dir):
    paths.data_dir()
    paths.db_path().write_text("")
    paths.protect_db_file()
    assert stat.S_IMODE(paths.db_path().stat().st_mode) == 0o600


def test_legacy_db_is_migrated_once(data_dir, monkeypatch, tmp_path):
    legacy = tmp_path / "install" / "bulk_ioc_scanner"
    legacy.mkdir(parents=True)
    (legacy.parent / paths.DB_FILENAME).write_text("original")
    monkeypatch.setattr(paths, "__file__", str(legacy / "paths.py"))

    paths.migrate_legacy_db()
    assert paths.db_path().read_text() == "original"

    # A second run must not clobber data written since the migration.
    paths.db_path().write_text("newer")
    paths.migrate_legacy_db()
    assert paths.db_path().read_text() == "newer"


def test_migration_is_a_no_op_without_a_legacy_db(data_dir):
    paths.migrate_legacy_db()
    assert not paths.db_path().exists()
