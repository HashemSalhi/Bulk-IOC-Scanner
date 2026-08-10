"""Launcher argument handling, port selection, and the browser thread."""
import socket

import pytest

from bulk_ioc_scanner import cli


@pytest.fixture
def taken_port():
    """Bind a real port so find_port has something genuinely in use to skip."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    yield sock.getsockname()[1]
    sock.close()


def test_defaults():
    args = cli.build_parser().parse_args([])
    assert (args.host, args.port) == (cli.DEFAULT_HOST, cli.DEFAULT_PORT)
    assert args.no_browser is False
    assert args.data_dir is None


def test_find_port_prefers_the_requested_one():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        free = probe.getsockname()[1]
    assert cli.find_port("127.0.0.1", free) == free


def test_find_port_skips_a_port_in_use(taken_port):
    chosen = cli.find_port("127.0.0.1", taken_port)
    assert chosen > taken_port


def test_find_port_gives_a_readable_error_when_nothing_is_free(monkeypatch):
    monkeypatch.setattr(cli, "_port_is_free", lambda host, port: False)
    with pytest.raises(SystemExit) as excinfo:
        cli.find_port("127.0.0.1", 8000)
    assert "--port" in str(excinfo.value)


def test_version_exits_without_starting_a_server(capsys, monkeypatch):
    monkeypatch.setattr(
        cli, "find_port", lambda *a: pytest.fail("must not look for a port")
    )
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out.strip()


def test_data_dir_is_exported_before_the_config_is_read(tmp_path, monkeypatch):
    """--data-dir only works if it lands in the environment before startup."""
    from bulk_ioc_scanner.paths import ENV_VAR

    recorded = {}

    def fake_run(_app, **kwargs):
        import os
        recorded["data_dir"] = os.environ[ENV_VAR]
        recorded["port"] = kwargs["port"]

    monkeypatch.setattr("uvicorn.run", fake_run)
    cli.main(["--data-dir", str(tmp_path / "elsewhere"), "--no-browser", "--port", "0"])

    assert recorded["data_dir"] == str(tmp_path / "elsewhere")


def test_browser_opens_at_the_loopback_when_bound_to_all_interfaces(monkeypatch):
    """0.0.0.0 is not an address a browser can visit."""
    opened = {}
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    monkeypatch.setattr(cli, "find_port", lambda host, port: port)
    monkeypatch.setattr(
        cli, "_open_browser_when_ready",
        lambda url, host, port, **kw: opened.setdefault("url", url),
    )

    cli.main(["--host", "0.0.0.0", "--port", "9123"])
    assert opened["url"] == "http://localhost:9123"


def test_no_browser_skips_the_thread(monkeypatch):
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    monkeypatch.setattr(cli, "find_port", lambda host, port: port)
    monkeypatch.setattr(
        cli, "_open_browser_when_ready",
        lambda *a, **k: pytest.fail("browser must not open with --no-browser"),
    )
    assert cli.main(["--no-browser"]) == 0
