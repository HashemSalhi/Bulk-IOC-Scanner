"""Proxy and CA bundle resolution for outbound provider requests."""
import pytest

from bulk_ioc_scanner.config import settings
from bulk_ioc_scanner.providers import http


@pytest.fixture(autouse=True)
def clean_network_settings(monkeypatch):
    monkeypatch.setattr(settings, "proxy_url", "")
    monkeypatch.setattr(settings, "ca_bundle", "")
    monkeypatch.setattr(settings, "insecure_skip_verify", False)
    for var in http._CA_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def test_defaults_to_the_bundled_trust_store():
    assert http.resolve_verify() is True


def test_no_proxy_means_httpx_reads_the_environment():
    """Returning None keeps trust_env in charge of HTTP_PROXY/HTTPS_PROXY."""
    assert http.resolve_proxy() is None


def test_configured_proxy_wins(monkeypatch):
    monkeypatch.setattr(settings, "proxy_url", "http://proxy.corp:8080")
    assert http.resolve_proxy() == "http://proxy.corp:8080"


def test_proxy_whitespace_is_ignored(monkeypatch):
    monkeypatch.setattr(settings, "proxy_url", "   ")
    assert http.resolve_proxy() is None


def test_configured_ca_bundle_is_used(tmp_path, monkeypatch):
    bundle = tmp_path / "corp-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----")
    monkeypatch.setattr(settings, "ca_bundle", str(bundle))
    assert http.resolve_verify() == str(bundle)


def test_missing_ca_bundle_falls_back_instead_of_crashing(tmp_path, monkeypatch, caplog):
    monkeypatch.setattr(settings, "ca_bundle", str(tmp_path / "absent.pem"))
    with caplog.at_level("ERROR"):
        assert http.resolve_verify() is True
    assert "does not exist" in caplog.text


@pytest.mark.parametrize("var", http._CA_ENV_VARS)
def test_standard_ca_environment_variables_are_honoured(var, tmp_path, monkeypatch):
    """An analyst who already configured curl or pip should need no extra setup."""
    bundle = tmp_path / "env-ca.pem"
    bundle.write_text("-----BEGIN CERTIFICATE-----")
    monkeypatch.setenv(var, str(bundle))
    assert http.resolve_verify() == str(bundle)


def test_nonexistent_path_in_the_environment_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "gone.pem"))
    assert http.resolve_verify() is True


def test_explicit_bundle_beats_the_environment(tmp_path, monkeypatch):
    configured = tmp_path / "configured.pem"
    configured.write_text("x")
    from_env = tmp_path / "env.pem"
    from_env.write_text("x")
    monkeypatch.setattr(settings, "ca_bundle", str(configured))
    monkeypatch.setenv("SSL_CERT_FILE", str(from_env))
    assert http.resolve_verify() == str(configured)


def test_insecure_mode_disables_verification_and_warns(monkeypatch, caplog):
    monkeypatch.setattr(settings, "insecure_skip_verify", True)
    with caplog.at_level("WARNING"):
        assert http.resolve_verify() is False
    assert "DISABLED" in caplog.text


async def test_client_carries_a_user_agent_and_the_configured_timeouts(monkeypatch):
    monkeypatch.setattr(settings, "request_timeout_seconds", 12.0)
    monkeypatch.setattr(settings, "connect_timeout_seconds", 3.0)

    async with http.make_client() as client:
        assert client.headers["user-agent"] == http.USER_AGENT
        assert client.timeout.read == 12.0
        assert client.timeout.connect == 3.0
