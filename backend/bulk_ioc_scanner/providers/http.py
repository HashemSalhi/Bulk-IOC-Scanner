"""The HTTP client every provider request goes through.

Corporate networks are the normal case for a SOC tool: outbound traffic goes
via a proxy, and TLS is often intercepted by an internal certificate authority.
Both are configurable here so provider lookups do not simply fail with an
unexplained connection error.
"""
import logging
import os

import httpx

from bulk_ioc_scanner.config import settings

logger = logging.getLogger(__name__)

USER_AGENT = "Bulk-IOC-Scanner (+https://github.com/HashemSalhi/Bulk-IOC-Scanner)"

# Variables other security tools already use for a corporate CA bundle. Reusing
# them means an analyst who has configured curl or pip is already configured here.
_CA_ENV_VARS = ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE")


def resolve_verify() -> bool | str:
    """Return the value for httpx's `verify`: a CA bundle path, or True/False."""
    if settings.insecure_skip_verify:
        logger.warning(
            "TLS certificate verification is DISABLED for provider requests "
            "(insecure_skip_verify). Set ca_bundle to your organisation's CA "
            "certificate instead."
        )
        return False

    configured = settings.ca_bundle.strip()
    if configured:
        if os.path.exists(configured):
            logger.info("Using CA bundle %s for provider requests", configured)
            return configured
        logger.error(
            "ca_bundle points at %s, which does not exist. Falling back to the "
            "default trust store; provider requests may fail.", configured
        )
        return True

    for var in _CA_ENV_VARS:
        value = (os.environ.get(var) or "").strip()
        if value and os.path.exists(value):
            logger.info("Using CA bundle from %s (%s)", var, value)
            return value

    return True


def resolve_proxy() -> str | None:
    """Explicit proxy setting, or None to let httpx read the environment."""
    configured = settings.proxy_url.strip()
    if configured:
        logger.info("Routing provider requests through proxy %s", configured)
        return configured
    return None


def make_client() -> httpx.AsyncClient:
    """Build the client used for one scan.

    `trust_env` stays on, so HTTP_PROXY / HTTPS_PROXY / NO_PROXY apply unless a
    proxy is configured explicitly.
    """
    timeout = httpx.Timeout(
        settings.request_timeout_seconds,
        connect=settings.connect_timeout_seconds,
    )
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=resolve_verify(),
        proxy=resolve_proxy(),
        trust_env=True,
        headers={"User-Agent": USER_AGENT},
    )
