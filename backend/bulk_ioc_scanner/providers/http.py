"""The HTTP client every provider request goes through.

Corporate networks are the normal case for a SOC tool: outbound traffic goes
via a proxy, and TLS is often intercepted by an internal certificate authority.
Both are configurable here so provider lookups do not simply fail with an
unexplained connection error.
"""
import asyncio
import logging
import os
import random

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


# ── Retrying requests ─────────────────────────────────────────────────────────

MAX_ATTEMPTS = 3
BASE_BACKOFF_SECONDS = 1.0

# Transient server-side states. 429 is handled separately because the server
# usually tells us how long to wait.
RETRYABLE_STATUSES = frozenset({502, 503, 504})

# Transport-level failures worth one more go: a dropped connection or a slow
# proxy is often gone by the next attempt. DNS and TLS failures are not
# included — they fail the same way every time and retrying only wastes a scan.
RETRYABLE_ERRORS = (
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.PoolTimeout,
    httpx.ReadError,
    httpx.WriteError,
    httpx.RemoteProtocolError,
)


class ProviderRequestError(Exception):
    """A request that could not be completed, with a message worth showing.

    Providers turn this into a failed ProviderResult, so a dead endpoint costs
    that provider's results and nothing else.
    """


def describe_transport_error(exc: Exception) -> str:
    """Explain a connection failure in terms an analyst can act on."""
    if isinstance(exc, httpx.ConnectTimeout):
        return "timed out connecting (check your proxy settings)"
    if isinstance(exc, (httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout)):
        return "the request timed out"
    if isinstance(exc, httpx.ProxyError):
        return f"the proxy refused the connection ({exc})"
    if isinstance(exc, httpx.ConnectError):
        hint = (
            "check your network, proxy, or CA bundle settings"
            if not settings.proxy_url
            else f"check that the proxy {settings.proxy_url} is reachable"
        )
        return f"could not connect ({hint})"
    if isinstance(exc, httpx.TimeoutException):
        return "the request timed out"
    return str(exc) or exc.__class__.__name__


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with jitter, so retries do not arrive in lockstep."""
    return BASE_BACKOFF_SECONDS * (2 ** attempt) * (0.5 + random.random())


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    provider: str,
    max_attempts: int = MAX_ATTEMPTS,
    **kwargs,
) -> httpx.Response:
    """Perform one provider request, retrying the failures worth retrying.

    Returns the response whatever its status, so callers keep their own
    handling of 404 and friends. Raises ProviderRequestError when the request
    could not be completed at all, or when retries ran out on a transient
    failure.
    """
    from bulk_ioc_scanner.services.ratelimit import limiter, retry_after_seconds

    last_error = "request failed"

    for attempt in range(max_attempts):
        is_last = attempt == max_attempts - 1
        try:
            response = await client.request(method, url, **kwargs)
        except RETRYABLE_ERRORS as e:
            last_error = describe_transport_error(e)
            if is_last:
                raise ProviderRequestError(last_error) from e
            logger.warning(
                "%s: %s — retrying (attempt %d of %d)",
                provider, last_error, attempt + 1, max_attempts,
            )
            await asyncio.sleep(_backoff_delay(attempt))
            continue
        except httpx.HTTPError as e:
            # DNS failures, TLS verification, invalid URLs: retrying will not help.
            raise ProviderRequestError(describe_transport_error(e)) from e

        if response.status_code == 429:
            wait = retry_after_seconds(response)
            # The limit belongs to the provider, not to this one request, so
            # make every later call for it wait as well.
            limiter.penalize(provider, wait)
            if is_last:
                return response  # let the caller report it as a rate-limit error
            logger.warning(
                "%s: rate limited, waiting %.1fs before retrying (attempt %d of %d)",
                provider, wait, attempt + 1, max_attempts,
            )
            await asyncio.sleep(wait)
            continue

        if response.status_code in RETRYABLE_STATUSES and not is_last:
            logger.warning(
                "%s: HTTP %d — retrying (attempt %d of %d)",
                provider, response.status_code, attempt + 1, max_attempts,
            )
            await asyncio.sleep(_backoff_delay(attempt))
            continue

        return response

    raise ProviderRequestError(last_error)  # pragma: no cover - loop always returns
