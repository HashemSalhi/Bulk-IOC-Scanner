"""Retry and backoff behaviour for provider requests."""
import httpx
import pytest

from bulk_ioc_scanner.providers import http as provider_http
from bulk_ioc_scanner.providers.http import ProviderRequestError, request_with_retry
from bulk_ioc_scanner.services.ratelimit import limiter


@pytest.fixture(autouse=True)
def no_real_sleeping(monkeypatch):
    """Keep the backoff logic, drop the wall-clock cost."""
    slept = []

    async def _instant(seconds):
        slept.append(seconds)

    monkeypatch.setattr(provider_http.asyncio, "sleep", _instant)
    return slept


def client_for(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def get(client, **kwargs):
    return await request_with_retry(client, "GET", "https://example.test/x",
                                    provider="testprovider", **kwargs)


async def test_success_on_the_first_attempt_does_not_sleep(no_real_sleeping):
    async with client_for(lambda r: httpx.Response(200, json={"ok": True})) as client:
        res = await get(client)
    assert res.status_code == 200
    assert no_real_sleeping == []


async def test_rate_limit_then_success():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "2"})
        return httpx.Response(200, json={"ok": True})

    async with client_for(handler) as client:
        res = await get(client)

    assert res.status_code == 200
    assert calls["n"] == 2


async def test_rate_limit_waits_for_the_retry_after_value(no_real_sleeping):
    def handler(request):
        return httpx.Response(429, headers={"Retry-After": "7"})

    async with client_for(handler) as client:
        res = await get(client)

    assert res.status_code == 429  # returned so the provider can report it
    assert no_real_sleeping[0] == 7.0


async def test_rate_limit_penalizes_the_whole_provider(monkeypatch):
    """A 429 must slow every later call for that provider, not just this one."""
    recorded = []
    monkeypatch.setattr(
        limiter, "penalize", lambda name, seconds: recorded.append((name, seconds))
    )

    async with client_for(lambda r: httpx.Response(429, headers={"Retry-After": "5"})) as client:
        await get(client)

    assert ("testprovider", 5.0) in recorded


@pytest.mark.parametrize("status", sorted(provider_http.RETRYABLE_STATUSES))
async def test_transient_server_errors_are_retried(status):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] < provider_http.MAX_ATTEMPTS:
            return httpx.Response(status)
        return httpx.Response(200, json={"ok": True})

    async with client_for(handler) as client:
        res = await get(client)

    assert res.status_code == 200
    assert calls["n"] == provider_http.MAX_ATTEMPTS


async def test_client_errors_are_not_retried():
    """A 404 or 401 is a real answer; retrying wastes quota."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(404)

    async with client_for(handler) as client:
        res = await get(client)

    assert res.status_code == 404
    assert calls["n"] == 1


async def test_dropped_connections_are_retried():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ReadError("connection reset")
        return httpx.Response(200, json={"ok": True})

    async with client_for(handler) as client:
        res = await get(client)

    assert res.status_code == 200
    assert calls["n"] == 2


async def test_persistent_transport_failure_raises_a_readable_error():
    def handler(request):
        raise httpx.ConnectTimeout("timed out")

    async with client_for(handler) as client:
        with pytest.raises(ProviderRequestError) as excinfo:
            await get(client)

    assert "proxy" in str(excinfo.value)


async def test_dns_failure_is_not_retried():
    """A name that does not resolve will not resolve on the next attempt either."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ConnectError("Name or service not known")

    async with client_for(handler) as client:
        with pytest.raises(ProviderRequestError):
            await get(client)

    assert calls["n"] == 1


async def test_backoff_grows_between_attempts(no_real_sleeping):
    async with client_for(lambda r: httpx.Response(503)) as client:
        await get(client)

    assert len(no_real_sleeping) == provider_http.MAX_ATTEMPTS - 1
    assert no_real_sleeping[1] > no_real_sleeping[0]


async def test_connect_error_message_names_the_configured_proxy(monkeypatch):
    from bulk_ioc_scanner.config import settings

    monkeypatch.setattr(settings, "proxy_url", "http://proxy.corp:8080")

    def handler(request):
        raise httpx.ConnectError("nope")

    async with client_for(handler) as client:
        with pytest.raises(ProviderRequestError) as excinfo:
            await get(client)

    assert "proxy.corp:8080" in str(excinfo.value)
