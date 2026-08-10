"""Tests for the provider batch (lookup_batch) mechanism and per-IOC fallback."""
import httpx

from bulk_ioc_scanner.models.schemas import ProviderResult
from bulk_ioc_scanner.providers.base import Provider
from bulk_ioc_scanner.services.scanner import _gather_provider_results


class CountingProvider(Provider):
    """Records how many lookup() and lookup_batch() calls it receives."""
    name = "counting"

    def __init__(self, batch_capable=False):
        self.batch_capable = batch_capable
        self.lookup_calls = 0
        self.batch_calls = 0

    def supports(self, ioc_type):
        return ioc_type in {"ip", "domain"}

    async def lookup(self, client, ioc, ioc_type):
        self.lookup_calls += 1
        return ProviderResult(provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
                              detection_ratio="ok", raw={})

    async def lookup_batch(self, client, items):
        self.batch_calls += 1
        # One request for the whole set: return a result per item.
        return [ProviderResult(provider=self.name, ioc=ioc, ioc_type=t, success=True,
                               detection_ratio="bulk", raw={"bulk": True})
                for ioc, t in items]


def _noop_client():
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))


async def test_batch_capable_provider_makes_one_call(monkeypatch):
    # Disable pacing so the test is instant
    from bulk_ioc_scanner.services import scanner
    class _NoLimit:
        async def __aenter__(self): return self
        async def __aexit__(self, *e): return False
    monkeypatch.setattr(scanner.limiter, "for_provider", lambda n: _NoLimit())

    p = CountingProvider(batch_capable=True)
    typed = [("1.1.1.1", "ip"), ("8.8.8.8", "ip"), ("example.com", "domain")]
    async with _noop_client() as client:
        by_ioc = await _gather_provider_results(client, [p], typed)

    assert p.batch_calls == 1          # ONE request for all three IOCs
    assert p.lookup_calls == 0
    assert set(by_ioc) == {"1.1.1.1", "8.8.8.8", "example.com"}
    assert by_ioc["8.8.8.8"][0].raw == {"bulk": True}


async def test_non_batch_provider_falls_back_to_per_ioc(monkeypatch):
    from bulk_ioc_scanner.services import scanner
    class _NoLimit:
        async def __aenter__(self): return self
        async def __aexit__(self, *e): return False
    monkeypatch.setattr(scanner.limiter, "for_provider", lambda n: _NoLimit())

    p = CountingProvider(batch_capable=False)
    typed = [("1.1.1.1", "ip"), ("8.8.8.8", "ip"), ("example.com", "domain")]
    async with _noop_client() as client:
        by_ioc = await _gather_provider_results(client, [p], typed)

    assert p.batch_calls == 0
    assert p.lookup_calls == 3          # one call per IOC (fallback)
    assert len(by_ioc) == 3


async def test_provider_only_gets_supported_iocs(monkeypatch):
    from bulk_ioc_scanner.services import scanner
    class _NoLimit:
        async def __aenter__(self): return self
        async def __aexit__(self, *e): return False
    monkeypatch.setattr(scanner.limiter, "for_provider", lambda n: _NoLimit())

    p = CountingProvider(batch_capable=True)
    # 'md5' is unsupported -> excluded from the batch
    typed = [("1.1.1.1", "ip"), ("abc123", "md5")]
    async with _noop_client() as client:
        by_ioc = await _gather_provider_results(client, [p], typed)

    assert p.batch_calls == 1
    assert by_ioc["1.1.1.1"]            # supported IOC enriched
    assert by_ioc["abc123"] == []      # unsupported IOC got no provider result


async def test_misaligned_batch_result_is_repaired(monkeypatch):
    """A buggy batch override returning too few results must not lose IOCs."""
    from bulk_ioc_scanner.services import scanner
    class _NoLimit:
        async def __aenter__(self): return self
        async def __aexit__(self, *e): return False
    monkeypatch.setattr(scanner.limiter, "for_provider", lambda n: _NoLimit())

    class ShortProvider(CountingProvider):
        async def lookup_batch(self, client, items):
            # Bug: only returns the first item's result
            ioc, t = items[0]
            return [ProviderResult(provider=self.name, ioc=ioc, ioc_type=t, success=True, raw={})]

    p = ShortProvider(batch_capable=True)
    typed = [("1.1.1.1", "ip"), ("8.8.8.8", "ip")]
    async with _noop_client() as client:
        by_ioc = await _gather_provider_results(client, [p], typed)

    # Both IOCs still have exactly one result; the missing one is an error placeholder
    assert len(by_ioc["1.1.1.1"]) == 1
    assert len(by_ioc["8.8.8.8"]) == 1
    assert by_ioc["8.8.8.8"][0].success is False
