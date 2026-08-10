"""A failing provider must cost its own results and nothing else.

The guarantee under test: every IOC submitted comes back with exactly one
result, whatever the providers do.
"""
import httpx
import pytest

from bulk_ioc_scanner.models.schemas import ProviderResult
from bulk_ioc_scanner.providers.base import Provider
from bulk_ioc_scanner.services import scanner
from bulk_ioc_scanner.services.scanner import _gather_provider_results, scan_bulk

IOCS = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


class HealthyProvider(Provider):
    name = "healthy"

    def supports(self, ioc_type):
        return ioc_type == "ip"

    async def lookup(self, client, ioc, ioc_type):
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
            harmless=1, raw={},
        )


class PoisonPillProvider(HealthyProvider):
    """Raises for one specific IOC and succeeds for the rest."""
    name = "poison"

    def __init__(self, bad_ioc):
        self.bad_ioc = bad_ioc

    async def lookup(self, client, ioc, ioc_type):
        if ioc == self.bad_ioc:
            raise RuntimeError("provider exploded on this one")
        return await super().lookup(client, ioc, ioc_type)


class DeadProvider(HealthyProvider):
    name = "dead"

    async def lookup(self, client, ioc, ioc_type):
        raise httpx.ConnectError("host unreachable")


class LyingBatchProvider(HealthyProvider):
    """A batch override that answers about an IOC nobody asked for."""
    name = "liar"
    batch_capable = True

    async def lookup_batch(self, client, items):
        return [
            ProviderResult(
                provider=self.name, ioc="not-in-this-batch", ioc_type="ip",
                success=True, raw={},
            )
            for _ in items
        ]


@pytest.fixture
def client():
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))


async def test_one_bad_ioc_does_not_take_down_its_siblings(client):
    """The exact regression: gather without return_exceptions lost the batch."""
    provider = PoisonPillProvider(bad_ioc="1.1.1.1")
    typed = [(ioc, "ip") for ioc in IOCS]

    async with client as c:
        by_ioc = await _gather_provider_results(c, [provider], typed)

    assert set(by_ioc) == set(IOCS)
    assert by_ioc["1.1.1.1"][0].success is False
    assert "exploded" in by_ioc["1.1.1.1"][0].error
    assert by_ioc["8.8.8.8"][0].success is True
    assert by_ioc["9.9.9.9"][0].success is True


async def test_a_dead_provider_leaves_the_healthy_one_intact(client):
    typed = [(ioc, "ip") for ioc in IOCS]

    async with client as c:
        by_ioc = await _gather_provider_results(c, [DeadProvider(), HealthyProvider()], typed)

    for ioc in IOCS:
        outcomes = {r.provider: r.success for r in by_ioc[ioc]}
        assert outcomes == {"dead": False, "healthy": True}


async def test_every_ioc_gets_exactly_one_result_when_a_provider_dies(monkeypatch):
    monkeypatch.setattr(scanner, "get_providers", lambda: [DeadProvider()])

    results = await scan_bulk(IOCS)

    assert [r.ioc for r in results] == IOCS
    assert all(r.status == "error" for r in results)


async def test_misaligned_batch_results_are_backfilled(client):
    """A provider that answers about the wrong IOC must not drop the others."""
    typed = [(ioc, "ip") for ioc in IOCS]

    async with client as c:
        by_ioc = await _gather_provider_results(c, [LyingBatchProvider()], typed)

    for ioc in IOCS:
        assert len(by_ioc[ioc]) == 1
        assert by_ioc[ioc][0].success is False
        assert "missing batch result" in by_ioc[ioc][0].error


async def test_no_active_provider_explains_what_to_do(monkeypatch):
    """First run with no API keys: a hash has no provider that handles it."""
    monkeypatch.setattr(scanner, "get_providers", lambda: [])

    results = await scan_bulk(["44d88612fea8a8f36de82e1278abb02f"])

    assert len(results) == 1
    assert results[0].status == "error"
    assert "Settings page" in results[0].provider_results[0].error


async def test_batch_fallback_isolates_a_single_failure(client):
    """Provider.lookup_batch's default implementation has the same guarantee."""
    provider = PoisonPillProvider(bad_ioc="9.9.9.9")
    items = [(ioc, "ip") for ioc in IOCS]

    async with client as c:
        results = await provider.lookup_batch(c, items)

    assert len(results) == len(IOCS)
    by_ioc = {r.ioc: r for r in results}
    assert by_ioc["9.9.9.9"].success is False
    assert by_ioc["8.8.8.8"].success is True
