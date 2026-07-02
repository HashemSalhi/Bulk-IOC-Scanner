"""Core scanning orchestrator — fans out IOCs to all applicable providers."""
import asyncio
import logging

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models.schemas import ProviderResult, ScanResult
from app.models.tables import _utcnow
from app.providers.registry import get_providers
from app.services.ioc_detect import detect, refang
from app.services.ratelimit import limiter
from app.services.risk import compute_risk

logger = logging.getLogger(__name__)

# Shared httpx client timeout
_TIMEOUT = httpx.Timeout(30.0, connect=10.0)

# Recognized IOC types that no current provider can enrich
_NON_ENRICHABLE = {"email", "cve", "asn", "crypto", "unknown"}


async def _run_provider(provider, client, items: list[tuple[str, str]]) -> list[ProviderResult]:
    """Run one provider over all the IOCs it supports.

    Batch-capable providers issue a single paced call via lookup_batch(); others
    fall back to per-IOC lookups, each paced individually through the limiter.
    Always returns exactly len(items) results so callers can rely on the count.
    """
    name = provider.name
    try:
        if provider.batch_capable:
            async with limiter.for_provider(name):
                results = await provider.lookup_batch(client, items)
        else:
            async def _one(ioc, ioc_type):
                async with limiter.for_provider(name):
                    return await provider.lookup(client, ioc, ioc_type)
            results = await asyncio.gather(*(_one(ioc, t) for ioc, t in items))
    except Exception as e:  # a provider should not raise, but never deadlock the caller
        logger.exception("Provider %s batch failed", name)
        return [_provider_error(name, ioc, t, str(e)) for ioc, t in items]

    # Guard against a batch override returning a misaligned set of results.
    if len(results) != len(items):
        logger.error("Provider %s returned %d results for %d items", name, len(results), len(items))
        by_ioc = {r.ioc: r for r in results}
        results = [
            by_ioc.get(ioc) or _provider_error(name, ioc, t, "missing batch result")
            for ioc, t in items
        ]
    return results


def _provider_error(name, ioc, ioc_type, msg) -> ProviderResult:
    return ProviderResult(
        provider=name, ioc=ioc, ioc_type=ioc_type, success=False,
        error=msg, raw={"error": msg},
    )


def _assemble(ioc, ioc_type, provider_results, source_filename=None, file_size=None) -> ScanResult:
    """Build a ScanResult from the provider results gathered for one IOC."""
    if not provider_results:
        if ioc_type in _NON_ENRICHABLE:
            msg = f"Recognized as '{ioc_type}', but no provider enriches this type yet."
        else:
            msg = f"No active provider supports type '{ioc_type}'. Enable one on the Settings page."
        return ScanResult(
            ioc=ioc, ioc_type=ioc_type, risk_score=0.0, risk_band="Low", status="error",
            provider_results=[_provider_error("system", ioc, ioc_type, msg)],
            source_filename=source_filename, file_size=file_size, created_at=_utcnow(),
        )

    detection_ratio = next(
        (r.detection_ratio for r in provider_results if r.success and r.detection_ratio), None
    )
    risk_score, risk_band = compute_risk(provider_results)
    status = "completed" if any(r.success for r in provider_results) else "error"
    return ScanResult(
        ioc=ioc, ioc_type=ioc_type, risk_score=risk_score, risk_band=risk_band,
        detection_ratio=detection_ratio, status=status, provider_results=provider_results,
        source_filename=source_filename, file_size=file_size, created_at=_utcnow(),
    )


async def _gather_provider_results(
    client, providers, typed_iocs: list[tuple[str, str]]
) -> dict[str, list[ProviderResult]]:
    """Provider-major dispatch: each provider receives every IOC it supports in
    one lookup_batch() call. Returns {ioc: [ProviderResult, ...]}."""
    results_by_ioc: dict[str, list[ProviderResult]] = {ioc: [] for ioc, _ in typed_iocs}

    async def run(provider):
        items = [(ioc, t) for ioc, t in typed_iocs if provider.supports(t)]
        if not items:
            return
        for pr in await _run_provider(provider, client, items):
            results_by_ioc.setdefault(pr.ioc, []).append(pr)

    await asyncio.gather(*(run(p) for p in providers))
    return results_by_ioc


def _scan_from_cached(scan, source_filename, file_size) -> ScanResult:
    """Build a ScanResult from a cached DB row (no provider call)."""
    from app.database.crud import hydrate_provider_results

    return ScanResult(
        id=scan.id,
        ioc=scan.ioc,
        ioc_type=scan.ioc_type,
        risk_score=scan.risk_score,
        risk_band=scan.risk_band,
        detection_ratio=scan.detection_ratio,
        status=scan.status,
        tag=scan.tag,
        source_filename=source_filename or scan.source_filename,
        file_size=file_size if file_size is not None else scan.file_size,
        created_at=scan.created_at,
        from_cache=True,
        provider_results=hydrate_provider_results(scan),
    )


async def scan_bulk(
    iocs: list[str],
    source_files: dict[str, tuple[str, int]] | None = None,
    db: AsyncSession | None = None,
    force: bool = False,
) -> list[ScanResult]:
    """
    Scan a list of IOC strings. If `db` is provided and `force` is False, reuse a
    recent stored result (within CACHE_TTL_HOURS) instead of re-hitting providers.
    Cached results carry from_cache=True and a populated id; callers should not
    re-persist them.
    """
    from app.database.crud import get_recent_scan

    providers = get_providers()

    typed_iocs: list[tuple[str, str]] = []
    for ioc in iocs:
        # Refang first so providers receive a valid indicator (e.g. 8[.]8[.]8[.]8 -> 8.8.8.8)
        clean = refang(ioc)
        typed_iocs.append((clean, detect(clean)))

    results: list[ScanResult | None] = [None] * len(typed_iocs)
    to_scan: list[int] = []

    # Cache pass
    for i, (ioc, ioc_type) in enumerate(typed_iocs):
        if db is not None and not force:
            cached = await get_recent_scan(db, ioc, ioc_type, settings.cache_ttl_hours)
            if cached is not None:
                fname, fsize = (source_files or {}).get(ioc, (None, None))
                results[i] = _scan_from_cached(cached, fname, fsize)
                continue
        to_scan.append(i)

    # Live pass for cache misses — dispatch unique IOCs once (provider-major).
    if to_scan:
        unique_typed = list({typed_iocs[i][0]: typed_iocs[i] for i in to_scan}.values())
        async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
            by_ioc = await _gather_provider_results(client, providers, unique_typed)
        for i in to_scan:
            ioc, ioc_type = typed_iocs[i]
            fname, fsize = (source_files or {}).get(ioc, (None, None))
            results[i] = _assemble(ioc, ioc_type, by_ioc.get(ioc, []), fname, fsize)

    return [r for r in results if r is not None]


async def scan_bulk_stream(
    iocs: list[str],
    db: AsyncSession,
    force: bool = False,
):
    """
    Async generator yielding each ScanResult as soon as it's ready (cache hits
    first, then live results as they complete). Persists fresh results inline and
    sets their id before yielding. Used by the NDJSON streaming endpoint.
    """
    from app.database.crud import get_recent_scan, save_scan

    providers = get_providers()
    typed_iocs = [(ioc := refang(i), detect(ioc)) for i in iocs]

    # Cache pass (yield immediately); collect unique live misses.
    seen: set[str] = set()
    misses: list[tuple[str, str]] = []
    for ioc, ioc_type in typed_iocs:
        if not force:
            cached = await get_recent_scan(db, ioc, ioc_type, settings.cache_ttl_hours)
            if cached is not None:
                yield _scan_from_cached(cached, None, None)
                continue
        if ioc in seen:
            continue
        seen.add(ioc)
        misses.append((ioc, ioc_type))

    if not misses:
        return

    type_of = {ioc: t for ioc, t in misses}
    results_by_ioc: dict[str, list[ProviderResult]] = {ioc: [] for ioc, _ in misses}
    # How many provider results to expect per IOC; when it hits 0, the IOC is done.
    pending = {ioc: sum(1 for p in providers if p.supports(t)) for ioc, t in misses}

    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        queue: asyncio.Queue = asyncio.Queue()

        async def run(provider):
            items = [(ioc, t) for ioc, t in misses if provider.supports(t)]
            if items:
                for pr in await _run_provider(provider, client, items):
                    await queue.put(pr)

        producer = asyncio.gather(*(run(p) for p in providers))
        try:
            # IOCs no provider supports are done at once (system message row).
            for ioc, t in misses:
                if pending[ioc] == 0:
                    res = _assemble(ioc, t, [])
                    res.id = await save_scan(db, res)
                    yield res

            remaining = sum(pending.values())
            while remaining > 0:
                pr = await queue.get()
                remaining -= 1
                results_by_ioc[pr.ioc].append(pr)
                pending[pr.ioc] -= 1
                if pending[pr.ioc] == 0:
                    res = _assemble(pr.ioc, type_of[pr.ioc], results_by_ioc[pr.ioc])
                    res.id = await save_scan(db, res)
                    yield res
            await producer
        finally:
            # If the client disconnected mid-stream, the generator is closed and
            # we land here with the producer still running. Cancel it AND await
            # it so its CancelledError is retrieved — otherwise asyncio logs
            # "_GatheringFuture exception was never retrieved".
            producer.cancel()
            try:
                await producer
            except (asyncio.CancelledError, Exception):
                pass
