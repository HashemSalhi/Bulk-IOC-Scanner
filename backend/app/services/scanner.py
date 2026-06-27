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


async def _paced_lookup(provider, client, ioc, ioc_type) -> ProviderResult:
    """Run a provider lookup through its rate limiter."""
    async with limiter.for_provider(provider.name):
        return await provider.lookup(client, ioc, ioc_type)


async def scan_ioc(
    client: httpx.AsyncClient,
    providers: list,
    ioc: str,
    ioc_type: str,
    source_filename: str | None = None,
    file_size: int | None = None,
) -> ScanResult:
    """Dispatch a single IOC to all supporting providers (rate-paced)."""
    applicable = [p for p in providers if p.supports(ioc_type)]

    if not applicable:
        pr = ProviderResult(
            provider="system",
            ioc=ioc,
            ioc_type=ioc_type,
            success=False,
            error=f"No configured provider supports type '{ioc_type}'. Add an API key on the Settings page.",
            raw={"error": "No provider available"},
        )
        return ScanResult(
            ioc=ioc,
            ioc_type=ioc_type,
            risk_score=0.0,
            risk_band="Low",
            status="error",
            provider_results=[pr],
            source_filename=source_filename,
            file_size=file_size,
            created_at=_utcnow(),
        )

    tasks = [_paced_lookup(p, client, ioc, ioc_type) for p in applicable]
    results: list[ProviderResult] = await asyncio.gather(*tasks, return_exceptions=False)

    # Determine detection_ratio from first successful provider with one
    detection_ratio = None
    for r in results:
        if r.success and r.detection_ratio:
            detection_ratio = r.detection_ratio
            break

    risk_score, risk_band = compute_risk(results)
    status = "completed" if any(r.success for r in results) else "error"

    return ScanResult(
        ioc=ioc,
        ioc_type=ioc_type,
        risk_score=risk_score,
        risk_band=risk_band,
        detection_ratio=detection_ratio,
        status=status,
        provider_results=results,
        source_filename=source_filename,
        file_size=file_size,
        created_at=_utcnow(),
    )


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

    # Live pass for cache misses
    if to_scan:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            tasks = []
            for i in to_scan:
                ioc, ioc_type = typed_iocs[i]
                fname, fsize = (source_files or {}).get(ioc, (None, None))
                tasks.append(scan_ioc(client, providers, ioc, ioc_type, fname, fsize))
            scanned = await asyncio.gather(*tasks)
        for idx, res in zip(to_scan, scanned):
            results[idx] = res

    return [r for r in results if r is not None]
