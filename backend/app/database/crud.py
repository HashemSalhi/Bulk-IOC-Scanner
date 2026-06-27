import json

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.schemas import ProviderResult, ScanResult
from app.models.tables import ApiKey, ProviderResponse, Scan, _utcnow


async def save_scan(db: AsyncSession, result: ScanResult) -> int:
    """Persist a ScanResult and its ProviderResults; returns the new Scan.id."""
    scan = Scan(
        ioc=result.ioc,
        ioc_type=result.ioc_type,
        risk_score=result.risk_score,
        risk_band=result.risk_band,
        detection_ratio=result.detection_ratio,
        status=result.status,
        tag=result.tag,
        source_filename=result.source_filename,
        file_size=result.file_size,
        created_at=result.created_at or _utcnow(),
        summary_json=json.dumps(_build_summary(result)),
    )
    db.add(scan)
    await db.flush()  # get scan.id before adding children

    for pr in result.provider_results:
        db.add(
            ProviderResponse(
                scan_id=scan.id,
                provider=pr.provider,
                success=pr.success,
                raw_json=json.dumps(pr.raw) if pr.raw else None,
            )
        )

    await db.commit()
    await db.refresh(scan)
    return scan.id


async def update_scan_tag(db: AsyncSession, scan_id: int, tag: str | None) -> bool:
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if scan is None:
        return False
    scan.tag = tag
    await db.commit()
    return True


async def list_scans(db: AsyncSession, limit: int = 500) -> list[Scan]:
    result = await db.execute(
        select(Scan).order_by(desc(Scan.created_at)).limit(limit)
    )
    return list(result.scalars().all())


async def get_recent_scan(
    db: AsyncSession, ioc: str, ioc_type: str, max_age_hours: int
) -> Scan | None:
    """
    Return the newest successful scan for this IOC within the cache window,
    with provider responses eagerly loaded. Returns None on a miss.
    """
    from datetime import timedelta

    cutoff = _utcnow() - timedelta(hours=max_age_hours)
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.provider_responses))
        .where(
            Scan.ioc == ioc,
            Scan.ioc_type == ioc_type,
            Scan.status == "completed",
            Scan.created_at >= cutoff,
        )
        .order_by(desc(Scan.created_at))
        .limit(1)
    )
    return result.scalar_one_or_none()


async def get_scan(db: AsyncSession, scan_id: int) -> Scan | None:
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.provider_responses))
        .where(Scan.id == scan_id)
    )
    return result.scalar_one_or_none()


async def get_stats(db: AsyncSession) -> dict:
    """Return aggregate counts for the dashboard."""
    all_scans = await list_scans(db, limit=10000)
    total = len(all_scans)
    malicious = sum(1 for s in all_scans if s.risk_band == "High")
    suspicious = sum(1 for s in all_scans if s.risk_band == "Medium")
    clean = sum(1 for s in all_scans if s.risk_band == "Low")
    return {
        "total": total,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean,
    }


def _build_summary(result: ScanResult) -> dict:
    return {
        "ioc": result.ioc,
        "ioc_type": result.ioc_type,
        "risk_score": result.risk_score,
        "risk_band": result.risk_band,
        "detection_ratio": result.detection_ratio,
    }


def hydrate_provider_results(scan: Scan) -> list[ProviderResult]:
    """Reconstruct ProviderResult list from stored ProviderResponse rows."""
    out = []
    for pr in scan.provider_responses:
        raw = json.loads(pr.raw_json) if pr.raw_json else {}
        out.append(
            ProviderResult(
                provider=pr.provider,
                ioc=scan.ioc,
                ioc_type=scan.ioc_type,
                success=bool(pr.success),
                error=raw.get("error"),
                malicious=raw.get("malicious"),
                suspicious=raw.get("suspicious"),
                harmless=raw.get("harmless"),
                undetected=raw.get("undetected"),
                detection_ratio=raw.get("detection_ratio"),
                raw=raw,
            )
        )
    return out


# ── API key persistence ────────────────────────────────────────────────────────

async def get_all_api_keys(db: AsyncSession) -> dict[str, str]:
    """Return {provider: key_value} for all stored keys."""
    result = await db.execute(select(ApiKey))
    return {row.provider: row.key_value for row in result.scalars().all()}


async def upsert_api_key(db: AsyncSession, provider: str, key_value: str) -> None:
    """Insert or update the key for a provider."""
    result = await db.execute(select(ApiKey).where(ApiKey.provider == provider))
    row = result.scalar_one_or_none()
    if row:
        row.key_value = key_value
        row.updated_at = _utcnow()
    else:
        db.add(ApiKey(provider=provider, key_value=key_value))
    await db.commit()
