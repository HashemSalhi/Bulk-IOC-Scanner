"""Scan history endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.crud import (
    clear_scans,
    count_scans,
    get_scan,
    get_stats,
    hydrate_provider_results,
    list_scans,
)
from app.database.db import get_db
from app.models.schemas import HistoryPage, ScanDetail, ScanHistoryItem

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("", response_model=HistoryPage)
async def get_history(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    q: str | None = Query(None, description="Substring match on the IOC"),
    tag: str | None = Query(None, description="Filter by tag"),
    db: AsyncSession = Depends(get_db),
):
    """Return a page of scans (newest first) plus the total matching count."""
    scans = await list_scans(db, limit=limit, offset=offset, q=q, tag=tag)
    total = await count_scans(db, q=q, tag=tag)
    return HistoryPage(
        items=[ScanHistoryItem.model_validate(s) for s in scans],
        total=total,
    )


@router.delete("", response_model=dict)
async def clear_history(
    q: str | None = Query(None, description="Only clear scans whose IOC matches"),
    tag: str | None = Query(None, description="Only clear scans with this tag"),
    db: AsyncSession = Depends(get_db),
):
    """Delete scan history. With no filters, clears everything; with q/tag,
    clears only the matching scans."""
    deleted = await clear_scans(db, q=q, tag=tag)
    return {"status": "ok", "deleted": deleted}


@router.get("/stats", response_model=dict)
async def history_stats(db: AsyncSession = Depends(get_db)):
    """Aggregate counts for the dashboard."""
    return await get_stats(db)


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan_detail(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Return full scan detail including per-provider results."""
    scan = await get_scan(db, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    detail = ScanDetail.model_validate(scan)
    detail.provider_results = hydrate_provider_results(scan)
    return detail
