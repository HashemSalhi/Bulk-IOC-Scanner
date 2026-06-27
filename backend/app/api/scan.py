"""Scan endpoints: text IOCs and file uploads."""
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database.crud import save_scan
from app.database.db import get_db
from app.models.schemas import (
    FileHashInfo,
    FileScanResult,
    ScanRequest,
    ScanResult,
    TagUpdate,
    TextScanRequest,
)
from app.services.hashing import hash_upload
from app.services.ioc_detect import parse_bulk_input
from app.services.scanner import scan_bulk
from app.utils.validation import validate_ioc_list
from app.database.crud import update_scan_tag

router = APIRouter(prefix="/api/scan", tags=["scan"])
logger = logging.getLogger(__name__)


@router.post("", response_model=list[ScanResult])
async def scan_iocs(
    body: ScanRequest,
    force: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """Scan a list of IOC strings (hashes, IPs, domains, URLs)."""
    validated = validate_ioc_list(body.iocs)
    logger.info("Scan request: %d IOCs (force=%s)", len(validated), force)

    results = await scan_bulk(validated, db=db, force=force)

    # Persist fresh results; cached ones already have an id
    for result in results:
        if not result.from_cache:
            result.id = await save_scan(db, result)

    return results


@router.post("/text", response_model=list[ScanResult])
async def scan_text(
    body: TextScanRequest,
    force: bool = False,
    db: AsyncSession = Depends(get_db),
):
    """Accept raw pasted text; split on newline/comma then scan."""
    if not body.text.strip():
        raise HTTPException(status_code=422, detail="No text provided")
    iocs = parse_bulk_input(body.text)
    validated = validate_ioc_list(iocs)
    results = await scan_bulk(validated, db=db, force=force)
    for result in results:
        if not result.from_cache:
            result.id = await save_scan(db, result)
    return results


@router.post("/files", response_model=list[FileScanResult])
async def scan_files(
    files: Annotated[list[UploadFile], File(description="Files to hash and scan")],
    db: AsyncSession = Depends(get_db),
):
    """Upload files; compute hashes locally; scan only the SHA256 hashes."""
    if not files:
        raise HTTPException(status_code=422, detail="No files provided")

    file_results: list[FileScanResult] = []

    for upload in files:
        try:
            hashes = await hash_upload(upload, settings.max_upload_bytes)
        except ValueError as e:
            raise HTTPException(status_code=413, detail=str(e))

        # Only the SHA256 goes out to providers
        source_files = {hashes.sha256: (hashes.filename, hashes.size)}
        scan_results = await scan_bulk([hashes.sha256], source_files=source_files, db=db)
        result = scan_results[0]
        # Always record the upload in history (even on a cache hit) with this filename
        result.id = await save_scan(db, result)

        file_results.append(
            FileScanResult(
                file_info=FileHashInfo(
                    filename=hashes.filename,
                    size=hashes.size,
                    md5=hashes.md5,
                    sha1=hashes.sha1,
                    sha256=hashes.sha256,
                ),
                scan_result=result,
            )
        )

    return file_results


@router.patch("/{scan_id}/tag", response_model=dict)
async def tag_scan(
    scan_id: int,
    body: TagUpdate,
    db: AsyncSession = Depends(get_db),
):
    """Update the tag on a historical scan result."""
    ok = await update_scan_tag(db, scan_id, body.tag)
    if not ok:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "ok", "scan_id": scan_id, "tag": body.tag}
