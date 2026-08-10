"""Input validation helpers."""
from fastapi import HTTPException

from bulk_ioc_scanner.config import settings


def validate_ioc_list(iocs: list[str]) -> list[str]:
    """Strip, deduplicate (order-preserving), and enforce the per-scan cap."""
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in iocs:
        item = raw.strip()
        if item and item not in seen:
            seen.add(item)
            cleaned.append(item)
    if not cleaned:
        raise HTTPException(status_code=422, detail="No valid IOCs provided")
    if len(cleaned) > settings.max_iocs_per_scan:
        raise HTTPException(
            status_code=422,
            detail=f"Too many IOCs: {len(cleaned)} submitted, max is {settings.max_iocs_per_scan}",
        )
    return cleaned
