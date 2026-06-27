"""
Simple async rate limiter to pace outbound provider requests.

Free API tiers are strict (e.g. VirusTotal = 4 req/min). This enforces a minimum
interval between calls per provider so a bulk scan doesn't instantly hit HTTP 429.
Concurrent scan tasks serialize through the per-provider lock.
"""
import asyncio
import time

import httpx

from app.config import settings


def retry_after_seconds(response: "httpx.Response", default: float = 15.0) -> float:
    """Parse a Retry-After header (seconds) from a 429 response; fall back to default."""
    value = response.headers.get("Retry-After", "")
    try:
        return min(max(float(value), 1.0), 60.0)
    except (TypeError, ValueError):
        return default

# Map provider name -> configured requests/min
_RATES = {
    "virustotal": settings.vt_rate_per_min,
    "abuseipdb": settings.abuseipdb_rate_per_min,
    "greynoise": settings.greynoise_rate_per_min,
    "threatfox": settings.threatfox_rate_per_min,
    "urlscan": settings.urlscan_rate_per_min,
}


class _ProviderLimiter:
    def __init__(self, per_min: int):
        self._min_interval = 60.0 / per_min if per_min > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last = 0.0

    async def __aenter__(self):
        await self._lock.acquire()
        if self._min_interval:
            wait = self._min_interval - (time.monotonic() - self._last)
            if wait > 0:
                await asyncio.sleep(wait)
        self._last = time.monotonic()
        return self

    async def __aexit__(self, *exc):
        self._lock.release()
        return False


class RateLimiter:
    def __init__(self):
        self._limiters: dict[str, _ProviderLimiter] = {}

    def for_provider(self, name: str) -> _ProviderLimiter:
        if name not in self._limiters:
            self._limiters[name] = _ProviderLimiter(_RATES.get(name, 60))
        return self._limiters[name]


# Process-wide limiter shared across all scans
limiter = RateLimiter()
