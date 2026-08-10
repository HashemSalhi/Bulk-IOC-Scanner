"""
Simple async rate limiter to pace outbound provider requests.

Free API tiers are strict (e.g. VirusTotal = 4 req/min). This enforces a minimum
interval between calls per provider so a bulk scan doesn't instantly hit HTTP 429.
Concurrent scan tasks serialize through the per-provider lock.
"""
import asyncio
import time

import httpx

from bulk_ioc_scanner.config import settings


MAX_RETRY_AFTER = 60.0


def retry_after_seconds(response: "httpx.Response", default: float = 15.0) -> float:
    """Seconds to wait per a Retry-After header, clamped to a sane range.

    The header comes in two forms: a delay in seconds, or an HTTP date. Both are
    accepted; anything else falls back to `default`.
    """
    value = (response.headers.get("Retry-After") or "").strip()
    if not value:
        return default

    try:
        return min(max(float(value), 1.0), MAX_RETRY_AFTER)
    except ValueError:
        pass

    # HTTP-date form, e.g. "Wed, 21 Oct 2015 07:28:00 GMT"
    from email.utils import parsedate_to_datetime

    try:
        target = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return default
    if target is None:
        return default

    import datetime as _dt

    if target.tzinfo is None:
        target = target.replace(tzinfo=_dt.timezone.utc)
    delta = (target - _dt.datetime.now(_dt.timezone.utc)).total_seconds()
    if delta <= 0:
        return default
    return min(max(delta, 1.0), MAX_RETRY_AFTER)

# Map provider name -> configured requests/min
_RATES = {
    "virustotal": settings.vt_rate_per_min,
    "abuseipdb": settings.abuseipdb_rate_per_min,
    "greynoise": settings.greynoise_rate_per_min,
    "threatfox": settings.threatfox_rate_per_min,
    "urlscan": settings.urlscan_rate_per_min,
    "ipify": settings.ipify_rate_per_min,
    "rdap": 60,  # rdap.org is generous; keep a sane default
}


class _ProviderLimiter:
    def __init__(self, per_min: int):
        self._min_interval = 60.0 / per_min if per_min > 0 else 0.0
        self._lock = asyncio.Lock()
        self._last = 0.0
        self._cooldown_until = 0.0

    async def __aenter__(self):
        await self._lock.acquire()
        wait = 0.0
        if self._min_interval:
            wait = self._min_interval - (time.monotonic() - self._last)
        # A 429 applies to the whole provider, not just the request that saw it,
        # so every later call waits out the cooldown too.
        wait = max(wait, self._cooldown_until - time.monotonic())
        if wait > 0:
            await asyncio.sleep(wait)
        self._last = time.monotonic()
        return self

    async def __aexit__(self, *exc):
        self._lock.release()
        return False

    def penalize(self, seconds: float) -> None:
        """Hold off on this provider for at least `seconds` from now."""
        self._cooldown_until = max(self._cooldown_until, time.monotonic() + seconds)


class RateLimiter:
    def __init__(self):
        self._limiters: dict[str, _ProviderLimiter] = {}

    def for_provider(self, name: str) -> _ProviderLimiter:
        if name not in self._limiters:
            self._limiters[name] = _ProviderLimiter(_RATES.get(name, 60))
        return self._limiters[name]

    def penalize(self, name: str, seconds: float) -> None:
        """Record that a provider asked us to back off (a 429)."""
        self.for_provider(name).penalize(seconds)


# Process-wide limiter shared across all scans
limiter = RateLimiter()
