"""Tests for the rate limiter and Retry-After parsing."""
import time

import httpx

from app.services.ratelimit import RateLimiter, _ProviderLimiter, retry_after_seconds


async def test_limiter_spaces_calls():
    # 120/min => 0.5s min interval
    lim = _ProviderLimiter(per_min=120)
    start = time.monotonic()
    async with lim:
        pass
    async with lim:
        pass
    elapsed = time.monotonic() - start
    assert elapsed >= 0.5


async def test_limiter_zero_rate_no_wait():
    lim = _ProviderLimiter(per_min=0)
    start = time.monotonic()
    async with lim:
        pass
    assert time.monotonic() - start < 0.1


def test_rate_limiter_caches_per_provider():
    rl = RateLimiter()
    a = rl.for_provider("virustotal")
    b = rl.for_provider("virustotal")
    assert a is b


def test_retry_after_parsing():
    resp = httpx.Response(429, headers={"Retry-After": "5"})
    assert retry_after_seconds(resp) == 5.0
    # missing header -> default
    assert retry_after_seconds(httpx.Response(429), default=15) == 15.0
    # absurd value clamped to 60
    assert retry_after_seconds(httpx.Response(429, headers={"Retry-After": "9999"})) == 60.0
