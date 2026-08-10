"""Tests for the rate limiter and Retry-After parsing."""
import time
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx

from bulk_ioc_scanner.services.ratelimit import RateLimiter, _ProviderLimiter, retry_after_seconds


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


def test_retry_after_accepts_the_http_date_form():
    """RFC 9110 allows a date as well as a delay; both are valid from a server."""
    soon = datetime.now(timezone.utc) + timedelta(seconds=20)
    header = format_datetime(soon, usegmt=True)
    assert 10 <= retry_after_seconds(httpx.Response(429, headers={"Retry-After": header})) <= 21


def test_retry_after_in_the_past_uses_the_default():
    past = format_datetime(datetime.now(timezone.utc) - timedelta(hours=1), usegmt=True)
    assert retry_after_seconds(httpx.Response(429, headers={"Retry-After": past}), default=8) == 8.0


def test_retry_after_garbage_uses_the_default():
    resp = httpx.Response(429, headers={"Retry-After": "soon-ish"})
    assert retry_after_seconds(resp, default=12) == 12.0


async def test_penalty_delays_the_next_call():
    """A 429 backs off every later call for that provider, not just the one that saw it."""
    lim = _ProviderLimiter(per_min=0)  # no pacing, so only the penalty can delay us
    lim.penalize(0.3)

    start = time.monotonic()
    async with lim:
        pass
    assert time.monotonic() - start >= 0.3


async def test_penalty_keeps_the_longest_cooldown():
    lim = _ProviderLimiter(per_min=0)
    lim.penalize(0.4)
    lim.penalize(0.05)  # must not shorten the existing back-off

    start = time.monotonic()
    async with lim:
        pass
    assert time.monotonic() - start >= 0.4


def test_penalize_routes_to_the_right_provider():
    rl = RateLimiter()
    rl.penalize("virustotal", 5)
    assert rl.for_provider("virustotal")._cooldown_until > 0
    assert rl.for_provider("abuseipdb")._cooldown_until == 0
