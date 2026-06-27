"""Tests for provider response parsing using a mocked httpx transport."""
import httpx
import pytest

from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.virustotal import VirusTotalProvider


def make_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ── VirusTotal ────────────────────────────────────────────────────────────────

async def test_vt_hash_malicious():
    def handler(request):
        assert "x-apikey" in request.headers
        return httpx.Response(200, json={
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 50, "suspicious": 2, "harmless": 10, "undetected": 6},
                "type_description": "Win32 EXE",
                "meaningful_name": "evil.exe",
                "last_analysis_results": {
                    "Kaspersky": {"category": "malicious", "result": "Trojan.X"},
                    "CleanAV": {"category": "harmless", "result": None},
                },
            }}
        })

    provider = VirusTotalProvider("fake-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "abc123", "md5")

    assert res.success
    assert res.malicious == 50
    assert res.detection_ratio == "50/68"
    assert res.raw["file_name"] == "evil.exe"
    # Only malicious/suspicious vendors are surfaced
    assert "Kaspersky" in res.raw["vendor_detections"]
    assert "CleanAV" not in res.raw["vendor_detections"]


async def test_vt_ip_lookup():
    def handler(request):
        return httpx.Response(200, json={
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 80, "undetected": 11},
                "country": "US", "asn": 15169, "as_owner": "GOOGLE", "reputation": 0,
            }}
        })

    provider = VirusTotalProvider("fake-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "8.8.8.8", "ip")

    assert res.success
    assert res.raw["country"] == "US"
    assert res.raw["as_owner"] == "GOOGLE"


async def test_vt_404_not_found():
    def handler(request):
        return httpx.Response(404, json={"error": {"message": "not found"}})

    provider = VirusTotalProvider("fake-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "deadbeef", "sha256")

    assert not res.success
    assert "Not found" in res.error


async def test_vt_invalid_key():
    def handler(request):
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    provider = VirusTotalProvider("bad-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "8.8.8.8", "ip")

    assert not res.success
    assert "invalid API key" in res.error


async def test_vt_rate_limit_retries_then_errors(monkeypatch):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(429)

    # Don't actually wait for the Retry-After backoff
    import app.providers.virustotal as vt
    async def _instant(_):
        return None
    monkeypatch.setattr(vt.asyncio, "sleep", _instant)

    provider = VirusTotalProvider("fake-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "8.8.8.8", "ip")

    assert not res.success
    assert "rate limit" in res.error.lower()
    assert calls["n"] == 2  # initial attempt + one retry


# ── AbuseIPDB ─────────────────────────────────────────────────────────────────

async def test_abuseipdb_high_confidence():
    def handler(request):
        assert request.headers.get("Key") == "fake-key"
        return httpx.Response(200, json={
            "data": {
                "abuseConfidenceScore": 90,
                "countryCode": "RU",
                "isp": "EvilCorp",
                "totalReports": 120,
                "isTor": True,
            }
        })

    provider = AbuseIPDBProvider("fake-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "1.2.3.4", "ip")

    assert res.success
    assert res.raw["abuse_confidence_score"] == 90
    assert res.malicious == 1
    assert res.raw["is_tor"] is True


def test_abuseipdb_only_supports_ip():
    provider = AbuseIPDBProvider("fake-key")
    assert provider.supports("ip")
    assert not provider.supports("md5")
    assert not provider.supports("domain")


async def test_abuseipdb_rejects_non_ip():
    provider = AbuseIPDBProvider("fake-key")
    async with make_client(lambda r: httpx.Response(200, json={})) as client:
        res = await provider.lookup(client, "example.com", "domain")
    assert not res.success
