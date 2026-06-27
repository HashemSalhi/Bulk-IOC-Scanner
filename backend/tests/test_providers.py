"""Tests for provider response parsing using a mocked httpx transport."""
import httpx
import pytest

from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.greynoise import GreyNoiseProvider
from app.providers.threatfox import ThreatFoxProvider
from app.providers.urlscan import URLScanProvider
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


# ── GreyNoise ─────────────────────────────────────────────────────────────────

async def test_greynoise_malicious():
    def handler(request):
        assert request.headers.get("key") == "gn-key"
        return httpx.Response(200, json={
            "ip": "1.2.3.4", "noise": True, "riot": False,
            "classification": "malicious", "name": "Scanner", "last_seen": "2024-01-01",
        })

    provider = GreyNoiseProvider("gn-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "1.2.3.4", "ip")
    assert res.success
    assert res.malicious == 1
    assert res.raw["greynoise_malicious"] is True


async def test_greynoise_benign_riot():
    def handler(request):
        return httpx.Response(200, json={
            "ip": "8.8.8.8", "noise": False, "riot": True, "classification": "benign",
        })

    provider = GreyNoiseProvider("gn-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "8.8.8.8", "ip")
    assert res.success
    assert res.raw["greynoise_benign"] is True
    assert res.harmless == 1


async def test_greynoise_404_unobserved():
    provider = GreyNoiseProvider("gn-key")
    async with make_client(lambda r: httpx.Response(404, json={"message": "not observed"})) as client:
        res = await provider.lookup(client, "10.0.0.1", "ip")
    assert res.success
    assert res.raw["classification"] == "unobserved"


# ── ThreatFox ─────────────────────────────────────────────────────────────────

async def test_threatfox_match():
    def handler(request):
        assert request.headers.get("Auth-Key") == "tf-key"
        return httpx.Response(200, json={
            "query_status": "ok",
            "data": [{"confidence_level": 90, "threat_type": "botnet_cc",
                      "malware_printable": "Emotet", "tags": ["emotet"]}],
        })

    provider = ThreatFoxProvider("tf-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "1.2.3.4", "ip")
    assert res.success
    assert res.malicious == 1
    assert res.raw["threatfox_confidence"] == 90
    assert res.raw["malware"] == "Emotet"


async def test_threatfox_no_result():
    def handler(request):
        return httpx.Response(200, json={"query_status": "no_result", "data": []})

    provider = ThreatFoxProvider("tf-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "8.8.8.8", "ip")
    assert res.success
    assert res.malicious in (0, None)
    assert res.raw["matches"] == 0


# ── URLScan ───────────────────────────────────────────────────────────────────

async def test_urlscan_search_with_malicious_verdict():
    def handler(request):
        return httpx.Response(200, json={
            "total": 2,
            "results": [
                {"verdicts": {"malicious": True}, "result": "https://urlscan.io/r/1",
                 "task": {"time": "2024-01-01"}},
                {"verdicts": {"malicious": False}},
            ],
        })

    provider = URLScanProvider("us-key")
    async with make_client(handler) as client:
        res = await provider.lookup(client, "evil.com", "domain")
    assert res.success
    assert res.raw["total_scans"] == 2
    assert res.raw["malicious_scans"] == 1
    assert res.malicious == 1


def test_urlscan_supports():
    provider = URLScanProvider("us-key")
    assert provider.supports("url")
    assert provider.supports("domain")
    assert not provider.supports("ip")


# ── Registry honors the on/off toggle ─────────────────────────────────────────

def test_registry_respects_provider_toggle():
    from app.providers.registry import get_providers
    from app.services.keystore import keystore

    keystore._keys.clear(); keystore._enabled.clear()
    keystore._keys["virustotal"] = "x"           # key present, toggle defaults on
    assert any(p.name == "virustotal" for p in get_providers())

    keystore._enabled["virustotal"] = False        # toggled OFF
    assert not any(p.name == "virustotal" for p in get_providers())

    keystore._keys.clear(); keystore._enabled.clear()


# ── RDAP / WHOIS (keyless) ────────────────────────────────────────────────────

async def test_rdap_domain_newly_registered():
    from datetime import datetime, timezone, timedelta
    from app.providers.rdap import RDAPProvider

    recent = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def handler(request):
        return httpx.Response(200, json={
            "events": [{"eventAction": "registration", "eventDate": recent}],
            "nameservers": [{"ldhName": "ns1.bad.com"}],
            "status": ["active"],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "EvilRegistrar"]]]}],
        })

    provider = RDAPProvider()
    async with make_client(handler) as client:
        res = await provider.lookup(client, "bad.com", "domain")
    assert res.success
    assert res.raw["registrar"] == "EvilRegistrar"
    assert res.raw["rdap_newly_registered"] is True
    assert res.suspicious == 1


async def test_rdap_ip_network():
    from app.providers.rdap import RDAPProvider

    def handler(request):
        return httpx.Response(200, json={
            "name": "GOGL", "country": "US",
            "startAddress": "8.8.8.0", "endAddress": "8.8.8.255",
            "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
        })

    provider = RDAPProvider()
    async with make_client(handler) as client:
        res = await provider.lookup(client, "8.8.8.8", "ip")
    assert res.success
    assert res.raw["network_name"] == "GOGL"
    assert res.raw["cidr"] == "8.8.8.0/24"


async def test_rdap_404_no_record():
    from app.providers.rdap import RDAPProvider
    provider = RDAPProvider()
    async with make_client(lambda r: httpx.Response(404)) as client:
        res = await provider.lookup(client, "nope.invalid", "domain")
    assert res.success
    assert res.raw["found"] is False


def test_rdap_supports():
    from app.providers.rdap import RDAPProvider
    p = RDAPProvider()
    assert p.supports("domain") and p.supports("ip") and p.supports("cidr")
    assert not p.supports("md5")
