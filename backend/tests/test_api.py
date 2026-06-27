"""Integration tests for the FastAPI endpoints (providers mocked, isolated DB)."""
import io


async def test_health(client):
    r = await client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


async def test_scan_iocs_classifies_and_scores(client):
    r = await client.post("/api/scan", json={
        "iocs": ["44d88612fea8a8f36de82e1278abb02f", "8.8.8.8", "example.com"],
    })
    assert r.status_code == 200
    data = r.json()
    by_ioc = {d["ioc"]: d for d in data}

    assert by_ioc["44d88612fea8a8f36de82e1278abb02f"]["ioc_type"] == "md5"
    assert by_ioc["44d88612fea8a8f36de82e1278abb02f"]["risk_band"] == "High"
    assert by_ioc["8.8.8.8"]["ioc_type"] == "ip"
    assert by_ioc["8.8.8.8"]["risk_band"] == "Low"
    assert by_ioc["example.com"]["ioc_type"] == "domain"
    # Each scan got persisted (has an id)
    assert all(d["id"] for d in data)


async def test_scan_refangs_defanged_iocs(client):
    r = await client.post("/api/scan", json={"iocs": ["8[.]8[.]8[.]8"]})
    assert r.status_code == 200
    data = r.json()
    assert data[0]["ioc"] == "8.8.8.8"          # stored/scanned refanged
    assert data[0]["ioc_type"] == "ip"


async def test_scan_deduplicates(client):
    r = await client.post("/api/scan", json={"iocs": ["8.8.8.8", "8.8.8.8", " 8.8.8.8 "]})
    assert r.status_code == 200
    assert len(r.json()) == 1


async def test_scan_empty_rejected(client):
    r = await client.post("/api/scan", json={"iocs": ["   ", ""]})
    assert r.status_code == 422


async def test_scan_stream_ndjson(client):
    import json
    r = await client.post("/api/scan/stream", json={"iocs": ["5.5.5.5", "6.6.6.6", "7.7.7.7"]})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/x-ndjson")
    lines = [ln for ln in r.text.strip().split("\n") if ln]
    assert len(lines) == 3
    parsed = [json.loads(ln) for ln in lines]
    assert {p["ioc"] for p in parsed} == {"5.5.5.5", "6.6.6.6", "7.7.7.7"}
    assert all(p["id"] for p in parsed)  # persisted with ids


async def test_scan_text_endpoint(client):
    r = await client.post("/api/scan/text", json={"text": "8.8.8.8, example.com\n1.1.1.1"})
    assert r.status_code == 200
    assert len(r.json()) == 3


async def test_cache_reuses_recent_scan(client):
    first = (await client.post("/api/scan", json={"iocs": ["9.9.9.9"]})).json()[0]
    assert first["from_cache"] is False
    second = (await client.post("/api/scan", json={"iocs": ["9.9.9.9"]})).json()[0]
    assert second["from_cache"] is True
    assert second["id"] == first["id"]  # same stored row, not re-persisted


async def test_force_bypasses_cache(client):
    await client.post("/api/scan", json={"iocs": ["9.9.4.4"]})
    forced = (await client.post("/api/scan?force=true", json={"iocs": ["9.9.4.4"]})).json()[0]
    assert forced["from_cache"] is False


async def test_timestamps_are_utc_iso(client):
    data = (await client.post("/api/scan", json={"iocs": ["8.8.4.4"]})).json()
    assert data[0]["created_at"].endswith("Z")
    hist = (await client.get("/api/history")).json()
    assert all(h["created_at"].endswith("Z") for h in hist)


async def test_history_records_scans(client):
    await client.post("/api/scan", json={"iocs": ["198.51.100.7"]})
    r = await client.get("/api/history")
    assert r.status_code == 200
    iocs = [h["ioc"] for h in r.json()]
    assert "198.51.100.7" in iocs


async def test_history_detail_and_stats(client):
    scan = (await client.post("/api/scan", json={"iocs": ["203.0.113.9"]})).json()[0]
    detail = await client.get(f"/api/history/{scan['id']}")
    assert detail.status_code == 200
    assert detail.json()["ioc"] == "203.0.113.9"
    assert len(detail.json()["provider_results"]) >= 1

    stats = await client.get("/api/history/stats")
    assert stats.status_code == 200
    assert stats.json()["total"] >= 1


async def test_history_detail_404(client):
    r = await client.get("/api/history/999999")
    assert r.status_code == 404


async def test_tag_scan(client):
    scan = (await client.post("/api/scan", json={"iocs": ["192.0.2.55"]})).json()[0]
    r = await client.patch(f"/api/scan/{scan['id']}/tag", json={"tag": "Malware"})
    assert r.status_code == 200

    detail = (await client.get(f"/api/history/{scan['id']}")).json()
    assert detail["tag"] == "Malware"


async def test_tag_nonexistent_scan(client):
    r = await client.patch("/api/scan/999999/tag", json={"tag": "Phishing"})
    assert r.status_code == 404


async def test_file_scan_hashes_locally(client):
    content = b"hello world test file"
    files = {"files": ("test.txt", io.BytesIO(content), "text/plain")}
    r = await client.post("/api/scan/files", files=files)
    assert r.status_code == 200
    data = r.json()[0]

    import hashlib
    assert data["file_info"]["sha256"] == hashlib.sha256(content).hexdigest()
    assert data["file_info"]["md5"] == hashlib.md5(content).hexdigest()
    assert data["file_info"]["filename"] == "test.txt"
    # The scanned IOC is the SHA256, and original filename is preserved
    assert data["scan_result"]["ioc"] == data["file_info"]["sha256"]
    assert data["scan_result"]["source_filename"] == "test.txt"
    assert data["error"] is None


async def test_file_scan_isolates_oversize_file(client, monkeypatch):
    # Force a tiny upload cap so one file is rejected but the other still scans
    from app.config import settings
    monkeypatch.setattr(settings, "max_upload_mb", 0)  # 0 MB => any non-empty file too big

    files = [
        ("files", ("ok.txt", io.BytesIO(b""), "text/plain")),          # empty -> fits
        ("files", ("big.bin", io.BytesIO(b"X" * 5000), "application/octet-stream")),
    ]
    r = await client.post("/api/scan/files", files=files)
    assert r.status_code == 200
    data = {d["filename"]: d for d in r.json()}
    assert data["big.bin"]["error"] is not None
    assert data["big.bin"]["scan_result"] is None
    assert data["ok.txt"]["error"] is None
    assert data["ok.txt"]["scan_result"] is not None


async def test_settings_lists_all_providers(client):
    r = await client.get("/api/settings")
    assert r.status_code == 200
    ids = {p["id"] for p in r.json()["providers"]}
    assert {"virustotal", "abuseipdb", "greynoise", "threatfox", "urlscan"} <= ids
    assert all(p["enabled"] is False for p in r.json()["providers"])


async def test_settings_key_update_by_id(client):
    # Save keys via the UI endpoint, keyed by provider id
    r = await client.put("/api/settings/keys", json={
        "keys": {"virustotal": "ABCD1234EFGH5678", "greynoise": "GN12345678ABCD"},
    })
    assert r.status_code == 200
    providers = {p["id"]: p for p in r.json()["providers"]}
    assert providers["virustotal"]["enabled"] is True
    assert providers["virustotal"]["key_hint"] == "ABCD...5678"
    assert providers["greynoise"]["enabled"] is True
    # Full keys are never returned
    assert "ABCD1234EFGH5678" not in r.text
    # Clearing a key disables the provider
    r = await client.put("/api/settings/keys", json={"keys": {"virustotal": ""}})
    providers = {p["id"]: p for p in r.json()["providers"]}
    assert providers["virustotal"]["enabled"] is False
