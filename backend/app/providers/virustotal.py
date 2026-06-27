"""VirusTotal API v3 provider."""
import asyncio
import base64
import logging
from datetime import datetime, timezone

import httpx

from app.models.schemas import ProviderResult
from app.providers.base import HASH_TYPES, Provider
from app.services.ratelimit import retry_after_seconds

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(Provider):
    name = "virustotal"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in HASH_TYPES | {"ip", "domain", "url"}

    async def lookup(self, client: httpx.AsyncClient, ioc: str, ioc_type: str) -> ProviderResult:
        headers = {"x-apikey": self._api_key}
        for attempt in range(2):  # one retry on 429
            try:
                return await self._dispatch(client, headers, ioc, ioc_type)
            except httpx.TimeoutException:
                return self._error(ioc, ioc_type, "Request timed out")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt == 0:
                    await asyncio.sleep(retry_after_seconds(e.response))
                    continue
                return self._http_error(ioc, ioc_type, e)
            except Exception as e:
                logger.exception("VirusTotal unexpected error for %s", ioc)
                return self._error(ioc, ioc_type, str(e))

    async def _dispatch(self, client, headers, ioc, ioc_type):
        if ioc_type in HASH_TYPES:
            return await self._lookup_hash(client, headers, ioc, ioc_type)
        elif ioc_type == "ip":
            return await self._lookup_ip(client, headers, ioc)
        elif ioc_type == "domain":
            return await self._lookup_domain(client, headers, ioc)
        elif ioc_type == "url":
            return await self._lookup_url(client, headers, ioc)
        return self._error(ioc, ioc_type, f"Unsupported IOC type: {ioc_type}")

    # ── Hash lookup ───────────────────────────────────────────────────────────

    async def _lookup_hash(self, client, headers, ioc, ioc_type):
        resp = await client.get(f"{VT_BASE}/files/{ioc}", headers=headers)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)
        undet = stats.get("undetected", 0)
        total = mal + sus + harm + undet

        # Vendor detections: {engine_name: {category, result}}
        vendor_map = attrs.get("last_analysis_results", {})
        detections = {
            k: v for k, v in vendor_map.items()
            if v.get("category") in ("malicious", "suspicious")
        }

        raw = {
            "malicious": mal,
            "suspicious": sus,
            "harmless": harm,
            "undetected": undet,
            "detection_ratio": f"{mal}/{total}" if total else None,
            "file_type": attrs.get("type_description"),
            "file_name": attrs.get("meaningful_name"),
            "first_seen": _fmt_ts(attrs.get("first_submission_date")),
            "last_analysis": _fmt_ts(attrs.get("last_analysis_date")),
            "vendor_detections": detections,
        }
        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            success=True,
            malicious=mal,
            suspicious=sus,
            harmless=harm,
            undetected=undet,
            detection_ratio=f"{mal}/{total}" if total else None,
            raw=raw,
        )

    # ── IP lookup ─────────────────────────────────────────────────────────────

    async def _lookup_ip(self, client, headers, ioc):
        resp = await client.get(f"{VT_BASE}/ip_addresses/{ioc}", headers=headers)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)
        undet = stats.get("undetected", 0)
        total = mal + sus + harm + undet

        raw = {
            "malicious": mal,
            "suspicious": sus,
            "harmless": harm,
            "undetected": undet,
            "detection_ratio": f"{mal}/{total}" if total else None,
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags", []),
            "last_analysis": _fmt_ts(attrs.get("last_analysis_date")),
        }
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type="ip",
            success=True,
            malicious=mal, suspicious=sus, harmless=harm, undetected=undet,
            detection_ratio=f"{mal}/{total}" if total else None,
            raw=raw,
        )

    # ── Domain lookup ─────────────────────────────────────────────────────────

    async def _lookup_domain(self, client, headers, ioc):
        resp = await client.get(f"{VT_BASE}/domains/{ioc}", headers=headers)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)
        undet = stats.get("undetected", 0)
        total = mal + sus + harm + undet

        raw = {
            "malicious": mal,
            "suspicious": sus,
            "harmless": harm,
            "undetected": undet,
            "detection_ratio": f"{mal}/{total}" if total else None,
            "reputation": attrs.get("reputation"),
            "categories": attrs.get("categories", {}),
            "last_dns_records": attrs.get("last_dns_records", []),
            "creation_date": _fmt_ts(attrs.get("creation_date")),
            "last_analysis": _fmt_ts(attrs.get("last_analysis_date")),
        }
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type="domain",
            success=True,
            malicious=mal, suspicious=sus, harmless=harm, undetected=undet,
            detection_ratio=f"{mal}/{total}" if total else None,
            raw=raw,
        )

    # ── URL lookup ────────────────────────────────────────────────────────────

    async def _lookup_url(self, client, headers, ioc):
        # VT URL lookup uses a base64url-encoded URL without padding
        url_id = base64.urlsafe_b64encode(ioc.encode()).rstrip(b"=").decode()
        resp = await client.get(f"{VT_BASE}/urls/{url_id}", headers=headers)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        sus = stats.get("suspicious", 0)
        harm = stats.get("harmless", 0)
        undet = stats.get("undetected", 0)
        total = mal + sus + harm + undet

        raw = {
            "malicious": mal,
            "suspicious": sus,
            "harmless": harm,
            "undetected": undet,
            "detection_ratio": f"{mal}/{total}" if total else None,
            "title": attrs.get("title"),
            "final_url": attrs.get("last_final_url"),
            "last_analysis": _fmt_ts(attrs.get("last_analysis_date")),
            "categories": attrs.get("categories", {}),
        }
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type="url",
            success=True,
            malicious=mal, suspicious=sus, harmless=harm, undetected=undet,
            detection_ratio=f"{mal}/{total}" if total else None,
            raw=raw,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _error(self, ioc, ioc_type, msg) -> ProviderResult:
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type,
            success=False, error=msg, raw={"error": msg},
        )

    def _http_error(self, ioc, ioc_type, exc: httpx.HTTPStatusError) -> ProviderResult:
        status = exc.response.status_code
        if status == 401:
            msg = "VirusTotal: invalid API key (401)"
        elif status == 404:
            msg = "Not found in VirusTotal"
        elif status == 429:
            msg = "VirusTotal: rate limit exceeded (429) — wait and retry"
        else:
            msg = f"VirusTotal HTTP {status}"
        return self._error(ioc, ioc_type, msg)


def _fmt_ts(ts: int | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
