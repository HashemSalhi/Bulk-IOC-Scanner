"""ThreatFox (abuse.ch) provider — checks an IOC against known threat indicators.

Requires a free abuse.ch Auth-Key (sent in the Auth-Key header).
"""
import asyncio
import logging

import httpx

from app.models.schemas import ProviderResult
from app.providers.base import HASH_TYPES, Provider
from app.services.ratelimit import retry_after_seconds

logger = logging.getLogger(__name__)

THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxProvider(Provider):
    name = "threatfox"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in HASH_TYPES | {"ip", "domain", "url"}

    async def lookup(self, client: httpx.AsyncClient, ioc: str, ioc_type: str) -> ProviderResult:
        headers = {"Auth-Key": self._api_key, "Accept": "application/json"}
        payload = {"query": "search_ioc", "search_term": ioc}

        for attempt in range(2):
            try:
                resp = await client.post(THREATFOX_URL, json=payload, headers=headers)
                resp.raise_for_status()
                body = resp.json()
                break
            except httpx.TimeoutException:
                return self._error(ioc, ioc_type, "ThreatFox: request timed out")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt == 0:
                    await asyncio.sleep(retry_after_seconds(e.response))
                    continue
                return self._http_error(ioc, ioc_type, e)
            except Exception as e:
                logger.exception("ThreatFox unexpected error for %s", ioc)
                return self._error(ioc, ioc_type, str(e))

        status = body.get("query_status")
        if status == "no_result":
            return ProviderResult(
                provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
                harmless=1, detection_ratio="no match", raw={"matches": 0},
            )
        if status != "ok":
            return self._error(ioc, ioc_type, f"ThreatFox: {status}")

        entries = body.get("data", []) or []
        first = entries[0] if entries else {}
        confidence = int(first.get("confidence_level", 0) or 0)
        raw = {
            "matches": len(entries),
            "threatfox_confidence": confidence,
            "threat_type": first.get("threat_type"),
            "malware": first.get("malware_printable") or first.get("malware"),
            "tags": first.get("tags") or [],
            "first_seen": first.get("first_seen"),
            "reference": first.get("reference"),
        }
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
            malicious=1 if entries else 0,
            detection_ratio=f"{len(entries)} match(es)",
            raw=raw,
        )

    def _error(self, ioc, ioc_type, msg) -> ProviderResult:
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type,
            success=False, error=msg, raw={"error": msg},
        )

    def _http_error(self, ioc, ioc_type, exc: httpx.HTTPStatusError) -> ProviderResult:
        status = exc.response.status_code
        if status in (401, 403):
            msg = "ThreatFox: invalid Auth-Key"
        elif status == 429:
            msg = "ThreatFox: rate limit exceeded (429)"
        else:
            msg = f"ThreatFox HTTP {status}"
        return self._error(ioc, ioc_type, msg)
