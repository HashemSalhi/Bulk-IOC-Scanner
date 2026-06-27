"""AbuseIPDB API v2 provider — IP reputation only."""
import asyncio
import logging

import httpx

from app.models.schemas import ProviderResult
from app.providers.base import Provider
from app.services.ratelimit import retry_after_seconds

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    async def lookup(self, client: httpx.AsyncClient, ioc: str, ioc_type: str) -> ProviderResult:
        if ioc_type != "ip":
            return self._error(ioc, ioc_type, "AbuseIPDB only supports IP addresses")

        headers = {"Key": self._api_key, "Accept": "application/json"}
        params = {"ipAddress": ioc, "maxAgeInDays": 90, "verbose": ""}

        for attempt in range(2):  # one retry on 429
            try:
                resp = await client.get(f"{ABUSEIPDB_BASE}/check", headers=headers, params=params)
                resp.raise_for_status()
                data = resp.json().get("data", {})
                break
            except httpx.TimeoutException:
                return self._error(ioc, ioc_type, "AbuseIPDB: request timed out")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt == 0:
                    await asyncio.sleep(retry_after_seconds(e.response))
                    continue
                return self._http_error(ioc, ioc_type, e)
            except Exception as e:
                logger.exception("AbuseIPDB unexpected error for %s", ioc)
                return self._error(ioc, ioc_type, str(e))

        confidence = data.get("abuseConfidenceScore", 0)

        raw = {
            "abuse_confidence_score": confidence,
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports", 0),
            "is_tor": data.get("isTor", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "usage_type": data.get("usageType"),
            "last_reported": data.get("lastReportedAt"),
        }

        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            ioc_type=ioc_type,
            success=True,
            # Map confidence >= 50 as malicious, < 50 but > 0 as suspicious
            malicious=1 if confidence >= 50 else 0,
            suspicious=1 if 0 < confidence < 50 else 0,
            harmless=1 if confidence == 0 else 0,
            detection_ratio=f"{confidence}% confidence",
            raw=raw,
        )

    def _error(self, ioc, ioc_type, msg) -> ProviderResult:
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type,
            success=False, error=msg, raw={"error": msg},
        )

    def _http_error(self, ioc, ioc_type, exc: httpx.HTTPStatusError) -> ProviderResult:
        status = exc.response.status_code
        if status == 401:
            msg = "AbuseIPDB: invalid API key (401)"
        elif status == 429:
            msg = "AbuseIPDB: rate limit exceeded (429) — wait and retry"
        elif status == 422:
            msg = f"AbuseIPDB: invalid IP address — {ioc}"
        else:
            msg = f"AbuseIPDB HTTP {status}"
        return self._error(ioc, ioc_type, msg)
