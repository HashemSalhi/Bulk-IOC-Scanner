"""IPify Geolocation provider — maps an IP to its physical location and network.

Uses geo.ipify.org (https://geo.ipify.org/docs). Free tier needs an API key.
Pure enrichment: returns country / region / city / coordinates / ISP / ASN —
it does not assert maliciousness, so it never sets a malicious signal.
"""
import asyncio
import logging

import httpx

from app.models.schemas import ProviderResult
from app.providers.base import Provider
from app.services.ratelimit import retry_after_seconds

logger = logging.getLogger(__name__)

IPIFY_BASE = "https://geo.ipify.org/api/v2/country,city"


class IPifyProvider(Provider):
    name = "ipify"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    async def lookup(self, client: httpx.AsyncClient, ioc: str, ioc_type: str) -> ProviderResult:
        if ioc_type != "ip":
            return self._error(ioc, ioc_type, "IPify only supports IP addresses")

        params = {"apiKey": self._api_key, "ipAddress": ioc}
        for attempt in range(2):
            try:
                resp = await client.get(IPIFY_BASE, params=params)
                resp.raise_for_status()
                data = resp.json()
                break
            except httpx.TimeoutException:
                return self._error(ioc, ioc_type, "IPify: request timed out")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt == 0:
                    await asyncio.sleep(retry_after_seconds(e.response))
                    continue
                return self._http_error(ioc, ioc_type, e)
            except Exception as e:
                logger.exception("IPify unexpected error for %s", ioc)
                return self._error(ioc, ioc_type, str(e))

        loc = data.get("location", {}) or {}
        asn = data.get("as", {}) or {}
        country = loc.get("country")
        city = loc.get("city")
        region = loc.get("region")
        located = ", ".join(p for p in (city, region, country) if p)

        raw = {
            "found": True,
            "country": country,
            "region": region,
            "city": city,
            "postal_code": loc.get("postalCode"),
            "lat": loc.get("lat"),
            "lng": loc.get("lng"),
            "timezone": loc.get("timezone"),
            "isp": data.get("isp"),
            "asn": asn.get("asn"),
            "as_name": asn.get("name"),
            "as_route": asn.get("route"),
            "as_domain": asn.get("domain"),
        }
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
            detection_ratio=located or "located",
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
            msg = "IPify: invalid API key"
        elif status == 422:
            msg = "IPify: invalid IP address"
        elif status == 429:
            msg = "IPify: rate limit / quota exceeded (429)"
        else:
            msg = f"IPify HTTP {status}"
        return self._error(ioc, ioc_type, msg)
