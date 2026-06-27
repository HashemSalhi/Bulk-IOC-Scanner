"""GreyNoise Community API provider — IP triage ("is this just internet noise?")."""
import asyncio
import logging

import httpx

from app.models.schemas import ProviderResult
from app.providers.base import Provider
from app.services.ratelimit import retry_after_seconds

logger = logging.getLogger(__name__)

GREYNOISE_BASE = "https://api.greynoise.io/v3/community"


class GreyNoiseProvider(Provider):
    name = "greynoise"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type == "ip"

    async def lookup(self, client: httpx.AsyncClient, ioc: str, ioc_type: str) -> ProviderResult:
        if ioc_type != "ip":
            return self._error(ioc, ioc_type, "GreyNoise only supports IP addresses")

        headers = {"key": self._api_key, "Accept": "application/json"}
        for attempt in range(2):
            try:
                resp = await client.get(f"{GREYNOISE_BASE}/{ioc}", headers=headers)
                if resp.status_code == 404:
                    # Not observed scanning the internet / not in RIOT — benign-ish
                    return ProviderResult(
                        provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
                        harmless=1, detection_ratio="not observed",
                        raw={"classification": "unobserved", "noise": False, "riot": False},
                    )
                resp.raise_for_status()
                data = resp.json()
                break
            except httpx.TimeoutException:
                return self._error(ioc, ioc_type, "GreyNoise: request timed out")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt == 0:
                    await asyncio.sleep(retry_after_seconds(e.response))
                    continue
                return self._http_error(ioc, ioc_type, e)
            except Exception as e:
                logger.exception("GreyNoise unexpected error for %s", ioc)
                return self._error(ioc, ioc_type, str(e))

        classification = data.get("classification", "unknown")  # benign | malicious | unknown
        riot = bool(data.get("riot", False))
        noise = bool(data.get("noise", False))

        raw = {
            "classification": classification,
            "noise": noise,
            "riot": riot,
            "name": data.get("name"),
            "last_seen": data.get("last_seen"),
            "link": data.get("link"),
            # Consumed by risk.py: benign/RIOT lowers risk, malicious raises it
            "greynoise_benign": classification == "benign" or riot,
            "greynoise_malicious": classification == "malicious",
        }
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
            malicious=1 if classification == "malicious" else 0,
            harmless=1 if (classification == "benign" or riot) else 0,
            detection_ratio=classification,
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
            msg = "GreyNoise: invalid API key"
        elif status == 429:
            msg = "GreyNoise: rate limit exceeded (429)"
        else:
            msg = f"GreyNoise HTTP {status}"
        return self._error(ioc, ioc_type, msg)
