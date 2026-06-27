"""URLScan.io provider — surfaces existing scans for a domain/URL (context, not a verdict)."""
import asyncio
import logging

import httpx

from app.models.schemas import ProviderResult
from app.providers.base import Provider
from app.services.ratelimit import retry_after_seconds

logger = logging.getLogger(__name__)

URLSCAN_SEARCH = "https://urlscan.io/api/v1/search/"


class URLScanProvider(Provider):
    name = "urlscan"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in {"url", "domain"}

    async def lookup(self, client: httpx.AsyncClient, ioc: str, ioc_type: str) -> ProviderResult:
        headers = {"API-Key": self._api_key, "Accept": "application/json"}
        # For URLs search by page.url, for domains search by domain
        field = "page.url" if ioc_type == "url" else "domain"
        params = {"q": f'{field}:"{ioc}"', "size": 5}

        for attempt in range(2):
            try:
                resp = await client.get(URLSCAN_SEARCH, params=params, headers=headers)
                resp.raise_for_status()
                body = resp.json()
                break
            except httpx.TimeoutException:
                return self._error(ioc, ioc_type, "URLScan: request timed out")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt == 0:
                    await asyncio.sleep(retry_after_seconds(e.response))
                    continue
                return self._http_error(ioc, ioc_type, e)
            except Exception as e:
                logger.exception("URLScan unexpected error for %s", ioc)
                return self._error(ioc, ioc_type, str(e))

        results = body.get("results", []) or []
        total = body.get("total", len(results))
        latest = results[0] if results else {}
        malicious_hits = sum(
            1 for r in results if (r.get("verdicts", {}) or {}).get("malicious")
        )
        raw = {
            "total_scans": total,
            "malicious_scans": malicious_hits,
            "latest_result": (latest.get("result") if latest else None),
            "latest_time": (latest.get("task", {}) or {}).get("time") if latest else None,
        }
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
            malicious=1 if malicious_hits else 0,
            detection_ratio=f"{total} scan(s)",
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
            msg = "URLScan: invalid API key"
        elif status == 429:
            msg = "URLScan: rate limit exceeded (429)"
        else:
            msg = f"URLScan HTTP {status}"
        return self._error(ioc, ioc_type, msg)
