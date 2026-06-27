"""RDAP / WHOIS enrichment provider (keyless).

Uses the public RDAP bootstrap at rdap.org — free, no API key, official IETF
replacement for WHOIS. Returns registrar / creation date / nameservers for
domains and network owner / allocation for IPs and CIDRs. Flags newly-registered
domains, a common phishing/malware signal.
"""
import asyncio
import logging
from datetime import datetime, timezone

import httpx

from app.models.schemas import ProviderResult
from app.providers.base import Provider
from app.services.ratelimit import retry_after_seconds

logger = logging.getLogger(__name__)

RDAP_BASE = "https://rdap.org"
NEW_DOMAIN_DAYS = 30  # domains younger than this are flagged as suspicious


class RDAPProvider(Provider):
    name = "rdap"

    def __init__(self, api_key: str = ""):
        self._api_key = api_key  # unused; RDAP is keyless

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in {"domain", "ip", "cidr"}

    async def lookup(self, client: httpx.AsyncClient, ioc: str, ioc_type: str) -> ProviderResult:
        if ioc_type == "domain":
            path = f"/domain/{ioc}"
        elif ioc_type in ("ip", "cidr"):
            # RDAP ip endpoint takes a single address; use the network address for CIDR
            path = f"/ip/{ioc.split('/')[0]}"
        else:
            return self._error(ioc, ioc_type, f"RDAP does not support type '{ioc_type}'")

        for attempt in range(2):
            try:
                resp = await client.get(f"{RDAP_BASE}{path}", headers={"Accept": "application/rdap+json"})
                if resp.status_code == 404:
                    return ProviderResult(
                        provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
                        detection_ratio="no record", raw={"found": False},
                    )
                resp.raise_for_status()
                data = resp.json()
                break
            except httpx.TimeoutException:
                return self._error(ioc, ioc_type, "RDAP: request timed out")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429 and attempt == 0:
                    await asyncio.sleep(retry_after_seconds(e.response))
                    continue
                return self._error(ioc, ioc_type, f"RDAP HTTP {e.response.status_code}")
            except Exception as e:
                logger.exception("RDAP unexpected error for %s", ioc)
                return self._error(ioc, ioc_type, str(e))

        if ioc_type == "domain":
            return self._parse_domain(ioc, ioc_type, data)
        return self._parse_ip(ioc, ioc_type, data)

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse_domain(self, ioc, ioc_type, data):
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        registration = events.get("registration")
        age_days = _age_days(registration)
        newly_registered = age_days is not None and age_days <= NEW_DOMAIN_DAYS

        nameservers = [ns.get("ldhName") for ns in data.get("nameservers", []) if ns.get("ldhName")]
        registrar = _registrar(data)

        raw = {
            "found": True,
            "registrar": registrar,
            "registered": registration,
            "expires": events.get("expiration"),
            "last_changed": events.get("last changed"),
            "age_days": age_days,
            "nameservers": nameservers,
            "statuses": data.get("status", []),
            "rdap_newly_registered": newly_registered,
        }
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
            suspicious=1 if newly_registered else 0,
            detection_ratio=(f"registered {age_days}d ago" if age_days is not None else "registered"),
            raw=raw,
        )

    def _parse_ip(self, ioc, ioc_type, data):
        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
        raw = {
            "found": True,
            "network_name": data.get("name"),
            "owner": _registrar(data) or data.get("name"),
            "country": data.get("country"),
            "range": f"{data.get('startAddress', '')}–{data.get('endAddress', '')}".strip("–"),
            "cidr": _cidr(data),
            "registered": events.get("registration"),
            "last_changed": events.get("last changed"),
        }
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
            detection_ratio=raw["network_name"] or "allocated",
            raw=raw,
        )

    def _error(self, ioc, ioc_type, msg) -> ProviderResult:
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type,
            success=False, error=msg, raw={"error": msg},
        )


def _registrar(data) -> str | None:
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles or "registrant" in roles or "administrative" in roles:
            for item in entity.get("vcardArray", [[], []])[1]:
                if item and item[0] == "fn":
                    return item[3]
    return None


def _cidr(data) -> str | None:
    cidrs = data.get("cidr0_cidrs") or []
    if cidrs:
        c = cidrs[0]
        prefix = c.get("v4prefix") or c.get("v6prefix")
        length = c.get("length")
        if prefix and length is not None:
            return f"{prefix}/{length}"
    return None


def _age_days(date_str: str | None) -> int | None:
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return None
