"""Central catalog of known providers — single source of truth for ids, display
names, and the config attribute that holds each provider's key.

Kept free of provider-class imports so it's cheap to import from keystore and the
settings API. The registry builds the actual Provider instances.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class ProviderInfo:
    id: str                       # must match Provider.name
    display: str                  # human-friendly name shown in the UI
    env_attr: str | None          # Settings attribute holding the key (None if keyless)
    requires_key: bool = True     # some providers (e.g. RDAP) need no API key


PROVIDERS: list[ProviderInfo] = [
    ProviderInfo("virustotal", "VirusTotal", "virustotal_api_key"),
    ProviderInfo("abuseipdb", "AbuseIPDB", "abuseipdb_api_key"),
    ProviderInfo("greynoise", "GreyNoise", "greynoise_api_key"),
    ProviderInfo("threatfox", "ThreatFox", "threatfox_auth_key"),
    ProviderInfo("urlscan", "URLScan.io", "urlscan_api_key"),
    ProviderInfo("rdap", "RDAP / WHOIS", None, requires_key=False),
]

PROVIDERS_BY_ID: dict[str, ProviderInfo] = {p.id: p for p in PROVIDERS}
