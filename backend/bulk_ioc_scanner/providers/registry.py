"""Provider registry — instantiate enabled providers from the key store.

To add a new provider:
  1. Create backend/bulk_ioc_scanner/providers/yourprovider.py implementing the Provider ABC.
  2. Add a ProviderInfo entry to providers/catalog.py and a key field to config.py.
  3. Add its (id -> factory) mapping to _FACTORIES below.
"""
from bulk_ioc_scanner.providers.base import Provider


def _factories() -> dict:
    from bulk_ioc_scanner.providers.abuseipdb import AbuseIPDBProvider
    from bulk_ioc_scanner.providers.greynoise import GreyNoiseProvider
    from bulk_ioc_scanner.providers.ipify import IPifyProvider
    from bulk_ioc_scanner.providers.rdap import RDAPProvider
    from bulk_ioc_scanner.providers.threatfox import ThreatFoxProvider
    from bulk_ioc_scanner.providers.urlscan import URLScanProvider
    from bulk_ioc_scanner.providers.virustotal import VirusTotalProvider

    return {
        "virustotal": VirusTotalProvider,
        "abuseipdb": AbuseIPDBProvider,
        "greynoise": GreyNoiseProvider,
        "threatfox": ThreatFoxProvider,
        "urlscan": URLScanProvider,
        "ipify": IPifyProvider,
        "rdap": RDAPProvider,
    }


def get_providers() -> list[Provider]:
    """Return a list of enabled provider instances based on currently active keys."""
    from bulk_ioc_scanner.services.keystore import keystore

    providers: list[Provider] = []
    for provider_id, factory in _factories().items():
        if keystore.is_active(provider_id):
            providers.append(factory(keystore.get(provider_id)))
    return providers
