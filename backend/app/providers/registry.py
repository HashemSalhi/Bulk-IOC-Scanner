"""Provider registry — instantiate enabled providers from the key store.

To add a new provider:
  1. Create backend/app/providers/yourprovider.py implementing the Provider ABC.
  2. Add a ProviderInfo entry to providers/catalog.py and a key field to config.py.
  3. Add its (id -> factory) mapping to _FACTORIES below.
"""
from app.providers.base import Provider


def _factories() -> dict:
    from app.providers.abuseipdb import AbuseIPDBProvider
    from app.providers.greynoise import GreyNoiseProvider
    from app.providers.rdap import RDAPProvider
    from app.providers.threatfox import ThreatFoxProvider
    from app.providers.urlscan import URLScanProvider
    from app.providers.virustotal import VirusTotalProvider

    return {
        "virustotal": VirusTotalProvider,
        "abuseipdb": AbuseIPDBProvider,
        "greynoise": GreyNoiseProvider,
        "threatfox": ThreatFoxProvider,
        "urlscan": URLScanProvider,
        "rdap": RDAPProvider,
    }


def get_providers() -> list[Provider]:
    """Return a list of enabled provider instances based on currently active keys."""
    from app.services.keystore import keystore

    providers: list[Provider] = []
    for provider_id, factory in _factories().items():
        if keystore.is_active(provider_id):
            providers.append(factory(keystore.get(provider_id)))
    return providers
