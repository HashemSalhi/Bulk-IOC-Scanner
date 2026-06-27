"""Settings/provider status and API key management endpoint."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings as cfg
from app.database.db import get_db
from app.models.schemas import ApiKeyUpdate, ProviderStatus, SettingsResponse
from app.providers.catalog import PROVIDERS, PROVIDERS_BY_ID
from app.services.keystore import keystore

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _mask_key(key: str) -> str | None:
    if not key or len(key) < 8:
        return None
    return key[:4] + "..." + key[-4:]


def _build_provider_list() -> list[ProviderStatus]:
    return [
        ProviderStatus(
            id=info.id,
            name=info.display,
            enabled=keystore.is_enabled(info.id),
            key_hint=_mask_key(keystore.get(info.id)),
        )
        for info in PROVIDERS
    ]


def _response() -> SettingsResponse:
    return SettingsResponse(
        providers=_build_provider_list(),
        max_upload_mb=cfg.max_upload_mb,
        max_iocs_per_scan=cfg.max_iocs_per_scan,
    )


@router.get("", response_model=SettingsResponse)
async def get_settings():
    """Return provider availability and configuration limits (keys are masked)."""
    return _response()


@router.put("/keys", response_model=SettingsResponse)
async def update_api_keys(
    body: ApiKeyUpdate,
    db: AsyncSession = Depends(get_db),
):
    """
    Save API keys for one or more providers, keyed by provider id (e.g.
    {"keys": {"virustotal": "...", "greynoise": ""}}). Empty string clears a key;
    omitting a provider leaves it unchanged. Unknown provider ids are ignored.
    Keys persist in SQLite and take effect immediately (no restart).
    """
    for provider_id, key in (body.keys or {}).items():
        if provider_id in PROVIDERS_BY_ID:
            await keystore.set(db, provider_id, key)
    return _response()
