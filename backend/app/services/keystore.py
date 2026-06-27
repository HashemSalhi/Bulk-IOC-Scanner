"""
In-memory key store for API keys.

Priority (highest wins):
  1. Keys saved through the web UI (persisted in SQLite, loaded on startup).
  2. Keys set in backend/.env (read at process start by pydantic-settings).

This lets operators configure keys once via the UI without editing files or
restarting the backend.
"""
import logging

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.providers.catalog import PROVIDERS

logger = logging.getLogger(__name__)


class KeyStore:
    def __init__(self):
        self._keys: dict[str, str] = {}
        # Seed from env so the store is usable before DB is loaded
        self._load_from_env()

    def _load_from_env(self) -> None:
        for info in PROVIDERS:
            value = getattr(settings, info.env_attr, "").strip()
            if value:
                self._keys[info.id] = value

    async def load_from_db(self, db: AsyncSession) -> None:
        """Called once during app startup; DB values override env values."""
        from app.database.crud import get_all_api_keys

        stored = await get_all_api_keys(db)
        for provider, key in stored.items():
            if key.strip():
                self._keys[provider] = key.strip()
                logger.info("Loaded API key for '%s' from database", provider)

    async def set(self, db: AsyncSession, provider: str, key: str) -> None:
        """Update a key in memory and persist it to the database."""
        from app.database.crud import upsert_api_key

        key = key.strip()
        if key:
            self._keys[provider] = key
        else:
            self._keys.pop(provider, None)

        await upsert_api_key(db, provider, key)
        logger.info("API key for '%s' updated via web UI", provider)

    def get(self, provider: str) -> str:
        return self._keys.get(provider, "")

    def is_enabled(self, provider: str) -> bool:
        return bool(self._keys.get(provider, "").strip())


keystore = KeyStore()
