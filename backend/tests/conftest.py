"""Shared pytest fixtures — isolated DB and mocked providers for endpoint tests."""
import os
import tempfile

# Point the app at a throwaway SQLite DB BEFORE any app module is imported.
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{_tmp_db.name}"
os.environ["VIRUSTOTAL_API_KEY"] = ""
os.environ["ABUSEIPDB_API_KEY"] = ""

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.database.db import init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models.schemas import ProviderResult  # noqa: E402


class FakeProvider:
    """Stub provider returning canned results so endpoint tests need no network."""
    name = "fakeprovider"

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in {"md5", "sha1", "sha256", "ip", "domain", "url"}

    async def lookup(self, client, ioc, ioc_type):
        malicious = 60 if ioc_type in {"md5", "sha1", "sha256"} else 0
        total = 70
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type, success=True,
            malicious=malicious, suspicious=0, harmless=total - malicious, undetected=0,
            detection_ratio=f"{malicious}/{total}",
            raw={"malicious": malicious, "detection_ratio": f"{malicious}/{total}"},
        )


@pytest_asyncio.fixture(autouse=True)
async def _init_db():
    await init_db()
    yield


class _NoLimit:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.fixture(autouse=True)
def _mock_providers(monkeypatch):
    monkeypatch.setattr("app.services.scanner.get_providers", lambda: [FakeProvider()])
    # Disable rate pacing so integration tests run fast (pacing is unit-tested separately)
    from app.services.ratelimit import limiter
    monkeypatch.setattr(limiter, "for_provider", lambda name: _NoLimit())
    # Reset the keystore singleton so saved keys don't leak across tests
    from app.services.keystore import keystore
    keystore._keys.clear()


@pytest_asyncio.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
