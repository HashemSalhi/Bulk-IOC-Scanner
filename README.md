# IOC-Radar

A lightweight, polished web tool for SOC analysts to bulk-scan Indicators of Compromise (hashes, IPs, domains, URLs) against threat intelligence providers.

## Features

- **Bulk text scanning** — paste multiple IOCs (newline or comma separated)
- **File upload scanning** — files are hashed locally (MD5/SHA1/SHA256); only the hash is sent to providers
- **Auto IOC-type detection** — MD5/SHA1/SHA256, IP, domain, URL
- **VirusTotal v3** — hash, IP, domain, URL lookups with vendor detections
- **AbuseIPDB v2** — IP reputation checks
- **Risk scoring** — 0–100 score → Low / Medium / High (color-coded)
- **Scan history** — all results persisted in SQLite; searchable and sortable
- **IOC tagging** — Malware / Phishing / Investigation / False Positive
- **Investigation report** — copy-to-clipboard formatted report per IOC
- **CSV export** — export any result set
- **Modular provider system** — add new providers with minimal code

---

## Quick Start — One Command

```bash
git clone <repo-url>
cd IOC-Radar
./run.sh
```

`run.sh` bootstraps the Python virtualenv + backend deps and the frontend `node_modules`
on first run, then starts **both** servers together with live reload:

- Frontend → http://localhost:5173
- Backend  → http://localhost:8000  (API docs at `/docs`)

Press **Ctrl+C** to stop both. No API key is required to start — add keys later from the
**Settings** page in the UI.

> Requirements: `python3`, `npm`, and `bash`.

---

## Manual Start (alternative)

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload
# API available at http://localhost:8000  (docs at /docs)
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# UI available at http://localhost:5173
```

---

## Environment Variables

There are **two ways** to configure API keys:

1. **Settings page (recommended)** — enter keys in the web UI. They are stored in the
   SQLite database, take effect immediately (no restart), and override any `.env` values.
2. **`backend/.env` file** — copy `.env.example` and fill in keys before starting.

Either is optional at startup: the app boots without keys, and scans for a given IOC type
simply return a clear "add an API key on the Settings page" message until a key is configured.

| Variable              | Description                                    | Default                          |
|-----------------------|------------------------------------------------|----------------------------------|
| `VIRUSTOTAL_API_KEY`  | VirusTotal API v3 key                          | *(optional; or set via UI)*      |
| `ABUSEIPDB_API_KEY`   | AbuseIPDB API v2 key                           | *(optional; or set via UI)*      |
| `MAX_UPLOAD_MB`       | Max file upload size                           | `32`                             |
| `MAX_IOCS_PER_SCAN`   | Max IOCs per scan request                      | `200`                            |
| `FRONTEND_ORIGIN`     | CORS origin for the frontend                   | `http://localhost:5173`          |
| `DATABASE_URL`        | SQLite connection string                       | `sqlite+aiosqlite:///./ioc_radar.db` |

Keys are never returned by the API — only a masked hint (e.g. `be97...b8e1`) is shown in Settings.

## Running Tests

```bash
cd backend
pip install pytest pytest-asyncio   # if not already installed
pytest                              # runs the full suite (no network or API key needed)
```

Tests cover IOC detection/defanging, local file hashing, risk scoring, provider response
parsing (mocked HTTP), and all API endpoints (isolated temp DB, mocked providers).

---

## Docker

```bash
docker compose up --build
# Frontend: http://localhost:80
# Backend:  http://localhost:8000
```

API keys can be added afterwards from the **Settings** page (persisted in the `db_data`
volume). To pre-seed them instead, create `backend/.env` (copy `.env.example`) before
running — it is picked up automatically but is optional.

---

## How File Hashing Works

1. User selects files through the browser.
2. Files are uploaded to the backend via multipart form data.
3. The backend **streams** each file through MD5/SHA1/SHA256 hash functions in 64 KB chunks.
4. The temp file is deleted immediately after hashing — **file bytes never persist on disk**.
5. Only the SHA256 hash is sent to threat intelligence providers.
6. The UI displays the filename, size, and all three hashes, plus the scan result.

This means VirusTotal and AbuseIPDB never receive your file content — only a hash identifier.

---

## Adding a New Provider

1. Create `backend/app/providers/yourprovider.py`:

```python
import httpx
from app.models.schemas import ProviderResult
from app.providers.base import Provider

class YourProvider(Provider):
    name = "yourprovider"

    def __init__(self, api_key: str):
        self._api_key = api_key

    def supports(self, ioc_type: str) -> bool:
        return ioc_type in {"ip", "domain"}   # adjust to what your API supports

    async def lookup(self, client: httpx.AsyncClient, ioc: str, ioc_type: str) -> ProviderResult:
        # ... call your API ...
        return ProviderResult(
            provider=self.name, ioc=ioc, ioc_type=ioc_type,
            success=True, malicious=0, suspicious=0, harmless=1,
            raw={},
        )
```

2. Register it in `backend/app/providers/registry.py`:

```python
from app.providers.yourprovider import YourProvider

def get_providers():
    # ...existing providers...
    if settings.your_api_key:
        providers.append(YourProvider(settings.your_api_key))
    return providers
```

3. Add `YOUR_API_KEY=` to `.env.example` and `backend/app/config.py`.

---

## API Endpoints

| Method | Path                      | Description                      |
|--------|---------------------------|----------------------------------|
| POST   | `/api/scan`               | Scan a list of IOC strings       |
| POST   | `/api/scan/text`          | Scan from raw pasted text        |
| POST   | `/api/scan/files`         | Upload files; hash+scan          |
| PATCH  | `/api/scan/{id}/tag`      | Tag a scan result                |
| GET    | `/api/history`            | All scan history                 |
| GET    | `/api/history/stats`      | Aggregate counts (dashboard)     |
| GET    | `/api/history/{id}`       | Full detail for one scan         |
| GET    | `/api/settings`           | Provider status and limits       |
| GET    | `/health`                 | Health check                     |
| GET    | `/docs`                   | Swagger interactive docs         |
