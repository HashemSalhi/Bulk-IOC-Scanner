# Development Guide

Architecture and common commands for working in this repository.

## Commands

### Backend

```bash
cd backend

# Setup (first time)
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp ../.env.example .env   # then fill in API keys

# Run dev server
uvicorn bulk_ioc_scanner.main:app --reload          # http://localhost:8000
# Interactive API docs: http://localhost:8000/docs
```

### Frontend

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173
npm run build    # production build → dist/
```

### Docker (full stack)

```bash
# From project root, after setting up backend/.env
docker compose up --build
```

---

## Architecture

```
backend/bulk_ioc_scanner/
  main.py              — FastAPI app, CORS, lifespan (DB init), router mounts
  config.py            — pydantic-settings; loads backend/.env; exposes settings singleton
  api/
    scan.py            — POST /api/scan, /api/scan/text, /api/scan/files, PATCH /api/scan/{id}/tag
    history.py         — GET /api/history, /api/history/stats, /api/history/{id}
    settings.py        — GET /api/settings (provider status + limits, keys masked)
  providers/
    base.py            — Provider ABC: name, supports(ioc_type)->bool, async lookup()->ProviderResult
    virustotal.py      — VT API v3: hash/ip/domain/url
    abuseipdb.py       — AbuseIPDB v2: ip only
    registry.py        — get_providers() → list of enabled Provider instances
  services/
    ioc_detect.py      — detect(ioc)->type, parse_bulk_input(text)->list[str]
    hashing.py         — hash_upload(UploadFile, max_bytes)->FileHashes; deletes temp file in finally
    scanner.py         — scan_bulk(iocs, source_files)->list[ScanResult]; asyncio.gather across providers
    risk.py            — compute_risk(provider_results)->(score, band); max-wins across providers
  database/
    db.py              — AsyncSession factory, init_db(), get_db() dependency
    crud.py            — save_scan, update_scan_tag, list_scans, get_scan, get_stats, hydrate_provider_results
  models/
    tables.py          — Scan, ProviderResponse ORM tables
    schemas.py         — Pydantic schemas: ScanRequest, ProviderResult, ScanResult, ScanDetail, etc.

frontend/src/
  api/client.js        — fetch wrapper: scanIOCs, scanText, scanFiles, tagScan, getHistory, getSettings
  components/
    Sidebar.jsx        — nav with Bulk-IOC-Scanner branding
    RiskBadge.jsx      — color-coded High/Medium/Low chip
    ScanProgress.jsx   — progress bar for scan in-flight
    TagSelector.jsx    — Malware/Phishing/Investigation/False Positive buttons; calls tagScan API
    FileDropzone.jsx   — drag-drop + click file picker; shows selected files list
    ResultsTable.jsx   — main results view: search, type/risk filter, sort, Export CSV, row→modal
    ResultDetailModal.jsx — slide-out panel: per-provider breakdown, TagSelector, investigation report
    CopyReportButton.jsx  — builds + clipboard-copies a formatted ASCII report
  pages/
    Dashboard.jsx      — stat cards, provider status, recent scans
    Scan.jsx           — text/file mode tabs, textarea, FileDropzone, ScanProgress, ResultsTable
    History.jsx        — history table, click row→getScanDetail→ResultDetailModal
    Settings.jsx       — provider status, env instructions, limits, adding-provider guide
```

### Key data flows

**Text IOC scan:**  
`Scan.jsx` → `POST /api/scan` → `ioc_detect.detect()` per IOC → `scanner.scan_bulk()` fans out to providers via `asyncio.gather` → `risk.compute_risk()` → `crud.save_scan()` → response → `ResultsTable`

**File scan:**  
`FileDropzone` → `POST /api/scan/files` (multipart) → `hashing.hash_upload()` streams file, computes MD5/SHA1/SHA256, deletes temp → SHA256 only enters `scan_bulk()` → same path as above → response includes `file_info` with all three hashes

### Provider system

Adding a provider: implement `base.Provider` ABC, add to `registry.get_providers()`, add key to `config.py` + `.env.example`. The provider ABC requires only `supports(ioc_type)` and `async lookup(client, ioc, ioc_type) -> ProviderResult`. See `providers/abuseipdb.py` as the minimal reference example.

### Risk scoring

`risk.py`: VT malicious/total ratio weighted highest, suspicious at 0.5×; AbuseIPDB confidence score (0–100) fed directly. `max()` across all successful provider scores. 0–30 = Low, 31–70 = Medium, 71–100 = High.

### Security notes

- API keys only in `backend/.env` (gitignored); never returned by any endpoint (masked hint only in `/api/settings`)
- File bytes never leave the backend process: temp file deleted in `finally`, only SHA256 egresses
- CORS restricted to `FRONTEND_ORIGIN`; configurable in `.env`
- Per-scan IOC cap and per-file size cap enforced in `validation.py` and `hashing.py`
- 429 / auth errors from providers returned as per-IOC `success=false` results, not unhandled exceptions
