# Development Guide

For working on the code. If you just want to run the tool, see the
[README](README.md).

## Setup

```bash
git clone https://github.com/HashemSalhi/Bulk-IOC-Scanner.git
cd Bulk-IOC-Scanner

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Build the interface once so the backend has something to serve:

```bash
cd frontend && npm ci && npm run build && cd ..
```

That writes into `backend/bulk_ioc_scanner/web/`, which is gitignored — the
release workflow rebuilds it and ships it inside the wheel.

## Running

```bash
bulk-ioc-scanner                   # what users run: one port, prebuilt UI
python scripts/dev.py              # two ports, live reload on both
```

`scripts/dev.py` is the only path that needs Node at runtime. It starts uvicorn
with `--reload` on 8000 and Vite on 5173, and Vite proxies `/api` to the
backend. Stdlib only, so it works the same on Windows.

Interactive API docs: `http://localhost:8000/docs`.

## Tests

```bash
pytest                             # from the repository root
pytest backend/tests/test_retry.py -v
```

No network and no database setup: `backend/tests/conftest.py` points the app at
a temporary data directory and SQLite file before any application module is
imported, swaps in a stub provider, and disables rate pacing.

Tests that need the built interface are skipped when `backend/bulk_ioc_scanner/web/`
is absent, so a fresh clone still runs green.

## Layout

```
pyproject.toml            packaging, dependencies, pytest config
Dockerfile                node build stage -> python runtime, one container
scripts/dev.py            two-server development launcher
scripts/pyinstaller_entry.py  entry point for the standalone executables

backend/bulk_ioc_scanner/
  cli.py                  bulk-ioc-scanner command: ports, browser, banner
  paths.py                per-OS data directory, permissions, legacy DB move
  web_ui.py               serves the built UI with an index.html fallback
  main.py                 FastAPI app, lifespan, router and UI mounting
  config.py               pydantic-settings; every setting and its default
  api/
    scan.py               POST /api/scan, /scan/text, /scan/stream, /scan/files
    history.py            GET /api/history, /history/stats, /history/{id}
    settings.py           GET/PUT /api/settings — provider status and keys
  providers/
    base.py               Provider ABC: supports(), lookup(), lookup_batch()
    catalog.py            the provider list: ids, display names, key required
    registry.py           builds instances for the providers currently active
    http.py               shared client: proxy, CA bundle, retry with backoff
    virustotal.py abuseipdb.py greynoise.py threatfox.py urlscan.py
    ipify.py rdap.py
  services/
    ioc_detect.py         detect(ioc) -> type; refang(); parse_bulk_input()
    scanner.py            scan_bulk() and scan_bulk_stream() orchestration
    risk.py               compute_risk() -> (score, band), max across sources
    keystore.py           in-memory keys and on/off toggles, backed by SQLite
    ratelimit.py          per-provider pacing and 429 cooldowns
    hashing.py            hash_upload(): streams a file, deletes the temp copy
  database/
    db.py                 engine, session factory, init_db(), column migration
    crud.py               scan persistence, history queries, key storage
  models/
    tables.py             Scan, ProviderResponse, ApiKey
    schemas.py            request and response models

frontend/src/
  api/client.js           every API call; base URL is the relative "/api"
  pages/                  Dashboard, Scan, History, Settings
  components/             results table, detail modal, dropzone, badges
  utils/                  defang, IOC import from CSV/TXT
```

## How a scan works

`Scan.jsx` posts to `/api/scan/stream`, which returns newline-delimited JSON —
one result per line, written as each indicator finishes rather than at the end.

`scan_bulk_stream()` first answers from cache, then dispatches provider-major:
each provider receives every indicator it supports in one call, paced through
its own limiter. Results land on a queue and an indicator is emitted once all
of its providers have reported.

Two invariants worth preserving:

- **One result per input, always.** A provider that raises, times out, or
  answers about the wrong indicator only loses its own column.
  `backend/tests/test_failure_isolation.py` pins this down.
- **Nothing buffers the stream.** The progress bar only moves as lines arrive,
  so any proxy or middleware added in front must not collect the response.

## Adding a provider

1. Implement `Provider` in `backend/bulk_ioc_scanner/providers/yours.py`:
   `supports(ioc_type)` and `async lookup(client, ioc, ioc_type)`.
   `abuseipdb.py` is the smallest example.
2. Make requests with `request_with_retry()` from `providers/http.py` so you
   inherit proxy support, the CA bundle, and 429 backoff.
3. Return a `ProviderResult` for every outcome, including failures — never
   raise out of `lookup()`.
4. Add a `ProviderInfo` to `providers/catalog.py`, a key field to `config.py`,
   and the id-to-class mapping in `providers/registry.py`.
5. If the API has a real bulk endpoint, override `lookup_batch()` and set
   `batch_capable = True`; return exactly one result per input item.

## Risk scoring

`services/risk.py`. VirusTotal's malicious/total ratio weighs heaviest,
suspicious counts half. AbuseIPDB's confidence score feeds in directly. The
highest score across sources wins: 0–30 Low, 31–70 Medium, 71–100 High. More
than four VirusTotal vendors flagging an indicator forces at least Medium.

## Releasing

Push a `v*` tag. `.github/workflows/release.yml` builds the interface once,
then publishes the wheel and sdist to PyPI through Trusted Publishing, the
Linux and Windows executables, and a multi-architecture container image, and
attaches everything to the GitHub release with checksums.

Run the workflow manually with **Dry run** to build all of it and publish none
of it.

PyPI publishing needs a one-time Trusted Publisher entry on the PyPI side for
this repository and the `pypi` environment. Nothing is stored as a repository
secret.

## Notes on security

- API keys live in the user data directory, never in the repository. The
  database file is created readable only by its owner. Keys are stored in
  plain text, so the file matters.
- Uploaded files are hashed in a temporary file that is deleted in a `finally`
  block; only the SHA-256 is ever sent to a provider.
- Requests are same-origin, so CORS stays off unless `FRONTEND_ORIGIN` is set.
- There is no authentication. Binding to `0.0.0.0` exposes the whole interface,
  including saved keys, to anyone who can reach the port.
