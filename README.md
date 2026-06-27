# IOC-Radar

A web tool for SOC analysts to bulk-scan Indicators of Compromise — file hashes, IP
addresses, domains, and URLs — against threat intelligence providers (VirusTotal & AbuseIPDB).

## Features

- **Bulk scanning** — paste many IOCs at once (newline or comma separated)
- **File scanning** — files are hashed locally (MD5/SHA1/SHA256); only the hash is sent out
- **Auto type detection** — hashes, IPs, domains, URLs (handles defanged IOCs too)
- **Risk scoring** — 0–100 score, color-coded Low / Medium / High
- **History, tagging, CSV export, and copy-ready investigation reports**
- **API keys** configurable right in the UI — no file editing needed

## Tech Stack

FastAPI · SQLite · React · Tailwind CSS

---

## Running

You need `python3`, `npm`, and `bash`.

```bash
git clone https://github.com/HashemSalhi/IOC-Radar.git
cd IOC-Radar
./run.sh
```

`run.sh` installs everything on first run and starts both servers:

- **App:** http://localhost:5173
- **API:** http://localhost:8000 (docs at `/docs`)

Press **Ctrl+C** to stop.

### With Docker

```bash
docker compose up --build
# App: http://localhost   ·   API: http://localhost:8000
```

---

## Adding API Keys

No key is needed to start. To enable live lookups, open the **Settings** page in the app and
paste your keys — they are stored locally and take effect immediately.

- VirusTotal: https://www.virustotal.com/gui/my-apikey
- AbuseIPDB: https://www.abuseipdb.com/account/api

(You can also pre-set them in `backend/.env` — copy `.env.example`.)

---

## How File Scanning Stays Safe

Uploaded files are streamed through MD5/SHA1/SHA256 hashing and the temporary copy is deleted
right after. **Only the hash is sent to providers — your file contents never leave the machine.**

---

## Tests

```bash
cd backend
pip install -r requirements.txt pytest pytest-asyncio
pytest
```
