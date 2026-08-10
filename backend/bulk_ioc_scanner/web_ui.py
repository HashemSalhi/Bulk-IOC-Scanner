"""Serve the built React UI from the API process, on one port.

``vite build`` writes into ``bulk_ioc_scanner/web/`` and that directory ships
inside the wheel, so an installed copy serves its own UI with no Node runtime,
no second server, and no CORS.

The UI uses history-based routing, so a reload on /scan or /history asks the
server for a path that does not exist on disk. Every unmatched GET therefore
falls back to index.html and lets the router sort it out.
"""
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent / "web"

_NOT_BUILT_PAGE = """<!doctype html>
<meta charset="utf-8">
<title>Bulk-IOC-Scanner</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 40rem; margin: 4rem auto;
         padding: 0 1.5rem; line-height: 1.6; }
  code { background: #f4f4f5; padding: .15rem .4rem; border-radius: .25rem; }
</style>
<h1>The web interface has not been built</h1>
<p>You are running from a source checkout. Build the interface once:</p>
<pre><code>cd frontend
npm install
npm run build</code></pre>
<p>Then restart. Installed copies ship the interface prebuilt, so this page
only ever appears to developers.</p>
<p>The API itself is running — see <a href="/docs">/docs</a>.</p>
"""


def is_built() -> bool:
    return (WEB_DIR / "index.html").is_file()


def mount(app: FastAPI) -> None:
    """Attach the UI routes. Must be called after every API router."""

    @app.get("/api/{path:path}", include_in_schema=False)
    async def api_not_found(path: str):
        """Keep unknown API paths as JSON.

        Without this the catch-all below would answer a mistyped endpoint with
        the HTML page, which is a confusing thing to debug against.
        """
        return JSONResponse({"detail": f"Unknown API endpoint: /api/{path}"}, status_code=404)

    if not is_built():
        logger.warning("No built web interface at %s — serving build instructions", WEB_DIR)

        @app.get("/{path:path}", include_in_schema=False)
        async def not_built(path: str):
            return HTMLResponse(_NOT_BUILT_PAGE, status_code=200)

        return

    app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(request: Request, path: str):
        # Serve a real file when one exists (logo.svg, favicon, robots.txt),
        # otherwise hand the route to the client-side router.
        candidate = (WEB_DIR / path).resolve()
        if path and candidate.is_file() and candidate.is_relative_to(WEB_DIR):
            return FileResponse(candidate)
        return FileResponse(WEB_DIR / "index.html")
