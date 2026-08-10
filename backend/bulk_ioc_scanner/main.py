"""Bulk-IOC-Scanner FastAPI application entry point."""
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from bulk_ioc_scanner.api import history, scan, settings
from bulk_ioc_scanner.config import settings as cfg
from bulk_ioc_scanner.database.db import AsyncSessionLocal, init_db
from bulk_ioc_scanner.paths import db_path, migrate_legacy_db, protect_db_file
from bulk_ioc_scanner.utils.logging import configure_logging

configure_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Only relocate the old in-checkout database when we are actually using the
    # default location; a custom DATABASE_URL means the operator chose a path.
    if str(db_path()) in cfg.database_url:
        migrate_legacy_db()

    await init_db()
    protect_db_file()  # the database stores API keys in plain text
    # Load any keys previously saved via the web UI into the in-memory store
    async with AsyncSessionLocal() as db:
        from bulk_ioc_scanner.services.keystore import keystore
        await keystore.load_from_db(db)
    yield
    from bulk_ioc_scanner.database.db import engine
    await engine.dispose()


app = FastAPI(
    title="Bulk-IOC-Scanner",
    description="Bulk IOC threat intelligence scanner",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[cfg.frontend_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(history.router)
app.include_router(settings.router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "Bulk-IOC-Scanner"}
