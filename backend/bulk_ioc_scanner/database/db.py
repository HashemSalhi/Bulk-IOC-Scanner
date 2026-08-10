from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from bulk_ioc_scanner.config import settings

engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def init_db() -> None:
    """Create all tables on startup, then add any newly-declared columns."""
    from bulk_ioc_scanner.models import tables  # noqa: F401 — ensures models are registered

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_ensure_columns)


def _ensure_columns(conn) -> None:
    """
    Lightweight, Alembic-free migration: for each mapped table, add any column
    declared on the model but missing from the live SQLite table.

    create_all() only creates missing tables, never missing columns, so adding a
    field to an existing model would otherwise be invisible on existing databases.
    """
    from sqlalchemy import text

    for table in Base.metadata.sorted_tables:
        existing = {
            row[1]  # PRAGMA table_info: (cid, name, type, notnull, dflt_value, pk)
            for row in conn.execute(text(f'PRAGMA table_info("{table.name}")'))
        }
        if not existing:
            continue  # table doesn't exist yet (create_all handles it)
        for column in table.columns:
            if column.name in existing:
                continue
            col_type = column.type.compile(dialect=conn.dialect)
            conn.execute(
                text(f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {col_type}')
            )


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session
