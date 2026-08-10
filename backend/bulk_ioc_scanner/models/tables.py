import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from bulk_ioc_scanner.database.db import Base


def _utcnow() -> datetime.datetime:
    """Naive UTC timestamp (SQLite DateTime columns are timezone-naive)."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ioc: Mapped[str] = mapped_column(String(2048), nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_band: Mapped[str | None] = mapped_column(String(16), nullable=True)  # Low/Medium/High
    detection_ratio: Mapped[str | None] = mapped_column(String(32), nullable=True)  # "12/70"
    status: Mapped[str] = mapped_column(String(16), default="completed")  # completed/error
    tag: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_filename: Mapped[str | None] = mapped_column(String(512), nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=_utcnow
    )
    summary_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    provider_responses: Mapped[list["ProviderResponse"]] = relationship(
        "ProviderResponse", back_populates="scan", cascade="all, delete-orphan"
    )


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    key_value: Mapped[str] = mapped_column(String(512), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, default=_utcnow
    )


class ProviderResponse(Base):
    __tablename__ = "provider_responses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    success: Mapped[bool] = mapped_column(Integer, nullable=False)  # SQLite bool as int
    raw_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped["Scan"] = relationship("Scan", back_populates="provider_responses")
