from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer


def _utc_iso(dt: datetime | None) -> str | None:
    """Serialize a (naive-UTC) datetime as an unambiguous ISO-8601 UTC string."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ── Request models ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    iocs: list[str] = Field(..., min_length=1, description="List of IOC strings to scan")


class TextScanRequest(BaseModel):
    text: str = Field(..., description="Raw pasted text; split on newlines/commas")


# ── Provider result ───────────────────────────────────────────────────────────

class ProviderResult(BaseModel):
    provider: str
    ioc: str
    ioc_type: str
    success: bool
    error: str | None = None
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    undetected: int | None = None
    detection_ratio: str | None = None   # e.g. "12/70"
    raw: dict[str, Any] = {}


# ── Scan result (enriched with risk score) ───────────────────────────────────

class ScanResult(BaseModel):
    id: int | None = None
    ioc: str
    ioc_type: str
    risk_score: float | None = None
    risk_band: str | None = None          # Low / Medium / High
    detection_ratio: str | None = None
    status: str = "completed"
    tag: str | None = None
    source_filename: str | None = None
    file_size: int | None = None
    created_at: datetime | None = None
    from_cache: bool = False
    provider_results: list[ProviderResult] = []

    @field_serializer("created_at")
    def _ser_created_at(self, dt: datetime | None) -> str | None:
        return _utc_iso(dt)


# ── History / tag update ──────────────────────────────────────────────────────

class TagUpdate(BaseModel):
    tag: str | None = Field(None, description="Malware | Phishing | Investigation | False Positive | null to clear")


class ScanHistoryItem(BaseModel):
    id: int
    ioc: str
    ioc_type: str
    risk_score: float | None
    risk_band: str | None
    detection_ratio: str | None
    status: str
    tag: str | None
    source_filename: str | None
    file_size: int | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("created_at")
    def _ser_created_at(self, dt: datetime | None) -> str | None:
        return _utc_iso(dt)


class ScanDetail(ScanHistoryItem):
    provider_results: list[ProviderResult] = []


# ── Settings response ─────────────────────────────────────────────────────────

class ProviderStatus(BaseModel):
    id: str                       # provider id, e.g. "virustotal"
    name: str                     # display name, e.g. "VirusTotal"
    enabled: bool
    key_hint: str | None = None   # masked, e.g. "be97...b8e1"


class SettingsResponse(BaseModel):
    providers: list[ProviderStatus]
    max_upload_mb: int
    max_iocs_per_scan: int


class ApiKeyUpdate(BaseModel):
    # {provider_id: key}; empty string clears, omitted leaves unchanged
    keys: dict[str, str] = {}


# ── File scan response ────────────────────────────────────────────────────────

class FileHashInfo(BaseModel):
    filename: str
    size: int
    md5: str
    sha1: str
    sha256: str


class FileScanResult(BaseModel):
    file_info: FileHashInfo
    scan_result: ScanResult
