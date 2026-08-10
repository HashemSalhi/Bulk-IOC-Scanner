from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from bulk_ioc_scanner.paths import db_path, env_file_path


def _default_database_url() -> str:
    """SQLite URL pointing at the per-user data directory.

    Both POSIX (``/home/you/...``) and Windows (``C:\\Users\\...``) absolute
    paths are valid after the three-slash prefix.
    """
    return f"sqlite+aiosqlite:///{db_path()}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        # A .env is entirely optional. The one in the data directory is for
        # people who prefer a file over the Settings page; the one in the
        # working directory is the developer convenience and wins.
        env_file=(env_file_path(), ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # API Keys
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    greynoise_api_key: str = ""
    threatfox_auth_key: str = ""
    urlscan_api_key: str = ""
    ipify_api_key: str = ""

    # Limits
    max_upload_mb: int = 1024  # 1 GB
    max_iocs_per_scan: int = 200

    # Caching — reuse a stored result if the same IOC was scanned within this window
    cache_ttl_hours: int = 24

    # Per-provider rate pacing (requests per minute); tuned to free-tier limits
    vt_rate_per_min: int = 4
    abuseipdb_rate_per_min: int = 30
    greynoise_rate_per_min: int = 30
    threatfox_rate_per_min: int = 60
    urlscan_rate_per_min: int = 60
    ipify_rate_per_min: int = 60

    # CORS
    frontend_origin: str = "http://localhost:5173"

    # Database — defaults to the OS user data directory, not the install folder
    database_url: str = Field(default_factory=_default_database_url)

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


settings = Settings()
