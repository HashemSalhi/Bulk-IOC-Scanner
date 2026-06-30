from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
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

    # Database
    database_url: str = "sqlite+aiosqlite:///./bulk_ioc_scanner.db"

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


settings = Settings()
