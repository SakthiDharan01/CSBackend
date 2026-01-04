from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or defaults."""

    APP_NAME: str = "CyberShield Backend"
    VERSION: str = "0.1.0"
    SECURITY_DEFAULT_SCORE: float = 75.0
    SMB_DEFAULT_RISK_LEVEL: str = "low"
    VIRUSTOTAL_API_KEY: str = ""
    HIBP_API_KEY: str = ""
    CORS_ALLOW_ORIGINS: list[str] = ["*"]
    CORS_ALLOW_METHODS: list[str] = ["*"]
    CORS_ALLOW_HEADERS: list[str] = ["*"]
    CORS_ALLOW_CREDENTIALS: bool = False

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
