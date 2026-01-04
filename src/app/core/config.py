from functools import lru_cache
from pydantic import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables or defaults."""

    APP_NAME: str = "CyberShield Backend"
    VERSION: str = "0.1.0"
    SECURITY_DEFAULT_SCORE: float = 75.0
    SMB_DEFAULT_RISK_LEVEL: str = "low"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
