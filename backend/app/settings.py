import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://dadadevourer:change-me-in-production@db:5432/dadadevourer"
    redis_url: str = "redis://redis:6379/0"
    jwt_secret: str = "change-this-secret"
    jwt_expire_minutes: int = 60
    cors_origins: str = "http://localhost:3000,http://localhost:1420,tauri://localhost,http://tauri.localhost"
    environment: str = "development"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


settings = Settings()

if settings.environment.lower() == "production":
    if len(settings.jwt_secret) < 32 or settings.jwt_secret == "change-this-secret":
        raise RuntimeError("JWT_SECRET must be a unique secret of at least 32 characters in production")
    if "change-me-in-production" in settings.database_url:
        raise RuntimeError("DATABASE_URL must be changed in production")
