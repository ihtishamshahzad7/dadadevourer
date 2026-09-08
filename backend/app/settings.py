from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://dadadevourer:change-me-in-production@db:5432/dadadevourer"
    redis_url: str = "redis://redis:6379/0"
    jwt_secret: str = "change-this-secret"
    cors_origins: list[str] = ["http://localhost:3000"]
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
