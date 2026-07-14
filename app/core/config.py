from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Security Alert Investigation Agent"
    app_env: str = "local"
    rag_top_k: int = 5
    risk_threshold_high: int = 75
    risk_threshold_medium: int = 45
    database_url: str = "postgresql://incident:incident@localhost:5432/incident_response"
    use_postgres: bool = False

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
