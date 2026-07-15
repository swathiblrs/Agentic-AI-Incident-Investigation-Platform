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
    use_langgraph_checkpoints: bool = True
    postgres_host: str = "localhost"
    postgres_db: str = "incident_response"
    postgres_user: str = "incident"
    postgres_password: str = "incident"
    redis_url: str = "redis://localhost:6379/0"
    auth_required: bool = True
    jwt_secret_key: str = "change-me-local-secret-at-least-32-characters"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 120
    demo_username: str = "analyst"
    demo_password: str = "analyst"
    llm_provider: str = "openai"
    ollama_base_url: str = "http://localhost:11434"
    ollama_llm_model: str = "llama3.1"
    ollama_embed_model: str = "nomic-embed-text"
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    openai_embed_model: str = "text-embedding-3-small"
    openai_embed_dimensions: int = 384
    anthropic_api_key: str = ""
    anthropic_base_url: str = "https://api.anthropic.com/v1"
    anthropic_model: str = "claude-3-5-haiku-latest"
    llm_max_retries: int = 3
    llm_retry_base_seconds: float = 0.5
    llm_retry_max_seconds: float = 4.0
    db_pool_min_size: int = 1
    db_pool_max_size: int = 5
    langgraph_checkpoint_tables: tuple[str, ...] = (
        "checkpoints",
        "checkpoint_writes",
        "checkpoint_blobs",
    )
    langfuse_enabled: bool = False
    langfuse_host: str = "http://localhost:3001"
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    evaluation_provider: str = "auto"
    evaluation_model: str = "gpt-4o-mini"
    evaluation_max_retries: int = 2

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")


@lru_cache
def get_settings() -> Settings:
    return Settings()
