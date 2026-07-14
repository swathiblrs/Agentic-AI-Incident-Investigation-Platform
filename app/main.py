from fastapi import FastAPI

from app.api.routes import router
from app.core.config import get_settings


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="SOC-focused AI agent for alert triage, RAG-grounded investigation, and remediation.",
    )
    app.include_router(router, prefix="/api")
    return app


app = create_app()
