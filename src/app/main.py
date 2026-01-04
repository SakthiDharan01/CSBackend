from fastapi import FastAPI

from .api.routes import security, smb
from .core.config import settings


def create_app() -> FastAPI:
    app = FastAPI(title=settings.APP_NAME, version=settings.VERSION)

    @app.get("/health", tags=["health"])
    def health_check() -> dict:
        return {"status": "ok", "service": settings.APP_NAME, "version": settings.VERSION}

    app.include_router(security.router, prefix="/security_score", tags=["security_score"])
    app.include_router(smb.router, prefix="/smb", tags=["smb"])

    return app


app = create_app()
