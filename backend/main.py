import asyncio

import redis
import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from config import settings, validate_startup_security, ensure_secret_key, is_production
from database import engine
from routers.auth import router as auth_router
from routers.configs import router as configs_router
from routers.device_access import router as device_access_router
from routers.device_credentials import router as device_credentials_router
from routers.devices import router as devices_router
from routers.training import router as training_router
from routers.organizations import router as organizations_router
from routers.audit_schedules import router as audit_schedules_router
from routers.network_missions import router as network_missions_router

# Refuse to boot with default secrets in a production posture (no-op warning for
# local self-hosted). Runs at import so uvicorn/gunicorn can't skip it.
ensure_secret_key()
validate_startup_security()

app = FastAPI(
    title="Valsec Network Security API",
    description="Deterministic multi-vendor network configuration compliance auditing.",
    version="1.0.0",
    # L1: no interactive docs / schema disclosure in a production posture.
    **({"docs_url": None, "redoc_url": None, "openapi_url": None} if is_production() else {}),
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _check_database() -> None:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))


def _check_redis() -> None:
    client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.75, socket_timeout=0.75)
    client.ping()


def _check_ollama() -> None:
    headers = (
        {"Authorization": f"Bearer {settings.OLLAMA_AUTH_TOKEN}"}
        if settings.OLLAMA_AUTH_TOKEN else None
    )
    response = requests.get(
        f"{settings.OLLAMA_URL.rstrip('/')}/api/tags",
        headers=headers,
        timeout=0.75,
    )
    response.raise_for_status()


@app.get("/health", tags=["observability"])
def health():
    return {"status": "ok"}


@app.get("/ready", tags=["observability"])
async def ready():
    names = ("database", "redis", "ollama")
    checks = (_check_database, _check_redis, _check_ollama)
    results = await asyncio.gather(
        *(asyncio.to_thread(check) for check in checks),
        return_exceptions=True,
    )
    production = is_production()
    dependencies = {}
    for name, result in zip(names, results):
        if isinstance(result, BaseException):
            dependencies[name] = {
                "ok": False,
                "error": "unavailable" if production else f"{type(result).__name__}: {result}",
            }
        else:
            dependencies[name] = {"ok": True}
    healthy = all(item["ok"] for item in dependencies.values())
    payload = {"status": "ready" if healthy else "not_ready", "dependencies": dependencies}
    return payload if healthy else JSONResponse(status_code=503, content=payload)

app.include_router(auth_router)
app.include_router(device_access_router)
app.include_router(configs_router)
app.include_router(training_router)
app.include_router(devices_router)
app.include_router(device_credentials_router)
app.include_router(organizations_router)
app.include_router(audit_schedules_router)
app.include_router(network_missions_router)
