from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import settings, validate_startup_security, ensure_secret_key, is_production
from routers.auth import router as auth_router
from routers.configs import router as configs_router
from routers.device_access import router as device_access_router
from routers.training import router as training_router

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

app.include_router(auth_router)
app.include_router(device_access_router)
app.include_router(configs_router)
app.include_router(training_router)
