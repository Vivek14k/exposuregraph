from contextlib import asynccontextmanager
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.api.routes import router as api_router
from backend.core.config import settings, validate_runtime_settings
from backend.database.models import get_db, SessionLocal, Scan, utcnow

validate_runtime_settings()


def recover_stale_scans() -> int:
    """Recovers scans that were left PENDING or RUNNING when the app restarted in inline mode."""
    db = SessionLocal()
    try:
        updated = db.query(Scan).filter(Scan.status.in_(["PENDING", "RUNNING"])).update({
            Scan.status: "FAILED",
            Scan.error_message: "The application restarted before this assessment completed. Please start a new assessment.",
            Scan.completed_at: utcnow(),
        }, synchronize_session=False)
        db.commit()
        return updated
    except Exception:
        db.rollback()
        return 0
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.scan_execution_mode == "inline":
        recover_stale_scans()
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Cybersecurity attack surface and exposure graph platform.",
    debug=settings.debug,
    docs_url="/docs" if settings.debug else None,
    redoc_url=None,
    openapi_url="/openapi.json" if settings.debug else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
    expose_headers=["Retry-After"],
    max_age=600,
)


@app.middleware("http")
async def add_security_headers_and_check_origin(request: Request, call_next):
    if request.url.path.startswith("/api/") and request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin = request.headers.get("origin")
        if origin not in settings.cors_origins:
            return JSONResponse(status_code=403, content={"detail": "Request origin is not allowed."})

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=(self)"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    if settings.app_env == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return JSONResponse(status_code=503, content={"status": "unavailable", "service": settings.app_name})
    return {"status": "ok", "service": settings.app_name}


app.include_router(api_router)
