import os
import secrets
from pathlib import Path
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load .env if present
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)


def parse_cors_origins() -> list[str]:
    raw_origins = os.getenv("CORS_ORIGINS")
    if raw_origins is None:
        if os.getenv("APP_ENV", "development") == "production":
            return []
        raw_origins = "http://127.0.0.1:5173,http://localhost:5173"
    return [origin.strip().rstrip("/") for origin in raw_origins.split(",") if origin.strip()]


class Settings(BaseModel):
    app_name: str = "ExposureGraph"
    app_version: str = "0.1.0"
    app_env: str = os.getenv("APP_ENV", "development")
    debug: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./exposuregraph.db")
    session_secret: str = os.getenv("SESSION_SECRET", "")
    session_ttl_seconds: int = int(os.getenv("SESSION_TTL_SECONDS", "28800"))
    secure_cookies: bool = os.getenv(
        "COOKIE_SECURE",
        "true" if os.getenv("APP_ENV", "development") == "production" else "false",
    ).lower() in ("true", "1", "t")
    domain_auth_mode: str = os.getenv("DOMAIN_AUTH_MODE", "demo_attestation")
    cors_origins: list[str] = Field(default_factory=parse_cors_origins)
    max_active_scans_per_user: int = int(os.getenv("MAX_ACTIVE_SCANS_PER_USER", "2"))
    scan_execution_mode: str = os.getenv("SCAN_EXECUTION_MODE", "inline")
    scan_worker_poll_seconds: float = float(os.getenv("SCAN_WORKER_POLL_SECONDS", "1.0"))
    login_rate_limit: int = int(os.getenv("LOGIN_RATE_LIMIT", "8"))
    login_rate_window_seconds: int = int(os.getenv("LOGIN_RATE_WINDOW_SECONDS", "900"))
    user_rate_limit: int = int(os.getenv("USER_RATE_LIMIT", "120"))
    user_rate_window_seconds: int = int(os.getenv("USER_RATE_WINDOW_SECONDS", "60"))

    # Scanner limits & timeouts
    scan_timeout_seconds: float = float(os.getenv("SCAN_TIMEOUT_SECONDS", "45.0"))
    max_subdomains: int = int(os.getenv("MAX_SUBDOMAINS_TO_ENUMERATE", "30"))
    max_redirects: int = int(os.getenv("MAX_REDIRECTS", "4"))

    # Gnani STT Settings
    gnani_api_key: str = os.getenv("GNANI_API_KEY", "")

    # Gemini LLM Settings (voice assistant brain)
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    gnani_stt_url: str = os.getenv("GNANI_STT_URL", "https://api.vachana.ai/stt/v3")
    gnani_model: str = os.getenv("GNANI_MODEL", "prisma-v3.0")
    gnani_language_code: str = os.getenv("GNANI_LANGUAGE_CODE", "indic-auto")

    # Gnani TTS Settings
    gnani_tts_url: str = os.getenv("GNANI_TTS_URL", "https://api.vachana.ai/api/v1/tts/inference")
    gnani_tts_model: str = os.getenv("GNANI_TTS_MODEL", "timbre-v2.5")
    gnani_tts_voice: str = os.getenv("GNANI_TTS_VOICE", "Nalini")
    gnani_tts_language: str = os.getenv("GNANI_TTS_LANGUAGE", "en-IN")


settings = Settings()

# An ephemeral development key keeps local setup simple. Production startup
# rejects an absent/weak key so sessions cannot silently change on restart.
if not settings.session_secret and settings.app_env != "production":
    settings.session_secret = secrets.token_urlsafe(48)


def validate_runtime_settings() -> None:
    if settings.scan_execution_mode not in {"inline", "worker"}:
        raise RuntimeError("SCAN_EXECUTION_MODE must be inline or worker.")
    if settings.scan_timeout_seconds < 1 or settings.scan_timeout_seconds > 1800:
        raise RuntimeError("SCAN_TIMEOUT_SECONDS must be between 1 and 1800.")
    if settings.max_subdomains < 0 or settings.max_subdomains > 100:
        raise RuntimeError("MAX_SUBDOMAINS_TO_ENUMERATE must be between 0 and 100.")
    if settings.max_active_scans_per_user < 1 or settings.max_active_scans_per_user > 10:
        raise RuntimeError("MAX_ACTIVE_SCANS_PER_USER must be between 1 and 10.")
    if settings.app_env == "production":
        if len(settings.session_secret) < 32:
            raise RuntimeError("SESSION_SECRET must contain at least 32 characters in production.")
        if settings.debug:
            raise RuntimeError("DEBUG must be false in production.")
        if settings.domain_auth_mode != "dns_txt":
            raise RuntimeError("DOMAIN_AUTH_MODE=dns_txt is required in production.")
        if not settings.secure_cookies:
            raise RuntimeError("COOKIE_SECURE must be true in production.")
        if not settings.cors_origins or "*" in settings.cors_origins:
            raise RuntimeError("CORS_ORIGINS must be explicit in production.")
        if settings.scan_execution_mode != "worker":
            raise RuntimeError("SCAN_EXECUTION_MODE=worker is required in production.")
    elif settings.domain_auth_mode not in {"demo_attestation", "dns_txt"}:
        raise RuntimeError("DOMAIN_AUTH_MODE must be demo_attestation or dns_txt.")
