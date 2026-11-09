import hashlib
import hmac
import secrets
from datetime import timedelta
from typing import Optional

from fastapi import HTTPException, Request
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.database.models import AuthSession, RateLimitBucket, User, utcnow

SESSION_COOKIE = "eg_session"
CSRF_COOKIE = "eg_csrf"
CSRF_HEADER = "x-csrf-token"
SESSION_TTL = timedelta(seconds=settings.session_ttl_seconds)
_SALT_BYTES = 16
_SCRYPT_N = 2**15
_SCRYPT_P = 3


def digest_token(token: str) -> str:
    return hmac.new(settings.session_secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if len(normalized) > 320 or normalized.count("@") != 1:
        raise ValueError("Enter a valid email address.")
    local, domain = normalized.rsplit("@", 1)
    if not local or not domain or "." not in domain or any(char.isspace() for char in normalized):
        raise ValueError("Enter a valid email address.")
    return normalized


def hash_password(password: str) -> str:
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Passwords must contain between 12 and 256 characters.")
    salt = secrets.token_bytes(_SALT_BYTES)
    value = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=8, p=_SCRYPT_P, dklen=32,
        maxmem=64 * 1024 * 1024,
    )
    return f"scrypt${_SCRYPT_N}$8${_SCRYPT_P}${salt.hex()}${value.hex()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, n, r, p, salt_hex, expected_hex = encoded_hash.split("$")
        if algorithm != "scrypt" or len(password) > 256:
            return False
        calculated = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(expected_hex)),
            maxmem=64 * 1024 * 1024,
        )
        return hmac.compare_digest(calculated.hex(), expected_hex)
    except (ValueError, TypeError, MemoryError):
        return False


def create_user(db: Session, email: str, password: str, *, claim_legacy_scans: bool = False) -> User:
    normalized = normalize_email(email)
    if db.query(User.id).filter(User.email == normalized).first():
        raise ValueError("An account with that email already exists.")
    user = User(email=normalized, password_hash=hash_password(password))
    db.add(user)
    db.flush()
    if claim_legacy_scans:
        from backend.database.models import Scan

        db.query(Scan).filter(Scan.user_id.is_(None)).update({Scan.user_id: user.id}, synchronize_session=False)
    db.commit()
    db.refresh(user)
    return user


def issue_session(db: Session, user: User, csrf_token: str) -> tuple[str, int]:
    raw_token = secrets.token_urlsafe(48)
    now = utcnow()
    expires_at = now + SESSION_TTL
    db.query(AuthSession).filter(AuthSession.expires_at <= now).delete(synchronize_session=False)
    old_sessions = db.query(AuthSession).filter(
        AuthSession.user_id == user.id,
        AuthSession.expires_at > now,
    ).order_by(AuthSession.created_at.desc()).offset(9).all()
    for old_session in old_sessions:
        db.delete(old_session)
    db.add(AuthSession(
        token_hash=digest_token(raw_token),
        user_id=user.id,
        csrf_hash=digest_token(csrf_token),
        expires_at=expires_at,
    ))
    db.commit()
    return raw_token, settings.session_ttl_seconds


def revoke_session(db: Session, raw_token: Optional[str]) -> None:
    if not raw_token:
        return
    db.query(AuthSession).filter(AuthSession.token_hash == digest_token(raw_token)).delete(synchronize_session=False)
    db.commit()


def get_current_user(request: Request, db: Session) -> User:
    raw_token = request.cookies.get(SESSION_COOKIE)
    if not raw_token:
        raise HTTPException(status_code=401, detail="Authentication required.")
    session = db.query(AuthSession).filter(
        AuthSession.token_hash == digest_token(raw_token),
        AuthSession.expires_at > utcnow(),
    ).first()
    if not session or not session.user or not session.user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required.")

    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
        csrf_header = request.headers.get(CSRF_HEADER, "")
        if (
            not csrf_cookie
            or not csrf_header
            or not hmac.compare_digest(csrf_cookie, csrf_header)
            or not hmac.compare_digest(digest_token(csrf_cookie), session.csrf_hash)
        ):
            raise HTTPException(status_code=403, detail="CSRF validation failed.")
    return session.user


def verify_login_csrf(request: Request) -> str:
    csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
    csrf_header = request.headers.get(CSRF_HEADER, "")
    if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(status_code=403, detail="CSRF validation failed.")
    return csrf_cookie


def enforce_rate_limit(db: Session, key: str, limit: int, window_seconds: int) -> None:
    """Persistent fixed-window limiter shared by app workers through the DB."""
    key_hash = digest_token(key)
    now = utcnow()
    stale_before = now - timedelta(days=1)
    removed = db.query(RateLimitBucket).filter(
        RateLimitBucket.window_started_at < stale_before,
    ).delete(synchronize_session=False)
    if removed:
        db.commit()
    row = db.query(RateLimitBucket).filter(RateLimitBucket.key_hash == key_hash).with_for_update().first()
    if row is None:
        db.add(RateLimitBucket(key_hash=key_hash, window_started_at=now, hits=1))
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            return enforce_rate_limit(db, key, limit, window_seconds)
        return

    age = (now - row.window_started_at).total_seconds()
    if age >= window_seconds or age < 0:
        row.window_started_at = now
        row.hits = 1
        db.commit()
        return
    if row.hits >= limit:
        retry_after = max(1, int(window_seconds - age))
        db.rollback()
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait before trying again.",
            headers={"Retry-After": str(retry_after)},
        )
    row.hits += 1
    db.commit()


def client_rate_key(request: Request, purpose: str, identity: str = "") -> str:
    client_host = request.client.host if request.client else "unknown"
    return f"{purpose}:{client_host}:{identity.lower()}"


def set_auth_cookies(response, session_token: str, csrf_token: str, max_age: int) -> None:
    cookie_options = {
        "secure": settings.secure_cookies,
        "samesite": "strict",
        "path": "/",
    }
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=max_age,
        httponly=True,
        **cookie_options,
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=max_age,
        httponly=False,
        **cookie_options,
    )


def clear_auth_cookies(response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.secure_cookies, httponly=True, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=settings.secure_cookies, httponly=False, samesite="strict")
