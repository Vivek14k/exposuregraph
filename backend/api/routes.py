import asyncio
import hmac
import json
import secrets
from datetime import timedelta
from typing import Any, List, Literal, Optional

import dns.exception
import dns.resolver
from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Path, Query, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.api.schemas import (
    AssetResponse,
    AssistantChatRequest,
    AssistantChatResponse,
    AuthUserResponse,
    DomainAuthorizationRequest,
    DomainChallengeRequest,
    DomainChallengeResponse,
    DomainVerifyResponse,
    FindingResponse,
    GraphResponse,
    LoginRequest,
    ManualAttestationRequest,
    ManualAttestationResponse,
    ScanResponse,
    StartScanRequest,
    TTSRequest,
    VoiceTranscribeResponse,
)
from backend.core.auth import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    client_rate_key,
    clear_auth_cookies,
    digest_token,
    enforce_rate_limit,
    get_current_user,
    issue_session,
    set_auth_cookies,
    verify_login_csrf,
    verify_password,
)
from backend.core.config import settings
from backend.core.security import SecurityValidationError, normalize_domain
from backend.database.models import (
    Asset,
    AuthSession,
    DomainChallenge,
    Finding,
    GraphEdge,
    Scan,
    User,
    get_db,
    utcnow,
)
from backend.gnani.assistant import AssistantDialogueEngine, AuthorizationTokenManager
from backend.gnani.composer import ResponseComposer
from backend.gnani.stt import GnaniSTTService, detect_audio_format
from backend.gnani.tts import GnaniTTSService
try:
    # Optional dependency: only required for the LLM-driven streaming path.
    # If google-genai isn't installed (or GEMINI_API_KEY isn't set), the SSE
    # endpoint falls back to the deterministic FSM/composer path.
    from backend.gnani import llm as llm_mod
except Exception:  # noqa: BLE001 - ImportError or any failure inside llm.py
    llm_mod = None
from backend.graph.builder import ExposureGraphBuilder
from backend.scanner.orchestrator import execute_scan_task

router = APIRouter(prefix="/api", tags=["ExposureGraph API"])
MAX_AUDIO_SIZE_BYTES = 10 * 1024 * 1024
DOMAIN_CHALLENGE_TTL = timedelta(minutes=15)
DOMAIN_PROOF_TTL = timedelta(days=30)
_DUMMY_PASSWORD_HASH = None


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    rate_limit_user(request, user, db, "api")
    return user


def rate_limit_user(request: Request, user: User, db: Session, endpoint: str, limit: Optional[int] = None) -> None:
    enforce_rate_limit(
        db,
        client_rate_key(request, endpoint, f"user:{user.id}"),
        limit or settings.user_rate_limit,
        settings.user_rate_window_seconds,
    )


def get_owned_scan(db: Session, scan_id: int, user_id: int) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user_id).first()
    if not scan:
        # Same response for absent and another user's IDs prevents enumeration.
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


def resolve_txt_values(record_name: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    try:
        answers = resolver.resolve(record_name, "TXT", lifetime=4.0)
    except (dns.exception.DNSException, OSError):
        return []
    values = []
    for answer in answers:
        values.append(b"".join(answer.strings).decode("utf-8", errors="replace"))
    return values


def txt_proof_present(domain: str, token_hash: str) -> bool:
    record_name = f"_exposuregraph.{domain}"
    for value in resolve_txt_values(record_name):
        prefix, separator, token = value.partition("=")
        if separator and prefix == "exposuregraph-verification" and hmac.compare_digest(digest_token(token), token_hash):
            return True
    return False


@router.get("/auth/csrf")
def get_csrf_token(request: Request, response: Response, db: Session = Depends(get_db)):
    raw_session = request.cookies.get(SESSION_COOKIE)
    session = None
    if raw_session:
        session = db.query(AuthSession).filter(
            AuthSession.token_hash == digest_token(raw_session),
            AuthSession.expires_at > utcnow(),
        ).first()
    existing_csrf = request.cookies.get(CSRF_COOKIE, "")
    if session and existing_csrf and hmac.compare_digest(digest_token(existing_csrf), session.csrf_hash):
        token = existing_csrf
    else:
        token = secrets.token_urlsafe(32)
        if session:
            session.csrf_hash = digest_token(token)
            db.commit()
    response.set_cookie(
        CSRF_COOKIE,
        token,
        max_age=settings.session_ttl_seconds if session else 3600,
        path="/",
        secure=settings.secure_cookies,
        httponly=False,
        samesite="strict",
    )
    return {"csrf_token": token}


@router.post("/auth/login", response_model=AuthUserResponse)
def login(request: Request, payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    global _DUMMY_PASSWORD_HASH
    csrf_token = verify_login_csrf(request)
    email = payload.email.strip().lower()
    enforce_rate_limit(
        db,
        client_rate_key(request, "login", email),
        settings.login_rate_limit,
        settings.login_rate_window_seconds,
    )
    enforce_rate_limit(
        db,
        client_rate_key(request, "login-account", email),
        settings.login_rate_limit,
        settings.login_rate_window_seconds,
    )
    user = db.query(User).filter(User.email == email).first()
    if _DUMMY_PASSWORD_HASH is None:
        from backend.core.auth import hash_password
        _DUMMY_PASSWORD_HASH = hash_password("nonexistent-user-timing-equalizer")
    valid_password = verify_password(payload.password, user.password_hash if user else _DUMMY_PASSWORD_HASH)
    valid = bool(user and user.is_active and valid_password)
    if not valid:
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")

    raw_session, ttl = issue_session(db, user, csrf_token)
    set_auth_cookies(response, raw_session, csrf_token, ttl)
    return AuthUserResponse(id=user.id, email=user.email)


@router.get("/auth/me", response_model=AuthUserResponse)
def current_user(user: User = Depends(require_user)):
    return AuthUserResponse(id=user.id, email=user.email)


@router.post("/auth/logout")
def logout(request: Request, response: Response, user: User = Depends(require_user), db: Session = Depends(get_db)):
    raw_session = request.cookies.get(SESSION_COOKIE)
    db.query(AuthSession).filter(
        AuthSession.token_hash == digest_token(raw_session or ""),
        AuthSession.user_id == user.id,
    ).delete(synchronize_session=False)
    db.commit()
    clear_auth_cookies(response)
    return {"ok": True}


@router.get("/capabilities")
def get_capabilities(user: User = Depends(require_user)):
    stt = GnaniSTTService()
    tts = GnaniTTSService()
    return {
        "stt": {"configured": stt.is_configured(), "model": stt.model},
        "tts": {"configured": tts.is_configured(), "model": tts.model, "voice": tts.voice},
        "analysis": (
            f"Gemini · {settings.gemini_model}"
            if llm_mod is not None and llm_mod.is_configured()
            else "Evidence fallback · configure GEMINI_API_KEY for Gemini replies"
        ),
        "domain_auth_mode": settings.domain_auth_mode,
        "domain_auth_label": "DNS TXT verification" if settings.domain_auth_mode == "dns_txt" else "Local demo attestation",
    }


@router.post("/auth/attest", response_model=ManualAttestationResponse)
def manual_attest(
    payload: ManualAttestationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    rate_limit_user(request, user, db, "domain-attestation", limit=12)
    if settings.domain_auth_mode != "demo_attestation":
        raise HTTPException(status_code=403, detail="Manual attestation is available only in local demo mode.")
    if not payload.attestation_confirmed:
        raise HTTPException(status_code=400, detail="Attestation rejected. Confirm your authorization to continue.")
    try:
        clean_domain = normalize_domain(payload.domain)
    except SecurityValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    token = AuthorizationTokenManager.issue_token(
        clean_domain,
        attestation_method="demo_attestation",
        db_session=db,
        user_id=user.id,
    )
    return ManualAttestationResponse(authorization_token=token, domain=clean_domain)


@router.post("/domains/challenges", response_model=DomainChallengeResponse, status_code=201)
def create_domain_challenge(
    payload: DomainChallengeRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    rate_limit_user(request, user, db, "domain-challenge", limit=8)
    if settings.domain_auth_mode != "dns_txt":
        raise HTTPException(status_code=404, detail="DNS verification is not enabled in this local demo.")
    try:
        domain = normalize_domain(payload.domain)
    except SecurityValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    record_name = f"_exposuregraph.{domain}"
    if len(record_name) > 253:
        raise HTTPException(status_code=422, detail="The domain is too long to host the verification TXT record.")

    token = secrets.token_urlsafe(32)
    now = utcnow()
    expires_at = now + DOMAIN_CHALLENGE_TTL
    db.query(DomainChallenge).filter(DomainChallenge.expires_at <= now).delete(synchronize_session=False)
    challenge = DomainChallenge(
        user_id=user.id,
        domain=domain,
        token_hash=digest_token(token),
        expires_at=expires_at,
    )
    db.add(challenge)
    db.commit()
    db.refresh(challenge)
    return DomainChallengeResponse(
        id=challenge.id,
        domain=domain,
        record_name=record_name,
        record_value=f"exposuregraph-verification={token}",
        expires_at=expires_at,
    )


@router.post("/domains/challenges/{challenge_id}/verify", response_model=DomainVerifyResponse)
def verify_domain_challenge(
    request: Request,
    challenge_id: int = Path(gt=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    rate_limit_user(request, user, db, "domain-verify", limit=15)
    challenge = db.query(DomainChallenge).filter(
        DomainChallenge.id == challenge_id,
        DomainChallenge.user_id == user.id,
    ).first()
    if not challenge:
        raise HTTPException(status_code=404, detail="Verification challenge not found.")
    now = utcnow()
    if challenge.verified_at is None and challenge.expires_at <= now:
        raise HTTPException(status_code=410, detail="Verification challenge expired. Request a new challenge.")
    if not txt_proof_present(challenge.domain, challenge.token_hash):
        raise HTTPException(status_code=422, detail="The DNS TXT proof was not found. Check the record and allow DNS to propagate.")

    challenge.verified_at = now
    challenge.expires_at = now + DOMAIN_PROOF_TTL
    db.commit()
    token = AuthorizationTokenManager.issue_token(
        challenge.domain,
        attestation_method="dns_txt",
        db_session=db,
        user_id=user.id,
    )
    return DomainVerifyResponse(verified=True, domain=challenge.domain, authorization_token=token)


@router.post("/domains/authorize", response_model=ManualAttestationResponse)
def authorize_verified_domain(
    payload: DomainAuthorizationRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    rate_limit_user(request, user, db, "domain-authorize", limit=20)
    if settings.domain_auth_mode != "dns_txt":
        raise HTTPException(status_code=404, detail="DNS verification is not enabled in this local demo.")
    try:
        domain = normalize_domain(payload.domain)
    except SecurityValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    proof = db.query(DomainChallenge).filter(
        DomainChallenge.user_id == user.id,
        DomainChallenge.domain == domain,
        DomainChallenge.verified_at.is_not(None),
        DomainChallenge.expires_at > utcnow(),
    ).order_by(DomainChallenge.verified_at.desc()).first()
    if not proof or not txt_proof_present(domain, proof.token_hash):
        raise HTTPException(status_code=403, detail="Current DNS TXT domain-control verification is required.")
    token = AuthorizationTokenManager.issue_token(
        domain,
        attestation_method="dns_txt",
        db_session=db,
        user_id=user.id,
    )
    return ManualAttestationResponse(authorization_token=token, domain=domain)


@router.post("/scans", response_model=ScanResponse, status_code=202)
def start_scan(
    payload: StartScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    rate_limit_user(request, user, db, "start-scan", limit=12)
    if not payload.authorized:
        raise HTTPException(status_code=400, detail="Authorization is required to begin an assessment.")
    try:
        domain = normalize_domain(payload.domain)
    except SecurityValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not payload.authorization_token:
        raise HTTPException(status_code=403, detail="A valid domain authorization token is required.")
    active_count = db.query(Scan.id).filter(
        Scan.user_id == user.id,
        Scan.status.in_(["PENDING", "RUNNING"]),
    ).count()
    if active_count >= settings.max_active_scans_per_user:
        raise HTTPException(status_code=429, detail="The maximum number of active assessments has been reached.")

    valid = AuthorizationTokenManager.verify_and_consume(
        payload.authorization_token,
        domain,
        db_session=db,
        user_id=user.id,
    )
    if not valid:
        raise HTTPException(status_code=403, detail="Authorization token is invalid, expired, mismatched, or already used.")

    scan = Scan(user_id=user.id, target_domain=domain, authorized=True, status="PENDING")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    if settings.scan_execution_mode == "inline":
        background_tasks.add_task(execute_scan_task, scan.id)
    return scan


@router.get("/scans", response_model=List[ScanResponse])
def list_scans(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).limit(limit).all()


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(
    scan_id: int = Path(gt=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    return get_owned_scan(db, scan_id, user.id)


@router.get("/scans/{scan_id}/assets", response_model=List[AssetResponse])
def get_scan_assets(
    scan_id: int = Path(gt=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_owned_scan(db, scan_id, user.id)
    return db.query(Asset).filter(Asset.scan_id == scan_id).all()


@router.get("/scans/{scan_id}/findings", response_model=List[FindingResponse])
def get_scan_findings(
    scan_id: int = Path(gt=0),
    severity: Optional[Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]] = Query(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    get_owned_scan(db, scan_id, user.id)
    query = db.query(Finding).filter(Finding.scan_id == scan_id)
    if severity:
        query = query.filter(Finding.severity == severity.upper())
    return query.order_by(Finding.score.desc()).all()


@router.get("/scans/{scan_id}/graph", response_model=GraphResponse)
def get_scan_graph(
    scan_id: int = Path(gt=0),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    scan = get_owned_scan(db, scan_id, user.id)
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    edges = db.query(GraphEdge).filter(GraphEdge.scan_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return ExposureGraphBuilder(scan.target_domain).build_graph(assets, edges, findings)


@router.post("/voice/chat", response_model=AssistantChatResponse)
def assistant_chat(
    payload: AssistantChatRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    rate_limit_user(request, user, db, "assistant-chat")
    if (payload.current_state or "").upper() == "IDLE":
        ResponseComposer.reset_session()
    if not payload.scan_id:
        latest = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).first()
        if latest and (
            (payload.current_state or "").upper() in ("SCAN_FOLLOWUP", "SCAN-FOLLOWUP")
            or _is_scan_followup_case(payload)
        ):
            payload.scan_id = latest.id
    # Pass detected_language through to the LLM brain via threadlocal context.
    AssistantDialogueEngine.set_detected_language(payload.detected_language)
    AssistantDialogueEngine.set_conversation_history([
        item.model_dump() for item in payload.conversation_history
    ])
    try:
        result = AssistantDialogueEngine.process_message(
            user_text=payload.message,
            current_state=payload.current_state,
            current_domain=payload.current_domain,
            scan_id=payload.scan_id,
            db_session=db,
            user_id=user.id,
            allow_manual_attestation=settings.domain_auth_mode == "demo_attestation",
        )
    finally:
        AssistantDialogueEngine.set_detected_language(None)
        AssistantDialogueEngine.set_conversation_history(None)
    return AssistantChatResponse(**result)


_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
    "Connection": "keep-alive",
}


def _sse_data(payload: dict) -> str:
    """Format a single SSE data frame (no event type)."""
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _sse_event(event_name: str, payload: dict) -> str:
    """Format a typed SSE event frame."""
    return f"event: {event_name}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _is_scan_followup_case(payload: AssistantChatRequest) -> bool:
    """Replicates the scan-followup gate inside AssistantDialogueEngine.process_message
    so the SSE endpoint can take the streaming fast-path without invoking the
    (potentially expensive) LLM call hidden inside process_message -> answer_scan_question.
    """
    text = (payload.message or "").lower()
    is_scan_directive = any(text.startswith(p) for p in [
        "scan ", "please scan ", "check ", "assess ", "analyze ", "start scan", "run scan"
    ])
    is_question = any(q in text for q in [
        "how many", "show", "find", "found", "vulnerabilit",
        "ports", "assets", "risk", "score", "explain", "why", "detail", "summarize",
        "summary", "report", "hosts", "subdomains", "status", "scan is over", "is the scan"
    ])
    st = (payload.current_state or "").upper()
    return bool(
        (st in ("SCAN_FOLLOWUP", "SCAN-FOLLOWUP") or is_question)
        and not is_scan_directive
    )


def _conversation_messages(payload: AssistantChatRequest) -> list[dict]:
    """Convert the bounded, user-visible history to Gemini conversation turns."""
    return [
        {
            "role": "model" if item.role == "assistant" else "user",
            "parts": [{"text": item.content}],
        }
        for item in payload.conversation_history
        if item.content.strip()
    ]


@router.post("/voice/chat/stream")
async def assistant_chat_stream(
    payload: AssistantChatRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Server-Sent Events streaming variant of /api/voice/chat.

    Event protocol:
      data: {"type":"token","text":"..."}    - one LLM text delta
      event: done  data: {FSM transition payload}  - final state at end of stream
      event: error data: {"fallback": true, ...}   - client should fall back to /api/voice/chat
    """
    rate_limit_user(request, user, db, "assistant-chat")
    # Resolve the current user's latest scan for follow-up questions even if the UI has no selection.
    if (payload.current_state or "").upper() == "IDLE":
        ResponseComposer.reset_session()
    if not payload.scan_id:
        latest = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).first()
        if latest and (
            (payload.current_state or "").upper() in ("SCAN_FOLLOWUP", "SCAN-FOLLOWUP")
            or _is_scan_followup_case(payload)
        ):
            payload.scan_id = latest.id

    async def event_stream():
        try:
            # ---------- Path A: scan follow-up (LLM streaming) ----------
            if _is_scan_followup_case(payload) and llm_mod is not None and llm_mod.is_configured():
                scan = db.query(Scan).filter(
                    Scan.id == payload.scan_id, Scan.user_id == user.id
                ).first()
                if not scan:
                    # Scan missing - fall back to the deterministic process_message
                    # which will yield the canonical "couldn't identify" reply.
                    result = await asyncio.to_thread(
                        AssistantDialogueEngine.process_message,
                        payload.message,
                        payload.current_state,
                        payload.current_domain,
                        payload.scan_id,
                        db,
                        user.id,
                        settings.domain_auth_mode == "demo_attestation",
                    )
                    yield _sse_data({"type": "token", "text": result.get("assistant_reply", "")})
                    result.pop("assistant_reply", None)
                    yield _sse_event("done", result)
                    return

                scan_status = getattr(scan, "status", None)
                # Non-answerable scan states -> deterministic single-token reply.
                if scan_status in ("PENDING", "RUNNING", "FAILED") or llm_mod is None or not llm_mod.is_configured():
                    findings = db.query(Finding).filter(
                        Finding.scan_id == scan.id
                    ).order_by(Finding.score.desc()).all()
                    assets = db.query(Asset).filter(Asset.scan_id == scan.id).all()
                    reply = AssistantDialogueEngine._answer_scan_question_deterministic(
                        payload.message, scan, findings, assets
                    )
                    yield _sse_data({"type": "token", "text": reply})
                    yield _sse_event("done", {
                        "next_state": "SCAN_FOLLOWUP",
                        "domain": scan.target_domain,
                        "authorized": True,
                        "can_launch": False,
                        "authorization_token": None,
                    })
                    return

                # Stream the natural-language answer token-by-token.
                context_prefix = (
                    f"Context: scan_id={scan.id} target_domain={scan.target_domain} "
                    f"status={scan_status}.\nUser question: {payload.message}"
                )
                messages = _conversation_messages(payload)
                messages.append({"role": "user", "parts": [{"text": context_prefix}]})
                collected: list[str] = []
                allowed_finding_ids: set[int] = set()

                for _ in range(4):
                    tool_calls: list[Any] = []
                    async for kind, value in llm_mod.stream(
                        messages, detected_language=payload.detected_language
                    ):
                        if kind == "text":
                            collected.append(value)
                            yield _sse_data({"type": "token", "text": value})
                        elif kind == "tool":
                            tool_calls.append(value)

                    if not tool_calls:
                        break

                    # Append the model's tool-call turn to history.
                    messages.append({
                        "role": "model",
                        "parts": [
                            {"function_call": {
                                "name": fc.name,
                                "args": dict(getattr(fc, "args", {}) or {}),
                            }}
                            for fc in tool_calls
                        ],
                    })

                    # Dispatch each tool call and feed FunctionResponse back.
                    response_parts: list[dict] = []
                    for fc in tool_calls:
                        args = dict(getattr(fc, "args", {}) or {})
                        result = await llm_mod.dispatch_tool(fc.name, args, db, scan.id)
                        if fc.name in ("list_findings", "get_scan_summary"):
                            for f in (result.get("findings") or []):
                                fid = f.get("id")
                                if fid is not None:
                                    allowed_finding_ids.add(int(fid))
                        elif fc.name == "get_finding_detail":
                            fid = result.get("id")
                            if fid is not None:
                                allowed_finding_ids.add(int(fid))
                        response_parts.append({
                            "function_response": {"name": fc.name, "response": result}
                        })
                    messages.append({"role": "user", "parts": response_parts})

                full_reply = "".join(collected).strip()
                # Replace a rejected or empty model answer with a useful evidence-based reply.
                if not full_reply or not llm_mod.validate_finding_ids(full_reply, allowed_finding_ids):
                    findings = db.query(Finding).filter(
                        Finding.scan_id == scan.id
                    ).order_by(Finding.score.desc()).all()
                    assets = db.query(Asset).filter(Asset.scan_id == scan.id).all()
                    fallback = AssistantDialogueEngine._answer_scan_question_deterministic(
                        payload.message, scan, findings, assets
                    )
                    yield _sse_data({
                        "type": "token",
                        "text": fallback,
                        "fallback": True,
                        "replace": True,
                    })

                yield _sse_event("done", {
                    "next_state": "SCAN_FOLLOWUP",
                    "domain": scan.target_domain,
                    "authorized": True,
                    "can_launch": False,
                    "authorization_token": None,
                })
                return

            # ---------- Path B: General Conversation with Gemini (if not scanning directive) ----------
            # If Gemini is configured, use it for conversational answers instead of canned static strings
            if llm_mod is not None and llm_mod.is_configured() and not _is_scan_followup_case(payload):
                text_lower = (payload.message or "").lower().strip()
                is_scan_directive = any(text_lower.startswith(p) for p in [
                    "scan ", "please scan ", "check ", "assess ", "analyze ", "start scan", "run scan"
                ])
                # If it's a domain confirmation or affirmative/negative during auth flow, let FSM handle state transition
                is_auth_confirm = (
                    (payload.current_state or "").upper() in ("CONFIRM_DOMAIN", "AWAITING_AUTH")
                    and (AssistantDialogueEngine.is_affirmative(payload.message) or AssistantDialogueEngine.is_negative(payload.message))
                )

                if not is_scan_directive and not is_auth_confirm:
                    # Let Gemini handle natural conversation!
                    latest_scan = None
                    if payload.scan_id:
                        latest_scan = db.query(Scan).filter(Scan.id == payload.scan_id, Scan.user_id == user.id).first()
                    if not latest_scan:
                        latest_scan = db.query(Scan).filter(Scan.user_id == user.id).order_by(Scan.id.desc()).first()

                    scan_ctx = ""
                    if latest_scan:
                        scan_ctx = f"Active/latest scan: id={latest_scan.id}, target_domain={latest_scan.target_domain}, status={latest_scan.status}. "
                    
                    system_guidance = (
                        f"{scan_ctx}Current conversation state: {payload.current_state}. "
                        f"User says: {payload.message}\n"
                        "Respond to the latest message in the conversation naturally and directly. "
                        "If the user asks about scan data, use the evidence tools rather than guessing. "
                        "If the user wants to scan a target domain, ask them to confirm the domain; "
                        "the host application handles authorization."
                    )
                    
                    messages = _conversation_messages(payload)
                    messages.append({"role": "user", "parts": [{"text": system_guidance}]})
                    collected: list[str] = []
                    async for kind, value in llm_mod.stream(messages, detected_language=payload.detected_language):
                        if kind == "text":
                            collected.append(value)
                            yield _sse_data({"type": "token", "text": value})

                    full_reply = "".join(collected).strip()
                    if full_reply:
                        yield _sse_event("done", {
                            "next_state": payload.current_state or "IDLE",
                            "domain": payload.current_domain,
                            "authorized": False,
                            "can_launch": False,
                            "authorization_token": None,
                        })
                        return

            # ---------- Path C: deterministic FSM fallback (auth flow / commands) ----------
            result = await asyncio.to_thread(
                AssistantDialogueEngine.process_message,
                payload.message,
                payload.current_state,
                payload.current_domain,
                payload.scan_id,
                db,
                user.id,
                settings.domain_auth_mode == "demo_attestation",
            )
            reply_text = result.pop("assistant_reply", "")
            if reply_text:
                yield _sse_data({"type": "token", "text": reply_text})
            yield _sse_event("done", result)
        except Exception as exc:  # noqa: BLE001 - any failure tells the client to fall back
            yield _sse_event("error", {"fallback": True, "error": str(exc)})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers=_SSE_HEADERS,
    )


@router.post("/voice/transcribe", response_model=VoiceTranscribeResponse)
async def transcribe_voice(
    request: Request,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    rate_limit_user(request, user, db, "voice-transcription", limit=30)
    stt_service = GnaniSTTService()
    if not stt_service.is_configured():
        return VoiceTranscribeResponse(success=False, transcript="", error="Gnani Prisma is not configured.")
    try:
        chunks = bytearray()
        while True:
            chunk = await file.read(min(64 * 1024, MAX_AUDIO_SIZE_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > MAX_AUDIO_SIZE_BYTES:
                raise HTTPException(status_code=413, detail="Audio upload exceeds the 10 MB limit.")
        if not chunks:
            raise HTTPException(status_code=400, detail="Audio upload is empty.")
        mime_type, _ = detect_audio_format(bytes(chunks), file.filename or "recording")
        if mime_type not in {"audio/wav", "audio/webm", "audio/ogg", "audio/flac", "audio/mpeg", "audio/mp4"}:
            raise HTTPException(status_code=415, detail="This audio format is not supported.")
        return VoiceTranscribeResponse(**await asyncio.to_thread(
            stt_service.transcribe_audio,
            bytes(chunks),
            file.filename or "recording.wav",
        ))
    except HTTPException:
        raise
    except Exception:
        return VoiceTranscribeResponse(
            success=False,
            transcript="",
            error="Transcription could not be completed. Check backend configuration and logs.",
        )
    finally:
        await file.close()


@router.post("/voice/tts")
def synthesize_speech(
    payload: TTSRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    rate_limit_user(request, user, db, "voice-synthesis", limit=30)
    tts_service = GnaniTTSService()
    if not tts_service.is_configured():
        raise HTTPException(status_code=503, detail="Gnani Timbre is not configured.")
    result = tts_service.synthesize_speech(text=payload.text, voice=payload.voice, speed=payload.speed or 1.0)
    if not result.get("success"):
        raise HTTPException(status_code=result.get("status_code", 502), detail=result.get("error", "TTS request failed."))
    return Response(content=result["audio_bytes"], media_type=result.get("content_type", "audio/wav"))


@router.post("/voice/tts/stream")
async def synthesize_speech_stream(
    payload: TTSRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(require_user),
):
    """Chunked TTS endpoint: streams WAV audio chunks as they are synthesized.

    Splits the input text into sentences, synthesizes up to 3 chunks in
    parallel via ``GnaniTTSService.stream_tts``, and yields each WAV chunk
    sequentially. Reduces time-to-first-audio versus the monolithic
    /api/voice/tts endpoint.
    """
    rate_limit_user(request, user, db, "voice-synthesis", limit=30)
    tts_service = GnaniTTSService()
    if not tts_service.is_configured():
        raise HTTPException(status_code=503, detail="Gnani Timbre is not configured.")

    async def audio_stream():
        async for wav_chunk in tts_service.stream_tts(
            text=payload.text,
            voice=payload.voice,
            speed=payload.speed or 1.0,
        ):
            if wav_chunk:
                yield wav_chunk

    return StreamingResponse(
        audio_stream(),
        media_type="audio/wav",
        headers={
            "Cache-Control": "no-store",
            "X-Accel-Buffering": "no",
        },
    )
