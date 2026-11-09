import re
import time
import secrets
import threading
from typing import Dict, Any, Optional, List
from backend.core.security import normalize_domain, SecurityValidationError


class ConversationState:
    IDLE = "IDLE"
    CONFIRM_DOMAIN = "CONFIRM_DOMAIN"
    AWAITING_AUTH = "AWAITING_AUTH"
    AUTHORIZED = "AUTHORIZED"
    SCAN_FOLLOWUP = "SCAN_FOLLOWUP"


AFFIRMATIVE_RESPONSES = {
    "yes", "yeah", "yep", "correct", "right", "sure", "affirmative", "that is correct",
    "yes that is correct", "yes it is", "true", "proceed", "okay", "ok", "scan", "start", "go ahead"
}

NEGATIVE_RESPONSES = {
    "no", "nope", "wrong", "incorrect", "not correct", "cancel", "stop", "abort"
}

AUTH_KEYWORDS = [
    "i confirm that i own this domain or have authorization to scan it",
    "i confirm that i own this domain or have authorization to assess it",
    "i confirm that i own this domain",
    "i have authorization to scan it",
    "i have authorization to assess it",
    "i confirm authorization",
    "i own this domain and authorize",
    "i authorize this assessment",
    "i confirm ownership or authorization",
    "i confirm i own this domain",
    "i have permission to scan",
    "i have permission to assess",
    "i authorize this scan"
]


class AuthorizationTokenManager:
    """
    Server-side token manager for domain-bound, time-limited, one-time authorization attestations.
    """
    _tokens: Dict[str, Dict[str, Any]] = {}
    _lock = threading.Lock()
    DEFAULT_TTL_SECONDS: float = 300.0  # 5 minutes validity

    @classmethod
    def issue_token(
        cls,
        domain: str,
        attestation_method: str = "assistant_voice",
        db_session: Optional[Any] = None,
        user_id: Optional[int] = None,
    ) -> str:
        clean_domain = normalize_domain(domain)
        token = secrets.token_urlsafe(32)
        if db_session is not None and user_id is not None:
            from datetime import datetime, timedelta, timezone
            from backend.core.auth import digest_token
            from backend.database.models import ScanAuthorization

            created_at = datetime.now(timezone.utc).replace(tzinfo=None)
            db_session.query(ScanAuthorization).filter(
                (ScanAuthorization.expires_at <= created_at)
                | (ScanAuthorization.consumed_at < created_at - timedelta(days=1))
            ).delete(synchronize_session=False)
            db_session.add(ScanAuthorization(
                token_hash=digest_token(token),
                user_id=user_id,
                domain=clean_domain,
                attestation_method=attestation_method,
                created_at=created_at,
                expires_at=created_at + timedelta(seconds=cls.DEFAULT_TTL_SECONDS),
            ))
            db_session.commit()
            return token

        with cls._lock:
            cls._tokens[token] = {
                "domain": clean_domain,
                "attestation_method": attestation_method,
                "created_at": time.time(),
                "expires_at": time.time() + cls.DEFAULT_TTL_SECONDS,
                "used": False
            }
            cls._cleanup_expired()
        return token

    @classmethod
    def verify_and_consume(
        cls,
        token: str,
        domain: str,
        db_session: Optional[Any] = None,
        user_id: Optional[int] = None,
    ) -> bool:
        if not token:
            return False

        if db_session is not None and user_id is not None:
            from datetime import datetime, timezone
            from backend.core.auth import digest_token
            from backend.database.models import ScanAuthorization

            clean_domain = normalize_domain(domain)
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            updated = db_session.query(ScanAuthorization).filter(
                ScanAuthorization.token_hash == digest_token(token),
                ScanAuthorization.user_id == user_id,
                ScanAuthorization.domain == clean_domain,
                ScanAuthorization.expires_at > now,
                ScanAuthorization.consumed_at.is_(None),
            ).update({ScanAuthorization.consumed_at: now}, synchronize_session=False)
            if updated != 1:
                db_session.rollback()
                return False
            db_session.commit()
            return True

        with cls._lock:
            if token not in cls._tokens:
                return False

            data = cls._tokens[token]
            if data.get("used"):
                return False

            if time.time() > data.get("expires_at", 0):
                del cls._tokens[token]
                return False

            clean_domain = normalize_domain(domain)
            if data.get("domain") != clean_domain:
                return False

            data["used"] = True
            return True

    @classmethod
    def _cleanup_expired(cls):
        now = time.time()
        expired_keys = [k for k, v in cls._tokens.items() if now > v.get("expires_at", 0)]
        for k in expired_keys:
            del cls._tokens[k]


class AssistantDialogueEngine:
    """
    Manages conversational turn-taking, domain extraction, confirmation,
    explicit authorization checking, and intelligent follow-up query answering.
    """

    # Per-request context (threadlocal) so the sync /api/voice/chat endpoint
    # can pass the user's detected_language through process_message into
    # answer_scan_question without changing any method signature.
    _ctx = threading.local()

    @classmethod
    def set_detected_language(cls, lang: Optional[str]) -> None:
        cls._ctx.detected_language = lang

    @classmethod
    def get_detected_language(cls) -> Optional[str]:
        return getattr(cls._ctx, "detected_language", None)

    @classmethod
    def set_conversation_history(cls, history: Optional[List[Dict[str, str]]]) -> None:
        cls._ctx.conversation_history = history or []

    @classmethod
    def get_conversation_history(cls) -> List[Dict[str, str]]:
        return getattr(cls._ctx, "conversation_history", [])

    @staticmethod
    def is_affirmative(text: str) -> bool:
        cleaned = text.strip().lower().rstrip(".!?")
        if cleaned in AFFIRMATIVE_RESPONSES:
            return True
        return any(cleaned.startswith(f"{aff} ") or cleaned.endswith(f" {aff}") for aff in ["yes", "yeah", "yep", "correct"])

    @staticmethod
    def is_negative(text: str) -> bool:
        cleaned = text.strip().lower().rstrip(".!?")
        if cleaned in NEGATIVE_RESPONSES:
            return True
        return any(cleaned.startswith(f"{neg} ") for neg in ["no", "nope", "cancel", "stop"])

    @staticmethod
    def is_explicit_authorization(text: str) -> bool:
        cleaned = text.strip().lower().rstrip(".!?")
        if cleaned in {"yes", "yeah", "yep", "ok", "okay", "sure", "correct", "proceed"}:
            return False

        # Speech recognition can preserve negation inside longer statements. A
        # negative or ambiguous attestation must never mint a scan token.
        if re.search(r"\b(not|never|without|don't|do not|cannot|can't|won't|no longer)\b", cleaned):
            return False

        for phrase in AUTH_KEYWORDS:
            if phrase in cleaned:
                return True

        return bool(re.search(
            r"\bi (?:confirm|affirm) (?:that )?i (?:own|am the owner of) (?:this )?domain\b",
            cleaned,
        ))

    @classmethod
    def answer_scan_question(cls, text: str, scan: Any, findings: List[Any], assets: List[Any]) -> str:
        """
        Synthesizes concise, evidence-based spoken answers about actual scan findings,
        risk posture, and remediation without fabricating evidence.

        Primary path: stream through the Gemini LLM brain (backend.gnani.llm) with
        tool calls dispatched against the database. Falls back to the deterministic
        :class:`ResponseComposer` for any non-answerable scan state, when the LLM is
        not configured, on hallucination guardrail trips, or on any exception
        (including being called from inside a running event loop - the SSE streaming
        endpoint drives ``llm.stream()`` directly and does not need this code path).
        """
        scan_status = getattr(scan, "status", None)

        # Non-answerable states always go through the deterministic composer so the
        # user gets a sensible "scan still running / failed" message instantly.
        if scan_status in ("PENDING", "RUNNING", "FAILED"):
            return cls._answer_scan_question_deterministic(text, scan, findings, assets)

        try:
            from backend.gnani import llm as llm_mod
        except Exception:
            return cls._answer_scan_question_deterministic(text, scan, findings, assets)

        if not llm_mod.is_configured():
            return cls._answer_scan_question_deterministic(text, scan, findings, assets)

        scan_id = getattr(scan, "id", None)
        detected_language = cls.get_detected_language()

        try:
            import asyncio
            reply_text, valid = asyncio.run(
                cls._llm_answer(
                    text,
                    scan_id,
                    detected_language,
                    findings,
                    cls.get_conversation_history(),
                )
            )
            if not reply_text or not valid:
                return cls._answer_scan_question_deterministic(text, scan, findings, assets)
            return reply_text
        except Exception:
            # Includes RuntimeError("asyncio.run() cannot be called from a running
            # event loop") when the SSE endpoint drives process_message from inside
            # an async handler - that path uses llm.stream() directly.
            return cls._answer_scan_question_deterministic(text, scan, findings, assets)

    @classmethod
    async def _llm_answer(
        cls,
        text: str,
        scan_id: Optional[int],
        detected_language: Optional[str],
        findings: List[Any],
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ):
        """Runs a multi-round LLM conversation with tool dispatch.

        Returns (reply_text, is_valid) where ``is_valid`` is the result of the
        finding-id hallucination guardrail.
        """
        from backend.gnani import llm as llm_mod
        from backend.database.models import SessionLocal

        context_prefix = (
            f"Context: scan_id={scan_id} target_domain=unknown status=COMPLETED.\n"
            f"User question: {text}"
        )
        # Try to read target_domain from any scan-like object passed in indirectly.
        messages = [
            {
                "role": "model" if item["role"] == "assistant" else "user",
                "parts": [{"text": item["content"]}],
            }
            for item in (conversation_history or [])
            if item.get("content", "").strip()
        ]
        messages.append({"role": "user", "parts": [{"text": context_prefix}]})

        collected_text: list[str] = []
        allowed_finding_ids: set[int] = set(getattr(f, "id", None) for f in (findings or []))
        allowed_finding_ids.discard(None)

        db = SessionLocal()
        try:
            for _ in range(4):
                tool_calls_in_round: list[Any] = []
                async for kind, value in llm_mod.stream(messages, detected_language=detected_language):
                    if kind == "text":
                        collected_text.append(value)
                    elif kind == "tool":
                        tool_calls_in_round.append(value)

                if not tool_calls_in_round:
                    break

                # Append the model's tool-call turn to the conversation history.
                messages.append({
                    "role": "model",
                    "parts": [
                        {"function_call": {"name": fc.name, "args": dict(getattr(fc, "args", {}) or {})}}
                        for fc in tool_calls_in_round
                    ],
                })

                # Dispatch each tool call and collect FunctionResponse parts.
                response_parts: list[dict] = []
                for fc in tool_calls_in_round:
                    args = dict(getattr(fc, "args", {}) or {})
                    result = await llm_mod.dispatch_tool(fc.name, args, db, scan_id)
                    # Track finding IDs the tools actually returned so the
                    # guardrail can flag any IDs the model invents in its prose.
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
                        "function_response": {
                            "name": fc.name,
                            "response": result,
                        }
                    })
                messages.append({"role": "user", "parts": response_parts})
        finally:
            db.close()

        reply_text = "".join(collected_text).strip()
        if not reply_text:
            return "", False
        is_valid = llm_mod.validate_finding_ids(reply_text, allowed_finding_ids)
        return reply_text, is_valid

    @classmethod
    def _answer_scan_question_deterministic(cls, text: str, scan: Any, findings: List[Any], assets: List[Any]) -> str:
        """
        Original keyword-routed composer path. Retained as the deterministic
        fallback for the LLM brain, for non-answerable scan states, and for
        environments where GEMINI_API_KEY is not configured.
        Uses ResponseComposer for natural phrasing variation and caveat deduplication.
        """
        from backend.gnani.composer import ResponseComposer

        q = text.lower()
        domain = getattr(scan, "target_domain", "target domain")
        scan_status = getattr(scan, "status", None)
        is_partial = scan_status == "PARTIAL"
        ask_coverage = "coverage" in q or "partial" in q or "complete" in q or "limitation" in q

        if scan_status in ("PENDING", "RUNNING"):
            return f"Assessment for {domain} is still {scan_status.lower()}. Its results are not ready yet."
        if scan_status == "FAILED":
            return f"Assessment for {domain} failed. {getattr(scan, 'error_message', None) or 'No complete result is available.'}"

        if "critical" in q:
            critical = [finding for finding in findings if finding.severity == "CRITICAL"]
            return ResponseComposer.compose_critical_findings(domain, critical, is_partial=is_partial, ask_coverage=ask_coverage)

        # Follow-up: Remediation / Fixes
        if "fix" in q or "remediat" in q or "how to" in q or "resolve" in q:
            top = findings[0] if findings else None
            return ResponseComposer.compose_remediation(domain, top, is_partial=is_partial, ask_coverage=ask_coverage)

        if "explain" in q or "why" in q:
            matched = next(
                (finding for finding in findings if finding.title.lower() in q or finding.affected_asset.lower() in q),
                findings[0] if findings else None,
            )
            if matched:
                explanation_core = (
                    f"'{matched.title}' is rated {matched.severity} on {matched.affected_asset}. "
                    f"Observed: {matched.evidence} {matched.explanation} "
                    f"Remediation: {matched.remediation}"
                )
                if is_partial and ask_coverage:
                    return f"Note: this is a partial assessment based only on confirmed records. {explanation_core}"
                return explanation_core
            return f"I do not have a matching finding in this scan to explain. Ask about one of the recorded finding titles."

        # Follow-up: Risk score
        if "risk" in q or "score" in q or "posture" in q:
            risk_score = getattr(scan, "risk_score", 0.0)
            return ResponseComposer.compose_risk_score(domain, risk_score, len(findings), len(assets), is_partial=is_partial, ask_coverage=ask_coverage)

        # Follow-up: Findings / Issues summary
        if "finding" in q or "issue" in q or "vulnerabilit" in q or "problem" in q or "summary" in q:
            if any(term in q for term in ("show", "list", "which", "what are", "tell me the")):
                return ResponseComposer.compose_findings_list(domain, findings, is_partial=is_partial)
            crit = len([f for f in findings if f.severity == "CRITICAL"])
            high = len([f for f in findings if f.severity == "HIGH"])
            med = len([f for f in findings if f.severity == "MEDIUM"])
            low = len([f for f in findings if f.severity == "LOW"])
            top_finding = findings[0] if findings else None
            top_title = top_finding.title if top_finding else None
            top_asset = top_finding.affected_asset if top_finding else None
            return ResponseComposer.compose_findings_summary(
                domain, len(findings), crit, high, med, low, top_title, top_asset, is_partial=is_partial, ask_coverage=ask_coverage
            )

        # Follow-up: Assets / Subdomains
        if "asset" in q or "subdomain" in q or "host" in q or "ip" in q:
            subdomains = [a.identifier for a in assets if a.asset_type == "SUBDOMAIN"]
            root_domains = [a.identifier for a in assets if a.asset_type == "DOMAIN"]
            is_sub = "subdomain" in q
            return ResponseComposer.compose_assets_summary(
                domain, len(assets), root_domains, subdomains, is_subdomain_query=is_sub, is_partial=is_partial, ask_coverage=ask_coverage
            )

        # Generic default summary for scan
        risk_score = getattr(scan, "risk_score", 0.0)
        return ResponseComposer.compose_risk_score(domain, risk_score, len(findings), len(assets), is_partial=is_partial, ask_coverage=ask_coverage)

    @classmethod
    def process_message(
        cls,
        user_text: str,
        current_state: str,
        current_domain: Optional[str] = None,
        scan_id: Optional[int] = None,
        db_session: Optional[Any] = None,
        user_id: Optional[int] = None,
        allow_manual_attestation: bool = True,
    ) -> Dict[str, Any]:
        """
        Processes a single conversational user input given the current state.
        Returns next_state, assistant_reply, candidate_domain, is_authorized flag,
        and an issued authorization token upon explicit confirmation.
        """
        text = user_text.strip()
        from backend.gnani.stt import GnaniSTTService
        extracted = GnaniSTTService.extract_domain_from_command(text)

        st = (current_state or "").upper().replace("-", "_")
        if st in ("AWAITING_TOPIC", "TOPIC", "INITIAL", ""):
            st = ConversationState.IDLE
        current_state = st

        if current_state in (ConversationState.CONFIRM_DOMAIN, ConversationState.AWAITING_AUTH):
            try:
                current_domain = normalize_domain(current_domain or "")
            except SecurityValidationError:
                current_domain = None
                current_state = ConversationState.IDLE

        # Determine if the user's intent is actually to start/request a scan of a new domain,
        # or if they are asking an analytical question about findings/assets/vulnerabilities.
        is_question = any(q in text.lower() for q in [
            "tell me", "what", "how many", "show", "findings", "found", "vulnerabilit", 
            "ports", "assets", "risk", "score", "explain", "why", "detail", "summarize",
            "summary", "report", "hosts", "subdomains", "status", "scan is over", "is the scan"
        ])
        is_scan_directive = any(text.lower().startswith(p) for p in [
            "scan ", "please scan ", "check ", "assess ", "analyze ", "start scan", "run scan"
        ]) or (extracted and len(text.strip().split()) <= 2)

        # If user is asking a question about a scan, do NOT treat it as a new target request
        target_scan = None
        if db_session:
            from backend.database.models import Scan, Finding, Asset
            # Try to find a scan matching the mentioned domain or scan_id or latest scan
            if extracted and is_question:
                scan_query = db_session.query(Scan).filter(Scan.target_domain.ilike(f"%{extracted}%"))
                if user_id is not None:
                    scan_query = scan_query.filter(Scan.user_id == user_id)
                target_scan = scan_query.order_by(Scan.id.desc()).first()
            if not target_scan and scan_id:
                scan_query = db_session.query(Scan).filter(Scan.id == scan_id)
                if user_id is not None:
                    scan_query = scan_query.filter(Scan.user_id == user_id)
                target_scan = scan_query.first()
            if not target_scan and is_question:
                scan_query = db_session.query(Scan)
                if user_id is not None:
                    scan_query = scan_query.filter(Scan.user_id == user_id)
                target_scan = scan_query.order_by(Scan.id.desc()).first()

        if target_scan and (is_question or current_state == ConversationState.SCAN_FOLLOWUP) and not is_scan_directive:
            findings = db_session.query(Finding).filter(Finding.scan_id == target_scan.id).order_by(Finding.score.desc()).all()
            assets = db_session.query(Asset).filter(Asset.scan_id == target_scan.id).all()
            answer = cls.answer_scan_question(text, target_scan, findings, assets)
            return {
                "next_state": ConversationState.SCAN_FOLLOWUP,
                "assistant_reply": answer,
                "domain": target_scan.target_domain,
                "authorized": True,
                "can_launch": False,
                "authorization_token": None
            }

        # 1. State: IDLE / Starting Scan
        if current_state == ConversationState.IDLE or not current_state or current_state == ConversationState.SCAN_FOLLOWUP:
            if extracted and not is_question:
                try:
                    valid_dom = normalize_domain(extracted)
                    return {
                        "next_state": ConversationState.CONFIRM_DOMAIN,
                        "assistant_reply": f"I understood {valid_dom} as the target. Is that correct?",
                        "domain": valid_dom,
                        "authorized": False,
                        "can_launch": False,
                        "authorization_token": None
                    }
                except SecurityValidationError as e:
                    return {
                        "next_state": ConversationState.IDLE,
                        "assistant_reply": f"The domain '{extracted}' is invalid: {str(e)}. Please provide a valid domain name.",
                        "domain": None,
                        "authorized": False,
                        "can_launch": False,
                        "authorization_token": None
                    }
            else:
                msg_lower = text.lower()
                normalized_message = re.sub(r"[^\w\s]", "", msg_lower).strip()
                greetings = {
                    "who are you", "what can you do", "help", "how are you", "what are you",
                }
                if (
                    normalized_message in greetings
                    or re.match(r"^(?:hello|hi|hey)\b", normalized_message)
                ):
                    return {
                        "next_state": ConversationState.IDLE,
                        "assistant_reply": (
                            "Hi! I can help review scan findings, explain a risk, or guide you through an authorized assessment. "
                            "What would you like to look at?"
                        ),
                        "domain": None,
                        "authorized": False,
                        "can_launch": False,
                        "authorization_token": None
                    }
                return {
                    "next_state": ConversationState.IDLE,
                    "assistant_reply": (
                        "I can help with a scan or review its findings, assets, and risk score. "
                        "What would you like to check?"
                    ),
                    "domain": None,
                    "authorized": False,
                    "can_launch": False,
                    "authorization_token": None
                }

        # 2. State: CONFIRM_DOMAIN
        if current_state == ConversationState.CONFIRM_DOMAIN:
            if cls.is_affirmative(text):
                if allow_manual_attestation and current_domain:
                    token = AuthorizationTokenManager.issue_token(
                        current_domain,
                        attestation_method="demo_attestation",
                        db_session=db_session,
                        user_id=user_id,
                    )
                    return {
                        "next_state": ConversationState.AUTHORIZED,
                        "assistant_reply": f"Target confirmed for {current_domain}. Demo authorization recorded. I am launching the attack surface scan now.",
                        "domain": current_domain,
                        "authorized": True,
                        "can_launch": True,
                        "authorization_token": token
                    }
                return {
                    "next_state": ConversationState.AWAITING_AUTH,
                    "assistant_reply": f"Target confirmed: {current_domain}. Before proceeding, please explicitly confirm that you own this domain or have formal authorization to assess it.",
                    "domain": current_domain,
                    "authorized": False,
                    "can_launch": False,
                    "authorization_token": None
                }
            elif cls.is_negative(text):
                return {
                    "next_state": ConversationState.IDLE,
                    "assistant_reply": "Understood. Let's restart. Which target domain should we assess?",
                    "domain": None,
                    "authorized": False,
                    "can_launch": False,
                    "authorization_token": None
                }
            elif extracted and is_scan_directive:
                try:
                    valid_dom = normalize_domain(extracted)
                    return {
                        "next_state": ConversationState.CONFIRM_DOMAIN,
                        "assistant_reply": f"Understood, switching the assessment target to {valid_dom}. Is that correct?",
                        "domain": valid_dom,
                        "authorized": False,
                        "can_launch": False,
                        "authorization_token": None
                    }
                except SecurityValidationError:
                    return {
                        "next_state": ConversationState.CONFIRM_DOMAIN,
                        "assistant_reply": f"Please confirm if {current_domain} is correct, or speak a valid domain name.",
                        "domain": current_domain,
                        "authorized": False,
                        "can_launch": False,
                        "authorization_token": None
                    }
            elif is_question and target_scan:
                findings = db_session.query(Finding).filter(Finding.scan_id == target_scan.id).order_by(Finding.score.desc()).all()
                assets = db_session.query(Asset).filter(Asset.scan_id == target_scan.id).all()
                answer = cls.answer_scan_question(text, target_scan, findings, assets)
                return {
                    "next_state": ConversationState.SCAN_FOLLOWUP,
                    "assistant_reply": answer,
                    "domain": target_scan.target_domain,
                    "authorized": True,
                    "can_launch": False,
                    "authorization_token": None
                }
            else:
                return {
                    "next_state": ConversationState.CONFIRM_DOMAIN,
                    "assistant_reply": f"Please confirm with 'Yes' if {current_domain} is the correct target domain, or let me know a different domain.",
                    "domain": current_domain,
                    "authorized": False,
                    "can_launch": False,
                    "authorization_token": None
                }

        # 3. State: AWAITING_AUTH
        if current_state == ConversationState.AWAITING_AUTH:
            if cls.is_negative(text):
                return {
                    "next_state": ConversationState.IDLE,
                    "assistant_reply": "Assessment cancelled. Authorization was declined.",
                    "domain": None,
                    "authorized": False,
                    "can_launch": False,
                    "authorization_token": None
                }
            if cls.is_explicit_authorization(text):
                if not allow_manual_attestation:
                    return {
                        "next_state": ConversationState.AWAITING_AUTH,
                        "assistant_reply": (
                            f"I recorded your authorization statement for {current_domain}. Public assessments also require "
                            "DNS TXT domain-control verification. Open Overview and complete the verification step before scanning."
                        ),
                        "domain": current_domain,
                        "authorized": False,
                        "can_launch": False,
                        "authorization_token": None,
                    }
                token = AuthorizationTokenManager.issue_token(
                    current_domain,
                    attestation_method="demo_attestation",
                    db_session=db_session,
                    user_id=user_id,
                )
                return {
                    "next_state": ConversationState.AUTHORIZED,
                    "assistant_reply": f"Demo attestation recorded for {current_domain}. I am launching the external attack surface discovery now and will map all public hostnames, IP addresses, and web services.",
                    "domain": current_domain,
                    "authorized": True,
                    "can_launch": True,
                    "authorization_token": token
                }
            else:
                return {
                    "next_state": ConversationState.AWAITING_AUTH,
                    "assistant_reply": "A simple confirmation is not sufficient. Please explicitly state: 'I confirm that I own this domain or have authorization to scan it' before we can begin.",
                    "domain": current_domain,
                    "authorized": False,
                    "can_launch": False,
                    "authorization_token": None
                }

        # Default fallback
        return {
            "next_state": ConversationState.IDLE,
            "assistant_reply": "How can I help with your security assessment?",
            "domain": None,
            "authorized": False,
            "can_launch": False,
            "authorization_token": None
        }
