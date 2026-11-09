"""LLM brain for the ExposureGraph voice assistant.

Wires Gemini 2.x (via the google-genai SDK) as the natural-language reasoning
layer that sits on top of the deterministic FSM in :mod:`assistant`.

Public surface:
    * SYSTEM_PROMPT            - constant system instruction
    * TOOL_DECLARATIONS        - FunctionDeclaration list exposed to Gemini
    * stream()                 - async generator yielding ("text"|"tool", value)
    * dispatch_tool()          - executes a function call against the database
    * AssistantReply           - Pydantic model for normalized assistant replies
    * validate_finding_ids()   - hallucination guardrail for finding IDs
"""

from google import genai
from google.genai.types import GenerateContentConfig, Tool, FunctionDeclaration
from ..core.config import settings
from ..database.models import Scan, Finding, Asset
from sqlalchemy import select
from pydantic import BaseModel, field_validator
import asyncio, json, re


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = """You are AEGIS, the voice security assistant for ExposureGraph.

ROLE
- You answer follow-up questions about completed or in-progress attack surface scans.
- You also help users start new scans: first you confirm the target domain, then you require
  explicit authorization ("I confirm that I own this domain or have authorization to scan it").
  Do not invent or accept authorization on the user's behalf - the FSM in the host app handles that.
- You are concise, professional, and lead with the direct answer.
- Sound like a helpful analyst speaking to a person: use plain language, natural contractions
  where appropriate, and a brief conversational transition. Avoid canned openings, repeated
  summaries, filler, and unnecessary security jargon.
- Answer the user's latest question directly, using prior turns only to resolve references or
  continue the discussion. If a request is unclear, ask one short clarifying question instead
  of guessing or repeating the greeting.
- When asked to show or list findings, name the findings and include their severity and affected
  asset from tool results. Do not substitute only a total count for a requested list.

EVIDENCE RULE (HIGHEST PRIORITY - NEVER VIOLATE)
- Only describe findings, assets, severities, hostnames, ports, or evidence that came back from
  one of your tool calls. Never invent finding IDs, severities, hostnames, CVE numbers, or quotes.
- If the user asks about something no tool returned, say:
  "I don't have that in the current scan evidence."
- Do not speculate about remediation beyond what the finding.remediation field contains.
- Numbers (counts, scores) must come straight from the tool response - round only for speech.

LANGUAGE MIRRORING
- If the host provides a detected language, it uses the base language code (for example, hi
  from hi-IN). Reply in that language. If no language is provided, infer it from the latest
  user message and mirror that language; do not carry a previous turn's language into a new one.
- For Hindi use Devanagari; for other Indic languages use their native script.
- Keep domain names, finding titles, severity labels, and technical identifiers unchanged.
- Keep severity badges and Markdown tokens in ASCII even when the prose is in an Indic language.

OUTPUT FORMAT
- "spoken" reply: at most 1500 characters. Lead with the direct answer in the first sentence.
- You MAY also emit Markdown for the on-screen text bubble using: ## section, **bold**, `code`,
  - bullet lists, and | column | table | rows.
- Use severity badges inline: [CRITICAL] [HIGH] [MEDIUM] [LOW] [INFO].
- Do not narrate the Markdown syntax in the spoken text - read it as plain language.

TOOLS
- ALWAYS call a tool before answering if the user is asking about scan data (findings, assets,
  risk score, remediation, comparisons). Never answer from memory - the scan changes between turns.
- If the user is asking a generic question (what can you do, how does authorization work) you may
  answer directly without a tool call.
- Pass scan_id from the host context; do not guess it.
"""


# ---------------------------------------------------------------------------
# Tool declarations
# ---------------------------------------------------------------------------
get_scan_summary_decl = FunctionDeclaration(
    name="get_scan_summary",
    description=(
        "Retrieve the high-level summary of one scan: target domain, status, "
        "risk score (0-100), totals of assets and findings, and a per-severity "
        "finding count. Call this first when the user asks 'how did the scan go' "
        "or 'what is the risk'."
    ),
    parameters={
        "type": "object",
        "properties": {
            "scan_id": {
                "type": "integer",
                "description": "Numeric ID of the scan to summarize."
            }
        },
        "required": ["scan_id"]
    }
)

list_findings_decl = FunctionDeclaration(
    name="list_findings",
    description=(
        "List findings for a scan, optionally filtered by severity. Results are "
        "ordered by risk score descending. Use this for 'show me critical findings' "
        "or 'what issues were found'."
    ),
    parameters={
        "type": "object",
        "properties": {
            "scan_id": {
                "type": "integer",
                "description": "Numeric ID of the scan to query."
            },
            "severity": {
                "type": "string",
                "description": "Optional severity filter: CRITICAL, HIGH, MEDIUM, LOW, or INFO.",
                "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of findings to return (default 20)."
            }
        },
        "required": ["scan_id"]
    }
)

get_finding_detail_decl = FunctionDeclaration(
    name="get_finding_detail",
    description=(
        "Retrieve the full record for a single finding: title, affected asset, "
        "severity, score, confidence, observed evidence, explanation, and "
        "remediation guidance. Use this when the user asks 'explain finding #N' "
        "or 'how do I fix this issue'."
    ),
    parameters={
        "type": "object",
        "properties": {
            "scan_id": {
                "type": "integer",
                "description": "Numeric ID of the scan that owns the finding."
            },
            "finding_id": {
                "type": "integer",
                "description": "Numeric ID of the finding to retrieve."
            }
        },
        "required": ["scan_id", "finding_id"]
    }
)

list_assets_decl = FunctionDeclaration(
    name="list_assets",
    description=(
        "List discovered external assets for a scan, optionally filtered by "
        "asset_type (DOMAIN, SUBDOMAIN, IP_ADDRESS, WEB_ENDPOINT). Use this for "
        "'what hosts were found' or 'show me subdomains'."
    ),
    parameters={
        "type": "object",
        "properties": {
            "scan_id": {
                "type": "integer",
                "description": "Numeric ID of the scan to query."
            },
            "asset_type": {
                "type": "string",
                "description": "Optional asset type filter.",
                "enum": ["DOMAIN", "SUBDOMAIN", "IP_ADDRESS", "WEB_ENDPOINT"]
            },
            "limit": {
                "type": "integer",
                "description": "Maximum number of assets to return (default 50)."
            }
        },
        "required": ["scan_id"]
    }
)

compare_scans_decl = FunctionDeclaration(
    name="compare_scans",
    description=(
        "Compare the current scan against a baseline scan and report newly "
        "introduced findings, resolved findings, and the risk-score delta. Use "
        "this when the user asks 'what changed since the last scan'."
    ),
    parameters={
        "type": "object",
        "properties": {
            "scan_id": {
                "type": "integer",
                "description": "Numeric ID of the current scan."
            },
            "baseline_scan_id": {
                "type": "integer",
                "description": "Numeric ID of the baseline (earlier) scan to compare against."
            }
        },
        "required": ["scan_id", "baseline_scan_id"]
    }
)

TOOL_DECLARATIONS: list[FunctionDeclaration] = [
    get_scan_summary_decl,
    list_findings_decl,
    get_finding_detail_decl,
    list_assets_decl,
    compare_scans_decl,
]

_LLM_TOOLS = [Tool(function_declarations=TOOL_DECLARATIONS)]


# ---------------------------------------------------------------------------
# Client initialization (lazy - avoids hard failure at import time)
# ---------------------------------------------------------------------------
_client = None
_client_initialized = False


def normalize_language_code(language: str | None) -> str:
    """Reduce a language/locale tag to the base code understood by the prompt."""
    if not language or not language.strip():
        return "auto"
    code = language.strip().replace("_", "-").split("-", 1)[0].lower()
    supported = {"en", "hi", "ta", "te", "kn", "mr", "bn", "gu", "pa", "ml", "or"}
    return code if code in supported else "auto"


def _get_client():
    """Lazily build the Gemini client so importing this module never fails
    when GEMINI_API_KEY is missing or google-genai is not installed."""
    global _client, _client_initialized
    if _client_initialized:
        return _client
    _client_initialized = True
    if not settings.gemini_api_key:
        return None
    _client = genai.Client(api_key=settings.gemini_api_key)
    return _client


def is_configured() -> bool:
    return bool(settings.gemini_api_key)


# ---------------------------------------------------------------------------
# Streaming generator
# ---------------------------------------------------------------------------
async def stream(messages, detected_language: str | None = None, max_rounds: int = 4):
    """Async generator yielding ("text", delta) and ("tool", function_call) tuples.

    ``messages`` is a list of Gemini content dicts ({"role": ..., "parts": [...]}).

    The generator performs ONE streaming round per call. If Gemini emits a
    function_call part, it is yielded as ("tool", function_call) and the stream
    ends. The caller is responsible for dispatching via :func:`dispatch_tool`,
    appending a {"role": "function"} or {"role": "user", "parts": [FunctionResponse]}
    message, and calling stream() again with the extended message list.

    Up to 3 retries with exponential backoff (0.4s, 0.8s, 1.6s) on transport
    or API errors.
    """
    client = _get_client()
    if client is None:
        raise RuntimeError("Gemini API key is not configured (GEMINI_API_KEY).")

    lang_code = normalize_language_code(detected_language)
    config = GenerateContentConfig(
        system_instruction=[
            SYSTEM_PROMPT,
            f"\n\nDETECTED_LANGUAGE: {lang_code}",
        ],
        tools=_LLM_TOOLS,
        temperature=0.4,
        top_p=0.9,
        max_output_tokens=1024,
    )

    last_err: Exception | None = None
    for attempt in range(3):
        emitted_output = False
        try:
            response_stream = await client.aio.models.generate_content_stream(
                model=settings.gemini_model,
                contents=messages,
                config=config,
            )
            async for chunk in response_stream:
                if not chunk or not chunk.candidates:
                    continue
                cand = chunk.candidates[0]
                content = getattr(cand, "content", None)
                if not content or not getattr(content, "parts", None):
                    continue
                for part in content.parts:
                    text_val = getattr(part, "text", None)
                    fc = getattr(part, "function_call", None)
                    if text_val:
                        emitted_output = True
                        yield ("text", text_val)
                    elif fc and getattr(fc, "name", None):
                        emitted_output = True
                        yield ("tool", fc)
            return
        except Exception as exc:  # noqa: BLE001 - we retry on any API/transport error
            if emitted_output:
                raise
            last_err = exc
            if attempt < 2:
                await asyncio.sleep(0.4 * (2 ** attempt))
            continue
    if last_err:
        raise last_err


# ---------------------------------------------------------------------------
# Tool dispatcher
# ---------------------------------------------------------------------------
async def dispatch_tool(name: str, args, db, scan_id: int | None = None):
    """Execute a function call against the database and return a JSON-able dict."""
    args = dict(args or {})
    sid = args.get("scan_id") or scan_id
    if sid is None and name != "compare_scans":
        return {"error": "scan_id is required."}

    if name == "get_scan_summary":
        scan = db.execute(select(Scan).where(Scan.id == sid)).scalar_one_or_none()
        if not scan:
            return {"error": f"Scan {sid} not found."}
        findings = db.execute(select(Finding).where(Finding.scan_id == sid)).scalars().all()
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
        return {
            "scan_id": scan.id,
            "target_domain": scan.target_domain,
            "status": scan.status,
            "risk_score": float(scan.risk_score or 0.0),
            "total_assets": int(scan.total_assets or 0),
            "total_findings": int(scan.total_findings or 0),
            "severity_counts": sev_counts,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "error_message": scan.error_message,
            "is_partial": scan.status == "PARTIAL",
        }

    if name == "list_findings":
        severity = (args.get("severity") or "").upper() or None
        limit = int(args.get("limit") or 20)
        stmt = select(Finding).where(Finding.scan_id == sid)
        if severity:
            stmt = stmt.where(Finding.severity == severity)
        stmt = stmt.order_by(Finding.score.desc()).limit(limit)
        rows = db.execute(stmt).scalars().all()
        return {
            "scan_id": sid,
            "severity_filter": severity,
            "count": len(rows),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "affected_asset": f.affected_asset,
                    "severity": f.severity,
                    "score": float(f.score or 0.0),
                }
                for f in rows
            ],
        }

    if name == "get_finding_detail":
        finding_id = args.get("finding_id")
        if finding_id is None:
            return {"error": "finding_id is required."}
        f = db.execute(
            select(Finding).where(Finding.id == int(finding_id), Finding.scan_id == sid)
        ).scalar_one_or_none()
        if not f:
            return {"error": f"Finding {finding_id} not found in scan {sid}."}
        return {
            "id": f.id,
            "scan_id": f.scan_id,
            "title": f.title,
            "affected_asset": f.affected_asset,
            "severity": f.severity,
            "score": float(f.score or 0.0),
            "confidence": f.confidence,
            "evidence": f.evidence,
            "explanation": f.explanation,
            "remediation": f.remediation,
        }

    if name == "list_assets":
        asset_type = (args.get("asset_type") or "").upper() or None
        limit = int(args.get("limit") or 50)
        stmt = select(Asset).where(Asset.scan_id == sid)
        if asset_type:
            stmt = stmt.where(Asset.asset_type == asset_type)
        stmt = stmt.limit(limit)
        rows = db.execute(stmt).scalars().all()
        return {
            "scan_id": sid,
            "asset_type_filter": asset_type,
            "count": len(rows),
            "assets": [
                {
                    "id": a.id,
                    "asset_type": a.asset_type,
                    "identifier": a.identifier,
                    "hostname": a.hostname,
                    "ip_address": a.ip_address,
                    "port": a.port,
                    "protocol": a.protocol,
                    "http_status": a.http_status,
                    "page_title": a.page_title,
                }
                for a in rows
            ],
        }

    if name == "compare_scans":
        baseline_id = args.get("baseline_scan_id")
        if baseline_id is None:
            return {"error": "baseline_scan_id is required."}
        cur = db.execute(select(Scan).where(Scan.id == sid)).scalar_one_or_none()
        base = db.execute(select(Scan).where(Scan.id == int(baseline_id))).scalar_one_or_none()
        if not cur or not base:
            return {"error": "One or both scans not found."}
        cur_rows = db.execute(select(Finding).where(Finding.scan_id == sid)).scalars().all()
        base_rows = db.execute(select(Finding).where(Finding.scan_id == int(baseline_id))).scalars().all()
        cur_set = {(f.title, f.affected_asset) for f in cur_rows}
        base_set = {(f.title, f.affected_asset) for f in base_rows}
        new_keys = sorted(cur_set - base_set)
        resolved_keys = sorted(base_set - cur_set)
        return {
            "current_scan_id": sid,
            "baseline_scan_id": int(baseline_id),
            "current_target": cur.target_domain,
            "baseline_target": base.target_domain,
            "current_risk_score": float(cur.risk_score or 0.0),
            "baseline_risk_score": float(base.risk_score or 0.0),
            "risk_delta": float((cur.risk_score or 0.0) - (base.risk_score or 0.0)),
            "current_finding_count": len(cur_rows),
            "baseline_finding_count": len(base_rows),
            "new_findings": [{"title": t, "affected_asset": a} for (t, a) in new_keys[:20]],
            "resolved_findings": [{"title": t, "affected_asset": a} for (t, a) in resolved_keys[:20]],
        }

    return {"error": f"Unknown tool: {name}"}


# ---------------------------------------------------------------------------
# Reply model + guardrail
# ---------------------------------------------------------------------------
class AssistantReply(BaseModel):
    """Normalized assistant reply. ``spoken`` is what TTS reads aloud and is
    hard-capped at 1500 characters."""
    spoken: str
    bubble_markdown: str = ""
    next_state: str = "SCAN_FOLLOWUP"

    @field_validator("spoken")
    @classmethod
    def _cap_spoken(cls, v: str) -> str:
        if v is None:
            return ""
        return v[:1500]


# Pattern set used by the hallucination guardrail. We accept finding IDs
# mentioned as "finding #12", "id 12", "#12", or "issue 12".
_ID_PATTERNS = [
    re.compile(r"finding\s*#?\s*(\d+)", re.IGNORECASE),
    re.compile(r"\bissue\s*#?\s*(\d+)", re.IGNORECASE),
    re.compile(r"\bid\s*[:#]?\s*(\d+)", re.IGNORECASE),
    re.compile(r"#(\d+)\b"),
]


def validate_finding_ids(text: str, allowed_ids) -> bool:
    """Guardrail: returns True iff every finding ID mentioned in ``text`` is
    in ``allowed_ids``. A False result means the model invented a finding ID
    and the caller should fall back to the deterministic composer.

    If no IDs are mentioned, returns True (nothing to validate).
    """
    if not text:
        return True
    allowed = set(allowed_ids or ())
    mentioned: set[int] = set()
    for pat in _ID_PATTERNS:
        mentioned.update(int(m) for m in pat.findall(text))
    if not mentioned:
        return True
    return mentioned.issubset(allowed)
