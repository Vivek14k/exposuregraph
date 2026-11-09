from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator


class StartScanRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=2048, description="Target domain or HTTP(S) root URL", examples=["example.com"])
    authorized: bool = Field(..., description="Explicit confirmation of ownership or authorization")
    authorization_token: Optional[str] = Field(None, description="Server-validated authorization token bound to domain")


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_domain: str
    authorized: bool
    status: str
    error_message: Optional[str] = None
    execution_metadata: Optional[Dict[str, Any]] = None
    total_assets: int
    total_findings: int
    risk_score: float
    started_at: Optional[Any] = None
    completed_at: Optional[Any] = None


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    asset_type: str
    identifier: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    http_status: Optional[int] = None
    page_title: Optional[str] = None
    dns_records: Optional[Dict[str, Any]] = None
    tls_info: Optional[Dict[str, Any]] = None


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    affected_asset: str
    severity: str
    score: float
    confidence: str
    evidence: str
    explanation: str
    remediation: str


class GraphResponse(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class VoiceTranscribeResponse(BaseModel):
    success: bool
    transcript: str
    detected_language: Optional[str] = None
    parsed_domain: Optional[str] = None
    error: Optional[str] = None


class AssistantHistoryMessage(BaseModel):
    role: Literal["user", "assistant"]
    content: str = Field(..., min_length=1, max_length=2000)


class AssistantChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000, description="User voice transcript or typed message")
    current_state: str = Field("IDLE", description="Current conversation stage")
    current_domain: Optional[str] = Field(None, max_length=253, description="Identified candidate domain")
    scan_id: Optional[int] = Field(None, gt=0, description="Associated scan ID for follow-up questions")
    detected_language: Optional[str] = Field(None, max_length=16, description="Detected user language (hi/ta/te/kn/mr/bn/gu/pa/ml/or or en). Mirrored by the LLM.")
    conversation_history: List["AssistantHistoryMessage"] = Field(default_factory=list, max_length=12)

    @field_validator("current_state", mode="before")
    @classmethod
    def normalize_state(cls, v: Any) -> str:
        if not v or not isinstance(v, str):
            return "IDLE"
        s = v.strip().upper().replace("-", "_")
        if s in ("AWAITING_TOPIC", "TOPIC", "INITIAL"):
            return "IDLE"
        if s in ("IDLE", "CONFIRM_DOMAIN", "AWAITING_AUTH", "AUTHORIZED", "SCAN_FOLLOWUP"):
            return s
        return "IDLE"


class AssistantChatResponse(BaseModel):
    assistant_reply: str
    next_state: str
    domain: Optional[str] = None
    authorized: bool = False
    can_launch: bool = False
    authorization_token: Optional[str] = None


class ManualAttestationRequest(BaseModel):
    domain: str = Field(..., description="Domain for manual checkbox attestation")
    attestation_confirmed: bool = Field(..., description="User affirmed checkbox")


class ManualAttestationResponse(BaseModel):
    authorization_token: str
    domain: str


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=320)
    password: str = Field(..., min_length=1, max_length=256)


class AuthUserResponse(BaseModel):
    id: int
    email: str


class DomainChallengeRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)


class DomainChallengeResponse(BaseModel):
    id: int
    domain: str
    record_name: str
    record_value: str
    expires_at: Any


class DomainVerifyResponse(BaseModel):
    verified: bool
    domain: str
    authorization_token: str


class DomainAuthorizationRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=253)


class TTSRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=6000, description="Text to synthesize into speech")
    voice: Optional[str] = Field("Nalini", min_length=1, max_length=80, description="Voice identifier")
    speed: Optional[float] = Field(1.0, ge=0.85, le=1.15, description="Speech rate multiplier")
