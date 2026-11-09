import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

from backend.core.config import settings

Base = declarative_base()


def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    email = Column(String(320), nullable=False, unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    scans = relationship("Scan", back_populates="owner")
    sessions = relationship("AuthSession", back_populates="user", cascade="all, delete-orphan")


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    token_hash = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    csrf_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    user = relationship("User", back_populates="sessions")


class DomainChallenge(Base):
    __tablename__ = "domain_challenges"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(253), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    verified_at = Column(DateTime, nullable=True)
    __table_args__ = (Index("ix_domain_challenge_owner_domain", "user_id", "domain"),)


class ScanAuthorization(Base):
    __tablename__ = "scan_authorizations"

    token_hash = Column(String(64), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    domain = Column(String(253), nullable=False, index=True)
    attestation_method = Column(String(32), nullable=False)
    created_at = Column(DateTime, nullable=False, default=utcnow)
    expires_at = Column(DateTime, nullable=False, index=True)
    consumed_at = Column(DateTime, nullable=True)


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"

    key_hash = Column(String(64), primary_key=True)
    window_started_at = Column(DateTime, nullable=False, index=True)
    hits = Column(Integer, nullable=False, default=0)


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    # Nullable solely so the additive migration preserves and isolates legacy rows.
    # New scans always receive an owner; unclaimed legacy rows are never returned.
    user_id = Column(Integer, ForeignKey("users.id", ondelete="RESTRICT"), nullable=True, index=True)
    target_domain = Column(String(255), nullable=False, index=True)
    authorized = Column(Boolean, default=False, nullable=False)
    status = Column(String(50), default="PENDING", nullable=False)
    error_message = Column(Text, nullable=True)
    execution_metadata = Column(JSON, nullable=True)
    total_assets = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    started_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime, nullable=True)

    assets = relationship("Asset", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    graph_edges = relationship("GraphEdge", back_populates="scan", cascade="all, delete-orphan")
    owner = relationship("User", back_populates="scans")
    __table_args__ = (
        Index("ix_scans_status_id", "status", "id"),
        Index("ix_scans_owner_status", "user_id", "status"),
    )


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    asset_type = Column(String(50), nullable=False)
    identifier = Column(String(255), nullable=False, index=True)
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(100), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    http_status = Column(Integer, nullable=True)
    page_title = Column(String(500), nullable=True)
    tls_info = Column(JSON, nullable=True)
    dns_records = Column(JSON, nullable=True)
    discovered_at = Column(DateTime, default=utcnow)

    scan = relationship("Scan", back_populates="assets")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    affected_asset = Column(String(255), nullable=False)
    severity = Column(String(50), nullable=False)
    score = Column(Float, default=0.0)
    confidence = Column(String(50), default="HIGH")
    evidence = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utcnow)

    scan = relationship("Scan", back_populates="findings")


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False, index=True)
    source = Column(String(255), nullable=False)
    target = Column(String(255), nullable=False)
    relationship_type = Column(String(50), nullable=False)
    details = Column(JSON, nullable=True)

    scan = relationship("Scan", back_populates="graph_edges")


connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine_options = {"pool_pre_ping": True}
if not settings.database_url.startswith("sqlite"):
    engine_options.update(pool_size=5, max_overflow=5, pool_recycle=1800)
engine = create_engine(settings.database_url, connect_args=connect_args, **engine_options)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
