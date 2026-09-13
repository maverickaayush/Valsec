import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, Enum as SAEnum,
    DateTime, LargeBinary, ForeignKey, Text, UniqueConstraint, Float, Index, text
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from database import Base
import enum


class ConfigStatus(str, enum.Enum):
    queued = "queued"
    normalising = "normalising"
    awaiting_training = "awaiting_training"
    compliance_check = "compliance_check"
    complete = "complete"
    failed = "failed"
    cancelled = "cancelled"


class ConfidenceTier(str, enum.Enum):
    confirmed = "confirmed"
    probable = "probable"
    unverified = "unverified"


class ComplianceVerdict(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ComplianceSeverity(str, enum.Enum):
    Critical = "Critical"
    High = "High"
    Medium = "Medium"
    Low = "Low"
    Informational = "Informational"


class RemediationActionStatus(str, enum.Enum):
    proposed = "proposed"
    approved = "approved"
    applying = "applying"
    applied = "applied"
    failed = "failed"


class DiscoverySessionStatus(str, enum.Enum):
    running = "running"
    awaiting_input = "awaiting_input"
    complete = "complete"
    partial = "partial"
    failed = "failed"


class DiscoveredDeviceStatus(str, enum.Enum):
    discovered = "discovered"
    needs_input = "needs_input"
    pulling = "pulling"
    audit_queued = "audit_queued"
    failed = "failed"
    skipped = "skipped"


class User(Base):
    """Hosted-tier user account (routers/auth.py). Only used when
    config.REQUIRE_AUTH is True — a local single-operator deployment has no users.

    Passwords are Argon2id hashes (security.py); the plaintext is never stored
    or logged. OTP codes and browser sessions live in Redis, not here, so this
    table only carries durable identity + email-verification state.
    """
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False, unique=True, index=True)  # normalized
    # Nullable: OAuth-only users (Google/GitHub) have no password. Password
    # users still set it; verify_password treats None as "no password login".
    password_hash = Column(String(255), nullable=True)
    email_verified = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    providers = relationship("AuthProvider", back_populates="user",
                             cascade="all, delete-orphan")


class AuthProvider(Base):
    """External OAuth identity linked to a User (routers/auth.py + oauth.py).

    A single user may hold several providers PLUS a password — all resolving to
    ONE user via account-linking on a verified email, so no duplicate accounts.
    Password auth is NOT stored here (that's User.password_hash); this table is
    OAuth identities only. Only used when config.REQUIRE_AUTH is True.
    """
    __tablename__ = "auth_providers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    provider = Column(String(16), nullable=False)            # 'google' | 'github'
    provider_user_id = Column(String(255), nullable=False)   # stable id at the provider
    provider_metadata = Column(JSONB, nullable=True)         # login/name/avatar, non-secret
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="providers")

    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_provider_identity"),
    )


class Config(Base):
    """Uploaded device configuration and its audit lifecycle state.

    Raw configuration remains available for audit traceability while normalized
    findings and deterministic compliance results are retained as dependent
    records; an optional user owner preserves local/self-hosted operation.
    """
    __tablename__ = "configs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_name = Column(String(255), nullable=False)
    vendor = Column(String(64), nullable=False, default='cisco')
    os_type = Column(String(64), nullable=False, default='ios')
    firmware_version = Column(String(64), nullable=True)
    raw_config = Column(Text, nullable=False)
    status = Column(SAEnum(ConfigStatus), nullable=False, default=ConfigStatus.queued)
    selected_framework = Column(String(64), nullable=False, default='cis_cisco_ios_v1')
    compliance_score = Column(Float, nullable=True)
    total_passed = Column(Integer, nullable=False, default=0)
    total_failed = Column(Integer, nullable=False, default=0)
    total_na = Column(Integer, nullable=False, default=0)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    findings = relationship("NormalizedFinding", back_populates="config", cascade="all, delete-orphan")
    compliance_results = relationship("ComplianceResult", back_populates="config", cascade="all, delete-orphan")
    report = relationship("Report", back_populates="config", uselist=False, cascade="all, delete-orphan")
    discovery_device = relationship("DiscoveredDevice", back_populates="config", uselist=False)


class DiscoverySession(Base):
    """One authenticated seed traversal; request credentials are never persisted."""
    __tablename__ = "discovery_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    seed_host = Column(String(253), nullable=False)
    seed_vendor = Column(String(64), nullable=False, default="auto")
    status = Column(SAEnum(DiscoverySessionStatus), nullable=False, default=DiscoverySessionStatus.running)
    max_depth = Column(Integer, nullable=False, default=1)
    max_devices = Column(Integer, nullable=False, default=25)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    devices = relationship("DiscoveredDevice", back_populates="session", cascade="all, delete-orphan")


class DiscoveredDevice(Base):
    """Persistent evidence and processing state for one deduplicated address."""
    __tablename__ = "discovered_devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(UUID(as_uuid=True), ForeignKey("discovery_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    address = Column(String(64), nullable=False)
    parent_address = Column(String(64), nullable=False)
    mac_address = Column(String(32), nullable=True)
    interface = Column(String(128), nullable=True)
    vendor_hint = Column(String(64), nullable=True)
    platform_hint = Column(String(255), nullable=True)
    discovery_sources = Column(JSONB, nullable=False, default=list)
    raw_evidence = Column(JSONB, nullable=False, default=dict)
    depth = Column(Integer, nullable=False, default=1)
    status = Column(SAEnum(DiscoveredDeviceStatus), nullable=False, default=DiscoveredDeviceStatus.discovered)
    error_message = Column(Text, nullable=True)
    config_id = Column(UUID(as_uuid=True), ForeignKey("configs.id", ondelete="SET NULL"), nullable=True, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    session = relationship("DiscoverySession", back_populates="devices")
    config = relationship("Config", back_populates="discovery_device")

    __table_args__ = (
        UniqueConstraint("session_id", "address", name="uq_discovered_device_session_address"),
    )


class NormalizedFinding(Base):
    """One source-backed normalized field extracted from a device configuration.

    The original CLI line and optional line number keep each mapping auditable,
    while confidence and mapping source distinguish deterministic parsing from
    learned, AI-proposed, or operator-confirmed classifications.
    """
    __tablename__ = "normalized_findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    config_id = Column(UUID(as_uuid=True), ForeignKey("configs.id", ondelete="CASCADE"), nullable=False, index=True)
    schema_field = Column(String(128), nullable=False)
    field_value = Column(JSONB, nullable=False)
    raw_source_line = Column(Text, nullable=False)
    line_number = Column(Integer, nullable=True)
    confidence = Column(SAEnum(ConfidenceTier), nullable=False)
    mapping_source = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    config = relationship("Config", back_populates="findings")


class LearnedMapping(Base):
    """Persistent operator-approved interpretation for vendor-specific CLI syntax.

    A vendor and pattern signature can be learned only once, allowing later
    uploads to reuse an auditable mapping without sending configuration data
    outside the local deployment.
    """
    __tablename__ = "learned_mappings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # NULL is the single-operator/self-hosted scope. Authenticated deployments
    # always bind learned syntax to the user who approved it.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    vendor = Column(String(64), nullable=False)
    pattern_signature = Column(Text, nullable=False)
    schema_field = Column(String(128), nullable=False)
    created_by = Column(String(128), nullable=False, default='operator')
    confidence_score = Column(Float, nullable=False, default=1.0)
    examples = Column(JSONB, nullable=False, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    __table_args__ = (
        Index(
            "uq_learned_mapping_user_vendor_pattern",
            "user_id", "vendor", "pattern_signature",
            unique=True,
            postgresql_where=text("user_id IS NOT NULL"),
        ),
        Index(
            "uq_learned_mapping_local_vendor_pattern",
            "vendor", "pattern_signature",
            unique=True,
            postgresql_where=text("user_id IS NULL"),
        ),
    )


class ComplianceResult(Base):
    """Deterministic framework-control result recorded for a configuration audit.

    Verdict and severity are stored with the observed evidence and optional CLI
    remediation so reports remain reproducible even when rules later evolve.
    """
    __tablename__ = "compliance_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    config_id = Column(UUID(as_uuid=True), ForeignKey("configs.id", ondelete="CASCADE"), nullable=False, index=True)
    framework = Column(String(64), nullable=False)
    control_id = Column(String(32), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    verdict = Column(SAEnum(ComplianceVerdict), nullable=False)
    severity = Column(SAEnum(ComplianceSeverity), nullable=False)
    observed_value = Column(Text, nullable=True)
    remediation_cli = Column(Text, nullable=True)
    is_remediation_fallback = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    config = relationship("Config", back_populates="compliance_results")
    remediation_action = relationship(
        "RemediationAction", back_populates="finding", uselist=False,
        cascade="all, delete-orphan",
    )


class RemediationAction(Base):
    """Immutable operator-approved CLI plus evidence from an apply attempt."""
    __tablename__ = "remediation_actions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    finding_id = Column(
        UUID(as_uuid=True),
        ForeignKey("compliance_results.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    status = Column(
        SAEnum(RemediationActionStatus), nullable=False,
        default=RemediationActionStatus.proposed,
    )
    remediation_text = Column(Text, nullable=False)
    risky = Column(Boolean, nullable=False, default=False)
    pre_change_snapshot = Column(Text, nullable=True)
    post_change_snapshot = Column(Text, nullable=True)
    diff_summary = Column(Text, nullable=True)
    failure_message = Column(Text, nullable=True)
    applied_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    finding = relationship("ComplianceResult", back_populates="remediation_action")


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    config_id = Column(UUID(as_uuid=True), ForeignKey("configs.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    pdf_data = Column(LargeBinary, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)

    config = relationship("Config", back_populates="report")
