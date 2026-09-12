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


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    analysing = "analysing"
    awaiting_user_decision = "awaiting_user_decision"
    complete = "complete"
    failed = "failed"
    cancelled = "cancelled"


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


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), nullable=False)
    status = Column(SAEnum(ScanStatus), nullable=False, default=ScanStatus.queued)
    authorized = Column(Boolean, nullable=False, default=False)
    # 'quick' (passive-only profile) | 'full' (all 8 active modules). Default
    # 'full' preserves prior behavior for local/self-hosted callers that don't
    # send a mode.
    scan_type = Column(String(8), nullable=False, default='full')
    # Owner in hosted (REQUIRE_AUTH) mode; NULL for local/self-hosted scans.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    # Set the moment a scan is handed to Celery (immediately at acceptance, or
    # later by tasks/queue_scheduler.py when a slot frees). Distinguishes a scan
    # WAITING for capacity (status='queued' AND dispatched_at IS NULL) from one
    # already dispatched and occupying a slot. Only written/read when
    # config.HOSTED_QUEUE_ENABLED is True; stays NULL (and unused) otherwise, so
    # this column is inert for self-hosted deployments.
    dispatched_at = Column(DateTime, nullable=True)
    module_statuses = Column(JSONB, nullable=True, default=dict)
    raw_findings = Column(JSONB, nullable=True)
    ai_analysis = Column(JSONB, nullable=True)
    risk_score = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Bumped on every ORM-level write (status transitions, risk_score, etc.)
    # via onupdate - not bumped by base_task.py's raw-SQL module_statuses
    # update (that's deliberately a separate, high-frequency, per-module
    # signal; this column is "when did the scan's own record last change,"
    # for the /api/scans listing page's "Last updated" column).
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    report = relationship("Report", back_populates="scan", uselist=False)


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
    report = relationship("Report", back_populates="config", uselist=False)


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


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=True)
    config_id = Column(UUID(as_uuid=True), ForeignKey("configs.id", ondelete="CASCADE"), nullable=True, index=True)
    pdf_data = Column(LargeBinary, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="report")
    config = relationship("Config", back_populates="report")


class DomainVerification(Base):
    """Domain-ownership (Domain Control Validation) record - routers/verify.py.

    Two-step, claim-key model (deployment-scoped, no user accounts):
      1. issue  -> a `pending` row with a random `token` the owner must place
                   (meta tag on the homepage, or a file under /.well-known/).
      2. check  -> if the token is found, status flips to `verified`, a secret
                   claim key is minted and only its SHA-256 hash is stored here
                   (`key_hash`). The plaintext key is returned to the caller
                   exactly once and never persisted.

    A scan for this domain is then gated on presenting that claim key (its hash
    must match a non-expired verified row). This closes the "A verifies, B rides
    it" bypass a domain-only cache would have, without needing login/accounts.
    Only enforced when config.REQUIRE_DOMAIN_VERIFICATION is True.
    """
    __tablename__ = "domain_verifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Owner in hosted (REQUIRE_AUTH) mode; NULL for the account-less claim-key
    # flow (REQUIRE_DOMAIN_VERIFICATION) so that path keeps working unchanged.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    method = Column(String(16), nullable=False)          # 'meta_tag' | 'http_file'
    token = Column(String(96), nullable=False)           # challenge value to place
    key_hash = Column(String(64), nullable=True)         # sha256(claim_key), set on verify
    status = Column(String(16), nullable=False, default="pending")  # 'pending' | 'verified'
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)         # verified_at + TTL
