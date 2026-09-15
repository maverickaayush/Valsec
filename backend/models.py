import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, Enum as SAEnum,
    DateTime, LargeBinary, ForeignKey, Text, UniqueConstraint, Float, Index,
    CheckConstraint, text
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


class MembershipRole(str, enum.Enum):
    owner = "owner"
    operator = "operator"
    viewer = "viewer"


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


class NetworkMissionStatus(str, enum.Enum):
    created = "created"
    discovering = "discovering"
    collecting = "collecting"
    auditing = "auditing"
    ready_for_review = "ready_for_review"
    remediation_pending = "remediation_pending"
    remediating = "remediating"
    completed = "completed"
    partially_completed = "partially_completed"
    failed = "failed"
    cancelled = "cancelled"


class MissionDeviceState(str, enum.Enum):
    seed = "seed"
    identified = "identified"
    credential_missing = "credential_missing"
    unsupported = "unsupported"
    out_of_scope = "out_of_scope"
    unreachable = "unreachable"
    collection_failed = "collection_failed"
    ready = "ready"
    audit_queued = "audit_queued"
    audited = "audited"
    remediation_ready = "remediation_ready"


class RemediationCampaignStatus(str, enum.Enum):
    pending_approval = "pending_approval"
    approved = "approved"
    executing = "executing"
    completed = "completed"
    partially_completed = "partially_completed"
    failed = "failed"
    cancelled = "cancelled"


class CampaignTargetStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    applying = "applying"
    verified = "verified"
    already_compliant = "already_compliant"
    failed = "failed"
    rolled_back = "rolled_back"
    unreachable = "unreachable"


class User(Base):
    """Hosted-tier user account (routers/auth.py). Only used when
    config.REQUIRE_AUTH is True (a local single-operator deployment has no users).

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
    memberships = relationship("Membership", back_populates="user", cascade="all, delete-orphan")


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    is_personal = Column(Boolean, nullable=False, default=False)
    require_separate_remediation_approver = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)

    memberships = relationship("Membership", back_populates="organization", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="organization")
    network_missions = relationship("NetworkMission", back_populates="organization")
    remediation_campaigns = relationship("RemediationCampaign", back_populates="organization")


class Membership(Base):
    __tablename__ = "memberships"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(SAEnum(MembershipRole, name="membership_role"), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    user = relationship("User", back_populates="memberships")
    organization = relationship("Organization", back_populates="memberships")

    __table_args__ = (UniqueConstraint("user_id", "org_id", name="uq_memberships_user_org"),)


class AuthProvider(Base):
    """External OAuth identity linked to a User (routers/auth.py + oauth.py).

    A single user may hold several providers PLUS a password, all resolving to
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


class Device(Base):
    """Durable fleet identity shared by a device's configuration audits."""
    __tablename__ = "devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    site = Column(String(255), nullable=True)
    display_name = Column(String(255), nullable=False)
    vendor = Column(String(64), nullable=False)
    os_type = Column(String(64), nullable=False)
    management_address = Column(String(253), nullable=True)
    asset_tag = Column(String(128), nullable=True)
    tags = Column(JSONB, nullable=False, default=dict)
    is_active = Column(Boolean, nullable=False, default=True)
    baseline_config_id = Column(
        UUID(as_uuid=True),
        ForeignKey("configs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_audited_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)

    configs = relationship(
        "Config", back_populates="device", foreign_keys="Config.device_id",
    )
    baseline_config = relationship(
        "Config", foreign_keys=[baseline_config_id], post_update=True,
    )
    credentials = relationship(
        "DeviceCredential", back_populates="device", cascade="all, delete-orphan",
    )
    organization = relationship("Organization", back_populates="devices")
    schedules = relationship("AuditSchedule", back_populates="device", cascade="all, delete-orphan")
    mission_devices = relationship("NetworkMissionDevice", back_populates="device")

    __table_args__ = (
        Index(
            "uq_devices_vendor_management_address",
            "vendor", "management_address",
            unique=True,
            postgresql_where=text("management_address IS NOT NULL"),
        ),
        Index("ix_devices_vendor_display_name", "vendor", "display_name"),
        Index("ix_devices_org_active", "org_id", "is_active"),
        Index("ix_devices_last_audited_at", "last_audited_at"),
    )


class DeviceCredential(Base):
    """Metadata plus an opaque secret-backend reference; never plaintext."""
    __tablename__ = "device_credentials"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    credential_type = Column(String(16), nullable=False)
    username = Column(String(128), nullable=False)
    secret_backend = Column(String(64), nullable=False, default="local_encrypted")
    secret_ref = Column(Text, nullable=False)
    created_by_user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    rotation_required = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=True)

    device = relationship("Device", back_populates="credentials")
    access_logs = relationship(
        "CredentialAccessLog", back_populates="credential", cascade="all, delete-orphan",
    )
    schedules = relationship("AuditSchedule", back_populates="credential")

    __table_args__ = (
        UniqueConstraint("device_id", "credential_type", name="uq_device_credentials_device_type"),
        CheckConstraint(
            "credential_type IN ('ssh', 'telnet')",
            name="ck_device_credentials_type",
        ),
    )


class CredentialAccessLog(Base):
    """Append-only record of server-side credential use."""
    __tablename__ = "credential_access_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    credential_id = Column(
        UUID(as_uuid=True), ForeignKey("device_credentials.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    accessed_by_user_id = Column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True,
    )
    purpose = Column(String(64), nullable=False)
    mission_id = Column(
        UUID(as_uuid=True), ForeignKey("network_missions.id", ondelete="SET NULL"),
        nullable=True, index=True,
    )
    accessed_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    credential = relationship("DeviceCredential", back_populates="access_logs")


class AuditSchedule(Base):
    """Fixed-interval unattended pull and audit policy for one device."""
    __tablename__ = "audit_schedules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    credential_id = Column(UUID(as_uuid=True), ForeignKey("device_credentials.id", ondelete="SET NULL"), nullable=True, index=True)
    framework = Column(String(64), nullable=False)
    interval_minutes = Column(Integer, nullable=False)
    enabled = Column(Boolean, nullable=False, default=False)
    next_run_at = Column(DateTime, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String(255), nullable=False, default="awaiting_credential")
    consecutive_failures = Column(Integer, nullable=False, default=0)
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)

    device = relationship("Device", back_populates="schedules")
    credential = relationship("DeviceCredential", back_populates="schedules")

    __table_args__ = (
        CheckConstraint("interval_minutes >= 1", name="ck_audit_schedules_interval_positive"),
        Index("ix_audit_schedules_due", "enabled", "next_run_at"),
    )


class NetworkMission(Base):
    """One bounded, operator-controlled seed-to-fleet operation."""
    __tablename__ = "network_missions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    seed_device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="RESTRICT"), nullable=False, index=True)
    framework = Column(String(64), nullable=False)
    authorized_networks = Column(JSONB, nullable=False, default=list)
    max_depth = Column(Integer, nullable=False)
    max_devices = Column(Integer, nullable=False)
    status = Column(SAEnum(NetworkMissionStatus, name="network_mission_status"), nullable=False, default=NetworkMissionStatus.created)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)

    organization = relationship("Organization", back_populates="network_missions")
    seed_device = relationship("Device", foreign_keys=[seed_device_id])
    devices = relationship("NetworkMissionDevice", back_populates="mission", cascade="all, delete-orphan")
    events = relationship("NetworkMissionEvent", back_populates="mission", cascade="all, delete-orphan")
    campaigns = relationship("RemediationCampaign", back_populates="mission", cascade="all, delete-orphan")

    __table_args__ = (
        CheckConstraint("max_depth >= 1", name="ck_network_missions_max_depth"),
        CheckConstraint("max_devices >= 1", name="ck_network_missions_max_devices"),
        Index("ix_network_missions_org_created", "organization_id", "created_at"),
    )


class NetworkMissionDevice(Base):
    """Identity evidence and progress for one address in a mission topology."""
    __tablename__ = "network_mission_devices"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mission_id = Column(UUID(as_uuid=True), ForeignKey("network_missions.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    config_id = Column(UUID(as_uuid=True), ForeignKey("configs.id", ondelete="SET NULL"), nullable=True, index=True)
    address = Column(String(64), nullable=False)
    parent_address = Column(String(64), nullable=True)
    depth = Column(Integer, nullable=False, default=0)
    vendor_hint = Column(String(64), nullable=True)
    platform_hint = Column(String(255), nullable=True)
    discovery_sources = Column(JSONB, nullable=False, default=list)
    raw_evidence = Column(JSONB, nullable=False, default=dict)
    state = Column(SAEnum(MissionDeviceState, name="mission_device_state"), nullable=False)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)

    mission = relationship("NetworkMission", back_populates="devices")
    device = relationship("Device", back_populates="mission_devices")
    config = relationship("Config")

    __table_args__ = (
        UniqueConstraint("mission_id", "address", name="uq_network_mission_device_address"),
        Index("ix_network_mission_devices_state", "mission_id", "state"),
    )


class NetworkMissionEvent(Base):
    """Append-only, sanitized mission state-transition record."""
    __tablename__ = "network_mission_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mission_id = Column(UUID(as_uuid=True), ForeignKey("network_missions.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    actor_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    event_type = Column(String(64), nullable=False)
    detail = Column(JSONB, nullable=False, default=dict)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    mission = relationship("NetworkMission", back_populates="events")


class RemediationCampaign(Base):
    """One reviewed logical control fix with independently executed targets."""
    __tablename__ = "remediation_campaigns"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    mission_id = Column(UUID(as_uuid=True), ForeignKey("network_missions.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    created_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    framework = Column(String(64), nullable=False)
    control_id = Column(String(32), nullable=False)
    title = Column(String(255), nullable=False)
    status = Column(SAEnum(RemediationCampaignStatus, name="remediation_campaign_status"), nullable=False, default=RemediationCampaignStatus.pending_approval)
    approved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True, default=datetime.utcnow, onupdate=datetime.utcnow)

    mission = relationship("NetworkMission", back_populates="campaigns")
    organization = relationship("Organization", back_populates="remediation_campaigns")
    targets = relationship("RemediationCampaignTarget", back_populates="campaign", cascade="all, delete-orphan")

    __table_args__ = (Index("ix_remediation_campaign_control", "mission_id", "framework", "control_id"),)


class RemediationCampaignTarget(Base):
    """Stable per-device execution boundary for an approved campaign."""
    __tablename__ = "remediation_campaign_targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    campaign_id = Column(UUID(as_uuid=True), ForeignKey("remediation_campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    mission_device_id = Column(UUID(as_uuid=True), ForeignKey("network_mission_devices.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("compliance_results.id", ondelete="CASCADE"), nullable=False, index=True)
    remediation_action_id = Column(UUID(as_uuid=True), ForeignKey("remediation_actions.id", ondelete="SET NULL"), nullable=True, index=True)
    verification_config_id = Column(UUID(as_uuid=True), ForeignKey("configs.id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(SAEnum(CampaignTargetStatus, name="campaign_target_status"), nullable=False, default=CampaignTargetStatus.pending)
    failure_message = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    campaign = relationship("RemediationCampaign", back_populates="targets")
    mission_device = relationship("NetworkMissionDevice")
    device = relationship("Device")
    finding = relationship("ComplianceResult")
    remediation_action = relationship("RemediationAction")
    verification_config = relationship("Config", foreign_keys=[verification_config_id])

    __table_args__ = (
        UniqueConstraint("campaign_id", "finding_id", name="uq_campaign_target_finding"),
        Index("ix_campaign_targets_campaign_status", "campaign_id", "status"),
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
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    findings = relationship("NormalizedFinding", back_populates="config", cascade="all, delete-orphan")
    compliance_results = relationship("ComplianceResult", back_populates="config", cascade="all, delete-orphan")
    report = relationship("Report", back_populates="config", uselist=False, cascade="all, delete-orphan")
    discovery_device = relationship("DiscoveredDevice", back_populates="config", uselist=False)
    device = relationship("Device", back_populates="configs", foreign_keys=[device_id])

    __table_args__ = (
        Index("ix_configs_device_status_completed_at", "device_id", "status", "completed_at"),
        Index("ix_configs_device_uploaded_at", "device_id", "uploaded_at"),
    )


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
