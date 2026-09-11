"""Typed, vendor-neutral representation of a normalized device configuration.

This module deliberately has no database dependency.  Its finding records map
directly to ``normalized_findings`` when the future audit orchestrator persists
them, while keeping parsing usable in tests and offline tools.
"""
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any, Literal


class Confidence(StrEnum):
    """Confidence tiers shared with the persistence model as string values."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    UNVERIFIED = "unverified"


class MappingSource(StrEnum):
    """Origin labels stored alongside a normalized finding."""

    PARSER = "parser"
    LEARNED_MAPPING = "learned_mapping"
    AI_PROPOSAL = "ai_proposal"
    MANUAL_TRAINING = "manual_training"


@dataclass
class DeviceInfo:
    hostname: str | None = None
    domain_name: str | None = None
    model: str | None = None
    os_version: str | None = None
    enable_secret_type: int | None = None


@dataclass
class ServiceHardening:
    password_encryption: bool | None = None
    finger_disabled: bool | None = None
    tcp_small_servers_disabled: bool | None = None
    udp_small_servers_disabled: bool | None = None
    bootp_server_disabled: bool | None = None
    http_server_disabled: bool | None = None
    http_secure_server_enabled: bool | None = None


@dataclass
class AccessControl:
    banner_motd: str | None = None
    banner_login: str | None = None
    source_route_disabled: bool | None = None


@dataclass
class LineConsole:
    exec_timeout_minutes: int | None = None
    transport_preferred: str | None = None


@dataclass
class LineVTY:
    transport_input: list[str] = field(default_factory=list)
    exec_timeout_minutes: int | None = None
    access_class: str | None = None


@dataclass
class SSH:
    version: int | None = None
    timeout_seconds: int | None = None
    auth_retries: int | None = None


@dataclass
class AAA:
    new_model: bool | None = None
    authentication_login: str | None = None


@dataclass
class Logging:
    buffered_size: int | None = None
    trap_severity: str | None = None
    timestamps_enabled: bool | None = None


@dataclass
class SNMP:
    v3_only: bool | None = None
    default_communities_removed: bool | None = None


@dataclass
class NTP:
    servers: list[str] = field(default_factory=list)
    authenticate: bool | None = None


@dataclass
class CDP:
    global_disabled: bool | None = None


@dataclass
class InterfaceSettings:
    """Useful interface-level state retained without making it control-specific."""

    name: str | None = None
    description: str | None = None
    shutdown: bool | None = None
    ip_address: str | None = None
    cdp_disabled: bool | None = None


@dataclass
class VendorNeutralConfig:
    device_info: DeviceInfo = field(default_factory=DeviceInfo)
    service_hardening: ServiceHardening = field(default_factory=ServiceHardening)
    access_control: AccessControl = field(default_factory=AccessControl)
    line_console: LineConsole = field(default_factory=LineConsole)
    line_vty: LineVTY = field(default_factory=LineVTY)
    ssh: SSH = field(default_factory=SSH)
    aaa: AAA = field(default_factory=AAA)
    logging: Logging = field(default_factory=Logging)
    snmp: SNMP = field(default_factory=SNMP)
    ntp: NTP = field(default_factory=NTP)
    cdp: CDP = field(default_factory=CDP)
    interfaces: dict[str, InterfaceSettings] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return JSON-compatible data suitable for later rule evaluation."""
        return asdict(self)


@dataclass(frozen=True)
class NormalizedFinding:
    """A source-traceable normalized setting, ready for database persistence."""

    schema_field: str
    field_value: Any
    raw_source_line: str
    line_number: int
    confidence: Literal["confirmed", "probable", "unverified"] = Confidence.CONFIRMED
    mapping_source: Literal[
        "parser", "learned_mapping", "ai_proposal", "manual_training"
    ] = MappingSource.PARSER


@dataclass(frozen=True)
class UnknownLine:
    """A non-empty config line with no deterministic parser interpretation."""

    raw_source_line: str
    line_number: int
    context: str | None = None


@dataclass
class NormalizationResult:
    config: VendorNeutralConfig = field(default_factory=VendorNeutralConfig)
    findings: list[NormalizedFinding] = field(default_factory=list)
    unknown_lines: list[UnknownLine] = field(default_factory=list)
