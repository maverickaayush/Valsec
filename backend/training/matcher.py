"""Learned mapping resolver and Ollama-powered classifier.

The resolver checks persistent learned_mappings for existing vendor/pattern pairs.
The classifier uses Ollama to propose schema field mappings for unknown lines,
following strict patterns: retry logic, JSON format mode, timeout scaling, and
NO configuration data sent externally.

Critical: AI proposes only. Operator approval is required before persistence.
Compliance verdicts remain 100% deterministic via rule evaluation.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any, Optional
from uuid import UUID

from sqlalchemy.orm import Session

from analysis.ollama_client import propose_config_mappings
from models import LearnedMapping
from normalizer.schema import Confidence, MappingSource, NormalizedFinding


@dataclass(frozen=True)
class MappingMatch:
    """A learned mapping result supplied by the resolver."""
    schema_field: str
    field_value: Any

logger = logging.getLogger(__name__)

CONFIG_SCHEMA_REFERENCE = {
    "device_info.hostname": "Device hostname string",
    "device_info.domain_name": "Device domain name string",
    "device_info.model": "Device model string",
    "device_info.os_version": "Operating-system version string",
    "device_info.enable_secret_type": "Enable-secret hash type integer",
    "service_hardening.password_encryption": "Whether password encryption is enabled",
    "service_hardening.finger_disabled": "Whether the finger service is disabled",
    "service_hardening.tcp_small_servers_disabled": "Whether TCP small servers are disabled",
    "service_hardening.udp_small_servers_disabled": "Whether UDP small servers are disabled",
    "service_hardening.bootp_server_disabled": "Whether the BOOTP server is disabled",
    "service_hardening.http_server_disabled": "Whether the HTTP server is disabled",
    "service_hardening.http_secure_server_enabled": "Whether the HTTPS server is enabled",
    "service_hardening.strong_crypto_enabled": "Whether strong cryptography is enabled",
    "access_control.banner_motd": "Message-of-the-day warning banner text",
    "access_control.banner_login": "Login warning banner text",
    "access_control.source_route_disabled": "Whether IP source routing is disabled",
    "line_console.exec_timeout_minutes": "Console idle timeout in minutes",
    "line_console.transport_preferred": "Preferred console transport string",
    "line_vty.transport_input": "Allowed VTY transports as a list",
    "line_vty.exec_timeout_minutes": "VTY idle timeout in minutes",
    "line_vty.access_class": "VTY access-class name",
    "ssh.version": "SSH protocol version integer",
    "ssh.timeout_seconds": "SSH authentication timeout in seconds",
    "ssh.auth_retries": "SSH authentication retry count",
    "aaa.new_model": "Whether AAA new-model is enabled",
    "aaa.authentication_login": "AAA login authentication method string",
    "logging.buffered_size": "Logging buffer size in bytes",
    "logging.enabled": "Whether system logging is enabled",
    "logging.trap_severity": "Remote logging trap severity",
    "logging.timestamps_enabled": "Whether millisecond log timestamps are enabled",
    "snmp.v3_only": "Whether only SNMPv3 is configured",
    "snmp.default_communities_removed": "Whether default SNMP communities are absent",
    "ntp.servers": "NTP server addresses as a list",
    "ntp.enabled": "Whether NTP synchronization is enabled",
    "ntp.authenticate": "Whether NTP authentication is enabled",
    "cdp.global_disabled": "Whether CDP is globally disabled",
}


def resolve_line(
    vendor: str, raw_line: str, db: Session, user_id: UUID | None = None
) -> Optional[NormalizedFinding]:
    """Check learned_mappings for an existing mapping.

    Generates a pattern signature from the raw line and queries the database
    for a prior operator-approved mapping. If found, returns a confirmed finding
    ready for database persistence. No AI involved: this is pure lookup.

    Args:
        vendor: Device vendor (e.g., 'cisco')
        raw_line: The unparsed configuration line
        db: SQLAlchemy session for database queries

    Returns:
        NormalizedFinding if a learned mapping exists, else None.
        The finding carries confidence='confirmed' and mapping_source='learned_mapping'.
    """
    if not raw_line or not raw_line.strip():
        return None

    # Generate pattern signature: replace variable parts with wildcards
    pattern = _generate_pattern_signature(raw_line)

    try:
        mapping = (
            db.query(LearnedMapping)
            .filter(
                LearnedMapping.vendor == vendor,
                LearnedMapping.pattern_signature == pattern,
                LearnedMapping.user_id == user_id,
            )
            .first()
        )

        if mapping:
            logger.info(
                "Resolved learned mapping for %s -> %s", vendor, mapping.schema_field
            )
            example = _mapping_example(mapping.examples, raw_line)
            field_value = example.get("field_value") if isinstance(example, dict) else example
            return NormalizedFinding(
                schema_field=mapping.schema_field,
                field_value=field_value,
                raw_source_line=raw_line,
                line_number=None,  # Will be set by caller
                confidence=Confidence.CONFIRMED,
                mapping_source=MappingSource.LEARNED_MAPPING,
            )
    except Exception as exc:
        logger.error(f"Error resolving learned mapping: {exc}")

    return None


def classify_with_ollama(
    vendor: str, raw_line: str, schema_reference: dict
) -> Optional[dict[str, Any]]:
    """Use Ollama to propose a schema field mapping for an unknown line.

    Sends the raw line (NO full config data) to Ollama via the standard integration
    pattern: retry logic, JSON format mode, timeout scaling, graceful degradation.

    The AI proposes only; operator approval is required before persistence.

    Args:
        vendor: Device vendor (e.g., 'cisco')
        raw_line: The unparsed configuration line
        schema_reference: Dict mapping schema field names to their descriptions

    Returns:
        Dict with keys:
          - schema_field: str | None (proposed field name from schema, or None if no match)
          - field_value: Any (proposed value for that field)
          - confidence: float (0.0-1.0, Ollama's confidence in the proposal)
        Returns None if Ollama is unreachable or times out.
    """
    if not raw_line or not raw_line.strip():
        return None

    proposals = propose_config_mappings(
        vendor,
        [{"line_number": 1, "raw_source_line": raw_line, "context": None}],
        schema_reference,
    )
    return proposals.get(1)


def _mapping_example(examples: list | None, raw_line: str) -> Any:
    """Prefer the approved value for this exact line within a broad pattern."""
    values = examples or []
    for example in values:
        if isinstance(example, dict) and example.get("raw_line") == raw_line:
            return example
    return values[0] if values else None


def _generate_pattern_signature(raw_line: str) -> str:
    """Generate a regex-like pattern signature for a configuration line.

    Converts specific values to wildcards so similar lines match the same mapping.
    Examples:
      "ip address 192.168.1.1 255.255.255.0" -> "ip address .* .*"
      "username admin password 7 0102030405" -> "username .* password .* .*"

    This pattern is stored in learned_mappings.pattern_signature and used for
    matching during resolve_line().

    Args:
        raw_line: The configuration line to generate a pattern for

    Returns:
        A string pattern with variable parts replaced by wildcards.
    """
    if not raw_line or not raw_line.strip():
        return raw_line or ""

    parts = raw_line.split()
    if not parts:
        return raw_line

    pattern_parts = []
    for part in parts:
        # Keep keywords (lowercase or with hyphens), replace numbers/IPs/hashes
        if part.islower() or (part.replace("-", "").replace("_", "").isalpha() and not part.isdigit()):
            # Looks like a keyword (lowercase, may have hyphens/underscores)
            pattern_parts.append(part)
        else:
            # Looks like a value (IP, number, hash, mixed case, etc.)
            pattern_parts.append(".*")

    return " ".join(pattern_parts)


class DatabaseLearnedMappingResolver:
    """Database-backed implementation of LearnedMappingResolver protocol.

    Used by CiscoIOSNormalizer to check persistent learned mappings during
    parsing. No AI involved: pure database lookup of operator-approved mappings.
    """

    def __init__(self, db: Session, user_id: UUID | None = None):
        self._db = db
        self._user_id = user_id

    def resolve(self, *, vendor: str, raw_line: str, line_number: int,
                context: str | None) -> MappingMatch | None:
        """Return an approved mapping for a line, or None when unmatched."""
        if not raw_line or not raw_line.strip():
            return None

        pattern = _generate_pattern_signature(raw_line)

        try:
            mapping = (
                self._db.query(LearnedMapping)
                .filter(
                    LearnedMapping.vendor == vendor,
                    LearnedMapping.pattern_signature == pattern,
                    LearnedMapping.user_id == self._user_id,
                )
                .first()
            )

            if mapping:
                logger.info(
                    "Resolved learned mapping for %s -> %s", vendor, mapping.schema_field
                )
                example = _mapping_example(mapping.examples, raw_line)
                field_value = example.get("field_value") if isinstance(example, dict) else example
                return MappingMatch(
                    schema_field=mapping.schema_field,
                    field_value=field_value,
                )
        except Exception as exc:
            logger.error(f"Error resolving learned mapping: {exc}")

        return None
