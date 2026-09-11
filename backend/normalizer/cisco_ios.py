"""Deterministic Cisco IOS / IOS-XE running-configuration normalizer."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from .schema import (
    Confidence,
    MappingSource,
    InterfaceSettings,
    NormalizationResult,
    NormalizedFinding,
    UnknownLine,
)


@dataclass(frozen=True)
class MappingMatch:
    """A learned mapping result supplied by the future training persistence layer."""

    schema_field: str
    field_value: Any


class LearnedMappingResolver(Protocol):
    """Boundary for matching already-approved vendor syntax without ORM coupling."""

    def resolve(self, *, vendor: str, raw_line: str, line_number: int,
                context: str | None) -> MappingMatch | None:
        """Return an approved mapping for a line, or ``None`` when unmatched."""


_EXEC_TIMEOUT = re.compile(r"^exec-timeout\s+(\d+)(?:\s+(\d+))?$", re.I)
_INTERFACE = re.compile(r"^interface\s+(.+)$", re.I)
_LINE_CONSOLE = re.compile(r"^line\s+(?:con|console)\s+\d+", re.I)
_LINE_VTY = re.compile(r"^line\s+vty\s+.+$", re.I)
_BANNER = re.compile(r"^banner\s+(motd|login)\s+(.+)$", re.I)


class CiscoIOSNormalizer:
    """Parse supported IOS statements while preserving unrecognized source text.

    The parser is intentionally deterministic.  It does not classify unknown
    syntax itself; an optional injected resolver may apply only existing,
    operator-approved learned mappings before such lines are returned intact.
    """

    vendor = "cisco"

    def __init__(self, learned_mapping_resolver: LearnedMappingResolver | None = None):
        self._learned_mapping_resolver = learned_mapping_resolver

    def parse(self, raw_config: str) -> NormalizationResult:
        result = NormalizationResult()
        context: str | None = None
        banner: tuple[str, str, int, str, list[str]] | None = None

        for line_number, raw_line in enumerate(raw_config.splitlines(), start=1):
            stripped = raw_line.strip()

            if banner is not None:
                field, delimiter, start_line, start_raw, content = banner
                if stripped == delimiter or stripped.endswith(delimiter):
                    trailing = stripped[:-len(delimiter)].strip()
                    if trailing:
                        content.append(trailing)
                    value = "\n".join(content)
                    self._set(result, field, value, start_raw, start_line)
                    banner = None
                else:
                    content.append(raw_line)
                continue

            if not stripped:
                continue
            if stripped == "!":
                context = None
                continue

            banner_match = _BANNER.match(stripped)
            if banner_match:
                kind, remainder = banner_match.groups()
                field = f"access_control.banner_{kind.lower()}"
                # IOS commonly renders control-C delimiters as ``^C`` rather
                # than a literal control character in a running-config export.
                delimiter = remainder[:2] if re.fullmatch(r"\^[A-Za-z]", remainder[:2]) else remainder[0]
                text = remainder[len(delimiter):].strip()
                if delimiter and delimiter in text:
                    value, _, _ = text.partition(delimiter)
                    self._set(result, field, value.strip(), raw_line, line_number)
                else:
                    banner = (field, delimiter, line_number, raw_line, [text] if text else [])
                context = None
                continue

            interface_match = _INTERFACE.match(stripped)
            if interface_match:
                name = interface_match.group(1).strip()
                result.config.interfaces.setdefault(name, InterfaceSettings())
                self._set(result, f"interfaces.{name}.name", name, raw_line, line_number)
                context = f"interface:{name}"
                continue
            if _LINE_CONSOLE.match(stripped):
                context = "line_console"
                continue
            if _LINE_VTY.match(stripped):
                context = "line_vty"
                continue

            if self._parse_context_line(result, stripped, raw_line, line_number, context):
                continue
            if self._parse_global_line(result, stripped, raw_line, line_number):
                context = None
                continue
            if self._apply_learned_mapping(result, raw_line, line_number, context):
                continue
            result.unknown_lines.append(UnknownLine(raw_line, line_number, context))

        if banner is not None:
            # An unterminated banner is retained for training rather than treated as valid.
            _, _, start_line, start_raw, _ = banner
            result.unknown_lines.append(UnknownLine(start_raw, start_line, "banner"))
        return result

    def _parse_context_line(self, result: NormalizationResult, stripped: str,
                            raw_line: str, line_number: int,
                            context: str | None) -> bool:
        timeout = _EXEC_TIMEOUT.match(stripped)
        if timeout and context in {"line_console", "line_vty"}:
            minutes = int(timeout.group(1)) * 60 + int(timeout.group(2) or 0)
            field = f"{context}.exec_timeout_minutes"
            self._set(result, field, minutes, raw_line, line_number)
            return True

        if context == "line_console":
            match = re.match(r"^transport\s+preferred\s+(.+)$", stripped, re.I)
            if match:
                self._set(result, "line_console.transport_preferred", match.group(1).strip(), raw_line, line_number)
                return True
        elif context == "line_vty":
            match = re.match(r"^transport\s+input\s+(.+)$", stripped, re.I)
            if match:
                values = match.group(1).lower().split()
                self._set(result, "line_vty.transport_input", values, raw_line, line_number)
                return True
            match = re.match(r"^access-class\s+(.+)$", stripped, re.I)
            if match:
                self._set(result, "line_vty.access_class", match.group(1).strip(), raw_line, line_number)
                return True
        elif context and context.startswith("interface:"):
            name = context.split(":", 1)[1]
            prefix = f"interfaces.{name}"
            if stripped.lower() == "shutdown":
                self._set(result, f"{prefix}.shutdown", True, raw_line, line_number)
                return True
            if stripped.lower() == "no shutdown":
                self._set(result, f"{prefix}.shutdown", False, raw_line, line_number)
                return True
            match = re.match(r"^description\s+(.+)$", stripped, re.I)
            if match:
                self._set(result, f"{prefix}.description", match.group(1), raw_line, line_number)
                return True
            match = re.match(r"^ip\s+address\s+(\S+)\s+(\S+)", stripped, re.I)
            if match:
                self._set(result, f"{prefix}.ip_address", f"{match.group(1)} {match.group(2)}", raw_line, line_number)
                return True
            if stripped.lower() == "no cdp enable":
                self._set(result, f"{prefix}.cdp_disabled", True, raw_line, line_number)
                return True
        return False

    def _parse_global_line(self, result: NormalizationResult, stripped: str,
                           raw_line: str, line_number: int) -> bool:
        rules: list[tuple[str, Any, str]] = [
            (r"^service\s+password-encryption$", True, "service_hardening.password_encryption"),
            (r"^no\s+service\s+password-encryption$", False, "service_hardening.password_encryption"),
            (r"^no\s+service\s+finger$", True, "service_hardening.finger_disabled"),
            (r"^no\s+service\s+tcp-small-servers$", True, "service_hardening.tcp_small_servers_disabled"),
            (r"^no\s+service\s+udp-small-servers$", True, "service_hardening.udp_small_servers_disabled"),
            (r"^no\s+ip\s+bootp\s+server$", True, "service_hardening.bootp_server_disabled"),
            (r"^no\s+ip\s+http\s+server$", True, "service_hardening.http_server_disabled"),
            (r"^ip\s+http\s+secure-server$", True, "service_hardening.http_secure_server_enabled"),
            (r"^no\s+ip\s+source-route$", True, "access_control.source_route_disabled"),
            (r"^no\s+cdp\s+run$", True, "cdp.global_disabled"),
            (r"^aaa\s+new-model$", True, "aaa.new_model"),
            (r"^no\s+aaa\s+new-model$", False, "aaa.new_model"),
            (r"^ntp\s+authenticate$", True, "ntp.authenticate"),
            (r"^no\s+ntp\s+authenticate$", False, "ntp.authenticate"),
            (r"^service\s+timestamps\s+log\s+.+$", True, "logging.timestamps_enabled"),
            (r"^no\s+service\s+timestamps\s+log(?:\s+.+)?$", False, "logging.timestamps_enabled"),
        ]
        for pattern, value, field in rules:
            if re.match(pattern, stripped, re.I):
                self._set(result, field, value, raw_line, line_number)
                return True

        patterns: list[tuple[re.Pattern[str], str, Any]] = [
            (re.compile(r"^hostname\s+(.+)$", re.I), "device_info.hostname", lambda m: m.group(1).strip()),
            (re.compile(r"^ip\s+domain(?:-name)?\s+(.+)$", re.I), "device_info.domain_name", lambda m: m.group(1).strip()),
            (re.compile(r"^version\s+(.+)$", re.I), "device_info.os_version", lambda m: m.group(1).strip()),
            (re.compile(r"^enable\s+secret\s+(\d+)\s+.+$", re.I), "device_info.enable_secret_type", lambda m: int(m.group(1))),
            (re.compile(r"^ip\s+ssh\s+version\s+(\d+)$", re.I), "ssh.version", lambda m: int(m.group(1))),
            (re.compile(r"^ip\s+ssh\s+time-?out\s+(\d+)$", re.I), "ssh.timeout_seconds", lambda m: int(m.group(1))),
            (re.compile(r"^ip\s+ssh\s+authentication-retries\s+(\d+)$", re.I), "ssh.auth_retries", lambda m: int(m.group(1))),
            (re.compile(r"^aaa\s+authentication\s+login\s+(.+)$", re.I), "aaa.authentication_login", lambda m: m.group(1).strip()),
            (re.compile(r"^logging\s+buffered\s+(\d+).*$", re.I), "logging.buffered_size", lambda m: int(m.group(1))),
            (re.compile(r"^logging\s+trap\s+(.+)$", re.I), "logging.trap_severity", lambda m: m.group(1).strip()),
            (re.compile(r"^ntp\s+server\s+(\S+).*$", re.I), "ntp.servers", lambda m: m.group(1)),
        ]
        for pattern, field, value_fn in patterns:
            match = pattern.match(stripped)
            if match:
                self._set(result, field, value_fn(match), raw_line, line_number)
                return True

        if re.match(r"^snmp-server\s+(?:group|user)\s+.+\bv3\b", stripped, re.I):
            self._set(result, "snmp.v3_only", True, raw_line, line_number)
            return True
        community = re.match(r"^(no\s+)?snmp-server\s+community\s+(\S+).*$", stripped, re.I)
        if community:
            is_default = community.group(2).lower() in {"public", "private"}
            if is_default:
                self._set(result, "snmp.default_communities_removed", bool(community.group(1)), raw_line, line_number)
            else:
                self._set(result, "snmp.v3_only", False, raw_line, line_number)
            return True
        return False

    def _apply_learned_mapping(self, result: NormalizationResult, raw_line: str,
                               line_number: int, context: str | None) -> bool:
        if self._learned_mapping_resolver is None:
            return False
        match = self._learned_mapping_resolver.resolve(
            vendor=self.vendor, raw_line=raw_line, line_number=line_number, context=context
        )
        if match is None:
            return False
        result.findings.append(NormalizedFinding(
            schema_field=match.schema_field, field_value=match.field_value,
            raw_source_line=raw_line, line_number=line_number,
            confidence=Confidence.CONFIRMED, mapping_source=MappingSource.LEARNED_MAPPING,
        ))
        return True

    @staticmethod
    def _set(result: NormalizationResult, field: str, value: Any,
             raw_line: str, line_number: int) -> None:
        target: Any = result.config
        parts = field.split(".")
        for part in parts[:-1]:
            target = target[part] if isinstance(target, dict) else getattr(target, part)
        name = parts[-1]
        if isinstance(target, dict):
            target[name] = value
        else:
            current = getattr(target, name)
            if isinstance(current, list):
                if isinstance(value, list):
                    current[:] = value
                elif value not in current:
                    current.append(value)
            else:
                setattr(target, name, value)
        result.findings.append(NormalizedFinding(
            schema_field=field, field_value=value, raw_source_line=raw_line,
            line_number=line_number, confidence=Confidence.CONFIRMED,
            mapping_source=MappingSource.PARSER,
        ))
