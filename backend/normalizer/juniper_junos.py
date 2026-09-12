"""Deterministic Juniper JunOS set-style and hierarchical configuration adapter."""
from __future__ import annotations

import re
from typing import Any

from .cisco_ios import LearnedMappingResolver
from .schema import (
    Confidence, InterfaceSettings, MappingSource, NormalizationResult,
    NormalizedFinding, UnknownLine,
)


class JuniperJunosNormalizer:
    """Normalize representative JunOS security settings into the shared schema."""

    vendor = "juniper"

    def __init__(self, learned_mapping_resolver: LearnedMappingResolver | None = None):
        self._learned_mapping_resolver = learned_mapping_resolver

    def parse(self, raw_config: str) -> NormalizationResult:
        result = NormalizationResult()
        statements = self._statements(raw_config)
        saw_https = False
        saw_http = False
        saw_snmp_v3 = False
        saw_default_community = False

        for command, raw_line, line_number, context in statements:
            normalized = re.sub(r"\s+", " ", command.strip().rstrip(";")).strip()
            action = "set"
            if normalized.startswith(("set ", "delete ", "deactivate ")):
                action, normalized = normalized.split(" ", 1)
            lower = normalized.lower()

            match = re.match(r"^(?:system )?host-name\s+(.+)$", normalized, re.I)
            if match:
                self._set(result, "device_info.hostname", self._unquote(match.group(1)), raw_line, line_number)
                continue
            match = re.match(r"^(?:system )?version\s+(.+)$", normalized, re.I)
            if match:
                self._set(result, "device_info.os_version", self._unquote(match.group(1)), raw_line, line_number)
                continue
            match = re.match(r"^system root-authentication encrypted-password\s+(.+)$", normalized, re.I)
            if match:
                password = self._unquote(match.group(1))
                self._set(result, "device_info.enable_secret_type", 9 if password.startswith("$") else 0, raw_line, line_number)
                self._set(result, "service_hardening.password_encryption", password.startswith("$"), raw_line, line_number)
                continue
            if lower == "system services finger":
                self._set(result, "service_hardening.finger_disabled", action != "set", raw_line, line_number)
                continue
            if lower == "system services web-management http":
                saw_http = action == "set"
                self._set(result, "service_hardening.http_server_disabled", action != "set", raw_line, line_number)
                continue
            if lower.startswith("system services web-management https"):
                saw_https = action == "set"
                self._set(result, "service_hardening.http_secure_server_enabled", action == "set", raw_line, line_number)
                continue
            match = re.match(r"^system login message\s+(.+)$", normalized, re.I)
            if match:
                message = self._unquote(match.group(1))
                self._set(result, "access_control.banner_login", message, raw_line, line_number)
                self._set(result, "access_control.banner_motd", message, raw_line, line_number)
                continue
            match = re.match(r"^system login idle-timeout\s+(\d+(?:\.\d+)?)$", normalized, re.I)
            if match:
                value = float(match.group(1))
                value = int(value) if value.is_integer() else value
                self._set(result, "line_console.exec_timeout_minutes", value, raw_line, line_number)
                self._set(result, "line_vty.exec_timeout_minutes", value, raw_line, line_number)
                continue
            if lower == "system services ssh":
                self._set(result, "line_vty.transport_input", ["ssh"], raw_line, line_number)
                continue
            match = re.match(r"^system services ssh protocol-version\s+(?:v)?(\d+)$", normalized, re.I)
            if match:
                self._set(result, "ssh.version", int(match.group(1)), raw_line, line_number)
                self._set(result, "line_vty.transport_input", ["ssh"], raw_line, line_number)
                continue
            match = re.match(r"^system services ssh client-alive-interval\s+(\d+)$", normalized, re.I)
            if match:
                self._set(result, "ssh.timeout_seconds", int(match.group(1)), raw_line, line_number)
                continue
            match = re.match(r"^system services ssh max-authentication-retries\s+(\d+)$", normalized, re.I)
            if match:
                self._set(result, "ssh.auth_retries", int(match.group(1)), raw_line, line_number)
                continue
            match = re.match(r"^system authentication-order\s+(.+)$", normalized, re.I)
            if match:
                methods = self._unquote(match.group(1))
                self._set(result, "aaa.new_model", action == "set", raw_line, line_number)
                self._set(result, "aaa.authentication_login", methods, raw_line, line_number)
                continue
            match = re.match(r"^system syslog file\s+\S+ archive size\s+(\d+)([kmg])?$", normalized, re.I)
            if match:
                multiplier = {None: 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[match.group(2).lower() if match.group(2) else None]
                self._set(result, "logging.buffered_size", int(match.group(1)) * multiplier, raw_line, line_number)
                continue
            match = re.match(r"^system syslog (?:host|file)\s+\S+\s+\S+\s+(\S+)", normalized, re.I)
            if match:
                self._set(result, "logging.trap_severity", match.group(1).lower(), raw_line, line_number)
                self._set(result, "logging.timestamps_enabled", action == "set", raw_line, line_number)
                continue
            match = re.match(r"^system ntp server\s+(\S+)", normalized, re.I)
            if match:
                self._set(result, "ntp.servers", [match.group(1)], raw_line, line_number)
                continue
            if lower.startswith(("system ntp authentication-key", "system ntp trusted-key")):
                self._set(result, "ntp.authenticate", action == "set", raw_line, line_number)
                continue
            if lower.startswith("snmp v3"):
                saw_snmp_v3 = action == "set"
                self._set(result, "snmp.v3_only", action == "set", raw_line, line_number)
                continue
            match = re.match(r"^snmp community\s+(public|private)(?:\s|$)", normalized, re.I)
            if match:
                saw_default_community = action == "set"
                self._set(result, "snmp.default_communities_removed", action != "set", raw_line, line_number)
                continue
            if lower == "protocols lldp interface all disable":
                self._set(result, "cdp.global_disabled", action == "set", raw_line, line_number)
                continue
            match = re.match(r"^interfaces\s+(\S+)\s+disable$", normalized, re.I)
            if match:
                name = match.group(1)
                result.config.interfaces.setdefault(name, InterfaceSettings(name=name))
                result.config.interfaces[name].shutdown = action == "set"
                result.findings.append(NormalizedFinding(
                    f"interfaces.{name}.shutdown", action == "set", raw_line, line_number,
                    Confidence.CONFIRMED, MappingSource.PARSER,
                ))
                continue

            if self._apply_learned_mapping(result, raw_line, line_number, context):
                continue
            result.unknown_lines.append(UnknownLine(raw_line, line_number, context))

        # In a complete JunOS configuration, HTTPS present without HTTP and
        # SNMPv3 present without a default community are explicit absence facts.
        if saw_https and not saw_http and result.config.service_hardening.http_server_disabled is None:
            result.config.service_hardening.http_server_disabled = True
        if saw_snmp_v3 and not saw_default_community and result.config.snmp.default_communities_removed is None:
            result.config.snmp.default_communities_removed = True
        return result

    @staticmethod
    def _statements(raw_config: str) -> list[tuple[str, str, int, str | None]]:
        statements: list[tuple[str, str, int, str | None]] = []
        stack: list[str] = []
        for line_number, raw_line in enumerate(raw_config.splitlines(), 1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith(("#", "/*", "*")):
                continue
            if stripped in {"}", "};"}:
                if stack:
                    stack.pop()
                continue
            if stripped.endswith("{"):
                stack.append(stripped[:-1].strip())
                continue
            if stripped.startswith(("set ", "delete ", "deactivate ")):
                statements.append((stripped.rstrip(";"), raw_line, line_number, None))
                continue
            if stripped.endswith(";"):
                command = " ".join([*stack, stripped[:-1].strip()])
                statements.append((command, raw_line, line_number, " ".join(stack) or None))
                continue
            # Preserve malformed or unfamiliar syntax for training.
            statements.append((" ".join([*stack, stripped]), raw_line, line_number, " ".join(stack) or None))
        return statements

    def _apply_learned_mapping(self, result: NormalizationResult, raw_line: str,
                               line_number: int, context: str | None) -> bool:
        if self._learned_mapping_resolver is None:
            return False
        match = self._learned_mapping_resolver.resolve(
            vendor=self.vendor, raw_line=raw_line, line_number=line_number, context=context
        )
        if match is None:
            return False
        self._assign(result, match.schema_field, match.field_value)
        result.findings.append(NormalizedFinding(
            match.schema_field, match.field_value, raw_line, line_number,
            Confidence.CONFIRMED, MappingSource.LEARNED_MAPPING,
        ))
        return True

    @staticmethod
    def _set(result: NormalizationResult, field: str, value: Any,
             raw_line: str, line_number: int) -> None:
        JuniperJunosNormalizer._assign(result, field, value)
        result.findings.append(NormalizedFinding(
            field, value, raw_line, line_number, Confidence.CONFIRMED, MappingSource.PARSER,
        ))

    @staticmethod
    def _assign(result: NormalizationResult, field: str, value: Any) -> bool:
        target: Any = result.config
        try:
            for part in field.split(".")[:-1]:
                target = getattr(target, part)
            name = field.rsplit(".", 1)[-1]
            current = getattr(target, name)
            if isinstance(current, list):
                for item in value if isinstance(value, list) else [value]:
                    if item not in current:
                        current.append(item)
            else:
                setattr(target, name, value)
            return True
        except (AttributeError, TypeError):
            return False

    @staticmethod
    def _unquote(value: str) -> str:
        value = value.strip()
        return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value
