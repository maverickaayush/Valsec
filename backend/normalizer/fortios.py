"""Deterministic Fortinet FortiGate/FortiOS configuration adapter."""
from __future__ import annotations

import re
import shlex
from typing import Any

from .cisco_ios import LearnedMappingResolver
from .schema import (
    Confidence,
    FirewallPolicy,
    InterfaceSettings,
    MappingSource,
    NormalizationResult,
    NormalizedFinding,
    UnknownLine,
)


class FortiOSNormalizer:
    """Normalize supported FortiOS CLI blocks and fail closed on other syntax."""

    vendor = "fortinet"

    def __init__(self, learned_mapping_resolver: LearnedMappingResolver | None = None):
        self._learned_mapping_resolver = learned_mapping_resolver

    def parse(self, raw_config: str) -> NormalizationResult:
        result = NormalizationResult()
        stack: list[dict[str, str | None]] = []
        management_protocols: list[str] = []
        saw_allowaccess = False
        saw_snmp_v3 = False
        saw_default_community = False

        for line_number, raw_line in enumerate(raw_config.splitlines(), 1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                version = re.match(r"^#config-version=([A-Za-z0-9_-]+)-(\d+\.\d+(?:\.\d+)?)", stripped, re.I)
                if version:
                    self._set(result, "device_info.model", version.group(1), raw_line, line_number)
                    self._set(result, "device_info.os_version", version.group(2), raw_line, line_number)
                continue
            lower = stripped.lower()
            if lower.startswith("config "):
                stack.append({"section": stripped[7:].strip().lower(), "edit": None})
                continue
            if lower.startswith("edit "):
                if stack:
                    stack[-1]["edit"] = self._unquote(stripped[5:].strip())
                    self._ensure_record(result, stack)
                    continue
            if lower == "next":
                if stack:
                    stack[-1]["edit"] = None
                    continue
            if lower == "end":
                if stack:
                    stack.pop()
                    continue

            context = " > ".join(str(frame["section"]) for frame in stack) or None
            tokens = self._tokens(stripped)
            if len(tokens) >= 3 and tokens[0].lower() in {"set", "unset"}:
                action, key = tokens[0].lower(), tokens[1].lower()
                values = tokens[2:] if action == "set" else []
                value = values[0] if len(values) == 1 else values
                section = str(stack[-1]["section"]) if stack else ""
                edit = str(stack[-1]["edit"]) if stack and stack[-1]["edit"] is not None else None

                if section == "system global" and key == "hostname" and values:
                    self._set(result, "device_info.hostname", str(value), raw_line, line_number)
                    continue
                if section == "system global" and key in {"admintimeout", "admin-console-timeout"} and values and self._number(values[0]) is not None:
                    timeout = self._number(values[0])
                    self._set(result, "line_vty.exec_timeout_minutes", timeout, raw_line, line_number)
                    self._set(result, "line_console.exec_timeout_minutes", timeout, raw_line, line_number)
                    continue
                if section == "system global" and key == "admin-ssh-v1" and values:
                    self._set(result, "ssh.version", 2 if values[0].lower() == "disable" else 1, raw_line, line_number)
                    continue
                if section == "system global" and key == "strong-crypto" and values:
                    self._set(result, "service_hardening.strong_crypto_enabled", values[0].lower() == "enable", raw_line, line_number)
                    continue
                if section == "system interface" and edit:
                    interface = result.config.interfaces.setdefault(edit, InterfaceSettings(name=edit))
                    if key in {"alias", "description"} and values:
                        interface.description = " ".join(values)
                        self._finding(result, f"interfaces.{edit}.description", interface.description, raw_line, line_number)
                        continue
                    if key == "ip" and values:
                        interface.ip_address = " ".join(values)
                        self._finding(result, f"interfaces.{edit}.ip_address", interface.ip_address, raw_line, line_number)
                        continue
                    if key == "status" and values:
                        interface.shutdown = values[0].lower() == "down"
                        self._finding(result, f"interfaces.{edit}.shutdown", interface.shutdown, raw_line, line_number)
                        continue
                    if key == "allowaccess" and values:
                        saw_allowaccess = True
                        allowed = [item.lower() for item in values]
                        for protocol in ("ssh", "https", "http", "telnet"):
                            if protocol in allowed and protocol not in management_protocols:
                                management_protocols.append(protocol)
                        self._set(result, "line_vty.transport_input", management_protocols, raw_line, line_number)
                        continue
                if section == "system admin" and edit and key == "password" and values:
                    protected = values[0].upper() == "ENC"
                    current = result.config.service_hardening.password_encryption
                    self._set(result, "service_hardening.password_encryption", protected if current is None else current and protected, raw_line, line_number)
                    continue
                if section in {"user radius", "user tacacs+", "user ldap"} and edit and key in {"server", "remote-auth"} and values:
                    self._set(result, "aaa.new_model", True, raw_line, line_number)
                    self._set(result, "aaa.authentication_login", section.removeprefix("user "), raw_line, line_number)
                    continue
                if section in {"log disk setting", "log fortianalyzer setting", "log syslogd setting"} and key == "status" and values:
                    self._set(result, "logging.enabled", values[0].lower() == "enable", raw_line, line_number)
                    continue
                if section == "system ntp" and key == "ntpsync" and values:
                    self._set(result, "ntp.enabled", values[0].lower() == "enable", raw_line, line_number)
                    continue
                if section == "ntpserver" and edit and key == "server" and values:
                    self._set(result, "ntp.servers", [values[0]], raw_line, line_number)
                    continue
                if section == "system snmp user" and edit and key == "security-level" and values:
                    secure = values[0].lower() in {"auth-priv", "auth-no-priv"}
                    saw_snmp_v3 = saw_snmp_v3 or secure
                    self._set(result, "snmp.v3_only", secure, raw_line, line_number)
                    continue
                if section == "system snmp community" and edit and key == "name" and values:
                    if values[0].casefold() in {"public", "private"}:
                        saw_default_community = True
                        self._set(result, "snmp.default_communities_removed", False, raw_line, line_number)
                    else:
                        self._finding(result, "snmp.community", values[0], raw_line, line_number)
                    continue
                if section == "firewall policy" and edit:
                    policy = result.config.firewall_policies.setdefault(edit, FirewallPolicy(policy_id=edit))
                    if self._set_policy(policy, key, values):
                        self._finding(result, f"firewall_policies.{edit}.{key}", getattr(policy, self._policy_attribute(key)), raw_line, line_number)
                        continue

            if self._apply_learned_mapping(result, raw_line, line_number, context):
                continue
            result.unknown_lines.append(UnknownLine(raw_line, line_number, context))

        if saw_allowaccess:
            result.config.service_hardening.http_server_disabled = "http" not in management_protocols
            result.config.service_hardening.http_secure_server_enabled = "https" in management_protocols
        if saw_snmp_v3 and not saw_default_community:
            result.config.snmp.default_communities_removed = True
        return result

    @staticmethod
    def _tokens(line: str) -> list[str]:
        try:
            return shlex.split(line, comments=False, posix=True)
        except ValueError:
            return line.split()

    @staticmethod
    def _number(value: str) -> int | float | None:
        try:
            number = float(value)
            return int(number) if number.is_integer() else number
        except ValueError:
            return None

    @staticmethod
    def _unquote(value: str) -> str:
        value = value.strip()
        return value[1:-1] if len(value) >= 2 and value[0] == value[-1] == '"' else value

    @staticmethod
    def _policy_attribute(key: str) -> str:
        return {
            "name": "name", "srcintf": "source_interfaces", "dstintf": "destination_interfaces",
            "srcaddr": "source_addresses", "dstaddr": "destination_addresses", "service": "services",
            "action": "action", "status": "enabled", "logtraffic": "logging_enabled",
        }[key]

    @classmethod
    def _set_policy(cls, policy: FirewallPolicy, key: str, values: list[str]) -> bool:
        if key not in {"name", "srcintf", "dstintf", "srcaddr", "dstaddr", "service", "action", "status", "logtraffic"} or not values:
            return False
        attribute = cls._policy_attribute(key)
        if key in {"srcintf", "dstintf", "srcaddr", "dstaddr", "service"}:
            setattr(policy, attribute, values)
        elif key == "status":
            setattr(policy, attribute, values[0].lower() != "disable")
        elif key == "logtraffic":
            setattr(policy, attribute, values[0].lower() not in {"disable", "utm"})
        else:
            setattr(policy, attribute, " ".join(values))
        return True

    @staticmethod
    def _ensure_record(result: NormalizationResult, stack: list[dict[str, str | None]]) -> None:
        section = str(stack[-1]["section"])
        edit = stack[-1]["edit"]
        if edit is None:
            return
        if section == "system interface":
            result.config.interfaces.setdefault(str(edit), InterfaceSettings(name=str(edit)))
        elif section == "firewall policy":
            result.config.firewall_policies.setdefault(str(edit), FirewallPolicy(policy_id=str(edit)))

    def _apply_learned_mapping(self, result: NormalizationResult, raw_line: str,
                               line_number: int, context: str | None) -> bool:
        if self._learned_mapping_resolver is None:
            return False
        match = self._learned_mapping_resolver.resolve(
            vendor=self.vendor, raw_line=raw_line, line_number=line_number, context=context
        )
        if match is None or not self._assign(result, match.schema_field, match.field_value):
            return False
        result.findings.append(NormalizedFinding(
            match.schema_field, match.field_value, raw_line, line_number,
            Confidence.CONFIRMED, MappingSource.LEARNED_MAPPING,
        ))
        return True

    @classmethod
    def _set(cls, result: NormalizationResult, field: str, value: Any,
             raw_line: str, line_number: int) -> None:
        cls._assign(result, field, value)
        cls._finding(result, field, value, raw_line, line_number)

    @staticmethod
    def _finding(result: NormalizationResult, field: str, value: Any,
                 raw_line: str, line_number: int) -> None:
        result.findings.append(NormalizedFinding(
            field, value, raw_line, line_number, Confidence.CONFIRMED, MappingSource.PARSER,
        ))

    @staticmethod
    def _assign(result: NormalizationResult, field: str, value: Any) -> bool:
        parts = field.split(".")
        if len(parts) != 2:
            return False
        target = getattr(result.config, parts[0], None)
        if target is None or not hasattr(target, parts[1]):
            return False
        current = getattr(target, parts[1])
        if isinstance(current, list):
            for item in value if isinstance(value, list) else [value]:
                if item not in current:
                    current.append(item)
        else:
            setattr(target, parts[1], value)
        return True
