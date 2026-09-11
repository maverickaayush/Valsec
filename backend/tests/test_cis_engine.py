"""Focused deterministic CIS Cisco IOS compliance-engine tests."""
import os
import sys
from dataclasses import replace

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from compliance.cis_cisco_ios import CIS_CISCO_IOS_CONTROLS, FRAMEWORK
from compliance.engine import ComplianceVerdict, calculate_compliance_score, evaluate_cis_cisco_ios
from normalizer.schema import InterfaceSettings, VendorNeutralConfig


EXPECTED_CONTROLS = {
    "1.1.1": ("Ensure 'service password-encryption' is enabled", "Medium"),
    "1.1.2": ("Ensure 'enable secret' is configured using modern hashing", "Critical"),
    "1.2.1": ("Ensure 'no service finger' is configured", "Low"),
    "1.2.2": ("Ensure 'no ip http server' is configured", "Medium"),
    "1.2.3": ("Ensure 'ip http secure-server' is configured if HTTP management is required", "Medium"),
    "1.2.4": ("Ensure 'no service tcp-small-servers' is configured", "Medium"),
    "1.2.5": ("Ensure 'no service udp-small-servers' is configured", "Medium"),
    "1.2.6": ("Ensure 'no ip bootp server' is configured", "Low"),
    "1.3.1": ("Ensure 'no ip source-route' is configured", "Medium"),
    "1.3.2": ("Ensure 'no ip proxy-arp' is configured on all untrusted interfaces", "Low"),
    "1.4.1": ("Ensure login and MOTD warning banners are configured", "Low"),
    "1.5.1": ("Ensure console 'exec-timeout' is configured at 10 minutes or less", "Medium"),
    "1.5.2": ("Ensure VTY 'exec-timeout' is configured at 10 minutes or less", "Medium"),
    "1.5.3": ("Ensure VTY 'transport input ssh' is configured with no Telnet", "Critical"),
    "1.5.4": ("Ensure 'ip ssh version 2' is enabled", "High"),
    "1.5.5": ("Ensure 'ip ssh time-out' is configured at 60 seconds or less", "Low"),
    "1.5.6": ("Ensure 'ip ssh authentication-retries' is configured at 3 or less", "Medium"),
    "1.6.1": ("Ensure 'logging buffered' is enabled with at least 64000 bytes", "Medium"),
    "1.6.2": ("Ensure log timestamps are enabled", "Low"),
    "1.7.1": ("Ensure NTP servers are configured", "Medium"),
    "1.8.1": ("Ensure SNMPv3 is used and default community strings are removed", "High"),
    "1.9.1": ("Ensure 'aaa new-model' is enabled", "High"),
    "1.10.1": ("Ensure CDP is disabled", "Low"),
}


def compliant_config():
    config = VendorNeutralConfig()
    config.service_hardening.password_encryption = True
    config.device_info.enable_secret_type = 9
    config.service_hardening.finger_disabled = True
    config.service_hardening.http_server_disabled = True
    config.service_hardening.tcp_small_servers_disabled = True
    config.service_hardening.udp_small_servers_disabled = True
    config.service_hardening.bootp_server_disabled = True
    config.access_control.source_route_disabled = True
    config.access_control.banner_motd = "Authorized access only"
    config.access_control.banner_login = "Authorized access only"
    config.line_console.exec_timeout_minutes = 10
    config.line_vty.exec_timeout_minutes = 10
    config.line_vty.transport_input = ["ssh"]
    config.ssh.version = 2
    config.ssh.timeout_seconds = 60
    config.ssh.auth_retries = 3
    config.logging.buffered_size = 64000
    config.logging.timestamps_enabled = True
    config.ntp.servers = ["192.0.2.1"]
    config.snmp.v3_only = True
    config.snmp.default_communities_removed = True
    config.aaa.new_model = True
    config.cdp.global_disabled = True
    return config


def results_by_id(config):
    return {result.control_id: result for result in evaluate_cis_cisco_ios(config).results}


class TestCatalogue:
    def test_rule_ids_titles_severities_and_framework_are_regression_protected(self):
        assert len(CIS_CISCO_IOS_CONTROLS) == 23
        assert {rule.control_id: (rule.title, rule.severity) for rule in CIS_CISCO_IOS_CONTROLS} == EXPECTED_CONTROLS
        assert all(rule.framework == FRAMEWORK for rule in CIS_CISCO_IOS_CONTROLS)
        assert all(rule.remediation_reference == f"cisco_remediation:{rule.control_id}" for rule in CIS_CISCO_IOS_CONTROLS)


class TestEvaluations:
    def test_compliant_input_passes_every_applicable_rule(self):
        results = results_by_id(compliant_config())
        assert {key for key, value in results.items() if value.verdict == ComplianceVerdict.NOT_APPLICABLE} == {"1.2.3", "1.3.2"}
        assert all(value.verdict == ComplianceVerdict.PASS for key, value in results.items() if key not in {"1.2.3", "1.3.2"})

    @pytest.mark.parametrize("control_id, mutate", [
        ("1.1.1", lambda c: setattr(c.service_hardening, "password_encryption", False)),
        ("1.1.2", lambda c: setattr(c.device_info, "enable_secret_type", 7)),
        ("1.2.1", lambda c: setattr(c.service_hardening, "finger_disabled", False)),
        ("1.2.2", lambda c: setattr(c.service_hardening, "http_server_disabled", False)),
        ("1.2.3", lambda c: (setattr(c.service_hardening, "http_server_disabled", False), setattr(c.service_hardening, "http_secure_server_enabled", False))),
        ("1.2.4", lambda c: setattr(c.service_hardening, "tcp_small_servers_disabled", False)),
        ("1.2.5", lambda c: setattr(c.service_hardening, "udp_small_servers_disabled", False)),
        ("1.2.6", lambda c: setattr(c.service_hardening, "bootp_server_disabled", False)),
        ("1.3.1", lambda c: setattr(c.access_control, "source_route_disabled", False)),
        ("1.4.1", lambda c: setattr(c.access_control, "banner_login", None)),
        ("1.5.1", lambda c: setattr(c.line_console, "exec_timeout_minutes", 11)),
        ("1.5.2", lambda c: setattr(c.line_vty, "exec_timeout_minutes", 11)),
        ("1.5.3", lambda c: setattr(c.line_vty, "transport_input", ["ssh", "telnet"])),
        ("1.5.4", lambda c: setattr(c.ssh, "version", 1)),
        ("1.5.5", lambda c: setattr(c.ssh, "timeout_seconds", 61)),
        ("1.5.6", lambda c: setattr(c.ssh, "auth_retries", 4)),
        ("1.6.1", lambda c: setattr(c.logging, "buffered_size", 63999)),
        ("1.6.2", lambda c: setattr(c.logging, "timestamps_enabled", False)),
        ("1.7.1", lambda c: setattr(c.ntp, "servers", [""])),
        ("1.8.1", lambda c: setattr(c.snmp, "v3_only", False)),
        ("1.9.1", lambda c: setattr(c.aaa, "new_model", False)),
        ("1.10.1", lambda c: setattr(c.cdp, "global_disabled", False)),
    ])
    def test_each_evaluable_rule_has_a_deterministic_fail_path(self, control_id, mutate):
        config = compliant_config()
        mutate(config)
        assert results_by_id(config)[control_id].verdict == ComplianceVerdict.FAIL

    def test_proxy_arp_supports_future_explicit_interface_evidence(self):
        config = compliant_config()
        interface = InterfaceSettings(name="GigabitEthernet0/0")
        interface.proxy_arp_disabled = True
        config.interfaces[interface.name] = interface
        assert results_by_id(config)["1.3.2"].verdict == ComplianceVerdict.PASS
        interface.proxy_arp_disabled = False
        assert results_by_id(config)["1.3.2"].verdict == ComplianceVerdict.FAIL

    def test_missing_evidence_is_not_applicable_not_pass(self):
        report = evaluate_cis_cisco_ios(VendorNeutralConfig())
        assert report.total_passed == 0
        assert report.total_failed == 0
        assert report.total_na == 23
        assert report.compliance_score == 0.0

    def test_http_management_condition_and_interface_cdp_alternative(self):
        config = VendorNeutralConfig()
        config.service_hardening.http_server_disabled = False
        config.service_hardening.http_secure_server_enabled = True
        config.interfaces["GigabitEthernet0/0"] = InterfaceSettings(cdp_disabled=True)
        values = results_by_id(config)
        assert values["1.2.3"].verdict == ComplianceVerdict.PASS
        assert values["1.10.1"].verdict == ComplianceVerdict.PASS


class TestScoring:
    def test_score_excludes_na_controls_and_is_repeatable(self):
        config = compliant_config()
        config.service_hardening.password_encryption = False
        first = evaluate_cis_cisco_ios(config)
        second = evaluate_cis_cisco_ios(config)
        assert first == second
        assert first.total_passed == 20
        assert first.total_failed == 1
        assert first.total_na == 2
        assert first.compliance_score == pytest.approx(95.24)
        assert calculate_compliance_score(first.results) == first.compliance_score

    def test_severity_is_preserved_in_results(self):
        results = results_by_id(compliant_config())
        assert results["1.1.2"].severity == "Critical"
        assert results["1.5.3"].severity == "Critical"
        assert results["1.5.4"].severity == "High"
        assert results["1.2.1"].severity == "Low"
