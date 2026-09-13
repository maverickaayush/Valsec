"""Focused Fortinet FortiGate/FortiOS normalization and training tests."""
from pathlib import Path

from compliance.engine import ComplianceVerdict, evaluate_compliance
from normalizer.cisco_ios import MappingMatch
from normalizer.fortios import FortiOSNormalizer
from normalizer.schema import MappingSource


SAMPLE = Path(__file__).parent / "sample_configs" / "fortinet_hardened.conf"


def test_hardened_fortios_normalizes_real_blocks_and_passes_nist_catalogue():
    normalized = FortiOSNormalizer().parse(SAMPLE.read_text())

    assert normalized.unknown_lines == []
    assert normalized.config.device_info.hostname == "fortigate-edge-01"
    assert normalized.config.device_info.model == "FGT60F"
    assert normalized.config.device_info.os_version == "7.4.3"
    assert normalized.config.line_vty.exec_timeout_minutes == 10
    assert normalized.config.line_vty.transport_input == ["ssh", "https"]
    assert normalized.config.ssh.version == 2
    assert normalized.config.service_hardening.strong_crypto_enabled is True
    assert normalized.config.service_hardening.password_encryption is True
    assert normalized.config.logging.enabled is True
    assert normalized.config.ntp.enabled is True
    assert normalized.config.ntp.servers == ["192.0.2.10"]
    assert normalized.config.snmp.v3_only is True
    assert normalized.config.snmp.default_communities_removed is True
    policy = normalized.config.firewall_policies["1"]
    assert policy.action == "accept" and policy.logging_enabled is True

    report = evaluate_compliance(normalized.config, "nist_sp_800_53_rev5", "fortinet")
    assert report.total_passed == 7
    assert report.total_failed == 0
    assert report.compliance_score == 100.0
    assert all(result.verdict == ComplianceVerdict.PASS for result in report.results)


def test_fortios_vulnerable_values_fail_deterministically():
    normalized = FortiOSNormalizer().parse("""config system global
 set admintimeout 30
 set admin-ssh-v1 enable
 set strong-crypto disable
end
config system interface
 edit port1
  set allowaccess http telnet
 next
end
config log disk setting
 set status disable
end
config firewall policy
 edit 9
  set action accept
  set logtraffic disable
 next
end
""")
    report = evaluate_compliance(normalized.config, "nist_sp_800_53_rev5", "fortinet")
    failed = {result.control_id for result in report.results if result.verdict == ComplianceVerdict.FAIL}
    assert {"AC-12", "AC-17", "SC-13", "AU-2", "AU-12"} <= failed


def test_unknown_fortios_syntax_uses_vendor_scoped_learning_path():
    seen = []

    class Resolver:
        def resolve(self, *, vendor, raw_line, line_number, context):
            seen.append((vendor, raw_line, line_number, context))
            if raw_line.strip() == "set future-secure-mode enable":
                return MappingMatch("service_hardening.strong_crypto_enabled", True)
            return None

    learned = FortiOSNormalizer(Resolver()).parse("""config system global
 set hostname edge
 set future-secure-mode enable
 set another-future-setting strict
end
""")
    assert learned.config.service_hardening.strong_crypto_enabled is True
    assert any(finding.mapping_source == MappingSource.LEARNED_MAPPING for finding in learned.findings)
    assert [line.raw_source_line.strip() for line in learned.unknown_lines] == ["set another-future-setting strict"]
    assert all(item[0] == "fortinet" for item in seen)
