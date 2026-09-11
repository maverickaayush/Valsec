"""Focused tests for deterministic Cisco IOS configuration normalization."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from normalizer.cisco_ios import CiscoIOSNormalizer, MappingMatch
from normalizer.schema import Confidence, MappingSource


CONFIG = """hostname core-rtr-01
ip domain-name example.internal
version 17.9
service password-encryption
no service finger
no service tcp-small-servers
no service udp-small-servers
no ip bootp server
no ip http server
ip http secure-server
no ip source-route
enable secret 9 $9$abc
ip ssh version 2
ip ssh time-out 60
ip ssh authentication-retries 3
aaa new-model
aaa authentication login default group radius local
logging buffered 16384 informational
logging trap warnings
service timestamps log datetime msec
snmp-server group SEC v3 priv
no snmp-server community public
ntp server 192.0.2.10 prefer
ntp authenticate
no cdp run
banner motd ^C
Authorized users only
^C
banner login #Login warning#
line con 0
 exec-timeout 5 30
 transport preferred ssh
line vty 0 4
 transport input ssh
 exec-timeout 10 0
 access-class MGMT-ONLY in
interface GigabitEthernet1/0/1
 description Uplink to core
 ip address 192.0.2.2 255.255.255.0
 no shutdown
 no cdp enable
custom future command enabled
"""


def _find(result, field):
    return [finding for finding in result.findings if finding.schema_field == field]


class TestCiscoIOSNormalizer:
    def test_normalizes_representative_global_and_hierarchical_syntax(self):
        result = CiscoIOSNormalizer().parse(CONFIG)
        config = result.config

        assert config.device_info.hostname == "core-rtr-01"
        assert config.device_info.enable_secret_type == 9
        assert config.service_hardening.password_encryption is True
        assert config.service_hardening.finger_disabled is True
        assert config.service_hardening.http_server_disabled is True
        assert config.ssh.version == 2
        assert config.ssh.timeout_seconds == 60
        assert config.line_console.exec_timeout_minutes == 330
        assert config.line_vty.transport_input == ["ssh"]
        assert config.line_vty.access_class == "MGMT-ONLY in"
        assert config.aaa.authentication_login == "default group radius local"
        assert config.logging.buffered_size == 16384
        assert config.snmp.v3_only is True
        assert config.snmp.default_communities_removed is True
        assert config.ntp.servers == ["192.0.2.10"]
        assert config.access_control.banner_motd == "Authorized users only"
        assert config.access_control.banner_login == "Login warning"
        interface = config.interfaces["GigabitEthernet1/0/1"]
        assert interface.ip_address == "192.0.2.2 255.255.255.0"
        assert interface.shutdown is False
        assert interface.cdp_disabled is True

    def test_parser_findings_have_source_and_confirmed_parser_provenance(self):
        result = CiscoIOSNormalizer().parse(CONFIG)
        finding = _find(result, "line_vty.transport_input")[0]
        assert finding.raw_source_line == " transport input ssh"
        assert finding.line_number > 0
        assert finding.field_value == ["ssh"]
        assert finding.confidence == Confidence.CONFIRMED
        assert finding.mapping_source == MappingSource.PARSER

    def test_unknown_lines_are_preserved_with_context(self):
        result = CiscoIOSNormalizer().parse(CONFIG)
        unknown = result.unknown_lines[-1]
        assert unknown.raw_source_line == "custom future command enabled"
        assert unknown.context == "interface:GigabitEthernet1/0/1"
        assert unknown.line_number == CONFIG.splitlines().index("custom future command enabled") + 1

    def test_learned_mapping_is_injected_not_coupled_to_database(self):
        class Resolver:
            calls = []

            def resolve(self, **kwargs):
                self.calls.append(kwargs)
                if kwargs["raw_line"].strip() == "vendor feature secure":
                    return MappingMatch("service_hardening.vendor_feature", True)
                return None

        resolver = Resolver()
        result = CiscoIOSNormalizer(resolver).parse("vendor feature secure\n")
        assert resolver.calls[0]["vendor"] == "cisco"
        finding = result.findings[0]
        assert finding.schema_field == "service_hardening.vendor_feature"
        assert finding.confidence == Confidence.CONFIRMED
        assert finding.mapping_source == MappingSource.LEARNED_MAPPING
        assert result.unknown_lines == []

    def test_syntax_variations_and_schema_serialization(self):
        result = CiscoIOSNormalizer().parse("""ip domain-name corp.example
ip ssh timeout 45
line console 0
 exec-timeout 7
line vty 0 15
 transport input telnet SSH
""")
        assert result.config.device_info.domain_name == "corp.example"
        assert result.config.ssh.timeout_seconds == 45
        assert result.config.line_console.exec_timeout_minutes == 420
        assert result.config.line_vty.transport_input == ["telnet", "ssh"]
        assert result.config.to_dict()["ssh"]["timeout_seconds"] == 45
