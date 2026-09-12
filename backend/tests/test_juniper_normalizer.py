"""Focused Juniper JunOS normalization and training-path tests."""
from pathlib import Path
from unittest.mock import MagicMock
from uuid import uuid4

from compliance.engine import ComplianceVerdict, evaluate_compliance
from normalizer.juniper_junos import JuniperJunosNormalizer
from normalizer.schema import MappingSource
from training.matcher import DatabaseLearnedMappingResolver


SAMPLE = Path(__file__).parent / "sample_configs" / "juniper_hardened.conf"


def test_hierarchical_junos_config_normalizes_and_passes_cis_catalogue():
    normalized = JuniperJunosNormalizer().parse(SAMPLE.read_text())
    assert normalized.unknown_lines == []
    assert normalized.config.device_info.hostname == "juniper-edge-01"
    assert normalized.config.device_info.os_version == "22.4R1.10"
    assert normalized.config.ssh.version == 2
    assert normalized.config.line_vty.transport_input == ["ssh"]
    assert normalized.config.line_vty.exec_timeout_minutes == 10
    assert normalized.config.logging.buffered_size == 1024 * 1024
    assert normalized.config.ntp.servers == ["192.0.2.10"]
    assert normalized.config.snmp.v3_only is True
    report = evaluate_compliance(normalized.config, "cis_cisco_ios_v1", "juniper")
    assert report.total_failed == 0
    assert report.total_passed == 11
    assert report.compliance_score == 100.0


def test_set_style_junos_and_unknown_line_enter_training_flow():
    normalized = JuniperJunosNormalizer().parse("""set system host-name branch-1
set system services ssh protocol-version v2
set system login idle-timeout 5
set system future-service secure-mode strict
""")
    assert normalized.config.device_info.hostname == "branch-1"
    assert normalized.config.ssh.version == 2
    assert normalized.config.line_console.exec_timeout_minutes == 5
    assert [line.raw_source_line for line in normalized.unknown_lines] == [
        "set system future-service secure-mode strict"
    ]


def test_learned_mapping_lookup_is_vendor_and_user_scoped():
    user_id = uuid4()
    mapping = MagicMock(
        user_id=user_id,
        vendor="juniper",
        schema_field="ssh.version",
        examples=[{"raw_line": "set system secure-shell generation 2", "field_value": 2}],
    )

    class Query:
        def __init__(self): self.vendor = self.user = None
        def filter(self, *criteria):
            for criterion in criteria:
                key = getattr(getattr(criterion, "left", None), "key", None)
                value = getattr(getattr(criterion, "right", None), "value", None)
                if key == "vendor": self.vendor = value
                if key == "user_id": self.user = value
            return self
        def first(self):
            return mapping if (self.vendor, self.user) == (mapping.vendor, mapping.user_id) else None

    db = MagicMock()
    db.query.side_effect = lambda *_: Query()
    line = "set system secure-shell generation 2"
    juniper = DatabaseLearnedMappingResolver(db, user_id)
    cisco = DatabaseLearnedMappingResolver(db, user_id)
    resolved = JuniperJunosNormalizer(juniper).parse(line)
    assert not resolved.unknown_lines
    assert resolved.findings[0].mapping_source == MappingSource.LEARNED_MAPPING
    assert resolved.config.ssh.version == 2
    assert cisco.resolve(vendor="cisco", raw_line=line, line_number=1, context=None) is None
    assert all(result.verdict in ComplianceVerdict for result in evaluate_compliance(
        resolved.config, "nist_sp_800_53_rev5", "juniper"
    ).results)
