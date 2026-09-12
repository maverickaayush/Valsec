"""Regression checks for the three judge-demo Cisco configurations."""
from pathlib import Path
from unittest.mock import MagicMock

from compliance.engine import ComplianceVerdict, evaluate_cis_cisco_ios
from normalizer.cisco_ios import CiscoIOSNormalizer
from training.matcher import DatabaseLearnedMappingResolver


SAMPLES = Path(__file__).parent / "sample_configs"


def _parse(name: str, resolver=None):
    return CiscoIOSNormalizer(resolver).parse((SAMPLES / name).read_text())


def test_hardened_demo_is_fully_compliant_without_unknown_syntax():
    normalized = _parse("cisco_hardened.cfg")
    report = evaluate_cis_cisco_ios(normalized.config)
    assert normalized.unknown_lines == []
    assert report.compliance_score == 100.0
    assert report.total_passed == 21
    assert report.total_failed == 0
    assert report.total_na == 2


def test_vulnerable_demo_has_deterministic_failures_and_no_training_gate():
    normalized = _parse("cisco_vulnerable.cfg")
    report = evaluate_cis_cisco_ios(normalized.config)
    failures = {result.control_id for result in report.results if result.verdict == ComplianceVerdict.FAIL}
    assert normalized.unknown_lines == []
    assert {"1.1.1", "1.1.2", "1.5.1", "1.5.2", "1.5.3", "1.5.4"} <= failures
    assert report.total_failed >= 10


def test_unseen_demo_pauses_then_reuses_operator_mapping():
    first = _parse("cisco_unseen_syntax.cfg")
    assert [line.raw_source_line for line in first.unknown_lines] == [
        "vendor ssh-protocol generation 2"
    ]

    mapping = MagicMock(
        schema_field="ssh.version",
        examples=[{"raw_line": "vendor ssh-protocol generation 2", "field_value": 2}],
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = mapping
    resolver = DatabaseLearnedMappingResolver(db)

    resumed = _parse("cisco_unseen_syntax.cfg", resolver)
    second = _parse("cisco_unseen_syntax.cfg", resolver)
    assert resumed.unknown_lines == second.unknown_lines == []
    assert resumed.config.ssh.version == second.config.ssh.version == 2
    assert evaluate_cis_cisco_ios(resumed.config).compliance_score == 100.0
    assert evaluate_cis_cisco_ios(second.config).compliance_score == 100.0
