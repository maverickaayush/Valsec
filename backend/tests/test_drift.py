from types import SimpleNamespace
from pathlib import Path

from compliance.drift import build_drift_report
from compliance.engine import evaluate_compliance
from normalizer.cisco_ios import CiscoIOSNormalizer


def result(control_id, verdict, severity="High"):
    return SimpleNamespace(
        control_id=control_id, framework="NIST", title=f"Control {control_id}",
        severity=severity, verdict=verdict,
    )


def test_drift_classifies_control_changes_and_score_delta_deterministically():
    before = [result("A", "PASS"), result("B", "FAIL"), result("C", "FAIL"), result("D", "PASS")]
    after = [result("A", "FAIL"), result("B", "PASS"), result("C", "FAIL"), result("D", "PASS")]
    report = build_drift_report(
        before, after,
        "hostname edge\nservice ssh\n",
        "hostname edge\nno service ssh\n",
        baseline_config_id="before-id", compare_config_id="after-id",
    )
    assert report.score_before == report.score_after == 50.0
    assert [item.control_id for item in report.newly_failed] == ["A"]
    assert [item.control_id for item in report.newly_passed] == ["B"]
    assert [item.control_id for item in report.still_failing] == ["C"]
    assert report.unchanged_count == 2
    assert report.raw_config_diff.startswith("--- before\n+++ after")
    assert "-service ssh" in report.raw_config_diff and "+no service ssh" in report.raw_config_diff


def test_drift_without_baseline_has_none_score_and_new_failures():
    report = build_drift_report(
        None, [result("A", "FAIL")], "", "hostname edge\n",
        baseline_config_id=None, compare_config_id="current",
    )
    assert report.score_before is None and report.score_after == 0.0
    assert report.newly_failed[0].previous_verdict is None


def test_cisco_fixture_before_after_score_and_control_delta():
    samples = Path(__file__).parent / "sample_configs"
    vulnerable = (samples / "cisco_vulnerable.cfg").read_text()
    hardened = (samples / "cisco_hardened.cfg").read_text()
    before = evaluate_compliance(CiscoIOSNormalizer().parse(vulnerable).config, "cis_cisco_ios_v1", "cisco")
    after = evaluate_compliance(CiscoIOSNormalizer().parse(hardened).config, "cis_cisco_ios_v1", "cisco")
    improved = build_drift_report(
        before.results, after.results, vulnerable, hardened,
        baseline_config_id="vulnerable", compare_config_id="hardened",
    )
    regressed = build_drift_report(
        after.results, before.results, hardened, vulnerable,
        baseline_config_id="hardened", compare_config_id="vulnerable",
    )
    assert improved.score_after > improved.score_before
    assert improved.newly_passed
    assert regressed.newly_failed
