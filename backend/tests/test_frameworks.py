"""Deterministic multi-framework catalogue tests."""
from compliance.catalogues import FRAMEWORKS, get_controls, get_framework_metadata
from compliance.engine import ComplianceVerdict, evaluate_compliance
from tests.test_cis_engine import compliant_config


def test_all_registered_frameworks_have_working_deterministic_catalogues():
    config = compliant_config()
    expected_counts = {
        "cis_cisco_ios_v1": 23,
        "nist_sp_800_53_rev5": 8,
        "disa_stig_network_v1": 6,
        "iso_iec_27001_2022": 6,
    }
    assert set(FRAMEWORKS) == set(expected_counts)
    for key, count in expected_counts.items():
        report = evaluate_compliance(config, key, "cisco")
        assert len(report.results) == count == len(get_controls(key, "cisco"))
        assert report.total_failed == 0
        assert report.compliance_score == 100.0
        assert all(
            result.verdict in {ComplianceVerdict.PASS, ComplianceVerdict.NOT_APPLICABLE}
            for result in report.results
        )
        assert all(result.framework for result in report.results)


def test_framework_results_are_repeatable_and_catalogues_are_distinct():
    config = compliant_config()
    config.ssh.version = 1
    for key in FRAMEWORKS:
        assert evaluate_compliance(config, key, "cisco") == evaluate_compliance(config, key, "cisco")
    assert get_framework_metadata("cis_cisco_ios_v1", "cisco").title == "CIS Cisco IOS Benchmark"
    assert get_framework_metadata("cis_cisco_ios_v1", "juniper").title == "CIS Juniper JunOS Benchmark"
    assert get_framework_metadata("nist_sp_800_53_rev5", "juniper").version == "Rev. 5"


def test_missing_evidence_remains_not_applicable_across_frameworks():
    from normalizer.schema import VendorNeutralConfig
    for key in FRAMEWORKS:
        report = evaluate_compliance(VendorNeutralConfig(), key, "cisco")
        assert report.total_passed == 0
        assert report.total_failed == 0
        assert report.total_na == len(report.results)
