"""Deterministic Cisco remediation template tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from remediation.cisco_remediation import _TEMPLATES, generate_remediation
from remediation.juniper_remediation import generate_juniper_remediation
from remediation.service import deterministic_remediation, resolve_remediation


def test_every_template_is_a_complete_cisco_command_block():
    for control_id in _TEMPLATES:
        remediation = generate_remediation(control_id)
        assert remediation.is_fallback is False
        assert remediation.source == "deterministic_template"
        assert remediation.cli.startswith("configure terminal\n")
        assert remediation.cli.endswith("\nend\nwrite memory")


def test_major_failed_controls_have_expected_commands_and_do_not_change_verdicts():
    assert "service password-encryption" in generate_remediation("1.1.1").cli
    assert "transport input ssh" in generate_remediation("1.5.3").cli
    assert "no cdp run" in generate_remediation("1.10.1").cli


def test_missing_template_is_explicitly_marked_as_ai_fallback_request():
    remediation = generate_remediation("1.3.2")
    assert remediation.cli is None
    assert remediation.is_fallback is True
    assert remediation.source == "ai_generated_fallback_required"


def test_juniper_templates_are_exact_commit_blocks():
    remediation = generate_juniper_remediation("ssh.version")
    assert remediation.is_fallback is False
    assert remediation.cli == "configure\nset system services ssh protocol-version v2\ncommit and-quit"
    assert "delete system services web-management http" in generate_juniper_remediation("http.disabled").cli


def test_vendor_dispatch_uses_deterministic_template_before_ai(monkeypatch):
    monkeypatch.setattr(
        "remediation.service.propose_config_remediation",
        lambda **_: (_ for _ in ()).throw(AssertionError("AI must not run")),
    )
    result = type("Result", (), {
        "remediation_reference": "ssh.version",
        "framework": "NIST SP 800-53 Rev. 5",
        "control_id": "SC-8",
        "title": "Transmission Confidentiality",
        "observed_detail": "SSH version 1 is configured.",
    })()
    assert "ip ssh version 2" in resolve_remediation("cisco", "ios", result).cli
    assert "protocol-version v2" in resolve_remediation("juniper", "junos", result).cli


def test_missing_template_uses_marked_local_ai_fallback(monkeypatch):
    monkeypatch.setattr(
        "remediation.service.propose_config_remediation",
        lambda **_: "configure terminal\nno service legacy\nend",
    )
    result = type("Result", (), {
        "remediation_reference": "services.minimal",
        "framework": "NIST SP 800-53 Rev. 5",
        "control_id": "CM-7",
        "title": "Least Functionality",
        "observed_detail": "A legacy service is enabled.",
    })()
    remediation = resolve_remediation("cisco", "ios", result)
    assert remediation.cli == "configure terminal\nno service legacy\nend"
    assert remediation.is_fallback is True
    assert remediation.source == "ai_generated_fallback"


def test_missing_template_gracefully_reports_unavailable_ai(monkeypatch):
    monkeypatch.setattr("remediation.service.propose_config_remediation", lambda **_: None)
    result = type("Result", (), {
        "remediation_reference": "not.implemented",
        "framework": "ISO/IEC 27001:2022",
        "control_id": "A.0",
        "title": "Future control",
        "observed_detail": "Missing.",
    })()
    remediation = resolve_remediation("juniper", "junos", result)
    assert remediation.cli is None
    assert remediation.is_fallback is False
    assert remediation.source == "remediation_unavailable"
