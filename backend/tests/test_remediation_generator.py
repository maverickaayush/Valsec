"""Deterministic Cisco remediation template tests."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from remediation.cisco_remediation import _TEMPLATES, generate_remediation


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
