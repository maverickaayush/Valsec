"""Focused regression tests for training API hardening and compliance PDFs."""
from __future__ import annotations

import io
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

import pdfplumber
import pytest
from fastapi import HTTPException

from compliance.engine import ComplianceReport, ComplianceResult, ComplianceVerdict, evaluate_cis_cisco_ios, evaluate_compliance
from models import ConfigStatus, ConfidenceTier
from remediation.cisco_remediation import Remediation
from normalizer.schema import VendorNeutralConfig
from normalizer.cisco_ios import CiscoIOSNormalizer
from reports.compliance_generator import generate_compliance_pdf
from routers import configs, training
from training.matcher import DatabaseLearnedMappingResolver


class Query:
    def __init__(self, values): self.values = values
    def filter(self, *_): return self
    def all(self): return self.values
    def first(self): return self.values[0] if self.values else None


class Db:
    def __init__(self, values=()): self.values = list(values); self.queried = False
    def query(self, *_): self.queried = True; return Query(self.values)


def _config(config_id=None):
    return SimpleNamespace(
        id=config_id or uuid4(), device_name="core-router-01", vendor="cisco",
        os_type="ios-xe", firmware_version="17.9.4", status=ConfigStatus.awaiting_training,
        completed_at=datetime(2026, 9, 12, 12, 0), uploaded_at=datetime(2026, 9, 12, 11, 0),
    )


def test_unverified_response_exposes_real_ai_proposal_and_null_without_one(monkeypatch):
    config = _config()
    ai = SimpleNamespace(
        id=uuid4(), raw_source_line="vendor secure-shell generation 2", line_number=44,
        schema_field="ssh.version", mapping_source="ai_proposal",
        field_value={"field_value": 2, "ai_confidence": 0.83},
    )
    parser_only = SimpleNamespace(
        id=uuid4(), raw_source_line="future command", line_number=45,
        schema_field="unrecognized", mapping_source="parser", field_value={"context": None},
    )
    monkeypatch.setattr(training, "get_owned_config_or_404", lambda *_: config)
    payload = training.get_unverified_findings(str(config.id), None, Db([ai, parser_only]))

    first, second = payload["unverified_lines"]
    assert first["finding_id"] == str(ai.id)
    assert first["ai_suggested_schema_field"] == "ssh.version"
    assert first["ai_suggested_field"] == "ssh.version"
    assert first["ai_confidence"] == pytest.approx(0.83)
    assert second["ai_suggested_schema_field"] is None
    assert second["ai_suggested_field"] is None
    assert second["ai_confidence"] is None


@pytest.mark.parametrize("endpoint", ["get", "post"])
def test_training_endpoints_enforce_config_ownership_before_finding_access(monkeypatch, endpoint):
    config_id = uuid4()
    denial = HTTPException(status_code=404, detail="Configuration not found")
    monkeypatch.setattr(training, "get_owned_config_or_404", lambda *_: (_ for _ in ()).throw(denial))
    db = Db()

    with pytest.raises(HTTPException) as exc:
        if endpoint == "get":
            training.get_unverified_findings(str(config_id), None, db)
        else:
            training.submit_training(str(config_id), {
                "finding_id": str(uuid4()),
                "approved_schema_field": "ssh.version",
                "approved_value": 2,
            }, None, db)
    assert exc.value.status_code == 404
    assert db.queried is False


@pytest.mark.parametrize("endpoint", ["get", "post"])
def test_training_ownership_boundary_rejects_another_users_config(monkeypatch, endpoint):
    owner_id, requester_id = uuid4(), uuid4()
    config = _config()
    config.user_id = owner_id
    monkeypatch.setattr(configs, "_current_user", lambda *_: SimpleNamespace(id=requester_id))

    with pytest.raises(HTTPException) as exc:
        if endpoint == "get":
            training.get_unverified_findings(str(config.id), None, Db([config]))
        else:
            training.submit_training(str(config.id), {
                "finding_id": str(uuid4()),
                "approved_schema_field": "ssh.version",
                "approved_value": 2,
            }, None, Db([config]))
    assert exc.value.status_code == 404


def test_training_rejects_invalid_config_state(monkeypatch):
    config = _config()
    config.status = ConfigStatus.complete
    monkeypatch.setattr(training, "get_owned_config_or_404", lambda *_: config)

    with pytest.raises(HTTPException) as exc:
        training.submit_training(str(config.id), {
            "finding_id": str(uuid4()),
            "approved_schema_field": "ssh.version",
            "approved_value": 2,
        }, None, Db())
    assert exc.value.status_code == 409


class TxQuery:
    def __init__(self, value=None, count_value=0):
        self.value, self.count_value, self.locked = value, count_value, False
    def filter(self, *_): return self
    def with_for_update(self): self.locked = True; return self
    def first(self): return self.value
    def count(self): return self.count_value


class TxDb:
    def __init__(self, queries):
        self.queries = iter(queries)
        self.added = []
        self.commits = 0
        self.rollbacks = 0
    def query(self, *_): return next(self.queries)
    def add(self, value): self.added.append(value)
    def flush(self): pass
    def commit(self): self.commits += 1
    def rollback(self): self.rollbacks += 1


def test_training_transaction_scopes_mapping_and_claims_resume(monkeypatch):
    user_id = uuid4()
    config = _config()
    config.user_id = user_id
    finding = SimpleNamespace(
        id=uuid4(), raw_source_line="vendor ssh generation 2",
        schema_field="unrecognized", field_value={"context": None},
        confidence=ConfidenceTier.unverified, mapping_source="parser",
    )
    config_query, finding_query, mapping_query = TxQuery(config), TxQuery(finding), TxQuery(None)
    db = TxDb([config_query, finding_query, mapping_query, TxQuery(count_value=0)])
    monkeypatch.setattr(training, "get_owned_config_or_404", lambda *_: config)
    dispatch = MagicMock()
    monkeypatch.setattr(training.celery_app, "send_task", dispatch)

    result = training.submit_training(str(config.id), {
        "finding_id": str(finding.id),
        "approved_schema_field": "ssh.version",
        "approved_value": 2,
    }, None, db)

    assert result["audit_resumed"] is True
    assert config.status == ConfigStatus.normalising
    assert finding.confidence == "confirmed"
    assert len(db.added) == 1 and db.added[0].user_id == user_id
    assert db.added[0].schema_field == "ssh.version"
    assert config_query.locked and finding_query.locked and mapping_query.locked
    dispatch.assert_called_once()


def test_duplicate_training_submission_is_idempotent(monkeypatch):
    config = _config()
    config.user_id = uuid4()
    finding = SimpleNamespace(
        id=uuid4(), raw_source_line="vendor ssh generation 2",
        schema_field="ssh.version", field_value=2,
        confidence=ConfidenceTier.confirmed, mapping_source="manual_training",
    )
    mapping = SimpleNamespace(
        user_id=config.user_id, vendor="cisco", schema_field="ssh.version",
        examples=[{"raw_line": finding.raw_source_line, "field_value": 2}],
    )
    db = TxDb([
        TxQuery(config), TxQuery(finding), TxQuery(mapping), TxQuery(count_value=0),
    ])
    monkeypatch.setattr(training, "get_owned_config_or_404", lambda *_: config)
    dispatch = MagicMock()
    monkeypatch.setattr(training.celery_app, "send_task", dispatch)

    result = training.submit_training(str(config.id), {
        "finding_id": str(finding.id),
        "approved_schema_field": "ssh.version",
        "approved_value": 2,
    }, None, db)

    assert result["audit_resumed"] is True
    assert db.added == []
    assert mapping.examples == [{"raw_line": finding.raw_source_line, "field_value": 2}]
    dispatch.assert_called_once()


def test_dispatch_failure_restores_recoverable_training_state(monkeypatch):
    config = _config()
    config.user_id = uuid4()
    finding = SimpleNamespace(
        id=uuid4(), raw_source_line="vendor ssh generation 2",
        schema_field="unrecognized", field_value={"context": None},
        confidence=ConfidenceTier.unverified, mapping_source="parser",
    )
    db = TxDb([
        TxQuery(config), TxQuery(finding), TxQuery(None), TxQuery(count_value=0),
        TxQuery(config),
    ])
    monkeypatch.setattr(training, "get_owned_config_or_404", lambda *_: config)
    monkeypatch.setattr(
        training.celery_app, "send_task", MagicMock(side_effect=ConnectionError("broker down"))
    )

    with pytest.raises(HTTPException) as exc:
        training.submit_training(str(config.id), {
            "finding_id": str(finding.id),
            "approved_schema_field": "ssh.version",
            "approved_value": 2,
        }, None, db)

    assert exc.value.status_code == 503
    assert exc.value.detail["resume_pending"] is True
    assert config.status == ConfigStatus.awaiting_training
    assert finding.confidence == "confirmed"
    assert db.commits == 2


def _pdf_text(pdf: bytes) -> str:
    with pdfplumber.open(io.BytesIO(pdf)) as document:
        return "\n".join(page.extract_text() or "" for page in document.pages)


def test_compliance_pdf_contains_cis_results_and_no_legacy_terms():
    config = _config()
    normalized = VendorNeutralConfig()
    normalized.service_hardening.password_encryption = False
    normalized.device_info.enable_secret_type = 0
    normalized.line_vty.transport_input = ["telnet", "ssh"]
    report = evaluate_cis_cisco_ios(normalized)

    text = _pdf_text(generate_compliance_pdf(config, report))
    assert "V A L S E C" in text
    assert "core-router-01" in text
    assert "CISCO" in text and "IOS-XE" in text and "17.9.4" in text
    assert "CIS Cisco IOS Benchmark" in text and "v1.0.0" in text
    assert "PASS" in text and "FAIL" in text and "N/A" in text
    assert "1.1.1" in text and "service password-encryption" in text
    assert "REQUIREMENT" in text and "OBSERVED VALUE" in text
    assert "configure terminal" in text and "service password-encryption" in text
    for obsolete in ("ONUS", "VAPT", "CVSS", "OWASP"):
        assert obsolete not in text.upper()


def test_compliance_pdf_marks_ai_fallback_remediation_explicitly():
    config = _config()
    result = ComplianceResult(
        control_id="9.9.9", title="Ensure future control is configured",
        framework="CIS Cisco IOS Benchmark v1.0.0", severity="Medium",
        verdict=ComplianceVerdict.FAIL, observed_detail="Future setting is disabled.",
        remediation_reference="cisco_remediation:9.9.9",
    )
    report = ComplianceReport((result,), 0.0, 0, 1, 0)
    text = _pdf_text(generate_compliance_pdf(
        config, report,
        remediations={"9.9.9": Remediation(
            "configure terminal\nfuture secure-setting\nend",
            True,
            "ai_generated_fallback",
        )},
    ))
    assert "AI-GENERATED FALLBACK REMEDIATION" in text.upper()
    assert "OPERATOR REVIEW REQUIRED" in text.upper()


def test_pdf_uses_real_juniper_and_framework_metadata():
    config = _config()
    config.vendor = "juniper"
    config.os_type = "junos"
    config.selected_framework = "nist_sp_800_53_rev5"
    normalized = VendorNeutralConfig()
    normalized.ssh.version = 1
    report = evaluate_compliance(normalized, config.selected_framework, config.vendor)
    text = _pdf_text(generate_compliance_pdf(config, report))
    assert "JUNIPER JUNOS SECURITY COMPLIANCE AUDIT" in text.upper()
    assert "NIST SP 800-53" in text and "Rev. 5" in text
    assert "12 September 2026" in text
    assert "set system services ssh protocol-version v2" in text
    for obsolete in ("ONUS", "VAPT", "CVSS", "OWASP"):
        assert obsolete not in text.upper()


def test_first_audit_trains_and_second_audit_reuses_confirmed_mapping():
    raw_config = "vendor secure-shell generation 2"
    first_pass = CiscoIOSNormalizer().parse(raw_config)
    assert len(first_pass.unknown_lines) == 1

    learned = MagicMock(
        schema_field="ssh.version",
        examples=[{"raw_line": raw_config, "field_value": 2}],
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = learned
    resolver = DatabaseLearnedMappingResolver(db)

    resumed = CiscoIOSNormalizer(resolver).parse(raw_config)
    assert not resumed.unknown_lines
    assert resumed.config.ssh.version == 2
    assert resumed.findings[0].confidence == "confirmed"
    assert resumed.findings[0].mapping_source == "learned_mapping"

    second_audit = CiscoIOSNormalizer(resolver).parse(raw_config)
    assert not second_audit.unknown_lines
    assert second_audit.config.ssh.version == 2
    assert second_audit.findings[0].mapping_source == "learned_mapping"
