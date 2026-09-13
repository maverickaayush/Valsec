"""Audit lifecycle tests with a fake session; no broker or database required."""
import os
import sys
from types import SimpleNamespace
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
from models import Config, ConfigStatus
from normalizer.schema import DeviceInfo, NormalizationResult, UnknownLine, VendorNeutralConfig
from normalizer.cisco_ios import MappingMatch
from tasks import audit_orchestrator as audit


class Query:
    def __init__(self, item): self.item = item
    def filter(self, *_): return self
    def delete(self): return 0
    def first(self): return self.item


class Db:
    def __init__(self, config): self.config, self.added, self.commits = config, [], 0
    def query(self, *_): return Query(self.config)
    def add(self, item): self.added.append(item)
    def commit(self): self.commits += 1
    def rollback(self): pass
    def close(self): pass


def _config(status=ConfigStatus.queued):
    return Config(
        id=uuid4(), device_name="edge", vendor="cisco", os_type="ios",
        selected_framework="cis_cisco_ios_v1", raw_config="hostname edge", status=status,
    )


def _patch_session(monkeypatch, config):
    db = Db(config)
    monkeypatch.setattr(database, "SessionLocal", lambda: db)
    return db


def test_unverified_normalization_pauses_without_engine(monkeypatch):
    config = _config()
    _patch_session(monkeypatch, config)
    monkeypatch.setattr(audit.CiscoIOSNormalizer, "parse", lambda *_: NormalizationResult(unknown_lines=[UnknownLine("future syntax", 1)]))
    monkeypatch.setattr(audit, "evaluate_compliance", lambda *_: (_ for _ in ()).throw(AssertionError("engine must not run")))
    outcome = audit.run_config_audit.run(str(config.id))
    assert outcome["status"] == "awaiting_training"
    assert config.status == ConfigStatus.awaiting_training


def test_one_device_waiting_for_training_does_not_pause_other_batch_device(monkeypatch):
    waiting = _config()
    waiting.vendor = "Acme EdgeOS"
    waiting.selected_framework = "nist_sp_800_53_rev5"
    waiting.raw_config = "unknown edge command"
    completing = _config()
    completing.vendor = "Acme EdgeOS"
    completing.selected_framework = "nist_sp_800_53_rev5"
    completing.raw_config = "known after mapping"
    sessions = iter([Db(waiting), Db(completing)])
    monkeypatch.setattr(database, "SessionLocal", lambda: next(sessions))
    monkeypatch.setattr(audit, "_acquire_audit_lock", lambda *_: object())
    monkeypatch.setattr(audit, "_release_audit_lock", lambda *_: None)
    monkeypatch.setattr(
        audit.GenericFallbackNormalizer,
        "parse",
        lambda _self, raw: NormalizationResult(
            unknown_lines=[UnknownLine("unknown edge command", 1)]
        ) if raw == "unknown edge command" else NormalizationResult(),
    )
    monkeypatch.setattr(audit, "propose_config_mappings", lambda *_: {})
    report = SimpleNamespace(compliance_score=100.0, total_passed=1, total_failed=0, total_na=0)
    monkeypatch.setattr(audit, "evaluate_compliance", lambda *_: report)
    monkeypatch.setattr(audit, "_persist_compliance_results", lambda *_: {})
    monkeypatch.setattr(audit, "_generate_report", lambda *_: None)

    first = audit.run_config_audit.run(str(waiting.id))
    second = audit.run_config_audit.run(str(completing.id))

    assert first["status"] == "awaiting_training"
    assert waiting.status == ConfigStatus.awaiting_training
    assert second["status"] == "complete"
    assert completing.status == ConfigStatus.complete


def test_valid_ollama_proposal_is_persisted_as_probable(monkeypatch):
    config = _config()
    db = _patch_session(monkeypatch, config)
    unknown = UnknownLine("vendor ssh generation 2", 7, "line_vty")
    monkeypatch.setattr(
        audit.CiscoIOSNormalizer,
        "parse",
        lambda *_: NormalizationResult(unknown_lines=[unknown]),
    )
    monkeypatch.setattr(
        audit,
        "propose_config_mappings",
        lambda *_: {7: {"schema_field": "ssh.version", "field_value": 2, "confidence": 0.96}},
    )
    outcome = audit.run_config_audit.run(str(config.id))
    persisted = next(item for item in db.added if getattr(item, "raw_source_line", None))
    assert outcome["status"] == "awaiting_training"
    assert str(persisted.confidence) == "ConfidenceTier.probable"
    assert persisted.mapping_source == "ai_proposal"
    assert persisted.schema_field == "ssh.version"
    assert persisted.field_value["ai_confidence"] == 0.96


def test_unknown_vendor_uses_generic_normalizer_and_local_proposal_path(monkeypatch):
    config = _config()
    config.vendor = "Acme EdgeOS"
    config.os_type = "unknown"
    config.selected_framework = "nist_sp_800_53_rev5"
    config.raw_config = "set system ssh version 2\nset system session-timeout 5"
    db = _patch_session(monkeypatch, config)
    proposed = []

    def ollama(vendor, unknown_lines, schema_reference):
        proposed.append((vendor, unknown_lines, schema_reference))
        return {1: {"schema_field": "ssh.version", "field_value": 2, "confidence": 0.9}}

    monkeypatch.setattr(audit, "propose_config_mappings", ollama)
    monkeypatch.setattr(
        audit, "evaluate_compliance",
        lambda *_: (_ for _ in ()).throw(AssertionError("unverified syntax must pause before evaluation")),
    )

    outcome = audit.run_config_audit.run(str(config.id))

    findings = [item for item in db.added if getattr(item, "raw_source_line", None)]
    assert outcome["status"] == "awaiting_training"
    assert config.vendor == "Acme EdgeOS"
    assert len(proposed) == 1 and proposed[0][0] == "Acme EdgeOS"
    assert [line["line_number"] for line in proposed[0][1]] == [1, 2]
    assert [finding.raw_source_line for finding in findings] == config.raw_config.splitlines()
    assert str(findings[0].confidence) == "ConfidenceTier.probable"
    assert str(findings[1].confidence) == "ConfidenceTier.unverified"
    assert findings[0].mapping_source == "ai_proposal"
    assert findings[1].schema_field == "unrecognized"


def test_unknown_vendor_learned_mapping_is_confirmed_before_deterministic_resume(monkeypatch):
    config = _config()
    config.vendor = "Acme EdgeOS"
    config.os_type = "unknown"
    config.selected_framework = "nist_sp_800_53_rev5"
    config.raw_config = "set system ssh version 2"
    _patch_session(monkeypatch, config)
    seen = {}

    class ApprovedResolver:
        def __init__(self, _db, user_id=None): pass
        def resolve(self, *, vendor, raw_line, line_number, context):
            seen.update(vendor=vendor, raw_line=raw_line, line_number=line_number)
            return MappingMatch("ssh.version", 2)

    monkeypatch.setattr(audit, "DatabaseLearnedMappingResolver", ApprovedResolver)
    report = SimpleNamespace(compliance_score=100.0, total_passed=1, total_failed=0, total_na=0)
    evaluated = {}
    monkeypatch.setattr(audit, "evaluate_compliance", lambda value, framework, vendor: evaluated.update(config=value, framework=framework, vendor=vendor) or report)
    monkeypatch.setattr(audit, "_persist_compliance_results", lambda *_: {})
    monkeypatch.setattr(audit, "_generate_report", lambda *_: None)

    outcome = audit.run_config_audit.run(str(config.id))

    assert outcome["status"] == "complete"
    assert seen == {"vendor": "Acme EdgeOS", "raw_line": "set system ssh version 2", "line_number": 1}
    assert evaluated["vendor"] == "Acme EdgeOS"
    assert evaluated["config"].ssh.version == 2


def test_audit_constructs_user_scoped_mapping_resolver(monkeypatch):
    config = _config()
    config.user_id = uuid4()
    _patch_session(monkeypatch, config)
    captured = {}

    class Resolver:
        def __init__(self, _db, user_id=None): captured["user_id"] = user_id

    monkeypatch.setattr(audit, "DatabaseLearnedMappingResolver", Resolver)
    monkeypatch.setattr(audit.CiscoIOSNormalizer, "parse", lambda *_: NormalizationResult())
    monkeypatch.setattr(audit, "_persist_findings", lambda *_: False)
    report = SimpleNamespace(compliance_score=100.0, total_passed=1, total_failed=0, total_na=0)
    monkeypatch.setattr(audit, "evaluate_compliance", lambda *_: report)
    monkeypatch.setattr(audit, "_persist_compliance_results", lambda *_: None)
    monkeypatch.setattr(audit, "_generate_report", lambda *_: None)
    audit.run_config_audit.run(str(config.id))
    assert captured["user_id"] == config.user_id


def test_confirmed_path_runs_compliance_persists_totals_and_completes(monkeypatch):
    config = _config()
    _patch_session(monkeypatch, config)
    normalized_config = VendorNeutralConfig(device_info=DeviceInfo(os_version="17.9.4"))
    monkeypatch.setattr(audit.CiscoIOSNormalizer, "parse", lambda *_: NormalizationResult(config=normalized_config))
    monkeypatch.setattr(audit, "_persist_findings", lambda *_: False)
    report = SimpleNamespace(compliance_score=87.5, total_passed=7, total_failed=1, total_na=2)
    monkeypatch.setattr(audit, "evaluate_compliance", lambda *_: report)
    monkeypatch.setattr(audit, "_persist_compliance_results", lambda *_: None)
    monkeypatch.setattr(audit, "_generate_report", lambda *_: None)
    outcome = audit.run_config_audit.run(str(config.id))
    assert outcome["status"] == "complete"
    assert config.status == ConfigStatus.complete
    assert config.firmware_version == "17.9.4"
    assert (config.compliance_score, config.total_passed, config.total_failed, config.total_na) == (87.5, 7, 1, 2)


def test_juniper_and_selected_framework_dispatch_through_existing_pipeline(monkeypatch):
    config = _config()
    config.vendor = "juniper"
    config.os_type = "junos"
    config.selected_framework = "nist_sp_800_53_rev5"
    config.raw_config = "set system host-name edge"
    _patch_session(monkeypatch, config)
    normalized = NormalizationResult(config=VendorNeutralConfig(device_info=DeviceInfo(os_version="22.4R1")))
    monkeypatch.setattr(audit.JuniperJunosNormalizer, "parse", lambda *_: normalized)
    monkeypatch.setattr(audit, "_persist_findings", lambda *_: False)
    captured = {}
    report = SimpleNamespace(compliance_score=75.0, total_passed=3, total_failed=1, total_na=4)
    def evaluate(value, framework, vendor):
        captured.update(config=value, framework=framework, vendor=vendor)
        return report
    monkeypatch.setattr(audit, "evaluate_compliance", evaluate)
    monkeypatch.setattr(audit, "_persist_compliance_results", lambda *_: {})
    monkeypatch.setattr(audit, "_generate_report", lambda *_: None)

    outcome = audit.run_config_audit.run(str(config.id))
    assert outcome["status"] == "complete"
    assert captured == {
        "config": normalized.config,
        "framework": "nist_sp_800_53_rev5",
        "vendor": "juniper",
    }
    assert config.firmware_version == "22.4R1"


def test_fortinet_dispatches_through_normalize_compliance_remediation_report(monkeypatch):
    config = _config()
    config.vendor = "fortinet"
    config.os_type = "fortios"
    config.selected_framework = "nist_sp_800_53_rev5"
    config.raw_config = "config system global\n set hostname firewall\nend"
    _patch_session(monkeypatch, config)
    normalized = NormalizationResult(config=VendorNeutralConfig(device_info=DeviceInfo(os_version="7.4.3")))
    monkeypatch.setattr(audit.FortiOSNormalizer, "parse", lambda *_: normalized)
    monkeypatch.setattr(audit, "_persist_findings", lambda *_: False)
    report = SimpleNamespace(compliance_score=80.0, total_passed=4, total_failed=1, total_na=2)
    captured = {}
    monkeypatch.setattr(
        audit, "evaluate_compliance",
        lambda value, framework, vendor: captured.update(framework=framework, vendor=vendor) or report,
    )
    monkeypatch.setattr(audit, "_persist_compliance_results", lambda *_: {"AC-17": "fortios remediation"})
    monkeypatch.setattr(audit, "_generate_report", lambda _db, _config, _report, remediation: captured.update(remediation=remediation))

    outcome = audit.run_config_audit.run(str(config.id))

    assert outcome["status"] == "complete"
    assert captured == {
        "framework": "nist_sp_800_53_rev5", "vendor": "fortinet",
        "remediation": {"AC-17": "fortios remediation"},
    }
    assert config.firmware_version == "7.4.3"


def test_unknown_fortios_line_is_proposed_but_stays_behind_training_gate(monkeypatch):
    config = _config()
    config.vendor = "fortinet"
    config.os_type = "fortios"
    config.selected_framework = "nist_sp_800_53_rev5"
    config.raw_config = "config system global\n set hostname firewall\n set future-hardening enable\nend"
    db = _patch_session(monkeypatch, config)
    proposed = []
    monkeypatch.setattr(
        audit, "propose_config_mappings",
        lambda vendor, lines, schema: proposed.append((vendor, lines)) or {
            3: {"schema_field": "service_hardening.strong_crypto_enabled", "field_value": True, "confidence": 0.91}
        },
    )
    monkeypatch.setattr(
        audit, "evaluate_compliance",
        lambda *_: (_ for _ in ()).throw(AssertionError("unverified FortiOS must not be evaluated")),
    )

    outcome = audit.run_config_audit.run(str(config.id))
    finding = next(item for item in db.added if getattr(item, "line_number", None) == 3)

    assert outcome["status"] == "awaiting_training"
    assert proposed[0][0] == "fortinet"
    assert finding.mapping_source == "ai_proposal"
    assert str(finding.confidence) == "ConfidenceTier.probable"


def test_malformed_ollama_proposal_stays_unverified(monkeypatch):
    config = _config()
    db = _patch_session(monkeypatch, config)
    unknown = UnknownLine("future command", 9, None)
    monkeypatch.setattr(
        audit.CiscoIOSNormalizer, "parse",
        lambda *_: NormalizationResult(unknown_lines=[unknown]),
    )
    monkeypatch.setattr(audit, "propose_config_mappings", lambda *_: {9: {"confidence": 0.9}})

    outcome = audit.run_config_audit.run(str(config.id))
    finding = next(item for item in db.added if getattr(item, "line_number", None) == 9)

    assert outcome["status"] == "awaiting_training"
    assert finding.schema_field == "unrecognized"
    assert str(finding.confidence) == "ConfidenceTier.unverified"


def test_cancelled_config_is_not_processed(monkeypatch):
    config = _config(ConfigStatus.cancelled)
    _patch_session(monkeypatch, config)
    assert audit.run_config_audit.run(str(config.id))["status"] == "cancelled"


def test_duplicate_running_task_is_ignored_before_database_mutation(monkeypatch):
    config = _config()
    db = _patch_session(monkeypatch, config)
    monkeypatch.setattr(audit, "_acquire_audit_lock", lambda *_: False)

    outcome = audit.run_config_audit.run(str(config.id))

    assert outcome["status"] == "already_running"
    assert db.commits == 0
    assert config.status == ConfigStatus.queued


def test_exception_marks_config_failed(monkeypatch):
    config = _config()
    _patch_session(monkeypatch, config)
    monkeypatch.setattr(audit.CiscoIOSNormalizer, "parse", lambda *_: (_ for _ in ()).throw(RuntimeError("bad config")))
    outcome = audit.run_config_audit.run(str(config.id))
    assert outcome["status"] == "failed"
    assert "RuntimeError" in outcome["error"]
    assert config.status == ConfigStatus.failed
