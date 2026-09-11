"""Audit lifecycle tests with a fake session; no broker or database required."""
import os
import sys
from types import SimpleNamespace
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database
from models import Config, ConfigStatus
from normalizer.schema import NormalizationResult, UnknownLine
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
    return Config(id=uuid4(), device_name="edge", raw_config="hostname edge", status=status)


def _patch_session(monkeypatch, config):
    db = Db(config)
    monkeypatch.setattr(database, "SessionLocal", lambda: db)
    return db


def test_unverified_normalization_pauses_without_engine(monkeypatch):
    config = _config()
    _patch_session(monkeypatch, config)
    monkeypatch.setattr(audit.CiscoIOSNormalizer, "parse", lambda *_: NormalizationResult(unknown_lines=[UnknownLine("future syntax", 1)]))
    monkeypatch.setattr(audit, "evaluate_cis_cisco_ios", lambda *_: (_ for _ in ()).throw(AssertionError("engine must not run")))
    outcome = audit.run_config_audit.run(str(config.id))
    assert outcome["status"] == "awaiting_training"
    assert config.status == ConfigStatus.awaiting_training


def test_confirmed_path_runs_compliance_persists_totals_and_completes(monkeypatch):
    config = _config()
    _patch_session(monkeypatch, config)
    monkeypatch.setattr(audit.CiscoIOSNormalizer, "parse", lambda *_: NormalizationResult())
    monkeypatch.setattr(audit, "_persist_findings", lambda *_: False)
    report = SimpleNamespace(compliance_score=87.5, total_passed=7, total_failed=1, total_na=2)
    monkeypatch.setattr(audit, "evaluate_cis_cisco_ios", lambda *_: report)
    monkeypatch.setattr(audit, "_persist_compliance_results", lambda *_: None)
    monkeypatch.setattr(audit, "_generate_report", lambda *_: None)
    outcome = audit.run_config_audit.run(str(config.id))
    assert outcome["status"] == "complete"
    assert config.status == ConfigStatus.complete
    assert (config.compliance_score, config.total_passed, config.total_failed, config.total_na) == (87.5, 7, 1, 2)


def test_cancelled_config_is_not_processed(monkeypatch):
    config = _config(ConfigStatus.cancelled)
    _patch_session(monkeypatch, config)
    assert audit.run_config_audit.run(str(config.id))["status"] == "cancelled"


def test_exception_marks_config_failed(monkeypatch):
    config = _config()
    _patch_session(monkeypatch, config)
    monkeypatch.setattr(audit.CiscoIOSNormalizer, "parse", lambda *_: (_ for _ in ()).throw(RuntimeError("bad config")))
    outcome = audit.run_config_audit.run(str(config.id))
    assert outcome["status"] == "failed"
    assert "RuntimeError" in outcome["error"]
    assert config.status == ConfigStatus.failed
