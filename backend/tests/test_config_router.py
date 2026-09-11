"""Focused config-router helper and upload tests without infrastructure."""
import io
import os
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException, UploadFile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Config, ConfigStatus
from routers import configs


class Db:
    def __init__(self): self.added = []
    def add(self, value): self.added.append(value)
    def commit(self): pass
    def refresh(self, value):
        if value.id is None: value.id = uuid4()


class Query:
    def __init__(self, values): self.values = values
    def filter(self, *_): return self
    def count(self): return len(self.values)
    def order_by(self, *_): return self
    def offset(self, *_): return self
    def limit(self, *_): return self
    def all(self): return self.values
    def first(self): return self.values[0] if self.values else None


class ReadDb:
    def __init__(self, values): self.values = values
    def query(self, *_): return Query(self.values)


def test_upload_accepts_raw_text_creates_queued_config_and_dispatches(monkeypatch):
    db = Db()
    dispatched = []
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    from tasks.audit_orchestrator import run_config_audit
    monkeypatch.setattr(run_config_audit, "delay", lambda config_id: dispatched.append(config_id))
    response = configs.upload_config(None, None, "hostname edge", "cisco", "cis_cisco_ios_v1", "edge", db)
    assert response["status"] == "queued"
    assert db.added[0].device_name == "edge"
    assert dispatched == [str(response["config_id"])]


def test_upload_file_validation_and_zip_extraction():
    valid = UploadFile(filename="router.cfg", file=io.BytesIO(b"hostname edge\n"))
    assert configs._extract_upload(valid) == ("hostname edge\n", "router")
    invalid = UploadFile(filename="router.exe", file=io.BytesIO(b"x"))
    with pytest.raises(HTTPException, match="Supported files"):
        configs._extract_upload(invalid)


def test_progress_covers_lifecycle_and_invalid_vendor_is_rejected():
    config = Config(status=ConfigStatus.compliance_check)
    assert configs._progress(config) == 70
    with pytest.raises(HTTPException, match="Only Cisco"):
        configs.upload_config(None, None, "hostname edge", "juniper", "cis", None, Db())


def test_list_status_results_and_report_endpoints(monkeypatch):
    config = Config(id=uuid4(), device_name="edge", vendor="cisco", os_type="ios",
                    status=ConfigStatus.complete, total_passed=2, total_failed=1, total_na=3,
                    compliance_score=66.67)
    config.uploaded_at = None
    config.completed_at = None
    result = SimpleNamespace(control_id="1.1.1", framework="CIS", title="Password encryption",
                             description="not configured", verdict=SimpleNamespace(value="FAIL"),
                             severity=SimpleNamespace(value="Medium"), observed_value="false",
                             remediation_cli="configure terminal", is_remediation_fallback=False)
    report = SimpleNamespace(config_id=config.id, pdf_data=b"%PDF-test")
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    listed = configs.list_configs(None, 1, 25, None, "complete", ReadDb([config]))
    assert listed["total"] == 1 and listed["items"][0]["total_failed"] == 1
    monkeypatch.setattr(configs, "get_owned_config_or_404", lambda *_: config)
    status = configs.config_status(config.id, None, ReadDb([]))
    assert status["progress"] == 100 and status["training_required"] is False
    payload = configs.config_results(config.id, None, ReadDb([result]))
    assert payload["severity_counts"]["Medium"] == 1
    stream = configs.config_report(config.id, None, ReadDb([report]))
    assert stream.media_type == "application/pdf"
