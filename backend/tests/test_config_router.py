"""Focused config-router helper and upload tests without infrastructure."""
import io
import json
import os
import sys
import zipfile
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


def test_upload_accepts_unrecognized_vendor_hint_and_preserves_it(monkeypatch):
    db = Db()
    dispatched = []
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    from tasks.audit_orchestrator import run_config_audit
    monkeypatch.setattr(run_config_audit, "delay", lambda config_id: dispatched.append(config_id))

    response = configs.upload_config(
        None, None, "set system unfamiliar-setting yes", "  Acme EdgeOS  ",
        "nist_sp_800_53_rev5", "acme-device", db,
    )

    config = db.added[0]
    assert response["status"] == "queued"
    assert config.vendor == "Acme EdgeOS"
    assert config.os_type == "unknown"
    assert config.selected_framework == "nist_sp_800_53_rev5"
    assert dispatched == [str(response["config_id"])]


def test_unrecognized_vendor_defaults_to_vendor_neutral_framework(monkeypatch):
    db = Db()
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    from tasks.audit_orchestrator import run_config_audit
    monkeypatch.setattr(run_config_audit, "delay", lambda *_: None)

    configs.upload_config(
        None, None, "future vendor syntax", "Acme EdgeOS", None, None, db
    )

    assert db.added[0].selected_framework == "nist_sp_800_53_rev5"
    assert db.added[0].vendor == "Acme EdgeOS"


def test_upload_file_validation_and_zip_extraction():
    valid = UploadFile(filename="router.cfg", file=io.BytesIO(b"hostname edge\n"))
    assert configs._extract_upload(valid) == ("hostname edge\n", "router")
    invalid = UploadFile(filename="router.exe", file=io.BytesIO(b"x"))
    with pytest.raises(HTTPException, match="Supported files"):
        configs._extract_upload(invalid)


def _zip_upload(entries):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            archive.writestr(name, content)
    return UploadFile(filename="fleet.zip", file=io.BytesIO(data.getvalue()))


def test_multi_member_zip_creates_independent_device_audits(monkeypatch):
    db = Db()
    dispatched = []
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    from tasks.audit_orchestrator import run_config_audit
    monkeypatch.setattr(run_config_audit, "delay", lambda config_id: dispatched.append(config_id))
    upload = _zip_upload([
        ("site-a/core.cfg", "hostname core-a\n"),
        ("site-b/edge.conf", "hostname edge-b\n"),
    ])
    response = configs.upload_config(
        None, file=upload, vendor="cisco", framework="nist_sp_800_53_rev5", db=db
    )
    assert response["total"] == 2
    assert [item.device_name for item in db.added] == ["core", "edge"]
    assert all(item.selected_framework == "nist_sp_800_53_rev5" for item in db.added)
    assert dispatched == [str(item.id) for item in db.added]


def test_vendor_detection_distinguishes_cisco_juniper_fortinet_and_unknown():
    assert configs.detect_config_vendor("hostname edge\ninterface GigabitEthernet0/0") == "cisco"
    assert configs.detect_config_vendor("set system host-name edge") == "juniper"
    assert configs.detect_config_vendor("config system global\n set hostname edge\nend") == "fortinet"
    assert configs.detect_config_vendor("set allowaccess custom-secure-protocol") is None
    assert configs.detect_config_vendor("acme secure-widget enabled") is None


def test_mixed_zip_detects_fortinet_and_routes_unknown_separately(monkeypatch):
    db = Db()
    dispatched = []
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    from tasks.audit_orchestrator import run_config_audit
    monkeypatch.setattr(run_config_audit, "delay", lambda config_id: dispatched.append(config_id))
    response = configs.upload_config(
        None,
        file=_zip_upload([
            ("cisco.cfg", "hostname core\ninterface GigabitEthernet0/0\n"),
            ("juniper.conf", "set system host-name spine\n"),
            ("fortigate.conf", "config system global\n set hostname firewall\nend\n"),
            ("acme.cfg", "acme secure-widget enabled\n"),
        ]),
        vendor="Acme EdgeOS",
        framework="cis_cisco_ios_v1",
        vendor_hints=json.dumps({"acme.cfg": "Acme EdgeOS"}),
        db=db,
    )
    assert response["total"] == 4
    assert [config.vendor for config in db.added] == ["cisco", "juniper", "fortinet", "Acme EdgeOS"]
    assert [config.os_type for config in db.added] == ["ios", "junos", "fortios", "unknown"]
    assert [config.selected_framework for config in db.added] == [
        "cis_cisco_ios_v1", "cis_cisco_ios_v1", "nist_sp_800_53_rev5", "nist_sp_800_53_rev5",
    ]
    assert dispatched == [str(config.id) for config in db.added]


def test_mixed_vendor_zip_detects_each_file_and_keeps_unknown_isolated(monkeypatch):
    db = Db()
    dispatched = []
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    from tasks.audit_orchestrator import run_config_audit
    monkeypatch.setattr(run_config_audit, "delay", lambda config_id: dispatched.append(config_id))
    upload = _zip_upload([
        ("cisco.cfg", "hostname core\ninterface GigabitEthernet0/0\n"),
        ("juniper.conf", "set system host-name spine\nset system services ssh\n"),
        ("acme-edgeos.cfg", "acme-security-policy strict\n"),
        ("other.cfg", "edge-feature enabled\n"),
    ])

    response = configs.upload_config(
        None,
        file=upload,
        vendor="Acme EdgeOS",
        framework="cis_cisco_ios_v1",
        vendor_hints=json.dumps({"other.cfg": "Other Networks OS"}),
        db=db,
    )

    assert response["total"] == 4
    assert [(config.vendor, config.os_type, config.selected_framework) for config in db.added] == [
        ("cisco", "ios", "cis_cisco_ios_v1"),
        ("juniper", "junos", "cis_cisco_ios_v1"),
        ("Acme EdgeOS", "unknown", "nist_sp_800_53_rev5"),
        ("Other Networks OS", "unknown", "nist_sp_800_53_rev5"),
    ]
    assert dispatched == [str(config.id) for config in db.added]


def test_multipart_files_are_vendor_detected_independently(monkeypatch):
    db = Db()
    dispatched = []
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    from tasks.audit_orchestrator import run_config_audit
    monkeypatch.setattr(run_config_audit, "delay", lambda config_id: dispatched.append(config_id))

    response = configs.upload_config(
        None,
        vendor="Acme EdgeOS",
        framework="nist_sp_800_53_rev5",
        files=[
            UploadFile(filename="core.cfg", file=io.BytesIO(b"hostname core\ninterface Ethernet0/0\n")),
            UploadFile(filename="spine.conf", file=io.BytesIO(b"set system host-name spine\n")),
            UploadFile(filename="acme.cfg", file=io.BytesIO(b"acme feature enabled\n")),
        ],
        vendor_hints=json.dumps({"acme.cfg": "Acme EdgeOS"}),
        db=db,
    )

    assert response["total"] == 3
    assert [config.vendor for config in db.added] == ["cisco", "juniper", "Acme EdgeOS"]
    assert [config.status for config in db.added] == [ConfigStatus.queued] * 3
    assert dispatched == [str(config.id) for config in db.added]


def test_vendor_hint_isolation_and_zip_safety_remain_enforced(monkeypatch):
    db = Db()
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    from tasks.audit_orchestrator import run_config_audit
    monkeypatch.setattr(run_config_audit, "delay", lambda *_: None)
    upload = _zip_upload([
        ("nested/same.cfg", "unknown syntax one\n"),
        ("other.cfg", "unknown syntax two\n"),
    ])
    configs.upload_config(
        None, file=upload, vendor="Fallback Vendor", framework="nist_sp_800_53_rev5",
        vendor_hints=json.dumps({"nested/same.cfg": "Acme OS", "other.cfg": "Different OS"}), db=db,
    )
    assert [config.vendor for config in db.added] == ["Acme OS", "Different OS"]

    unsafe = _zip_upload([("../escape.cfg", "unknown syntax\n")])
    with pytest.raises(HTTPException, match="unsafe member path"):
        configs.upload_config(None, file=unsafe, vendor="Fallback Vendor", db=Db())


def test_one_dispatch_failure_does_not_stop_other_batch_items(monkeypatch):
    db = Db()
    calls = []
    monkeypatch.setattr(configs, "_current_user", lambda *_: None)
    from tasks.audit_orchestrator import run_config_audit
    def dispatch(config_id):
        calls.append(config_id)
        if len(calls) == 1:
            raise ConnectionError("broker error")
    monkeypatch.setattr(run_config_audit, "delay", dispatch)
    response = configs.upload_config(
        None,
        file=_zip_upload([("first.cfg", "hostname first"), ("second.cfg", "hostname second")]),
        vendor="juniper",
        framework="iso_iec_27001_2022",
        db=db,
    )
    assert len(calls) == 2
    assert len(response["dispatch_errors"]) == 1
    assert db.added[0].status == ConfigStatus.failed
    assert db.added[1].status == ConfigStatus.queued


def test_zip_upload_is_size_bounded_and_never_uses_member_path(tmp_path):
    archive_bytes = io.BytesIO()
    with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../../escape.cfg", b"hostname safe\n")
    upload = UploadFile(filename="router.zip", file=io.BytesIO(archive_bytes.getvalue()))
    with pytest.raises(HTTPException, match="unsafe member path"):
        configs._extract_upload(upload)
    assert not (tmp_path / "escape.cfg").exists()

    oversized_bytes = io.BytesIO()
    with zipfile.ZipFile(oversized_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.cfg", b"x" * (configs._MAX_UPLOAD_BYTES + 1))
    oversized = UploadFile(filename="large.zip", file=io.BytesIO(oversized_bytes.getvalue()))
    with pytest.raises(HTTPException) as exc:
        configs._extract_upload(oversized)
    assert exc.value.status_code == 413


def test_progress_covers_lifecycle_and_invalid_inputs_are_rejected():
    config = Config(status=ConfigStatus.compliance_check)
    assert configs._progress(config) == 70
    with pytest.raises(HTTPException, match="vendor-specific"):
        configs.upload_config(None, None, "fortinet-specific syntax", "fortinet", "cis_cisco_ios_v1", None, Db())
    with pytest.raises(HTTPException, match="Vendor must"):
        configs.upload_config(None, None, "hostname edge", "bad\nvendor", "nist_sp_800_53_rev5", None, Db())
    with pytest.raises(HTTPException, match="Unsupported compliance framework"):
        configs.upload_config(None, None, "hostname edge", "cisco", "made_up", None, Db())
    with pytest.raises(HTTPException, match="Device name"):
        configs.upload_config(
            None, None, "hostname edge", "cisco", "cis_cisco_ios_v1", "x" * 256, Db()
        )
    with pytest.raises(HTTPException, match="Fortinet FortiOS currently supports"):
        configs.upload_config(
            None, None, "config system global\n set hostname fgt\nend", "fortinet",
            "iso_iec_27001_2022", None, Db(), vendor_hints=None,
        )


def test_owned_config_lookup_hides_cross_owner_reports(monkeypatch):
    owner_id, requester_id = uuid4(), uuid4()
    config = Config(id=uuid4(), device_name="edge", vendor="cisco", os_type="ios",
                    status=ConfigStatus.complete, user_id=owner_id)
    monkeypatch.setattr(configs, "_current_user", lambda *_: SimpleNamespace(id=requester_id))

    with pytest.raises(HTTPException) as exc:
        configs.config_report(config.id, None, ReadDb([config]))
    assert exc.value.status_code == 404


def test_list_status_results_and_report_endpoints(monkeypatch):
    config = Config(id=uuid4(), device_name="edge", vendor="cisco", os_type="ios",
                    status=ConfigStatus.complete, total_passed=2, total_failed=1, total_na=3,
                    compliance_score=66.67, selected_framework="cis_cisco_ios_v1")
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
