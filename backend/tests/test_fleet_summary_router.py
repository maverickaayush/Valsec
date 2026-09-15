from types import SimpleNamespace
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from models import ConfigStatus, Device
from routers import devices


class Query:
    def __init__(self, rows): self.rows = rows
    def join(self, *_args, **_kwargs): return self
    def outerjoin(self, *_args, **_kwargs): return self
    def filter(self, *_args): return self
    def group_by(self, *_args): return self
    def order_by(self, *_args): return self
    def limit(self, *_args): return self
    def all(self): return self.rows


class Db:
    def __init__(self, rows): self.rows = iter(rows)
    def query(self, *_args): return Query(next(self.rows))


def test_fleet_summary_uses_latest_completed_rows_for_scores_and_controls(monkeypatch):
    columns = SimpleNamespace(status="status", device_id="device_id", compliance_score="score", config_id="config_id")
    monkeypatch.setattr(devices, "_latest_config_subquery", lambda *_args, **_kwargs: SimpleNamespace(c=columns))
    monkeypatch.setattr(devices, "_current_user", lambda *_: None)
    stale = Device(id=uuid4(), display_name="old", vendor="cisco", os_type="ios", is_active=True)
    db = Db([
        [(ConfigStatus.complete, 2), (ConfigStatus.failed, 1)],
        [(uuid4(), 90.0), (uuid4(), 50.0)],
        [("AC-1", "NIST", "Access control", 2)],
        [stale],
    ])
    summary = devices.fleet_summary(None, stale_since_days=30, db=db)
    assert summary["devices_by_status"]["complete"] == 2
    assert summary["average_score"] == 70.0
    assert summary["score_distribution"] == {"0-49": 0, "50-79": 1, "80-100": 1, "unscored": 0}
    assert summary["top_failing_controls"][0]["failure_count"] == 2


def test_latest_per_device_query_is_one_windowed_relation():
    relation = devices._latest_config_subquery(Session(), completed_only=True)
    sql = str(select(relation).compile(dialect=postgresql.dialect()))
    assert "row_number() OVER (PARTITION BY configs.device_id" in sql
    assert "configs.status" in sql and "row_number_1" in sql
