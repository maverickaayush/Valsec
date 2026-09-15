import importlib.util
from pathlib import Path


def test_schedule_migration_is_additive_and_reversible():
    path = Path(__file__).parents[2] / "migrations/versions/f1a4c7d92e63_add_audit_schedules.py"
    spec = importlib.util.spec_from_file_location("schedule_migration", path)
    migration = importlib.util.module_from_spec(spec); spec.loader.exec_module(migration)
    assert migration.revision == "f1a4c7d92e63"
    assert migration.down_revision == "c8d2e5f71a40"
    source = path.read_text()
    assert 'op.create_table(\n        "audit_schedules"' in source
    assert 'op.drop_table("audit_schedules")' in source
