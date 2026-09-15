import importlib.util
from pathlib import Path


def test_device_migration_declares_single_head_and_working_downgrade():
    path = Path(__file__).parents[2] / "migrations/versions/e2f6c8a41d90_add_devices.py"
    spec = importlib.util.spec_from_file_location("device_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert migration.down_revision == "d7a4b92f13c8"
    assert callable(migration.upgrade) and callable(migration.downgrade)
    calls = []
    class Operations:
        def __getattr__(self, name):
            return lambda *args, **kwargs: calls.append((name, args, kwargs))
    migration.op = Operations()
    migration.upgrade()
    migration.downgrade()
    names = [name for name, _, _ in calls]
    assert names.count("create_table") == names.count("drop_table") == 1
    assert names.count("add_column") == names.count("drop_column") == 1
    assert names.count("create_foreign_key") == names.count("drop_constraint") == 2
