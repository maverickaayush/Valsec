import importlib.util
from pathlib import Path


def test_device_credentials_migration_chains_to_confirmed_head_and_downgrades():
    path = Path(__file__).parents[2] / "migrations/versions/b3a7d1e94f20_add_device_credentials.py"
    spec = importlib.util.spec_from_file_location("device_credentials_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    assert migration.down_revision == "e2f6c8a41d90"
    calls = []
    class Operations:
        def __getattr__(self, name):
            return lambda *args, **kwargs: calls.append((name, args, kwargs))
    migration.op = Operations()
    migration.upgrade()
    migration.downgrade()
    names = [name for name, _, _ in calls]
    assert names.count("create_table") == names.count("drop_table") == 2
    assert names.count("create_index") == names.count("drop_index") == 2
