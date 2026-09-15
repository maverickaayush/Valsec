import importlib.util
from pathlib import Path


def test_network_mission_migration_is_additive_and_reversible():
    path = Path(__file__).parents[2] / "migrations/versions/a6e3d9f42b17_add_network_missions.py"
    spec = importlib.util.spec_from_file_location("network_mission_migration", path)
    migration = importlib.util.module_from_spec(spec); spec.loader.exec_module(migration)
    assert migration.down_revision == "f1a4c7d92e63"
    assert callable(migration.upgrade) and callable(migration.downgrade)
    source = path.read_text()
    assert "network_missions" in source
    assert "remediation_campaign_targets" in source
    assert 'op.drop_table("network_missions")' in source
    assert "rewrite" not in source.casefold().replace("does not rewrite", "")
