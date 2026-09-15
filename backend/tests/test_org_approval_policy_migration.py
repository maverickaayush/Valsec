import importlib.util
from pathlib import Path


def test_org_approval_policy_migration_is_additive_and_reversible():
    path = Path(__file__).parents[2] / "migrations/versions/d4b8e1c73f20_add_org_remediation_approval_policy.py"
    spec = importlib.util.spec_from_file_location("org_approval_policy_migration", path)
    migration = importlib.util.module_from_spec(spec); spec.loader.exec_module(migration)
    assert migration.down_revision == "a6e3d9f42b17"
    assert callable(migration.upgrade) and callable(migration.downgrade)
    source = path.read_text()
    assert "require_separate_remediation_approver" in source
    assert "server_default=sa.false()" in source
    assert 'op.drop_column("organizations", "require_separate_remediation_approver")' in source
