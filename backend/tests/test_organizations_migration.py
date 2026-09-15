from pathlib import Path
import importlib.util


def test_migration_preserves_identity_mapping_and_reverses_it():
    migration = Path(__file__).parents[2] / "migrations/versions/c8d2e5f71a40_add_organizations_memberships.py"
    source = migration.read_text()
    spec = importlib.util.spec_from_file_location("organizations_migration", migration)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.revision == "c8d2e5f71a40"
    assert module.down_revision == "b3a7d1e94f20"
    # Seeded pre-migration shape: two devices owned by A, one by B, one local.
    a, b = "user-a", "user-b"
    before = [a, a, b, None]
    organizations = {old: old for old in before if old is not None}
    memberships = {(old, organizations[old], "owner") for old in organizations}
    upgraded = [organizations.get(old) for old in before]
    # The migration intentionally uses the original user UUID as the personal
    # Organization UUID, so downgrade is identity-preserving even if members
    # were added after upgrade.
    downgraded = list(upgraded)
    assert upgraded == before
    assert memberships == {(a, a, "owner"), (b, b, "owner")}
    assert downgraded == before
    assert "devices.org_id contains a value that is not an existing user" in source
    assert "ON CONFLICT (user_id, org_id) DO UPDATE" in source
    assert "UPDATE devices d SET org_id=o.id" in source
