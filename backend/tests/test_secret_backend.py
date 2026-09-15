import pytest

import config
from secrets.local_encrypted import LocalEncryptedSecretBackend


def test_local_encrypted_backend_round_trip_never_stores_plaintext():
    plaintext = "vault-round-trip-value"
    backend = LocalEncryptedSecretBackend("a-dedicated-test-key-that-is-not-the-session-key")
    secret_ref = backend.store(plaintext)
    assert secret_ref != plaintext
    assert plaintext not in secret_ref
    assert backend.retrieve(secret_ref) == plaintext
    backend.delete(secret_ref)


def test_ciphertext_cannot_be_opened_with_a_different_vault_key():
    first = LocalEncryptedSecretBackend("first-dedicated-vault-key-with-enough-entropy")
    second = LocalEncryptedSecretBackend("second-dedicated-vault-key-with-enough-entropy")
    ref = first.store("isolated-value")
    with pytest.raises(ValueError, match="could not be decrypted"):
        second.retrieve(ref)


def test_enabled_vault_rejects_weak_key_in_production(monkeypatch):
    monkeypatch.setattr(config.settings, "VALSEC_ENV", "production")
    monkeypatch.setattr(config.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(config.settings, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setattr(config.settings, "SECRET_KEY", "s9" * 32)
    monkeypatch.setattr(
        config.settings, "DATABASE_URL",
        "postgresql://valsec:strong-local-test-value@db:5432/valsec",
    )
    monkeypatch.setattr(config.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(config.settings, "CREDENTIAL_VAULT_KEY", "change-me")
    with pytest.raises(RuntimeError, match="CREDENTIAL_VAULT_KEY"):
        config.validate_startup_security()


def test_enabled_vault_warns_for_weak_key_in_development(monkeypatch, caplog):
    monkeypatch.setattr(config.settings, "VALSEC_ENV", "development")
    monkeypatch.setattr(config.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(config.settings, "SESSION_COOKIE_SECURE", False)
    monkeypatch.setattr(config.settings, "ENABLE_CREDENTIAL_VAULT", True)
    monkeypatch.setattr(config.settings, "CREDENTIAL_VAULT_KEY", "")
    config.validate_startup_security()
    assert "CREDENTIAL_VAULT_KEY" in caplog.text
