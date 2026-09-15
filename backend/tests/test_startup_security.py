"""Boot-time secret enforcement (config.validate_startup_security).

The contract: weak secrets only WARN under the self-hosted default posture, but
are a hard boot failure the moment any production signal is set, so a fresh
`docker compose up` still boots while a real deployment cannot ship a footgun.
"""
import pytest

import config


@pytest.fixture
def s(monkeypatch):
    """Reset the relevant settings to the self-hosted defaults for each test."""
    monkeypatch.setattr(config.settings, "SECRET_KEY", "change-me-in-production")
    monkeypatch.setattr(config.settings, "DATABASE_URL",
                        "postgresql://valsec:valsec_local_change_me@localhost:5432/valsec")
    monkeypatch.setattr(config.settings, "VALSEC_ENV", "development")
    monkeypatch.setattr(config.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(config.settings, "SESSION_COOKIE_SECURE", False)
    return config.settings


def test_dev_default_warns_but_boots(s):
    # Weak secrets + development posture: must not raise.
    config.validate_startup_security()


def test_production_env_refuses_weak_secret(s, monkeypatch):
    monkeypatch.setattr(s, "VALSEC_ENV", "production")
    with pytest.raises(RuntimeError, match="insecure production startup"):
        config.validate_startup_security()


def test_require_auth_refuses_weak_secret(s, monkeypatch):
    monkeypatch.setattr(s, "REQUIRE_AUTH", True)
    with pytest.raises(RuntimeError):
        config.validate_startup_security()


def test_strong_secrets_boot_in_production(s, monkeypatch):
    monkeypatch.setattr(s, "VALSEC_ENV", "production")
    monkeypatch.setattr(s, "SECRET_KEY", "x9" * 30)  # 60 chars, no "change"
    monkeypatch.setattr(s, "DATABASE_URL",
                        "postgresql://valsec:A_Strong_Random_Pw_123@db:5432/valsec")
    config.validate_startup_security()


def test_short_secret_is_weak(s, monkeypatch):
    monkeypatch.setattr(s, "VALSEC_ENV", "production")
    monkeypatch.setattr(s, "SECRET_KEY", "short123")  # <32 chars
    monkeypatch.setattr(s, "DATABASE_URL",
                        "postgresql://valsec:A_Strong_Random_Pw_123@db:5432/valsec")
    with pytest.raises(RuntimeError):
        config.validate_startup_security()
