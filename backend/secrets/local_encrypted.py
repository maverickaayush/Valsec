"""Fernet-backed local encrypted secret references."""
from __future__ import annotations

import base64
from hashlib import sha256

from cryptography.fernet import Fernet, InvalidToken

from config import settings
from secrets.base import SecretBackend


_PREFIX = "fernet:v1:"


class LocalEncryptedSecretBackend(SecretBackend):
    """Encrypt the secret into the opaque DB reference using a dedicated key."""

    def __init__(self, key: str | None = None):
        source = settings.CREDENTIAL_VAULT_KEY if key is None else key
        derived_key = base64.urlsafe_b64encode(sha256(source.encode("utf-8")).digest())
        self._fernet = Fernet(derived_key)

    def store(self, plaintext: str) -> str:
        if not isinstance(plaintext, str) or not plaintext:
            raise ValueError("Credential secret must not be empty")
        token = self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        return f"{_PREFIX}{token}"

    def retrieve(self, ref: str) -> str:
        if not isinstance(ref, str) or not ref.startswith(_PREFIX):
            raise ValueError("Invalid credential reference")
        try:
            return self._fernet.decrypt(ref[len(_PREFIX):].encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError) as exc:
            raise ValueError("Credential reference could not be decrypted") from exc

    def delete(self, ref: str) -> None:
        # The encrypted payload is the opaque reference itself. Removing the
        # DeviceCredential row revokes access; external backends can override
        # this method to delete separately stored material.
        return None
