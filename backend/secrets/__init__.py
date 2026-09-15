"""Credential-vault backends plus compatibility with Python's ``secrets`` API.

The package name is required by the vault layout.  Because ``backend`` is placed
on ``sys.path``, expose the small standard-library API used by Valsec and its
dependencies so this package does not weaken existing random-token generation.
"""
from __future__ import annotations

import base64
import binascii
import hmac
import os
from random import SystemRandom


_system_random = SystemRandom()
choice = _system_random.choice
compare_digest = hmac.compare_digest


def randbelow(exclusive_upper_bound: int) -> int:
    if exclusive_upper_bound <= 0:
        raise ValueError("Upper bound must be positive.")
    return _system_random._randbelow(exclusive_upper_bound)


def token_bytes(nbytes: int | None = None) -> bytes:
    return os.urandom(32 if nbytes is None else nbytes)


def token_hex(nbytes: int | None = None) -> str:
    return binascii.hexlify(token_bytes(nbytes)).decode("ascii")


def token_urlsafe(nbytes: int | None = None) -> str:
    return base64.urlsafe_b64encode(token_bytes(nbytes)).rstrip(b"=").decode("ascii")


def get_secret_backend(name: str = "local_encrypted"):
    """Construct a configured backend without caching key material globally."""
    if name != "local_encrypted":
        raise ValueError("Unsupported secret backend")
    from secrets.local_encrypted import LocalEncryptedSecretBackend
    return LocalEncryptedSecretBackend()


__all__ = [
    "choice", "compare_digest", "get_secret_backend", "randbelow",
    "token_bytes", "token_hex", "token_urlsafe",
]
