"""Interface for replaceable credential secret stores."""
from abc import ABC, abstractmethod


class SecretBackend(ABC):
    @abstractmethod
    def store(self, plaintext: str) -> str:
        """Store a plaintext secret and return an opaque reference."""

    @abstractmethod
    def retrieve(self, ref: str) -> str:
        """Resolve an opaque reference to request-scoped plaintext."""

    @abstractmethod
    def delete(self, ref: str) -> None:
        """Delete or invalidate an opaque reference."""
