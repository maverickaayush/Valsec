"""Shared validation for operator-supplied Valsec metadata."""


def validate_device_name(value: str) -> str:
    """Return a normalized printable device name or raise ``ValueError``."""
    name = value.strip()
    if not name or len(name) > 255 or any(ord(character) < 32 for character in name):
        raise ValueError("Device name must be 1-255 printable characters")
    return name
