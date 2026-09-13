"""Constrained Telnet pull for legacy Cirotech appliances.

Telnet is permitted only for private/link-local targets and only with the
fixed Cirotech read command. It is plaintext and should be used solely on an
isolated management LAN when the appliance offers no SSH service.
"""
from __future__ import annotations

import ipaddress
import socket
import time

from .ssh_pull import DeviceAuthError, DeviceUnreachableError
from .target_guard import TargetResolutionError, UnsafeTargetError, assert_connectable_target


_IAC, _DONT, _DO, _WONT, _WILL = 255, 254, 253, 252, 251
_MAX_CONFIG_BYTES = 5 * 1024 * 1024
_CONFIG_COMMAND = b"mib all\r\n"


def _strip_telnet_negotiation(data: bytes, sock: socket.socket) -> bytes:
    clean = bytearray(); index = 0
    while index < len(data):
        if data[index] != _IAC:
            clean.append(data[index]); index += 1; continue
        if index + 2 >= len(data):
            break
        verb, option = data[index + 1], data[index + 2]
        if verb in (_WILL, _WONT): sock.sendall(bytes((_IAC, _DONT, option)))
        elif verb in (_DO, _DONT): sock.sendall(bytes((_IAC, _WONT, option)))
        index += 3
    return bytes(clean)


def _read_until(sock: socket.socket, markers: tuple[bytes, ...], timeout: float, limit: int = _MAX_CONFIG_BYTES) -> bytes:
    data = bytearray(); deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and len(data) < limit:
        try:
            chunk = sock.recv(min(8192, limit - len(data)))
        except socket.timeout:
            continue
        if not chunk:
            break
        data.extend(_strip_telnet_negotiation(chunk, sock))
        lowered = bytes(data).lower()
        if any(marker in lowered for marker in markers):
            return bytes(data)
    raise DeviceUnreachableError("Device Telnet session did not reach the expected prompt")


def fetch_cirotech_config(host: str, port: int, username: str, password: str, timeout: float = 8.0) -> str:
    """Authenticate and run exactly one fixed, read-only Cirotech MIB dump."""
    try:
        pinned_ip = assert_connectable_target(host)
    except TargetResolutionError as exc:
        raise DeviceUnreachableError(str(exc)) from exc
    address = ipaddress.ip_address(pinned_ip)
    if not (address.is_private or address.is_link_local):
        raise UnsafeTargetError("Legacy Telnet pull is restricted to private or link-local targets")
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((pinned_ip, port), timeout=timeout)
        sock.settimeout(min(timeout, 1.0))
        _read_until(sock, (b"login:", b"username:"), timeout)
        sock.sendall(username.encode("utf-8") + b"\r\n")
        _read_until(sock, (b"password:",), timeout)
        sock.sendall(password.encode("utf-8") + b"\r\n")
        prompt = _read_until(sock, (b"# ", b"> ", b"#\r", b">\r"), timeout)
        if b"incorrect" in prompt.lower() or b"failed" in prompt.lower():
            raise DeviceAuthError("Device authentication failed")
        sock.sendall(_CONFIG_COMMAND)
        output = _read_until(sock, (b"# ", b"> ", b"#\r", b">\r"), timeout)
        text = output.decode("utf-8", "replace").replace("\r", "")
        lines = text.splitlines()
        if lines and lines[0].strip() == _CONFIG_COMMAND.decode().strip():
            lines = lines[1:]
        if lines and lines[-1].strip().endswith(("#", ">")):
            lines = lines[:-1]
        config = "\n".join(lines).strip()
        if not config or "not found" in config.casefold():
            raise DeviceUnreachableError("Cirotech configuration export command was unavailable")
        return config + "\n"
    except DeviceAuthError:
        raise
    except (socket.timeout, TimeoutError, OSError) as exc:
        raise DeviceUnreachableError("Device Telnet connection failed") from exc
    finally:
        if sock is not None:
            sock.close()
