from collections import deque
from unittest.mock import MagicMock

import pytest

from connectors import telnet_pull
from connectors.ssh_pull import DeviceUnreachableError
from connectors.target_guard import UnsafeTargetError


class FakeSocket:
    def __init__(self, chunks):
        self.chunks = deque(chunks); self.sent = []; self.closed = False
    def settimeout(self, _value): pass
    def recv(self, _size): return self.chunks.popleft() if self.chunks else b""
    def sendall(self, value): self.sent.append(value)
    def close(self): self.closed = True


def test_cirotech_telnet_uses_fixed_mib_export(monkeypatch):
    sock = FakeSocket([b"login: ", b"Password: ", b"router# ", b"mib all\r\nHOST_NAME=RTR2\r\nrouter# "])
    monkeypatch.setattr(telnet_pull, "assert_connectable_target", lambda _host: "192.168.1.1")
    monkeypatch.setattr(telnet_pull.socket, "create_connection", lambda *_args, **_kwargs: sock)
    result = telnet_pull.fetch_cirotech_config("router", 23, "admin", "secret")
    assert result == "HOST_NAME=RTR2\n"
    assert telnet_pull._CONFIG_COMMAND in sock.sent
    assert all(b"mib commit" not in value for value in sock.sent)
    assert sock.closed


def test_cirotech_telnet_rejects_public_target_before_connect(monkeypatch):
    opened = MagicMock()
    monkeypatch.setattr(telnet_pull, "assert_connectable_target", lambda _host: "8.8.8.8")
    monkeypatch.setattr(telnet_pull.socket, "create_connection", opened)
    with pytest.raises(UnsafeTargetError):
        telnet_pull.fetch_cirotech_config("public", 23, "admin", "secret")
    opened.assert_not_called()


def test_cirotech_telnet_password_never_appears_in_failure(monkeypatch):
    password = "never-log-me"
    sock = FakeSocket([])
    monkeypatch.setattr(telnet_pull, "assert_connectable_target", lambda _host: "192.168.1.1")
    monkeypatch.setattr(telnet_pull.socket, "create_connection", lambda *_args, **_kwargs: sock)
    with pytest.raises(DeviceUnreachableError) as caught:
        telnet_pull.fetch_cirotech_config("router", 23, "admin", password, timeout=0.01)
    assert password not in str(caught.value)
