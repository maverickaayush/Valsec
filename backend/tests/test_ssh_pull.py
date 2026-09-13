import socket
from unittest.mock import MagicMock

import paramiko
import pytest

from connectors import ssh_pull


def _client(stdout=b"configuration\n"):
    client = MagicMock()
    stream = MagicMock()
    stream.read.return_value = stdout
    client.exec_command.return_value = (MagicMock(), stream, MagicMock())
    return client


@pytest.mark.parametrize("vendor,expected", [
    ("cisco", "show running-config"),
    ("juniper", "show configuration | display set"),
    ("fortinet", "show full-configuration"),
    ("OpenWrt", "uci show"),
])
def test_fetch_uses_one_fixed_command_and_pinned_ip(monkeypatch, vendor, expected):
    client = _client()
    monkeypatch.setattr(ssh_pull, "assert_connectable_target", lambda host: "192.168.1.9")
    monkeypatch.setattr(ssh_pull.paramiko, "SSHClient", lambda: client)
    assert ssh_pull.fetch_device_config("device.local", 22, "admin", "secret", vendor) == "configuration\n"
    assert client.connect.call_args.kwargs["hostname"] == "192.168.1.9"
    client.exec_command.assert_called_once_with(expected, timeout=8.0)
    client.close.assert_called_once()


def test_auth_failure_is_sanitized_and_client_closes(monkeypatch):
    password = "do-not-leak-this"
    client = _client()
    client.connect.side_effect = paramiko.AuthenticationException("bad password: " + password)
    monkeypatch.setattr(ssh_pull, "assert_connectable_target", lambda host: "10.0.0.2")
    monkeypatch.setattr(ssh_pull.paramiko, "SSHClient", lambda: client)
    with pytest.raises(ssh_pull.DeviceAuthError) as caught:
        ssh_pull.fetch_device_config("device", 22, "admin", password, "cisco")
    assert password not in str(caught.value)
    client.close.assert_called_once()


@pytest.mark.parametrize("failure", [socket.timeout("late"), paramiko.SSHException("bad transport")])
def test_transport_failures_are_sanitized(monkeypatch, failure):
    client = _client()
    client.connect.side_effect = failure
    monkeypatch.setattr(ssh_pull, "assert_connectable_target", lambda host: "10.0.0.2")
    monkeypatch.setattr(ssh_pull.paramiko, "SSHClient", lambda: client)
    with pytest.raises(ssh_pull.DeviceUnreachableError, match="SSH connection failed"):
        ssh_pull.fetch_device_config("device", 22, "admin", "secret-value", "cisco")
    assert "secret-value" not in str(failure)
    client.close.assert_called_once()
