from unittest.mock import MagicMock

import pytest

from connectors import ssh_push
from connectors.ssh_pull import DeviceUnreachableError


def _install_client(monkeypatch):
    channel = MagicMock()
    client = MagicMock()
    client.invoke_shell.return_value = channel
    monkeypatch.setattr(ssh_push, "assert_connectable_target", lambda host: "192.168.1.8")
    monkeypatch.setattr(ssh_push.paramiko, "SSHClient", lambda: client)
    return client, channel


def _sent(channel):
    return [call.args[0].decode().strip() for call in channel.sendall.call_args_list]


def test_cisco_applies_running_config_only_and_repulled_diff(monkeypatch):
    client, channel = _install_client(monkeypatch)
    snapshots = iter(["ntp server old\n", "ntp server 10.0.0.10\n"])
    monkeypatch.setattr(ssh_push, "fetch_device_config", lambda *_args: next(snapshots))
    result = ssh_push.apply_remediation(
        "router", 22, "admin", "secret", "cisco",
        "configure terminal\nntp server 10.0.0.10\nend\nwrite memory",
    )
    assert _sent(channel) == ["configure terminal", "ntp server 10.0.0.10", "end"]
    assert not any(command in {"write memory", "copy running-config startup-config"} for command in _sent(channel))
    assert "-ntp server old" in result.diff_summary
    client.close.assert_called_once()


def test_juniper_commit_confirmed_repulled_then_final_commit(monkeypatch):
    _, channel = _install_client(monkeypatch)
    snapshots = iter(["set system host-name old\n", "set system host-name edge\n"])
    monkeypatch.setattr(ssh_push, "fetch_device_config", lambda *_args: next(snapshots))
    ssh_push.apply_remediation(
        "router", 22, "admin", "secret", "juniper",
        "configure\nset system host-name edge\ncommit and-quit",
    )
    assert _sent(channel) == ["configure", "set system host-name edge", "commit confirmed 5", "commit"]


def test_juniper_unreachable_after_confirmed_commit_never_final_commits(monkeypatch):
    _, channel = _install_client(monkeypatch)
    calls = 0
    def pull(*_args):
        nonlocal calls
        calls += 1
        if calls == 1:
            return "before\n"
        raise DeviceUnreachableError("offline")
    monkeypatch.setattr(ssh_push, "fetch_device_config", pull)
    with pytest.raises(ssh_push.ConfirmedCommitPendingRollbackError, match="auto-rollback"):
        ssh_push.apply_remediation("router", 22, "admin", "secret", "juniper", "set system ntp server 10.0.0.1")
    assert _sent(channel)[-1] == "commit confirmed 5"
    assert _sent(channel).count("commit") == 0


def test_generic_non_risky_uci_change_commits_and_reloads(monkeypatch):
    _, channel = _install_client(monkeypatch)
    snapshots = iter(["system.hostname='old'\n", "system.hostname='edge'\n"])
    monkeypatch.setattr(ssh_push, "fetch_device_config", lambda *_args: next(snapshots))
    ssh_push.apply_remediation(
        "router", 22, "root", "secret", "OpenWrt",
        "uci set system.@system[0].hostname='edge'; uci commit",
    )
    assert _sent(channel) == [
        "uci set system.@system[0].hostname='edge'", "uci commit", "/etc/init.d/system reload",
    ]


def test_generic_risky_change_refused_before_any_connection(monkeypatch):
    ssh_client = MagicMock()
    pull = MagicMock()
    monkeypatch.setattr(ssh_push.paramiko, "SSHClient", ssh_client)
    monkeypatch.setattr(ssh_push, "fetch_device_config", pull)
    with pytest.raises(ssh_push.UnsupportedRiskyPushError, match="manually"):
        ssh_push.apply_remediation(
            "router", 22, "root", "secret", "OpenWrt",
            "uci set network.lan.ipaddr='192.168.2.1'",
        )
    ssh_client.assert_not_called()
    pull.assert_not_called()
