import socket

import pytest

from connectors import target_guard


@pytest.mark.parametrize("address", ["10.0.0.7", "192.168.1.1", "169.254.2.3", "8.8.8.8"])
def test_private_public_and_non_metadata_link_local_targets_are_allowed(address):
    assert target_guard.assert_connectable_target(address) == address


@pytest.mark.parametrize("address", ["127.0.0.1", "127.22.3.4", "::1", "169.254.169.254", "::ffff:127.0.0.1", "::ffff:169.254.169.254"])
def test_loopback_and_metadata_targets_are_blocked(address):
    with pytest.raises(target_guard.UnsafeTargetError):
        target_guard.assert_connectable_target(address)


def test_hostname_resolving_to_blocked_range_is_blocked(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.8", 0)),
    ])
    with pytest.raises(target_guard.UnsafeTargetError):
        target_guard.assert_connectable_target("router.internal")


def test_resolution_is_pinned_to_returned_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.50.7", 0)),
    ])
    assert target_guard.assert_connectable_target("router.internal") == "192.168.50.7"


def test_explicit_scope_and_admin_allow_list_are_enforced(monkeypatch):
    assert target_guard.assert_connectable_target("10.10.4.7", ["10.10.0.0/16"]) == "10.10.4.7"
    with pytest.raises(target_guard.UnsafeTargetError, match="outside"):
        target_guard.assert_connectable_target("10.20.4.7", ["10.10.0.0/16"])
    monkeypatch.setattr(target_guard.settings, "AUTHORIZED_NETWORKS", "10.0.0.0/8")
    assert target_guard.validate_requested_scope(["10.20.0.0/16"]) == ["10.20.0.0/16"]
    with pytest.raises(target_guard.UnsafeTargetError, match="outside AUTHORIZED_NETWORKS"):
        target_guard.validate_requested_scope(["192.168.0.0/16"])


def test_scope_validation_never_resolves_or_scans(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("no resolution")))
    assert target_guard.validate_requested_scope(["172.16.4.0/24"]) == ["172.16.4.0/24"]
