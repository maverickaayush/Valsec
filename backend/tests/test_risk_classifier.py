import pytest

from connectors.risk_classifier import classify_risk


@pytest.mark.parametrize("text", [
    "configure terminal\nline vty 0 4\ntransport input ssh\nend",
    "ip ssh version 2", "crypto key generate rsa", "interface GigabitEthernet0/0\nshutdown",
])
def test_cisco_session_affecting_changes_are_risky(text):
    assert classify_risk("cisco", text)


def test_cisco_ntp_change_is_not_risky():
    assert not classify_risk("cisco", "configure terminal\nntp server 10.0.0.10\nend")


@pytest.mark.parametrize("text", [
    "set system login retry-options tries-before-disconnect 3",
    "set system services ssh protocol-version v2",
])
def test_juniper_session_affecting_changes_are_risky(text):
    assert classify_risk("juniper", text)


def test_juniper_ntp_change_is_not_risky():
    assert not classify_risk("juniper", "set system ntp server 10.0.0.10")


@pytest.mark.parametrize("text", [
    "uci set dropbear.@dropbear[0].PasswordAuth='off'",
    "uci set network.lan.ipaddr='192.168.2.1'",
    "uci set network.wan.proto='dhcp'",
    "uci set firewall.@rule[0].enabled='0'",
])
def test_uci_connectivity_changes_are_risky(text):
    assert classify_risk("OpenWrt", text)


def test_uci_hostname_and_ntp_are_not_risky():
    assert not classify_risk("OpenWrt", "uci set system.@system[0].hostname='edge'\nuci set system.ntp.enabled='1'")
