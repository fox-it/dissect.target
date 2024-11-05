import os
import posixpath
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Counter
from unittest.mock import MagicMock, patch

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.general.network import UnixInterfaceRecord
from dissect.target.plugins.os.unix.linux.network import (
    LinuxConfigParser,
    LinuxNetworkPlugin,
    NetworkManagerConfigParser,
    SystemdNetworkConfigParser,
)


def test_networkmanager_parser(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    fixture_dir = "tests/_data/plugins/os/unix/linux/NetworkManager/"
    fs_linux.makedirs("/etc/NetworkManager/system-connections")

    fs_linux.map_file(
        "/etc/NetworkManager/system-connections/wired-static.nmconnection",
        os.path.join(fixture_dir, "wired-static.nmconnection"),
    )
    fs_linux.map_file(
        "/etc/NetworkManager/system-connections/vlan.nmconnection",
        os.path.join(fixture_dir, "vlan.nmconnection"),
    )
    fs_linux.map_file(
        "/etc/NetworkManager/system-connections/wireless.nmconnection",
        os.path.join(fixture_dir, "wireless.nmconnection"),
    )

    network_manager_config_parser = NetworkManagerConfigParser(target_linux)
    interfaces = list(network_manager_config_parser.interfaces())

    assert len(interfaces) == 2
    wired, wireless = interfaces

    assert wired.name == "enp0s3"
    assert wired.type == "ethernet"
    assert wired.mac == ["08:00:27:5B:4A:EB"]
    assert Counter(wired.ip) == Counter([ip_address("192.168.2.138"), ip_address("10.1.1.10")])
    assert wired.dns == [ip_address("88.88.88.88")]
    assert Counter(wired.gateway) == Counter(
        [ip_address("192.168.2.2"), ip_address("2620:52:0:2219:222:68ff:fe11:5403"), ip_address("192.168.2.3")]
    )
    assert Counter(wired.network) == Counter([ip_network("192.168.2.0/24"), ip_network("10.1.0.0/16")])
    assert not wired.dhcp_ipv4
    assert not wired.dhcp_ipv6
    assert wired.enabled is None
    assert wired.last_connected == datetime.fromisoformat("2024-10-29 07:59:54+00:00")
    assert wired.vlan == [10]
    assert wired.source == "/etc/NetworkManager/system-connections/wired-static.nmconnection"
    assert wired.configurator == "NetworkManager"

    assert wireless.name == "wlp2s0"
    assert wireless.type == "wifi"
    assert wireless.mac == []
    assert wireless.ip == []
    assert wireless.dns == []
    assert wireless.gateway == []
    assert wireless.network == []
    assert wireless.dhcp_ipv4
    assert wireless.dhcp_ipv6
    assert wireless.enabled is None
    assert wireless.last_connected is None
    assert wireless.vlan == []
    assert wireless.source == "/etc/NetworkManager/system-connections/wireless.nmconnection"
    assert wireless.configurator == "NetworkManager"


def test_systemd_network_parser(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    fixture_dir = "tests/_data/plugins/os/unix/linux/systemd.network/"
    fs_linux.makedirs("/etc/systemd/network")

    fs_linux.map_file(
        "/etc/systemd/network/20-wired-static.network", posixpath.join(fixture_dir, "20-wired-static.network")
    )
    fs_linux.map_file(
        "/etc/systemd/network/30-wired-static-complex.network",
        posixpath.join(fixture_dir, "30-wired-static-complex.network"),
    )
    fs_linux.map_file(
        "/usr/lib/systemd/network/40-wireless.network", posixpath.join(fixture_dir, "40-wireless.network")
    )
    fs_linux.map_file("/etc/systemd/network/20-vlan.netdev", posixpath.join(fixture_dir, "20-vlan.netdev"))

    systemd_network_config_parser = SystemdNetworkConfigParser(target_linux)
    interfaces = list(systemd_network_config_parser.interfaces())

    assert len(interfaces) == 3

    wired_static, wired_static_complex, wireless = interfaces

    assert wired_static.name == "enp1s0"
    assert wired_static.type is None
    assert wired_static.mac == ["aa::bb::cc::dd::ee::ff"]
    assert wired_static.ip == [ip_address("10.1.10.9")]
    assert wired_static.dns == [ip_address("10.1.10.1")]
    assert wired_static.gateway == [ip_address("10.1.10.1")]
    assert wired_static.network == [ip_network("10.1.10.0/24")]
    assert not wired_static.dhcp_ipv4
    assert not wired_static.dhcp_ipv6
    assert wired_static.enabled is None
    assert wired_static.last_connected is None
    assert wired_static.vlan == [100]
    assert wired_static.source == "/etc/systemd/network/20-wired-static.network"
    assert wired_static.configurator == "systemd-networkd"

    assert wired_static_complex.name == "enp1s0"
    assert wired_static_complex.type == "ether"
    assert Counter(wired_static_complex.mac) == Counter(
        ["aa::bb::cc::dd::ee::ff", "ff::ee::dd::cc::bb::aa", "cc::ff::bb::aa::dd", "bb::aa::dd::cc::ff"]
    )
    assert Counter(wired_static_complex.ip) == Counter([ip_address("10.1.10.9"), ip_address("10.1.9.10")])
    assert Counter(wired_static_complex.dns) == Counter(
        [ip_address("10.1.10.1"), ip_address("10.1.10.2"), ip_address("1111:2222::3333")]
    )
    assert Counter(wired_static_complex.gateway) == Counter(
        [ip_address("10.1.6.3"), ip_address("10.1.10.2"), ip_address("10.1.9.3")]
    )
    assert Counter(wired_static_complex.network) == Counter([ip_network("10.1.0.0/16"), ip_network("10.1.9.0/24")])
    assert not wired_static_complex.dhcp_ipv4
    assert not wired_static_complex.dhcp_ipv6
    assert wired_static_complex.enabled is None
    assert wired_static_complex.last_connected is None
    assert wired_static_complex.vlan == []
    assert wired_static_complex.source == "/etc/systemd/network/30-wired-static-complex.network"
    assert wired_static_complex.configurator == "systemd-networkd"

    assert wireless.name == "wlp2s0"
    assert wireless.type == "wifi"
    assert wireless.mac == []
    assert wireless.ip == []
    assert wireless.dns == []
    assert wireless.gateway == []
    assert wireless.network == []
    assert wireless.dhcp_ipv4
    assert wireless.dhcp_ipv6
    assert wireless.enabled is None
    assert wireless.last_connected is None
    assert wired_static_complex.vlan == []
    assert wireless.source == "/usr/lib/systemd/network/40-wireless.network"
    assert wired_static_complex.configurator == "systemd-networkd"


def test_linux_network_plugin_interfaces(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    """Assert that the LinuxNetworkPlugin aggregates from all Config Parsers."""

    MockLinuxConfigParser1: LinuxConfigParser = MagicMock()
    MockLinuxConfigParser1.return_value.interfaces.return_value = []

    MockLinuxConfigParser2: LinuxConfigParser = MagicMock()
    MockLinuxConfigParser2.return_value.interfaces.return_value = [UnixInterfaceRecord()]

    with patch(
        "dissect.target.plugins.os.unix.linux.network.MANAGERS", [MockLinuxConfigParser1, MockLinuxConfigParser2]
    ):
        linux_network_plugin = LinuxNetworkPlugin(target_linux)
        interfaces = list(linux_network_plugin.interfaces())

        assert len(interfaces) == 1
        MockLinuxConfigParser1.return_value.interfaces.assert_called_once()
        MockLinuxConfigParser2.return_value.interfaces.assert_called_once()
