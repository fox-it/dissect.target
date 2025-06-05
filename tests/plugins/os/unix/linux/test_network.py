from __future__ import annotations

import posixpath
from collections import Counter
from datetime import datetime
from ipaddress import ip_address, ip_interface
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from dissect.target.plugins.os.default.network import UnixInterfaceRecord
from dissect.target.plugins.os.unix.linux.network import (
    LinuxNetworkConfigParser,
    LinuxNetworkPlugin,
    NetworkManagerConfigParser,
    SystemdNetworkConfigParser,
)

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_networkmanager_parser(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    fixture_dir = "tests/_data/plugins/os/unix/linux/NetworkManager/"
    fs_linux.map_dir("/etc/NetworkManager/system-connections", fixture_dir)

    network_manager_config_parser = NetworkManagerConfigParser(target_linux)
    interfaces = list(network_manager_config_parser.interfaces())

    assert len(interfaces) == 2
    wired, wireless = interfaces

    assert wired.name == "enp0s3"
    assert wired.type == "ethernet"
    assert wired.enabled is None
    assert Counter(wired.cidr) == Counter([ip_interface("192.168.2.138/24"), ip_interface("10.1.1.10/16")])
    assert Counter(wired.gateway) == Counter(
        [ip_address("192.168.2.2"), ip_address("2620:52:0:2219:222:68ff:fe11:5403"), ip_address("192.168.2.3")]
    )
    assert wired.dns == [ip_address("88.88.88.88")]
    assert wired.mac == ["08:00:27:5B:4A:EB"]
    assert wired.source == "/etc/NetworkManager/system-connections/wired-static.nmconnection"
    assert not wired.dhcp_ipv4
    assert not wired.dhcp_ipv6
    assert wired.last_connected == datetime.fromisoformat("2024-10-29 07:59:54+00:00")
    assert Counter(wired.vlan) == Counter([10, 11])
    assert wired.configurator == "NetworkManager"

    assert wireless.name == "wlp2s0"
    assert wireless.type == "wifi"
    assert wireless.enabled is None
    assert wireless.cidr == []
    assert wireless.gateway == []
    assert wireless.dns == []
    assert wireless.mac == []
    assert wireless.source == "/etc/NetworkManager/system-connections/wireless.nmconnection"
    assert wireless.dhcp_ipv4
    assert wireless.dhcp_ipv6
    assert wireless.last_connected is None
    assert wireless.vlan == []
    assert wireless.configurator == "NetworkManager"


def test_systemd_network_parser(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    fixture_dir = "tests/_data/plugins/os/unix/linux/systemd.network/"

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
    fs_linux.map_file(
        "/run/systemd/network/40-wireless-ipv4.network", posixpath.join(fixture_dir, "40-wireless-ipv4.network")
    )
    fs_linux.map_file(
        "/usr/local/lib/systemd/network/40-wireless-ipv6.network",
        posixpath.join(fixture_dir, "40-wireless-ipv6.network"),
    )
    fs_linux.map_file("/etc/systemd/network/20-vlan.netdev", posixpath.join(fixture_dir, "20-vlan.netdev"))
    fs_linux.map_file("/etc/systemd/network/20-vlan2.netdev", posixpath.join(fixture_dir, "20-vlan2.netdev"))

    systemd_network_config_parser = SystemdNetworkConfigParser(target_linux)
    interfaces = list(systemd_network_config_parser.interfaces())

    assert len(interfaces) == 5
    wired_static, wired_static_complex, wireless, wireless_ipv4, wireless_ipv6 = interfaces

    assert wired_static.name == "enp1s0"
    assert wired_static.type is None
    assert wired_static.enabled is None
    assert wired_static.cidr == ["10.1.10.9/24"]
    assert wired_static.gateway == [ip_address("10.1.10.1")]
    assert wired_static.dns == [ip_address("10.1.10.1")]
    assert wired_static.mac == ["aa::bb::cc::dd::ee::ff"]
    assert wired_static.source == "/etc/systemd/network/20-wired-static.network"
    assert not wired_static.dhcp_ipv4
    assert not wired_static.dhcp_ipv6
    assert wired_static.last_connected is None
    assert Counter(wired_static.vlan) == Counter([100, 101])
    assert wired_static.configurator == "systemd-networkd"

    assert wired_static_complex.name == "enp1s0"
    assert wired_static_complex.type == "ether"
    assert wired_static_complex.enabled is None
    assert Counter(wired_static_complex.cidr) == Counter([ip_interface("10.1.10.9/16"), ip_interface("10.1.9.10/24")])
    assert Counter(wired_static_complex.gateway) == Counter(
        [ip_address("10.1.6.3"), ip_address("10.1.10.2"), ip_address("10.1.9.3")]
    )
    assert Counter(wired_static_complex.dns) == Counter(
        [ip_address("10.1.10.1"), ip_address("10.1.10.2"), ip_address("1111:2222::3333")]
    )
    assert Counter(wired_static_complex.mac) == Counter(
        ["aa::bb::cc::dd::ee::ff", "ff::ee::dd::cc::bb::aa", "cc::ff::bb::aa::dd", "bb::aa::dd::cc::ff"]
    )
    assert wired_static_complex.source == "/etc/systemd/network/30-wired-static-complex.network"
    assert not wired_static_complex.dhcp_ipv4
    assert not wired_static_complex.dhcp_ipv6
    assert wired_static_complex.last_connected is None
    assert wired_static_complex.vlan == []
    assert wired_static_complex.configurator == "systemd-networkd"

    assert wireless.name == "wlp2s0"
    assert wireless.type == "wifi"
    assert wireless.enabled is None
    assert wireless.cidr == []
    assert wireless.gateway == []
    assert wireless.dns == []
    assert wireless.mac == []
    assert wireless.source == "/usr/lib/systemd/network/40-wireless.network"
    assert wireless.dhcp_ipv4
    assert wireless.dhcp_ipv6
    assert wireless.last_connected is None
    assert wired_static_complex.vlan == []
    assert wired_static_complex.configurator == "systemd-networkd"

    assert wireless_ipv4.source == "/run/systemd/network/40-wireless-ipv4.network"
    assert wireless_ipv4.dhcp_ipv4
    assert not wireless_ipv4.dhcp_ipv6

    assert wireless_ipv6.source == "/usr/local/lib/systemd/network/40-wireless-ipv6.network"
    assert not wireless_ipv6.dhcp_ipv4
    assert wireless_ipv6.dhcp_ipv6


def test_systemd_network_drop(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    fixture_dir = "tests/_data/plugins/os/unix/linux/systemd.network/"

    fs_linux.map_file(
        "/etc/systemd/network/30-wired-static-complex.network",
        posixpath.join(fixture_dir, "30-wired-static-complex.network"),
    )
    fs_linux.map_file(
        "/etc/systemd/network/30-wired-static-complex.network.d/10-override.conf",
        posixpath.join(fixture_dir, "30-wired-static-complex.network.d/10-override.conf"),
    )
    fs_linux.map_file(
        "/etc/systemd/network/30-wired-static-complex.network.d/20-override.conf",
        posixpath.join(fixture_dir, "30-wired-static-complex.network.d/20-override.conf"),
    )

    systemd_network_config_parser = SystemdNetworkConfigParser(target_linux)
    interfaces = list(systemd_network_config_parser.interfaces())

    assert len(interfaces) == 1
    [wired_static_complex] = interfaces

    assert wired_static_complex.name == "wlp2s0"
    assert wired_static_complex.type == "wifi"
    assert wired_static_complex.enabled is None
    assert Counter(wired_static_complex.cidr) == Counter([ip_interface("10.1.10.11/16")])
    assert Counter(wired_static_complex.gateway) == Counter(
        [ip_address("10.1.6.3"), ip_address("10.1.10.2"), ip_address("10.1.9.3"), ip_address("10.1.10.4")]
    )
    assert Counter(wired_static_complex.dns) == Counter(
        [ip_address("10.1.10.1"), ip_address("10.1.10.2"), ip_address("1111:2222::3333")]
    )
    assert Counter(wired_static_complex.mac) == Counter(
        ["aa::bb::cc::dd::ee::ff", "ff::ee::dd::cc::bb::aa", "cc::ff::bb::aa::dd", "bb::aa::dd::cc::ff"]
    )
    assert wired_static_complex.source == "/etc/systemd/network/30-wired-static-complex.network"
    assert wired_static_complex.dhcp_ipv4
    assert not wired_static_complex.dhcp_ipv6
    assert wired_static_complex.last_connected is None
    assert wired_static_complex.vlan == []
    assert wired_static_complex.configurator == "systemd-networkd"


def test_linux_network_plugin_interfaces(target_linux: Target) -> None:
    """Assert that the LinuxNetworkPlugin aggregates from all Config Parsers."""

    MockLinuxConfigParser1: LinuxNetworkConfigParser = MagicMock()
    MockLinuxConfigParser1.return_value.interfaces.return_value = []

    MockLinuxConfigParser2: LinuxNetworkConfigParser = MagicMock()
    MockLinuxConfigParser2.return_value.interfaces.return_value = [UnixInterfaceRecord()]

    with patch(
        "dissect.target.plugins.os.unix.linux.network.MANAGERS", [MockLinuxConfigParser1, MockLinuxConfigParser2]
    ):
        linux_network_plugin = LinuxNetworkPlugin(target_linux)
        interfaces = list(linux_network_plugin.interfaces())

        assert len(interfaces) == 1
        MockLinuxConfigParser1.return_value.interfaces.assert_called_once()
        MockLinuxConfigParser2.return_value.interfaces.assert_called_once()
