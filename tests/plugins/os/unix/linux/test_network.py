from __future__ import annotations

import textwrap
from datetime import datetime
from io import BytesIO
from ipaddress import ip_address, ip_interface
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

from dissect.target.plugins.os.default.network import UnixInterfaceRecord
from dissect.target.plugins.os.unix.linux.network import (
    DhclientLeaseParser,
    LinuxNetworkConfigParser,
    LinuxNetworkPlugin,
    NetworkManagerConfigParser,
    NetworkManagerLeaseParser,
    ProcConfigParser,
    SystemdNetworkConfigParser,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_networkmanager_parser(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    fixture_dir = absolute_path("_data/plugins/os/unix/linux/NetworkManager")
    fs_linux.map_dir("/etc/NetworkManager/system-connections", fixture_dir)

    network_manager_config_parser = NetworkManagerConfigParser(target_linux)
    interfaces = list(network_manager_config_parser.interfaces())

    assert len(interfaces) == 2
    wired, wireless = interfaces

    assert wired.name == "enp0s3"
    assert wired.type == "ethernet"
    assert wired.enabled is None
    assert set(wired.cidr) == {ip_interface("192.168.2.138/24"), ip_interface("10.1.1.10/16")}
    assert set(wired.gateway) == {
        ip_address("192.168.2.2"),
        ip_address("2620:52:0:2219:222:68ff:fe11:5403"),
        ip_address("192.168.2.3"),
    }
    assert wired.dns == [ip_address("88.88.88.88")]
    assert wired.mac == ["08:00:27:5B:4A:EB"]
    assert wired.source == "/etc/NetworkManager/system-connections/wired-static.nmconnection"
    assert not wired.dhcp_ipv4
    assert not wired.dhcp_ipv6
    assert wired.last_connected == datetime.fromisoformat("2024-10-29 07:59:54+00:00")
    assert set(wired.vlan) == {10, 11}
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
    fixture_dir = absolute_path("_data/plugins/os/unix/linux/systemd.network")

    fs_linux.map_file("/etc/systemd/network/20-wired-static.network", fixture_dir.joinpath("20-wired-static.network"))
    fs_linux.map_file(
        "/etc/systemd/network/30-wired-static-complex.network",
        fixture_dir.joinpath("30-wired-static-complex.network"),
    )
    fs_linux.map_file("/usr/lib/systemd/network/40-wireless.network", fixture_dir.joinpath("40-wireless.network"))
    fs_linux.map_file("/run/systemd/network/40-wireless-ipv4.network", fixture_dir.joinpath("40-wireless-ipv4.network"))
    fs_linux.map_file(
        "/usr/local/lib/systemd/network/40-wireless-ipv6.network",
        fixture_dir.joinpath("40-wireless-ipv6.network"),
    )
    fs_linux.map_file("/etc/systemd/network/20-vlan.netdev", fixture_dir.joinpath("20-vlan.netdev"))
    fs_linux.map_file("/etc/systemd/network/20-vlan2.netdev", fixture_dir.joinpath("20-vlan2.netdev"))

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
    assert set(wired_static.vlan) == {100, 101}
    assert wired_static.configurator == "systemd-networkd"

    assert wired_static_complex.name == "enp1s0"
    assert wired_static_complex.type == "ether"
    assert wired_static_complex.enabled is None
    assert set(wired_static_complex.cidr) == {ip_interface("10.1.10.9/16"), ip_interface("10.1.9.10/24")}
    assert set(wired_static_complex.gateway) == {
        ip_address("10.1.6.3"),
        ip_address("10.1.10.2"),
        ip_address("10.1.9.3"),
    }
    assert set(wired_static_complex.dns) == {
        ip_address("10.1.10.1"),
        ip_address("10.1.10.2"),
        ip_address("1111:2222::3333"),
    }
    assert set(wired_static_complex.mac) == {
        "aa::bb::cc::dd::ee::ff",
        "ff::ee::dd::cc::bb::aa",
        "cc::ff::bb::aa::dd",
        "bb::aa::dd::cc::ff",
    }
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
    fixture_dir = absolute_path("_data/plugins/os/unix/linux/systemd.network")

    fs_linux.map_file(
        "/etc/systemd/network/30-wired-static-complex.network",
        fixture_dir.joinpath("30-wired-static-complex.network"),
    )
    fs_linux.map_file(
        "/etc/systemd/network/30-wired-static-complex.network.d/10-override.conf",
        fixture_dir.joinpath("30-wired-static-complex.network.d/10-override.conf"),
    )
    fs_linux.map_file(
        "/etc/systemd/network/30-wired-static-complex.network.d/20-override.conf",
        fixture_dir.joinpath("30-wired-static-complex.network.d/20-override.conf"),
    )

    systemd_network_config_parser = SystemdNetworkConfigParser(target_linux)
    interfaces = list(systemd_network_config_parser.interfaces())

    assert len(interfaces) == 1
    [wired_static_complex] = interfaces

    assert wired_static_complex.name == "wlp2s0"
    assert wired_static_complex.type == "wifi"
    assert wired_static_complex.enabled is None
    assert set(wired_static_complex.cidr) == {ip_interface("10.1.10.11/16")}
    assert set(wired_static_complex.gateway) == {
        ip_address("10.1.6.3"),
        ip_address("10.1.10.2"),
        ip_address("10.1.9.3"),
        ip_address("10.1.10.4"),
    }
    assert set(wired_static_complex.dns) == {
        ip_address("10.1.10.1"),
        ip_address("10.1.10.2"),
        ip_address("1111:2222::3333"),
    }
    assert set(wired_static_complex.mac) == {
        "aa::bb::cc::dd::ee::ff",
        "ff::ee::dd::cc::bb::aa",
        "cc::ff::bb::aa::dd",
        "bb::aa::dd::cc::ff",
    }
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


def test_linux_network_dhclient_leases_file(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    lease_dhcp_dhclient = r"""
    default-duid "\000\001\000\001\037\305\371\341\001\002\003\004\005\006"
    lease {
        interface "eth0";  # some comment
        fixed-address 1.2.3.4;
        option dhcp-lease-time 13337;
        option routers 0.0.0.0;
        option host-name "hostname";
        option subnet-mask 255.255.255.0;
        renew 1 2023/12/31 13:37:00;
        rebind 2 2023/01/01 01:00:00;
        expire 3 2024/01/01 13:37:00;
    }
    lease {
        interface "eth0";
        fixed-address 2001:db8::2:1;
        option dhcp-lease-time 13338;
        option routers 1.1.1.1;
        option host-name "hostname";
        renew 4 2024/12/31 14:37:00;
        rebind 5 2024/01/01 02:00:00;
        expire 6 2025/01/01 15:37:00;
        # some more comments
    }
    """

    fs_linux.map_file_fh("/var/lib/dhcp/dhclient.leases", BytesIO(textwrap.dedent(lease_dhcp_dhclient).encode()))
    fs_linux.map_file_fh(
        "/var/lib/dhclient/dhclient.eth0.leases", BytesIO(textwrap.dedent(lease_dhcp_dhclient).encode())
    )

    dhclient = DhclientLeaseParser(target_linux)

    leases = list(dhclient.interfaces())

    assert len(leases) == 4
    assert leases[0].name == "eth0"
    assert leases[0].type == "dhcp"
    assert leases[0].cidr == [ip_interface("1.2.3.4/24")]
    assert leases[0].gateway == [ip_address("0.0.0.0")]
    assert leases[0].dhcp_ipv4
    assert not leases[0].dhcp_ipv6
    assert leases[0].configurator == "dhclient"

    assert leases[3].name == "eth0"
    assert leases[3].type == "dhcp"
    assert leases[3].cidr == [ip_interface("2001:db8::2:1/128")]
    assert leases[3].gateway == [ip_address("1.1.1.1")]
    assert not leases[3].dhcp_ipv4
    assert leases[3].dhcp_ipv6
    assert leases[0].configurator == "dhclient"


def test_linux_network_networkmanager_leases_file(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    lease_networkmanager = """
    # This is private data. Do not parse.
    ADDRESS=1.3.3.7
    """

    fs_linux.map_file_fh(
        "/var/lib/NetworkManager/internal-d6b936ad-d73f-4898-a826-edbb61d6155a-eth0.lease",
        BytesIO(textwrap.dedent(lease_networkmanager).encode()),
    )

    networkmanager = NetworkManagerLeaseParser(target_linux)
    leases = list(networkmanager.interfaces())

    assert len(leases) == 1
    assert leases[0].name == "eth0"
    assert leases[0].type == "dhcp"
    assert leases[0].configurator == "NetworkManager"
    assert leases[0].cidr == [ip_interface("1.3.3.7/32")]


def test_proc_config_parser(target_linux: Target, fs_linux: VirtualFilesystem) -> None:
    fixture_dir = absolute_path("_data/plugins/os/unix/linux/proc")
    fs_linux.map_file("/proc/net/route", fixture_dir.joinpath("route"))
    fs_linux.map_file("/proc/net/tcp", fixture_dir.joinpath("tcp"))
    fs_linux.map_file("/proc/net/if_inet6", fixture_dir.joinpath("if_inet6"))
    fs_linux.map_file("/proc/net/fib_trie", fixture_dir.joinpath("fib_trie"))

    parser = ProcConfigParser(target_linux)
    interfaces = list(parser.interfaces())

    # Destructure interfaces by name for easy assertions
    assert len(interfaces) == 4
    (
        wlp,
        docker,
        vir,
        lo,
    ) = interfaces

    assert set(wlp.cidr) == {ip_interface("fe80::f66c:ff08:22f4:9090/64"), ip_interface("192.168.1.109/24")}
    assert wlp.gateway == [ip_address("192.168.1.1")]

    assert lo.cidr == [ip_interface("::1/128")]
    assert docker.cidr == [ip_interface("172.17.0.1/16")]
    assert vir.cidr == [ip_interface("192.168.122.1/24")]
