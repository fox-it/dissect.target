import textwrap
from io import BytesIO

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers.network_managers import NetworkManager
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from tests._utils import absolute_path


def test_ips_dhcp(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test DHCP lease messages from /var/log/syslog."""

    messages = """
    Jan  1 13:37:01 hostname NetworkManager[1]: <info>  [1600000000.0000] dhcp4 (eth0): option ip_address           => '10.13.37.1'
    Feb  2 13:37:02 test systemd-networkd[2]: eth0: DHCPv4 address 10.13.37.2/24 via 10.13.37.0
    Mar  3 13:37:03 localhost NetworkManager[3]: <info>  [1600000000.0003] dhcp4 (eth0):   address 10.13.37.3
    Apr  4 13:37:04 localhost dhclient[4]: bound to 10.13.37.4 -- renewal in 1337 seconds.
    May  5 13:37:05 test systemd-networkd[5]: eth0: DHCPv6 lease lost
    Jun  6 13:37:06 test systemd-networkd[5]: eth0: DHCPv6 address 2001:db8::/64 via 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
    """  # noqa E501

    fs_unix.map_file_fh(
        "/var/log/syslog",
        BytesIO(textwrap.dedent(messages).encode()),
    )

    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.ips
    results.reverse()
    assert len(results) == 5
    assert sorted(results) == ["10.13.37.1", "10.13.37.2", "10.13.37.3", "10.13.37.4", "2001:db8::"]


def test_ips_cloud_init(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test cloud-init dhcp.py lease messages."""

    messages = """
    2022-12-31 13:37:00,000 - dhcp.py[DEBUG]: Received dhcp lease on eth0 for 10.13.37.5/24
    """  # noqa E501

    fs_unix.map_file_fh(
        "/var/log/cloud-init.log",
        BytesIO(textwrap.dedent(messages).encode()),
    )

    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.ips

    assert len(results) == 1
    assert results == ["10.13.37.5"]


def test_ips_static(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test statically defined ipv4 and ipv6 addresses in /etc/network/interfaces."""

    fs_unix.map_file("/etc/network/interfaces", absolute_path("_data/plugins/os/unix/_os/ips/interfaces"))
    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.ips

    assert sorted(results) == sorted(["10.13.37.6", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"])


def test_ips_wicked_static(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test statically defined ipv4 addresses in /etc/wicked/ifconfig/."""

    fs_unix.map_file("/etc/wicked/ifconfig/eth0.xml", absolute_path("_data/plugins/os/unix/_os/ips/eth0.xml"))
    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.ips

    assert sorted(results) == sorted(["10.13.37.2", "2001:db8:ffff:ffff:ffff:ffff:ffff:fffe"])


def test_dns_static(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test statically defined ipv4 and ipv6 dns-nameservers in /etc/network/interfaces."""

    fs_unix.map_file("/etc/network/interfaces", absolute_path("_data/plugins/os/unix/_os/ips/interfaces"))
    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.dns

    assert results == [{"10.13.37.1", "10.13.37.2", "2001:db8::", "2001:db9::"}]


def test_ips_netplan_static(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test statically defined ipv4 and ipv6 ip addresses in /etc/netplan/*.yaml"""

    config = """
    # This file describes the network interfaces available on your system
    # For more information, see netplan(5).
    network:
        version: 2
        renderer: networkd
        ethernets:
            enp0s3:
                dhcp4: no
                addresses: [192.168.1.123/24]
                gateway4: 192.168.1.1
                nameservers:
                    addresses: [1.2.3.4, 5.6.7.8]
    """

    fs_unix.map_file_fh("/etc/netplan/01-netcfg.yaml", BytesIO(textwrap.dedent(config).encode()))
    target_unix_users.add_plugin(LinuxPlugin)
    assert target_unix_users.ips == ["192.168.1.123"]


@pytest.mark.parametrize(
    "config, expected_output",
    [
        ("", []),
        ("network:", []),
        ("network:\n    ethernets:\n", []),
        ("network:\n    ethernets:\n        eth0:\n", []),
        ("network:\n    ethernets:\n        eth0:\n            addresses: []\n", []),
        ("network:\n    ethernets:\n        eth0:\n            addresses: [1.2.3.4/24]\n", ["1.2.3.4"]),
        ("network:\n    ethernets:\n        eth0:\n            addresses: ['1.2.3.4']\n", ["1.2.3.4"]),
    ],
)
def test_ips_netplan_static_invalid(
    target_unix_users: Target, fs_unix: VirtualFilesystem, config: str, expected_output: list
) -> None:
    fs_unix.map_file_fh("/etc/netplan/02-netcfg.yaml", BytesIO(textwrap.dedent(config).encode()))
    target_unix_users.add_plugin(LinuxPlugin)
    assert target_unix_users.ips == expected_output


def test_ips_netplan_static_empty_regression(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    fs_unix.map_file_fh("/etc/netplan/01-netcfg.yaml", BytesIO(b""))
    target_unix_users.add_plugin(LinuxPlugin)
    assert target_unix_users.ips == []


@pytest.mark.parametrize(
    "input, expected_output",
    [
        # 'invalid' or input that should be filtered
        ("0.0.0.0", set()),
        ("127.0.0.1", set()),
        ("127.0.0.1/8", set()),
        ("0.0.0.0/24", set()),
        ("::1", set()),
        ("::", set()),
        ("0:0:0:0:0:0:0:1", set()),
        # valid input
        ("::ffff:192.0.2.128", {"::ffff:192.0.2.128"}),
        ("2001:db8::2:1", {"2001:db8::2:1"}),
        ("10.13.37.1", {"10.13.37.1"}),
        ("10.13.37.2/24", {"10.13.37.2"}),
        ("  10.13.37.3  ", {"10.13.37.3"}),
        ("2001:db8::", {"2001:db8::"}),
        ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", {"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"}),
    ],
)
def test_clean_ips(input: str, expected_output: set) -> None:
    """Test the cleaning of dirty ip addresses."""

    assert NetworkManager.clean_ips({input}) == expected_output
