from __future__ import annotations

import textwrap
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.plugins.os.unix.linux.network_managers import NetworkManager
from dissect.target.tools.query import main as target_query
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("expected_ips", "messages"),
    [
        (
            ["10.13.37.1"],
            "Jan  1 13:37:01 hostname NetworkManager[1]: <info>  [1600000000.0000] dhcp4 (eth0): option ip_address           => '10.13.37.1'",  # noqa: E501
        ),
        (["10.13.37.2"], "Feb  2 13:37:02 test systemd-networkd[2]: eth0: DHCPv4 address 10.13.37.2/24 via 10.13.37.0"),
        (
            ["10.13.37.3"],
            "Mar  3 13:37:03 localhost NetworkManager[3]: <info>  [1600000000.0003] dhcp4 (eth0):   address 10.13.37.3",
        ),
        (
            ["10.13.37.4"],
            "Apr  4 13:37:04 localhost dhclient[4]: bound to 10.13.37.4 -- renewal in 1337 seconds.",
        ),
        (
            ["2001:db8::"],
            (
                "Jun  6 13:37:06 test systemd-networkd[5]: eth0: DHCPv6 address 2001:db8::/64 via 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\n"  # noqa: E501
                "May  5 13:37:05 test systemd-networkd[5]: eth0: DHCPv6 lease lost\n"
            ),
        ),
    ],
)
def test_ips_dhcp(
    target_unix_users: Target, fs_unix: VirtualFilesystem, expected_ips: list[str], messages: str
) -> None:
    """Test DHCP lease messages from /var/log/syslog."""

    fs_unix.map_file_fh(
        "/var/log/syslog",
        BytesIO(textwrap.dedent(messages).encode()),
    )

    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.ips
    results.reverse()
    assert len(results) == len(expected_ips)
    assert sorted(results) == expected_ips


@pytest.mark.parametrize(
    ("flag", "expected_out"),
    [
        (None, "['10.13.37.2']"),
        # ("--dhcp-all", "['10.13.37.2', '10.13.37.1']"),
        # Temporarily disabled behaviour, for discussion see:
        # https://github.com/fox-it/dissect.target/pull/687#discussion_r1698515269
    ],
)
def test_ips_dhcp_arg(
    target_unix: Target,
    fs_unix: VirtualFilesystem,
    flag: str,
    expected_out: str,
    capsys: pytest.CaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test --dhcp-all flag behaviour."""

    fs_unix.map_file_fh("/etc/timezone", BytesIO(b"Europe/Amsterdam"))

    messages = """
    Apr  1 13:37:01 localhost dhclient[4]: bound to 10.13.37.1 -- renewal in 1337 seconds.
    Apr  2 13:37:02 localhost foo[1]: some other message.
    Apr  3 13:37:03 localhost dhclient[4]: bound to 10.13.37.2 -- renewal in 1337 seconds.
    """

    fs_unix.map_file_fh(
        "/var/log/syslog",
        BytesIO(textwrap.dedent(messages).encode()),
    )
    target_unix.add_plugin(LinuxPlugin)

    argv = ["target-query", "foo", "-f", "ips"]
    if flag:
        argv.append(flag)

    with patch("dissect.target.Target.open_all", return_value=[target_unix]), monkeypatch.context() as m:
        m.setattr("sys.argv", argv)
        target_query()
        out, _ = capsys.readouterr()
        assert expected_out in out


def test_ips_cloud_init(target_unix_users: Target, fs_unix: VirtualFilesystem) -> None:
    """Test cloud-init dhcp.py lease messages."""

    messages = """
    2022-12-31 13:37:00,000 - dhcp.py[DEBUG]: Received dhcp lease on eth0 for 10.13.37.5/24
    """

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
    """Test statically defined ipv4 and ipv6 ip addresses in /etc/netplan/*.yaml."""

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
    ("config", "expected_output"),
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
    ("input", "expected_output"),
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


def test_regression_ips_unique_strings(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Regression test for https://github.com/fox-it/dissect.target/issues/877."""

    config = """
    network:
        ethernets:
            eth0:
                addresses: ['1.2.3.4']
    """
    fs_unix.map_file_fh("/etc/netplan/01-netcfg.yaml", BytesIO(textwrap.dedent(config).encode()))
    fs_unix.map_file_fh("/etc/netplan/02-netcfg.yaml", BytesIO(textwrap.dedent(config).encode()))

    syslog = "Apr  4 13:37:04 localhost dhclient[4]: bound to 1.2.3.4 -- renewal in 1337 seconds."
    fs_unix.map_file_fh("/var/log/syslog", BytesIO(textwrap.dedent(syslog).encode()))

    target_unix.add_plugin(LinuxPlugin)

    assert isinstance(target_unix.ips, list)
    assert all(isinstance(ip, str) for ip in target_unix.ips)

    assert len(target_unix.ips) == 1
    assert target_unix.ips == ["1.2.3.4"]


def test_ips_dhcp_lease_files(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can detect DHCP lease files from NetworkManager and dhclient."""

    lease1 = """
    # This is private data. Do not parse.
    ADDRESS=1.2.3.4
    """

    lease2 = """
    lease {
        interface "eth0";
        fixed-address 9.0.1.2;
        option dhcp-lease-time 13337;
        option routers 0.0.0.0;
        option host-name "hostname";
        renew 1 2023/12/31 13:37:00;
        rebind 2 2023/01/01 01:00:00;
        expire 3 2024/01/01 13:37:00;
        # real leases contain more key/value pairs
    }
    lease {
        interface "eth0";
        fixed-address 5.6.7.8;
        option dhcp-lease-time 13337;
        option routers 0.0.0.0;
        option host-name "hostname";
        renew 1 2024/12/31 13:37:00;
        rebind 2 2024/01/01 01:00:00;
        expire 3 2025/01/01 13:37:00;
        # real leases contain more key/value pairs
    }
    """

    lease3 = """
    some-other "value";
    lease {
        interface "eth1";
        fixed-address 3.4.5.6;
    }
    """

    fs_unix.map_file_fh("/var/lib/NetworkManager/internal-uuid-eth0.lease", BytesIO(textwrap.dedent(lease1).encode()))
    fs_unix.map_file_fh("/var/lib/dhcp/dhclient.leases", BytesIO(textwrap.dedent(lease2).encode()))
    fs_unix.map_file_fh("/var/lib/dhclient/dhclient.eth0.leases", BytesIO(textwrap.dedent(lease3).encode()))

    syslog = "Apr  4 13:37:04 localhost dhclient[4]: bound to 1.3.3.7 -- renewal in 1337 seconds."
    fs_unix.map_file_fh("/var/log/syslog", BytesIO(textwrap.dedent(syslog).encode()))

    target_unix.add_plugin(LinuxPlugin)

    # tests if we did not call :func:`parse_unix_dhcp_log_messages` since :func:`parse_unix_dhcp_leases` has results.
    assert len(target_unix.ips) == 4
    assert sorted(target_unix.ips) == sorted(["1.2.3.4", "5.6.7.8", "9.0.1.2", "3.4.5.6"])
