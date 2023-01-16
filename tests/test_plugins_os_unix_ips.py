import textwrap
from io import BytesIO

from dissect.target.plugins.os.unix.linux._os import LinuxPlugin

from ._utils import absolute_path


def test_ips_dhcp_plugin(target_unix_users, fs_unix):
    """
    Test DHCP lease messages from /var/log/syslog.
    """

    messages = """
    Jan  1 13:37:01 hostname NetworkManager[1]: <info>  [1600000000.0000] dhcp4 (eth0): option ip_address           => '10.13.37.1'
    Feb  2 13:37:02 test systemd-networkd[2]: eth0: DHCPv4 address 10.13.37.2/24 via 10.13.37.0
    Mar  3 13:37:03 localhost NetworkManager[3]: <info>  [1600000000.0003] dhcp4 (eth0):   address 10.13.37.3
    Apr  4 13:37:04 localhost dhclient[4]: bound to 10.13.37.4 -- renewal in 1337 seconds.
    """  # noqa E501

    fs_unix.map_file_fh(
        "/var/log/syslog",
        BytesIO(textwrap.dedent(messages).encode()),
    )

    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.ips(dhcp=True)
    assert results == ["10.13.37.1", "10.13.37.2", "10.13.37.3", "10.13.37.4"]


def test_ips_cloud_init_plugin(target_unix_users, fs_unix):
    """
    Test cloud-init dhcp.py lease messages.
    """

    messages = """
    2022-12-31 13:37:00,000 - dhcp.py[DEBUG]: Received dhcp lease on eth0 for 10.13.37.5/24
    """  # noqa E501

    fs_unix.map_file_fh(
        "/var/log/cloud-init.log",
        BytesIO(textwrap.dedent(messages).encode()),
    )

    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.ips(dhcp=True)
    assert results == ["10.13.37.5"]


def test_ips_static_plugin(target_unix_users, fs_unix):
    """
    Test statically defined ipv4 and ipv6 addresses in /etc/network/interfaces.
    """

    fs_unix.map_file("/etc/network/interfaces", absolute_path("data/unix/configs/ips/interfaces"))
    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.ips()

    assert sorted(results) == sorted(["10.13.37.6", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"])


def test_dns_static_plugin(target_unix_users, fs_unix):
    """
    Test statically defined ipv4 and ipv6 dns-nameservers in /etc/network/interfaces.
    """

    fs_unix.map_file("/etc/network/interfaces", absolute_path("data/unix/configs/ips/interfaces"))
    target_unix_users.add_plugin(LinuxPlugin)
    results = target_unix_users.dns

    assert results == [{"10.13.37.1", "2001:db8::"}]
