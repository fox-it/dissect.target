from dissect.target.plugins.os.unix.bsd.osx._os import MacPlugin
from tests._utils import absolute_path


def test_unix_bsd_osx_os(target_osx_users, fs_osx):
    target_osx_users.add_plugin(MacPlugin)

    interface = absolute_path("_data/plugins/os/unix/bsd/osx/_os/en0.plist")
    fs_osx.map_file("/private/var/db/dhcpclient/leases/en0.plist", interface)

    hostname = target_osx_users.hostname
    version = target_osx_users.version
    users = list(target_osx_users.users())
    ips = target_osx_users.ips
    ips.sort()

    dissect_user = users[0]
    test_user = users[1]

    assert hostname == "dummys Mac"
    assert version == "macOS 11.7.5 (20G1225)"

    assert len(users) == 2
    assert len(ips) == 2

    assert dissect_user.name == "_dissect"
    assert dissect_user.passwd == "*"
    assert dissect_user.home == "/var/empty"
    assert dissect_user.shell == "/usr/bin/false"
    assert dissect_user.source == "/var/db/dslocal/nodes/Default/users/_dissect.plist"

    assert test_user.home is None

    assert ips == ["10.42.43.63", "10.42.43.64"]
