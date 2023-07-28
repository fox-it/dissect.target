from dissect.target.plugins.os.unix.bsd.osx._os import MacPlugin


def test_unix_bsd_osx_os(target_osx_users):
    target_osx_users.add_plugin(MacPlugin)

    hostname = target_osx_users.hostname
    version = target_osx_users.version
    users = list(target_osx_users.users())

    dissect_user = users[0]
    test_user = users[1]

    assert hostname == "dummys Mac"
    assert version == "macOS 11.7.5 (20G1225)"

    assert len(users) == 2

    assert dissect_user.name == "_dissect"
    assert dissect_user.passwd == "*"
    assert dissect_user.home == "/var/empty"
    assert dissect_user.shell == "/usr/bin/false"
    assert dissect_user.source == "/var/db/dslocal/nodes/Default/users/_dissect.plist"

    assert test_user.home is None
