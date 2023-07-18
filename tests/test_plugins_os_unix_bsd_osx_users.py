from dissect.target.plugins.os.unix.bsd.osx._os import MacPlugin

from ._utils import absolute_path


def test_unix_bsd_osx_user_plist_file(target_unix, fs_unix):
    plist_file = absolute_path("data/plugins/os/unix/bsd/osx/users/dissect.plist")
    fs_unix.map_file("/var/db/dslocal/nodes/Default/users/_dissect.plist", plist_file)

    target_unix.add_plugin(MacPlugin)

    results = list(target_unix.users())
    record = results[0]

    assert len(results) == 1
    assert record.name == "_dissect"
    assert record.passwd == "*"
    assert record.home == "/var/empty"
    assert record.shell == "/usr/bin/false"
    assert record.source == "/var/db/dslocal/nodes/Default/users/_dissect.plist"
