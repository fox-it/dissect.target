from flow.record.fieldtypes import datetime

from dissect.target.plugins.os.unix.bsd.osx.user import UserPlugin

from ._utils import absolute_path


def test_unix_bsd_osx_user_plist_file(target_unix, fs_unix):
    plist_file = absolute_path("data/plugins/os/unix/bsd/osx/users/dissect.plist")
    fs_unix.map_file("/var/db/dslocal/nodes/Default/users/_dissect.plist", plist_file)

    target_unix.add_plugin(UserPlugin)

    results = list(target_unix.account_policy())

    record = results[0]

    assert len(results) == 1
    assert record.user == "_dissect"
    assert record.creation_time == datetime("2022-09-19T15:15:34.564508Z")
    assert record.password_last_time is None
    assert record.failed_login_time is None
    assert record.failed_login_count is None
    assert record.generateduid == "BD6AC542-F7BE-1337-B2DB-30F9EE37E133"
    assert str(record.source) == "/var/db/dslocal/nodes/Default/users/_dissect.plist"
