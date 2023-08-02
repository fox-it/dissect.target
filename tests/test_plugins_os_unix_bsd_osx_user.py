from flow.record.fieldtypes import datetime

from dissect.target.plugins.os.unix.bsd.osx.user import UserPlugin


def test_unix_bsd_osx_user(target_osx_users):
    target_osx_users.add_plugin(UserPlugin)

    results = list(target_osx_users.account_policy())

    record = results[0]

    assert len(results) == 2

    assert record.creation_time == datetime("2022-09-19T15:15:34.564508Z")
    assert record.password_last_time is None
    assert record.failed_login_time is None
    assert record.failed_login_count is None
    assert record.generateduid == "BD6AC542-F7BE-1337-B2DB-30F9EE37E133"
    assert str(record.source) == "/var/db/dslocal/nodes/Default/users/_dissect.plist"
