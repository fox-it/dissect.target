from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime

from dissect.target.plugins.os.unix.bsd.darwin.macos.user import UserPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_unix_bsd_darwin_macos_user(target_macos_users: Target) -> None:
    target_macos_users.add_plugin(UserPlugin)

    results = list(target_macos_users.account_policy())
    assert len(results) == 2

    assert results[0].creation_time == datetime("2022-09-19T15:15:34.564508Z")
    assert results[0].password_last_time is None
    assert results[0].failed_login_time is None
    assert results[0].failed_login_count is None
    assert results[0].generateduid == "BD6AC542-F7BE-1337-B2DB-30F9EE37E133"
    assert results[0].source == "/var/db/dslocal/nodes/Default/users/_dissect.plist"
