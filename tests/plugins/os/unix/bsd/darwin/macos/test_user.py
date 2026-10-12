from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.fieldtypes import datetime

from dissect.target.plugins.os.unix.bsd.darwin.macos.user import UserPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_unix_bsd_darwin_macos_user(target_macos_users: Target) -> None:
    target_macos_users.add_plugin(UserPlugin)

    results = sorted(target_macos_users.account_policy(), key=lambda r: r.source)
    assert len(results) == 2

    assert results[0].creation_time == datetime("2022-09-19T15:15:34.564508Z")
    assert results[0].password_last_time is None
    assert results[0].failed_login_time is None
    assert results[0].failed_login_count is None
    assert results[0].generateduid == "BD6AC542-F7BE-1337-B2DB-30F9EE37E133"
    assert results[0].source == "/private/var/db/dslocal/nodes/Default/users/_dissect.plist"

    assert results[1].creation_time == datetime("2025-11-20T16:31:54.379867Z")
    assert results[1].password_last_time == datetime("2025-11-20T16:31:57.756140Z")
    assert results[1].failed_login_time == datetime("1970-01-01T00:00:00Z")
    assert results[1].failed_login_count == 0
    assert results[1].generateduid == "21310052-D276-4DCD-A380-AC195969184C"
    assert results[1].source == "/private/var/db/dslocal/nodes/Default/users/alexmaurie.plist"
