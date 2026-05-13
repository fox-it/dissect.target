from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.user_accounts import UserAccountsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        [
            "Accounts4.sqlite",
            "Accounts4.sqlite-wal",
        ]
    ],
)
def test_user_accounts(test_files: list[str], target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    target_unix.users = lambda: [
        user,
    ]

    stat_results = []
    entries = []
    for test_file in test_files:
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/user_accounts/{test_file}")
        fs_unix.map_file(f"Users/user/Library/Accounts/{test_file}", data_file)
        entry = fs_unix.get(f"Users/user/Library/Accounts/{test_file}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199
        entries.append(entry)
        stat_results.append(stat_result)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
        patch.object(entries[1], "stat", return_value=stat_results[1]),
    ):
        target_unix.add_plugin(UserAccountsPlugin)

        results = list(target_unix.user_accounts())

        assert len(results) == 290

        assert results[0].table == "ZACCESSOPTIONSKEY"
        assert results[0].z_pk == 1
        assert results[0].z_ent == 1
        assert results[0].z_opt == 1
        assert results[0].z_enum_value == 0
        assert results[0].z_name == "ACTencentWeiboAppIdKey"
        assert results[0].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[7].table == "Z_1OWNINGACCOUNTTYPES"
        assert results[7].z_1_access_keys == 7
        assert results[7].z_4_owning_account_types == 43
        assert results[7].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[19].table == "ZACCOUNT"
        assert results[19].z_pk == 1
        assert results[19].z_ent == 2
        assert results[19].z_opt == 7
        assert results[19].z_active == 0
        assert results[19].z_authenticated == 0
        assert results[19].z_supports_authentication == 1
        assert results[19].z_visible == 1
        assert results[19].z_warming_up == 0
        assert results[19].z_account_type == 50
        assert results[19].z_parent_account is None
        assert results[19].z_username == "local"
        assert results[19].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[21].table == "Z_2ENABLEDDATACLASSES"
        assert results[21].z_2_enabled_accounts == 2
        assert results[21].z_7_enabled_dataclasses == 20
        assert results[21].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[22].table == "ZACCOUNTPROPERTY"
        assert results[22].z_pk == 1
        assert results[22].z_ent == 3
        assert results[22].z_opt == 1
        assert results[22].z_owner == 1
        assert results[22].z_key == "isLocalAccount"
        assert results[22].z_value is not None
        assert results[22].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[36].table == "ZACCOUNTTYPE"
        assert results[36].z_pk == 1
        assert results[36].z_ent == 4
        assert results[36].z_opt == 1
        assert results[36].z_obsolete == 0
        assert results[36].z_supports_authentication == 1
        assert results[36].z_supports_multiple_accounts == 1
        assert results[36].z_visibility == 0
        assert results[36].z_account_type_description == "Gmail"
        assert results[36].z_credential_type == "oauth2"
        assert results[36].z_identifier == "com.apple.account.Google"
        assert results[36].source == "/Users/user/Library/Accounts/Accounts4.sqlite"
