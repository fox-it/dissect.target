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
        assert results[19].z_date.isoformat() == "1995-03-25T14:11:32.168510+00:00"
        assert results[19].z_last_credential_renewal_rejection_date is None
        assert results[19].z_account_description is None
        assert results[19].z_authentication_type is None
        assert results[19].z_credential_type is None
        assert results[19].z_identifier == "9DE5EA8C-7EE3-433C-9387-A1158923C75B"
        assert results[19].z_modification_id == "581D5181-C65D-4598-80EE-7386D70A8799"
        assert results[19].z_owning_bundle_id == "amsaccountsd"
        assert results[19].z_username == "local"
        assert results[19].z_dataclass_properties is None
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
        assert results[22].z_value == "True"
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
        assert results[36].z_credential_protection_policy is None
        assert results[36].z_credential_type == "oauth2"
        assert results[36].z_identifier == "com.apple.account.Google"
        assert results[36].z_owning_bundle_id == "com.apple.accountsd"
        assert results[36].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[92].table == "Z_4SUPPORTEDDATACLASSES"
        assert results[92].z_4_supported_types == 55
        assert results[92].z_7_supported_dataclasses == 27
        assert results[92].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[197].table == "Z_4SYNCABLEDATACLASSES"
        assert results[197].z_4_syncable_types == 55
        assert results[197].z_7_syncable_dataclasses == 27
        assert results[197].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[279].table == "Z_PRIMARYKEY"
        assert results[279].z_ent == 1
        assert results[279].z_name == "AccessOptionsKey"
        assert results[279].z_super == 0
        assert results[279].z_max == 7
        assert results[279].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[286].ac_account_type_version == 107
        assert results[286].ns_auto_vacuum_level == 2
        assert results[286].ns_persistence_framework_version == 1526
        assert results[286].ns_persistence_maximum_framework_version == 1526
        assert results[286].ns_store_model_version_checksum_key == "ZAPc9m2m45TI0HS9GepqhdVKmn8FObA8NpZcwc7UIT8="
        assert (
            results[286].ns_store_model_version_hashes_digest
            == "6zOxtAC8CBiqUoJ8U+mC0mHIF9LkhkOGYval68MNS/V6S4tVudh/sDu45bnjvnLbb+I3Ouq7XXF3ZNolh1b4+A=="
        )
        assert results[286].ns_store_model_version_hashes_version == 3
        assert results[286].ns_store_model_version_identifiers == "['30']"
        assert results[286].ns_store_type == "SQLite"
        assert results[286].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[287].access_options_key is not None
        assert isinstance(results[287].access_options_key, (bytes, bytearray))
        assert results[287].account_hash is not None
        assert isinstance(results[287].account_hash, (bytes, bytearray))
        assert results[287].account_property is not None
        assert isinstance(results[287].account_property, (bytes, bytearray))
        assert results[287].account_type is not None
        assert isinstance(results[287].account_type, (bytes, bytearray))
        assert results[287].authorization is not None
        assert isinstance(results[287].authorization, (bytes, bytearray))
        assert results[287].credential_item is not None
        assert isinstance(results[287].credential_item, (bytes, bytearray))
        assert results[287].dataclass is not None
        assert isinstance(results[287].dataclass, (bytes, bytearray))
        assert results[287].plist_path == "NSStoreModelVersionHashes"
        assert results[287].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[288].table == "Z_METADATA"
        assert results[288].z_version == 1
        assert results[288].z_uuid == "9802D604-BFA7-4F9D-A39F-0CF8E6FD0FAC"
        assert results[288].source == "/Users/user/Library/Accounts/Accounts4.sqlite"

        assert results[289].table == "Z_MODELCACHE"
        assert results[289].source == "/Users/user/Library/Accounts/Accounts4.sqlite"
