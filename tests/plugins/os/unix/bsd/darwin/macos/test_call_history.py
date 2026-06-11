from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.call_history import CallHistoryPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        [
            "CallHistory.storedata",
            "CallHistory.storedata-wal",
        ]
    ],
)
def test_call_history(test_files: list[str], target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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
    for test_file in test_files:
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/call_history/{test_file}")
        fs_unix.map_file(f"Users/user/Library/Application Support/CallHistoryDB/{test_file}", data_file)

    target_unix.add_plugin(CallHistoryPlugin)

    results = list(target_unix.call_history())

    assert len(results) == 9

    assert results[0].table == "ZCALLDBPROPERTIES"
    assert results[0].z_pk == 1
    assert results[0].z_ent == 1
    assert results[0].z_opt == 1
    assert results[0].z_timer_all == 0
    assert results[0].z_timer_incoming == 0
    assert results[0].z_timer_last == 0
    assert results[0].z_timer_lifetime == 0
    assert results[0].z_timer_outgoing == 0
    assert results[0].source == "/Users/user/Library/Application Support/CallHistoryDB/CallHistory.storedata"

    assert results[1].table == "Z_PRIMARYKEY"
    assert results[1].z_ent == 1
    assert results[1].z_name == "CallDBProperties"
    assert results[1].z_super == 0
    assert results[1].z_max == 1
    assert results[1].source == "/Users/user/Library/Application Support/CallHistoryDB/CallHistory.storedata"

    assert results[5].ac_account_type_version is None
    assert results[5].ns_auto_vacuum_level == 2
    assert results[5].ns_persistence_framework_version == 1526
    assert results[5].ns_persistence_maximum_framework_version == 1526
    assert results[5].ns_store_model_version_checksum_key == "6DaLHrl7O3U+MTsaWar2wVaVZaX9wGEPdMNvdZH8pQo="
    assert (
        results[5].ns_store_model_version_hashes_digest
        == "LEcn8D9uwY2SJgHgh77aZm8/vqfyybIcJvNNEfArEjU5Jsk+HqJ26e3bbK00b2Msn7RuITsNT8uEJbQejQdctA=="
    )
    assert results[5].ns_store_model_version_hashes_version == 3
    assert results[5].ns_store_model_version_identifiers == "['43']"
    assert results[5].ns_store_type == "SQLite"
    assert results[5].plist_path == "Z_METADATA/Z_VERSION=1"
    assert results[5].source == "/Users/user/Library/Application Support/CallHistoryDB/CallHistory.storedata"

    assert results[6].plist_path == "Z_METADATA/Z_VERSION=1/NSStoreModelVersionHashes"

    assert results[6].call_db_properties is not None
    assert isinstance(results[6].call_db_properties, (bytes, bytearray))
    assert results[6].call_record is not None
    assert isinstance(results[6].call_record, (bytes, bytearray))
    assert results[6].emergency_media_item is not None
    assert isinstance(results[6].emergency_media_item, (bytes, bytearray))
    assert results[6].handle is not None
    assert isinstance(results[6].handle, (bytes, bytearray))
    assert results[6].source == "/Users/user/Library/Application Support/CallHistoryDB/CallHistory.storedata"

    assert results[7].table == "Z_METADATA"
    assert results[7].z_version == 1
    assert results[7].z_uuid == "A3ED16E2-9E8F-45FC-A3EA-1ADAEF54C44A"
    assert results[7].source == "/Users/user/Library/Application Support/CallHistoryDB/CallHistory.storedata"

    assert results[8].table == "Z_MODELCACHE"
    assert results[8].source == "/Users/user/Library/Application Support/CallHistoryDB/CallHistory.storedata"
