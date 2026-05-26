from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.duet_activity_scheduler import DuetActivitySchedulerPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        [
            "DuetActivitySchedulerClassC.db",
            "DuetActivitySchedulerClassC.db-wal",
        ]
    ],
)
def test_duet_activity_scheduler(test_files: list[str], target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/duet_activity_scheduler/{test_file}")
        fs_unix.map_file(f"/var/db/DuetActivityScheduler/{test_file}", data_file)
        entry = fs_unix.get(f"/var/db/DuetActivityScheduler/{test_file}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199
        entries.append(entry)
        stat_results.append(stat_result)

    with (
        patch.object(entries[0], "stat", return_value=stat_results[0]),
        patch.object(entries[1], "stat", return_value=stat_results[1]),
    ):
        target_unix.add_plugin(DuetActivitySchedulerPlugin)

        results = list(target_unix.duet_activity_scheduler())

        assert len(results) == 55

        assert results[0].table == "ZGROUP"
        assert results[0].z_pk == 1
        assert results[0].z_ent == 2
        assert results[0].z_opt == 1
        assert results[0].z_max_concurrent == 6
        assert results[0].z_name == "com.apple.dasd.defaultNetwork"
        assert results[0].source == "/var/db/DuetActivityScheduler/DuetActivitySchedulerClassC.db"

        assert results[48].table == "Z_PRIMARYKEY"
        assert results[48].z_ent == 1
        assert results[48].z_name == "Activity"
        assert results[48].z_super == 0
        assert results[48].z_max == 0
        assert results[48].source == "/var/db/DuetActivityScheduler/DuetActivitySchedulerClassC.db"

        assert results[51].ns_persistence_maximum_framework_version == 1526
        assert results[51].ns_store_model_version_identifiers == [""]
        assert results[51].ns_store_type == "SQLite"
        assert results[51].ns_auto_vacuum_level == "2"
        assert (
            results[51].ns_store_model_version_hashes_digest
            == "rvkNkhmOezVbzsczB2H+gkUsiGN7C2d7a9TtXbZPD0kn0MZYSVEGM64BycQewlVstp1ROUAOBjEmkbNTkiu6JA=="
        )
        assert results[51].ns_store_model_version_checksum_key == "rXdwmenydb+cl65S3tSy9rIL6lkwSXqL7UvaJVK21Lc="
        assert results[51].ns_persistence_framework_version == 1526
        assert results[51].ns_store_model_version_hashes_version == 3
        assert results[51].source == "/var/db/DuetActivityScheduler/DuetActivitySchedulerClassC.db"

        assert results[52].tr_cloud_kit_sync_state is None
        assert results[52].text_replacement_entry is None
        assert results[52].plist_path == "NSStoreModelVersionHashes"
        assert results[52].source == "/var/db/DuetActivityScheduler/DuetActivitySchedulerClassC.db"

        assert results[53].table == "Z_METADATA"
        assert results[53].z_version == 1
        assert results[53].z_uuid == "514A8E5F-DE48-4C3E-9129-3AF14DEAD0E1"
        assert results[53].source == "/var/db/DuetActivityScheduler/DuetActivitySchedulerClassC.db"

        assert results[54].table == "Z_MODELCACHE"
        assert isinstance(results[54].z_content, (bytes, bytearray))
        assert results[54].source == "/var/db/DuetActivityScheduler/DuetActivitySchedulerClassC.db"
