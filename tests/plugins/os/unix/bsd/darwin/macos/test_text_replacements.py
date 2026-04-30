from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.text_replacements import TextReplacementsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        [
            "TextReplacements.db",
            "TextReplacements.db-wal",
        ]
    ],
)
def test_text_replacements(test_files: list[str], target_unix: Target, fs_unix: VirtualFilesystem) -> None:
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
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/text_replacements/{test_file}")
        fs_unix.map_file(f"Users/user/Library/KeyboardServices/{test_file}", data_file)
        entry = fs_unix.get(f"Users/user/Library/KeyboardServices/{test_file}")
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(TextReplacementsPlugin)

        results = list(target_unix.text_replacements())

        assert len(results) == 8

        assert results[0].table == "ZTEXTREPLACEMENTENTRY"
        assert results[0].z_pk == 1
        assert results[0].z_ent == 1
        assert results[0].z_opt == 1
        assert results[0].z_needs_save_to_cloud == 1
        assert results[0].z_was_deleted == 0
        assert results[0].z_timestamp == "796140768.339994"
        assert results[0].z_phrase == "On my way!"
        assert results[0].z_shortcut == "omw"
        assert results[0].z_unique_name == "CB36B9A8-B570-4972-BC6C-B12DAA7C0B97"
        assert results[0].z_remote_record_info is None
        assert results[0].source == "/Users/user/Library/KeyboardServices/TextReplacements.db"

        assert results[1].table == "ZTRCLOUDKITSYNCSTATE"
        assert results[1].z_pk == 1
        assert results[1].z_ent == 2
        assert results[1].z_opt == 1
        assert results[1].z_did_pull_once == 0
        assert results[1].z_fetch_change_token is None
        assert results[1].source == "/Users/user/Library/KeyboardServices/TextReplacements.db"

        assert results[2].table == "Z_PRIMARYKEY"
        assert results[2].z_ent == 1
        assert results[2].z_name == "TextReplacementEntry"
        assert results[2].z_super == 0
        assert results[2].z_max == 1
        assert results[2].source == "/Users/user/Library/KeyboardServices/TextReplacements.db"

        assert results[3].table == "Z_PRIMARYKEY"
        assert results[3].z_ent == 2
        assert results[3].z_name == "TRCloudKitSyncState"
        assert results[3].z_super == 0
        assert results[3].z_max == 1
        assert results[3].source == "/Users/user/Library/KeyboardServices/TextReplacements.db"

        assert results[4].ns_persistence_maximum_framework_version == 1526
        assert results[4].ns_store_type == "SQLite"
        assert results[4].ns_auto_vacuum_level == "2"
        assert results[4].ns_store_model_version_identifiers == [""]
        assert results[4].ns_store_model_version_hashes_version == 3
        assert results[4].ns_store_model_version_hashes_digest == (
            "nb/qJ+hB9auf83oGYKFndhE+Etk/7JNbNosAbVi5Zu0biqTNK/UfC4ofTqRhou6nHBT1ci00ct9E+U9vnbhfPw=="
        )
        assert results[4].ns_store_model_version_checksum_key == ("c4ljuOCxf+SvLXrpw0Xcnwe7kkFsMpkUuv43N2r16m4=")
        assert results[4].source == "/Users/user/Library/KeyboardServices/TextReplacements.db"

        assert results[5].tr_cloud_kit_sync_state == (
            "\udca2 \udc8cuo\udcd1V\udcd2p\udc89C#\udcbd\udcb1$\udcf1F\udc97X\udce9\x01\x1e\x02\udccb\udcf5\udce5y$\udc90\udcc4\udcee\udcdf"  # noqa E501
        )
        assert results[5].text_replacement_entry == (
            "#C\t\udcd2l\udca7\udceaK##S\udcae\udcb7>\udc82\udcb5\udcb5ȯB\udcf4\t\udcc4]\udca2)\udcb0}+٫\x03"  # noqa RUF001
        )
        assert results[5].plist_path == "NSStoreModelVersionHashes"
        assert results[5].source == "/Users/user/Library/KeyboardServices/TextReplacements.db"

        assert results[6].table == "Z_METADATA"
        assert results[6].z_version == 1
        assert results[6].z_uuid == "555547C2-D9F5-4B51-8BEE-EEE6158CDDED"
        assert results[6].source == "/Users/user/Library/KeyboardServices/TextReplacements.db"
