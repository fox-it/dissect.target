from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.bsd.darwin.macos.duet_interaction_c import DuetInteractionCPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    "test_files",
    [
        [
            "interactionC.db",
            "interactionC.db-wal",
        ]
    ],
)
def test_duet_activity_scheduler(test_files: list[str], target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    for test_file in test_files:
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/duet_interaction_c/{test_file}")
        fs_unix.map_file(f"/var/db/CoreDuet/People/{test_file}", data_file)

    target_unix.add_plugin(DuetInteractionCPlugin)

    results = list(target_unix.duet_interaction_c())

    assert len(results) == 12

    assert results[0].table == "ZMETADATA"
    assert results[0].z_pk == 1
    assert results[0].z_ent == 5
    assert results[0].z_opt == 1
    assert results[0].z_key == "migrateIMessageDomainIdentifiers"
    assert results[0].z_value == "True"
    assert results[0].source == "/var/db/CoreDuet/People/interactionC.db"

    assert results[1].table == "ZVERSION"
    assert results[1].z_pk == 1
    assert results[1].z_ent == 6
    assert results[1].z_opt == 1
    assert results[1].z_number == 1
    assert results[1].z_creation_date == datetime(2026, 5, 4, 11, 23, 21, 944464, tzinfo=timezone.utc)
    assert results[1].z_key == "store_version"
    assert results[1].source == "/var/db/CoreDuet/People/interactionC.db"

    assert results[2].table == "Z_PRIMARYKEY"
    assert results[2].z_ent == 1
    assert results[2].z_name == "Attachment"
    assert results[2].z_super == 0
    assert results[2].z_max == 0
    assert results[2].source == "/var/db/CoreDuet/People/interactionC.db"

    assert results[8].ns_persistence_maximum_framework_version == 1526
    assert results[8].ns_store_model_version_identifiers == ["15"]
    assert results[8].ns_store_type == "SQLite"
    assert results[8].ns_auto_vacuum_level == 2
    assert (
        results[8].ns_store_model_version_hashes_digest
        == "xtIOAHN/XyhlY4uahAH4diGw8uqBPUzu3nHg0qTa308d9X2+IXWH5fIYFrZ8DkWCDbXQ46RPaENynVIpxse4Jw=="
    )
    assert results[8].ns_store_model_version_checksum_key == "yBhxwKvskbIdxbJOzzLgxhbLYTjrWz9otOnAd9BgKA0="
    assert results[8].ns_persistence_framework_version == 1526
    assert results[8].ns_store_model_version_hashes_version == 3
    assert results[8].plist_path == "Z_METADATA/Z_VERSION=1"
    assert results[8].source == "/var/db/CoreDuet/People/interactionC.db"

    assert (
        results[9].attachment_hash
        == b"%6\xe0\xe5\x85u\x91Wf\xc7\xe8\xb8y\xe6\xfdf\x1a\xb9\x17t\x81h&e\xdc\xa9\xc3\xe1\xd3\x15\x9e\xe9"
    )
    assert (
        results[9].contacts
        == b"\x83\x87\x97\xd4\x08\xc9\xadN\xbc\xfa\xa8\xf6\x9e\xb0\x0e\xdf\x12\x96K\xb25\x1af\xef\xaaQ\xf3\x13I\x82\xfa\x94"  # noqa E501
    )
    assert (
        results[9].interactions
        == b"\x92m\xbe\x9d\x12\xf0M\xf3\xa7\xf9(\xbd9\x96Y\xa7e\xff\x1f\x9fE\xa2{\xe1\x03\xd2|\xdb\x12s%\x86"
    )
    assert (
        results[9].keywords_hash
        == b'\xff/$fi\xef\xb0\x03\x9d\xfd\xc8%>D\x9f\xbd3"\xd39\x84\xff\xe0\xf4\xa1\xe7\xd1\xf8\xcc253'
    )
    assert (
        results[9].metadata
        == b"\x93\\\xfe\x85\x91lG\xd1\x83lc\xde\xdeCO\x92G\xd0/\x8c\xa1t\xe0)y\x1d\xd1\x86M0\xdf\xc4"
    )
    assert (
        results[9].version_hash
        == b"\x94\x07\xac\x82%\x9f22\x9c\x162\xe9\xc5\xdb7\xb9\x1e\xf8\x8c(\x8e\xb1\xd7JT\xfd*\xe0\xad\x7f5\x01"
    )
    assert results[9].plist_path == "Z_METADATA/Z_VERSION=1/NSStoreModelVersionHashes"
    assert results[9].source == "/var/db/CoreDuet/People/interactionC.db"

    assert results[10].table == "Z_METADATA"
    assert results[10].z_version == 1
    assert results[10].z_uuid == "DD35E9BD-94E0-4016-887B-B91BFA9FCF84"
    assert results[10].source == "/var/db/CoreDuet/People/interactionC.db"

    assert results[11].table == "Z_MODELCACHE"
    assert results[11].source == "/var/db/CoreDuet/People/interactionC.db"
