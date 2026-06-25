from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.duet_knowledge_c import DuetKnowledgeCPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "Main.db",
                "Main.db-wal",
                "User.db",
                "User.db-wal",
            ),
            (
                "/var/db/CoreDuet/Knowledge/knowledgeC.db",
                "/var/db/CoreDuet/Knowledge/knowledgeC.db-wal",
                "Users/user/Library/Application Support/Knowledge/knowledgeC.db",
                "Users/user/Library/Application Support/Knowledge/knowledgeC.db-wal",
            ),
        ),
    ],
)
def test_duet_knowledge_c(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
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
    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/duet_knowledge_c/{name}")
        fs_unix.map_file(path, data_file)

    target_unix.add_plugin(DuetKnowledgeCPlugin)

    results = list(target_unix.duet_knowledge_c())
    results.sort(key=lambda r: r.source)

    assert len(results) == 1519

    assert results[0].table == "ZKEYVALUE"
    assert results[0].z_pk == 1
    assert results[0].z_ent == 8
    assert results[0].z_opt == 1
    assert results[0].z_domain == "_DKKnowledgeStorage"
    assert results[0].z_key == "_DKDeviceIdentifier"
    assert results[0].z_value == "0CDFEFCE-422B-5A80-ABA8-FF214731A207"
    assert results[0].source == "/Users/user/Library/Application Support/Knowledge/knowledgeC.db"

    assert results[4].table == "ZOBJECT"
    assert results[4].z_pk == 1
    assert results[4].z_ent == 11
    assert results[4].z_opt == 1
    assert results[4].z_uuid_hash == -8894672422482144995
    assert results[4].z_event is None
    assert results[4].z_source_fk is None
    assert results[4].z_category_type is None
    assert results[4].z_integer_value is None
    assert results[4].z_compatibility_version == 0
    assert results[4].z_end_day_of_week == 2
    assert results[4].z_end_second_of_day == 41368
    assert not results[4].z_has_custom_metadata
    assert results[4].z_has_structured_metadata
    assert results[4].z_seconds_from_gmt == -25200
    assert results[4].z_should_sync == 0
    assert results[4].z_start_day_of_week == 2
    assert results[4].z_start_second_of_day == 41357
    assert results[4].z_value_class == 1
    assert results[4].z_value_integer == 8601942810060236944
    assert results[4].z_value_type_code == 6584185901589580638
    assert results[4].z_structured_metadata == 1
    assert results[4].z_value is None
    assert results[4].z_9_value is None
    assert results[4].z_identifier_type is None
    assert results[4].z_quantity_type is None
    assert results[4].z_creation_date == datetime(2026, 5, 4, 11, 30, 14, 945838, tzinfo=timezone.utc)
    assert results[4].z_local_creation_date == datetime(2026, 5, 4, 11, 30, 14, 945838, tzinfo=timezone.utc)
    assert results[4].z_confidence == 1
    assert results[4].z_end_date == datetime(2026, 5, 4, 11, 29, 28, tzinfo=timezone.utc)
    assert results[4].z_start_date == datetime(2026, 5, 4, 11, 29, 17, tzinfo=timezone.utc)
    assert results[4].z_value_double == 8601942810060236800
    assert results[4].z_double_value is None
    assert results[4].z_uuid == "69EE812C-4254-4E54-BFB7-3ED3B5BEFB4C"
    assert results[4].z_stream_name == "/app/usage"
    assert results[4].z_value_string == "com.apple.SetupAssistant"
    assert results[4].z_string is None
    assert results[4].z_metadata is None
    assert results[4].source == "/Users/user/Library/Application Support/Knowledge/knowledgeC.db"

    assert results[701].table == "ZSOURCE"
    assert results[701].z_pk == 1
    assert results[701].z_ent == 14
    assert results[701].z_opt == 1
    assert results[701].z_user_id is None
    assert results[701].z_bundle_id == "com.apple.Spotlight"
    assert results[701].z_device_id is None
    assert results[701].z_group_id is None
    assert results[701].z_intent_id is None
    assert results[701].z_item_id is None
    assert results[701].z_source_id is None
    assert results[701].source == "/Users/user/Library/Application Support/Knowledge/knowledgeC.db"

    assert results[714].table == "ZSTRUCTUREDMETADATA"
    assert results[714].z_pk == 1
    assert results[714].z_ent == 15
    assert results[714].z_opt == 262
    assert results[714].source == "/Users/user/Library/Application Support/Knowledge/knowledgeC.db"

    assert results[875].ns_persistence_maximum_framework_version == 1526
    assert results[875].ns_store_model_version_identifiers == ["34"]
    assert results[875].ns_store_type == "SQLite"
    assert results[875].ns_auto_vacuum_level == 2
    assert (
        results[875].ns_store_model_version_hashes_digest
        == "3qw03JLBtryClpLQRtPhA43k8KZaw9qHvu+RVzuPBYSEm8++KjboFwDAjFByeXrvryJrBSPo/o4LL6G9pmuo8Q=="
    )
    assert results[875].ns_store_model_version_checksum_key == "1nRfv9qJjn86Sz4iC1FpuA6z3NAw1YNPMMABL4ISiEA="
    assert results[875].ns_persistence_framework_version == 1526
    assert results[875].ns_store_model_version_hashes_version == 3
    assert results[875].plist_path == "Z_METADATA/Z_VERSION=1"
    assert results[875].source == "/Users/user/Library/Application Support/Knowledge/knowledgeC.db"

    assert (
        results[876].addition_change_set
        == b"\x01\r!\xe0\xf4\xeb\x12VS\xa7\x9f\xa8\xaaF]m\xaa&*\xf4\x9f\x99\x1a%\x16y{\x98\x9b\x81\x80c"
    )
    assert (
        results[876].category_hash
        == b"\xfdXs \xdaJ\x1eo\t\x08\x10y\xc5\xa8\x80\xb3\x85$\x9c\xc2\x08\xef\r\x1d?\x96\xad5\xc0\xf3B\xa1"
    )
    assert (
        results[876].contextual_change_registration
        == b'\x8dg\x9b}\xb0\x7f\xe6sQ\xc9"\xc3>yd;n\xaf.,\xfd\xc8\x8fw\x06M\xb85+\xcd\xc0\xd7'
    )
    assert (
        results[876].contextual_key_path
        == b"\xd9\x16K\xa993y\xd6\x9bP\x03\xbew\x175\x8b\xa7\x16g@Up@9C\x85'*\x81\xf8\xa9M"
    )
    assert (
        results[876].custom_metadata
        == b"\xdd\xc4\x92x\xc5#.8\xfa4\x8b\xfe\xc6j\xa9P\xc8\xcbt\xb1\xca[\x06ze\xff\x12P\x14\r\x822"
    )
    assert (
        results[876].deletion_change_set
        == b"5\xf7X\xdd\xfdw\xaf\xef\x0f\xca\x15\x04\x85\xec\x17\x1d6\xc1H\x8c\x8b\x8e\x92\xa1\x18\xd8\xd2p\xec\xf3cH"
    )
    assert (
        results[876].event
        == b"\x92\x19\x0f7\xc3\x05q\xbb\x07#[\x18'\xde\x9e\xaf\x8e\x84h'[\xb2\x1bq\xcf\xfe\x88z\x01N\xf0\xf8"
    )
    assert (
        results[876].histogram
        == b"\xdby\x06D2\xade\x84z:\x8c+!\xb4\xdc\x1d\x02\xb9\x007\x866\x00\xad\x8d\xc4fz\xba\x05\xc7\xdf"
    )
    assert (
        results[876].histogram_value
        == b"N\x92&F\xacK\xce\xbc\xa1\x9d\xe1\xdf\xba\xa1X|\xe6DO\xebQ\x07\x8c2\xb0C7\xc66\x95}O"
    )
    assert (
        results[876].identifier_hash
        == b"\xa5\x0b\xd3\x1aJ7W\x05\xacp\xb7\x03\xdd\x85\x84\x04\xc2\xc6bOvy\x1ayZ\xb3Qm5^\x8a\xf8"
    )
    assert (
        results[876].key_value
        == b"\xf5\xe0z;\xbe\xdf~\xed\x10T4-^\x88\x95\x99\xd4e\xa8AZc\xdf\x0c?\x90 \xfc\x88\x06\x7fE"
    )
    assert (
        results[876].z_object
        == b"{\xe0\xb9\x12<\xb6\xe9\xfd\x03\x81'P\xce\xdd\x15c\xf7\xbc\x0bI\xb4\xd4\x98\xc2\xfa\x01TK\x8f\x81&u"
    )
    assert (
        results[876].quantity
        == b'l-&\xc2\xa4\xc6\xc4w\xeb"EC\x8a\xc6\x84\x91\x8fQ\x81\xaf\xfc\x7f\x137\x98\x04o\x89\xf0\x93\xf4\x94'
    )
    assert (
        results[876].z_source
        == b":`?\xb5\xfa\x1b\xfa\x1dJo\x05h\xf2\x83\x91(D3#\x9c.\xfa\x1d\xd6\xca\xd6\xca'\xa7\xf1\x8b\xb7"
    )
    assert (
        results[876].structured_metadata
        == b"+$\x00D\x94A\x91\xe8#\x96=\xe6B\x9e6\x8bY\xb4U\x81AD\x85Y\xff\x7fZ\xef\xde2\xa0<"
    )
    assert (
        results[876].sync_peer
        == b"\xb4q\xdc\xac\x9f\x14\x0c\xc6X\x00\x18i\xce\x80\x11\xfc\x8b\x1c\x85\x95\xf44\x17\x8a\xe1MC\xc3\x05\x809l"
    )
    assert results[876].plist_path == "Z_METADATA/Z_VERSION=1/NSStoreModelVersionHashes"
    assert results[876].source == "/Users/user/Library/Application Support/Knowledge/knowledgeC.db"

    assert results[877].table == "Z_METADATA"
    assert results[877].z_version == 1
    assert results[877].z_uuid == "D66E2FEA-1161-43F5-B00C-B877BBDE1A2D"
    assert results[877].source == "/Users/user/Library/Application Support/Knowledge/knowledgeC.db"

    assert results[878].table == "Z_MODELCACHE"
    assert results[878].source == "/Users/user/Library/Application Support/Knowledge/knowledgeC.db"

    assert results[879].table == "ZCONTEXTUALCHANGEREGISTRATION"
    assert results[879].z_pk == 1
    assert results[879].z_ent == 2
    assert results[879].z_opt == 22
    assert results[879].z_is_active == 1
    assert results[879].z_is_multi_device_registration == 0
    assert results[879].z_creation_date == datetime(2026, 5, 11, 9, 1, 51, 201296, tzinfo=timezone.utc)
    assert results[879].z_identifier == "com.apple.das.apppolicy.appchanged"
    assert results[879].z_properties == "<_CDContextualChangeRegistration>"
    assert results[879].source == "/var/db/CoreDuet/Knowledge/knowledgeC.db"
