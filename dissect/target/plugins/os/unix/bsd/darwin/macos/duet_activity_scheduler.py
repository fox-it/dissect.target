from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

ZPrimaryKeyRecord = TargetRecordDescriptor(
    "macos/duet_activity_scheduler/z_primary_key",
    [
        ("string", "table"),
        ("varint", "z_ent"),
        ("string", "z_name"),
        ("varint", "z_super"),
        ("varint", "z_max"),
        ("path", "source"),
    ],
)

ZGroupRecord = TargetRecordDescriptor(
    "macos/duet_activity_scheduler/z_group",
    [
        ("string", "table"),
        ("varint", "z_max_concurrent"),
        ("string", "z_name"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_pk"),
        ("path", "source"),
    ],
)

ZMetadataRecord = TargetRecordDescriptor(
    "macos/duet_activity_scheduler/z_metadata",
    [
        ("string", "table"),
        ("varint", "z_version"),
        ("string", "z_uuid"),
        ("path", "source"),
    ],
)

ZPlistRecord = TargetRecordDescriptor(
    "macos/duet_activity_scheduler/z_plist",
    [
        ("varint", "ns_persistence_maximum_framework_version"),
        ("string[]", "ns_store_model_version_identifiers"),
        ("string", "ns_store_type"),
        ("string", "ns_auto_vacuum_level"),
        ("string", "ns_store_model_version_hashes_digest"),
        ("string", "ns_store_model_version_checksum_key"),
        ("varint", "ns_persistence_framework_version"),
        ("varint", "ns_store_model_version_hashes_version"),
        ("path", "source"),
    ],
)

NSStoreModelVersionHashesRecord = TargetRecordDescriptor(
    "macos/duet_activity_scheduler/ns_store_model_version_hashes",
    [
        ("string", "tr_cloud_kit_sync_state"),
        ("string", "text_replacement_entry"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

ZModelCacheRecord = TargetRecordDescriptor(
    "macos/duet_activity_scheduler",
    [
        ("string", "table"),
        ("string", "z_content"),
        ("path", "source"),
    ],
)

DuetActivityRecords = (
    ZPrimaryKeyRecord,
    ZGroupRecord,
    ZMetadataRecord,
    ZPlistRecord,
    NSStoreModelVersionHashesRecord,
    ZModelCacheRecord,
)

FIELD_MAPPINGS = {
    "Z_PK": "z_pk",
    "Z_ENT": "z_ent",
    "Z_OPT": "z_opt",
    "Z_NAME": "z_name",
    "Z_SUPER": "z_super",
    "Z_MAX": "z_max",
    "ZMAXCONCURRENT": "z_max_concurrent",
    "ZNAME": "z_name",
    "Z_VERSION": "z_version",
    "Z_UUID": "z_uuid",
    "Z_CONTENT": "z_content",
    "NSPersistenceMaximumFrameworkVersion": "ns_persistence_maximum_framework_version",
    "NSStoreModelVersionIdentifiers": "ns_store_model_version_identifiers",
    "NSStoreType": "ns_store_type",
    "NSAutoVacuumLevel": "ns_auto_vacuum_level",
    "NSStoreModelVersionHashesDigest": "ns_store_model_version_hashes_digest",
    "NSStoreModelVersionChecksumKey": "ns_store_model_version_checksum_key",
    "NSPersistenceFrameworkVersion": "ns_persistence_framework_version",
    "NSStoreModelVersionHashesVersion": "ns_store_model_version_hashes_version",
    "TRCloudKitSyncState": "tr_cloud_kit_sync_state",
    "TextReplacementEntry": "text_replacement_entry",
}


class DuetActivitySchedulerPlugin(Plugin):
    """macOS duet activity scheduler plugin."""

    PATH = "/var/db/DuetActivityScheduler/DuetActivitySchedulerClassC.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = None
        self._resolve_file()

    def _resolve_file(self) -> None:
        path = self.target.fs.path(self.PATH)
        if path.exists():
            self.file = path

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No DuetActivitySchedulerClassC.db file found")

    @export(record=DuetActivityRecords)
    def duet_activity_scheduler(
        self,
    ) -> Iterator[DuetActivityRecords]:
        """Yield duet activity scheduler information."""
        yield from build_sqlite_records(
            self,
            (self.file,),
            DuetActivityRecords,
            field_mappings=FIELD_MAPPINGS,
        )

        # Still missing ZACTIVITY, Z_1TRIGGERS, ZTRIGGER,
        # Z_PRIMARYKEY, Z_METADATA,Z_MODELCACHE tables
