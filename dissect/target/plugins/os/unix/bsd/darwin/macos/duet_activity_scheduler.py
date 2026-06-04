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
        ("varint", "ns_auto_vacuum_level"),
        ("string", "ns_store_model_version_hashes_digest"),
        ("string", "ns_store_model_version_checksum_key"),
        ("varint", "ns_persistence_framework_version"),
        ("varint", "ns_store_model_version_hashes_version"),
        ("path", "source"),
    ],
)

ActivityRecord = TargetRecordDescriptor(
    "macos/duet_activity_scheduler/activity",
    [
        ("bytes", "activity"),
        ("bytes", "group_binary"),
        ("bytes", "trigger"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

ZModelCacheRecord = TargetRecordDescriptor(
    "macos/duet_activity_scheduler/z_cache",
    [
        ("string", "table"),
        ("path", "source"),
    ],
)

DuetActivityRecords = (
    ZPrimaryKeyRecord,
    ZGroupRecord,
    ZMetadataRecord,
    ZPlistRecord,
    ActivityRecord,
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
    "NSPersistenceMaximumFrameworkVersion": "ns_persistence_maximum_framework_version",
    "NSStoreModelVersionIdentifiers": "ns_store_model_version_identifiers",
    "NSStoreType": "ns_store_type",
    "NSAutoVacuumLevel": "ns_auto_vacuum_level",
    "NSStoreModelVersionHashesDigest": "ns_store_model_version_hashes_digest",
    "NSStoreModelVersionChecksumKey": "ns_store_model_version_checksum_key",
    "NSPersistenceFrameworkVersion": "ns_persistence_framework_version",
    "NSStoreModelVersionHashesVersion": "ns_store_model_version_hashes_version",
    "Activity": "activity",
    "Group": "group_binary",
    "Trigger": "trigger",
}


class DuetActivitySchedulerPlugin(Plugin):
    """macOS Duet Activity Scheduler plugin.

    The Duet Activity Scheduler is a macOS background daemon
    responsible for scheduling and managing deferred and conditional
    activities.

    References:
        - https://fatbobman.com/en/posts/tables_and_fields_of_coredata/
        - https://developer.apple.com/documentation/coredata/nsstoremodelversionidentifierskey
    """

    PATH = "/var/db/DuetActivityScheduler/DuetActivitySchedulerClassC.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No DuetActivitySchedulerClassC.db file found")

    @export(record=DuetActivityRecords)
    def duet_activity_scheduler(
        self,
    ) -> Iterator[DuetActivityRecords]:
        """Return macOS Duet Activity Scheduler database entries.

        Yields the following record types extracted from the
        DuetActivitySchedulerClassC.db database:

        .. code-block:: text

            ZPrimaryKeyRecord:
                table (string): Name of the source table (Z_PRIMARYKEY).
                z_ent (varint): The ID of the table.
                z_name (string): The name of the entity in the data model.
                z_super (varint): This value corresponds to the Z_ENT of the parent entity.
                    0 indicates that the entity has no parent entity.
                z_max (varint): Marks the last used z_pk value for each registry table.
                source (path): Path to the DuetActivitySchedulerClassC.db file.

            ZGroupRecord:
                table (string): Name of the source table (ZGROUP).
                z_max_concurrent (varint): Maximum number of concurrent activities allowed.
                z_name (string): The name of the entity in the data model.
                z_ent (varint): The ID of the table.
                z_opt (varint): The version number of the data record.
                z_pk (varint): The autoincrement primary key of the table.
                source (path): Path to the DuetActivitySchedulerClassC.db file.

            ZMetadataRecord:
                table (string): Name of the source table (Z_METADATA).
                z_version (varint): The specific purpose is unknown, value is always 1.
                z_uuid (string): The ID identifier (UUID type) of the current database file.
                source (path): Path to the DuetActivitySchedulerClassC.db file.

            ZPlistRecord (Plist extracted from Z_METADATA's Z_PLIST field):
                ns_persistence_maximum_framework_version (varint): Maximum supported persistence framework version.
                ns_store_model_version_identifiers (string[]): Version identifiers for the model,
                    used to create the store.
                ns_store_type (string): Store type.
                ns_auto_vacuum_level (varint): Auto-vacuum level.
                ns_store_model_version_hashes_digest (string): Digest of model version hashes.
                ns_store_model_version_checksum_key (string): Model version checksum key.
                ns_persistence_framework_version (varint): Persistence framework version.
                ns_store_model_version_hashes_version (varint): Version of the hashes.
                source (path): Path to the DuetActivitySchedulerClassC.db file.

            ActivityRecord:
                activity (bytes): Binary identifier of the activity.
                group_binary (bytes): Binary identifier referencing a group.
                trigger (bytes): Binary identifier referencing a trigger.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the DuetActivitySchedulerClassC.db file.

            ZModelCacheRecord (contains Z_CONTENT field with binary data):
                table (string): Name of the source table (Z_MODELCACHE).
                source (path): Path to the DuetActivitySchedulerClassC.db file.
        """
        yield from build_sqlite_records(
            self,
            (self.file,),
            DuetActivityRecords,
            field_mappings=FIELD_MAPPINGS,
        )

        # TODO: Add ZACTIVITY, Z_1TRIGGERS, ZTRIGGER,
        # Z_PRIMARYKEY, Z_METADATA,Z_MODELCACHE tables
