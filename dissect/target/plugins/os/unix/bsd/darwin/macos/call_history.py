from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import (
    build_sqlite_records,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

ZCallBPropertiesRecord = TargetRecordDescriptor(
    "macos/call_history/call_db_properties_record",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_timer_all"),
        ("varint", "z_timer_incoming"),
        ("varint", "z_timer_last"),
        ("varint", "z_timer_lifetime"),
        ("varint", "z_timer_outgoing"),
        ("path", "source"),
    ],
)

ZPrimaryKeyRecord = TargetRecordDescriptor(
    "macos/call_history/z_primary_key",
    [
        ("string", "table"),
        ("varint", "z_ent"),
        ("string", "z_name"),
        ("varint", "z_super"),
        ("varint", "z_max"),
        ("path", "source"),
    ],
)

ZMetadataRecord = TargetRecordDescriptor(
    "macos/call_history/z_metadata",
    [
        ("string", "table"),
        ("varint", "z_version"),
        ("string", "z_uuid"),
        ("path", "source"),
    ],
)

ZPlistRecord = TargetRecordDescriptor(
    "macos/call_history/z_plist",
    [
        ("varint", "ac_account_type_version"),
        ("varint", "ns_auto_vacuum_level"),
        ("varint", "ns_persistence_framework_version"),
        ("varint", "ns_persistence_maximum_framework_version"),
        ("string", "ns_store_model_version_checksum_key"),
        ("string", "ns_store_model_version_hashes_digest"),
        ("varint", "ns_store_model_version_hashes_version"),
        ("string", "ns_store_model_version_identifiers"),
        ("string", "ns_store_type"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

NSStoreModelVersionHashesRecord = TargetRecordDescriptor(
    "macos/call_history/ns_store_model_version_hashes",
    [
        ("bytes", "call_db_properties"),
        ("bytes", "call_record"),
        ("bytes", "emergency_media_item"),
        ("bytes", "handle"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

# Contains additional Z_CONTENT field which is a binary blob. This field been removed
# from the record descriptor. The field's presence will still be mentioned in a warning.
ZModelCacheRecord = TargetRecordDescriptor(
    "macos/call_history/z_model_cache",
    [
        ("string", "table"),
        ("path", "source"),
    ],
)

CallHistoryRecords = (
    ZCallBPropertiesRecord,
    ZPrimaryKeyRecord,
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
    "Z_VERSION": "z_version",
    "Z_UUID": "z_uuid",
    "ZTIMER_ALL": "z_timer_all",
    "ZTIMER_INCOMING": "z_timer_incoming",
    "ZTIMER_LAST": "z_timer_last",
    "ZTIMER_LIFETIME": "z_timer_lifetime",
    "ZTIMER_OUTGOING": "z_timer_outgoing",
    "NSAutoVacuumLevel": "ns_auto_vacuum_level",
    "NSPersistenceFrameworkVersion": "ns_persistence_framework_version",
    "NSPersistenceMaximumFrameworkVersion": "ns_persistence_maximum_framework_version",
    "NSStoreModelVersionChecksumKey": "ns_store_model_version_checksum_key",
    "NSStoreModelVersionHashesDigest": "ns_store_model_version_hashes_digest",
    "NSStoreModelVersionHashesVersion": "ns_store_model_version_hashes_version",
    "NSStoreModelVersionIdentifiers": "ns_store_model_version_identifiers",
    "NSStoreType": "ns_store_type",
    "CallDBProperties": "call_db_properties",
    "CallRecord": "call_record",
    "EmergencyMediaItem": "emergency_media_item",
    "Handle": "handle",
}


class CallHistoryPlugin(Plugin):
    """macOS call history plugin.

    Parses macOS call history SQLite database file.

    References:
        - https://fatbobman.com/en/posts/tables_and_fields_of_coredata/
        - https://developer.apple.com/documentation/coredata/nsstoremodelversionidentifierskey
    """

    USER_PATH = ("Library/Application Support/CallHistoryDB/CallHistory.storedata",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No CallHistory.storedata file found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=CallHistoryRecords)
    def call_history(
        self,
    ) -> Iterator[CallHistoryRecords]:
        """Return call history information.

        Yields the following record types extracted from the
        CallHistory.storedata database:

        .. code-block:: text

            ZCallBPropertiesRecord:
                table (string): Name of the source table (ZCALLDBPROPERTIES).
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_timer_all (varint): Timer for all calls.
                z_timer_incoming (varint): Timer for incoming calls.
                z_timer_last (varint): Timer for last call.
                z_timer_lifetime (varint): Timer of lifetime.
                z_timer_outgoing (varint): Timer for outgoing calls.
                source (path): Path to the CallHistory.storedata database file.

            ZPrimaryKeyRecord:
                table (string): Name of the source table (Z_PRIMARYKEY).
                z_ent (varint): Entity identifier.
                z_name (string): The name of the entity in the data model.
                z_super (varint): This value corresponds to the Z_ENT of the parent entity.
                    0 indicates that the entity has no parent entity.
                z_max (varint): Marks the last used z_pk value for each registry table.
                source (path): Path to the CallHistory.storedata database file.

            ZMetadataRecord:
                table (string): Name of the source table (Z_METADATA).
                z_version (varint): The specific purpose is unknown, value is always 1.
                z_uuid (string): The ID identifier (UUID type) of the current database file.
                source (path): Path to the CallHistory.storedata database file.

            ZPlistRecord (Plist extracted from Z_METADATA's Z_PLIST field):
                ac_account_type_version (varint): AC account type version.
                ns_persistence_maximum_framework_version (varint): Maximum supported persistence framework version.
                ns_store_model_version_identifiers (string[]): Version identifiers for the model,
                    used to create the store.
                ns_store_type (string): Store type.
                ns_auto_vacuum_level (varint): Auto-vacuum level.
                ns_store_model_version_hashes_digest (string): Digest of model version hashes.
                ns_store_model_version_checksum_key (string): Model version checksum key.
                ns_persistence_framework_version (varint): Persistence framework version.
                ns_store_model_version_hashes_version (varint): Version of the ns store version hashes.
                plist_path (string): Path pointing to the Z_METADATA table and Z_VERSION value of the
                    Z_PLIST row that this record was extracted from.
                source (path): Path to the CallHistory.storedata database file.

            NSStoreModelVersionHashesRecord:
                call_db_properties (bytes): Hash for ZCALLDBPROPERTIES entity.
                call_record (bytes): Hash for ZCALLRECORD entity.
                emergency_media_item (bytes): Hash for ZEMERGENCYMEDIAITEM entity.
                handle (bytes): Hash for ZHANDLE entity.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the CallHistory.storedata database file.

            ZModelCacheRecord (contains Z_CONTENT field with binary data):
                table (string): Name of the source table (Z_MODELCACHE).
                source (path): Path to the CallHistory.storedata database file.
        """
        yield from build_sqlite_records(self, self.files, CallHistoryRecords, field_mappings=FIELD_MAPPINGS)

        # TODO: Add ZCALLRECORD, Z_2REMOTEPARTICIPANTHANDLES, ZEMERGENCYMEDIAITEM, ZHANDLE tables
