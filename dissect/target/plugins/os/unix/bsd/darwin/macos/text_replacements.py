from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_paths import _build_userdirs
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target


ZTextReplacementEntryRecord = TargetRecordDescriptor(
    "macos/text_replacements/z_text_replacement_entry",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_was_deleted"),
        ("varint", "z_needs_save_to_cloud"),
        ("datetime", "z_timestamp"),
        ("string", "z_phrase"),
        ("string", "z_shortcut"),
        ("string", "z_unique_name"),
        ("string", "z_remote_record_info"),
        ("path", "source"),
    ],
)

ZTrCloudKitSyncStateRecord = TargetRecordDescriptor(
    "macos/text_replacements/z_tr_cloud_kit_sync_state",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_did_pull_once"),
        ("string", "z_fetch_change_token"),
        ("path", "source"),
    ],
)

ZPrimaryKeyRecord = TargetRecordDescriptor(
    "macos/text_replacements/z_primary_key",
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
    "macos/text_replacements/z_metadata",
    [
        ("string", "table"),
        ("varint", "z_version"),
        ("string", "z_uuid"),
        ("path", "source"),
    ],
)

ZPlistRecord = TargetRecordDescriptor(
    "macos/text_replacements/z_plist",
    [
        ("varint", "ns_persistence_maximum_framework_version"),
        ("string[]", "ns_store_model_version_identifiers"),
        ("string", "ns_store_type"),
        ("varint", "ns_auto_vacuum_level"),
        ("string", "ns_store_model_version_hashes_digest"),
        ("string", "ns_store_model_version_checksum_key"),
        ("varint", "ns_persistence_framework_version"),
        ("varint", "ns_store_model_version_hashes_version"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

NSStoreModelVersionHashesRecord = TargetRecordDescriptor(
    "macos/text_replacements/ns_store_model_version_hashes",
    [
        ("bytes", "tr_cloud_kit_sync_state"),
        ("bytes", "text_replacement_entry"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

# Contains additional Z_CONTENT field which is a binary blob. This field been removed
# from the record descriptor. The field's presence will still be mentioned in a warning.
ZModelCacheRecord = TargetRecordDescriptor(
    "macos/text_replacements/z_model_cache",
    [
        ("string", "table"),
        ("path", "source"),
    ],
)

TextReplacementsRecords = (
    ZTextReplacementEntryRecord,
    ZTrCloudKitSyncStateRecord,
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
    "ZWASDELETED": "z_was_deleted",
    "ZNEEDSSAVETOCLOUD": "z_needs_save_to_cloud",
    "ZTIMESTAMP": "z_timestamp",
    "ZPHRASE": "z_phrase",
    "ZSHORTCUT": "z_shortcut",
    "ZUNIQUENAME": "z_unique_name",
    "ZREMOTERECORDINFO": "z_remote_record_info",
    "ZDIDPULLONCE": "z_did_pull_once",
    "ZFETCHCHANGETOKEN": "z_fetch_change_token",
    "Z_NAME": "z_name",
    "Z_SUPER": "z_super",
    "Z_MAX": "z_max",
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
    "TRCloudKitSyncState": "tr_cloud_kit_sync_state",
    "TextReplacementEntry": "text_replacement_entry",
}

CONVERT_TIMESTAMPS = {
    "z_timestamp": "2001",
}


class TextReplacementsPlugin(Plugin):
    """macOS text replacements plugin.

    References:
        - https://fatbobman.com/en/posts/tables_and_fields_of_coredata/
        - https://developer.apple.com/documentation/coredata/nsstoremodelversionidentifierskey
    """

    PATH = ("Library/KeyboardServices/TextReplacements.db",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No TextReplacements.db files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.PATH):
            files.add(path)
        return files

    @export(record=TextReplacementsRecords)
    def text_replacements(
        self,
    ) -> Iterator[TextReplacementsRecords]:
        """Return text replacements information.

        Yields the following record types extracted from the
        TextReplacements.db database:

        .. code-block:: text

            ZTextReplacementEntryRecord:
                table (string): Name of the source table (ZTEXTREPLACEMENTENTRY).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_was_deleted (varint): Indicates if the record was deleted.
                z_needs_save_to_cloud (varint): Indicates if the record needs to be saved to cloud.
                z_timestamp (datetime): Timestamp associated with the record.
                z_phrase (string): Full replacement text (what gets inserted).
                z_shortcut (string): Shortcut text that triggers the replacement.
                z_unique_name (string): Unique identifier for the replacement entry.
                z_remote_record_info (string): Remote record info.
                source (path): Path to the TextReplacements.db file.

            ZTrCloudKitSyncStateRecord:
                table (string): Name of the source table (ZTRCLOUDKITSYNCSTATE).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_did_pull_once (varint): Indicates if initial CloudKit sync has occurred.
                z_fetch_change_token (string): CloudKit change token for sync state tracking.
                source (path): Path to the TextReplacements.db file.

            ZPrimaryKeyRecord:
                table (string): Name of the source table (Z_PRIMARYKEY).
                z_ent (varint): Entity identifier.
                z_name (string): The name of the entity in the data model.
                z_super (varint): This value corresponds to the Z_ENT of the parent entity.
                    0 indicates that the entity has no parent entity.
                z_max (varint): Marks the last used z_pk value for each registry table.
                source (path): Path to the TextReplacements.db file.

            ZMetadataRecord:
                table (string): Name of the source table (Z_METADATA).
                z_version (varint): The specific purpose is unknown, value is always 1.
                z_uuid (string): The ID identifier (UUID type) of the current database file.
                source (path): Path to the TextReplacements.db file.

            ZPlistRecord (Plist extracted from Z_METADATA's Z_PLIST field):
                ns_persistence_maximum_framework_version (varint): Maximum supported persistence framework version.
                ns_store_model_version_identifiers (string[]): Version identifiers for the model,
                    used to create the store.
                ns_store_type (string): Store type.
                ns_auto_vacuum_level (varint): Auto-vacuum level.
                ns_store_model_version_hashes_digest (string): Digest of model version hashes.
                ns_store_model_version_checksum_key (string): Model version checksum key.
                ns_persistence_framework_version (varint): Persistence framework version.
                ns_store_model_version_hashes_version (varint): Version of the ns store version hashes.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the TextReplacements.db file.

            NSStoreModelVersionHashesRecord:
                tr_cloud_kit_sync_state (bytes): Hash for ZTRCLOUDKITSYNCSTATE entity.
                text_replacement_entry (bytes): Hash for ZTEXTREPLACEMENTENTRY entity.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the TextReplacements.db file.

            ZModelCacheRecord (contains Z_CONTENT field with binary data):
                table (string): Name of the source table (Z_MODELCACHE).
                source (path): Path to the TextReplacements.db file.
        """
        yield from build_sqlite_records(
            self,
            self.files,
            TextReplacementsRecords,
            field_mappings=FIELD_MAPPINGS,
            convert_timestamps=CONVERT_TIMESTAMPS,
        )
