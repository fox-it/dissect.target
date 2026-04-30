from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.general import _build_userdirs

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
        ("string", "z_timestamp"),
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
        ("string", "ns_auto_vacuum_level"),
        ("string", "ns_store_model_version_hashes_digest"),
        ("string", "ns_store_model_version_checksum_key"),
        ("varint", "ns_persistence_framework_version"),
        ("varint", "ns_store_model_version_hashes_version"),
        ("path", "source"),
    ],
)

NSStoreModelVersionHashesRecord = TargetRecordDescriptor(
    "macos/text_replacements/ns_store_model_version_hashes",
    [
        ("string", "tr_cloud_kit_sync_state"),
        ("string", "text_replacement_entry"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

ZModelCacheRecord = TargetRecordDescriptor(
    "macos/text_replacements/z_model_cache",
    [
        ("string", "table"),
        ("string", "z_content"),
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


class TextReplacementsPlugin(Plugin):
    """macOS text replacements plugin."""

    PATH = ("Library/KeyboardServices/TextReplacements.db",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No TextReplacements.db files found")

    def _find_files(self) -> None:
        for _, path in _build_userdirs(self, self.PATH):
            self.files.add(path)

    @export(record=TextReplacementsRecords)
    def text_replacements(
        self,
    ) -> Iterator[TextReplacementsRecords]:
        """Yield text replacements information."""
        yield from build_sqlite_records(self, self.files, TextReplacementsRecords, field_mappings=FIELD_MAPPINGS)
