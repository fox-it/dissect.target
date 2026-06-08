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
    "macos/duet_interaction_c/z_primary_key",
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
    "macos/duet_interaction_c/z_metadata",
    [
        ("string", "table"),
        ("varint", "z_version"),
        ("string", "z_uuid"),
        ("path", "source"),
    ],
)

ZPlistRecord = TargetRecordDescriptor(
    "macos/duet_interaction_c/z_plist",
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

NSStoreModelVersionHashesRecord = TargetRecordDescriptor(
    "macos/duet_interaction_c/ns_store_model_version_hashes",
    [
        ("bytes", "attachment"),
        ("bytes", "contacts"),
        ("bytes", "interactions"),
        ("bytes", "keywords"),
        ("bytes", "metadata"),
        ("bytes", "version"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

ZKeyValueMetadataRecord = TargetRecordDescriptor(
    "macos/duet_interaction_c/z_key_value_metadata",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("string", "z_key"),
        ("string", "z_value"),
        ("path", "source"),
    ],
)

ZVersionRecord = TargetRecordDescriptor(
    "macos/duet_interaction_c/z_key_value_metadata",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_number"),
        ("datetime", "z_creation_date"),
        ("string", "z_key"),
        ("path", "source"),
    ],
)

# Contains additional Z_CONTENT field which is a binary blob. This field been removed
# from the record descriptor. The field's presence will still be mentioned in a warning.
ZModelCacheRecord = TargetRecordDescriptor(
    "macos/duet_interaction_c/z_model_cache",
    [
        ("string", "table"),
        ("path", "source"),
    ],
)

DuetInteractionCRecords = (
    ZPrimaryKeyRecord,
    ZMetadataRecord,
    ZPlistRecord,
    NSStoreModelVersionHashesRecord,
    ZModelCacheRecord,
    ZKeyValueMetadataRecord,
    ZVersionRecord,
)

FIELD_MAPPINGS = {
    "Z_PK": "z_pk",
    "Z_ENT": "z_ent",
    "Z_OPT": "z_opt",
    "Z_NAME": "z_name",
    "Z_SUPER": "z_super",
    "Z_MAX": "z_max",
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
    "ZKEY": "z_key",
    "ZVALUE": "z_value",
    "ZNUMBER": "z_number",
    "ZCREATIONDATE": "z_creation_date",
    "Attachment": "attachment",
    "Contacts": "contacts",
    "Interactions": "interactions",
    "Keywords": "keywords",
    "Metadata": "metadata",
    "Version": "version",
}

CONVERT_TIMESTAMPS = {
    "z_creation_date": "2001",
}


class DuetInteractionCPlugin(Plugin):
    """macOS Duet InteractionC plugin.

    Parses basic information about recent app activity.

    References:
        - https://www.msab.com/blog/hidden-gems-in-apple-ios-digital-forensics/
        - https://fatbobman.com/en/posts/tables_and_fields_of_coredata/
        - https://developer.apple.com/documentation/coredata/nsstoremodelversionidentifierskey
    """

    PATH = "/var/db/CoreDuet/People/interactionC.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No interactionC.db file found")

    @export(record=DuetInteractionCRecords)
    def duet_interaction_c(
        self,
    ) -> Iterator[DuetInteractionCRecords]:
        """Return macOS Duet InteractionC database entries.

        Yields the following record types extracted from the
        interactionC.db database:

        .. code-block:: text

            ZPrimaryKeyRecord:
                table (string): Name of the source table (Z_PRIMARYKEY).
                z_ent (varint): The ID of the table.
                z_name (string): The name of the entity in the data model.
                z_super (varint): This value corresponds to the Z_ENT of the parent entity.
                    0 indicates that the entity has no parent entity.
                z_max (varint): Marks the last used z_pk value for each registry table.
                source (path): Path to the interactionC.db file.

            ZMetadataRecord:
                table (string): Name of the source table (Z_METADATA).
                z_version (varint): The specific purpose is unknown, value is always 1.
                z_uuid (string): The ID identifier (UUID type) of the current database file.
                source (path): Path to the interactionC.db file.

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
                source (path): Path to the interactionC.db file.

            NSStoreModelVersionHashesRecord:
                attachment (bytes): Hash for ZATTACHMENT entity.
                contacts (bytes): Hash for ZCONTACTS entity.
                interactions (bytes): Hash for ZINTERACTIONS entity.
                keywords (bytes): Hash for ZKEYWORDS entity.
                metadata (bytes): Hash for ZMETADATA entity.
                version (bytes): Hash for ZVERSION entity.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the knowledgeC.db database file.

            ZModelCacheRecord (contains Z_CONTENT field with binary data):
                table (string): Name of the source table (Z_MODELCACHE).
                source (path): Path to the interactionC.db file.

            ZKeyValueMetadataRecord:
                table (string): Name of the source table (ZMETADATA).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): The ID of the table.
                z_opt (varint): The version number of the data record.
                z_key (string): Property key.
                z_value (string): Property value.
                source (path): Path to the knowledgeC.db database file.

            ZVersionRecord:
                table (string): Name of the source table (ZVERSION).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): The ID of the table.
                z_opt (varint): The version number of the data record.
                z_creation_date (datetime): Creation timestamp.
                z_key (string): Property key.
        """
        yield from build_sqlite_records(
            self,
            (self.file,),
            DuetInteractionCRecords,
            field_mappings=FIELD_MAPPINGS,
            convert_timestamps=CONVERT_TIMESTAMPS,
        )

        # TODO: Add ZATTACHMENT, Z_1INTERACTIONS, ZCONTACTS, Z_2INTERACTIONRECIPIENT,
        # ZINTERACTIONS, `Z_3KEYWORDS, ZKEYWORDS tables
