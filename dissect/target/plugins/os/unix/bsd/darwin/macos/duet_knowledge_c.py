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

ZKeyValueRecord = TargetRecordDescriptor(
    "macos/duet_knowledge_c/z_key_value",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("string", "z_domain"),
        ("string", "z_key"),
        ("string", "z_value"),
        ("path", "source"),
    ],
)

ZContextualChangeRegistrationRecord = TargetRecordDescriptor(
    "macos/duet_knowledge_c/z_contextual_change_registration",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("boolean", "z_is_active"),
        ("boolean", "z_is_multi_device_registration"),
        ("datetime", "z_creation_date"),
        ("string", "z_identifier"),
        ("string", "z_properties"),
        ("path", "source"),
    ],
)

ZObjectRecord = TargetRecordDescriptor(
    "macos/duet_knowledge_c/z_object",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_uuid_hash"),
        ("string", "z_event"),
        ("varint", "z_source_fk"),
        ("string", "z_category_type"),
        ("varint", "z_integer_value"),
        ("varint", "z_compatibility_version"),
        ("varint", "z_end_day_of_week"),
        ("varint", "z_end_second_of_day"),
        ("boolean", "z_has_custom_metadata"),
        ("boolean", "z_has_structured_metadata"),
        ("varint", "z_seconds_from_gmt"),
        ("varint", "z_should_sync"),
        ("varint", "z_start_day_of_week"),
        ("varint", "z_start_second_of_day"),
        ("varint", "z_value_class"),
        ("varint", "z_value_integer"),
        ("varint", "z_value_type_code"),
        ("varint", "z_structured_metadata"),
        ("string", "z_value"),
        ("string", "z_9_value"),
        ("string", "z_identifier_type"),
        ("string", "z_quantity_type"),
        ("datetime", "z_creation_date"),
        ("datetime", "z_local_creation_date"),
        ("varint", "z_confidence"),
        ("datetime", "z_end_date"),
        ("datetime", "z_start_date"),
        ("varint", "z_value_double"),
        ("varint", "z_double_value"),
        ("string", "z_uuid"),
        ("string", "z_stream_name"),
        ("string", "z_value_string"),
        ("string", "z_string"),
        ("string", "z_metadata"),
        ("path", "source"),
    ],
)

ZSourceRecord = TargetRecordDescriptor(
    "macos/duet_knowledge_c/z_source",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("string", "z_user_id"),
        ("string", "z_bundle_id"),
        ("string", "z_device_id"),
        ("string", "z_group_id"),
        ("string", "z_intent_id"),
        ("string", "z_item_id"),
        ("string", "z_source_id"),
        ("path", "source"),
    ],
)

# ZSTRUCTUREDMETADATA table contains 200+ more columns, most of which are None in the majority of rows.
# Reduced record descriptor to core fields, other fields will be included in a warning.
ZStructuredMetadataRecord = TargetRecordDescriptor(
    "macos/duet_knowledge_c/z_structured_metadata",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("path", "source"),
    ],
)

ZPrimaryKeyRecord = TargetRecordDescriptor(
    "macos/duet_knowledge_c/z_primary_key",
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
    "macos/duet_knowledge_c/z_metadata",
    [
        ("string", "table"),
        ("varint", "z_version"),
        ("string", "z_uuid"),
        ("path", "source"),
    ],
)

ZPlistRecord = TargetRecordDescriptor(
    "macos/duet_knowledge_c/z_plist",
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
    "macos/duet_knowledge_c/ns_store_model_version_hashes",
    [
        ("bytes", "addition_change_set"),
        ("bytes", "category_hash"),
        ("bytes", "contextual_change_registration"),
        ("bytes", "contextual_key_path"),
        ("bytes", "custom_metadata"),
        ("bytes", "deletion_change_set"),
        ("bytes", "event"),
        ("bytes", "histogram"),
        ("bytes", "histogram_value"),
        ("bytes", "identifier_hash"),
        ("bytes", "key_value"),
        ("bytes", "z_object"),
        ("bytes", "quantity"),
        ("bytes", "z_source"),
        ("bytes", "structured_metadata"),
        ("bytes", "sync_peer"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

# Contains additional Z_CONTENT field which is a binary blob. This field been removed
# from the record descriptor. The field's presence will still be mentioned in a warning.
ZModelCacheRecord = TargetRecordDescriptor(
    "macos/duet_knowledge_c/z_model_cache",
    [
        ("string", "table"),
        ("path", "source"),
    ],
)

DuetKnowledgeCRecords = (
    ZKeyValueRecord,
    ZContextualChangeRegistrationRecord,
    ZObjectRecord,
    ZSourceRecord,
    ZStructuredMetadataRecord,
    ZPlistRecord,
    NSStoreModelVersionHashesRecord,
    ZPrimaryKeyRecord,
    ZMetadataRecord,
    ZModelCacheRecord,
)
FIELD_MAPPINGS = {
    "Z_PK": "z_pk",
    "Z_ENT": "z_ent",
    "Z_OPT": "z_opt",
    "ZISACTIVE": "z_is_active",
    "ZISMULTIDEVICEREGISTRATION": "z_is_multi_device_registration",
    "ZCREATIONDATE": "z_creation_date",
    "ZIDENTIFIER": "z_identifier",
    "ZPROPERTIES": "z_properties",
    "ZUUIDHASH": "z_uuid_hash",
    "ZEVENT": "z_event",
    "ZSOURCE": "z_source_fk",
    "ZCATEGORYTYPE": "z_category_type",
    "ZINTEGERVALUE": "z_integer_value",
    "ZCOMPATIBILITYVERSION": "z_compatibility_version",
    "ZENDDAYOFWEEK": "z_end_day_of_week",
    "ZENDSECONDOFDAY": "z_end_second_of_day",
    "ZHASCUSTOMMETADATA": "z_has_custom_metadata",
    "ZHASSTRUCTUREDMETADATA": "z_has_structured_metadata",
    "ZSECONDSFROMGMT": "z_seconds_from_gmt",
    "ZSHOULDSYNC": "z_should_sync",
    "ZSTARTDAYOFWEEK": "z_start_day_of_week",
    "ZSTARTSECONDOFDAY": "z_start_second_of_day",
    "ZVALUECLASS": "z_value_class",
    "ZVALUEINTEGER": "z_value_integer",
    "ZVALUETYPECODE": "z_value_type_code",
    "ZSTRUCTUREDMETADATA": "z_structured_metadata",
    "ZKEY": "z_key",
    "ZVALUE": "z_value",
    "Z9_VALUE": "z_9_value",
    "ZIDENTIFIERTYPE": "z_identifier_type",
    "ZQUANTITYTYPE": "z_quantity_type",
    "ZLOCALCREATIONDATE": "z_local_creation_date",
    "ZCONFIDENCE": "z_confidence",
    "ZENDDATE": "z_end_date",
    "ZSTARTDATE": "z_start_date",
    "ZVALUEDOUBLE": "z_value_double",
    "ZDOUBLEVALUE": "z_double_value",
    "ZUUID": "z_uuid",
    "Z_UUID": "z_uuid",
    "ZSTREAMNAME": "z_stream_name",
    "ZVALUESTRING": "z_value_string",
    "ZSTRING": "z_string",
    "ZMETADATA": "z_metadata",
    "ZDOMAIN": "z_domain",
    "ZUSERID": "z_user_id",
    "ZBUNDLEID": "z_bundle_id",
    "ZDEVICEID": "z_device_id",
    "ZGROUPID": "z_group_id",
    "ZINTENTID": "z_intent_id",
    "ZITEMID": "z_item_id",
    "ZSOURCEID": "z_source_id",
    "Z_NAME": "z_name",
    "ZNAME": "z_name",
    "Z_SUPER": "z_super",
    "Z_MAX": "z_max",
    "Z_VERSION": "z_version",
    "NSPersistenceMaximumFrameworkVersion": "ns_persistence_maximum_framework_version",
    "NSStoreModelVersionIdentifiers": "ns_store_model_version_identifiers",
    "NSStoreType": "ns_store_type",
    "NSAutoVacuumLevel": "ns_auto_vacuum_level",
    "NSStoreModelVersionHashesDigest": "ns_store_model_version_hashes_digest",
    "NSStoreModelVersionChecksumKey": "ns_store_model_version_checksum_key",
    "NSPersistenceFrameworkVersion": "ns_persistence_framework_version",
    "NSStoreModelVersionHashesVersion": "ns_store_model_version_hashes_version",
    "AdditionChangeSet": "addition_change_set",
    "Category": "category_hash",
    "ContextualChangeRegistration": "contextual_change_registration",
    "ContextualKeyPath": "contextual_key_path",
    "CustomMetadata": "custom_metadata",
    "DeletionChangeSet": "deletion_change_set",
    "Event": "event",
    "Histogram": "histogram",
    "HistogramValue": "histogram_value",
    "Identifier": "identifier_hash",
    "KeyValue": "key_value",
    "Object": "z_object",
    "Quantity": "quantity",
    "Source": "z_source",
    "StructuredMetadata": "structured_metadata",
    "SyncPeer": "sync_peer",
}

CONVERT_TIMESTAMPS = {
    "z_creation_date": "2001",
    "z_local_creation_date": "2001",
    "z_end_date": "2001",
    "z_start_date": "2001",
}


class DuetKnowledgeCPlugin(Plugin):
    """macOS Duet KnowledgeC Plugin.

    Parses information about app and system activities.

    References:
        - https://www.msab.com/blog/hidden-gems-in-apple-ios-digital-forensics/
        - https://fatbobman.com/en/posts/tables_and_fields_of_coredata/
        - https://developer.apple.com/documentation/coredata/nsstoremodelversionidentifierskey
    """

    PATH = "/var/db/CoreDuet/Knowledge/knowledgeC.db"

    USER_PATH = ("Library/Application Support/Knowledge/knowledgeC.db",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def _find_files(self) -> set:
        files = set()
        files.add(self.target.fs.path(self.PATH))
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No knowledgeC.db files found")

    @export(record=DuetKnowledgeCRecords)
    def duet_knowledge_c(
        self,
    ) -> Iterator[DuetKnowledgeCRecords]:
        """Return macOS KnowledgeC database entries.

        Yields multiple record types extracted from the knowledgeC.db databases.

        .. code-block:: text

            ZKeyValueRecord:
                table (string): Name of the source table (Z_KEYVALUE).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_domain (string): Domain of the key/value pair.
                z_key (string): Property key.
                z_value (string): Property value.
                source (path): Path to the knowledgeC.db database file.

            ZContextualChangeRegistrationRecord:
                table (string): Name of the source table (ZCONTEXTUALCHANGEREGISTRATION).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_is_active (boolean): Whether the registration is active.
                z_is_multi_device_registration (boolean): Whether the registration is a multi-device registration.
                z_creation_date (datetime): Creation timestamp.
                z_identifier (string): Identifier of the registration.
                z_properties (string): Properties of the registration.
                source (path): Path to the knowledgeC.db database file.

            ZObjectRecord:
                table (string): Name of the source table (ZOBJECT).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_uuid_hash (varint): Hash of the UUID.
                z_event (string): Associated event.
                z_source_fk (varint): Reference to z_pk in ZSOURCE table.
                z_category_type (string): Category type.
                z_integer_value (varint): Integer value.
                z_compatibility_version (varint): Compatibility version.
                z_end_day_of_week (varint): End day of week.
                z_end_second_of_day (varint): End second of day.
                z_has_custom_metadata (boolean): Whether entry has custom metadata.
                z_has_structured_metadata (boolean): Whether entry has structured metadata.
                z_seconds_from_gmt (varint): Timezone offset from gmt.
                z_should_sync (varint): Sync flag.
                z_start_day_of_week (varint): Start day of week.
                z_start_second_of_day (varint): Start second of day.
                z_value_class (varint): Value class identifier.
                z_value_integer (varint): Integer value.
                z_value_type_code (varint): Value type code.
                z_structured_metadata (varint): Foreign key to z_pk in structured metadata.
                z_value (string): Property value.
                z_9_value (string): Secondary property value.
                z_identifier_type (string): Identifier type.
                z_quantity_type (string): Quantity type.
                z_creation_date (datetime): Creation timestamp.
                z_local_creation_date (datetime): Local creation timestamp.
                z_confidence (varint): Confidence score.
                z_end_date (datetime): End timestamp.
                z_start_date (datetime): Start timestamp.
                z_value_double (varint): Double value.
                z_double_value (varint): Double value? (Usually None)
                z_uuid (string): The ID identifier (UUID type) of the current database file.
                z_stream_name (string): Name of associated stream, identifies the activity.
                z_value_string (string): String value.
                z_string (string): Additional string field.
                z_metadata (string): Metadata.
                source (path): Path to the knowledgeC.db database file.

            ZSourceRecord:
                table (string): Name of the source table (ZSOURCE).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_user_id (string): User identifier.
                z_bundle_id (string): Application bundle ID.
                z_device_id (string): Device identifier.
                z_group_id (string): Group identifier.
                z_intent_id (string): Intent identifier.
                z_item_id (string): Item identifier.
                z_source_id (string): Unique source identifier.
                source (path): Path to the knowledgeC.db database file.

            ZStructuredMetadataRecord (table contains 200+ more columns):
                table (string): Name of the source table (ZSTRUCTUREDMETADATA).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                source (path): Path to the knowledgeC.db database file.

            ZPrimaryKeyRecord:
                table (string): Name of the source table (Z_PRIMARYKEY).
                z_ent (varint): Entity identifier.
                z_name (string): The name of the entity in the data model.
                z_super (varint): This value corresponds to the Z_ENT of the parent entity.
                    0 indicates that the entity has no parent entity.
                z_max (varint): Marks the last used z_pk value for each registry table.
                source (path): Path to the knowledgeC.db database file.

            ZMetadataRecord:
                table (string): Name of the source table (Z_METADATA).
                z_version (varint): The specific purpose is unknown, value is always 1.
                z_uuid (string): The ID identifier (UUID type) of the current database file.
                source (path): Path to the knowledgeC.db database file.

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
                source (path): Path to the knowledgeC.db database file.

            NSStoreModelVersionHashesRecord:
                addition_change_set (bytes): Hash for ZADDITIONCHANGESET entity.
                category_hash (bytes): Category hash.
                contextual_change_registration (bytes): Hash for ZCONTEXTUALCHANGEREGISTRATION entity.
                contextual_key_path (bytes): Hash for ZCONTEXTUALKEYPATH entity.
                custom_metadata (bytes): Hash for ZCUSTOMMETADATA entity.
                deletion_change_set (bytes): Hash for ZDELETIONCHANGESET entity.
                event (bytes): Hash for Z_4EVENT entity.
                histogram (bytes): Hash for ZHISTOGRAM entity.
                histogram_value (bytes): Hash for ZHISTOGRAMVALUE entity.
                identifier_hash (bytes): Identifier hash.
                key_value (bytes): Hash for ZKEYVALUE entity.
                z_object (bytes): Hash for ZOBJECT entity.
                quantity (bytes): Hash for ZQUANTITY entity.
                z_source (bytes): Hash for ZSOURCE entity.
                structured_metadata (bytes): Hash for ZSTRUCTUREDMETADATA entity.
                sync_peer (bytes): Hash for ZSYNCPEER entity.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the knowledgeC.db database file.

            ZModelCacheRecord (contains Z_CONTENT field with binary data):
                table (string): Name of the source table (Z_MODELCACHE).
                source (path): Path to the knowledgeC.db database file.
        """
        yield from build_sqlite_records(
            self,
            self.files,
            DuetKnowledgeCRecords,
            field_mappings=FIELD_MAPPINGS,
            convert_timestamps=CONVERT_TIMESTAMPS,
        )


# TODO: Add ZADDITIONCHANGESET, ZCONTEXTUALKEYPATH, ZCUSTOMMETADATA, Z_4EVENT,
#   ZDELETIONCHANGESET, ZHISTOGRAM, ZHISTOGRAMVALUE, ZKEYVALUE, ZSYNCPEER tables
