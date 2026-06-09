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

ZAccountRecord = TargetRecordDescriptor(
    "macos/notes/z_account",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_allow_insecure_authentication"),
        ("varint", "z_did_choose_to_migrate"),
        ("varint", "z_enabled"),
        ("varint", "z_root_folder"),
        ("varint", "z6_root_folder"),
        ("varint", "z_trash_folder"),
        ("string", "z_gmail_capabilities_support"),
        ("string", "z_port"),
        ("string", "z_security_layer_type"),
        ("varint", "z_migration_offered"),
        ("string", "z_account_description"),
        ("string", "z_email_address"),
        ("string", "z_full_name"),
        ("string", "z_parent_account_identifier"),
        ("string", "z_user_name"),
        ("string", "z_folder_hierarchy_sync_state"),
        ("string", "z_authentication"),
        ("string", "z_host_name"),
        ("string", "z_server_path_prefix"),
        ("string", "z_external_url"),
        ("string", "z_internal_url"),
        ("string", "z_last_used_autodiscover_url"),
        ("string", "z_tls_certificate"),
        ("path", "source"),
    ],
)

ZFolderRecord = TargetRecordDescriptor(
    "macos/notes/z_folder",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_account"),
        ("varint", "z1_account"),
        ("varint", "z_parent"),
        ("varint", "z6_parent"),
        ("string", "z_is_distinguished"),
        ("string", "z_alleged_highest_modification_sequence"),
        ("string", "z_computed_highest_modification_sequence"),
        ("string", "z_uid_next"),
        ("string", "z_uid_validity"),
        ("varint", "z_trash_account"),
        ("varint", "z1_trash_account"),
        ("string", "z_name"),
        ("string", "z_change_key"),
        ("string", "z_user_name"),
        ("varint", "z_folder_id"),
        ("string", "z_sync_state"),
        ("string", "z_server_name"),
        ("path", "source"),
    ],
)

ZPrimaryKeyRecord = TargetRecordDescriptor(
    "macos/notes/z_primary_key",
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
    "macos/notes/z_metadata",
    [
        ("string", "table"),
        ("varint", "z_version"),
        ("string", "z_uuid"),
        ("path", "source"),
    ],
)

ZPlistRecord = TargetRecordDescriptor(
    "macos/notes/z_plist",
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
        ("path", "source"),
    ],
)

NSStoreModelVersionHashesRecord = TargetRecordDescriptor(
    "macos/notes/ns_store_model_version_hashes",
    [
        ("bytes", "account_hash"),
        ("bytes", "attachment_hash"),
        ("bytes", "ews_account"),
        ("bytes", "ews_folder"),
        ("bytes", "ews_note"),
        ("bytes", "folder"),
        ("bytes", "folder_action"),
        ("bytes", "imap_account"),
        ("bytes", "imap_folder"),
        ("bytes", "imap_note"),
        ("bytes", "insert_folder_action"),
        ("bytes", "insert_note_action"),
        ("bytes", "local_account"),
        ("bytes", "move_folder_action"),
        ("bytes", "move_note_action"),
        ("bytes", "note"),
        ("bytes", "note_action"),
        ("bytes", "note_body"),
        ("bytes", "offline_action"),
        ("bytes", "trash_folder"),
        ("bytes", "update_folder_action"),
        ("bytes", "update_note_action"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

# Contains additional Z_CONTENT field which is a binary blob. This field been removed
# from the record descriptor. The field's presence will still be mentioned in a warning.
ZModelCacheRecord = TargetRecordDescriptor(
    "macos/notes/z_model_cache",
    [
        ("string", "table"),
        ("path", "source"),
    ],
)

AChangeRecord = TargetRecordDescriptor(
    "macos/notes/a_change",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_change_type"),
        ("varint", "z_entity"),
        ("varint", "z_entity_pk"),
        ("varint", "z_transaction_id"),
        ("bytes", "z_columns"),
        ("path", "source"),
    ],
)

ATransactionRecord = TargetRecordDescriptor(
    "macos/notes/a_transaction",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_author_ts"),
        ("varint", "z_bundle_id_ts"),
        ("varint", "z_context_name_ts"),
        ("varint", "z_process_id_ts"),
        ("datetime", "z_timestamp"),
        ("string", "z_author"),
        ("string", "z_bundle_id"),
        ("string", "z_context_name"),
        ("varint", "z_process_id"),
        ("string", "z_query_gen"),
        ("path", "source"),
    ],
)

ATransactionStringRecord = TargetRecordDescriptor(
    "macos/notes/a_transaction_string",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("string", "z_name"),
        ("path", "source"),
    ],
)

NotesRecords = (
    ZAccountRecord,
    ZFolderRecord,
    ZPrimaryKeyRecord,
    ZMetadataRecord,
    ZPlistRecord,
    NSStoreModelVersionHashesRecord,
    ZModelCacheRecord,
    AChangeRecord,
    ATransactionRecord,
    ATransactionStringRecord,
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
    "NSAutoVacuumLevel": "ns_auto_vacuum_level",
    "NSPersistenceFrameworkVersion": "ns_persistence_framework_version",
    "NSPersistenceMaximumFrameworkVersion": "ns_persistence_maximum_framework_version",
    "NSStoreModelVersionChecksumKey": "ns_store_model_version_checksum_key",
    "NSStoreModelVersionHashesDigest": "ns_store_model_version_hashes_digest",
    "NSStoreModelVersionHashesVersion": "ns_store_model_version_hashes_version",
    "NSStoreModelVersionIdentifiers": "ns_store_model_version_identifiers",
    "NSStoreType": "ns_store_type",
    "ZALLOWINSECUREAUTHENTICATION": "z_allow_insecure_authentication",
    "ZDIDCHOOSETOMIGRATE": "z_did_choose_to_migrate",
    "ZENABLED": "z_enabled",
    "ZROOTFOLDER": "z_root_folder",
    "Z6_ROOTFOLDER": "z6_root_folder",
    "ZTRASHFOLDER": "z_trash_folder",
    "ZGMAILCAPABILITIESSUPPORT": "z_gmail_capabilities_support",
    "ZPORT": "z_port",
    "ZMIGRATIONOFFERED": "z_migration_offered",
    "ZACCOUNTDESCRIPTION": "z_account_description",
    "ZEMAILADDRESS": "z_email_address",
    "ZFULLNAME": "z_full_name",
    "ZUSERNAME": "z_user_name",
    "ZFOLDERHIERARCHYSYNCSTATE": "z_folder_hierarchy_sync_state",
    "ZAUTHENTICATION": "z_authentication",
    "ZHOSTNAME": "z_host_name",
    "ZSERVERPATHPREFIX": "z_server_path_prefix",
    "ZEXTERNALURL": "z_external_url",
    "ZINTERNALURL": "z_internal_url",
    "ZLASTUSEDAUTODISCOVERURL": "z_last_used_autodiscover_url",
    "ZTLSCERTIFICATE": "z_tls_certificate",
    "ZACCOUNT": "z_account",
    "Z1_ACCOUNT": "z1_account",
    "ZPARENT": "z_parent",
    "Z6_PARENT": "z6_parent",
    "ZISDISTINGUISHED": "z_is_distinguished",
    "ZALLEGEDHIGHESTMODIFICATIONSEQUENCE": "z_alleged_highest_modification_sequence",
    "ZCOMPUTEDHIGHESTMODIFICATIONSEQUENCE": "z_computed_highest_modification_sequence",
    "ZUIDNEXT": "z_uid_next",
    "ZTRASHACCOUNT": "z_trash_account",
    "Z1_TRASHACCOUNT": "z1_trash_account",
    "ZNAME": "z_name",
    "ZCHANGEKEY": "z_change_key",
    "ZFOLDERID": "z_folder_id",
    "ZSYNCSTATE": "z_sync_state",
    "ZSERVERNAME": "z_server_name",
    "ZCHANGETYPE": "z_change_type",
    "ZENTITY": "z_entity",
    "ZENTITYPK": "z_entity_pk",
    "ZTRANSACTIONID": "z_transaction_id",
    "ZCOLUMNS": "z_columns",
    "ZAUTHORTS": "z_author_ts",
    "ZBUNDLEIDTS": "z_bundle_id_ts",
    "ZCONTEXTNAMETS": "z_context_name_ts",
    "ZPROCESSIDTS": "z_process_id_ts",
    "ZTIMESTAMP": "z_timestamp",
    "ZAUTHOR": "z_author",
    "ZBUNDLEID": "z_bundle_id",
    "ZCONTEXTNAME": "z_context_name",
    "ZPROCESSID": "z_process_id",
    "ZQUERYGEN": "z_query_gen",
    "ZSECURITYLAYERTYPE": "z_security_layer_type",
    "ZPARENTACACCOUNTIDENTIFIER": "z_parent_account_identifier",
    "ZUIDVALIDITY": "z_uid_validity",
    "Account": "account_hash",
    "Attachment": "attachment_hash",
    "EWSAccount": "ews_account",
    "EWSFolder": "ews_folder",
    "EWSNote": "ews_note",
    "Folder": "folder",
    "FolderAction": "folder_action",
    "IMAPAccount": "imap_account",
    "IMAPFolder": "imap_folder",
    "IMAPNote": "imap_note",
    "InsertFolderAction": "insert_folder_action",
    "InsertNoteAction": "insert_note_action",
    "LocalAccount": "local_account",
    "MoveFolderAction": "move_folder_action",
    "MoveNoteAction": "move_note_action",
    "Note": "note",
    "NoteAction": "note_action",
    "NoteBody": "note_body",
    "OfflineAction": "offline_action",
    "TrashFolder": "trash_folder",
    "UpdateFolderAction": "update_folder_action",
    "UpdateNoteAction": "update_note_action",
}

CONVERT_TIMESTAMPS = {
    "z_timestamp": "2001",
}


class NotesPlugin(Plugin):
    """macOS notes plugin.

    Parses macOS notes SQLite database file.

    References:
        - https://fatbobman.com/en/posts/tables_and_fields_of_coredata/
        - https://developer.apple.com/documentation/coredata/nsstoremodelversionidentifierskey
    """

    USER_PATH = ("Library/Containers/com.apple.Notes/Data/Library/Notes/NotesV*.storedata",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No NotesV*.storedata files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=NotesRecords)
    def notes(
        self,
    ) -> Iterator[NotesRecords]:
        """Return notes information.

        Yields the following record types extracted from the
        NotesV*.storedata databases:

        .. code-block:: text

            ZAccountRecord:
                table (string): Name of the source table (ZACCOUNT).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_allow_insecure_authentication (varint): Indicates whether insecure authentication is allowed:
                    0 = False.
                    1 = True.
                z_did_choose_to_migrate (varint): Indicates if migration was selected:
                    0 = False.
                    1 = True.
                z_enabled (varint): Indicates whether the account is enabled.
                z_root_folder (varint): Reference to the root folder.
                z6_root_folder (varint): Alternate root folder reference.
                z_trash_folder (varint): Reference to the trash folder.
                z_gmail_capabilities_support (string): Gmail capability support flag.
                z_port (string): Port value.
                z_security_layer_type (string): Security layer type.
                z_migration_offered (varint): Indicates if migration was offered:
                    0 = False.
                    1 = True.
                z_account_description (string): Account description:
                z_email_address (string): Associated email address.
                z_full_name (string): Full name of the account.
                z_parent_account_identifier (string): Parent account identifier.
                z_user_name (string): Username.
                z_folder_hierarchy_sync_state (string): Folder sync state.
                z_authentication (string): Authentication method.
                z_host_name (string): Hostname.
                z_server_path_prefix (string): Server path prefix.
                z_external_url (string): External URL.
                z_internal_url (string): Internal URL.
                z_last_used_autodiscover_url (string): Last used autodiscover URL.
                z_tls_certificate (string): TLS certificate data.
                source (path): Path to the database file.

            ZFolderRecord:
                table (string): Name of the source table (ZFOLDER).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_account (varint): Reference to Z_PK in ZACCOUNT.
                z1_account (varint): Alternate reference to Z_PK in ZACCOUNT.
                z_parent (varint): Parent folder reference.
                z6_parent (varint): Alternate parent reference.
                z_is_distinguished (varint): Whether entry is distinguished:
                    0 = False.
                    1 = True.
                z_alleged_highest_modification_sequence (string): Alleged highest modification sequence.
                z_computed_highest_modification_sequence (string): Computed highest modification sequence.
                z_uid_next (string): Next UID value.
                z_uid_validity: UID validity.
                z_trash_account (varint): Trash account reference.
                z1_trash_account (varint): Alternate trash account reference.
                z_name (string): Entry name.
                z_change_key (string): Change key.
                z_user_name (string): Username.
                z_folder_id (varint): Folder identifier.
                z_sync_state (string): Synchronization state.
                z_server_name (string): Server name.
                source (path): Path to the database file.

            ZPrimaryKeyRecord:
                table (string): Name of the source table (Z_PRIMARYKEY).
                z_ent (varint): Entity identifier.
                z_name (string): The name of the entity in the data model.
                z_super (varint): This value corresponds to the Z_ENT of the parent entity.
                    0 indicates that the entity has no parent entity.
                z_max (varint): Marks the last used z_pk value for each registry table.
                source (path): Path to the database file.

            ZMetadataRecord:
                table (string): Name of the source table (Z_METADATA).
                z_version (varint): The specific purpose is unknown, value is always 1.
                z_uuid (string): The ID identifier (UUID type) of the current database file.
                source (path): Path to the database file.

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
                source (path): Path to the database file.

            NSStoreModelVersionHashesRecord:
                account_hash (bytes): Hash for ZACCOUNT entity.
                attachment_hash (bytes): Hash for ZATTACHMENT entity.
                ews_account (bytes): Hash for EWS account.
                ews_folder (bytes): Hash for EWS folder.
                ews_note (bytes): Hash for EWS note.
                folder (bytes): Hash for ZFOLDER entity.
                folder_action (bytes): Hash for folder action.
                imap_account (bytes): Hash for IMAP account.
                imap_folder (bytes): Hash for IMAP folder.
                imap_note (bytes): Hash for IMAP note.
                insert_folder_action (bytes): Hash for insert folder action.
                insert_note_action (bytes): Hash for insert note action.
                local_account (bytes): Hash for local account.
                move_folder_action (bytes): Hash for move folder action.
                move_note_action (bytes): Hash for move note action.
                note (bytes): Hash for ZNOTE entity.
                note_action (bytes): Hash for note action.
                note_body (bytes): Hash for ZNOTEBODY entity.
                offline_action (bytes): Hash for ZOFFLINEACTION entity.
                trash_folder (bytes): Hash for trash folder.
                update_folder_action (bytes): Hash for update folder action.
                update_note_action (bytes): Hash for update note action.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the database file.

            ZModelCacheRecord (contains Z_CONTENT field with binary data):
                table (string): Name of the source table (Z_MODELCACHE).
                source (path): Path to the database file.

            AChangeRecord:
                table (string): Name of the source table (ACHANGE).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_change_type (varint): Type of change.
                z_entity (varint): Entity type affected.
                z_entity_pk (varint): Primary key of affected entity.
                z_transaction_id (varint): Transaction identifier.
                z_columns (bytes): Columns affected by the change.
                source (path): Path to the database file.

            ATransactionRecord:
                table (string): Name of the source table (ATRANSACTION).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_author_ts (varint): Author timestamp reference.
                z_bundle_id_ts (varint): Bundle ID timestamp reference.
                z_context_name_ts (varint): Context name timestamp reference.
                z_process_id_ts (varint): Process ID timestamp reference.
                z_timestamp (datetime): Transaction timestamp.
                z_author (string): Author of the transaction.
                z_bundle_id (string): Bundle identifier.
                z_context_name (string): Context name.
                z_process_id (varint): Process ID.
                z_query_gen (string): Query generation.
                source (path): Path to the database file.

            ATransactionStringRecord:
                table (string): Name of the source table (ATRANSACTIONSTRING).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_name (string): The name of the entity in the data model.
                source (path): Path to the database file.
        """
        yield from build_sqlite_records(
            self, self.files, NotesRecords, field_mappings=FIELD_MAPPINGS, convert_timestamps=CONVERT_TIMESTAMPS
        )

        # TODO: Add ZNOTE, ZNOTEBODY, ZOFFLINEACTION, ZATTACHMENT, tables
