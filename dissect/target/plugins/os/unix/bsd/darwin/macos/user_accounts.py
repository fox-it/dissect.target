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


ZAccessOptionsKeyRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_access_options_key",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_enum_value"),
        ("string", "z_name"),
        ("path", "source"),
    ],
)

ZOwningAccountTypesRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_owning_account_types",
    [
        ("string", "table"),
        ("varint", "z_1_access_keys"),
        ("varint", "z_4_owning_account_types"),
        ("path", "source"),
    ],
)

ZAccountRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_account",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("boolean", "z_active"),
        ("boolean", "z_authenticated"),
        ("boolean", "z_supports_authentication"),
        ("boolean", "z_visible"),
        ("boolean", "z_warming_up"),
        ("varint", "z_account_type"),
        ("varint", "z_parent_account"),
        ("datetime", "z_date"),
        ("datetime", "z_last_credential_renewal_rejection_date"),
        ("string", "z_account_description"),
        ("string", "z_authentication_type"),
        ("string", "z_credential_type"),
        ("string", "z_identifier"),
        ("string", "z_modification_id"),
        ("string", "z_owning_bundle_id"),
        ("string", "z_username"),
        ("bytes", "z_dataclass_properties"),
        ("path", "source"),
    ],
)

ZEnabledDataClassesRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_enabled_dataclasses",
    [
        ("string", "table"),
        ("varint", "z_2_enabled_accounts"),
        ("varint", "z_7_enabled_dataclasses"),
        ("path", "source"),
    ],
)

ZAccountPropertyRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_account_property",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("varint", "z_owner"),
        ("string", "z_key"),
        ("string", "z_value"),
        ("path", "source"),
    ],
)

ZAccountTypeRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_account_type",
    [
        ("string", "table"),
        ("varint", "z_pk"),
        ("varint", "z_ent"),
        ("varint", "z_opt"),
        ("boolean", "z_obsolete"),
        ("boolean", "z_supports_authentication"),
        ("boolean", "z_supports_multiple_accounts"),
        ("boolean", "z_visibility"),
        ("string", "z_account_type_description"),
        ("string", "z_credential_protection_policy"),
        ("string", "z_credential_type"),
        ("string", "z_identifier"),
        ("string", "z_owning_bundle_id"),
        ("path", "source"),
    ],
)

ZSupportedDataClassesRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_supported_dataclasses",
    [
        ("string", "table"),
        ("varint", "z_4_supported_types"),
        ("varint", "z_7_supported_dataclasses"),
        ("path", "source"),
    ],
)

ZSyncableDataClassesRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_syncable_dataclasses",
    [
        ("string", "table"),
        ("varint", "z_4_syncable_types"),
        ("varint", "z_7_syncable_dataclasses"),
        ("path", "source"),
    ],
)

ZPrimaryKeyRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_primary_key",
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
    "macos/user_accounts/z_metadata",
    [
        ("string", "table"),
        ("varint", "z_version"),
        ("string", "z_uuid"),
        ("path", "source"),
    ],
)

ZPlistRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_plist",
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
    "macos/user_accounts/ns_store_model_version_hashes",
    [
        ("bytes", "access_options_key"),
        ("bytes", "account_hash"),
        ("bytes", "account_property"),
        ("bytes", "account_type"),
        ("bytes", "authorization"),
        ("bytes", "credential_item"),
        ("bytes", "dataclass"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

# Contains additional Z_CONTENT field which is a binary blob. This field been removed
# from the record descriptor. The field's presence will still be mentioned in a warning.
ZModelCacheRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_model_cache",
    [
        ("string", "table"),
        ("path", "source"),
    ],
)

UserAccountRecords = (
    ZAccessOptionsKeyRecord,
    ZOwningAccountTypesRecord,
    ZAccountRecord,
    ZEnabledDataClassesRecord,
    ZAccountPropertyRecord,
    ZAccountTypeRecord,
    ZSupportedDataClassesRecord,
    ZSyncableDataClassesRecord,
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
    "ZENUMVALUE": "z_enum_value",
    "ZNAME": "z_name",
    "Z_1ACCESSKEYS": "z_1_access_keys",
    "Z_4OWNINGACCOUNTTYPES": "z_4_owning_account_types",
    "ZACTIVE": "z_active",
    "ZAUTHENTICATED": "z_authenticated",
    "ZSUPPORTSAUTHENTICATION": "z_supports_authentication",
    "ZVISIBLE": "z_visible",
    "ZWARMINGUP": "z_warming_up",
    "ZACCOUNTTYPE": "z_account_type",
    "ZPARENTACCOUNT": "z_parent_account",
    "ZDATE": "z_date",
    "ZLASTCREDENTIALRENEWALREJECTIONDATE": "z_last_credential_renewal_rejection_date",
    "ZACCOUNTDESCRIPTION": "z_account_description",
    "ZAUTHENTICATIONTYPE": "z_authentication_type",
    "ZCREDENTIALTYPE": "z_credential_type",
    "ZIDENTIFIER": "z_identifier",
    "ZMODIFICATIONID": "z_modification_id",
    "ZOWNINGBUNDLEID": "z_owning_bundle_id",
    "ZUSERNAME": "z_username",
    "ZDATACLASSPROPERTIES": "z_dataclass_properties",
    "Z_2ENABLEDACCOUNTS": "z_2_enabled_accounts",
    "Z_7ENABLEDDATACLASSES": "z_7_enabled_dataclasses",
    "ZOWNER": "z_owner",
    "ZKEY": "z_key",
    "ZVALUE": "z_value",
    "ZOBSOLETE": "z_obsolete",
    "ZSUPPORTSMULTIPLEACCOUNTS": "z_supports_multiple_accounts",
    "ZVISIBILITY": "z_visibility",
    "ZACCOUNTTYPEDESCRIPTION": "z_account_type_description",
    "ZCREDENTIALPROTECTIONPOLICY": "z_credential_protection_policy",
    "Z_4SUPPORTEDTYPES": "z_4_supported_types",
    "Z_7SUPPORTEDDATACLASSES": "z_7_supported_dataclasses",
    "Z_4SYNCABLETYPES": "z_4_syncable_types",
    "Z_7SYNCABLEDATACLASSES": "z_7_syncable_dataclasses",
    "Z_NAME": "z_name",
    "Z_SUPER": "z_super",
    "Z_MAX": "z_max",
    "Z_VERSION": "z_version",
    "Z_UUID": "z_uuid",
    "ACAccountTypeVersion": "ac_account_type_version",
    "NSAutoVacuumLevel": "ns_auto_vacuum_level",
    "NSPersistenceFrameworkVersion": "ns_persistence_framework_version",
    "NSPersistenceMaximumFrameworkVersion": "ns_persistence_maximum_framework_version",
    "NSStoreModelVersionChecksumKey": "ns_store_model_version_checksum_key",
    "NSStoreModelVersionHashesDigest": "ns_store_model_version_hashes_digest",
    "NSStoreModelVersionHashesVersion": "ns_store_model_version_hashes_version",
    "NSStoreModelVersionIdentifiers": "ns_store_model_version_identifiers",
    "NSStoreType": "ns_store_type",
    "AccessOptionsKey": "access_options_key",
    "Account": "account_hash",
    "AccountProperty": "account_property",
    "AccountType": "account_type",
    "Authorization": "authorization",
    "CredentialItem": "credential_item",
    "Dataclass": "dataclass",
}


class UserAccountsPlugin(Plugin):
    """macOS user accounts plugin.

    Parses macOS user account SQLite database files.

    References:
        - https://fatbobman.com/en/posts/tables_and_fields_of_coredata/
        - https://developer.apple.com/documentation/coredata/nsstoremodelversionidentifierskey
    """

    USER_PATH = ("Library/Accounts/Accounts*.sqlite",)

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No user account database files found")

    def _find_files(self) -> set:
        files = set()
        for _, path in _build_userdirs(self, self.USER_PATH):
            files.add(path)
        return files

    @export(record=UserAccountRecords)
    def user_accounts(
        self,
    ) -> Iterator[UserAccountRecords]:
        """Return user accounts information.

        Yields the following record types extracted from the
        Accounts*.sqlite databases:

        .. code-block:: text

            ZAccessOptionsKeyRecord:
                table (string): Name of the source table (ZACCESSOPTIONSKEY).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_enum_value (varint): Enumeration value.
                z_name (string): The name of the entity in the data model.
                source (path): Path to the Accounts*.sqlite database file.

            ZOwningAccountTypesRecord:
                table (string): Name of the source table (Z_1OWNINGACCOUNTTYPES).
                z_1_access_keys (varint): Reference to z_pk in ZACCESSOPTIONSKEY.
                z_4_owning_account_types (varint): Reference to z_pk in ZACCOUNTTYPE.
                source (path): Path to the Accounts*.sqlite database file.

            ZAccountRecord:
                table (string): Name of the source table (ZACCOUNT).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_active (boolean): Indicates whether the account is active.
                z_authenticated (boolean): Indicates whether the account is authenticated.
                z_supports_authentication (boolean): Indicates if authentication is supported.
                z_visible (boolean): Indicates whether account is visible.
                z_warming_up (boolean): Indicates account initialization state.
                z_account_type (varint): Reference to z_pk in ZACCOUNTTYPE.
                z_parent_account (varint): Reference to z_pk of parent account.
                z_date (datetime): Timestamp.
                z_last_credential_renewal_rejection_date (datetime): Timestamp of last credential renewal rejection.
                z_account_description (string): Account description.
                z_authentication_type (string): Authentication type.
                z_credential_type (string): Credential type.
                z_identifier (string): Account identifier.
                z_modification_id (string): Modification identifier.
                z_owning_bundle_id (string): Bundle ID of owning service/app.
                z_username (string): Username for the account.
                z_dataclass_properties (bytes): Dataclass properties.
                source (path): Path to the Accounts*.sqlite database file.

            ZEnabledDataClassesRecord:
                table (string): Name of the source table (Z_2ENABLEDDATACLASSES).
                z_2_enabled_accounts (varint): Reference to z_pk in ZACCOUNT.
                z_7_enabled_dataclasses (varint): Reference to z_pk in ZDATACLASS.
                source (path): Path to the Accounts*.sqlite database file.

            ZAccountPropertyRecord:
                table (string): Name of the source table (ZACCOUNTPROPERTY).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_owner (varint): Reference to z_pk of owning ZACCOUNT.
                z_key (string): Property key.
                z_value (string): Property value.
                source (path): Path to the Accounts*.sqlite database file.

            ZAccountTypeRecord:
                table (string): Name of the source table (ZACCOUNTTYPE).
                z_pk (varint): The autoincrement primary key of the table.
                z_ent (varint): Entity identifier.
                z_opt (varint): The version number of the data record.
                z_obsolete (boolean): Indicates whether account type is obsolute.
                z_supports_authentication (boolean): Indicates whether authentication is supported.
                z_supports_multiple_accounts (boolean): Indicates whether multiple accounts are supported.
                z_visibility (boolean): Indicates visibility of the account type.
                z_account_type_description (string): Description of account type.
                z_credential_protection_policy (string): Credential protection policy.
                z_credential_type (string): Credential type.
                z_identifier (string): Account identifier.
                z_owning_bundle_id (string): Owning bundle ID.
                source (path): Path to the Accounts*.sqlite database file.

            ZSupportedDataClassesRecord:
                table (string): Name of the source table (Z_4SUPPORTEDDATACLASSES).
                z_4_supported_types (varint): Reference to z_pk in ZACCOUNTTYPE.
                z_7_supported_dataclasses (varint): Reference to z_pk in ZDATACLASS.
                source (path): Path to the Accounts*.sqlite database file.

            ZSyncableDataClassesRecord:
                table (string): Name of the source table (Z_4SYNCABLEDATACLASSES).
                z_4_syncable_types (varint): Reference to z_pk in ZACCOUNTTYPE.
                z_7_syncable_dataclasses (varint): Reference to z_pk in ZDATACLASS.
                source (path): Path to the Accounts*.sqlite database file.

            ZPrimaryKeyRecord:
                table (string): Name of the source table (Z_PRIMARYKEY).
                z_ent (varint): Entity identifier.
                z_name (string): The name of the entity in the data model.
                z_super (varint): This value corresponds to the Z_ENT of the parent entity.
                    0 indicates that the entity has no parent entity.
                z_max (varint): Marks the last used z_pk value for each registry table.
                source (path): Path to the Accounts*.sqlite database file.

            ZMetadataRecord:
                table (string): Name of the source table (Z_METADATA).
                z_version (varint): The specific purpose is unknown, value is always 1.
                z_uuid (string): The ID identifier (UUID type) of the current database file.
                source (path): Path to the Accounts*.sqlite database file.

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
                source (path): Path to the Accounts*.sqlite database file.

            NSStoreModelVersionHashesRecord:
                access_options_key (bytes): Hash for ZACCESSOPTIONSKEY entity.
                account (bytes): Hash for ZACCOUNT entity.
                account_property (bytes): Hash for ZACCOUNTPROPERTY entity.
                account_type (bytes): Hash for ZACCOUNTTYPE entity.
                authorization (bytes): Hash for ZAUTHORIZATION entity.
                credential_item (bytes): Hash for ZCREDENTIALITEM entity.
                dataclass (bytes): Hash for ZDATACLASS entity.
                plist_path (string): Path pointing to the location of the entry within the plist structure.
                source (path): Path to the Accounts*.sqlite database file.

            ZModelCacheRecord (contains Z_CONTENT field with binary data):
                table (string): Name of the source table (Z_MODELCACHE).
                source (path): Path to the Accounts*.sqlite database file.
        """
        yield from build_sqlite_records(self, self.files, UserAccountRecords, field_mappings=FIELD_MAPPINGS)

        # TODO: Add Z_2PROVISIONEDDATACLASSES, ZAUTHORIZATION, ZCREDENTIALITEM tables
