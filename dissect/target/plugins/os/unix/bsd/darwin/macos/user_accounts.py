from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import (
    build_sqlite_records,
)
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.general import _build_userdirs

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
        ("varint", "z_active"),
        ("varint", "z_authenticated"),
        ("varint", "z_supports_authentication"),
        ("varint", "z_visible"),
        ("varint", "z_warming_up"),
        ("varint", "z_account_type"),
        ("varint", "z_parent_account"),
        ("float", "z_date"),
        ("float", "z_last_credential_renewal_rejection_date"),
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
        ("varint", "z_obsolete"),
        ("varint", "z_supports_authentication"),
        ("varint", "z_supports_multiple_accounts"),
        ("varint", "z_visibility"),
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

ZDataClassRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_dataclass",
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
        ("string", "ac_account_type_version"),
        ("string", "ns_auto_vacuum_level"),
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
        ("string", "access_options_key"),
        ("string", "account"),
        ("string", "account_property"),
        ("string", "account_type"),
        ("string", "authorization"),
        ("string", "credential_item"),
        ("string", "dataclass"),
        ("string", "plist_path"),
        ("path", "source"),
    ],
)

ZModelCacheRecord = TargetRecordDescriptor(
    "macos/user_accounts/z_model_cache",
    [
        ("string", "table"),
        ("string", "z_content"),
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
    ZDataClassRecord,
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
    "Account": "account",
    "AccountProperty": "account_property",
    "AccountType": "account_type",
    "Authorization": "authorization",
    "CredentialItem": "credential_item",
    "Dataclass": "dataclass",
    "Z_CONTENT": "z_content",
}


class UserAccountsPlugin(Plugin):
    """macOS user accounts plugin."""

    USER_PATH = ("Library/Accounts/Accounts*.sqlite",)

    def __init__(self, target: Target):
        super().__init__(target)

        self.files = set()
        self._find_files()

    def check_compatible(self) -> None:
        if not (self.files):
            raise UnsupportedPluginError("No user account database files found")

    def _find_files(self) -> None:
        for _, path in _build_userdirs(self, self.USER_PATH):
            self.files.add(path)

    @export(
        record=[
            ZAccessOptionsKeyRecord,
            ZOwningAccountTypesRecord,
            ZAccountRecord,
            ZEnabledDataClassesRecord,
            ZAccountPropertyRecord,
            ZAccountTypeRecord,
            ZSupportedDataClassesRecord,
            ZSyncableDataClassesRecord,
            ZDataClassRecord,
            ZPrimaryKeyRecord,
            ZMetadataRecord,
            ZPlistRecord,
            NSStoreModelVersionHashesRecord,
            ZModelCacheRecord,
        ]
    )
    def user_accounts(
        self,
    ) -> Iterator[
        [
            ZAccessOptionsKeyRecord,
            ZOwningAccountTypesRecord,
            ZAccountRecord,
            ZEnabledDataClassesRecord,
            ZAccountPropertyRecord,
            ZAccountTypeRecord,
            ZSupportedDataClassesRecord,
            ZSyncableDataClassesRecord,
            ZDataClassRecord,
            ZPrimaryKeyRecord,
            ZMetadataRecord,
            ZPlistRecord,
            NSStoreModelVersionHashesRecord,
            ZModelCacheRecord,
        ]
    ]:
        """Yield user accounts information."""
        yield from build_sqlite_records(self, self.files, UserAccountRecords, field_mappings=FIELD_MAPPINGS)

        # Still missing Z_2PROVISIONEDDATACLASSES, ZAUTHORIZATION, ZCREDENTIALITEM tables
