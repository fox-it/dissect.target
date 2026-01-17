from __future__ import annotations

from datetime import datetime
from functools import cached_property
from typing import TYPE_CHECKING, Any

from dissect.database.ese.ntds import NTDS
from dissect.database.ese.ntds.util import UserAccountControl

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, UnsupportedPluginError, export
from dissect.target.plugins.os.windows.credential.sam import remove_des_layer

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Computer, User

    from dissect.target.target import Target


# Kerberos encryption type mappings
KERBEROS_TYPE = {
    # DES
    1: "des-cbc-crc",
    2: "des-cbc-md4",
    3: "des-cbc-md5",
    # RC4
    23: "rc4-hmac",
    -133: "rc4-hmac-exp",
    0xFFFFFF74: "rc4_hmac_old",
    # AES (RFC 3962)
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    # AES (newer RFC 8009)
    19: "aes128-cts-hmac-sha256-128",
    20: "aes256-cts-hmac-sha384-192",
    # Other / legacy
    16: "des3-cbc-sha1",
    24: "rc4-hmac-exp-old",
}

# SAM account type constants
SAM_ACCOUNT_TYPE_INTERNAL_TO_NAME = {
    0x0: "SAM_DOMAIN_OBJECT",
    0x10000000: "SAM_GROUP_OBJECT",
    0x10000001: "SAM_NON_SECURITY_GROUP_OBJECT",
    0x20000000: "SAM_ALIAS_OBJECT",
    0x20000001: "SAM_NON_SECURITY_ALIAS_OBJECT",
    0x30000000: "SAM_USER_OBJECT",
    0x30000001: "SAM_MACHINE_ACCOUNT",
    0x30000002: "SAM_TRUST_ACCOUNT",
    0x40000000: "SAM_APP_BASIC_GROUP",
    0x40000001: "SAM_APP_QUERY_GROUP",
    0x7FFFFFFF: "SAM_ACCOUNT_TYPE_MAX",
}


GENERIC_FIELDS = [
    ("string", "common_name"),
    ("string", "upn"),
    ("string", "sam_name"),
    ("string", "sam_type"),
    ("string", "description"),
    ("string", "sid"),
    ("varint", "rid"),
    ("datetime", "password_last_set"),
    ("datetime", "logon_last_failed"),
    ("datetime", "logon_last_success"),
    ("datetime", "account_expires"),
    ("datetime", "creation_time"),
    ("datetime", "last_modified_time"),
    ("boolean", "admin_count"),
    ("boolean", "is_deleted"),
    ("string", "lm"),
    ("string[]", "lm_history"),
    ("string", "nt"),
    ("string[]", "nt_history"),
    ("string", "cleartext_password"),
    ("string", "credential_type"),
    ("string", "kerberos_type"),
    ("string", "kerberos_key"),
    ("string", "default_salt"),
    ("uint32", "iteration_count"),
    ("uint32", "default_iteration_count"),
    ("string[]", "packages"),
    ("string[]", "w_digest"),
    ("uint32", "user_account_control"),
    *[("boolean", flag.name.lower()) for flag in UserAccountControl],
    ("string[]", "object_classes"),
    ("string", "distinguished_name"),
    ("string", "object_guid"),
    ("uint32", "primary_group_id"),
    ("string[]", "member_of"),
    ("string[]", "service_principal_name"),
]

# Record descriptor for NTDS user secrets
NtdsUserAccountRecord = TargetRecordDescriptor(
    "windows/credential/ntds/user",
    [
        *GENERIC_FIELDS,
        ("string", "info"),
        ("string", "comment"),
        ("string", "telephone_number"),
        ("string", "home_directory"),
    ],
)
NtdsComputerAccountRecord = TargetRecordDescriptor(
    "windows/credential/ntds/computer",
    [
        *GENERIC_FIELDS,
        ("string", "dns_hostname"),
        ("string", "operating_system"),
        ("string", "operating_system_version"),
    ],
)


class NtdsPlugin(Plugin):
    """Plugin to parse NTDS.dit Active Directory database and extract user credentials.

    This plugin extracts user password hashes, password history, Kerberos keys,
    and other authentication data from the NTDS.dit database found on Windows Domain Controllers.
    """

    __namespace__ = "ntds"

    # NTDS Registry consts
    NTDS_PARAMETERS_REGISTRY_PATH = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
    NTDS_PARAMETERS_DB_VALUE = "DSA Database file"

    # Default values
    DEFAULT_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
    DEFAULT_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"

    def __init__(self, target: Target):
        """Initialize the NTDS plugin.

        Args:
            target: The target system to analyze.
        """
        super().__init__(target)

        if self.target.has_function("registry"):
            ntds_path_key = self.target.registry.value(
                key=self.NTDS_PARAMETERS_REGISTRY_PATH, value=self.NTDS_PARAMETERS_DB_VALUE
            )
            self.ntds_path = self.target.fs.path(ntds_path_key.value)

    def check_compatible(self) -> None:
        """Check if the plugin can run on the target system.

        Raises:
            UnsupportedPluginError: If NTDS.dit is not found or system hive is missing.
        """
        if not self.target.has_function("lsa") or not hasattr(self.target.lsa, "syskey"):
            raise UnsupportedPluginError("System Hive is not present or LSA function not available")

        if not self.ntds_path.exists():
            raise UnsupportedPluginError("NTDS.dit file does not exists")

    @cached_property
    def ntds(self) -> NTDS:
        ntds = NTDS(self.ntds_path.open())
        ntds.pek.unlock(self.target.lsa.syskey)

        return ntds

    def _decode_user_account_control(self, uac: int) -> dict[str, bool]:
        """Decode User Account Control flags.

        Args:
            uac: User Account Control integer value.

        Returns:
            Dictionary mapping flag names to boolean values.
        """
        return {flag.name.lower(): bool(uac & flag.value) for flag in UserAccountControl}

    def _extract_supplemental_info(self, account: User | Computer) -> Iterator[dict[str, str | None]]:
        """Extract and decrypt supplemental credentials (Kerberos keys, cleartext passwords).

        Args:
            account: Account record from the database.

        Yields:
            Dictionary containing supplemental credential information.
        """
        try:
            supplemental_credentials = account.supplementalCredentials
        except KeyError:
            supplemental_credentials = None

        if supplemental_credentials is None:
            yield {}
            return

        for supplemental_credential in supplemental_credentials:
            info = {}
            if "Primary:CLEARTEXT" in supplemental_credential:
                info["cleartext_password"] = supplemental_credential["Primary:CLEARTEXT"]

            if "Packages" in supplemental_credential:
                info["packages"] = supplemental_credential["Packages"]

            if "Primary:WDigest" in supplemental_credential:
                info["w_digest"] = [digest_hash.hex() for digest_hash in supplemental_credential["Primary:WDigest"]]

            if not {"Primary:Kerberos", "Primary:Kerberos-Newer-Keys"}.intersection(supplemental_credential):
                yield info
                return

            for key_information in self._extract_kerberos_keys(supplemental_credential["Primary:Kerberos-Newer-Keys"]):
                key_information.update(info)
                yield key_information

    def _extract_kerberos_keys(self, kerberos_keys: dict[str, Any]) -> Iterator[dict[str, str | None]]:
        """Extract Kerberos keys from property value.

        Args:
            kerberos_keys: ``dict`` Kerberos keys.

        Yields:
            Dictionary containing Kerberos key information.
        """
        # Extract default salt if present
        default_salt = None
        if "DefaultSalt" in kerberos_keys:
            default_salt = kerberos_keys["DefaultSalt"].hex()

        default_iteration_count = None
        if "DefaultIterationCount" in kerberos_keys:
            default_iteration_count = kerberos_keys["DefaultIterationCount"]

        # Process all key entries
        credential_types = {
            "Credentials",
            "ServiceCredentials",
            "OldCredentials",
            "OlderCredentials",
        }

        for credential_type in credential_types:
            if credential_type not in kerberos_keys:
                continue

            for key in kerberos_keys[credential_type]:
                key_information = {
                    "default_salt": default_salt,
                    "default_iteration_count": default_iteration_count,
                }

                key_information["credential_type"] = credential_type
                key_information["kerberos_key"] = key["Key"].hex()
                key_information["kerberos_type"] = KERBEROS_TYPE.get(key["KeyType"], str(key["KeyType"]))
                key_information["iteration_count"] = key["IterationCount"]
                key_information["default_salt"] = default_salt

                yield key_information

    def extract_generic_account_info(self, account: User | Computer) -> Iterator[dict[str, Any]]:
        """Convert a database account record to NTDS account secret records.

        Args:
            account: Account object from the database.

        Yields:
            NtdsUserSecretRecord containing decrypted credentials.
        """
        self.target.log.debug("Decrypting hash for user: %s", account.name)

        try:
            lm_pwd_data = account.dBCSPwd
        except KeyError:
            lm_pwd_data = None
        lm_hash = remove_des_layer(lm_pwd_data, account.rid).hex() if lm_pwd_data else self.DEFAULT_LM_HASH

        try:
            nt_pwd_data = account.unicodePwd
        except KeyError:
            nt_pwd_data = None
        nt_hash = remove_des_layer(nt_pwd_data, account.rid).hex() if nt_pwd_data else self.DEFAULT_NT_HASH

        # Decrypt password histories
        try:
            lm_history_data = account.lmPwdHistory
        except KeyError:
            lm_history_data = None
        lm_history = [remove_des_layer(lm, account.rid).hex() for lm in lm_history_data] if lm_history_data else None

        try:
            nt_history_data = account.ntPwdHistory
        except KeyError:
            nt_history_data = None
        nt_history = [remove_des_layer(nt, account.rid).hex() for nt in nt_history_data] if nt_history_data else None

        # Decode UAC flags
        uac_flags = self._decode_user_account_control(account.user_account_control)

        # Peripheral information
        try:
            upn = account.userPrincipalName
        except KeyError:
            upn = None

        try:
            description = account.description
        except KeyError:
            description = None

        try:
            admin_count = bool(account.adminCount)
        except KeyError:
            admin_count = False

        try:
            member_of = [group.distinguished_name for group in account.groups()]
        except Exception:  # TODO: Understand why multiple exception are thrown
            member_of = None

        try:
            service_principal_name = (
                [account.servicePrincipalName]
                if isinstance(account.servicePrincipalName, str)
                else account.servicePrincipalName
            )
        except KeyError:
            service_principal_name = None

        # Extract supplemental credentials and yield records
        for supplemental_info in self._extract_supplemental_info(account):
            yield dict(
                common_name=account.cn,
                upn=upn,
                sam_name=account.sam_account_name,
                sam_type=SAM_ACCOUNT_TYPE_INTERNAL_TO_NAME[account.sAMAccountType].lower(),
                description=description,
                sid=account.sid,
                rid=account.rid,
                password_last_set=account.pwdLastSet,
                logon_last_failed=account.badPasswordTime,
                logon_last_success=account.instance_type,
                account_expires=account.accountExpires if isinstance(account.accountExpires, datetime) else None,
                creation_time=account.when_created,
                last_modified_time=account.when_changed,
                admin_count=admin_count,
                is_deleted=account.is_deleted,
                lm=lm_hash,
                lm_history=lm_history,
                nt=nt_hash,
                nt_history=nt_history,
                **supplemental_info,
                user_account_control=account.user_account_control,
                **uac_flags,
                object_classes=account.object_class,
                distinguished_name=account.distinguished_name,
                object_guid=account.guid,
                primary_group_id=account.primary_group_id,
                member_of=member_of,
                service_principal_name=service_principal_name,
            )

    @export(record=NtdsUserAccountRecord, description="Extract user accounts & thier sercrets from NTDS.dit database")
    def user_accounts(self) -> Iterator[NtdsUserAccountRecord]:
        """Extract all user account from the NTDS.dit database.

        Yields:
            ``NtdsUserAccountRecord``: for each user account found in the database.
        """
        for account in self.ntds.users():
            for generic_info in self.extract_generic_account_info(account):
                # TODO: Fix the extraction here
                try:
                    info = account.info
                except KeyError:
                    info = None

                try:
                    comment = account.comment
                except KeyError:
                    comment = None

                try:
                    telephone_number = account.telephoneNumber
                except KeyError:
                    telephone_number = None

                try:
                    home_directory = account.homeDirectory
                except KeyError:
                    home_directory = None

                yield NtdsUserAccountRecord(
                    **generic_info,
                    info=info,
                    comment=comment,
                    telephone_number=telephone_number,
                    home_directory=home_directory,
                    _target=self.target,
                )

    @export(
        record=NtdsComputerAccountRecord,
        description="Extract computer accounts & thier sercrets from NTDS.dit database",
    )
    def computer_accounts(self) -> Iterator[NtdsComputerAccountRecord]:
        """Extract all computer account from the NTDS.dit database.

        Yields:
            ``NtdsComputerAccountRecord``: for each computer account found in the database.
        """
        for account in self.ntds.computers():
            for generic_info in self.extract_generic_account_info(account):
                try:
                    dns_hostname = account.dNSHostName
                except KeyError:
                    dns_hostname = None

                try:
                    operating_system = account.operatingSystem
                except KeyError:
                    operating_system = None

                try:
                    operating_system_version = account.operatingSystemVersion
                except KeyError:
                    operating_system_version = None

                yield NtdsComputerAccountRecord(
                    **generic_info,
                    dns_hostname=dns_hostname,
                    operating_system=operating_system,
                    operating_system_version=operating_system_version,
                    _target=self.target,
                )
