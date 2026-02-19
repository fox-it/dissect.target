from __future__ import annotations

from datetime import datetime
from functools import cached_property
from typing import TYPE_CHECKING, Any

from dissect.database.ese.ntds import NTDS

from dissect.target.exceptions import RegistryKeyNotFoundError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, UnsupportedPluginError, export, internal
from dissect.target.plugins.os.windows.sam import des_decrypt

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Computer, User

    from dissect.target.target import Target


GENERIC_FIELDS = [
    ("string", "cn"),
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
    ("string", "supplemental_credentials"),
    ("string", "user_account_control"),
    ("string[]", "object_classes"),
    ("string", "distinguished_name"),
    ("string", "object_guid"),
    ("uint32", "primary_group_id"),
    ("string[]", "member_of"),
    ("string[]", "service_principal_name"),
]

# Record descriptor for NTDS user secrets
NtdsUserRecord = TargetRecordDescriptor(
    "windows/ad/user",
    [
        *GENERIC_FIELDS,
        ("string", "info"),
        ("string", "comment"),
        ("string", "telephone_number"),
        ("string", "home_directory"),
    ],
)
NtdsComputerRecord = TargetRecordDescriptor(
    "windows/ad/computer",
    [
        *GENERIC_FIELDS,
        ("string", "dns_hostname"),
        ("string", "operating_system"),
        ("string", "operating_system_version"),
    ],
)

NtdsGPORecord = TargetRecordDescriptor(
    "windows/ad/gpo",
    [
        ("string", "cn"),
        ("string", "distinguished_name"),
        ("string", "object_guid"),
        ("string", "name"),
        ("string", "display_name"),
        ("datetime", "creation_time"),
        ("datetime", "last_modified_time"),
    ],
)

# NTDS Registry consts
NTDS_PARAMETERS_REGISTRY_PATH = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters"
NTDS_PARAMETERS_DB_VALUE = "DSA Database file"

# Default values
DEFAULT_LM_HASH = "aad3b435b51404eeaad3b435b51404ee"
DEFAULT_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"


class NtdsPlugin(Plugin):
    """Plugin to parse NTDS.dit Active Directory database and extract user credentials.

    This plugin extracts user password hashes, password history, Kerberos keys, and other authentication data
    from the NTDS.dit database found on Windows Domain Controllers.
    """

    __namespace__ = "ad"

    def __init__(self, target: Target):
        super().__init__(target)
        self.path = None

        # Fallback path
        if self.target.has_function("registry"):
            key = self.target.registry.value(NTDS_PARAMETERS_REGISTRY_PATH, NTDS_PARAMETERS_DB_VALUE)
            self.path = self.target.fs.path(key.value)

    def check_compatible(self) -> None:
        if not self.target.has_function("lsa"):
            raise UnsupportedPluginError("System Hive is not present or LSA function not available")

        if self.path is None or not self.path.is_file():
            raise UnsupportedPluginError("No NTDS.dit database found on target")

    @cached_property
    @internal
    def ntds(self) -> NTDS:
        ntds = NTDS(self.path.open("rb"))

        if self.target.has_function("lsa"):
            ntds.pek.unlock(self.target.lsa.syskey)

        return ntds

    @export(record=NtdsUserRecord)
    def users(self) -> Iterator[NtdsUserRecord]:
        """Extract all user accounts from the NTDS.dit database."""
        for user in self.ntds.users():
            yield NtdsUserRecord(
                **extract_user_info(user, self.target),
                info=user.get("info"),
                comment=user.get("comment"),
                telephone_number=user.get("telephoneNumber"),
                home_directory=user.get("homeDirectory"),
                _target=self.target,
            )

    @export(record=NtdsComputerRecord)
    def computers(self) -> Iterator[NtdsComputerRecord]:
        """Extract all computer accounts from the NTDS.dit database."""
        for computer in self.ntds.computers():
            yield NtdsComputerRecord(
                **extract_user_info(computer, self.target),
                dns_hostname=computer.get("dNSHostName"),
                operating_system=computer.get("operatingSystem"),
                operating_system_version=computer.get("operatingSystemVersion"),
                _target=self.target,
            )

    @export(record=NtdsGPORecord)
    def group_policy(self) -> Iterator[NtdsGPORecord]:
        """Extract all group policy objects (GPO) NTDS.dit database."""

        for gpo in self.ntds.group_policies():
            yield NtdsGPORecord(
                cn=gpo.cn,
                distinguished_name=gpo.distinguishedName,
                object_guid=gpo.guid,
                name=gpo.name,
                display_name=gpo.displayName,
                creation_time=gpo.whenCreated,
                last_modified_time=gpo.whenChanged,
                _target=self.target,
            )


def extract_user_info(user: User | Computer, target: Target) -> dict[str, Any]:
    """Extract generic information from a User or Computer account."""

    lm_hash = des_decrypt(lm_pwd, user.rid).hex() if (lm_pwd := user.get("dBCSPwd")) else DEFAULT_LM_HASH
    nt_hash = des_decrypt(nt_pwd, user.rid).hex() if (nt_pwd := user.get("unicodePwd")) else DEFAULT_NT_HASH

    # Decrypt password history
    lm_history = [des_decrypt(lm, user.rid).hex() for lm in user.get("lmPwdHistory")]
    nt_history = [des_decrypt(nt, user.rid).hex() for nt in user.get("ntPwdHistory")]

    try:
        member_of = [group.distinguished_name for group in user.groups()]
    except Exception as e:
        member_of = []
        target.log.warning("Failed to extract group membership for user %s: %s", user, e)
        target.log.debug("", exc_info=e)

    # Extract supplemental credentials and yield records
    return {
        "cn": user.get("cn"),
        "upn": user.get("userPrincipalName"),
        "sam_name": user.sam_account_name,
        "sam_type": user.sam_account_type.name,
        "description": user.get("description"),
        "sid": user.sid,
        "rid": user.rid,
        "password_last_set": user.get("pwdLastSet"),
        "logon_last_failed": user.get("badPasswordTime"),
        "logon_last_success": user.get("lastLogon"),
        "account_expires": user.get("accountExpires") if isinstance(user.get("accountExpires"), datetime) else None,
        "creation_time": user.when_created,
        "last_modified_time": user.when_changed,
        "admin_count": user.get("adminCount"),
        "is_deleted": user.is_deleted,
        "lm": lm_hash,
        "lm_history": lm_history,
        "nt": nt_hash,
        "nt_history": nt_history,
        "supplemental_credentials": user.get("supplementalCredentials"),
        "user_account_control": user.user_account_control.name,
        "object_classes": user.object_class,
        "distinguished_name": user.distinguished_name,
        "object_guid": user.guid,
        "primary_group_id": user.primary_group_id,
        "member_of": member_of,
        "service_principal_name": user.get("servicePrincipalName"),
    }
