from __future__ import annotations

from datetime import datetime
from functools import cached_property
from itertools import zip_longest
from typing import TYPE_CHECKING, Any

from dissect.database.ese.ntds import NTDS
from dissect.database.ese.ntds.util import UserAccountControl

from dissect.target.exceptions import RegistryKeyNotFoundError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, UnsupportedPluginError, export, internal
from dissect.target.plugins.os.windows.sam import des_decrypt

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds.objects import Computer, DomainDNS, Object, OrganizationalUnit, SecurityObject, User

    from dissect.target.target import Target


OBJECTS_FIELDS = [
    ("string", "cn"),
    ("string", "sid"),
    ("string", "description"),
    ("string[]", "object_classes"),
    ("string", "distinguished_name"),
    ("string", "object_guid"),
    ("datetime", "creation_time"),
    ("datetime", "last_modified_time"),
    ("boolean", "is_deleted"),
    ("varint", "nt_security_descriptor"),
]

SECURITY_PRINCIPAL_FIELDS = [
    *OBJECTS_FIELDS,
    ("varint", "rid"),
    ("string", "sam_name"),
    ("string", "sam_type"),
    ("boolean", "admin_count"),
    ("string[]", "sid_history"),
]

ACCOUNT_FIELDS = [
    *SECURITY_PRINCIPAL_FIELDS,
    ("string", "upn"),
    ("string", "user_account_control"),
    ("datetime", "password_last_set"),
    ("datetime", "logon_last_failed"),
    ("datetime", "logon_last_success"),
    ("datetime", "account_expires"),
    ("uint32", "primary_group_id"),
    ("string[]", "member_of"),
    ("string[]", "allowed_to_delegate"),
    ("string", "lm"),
    ("string[]", "lm_history"),
    ("string", "nt"),
    ("string[]", "nt_history"),
    ("string", "supplemental_credentials"),
    ("string", "info"),
    ("string", "comment"),
    ("string", "telephone_number"),
    ("string", "home_directory"),
]

CONTAINER_FIELDS = [
    *OBJECTS_FIELDS,
    ("string", "name"),
    ("string", "display_name"),
    ("string", "gplink"),
]

NtdsUserRecord = TargetRecordDescriptor(
    "windows/ad/user",
    [
        *ACCOUNT_FIELDS,
    ],
)

NtdsComputerRecord = TargetRecordDescriptor(
    "windows/ad/computer",
    [
        *ACCOUNT_FIELDS,
        ("string", "dns_hostname"),
        ("string", "operating_system"),
        ("string", "operating_system_version"),
        ("string[]", "service_principal_name"),
        ("varint", "allowed_to_act"),
    ],
)

NtdsGroupRecord = TargetRecordDescriptor(
    "windows/ad/group",
    [
        *SECURITY_PRINCIPAL_FIELDS,
        ("string[]", "members"),
    ],
)

NtdsDomainRecord = TargetRecordDescriptor(
    "windows/ad/domain",
    [
        *CONTAINER_FIELDS,
        ("uint32", "machine_account_quota"),
    ],
)

NtdsOURecord = TargetRecordDescriptor(
    "windows/ad/ou",
    [
        *CONTAINER_FIELDS,
        ("boolean", "blocks_inheritance"),
    ],
)

NtdsGPORecord = TargetRecordDescriptor(
    "windows/ad/gpo",
    [
        *CONTAINER_FIELDS,
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
        path = "sysvol/windows/NTDS/ntds.dit"
        if self.target.has_function("registry"):
            try:
                key = self.target.registry.value(NTDS_PARAMETERS_REGISTRY_PATH, NTDS_PARAMETERS_DB_VALUE)
                path = key.value
            except RegistryKeyNotFoundError:
                pass

        self.path = self.target.fs.path(path)

    def check_compatible(self) -> None:
        if not self.path.is_file() or not self.path.exists():
            raise UnsupportedPluginError("No NTDS.dit database found on target")

    @cached_property
    @internal
    def ntds(self) -> NTDS:
        ntds = NTDS(self.path.open("rb"))

        if self.target.has_function("lsa"):
            ntds.pek.unlock(self.target.lsa.syskey)
        else:
            self.target.log.warning("LSA plugin not available, cannot unlock PEK and decrypt sensitive data")

        return ntds

    @export(record=NtdsUserRecord)
    def users(self) -> Iterator[NtdsUserRecord]:
        """Extract all user accounts from the NTDS.dit database."""
        for user in self.ntds.users():
            yield NtdsUserRecord(
                **extract_user_info(user, self.target),
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
                service_principal_name=computer.get("servicePrincipalName"),
                allowed_to_act=computer.get("msDS-AllowedToActOnBehalfOfOtherIdentity"),
                _target=self.target,
            )

    @export(record=NtdsGroupRecord)
    def groups(self) -> Iterator[NtdsGroupRecord]:
        """Extract all groups from the NTDS.dit database."""
        for group in self.ntds.groups():
            try:
                members = [member.sid for member in group.members()]
            except Exception as e:
                members = []
                self.target.log.warning("Failed to extract group members for group %s: %s", group, e)
                self.target.log.debug("", exc_info=e)

            yield NtdsGroupRecord(
                **extract_security_info(group),
                members=members,
                _target=self.target,
            )

    @export(record=NtdsDomainRecord)
    def domains(self) -> Iterator[NtdsDomainRecord]:
        """Extract all domains from the NTDS.dit database."""
        for domain in self.ntds.search(objectClass="domainDNS"):
            yield NtdsDomainRecord(
                **extract_container_info(domain),
                machine_account_quota=domain.get("ms-DS-MachineAccountQuota"),
                _target=self.target,
            )

    @export(record=NtdsOURecord)
    def ous(self) -> Iterator[NtdsOURecord]:
        """Extract all ou's from the NTDS.dit database."""
        for ou in self.ntds.search(objectClass="organizationalUnit"):
            gp_options = ou.get("gPOptions")
            yield NtdsOURecord(
                **extract_container_info(ou),
                blocks_inheritance=gp_options == 1 if gp_options is not None else None,
                _target=self.target,
            )

    @export(record=NtdsGPORecord)
    def group_policies(self) -> Iterator[NtdsGPORecord]:
        """Extract all group policy objects (GPO) NTDS.dit database."""
        for gpo in self.ntds.group_policies():
            yield NtdsGPORecord(
                **extract_container_info(gpo),
                _target=self.target,
            )

    @export(output="yield")
    def secretsdump(self) -> Iterator[str]:
        """Extract credentials in secretsdump format. Because it's a popular format."""

        # Keep impacket defined constants in the method so we don't pollute our own
        kerberos_key_type = {
            1: "dec-cbc-crc",
            3: "des-cbc-md5",
            17: "aes128-cts-hmac-sha1-96",
            18: "aes256-cts-hmac-sha1-96",
            0xFFFFFF74: "rc4_hmac",
        }

        for obj in self.ntds.query(
            # For now just use the same filter as secretsdump.py
            "(&(|(sAMAccountType=805306368)(sAMAccountType=805306369)(sAMAccountType=805306370))(instanceType=4))"
        ):
            if (upn := obj.get("userPrincipalName")) is not None:
                domain = upn.split("@")[-1]
                username = f"{domain}\\{obj.sam_account_name}"
            else:
                username = obj.sam_account_name

            rid = obj.rid
            lm_hash = des_decrypt(lm_pwd, rid).hex() if (lm_pwd := obj.get("dBCSPwd")) else DEFAULT_LM_HASH
            nt_hash = des_decrypt(nt_pwd, rid).hex() if (nt_pwd := obj.get("unicodePwd")) else DEFAULT_NT_HASH
            pwd_last_set = obj.get("pwdLastSet")
            user_account_status = (
                "Disabled" if UserAccountControl.ACCOUNTDISABLE in obj.user_account_control else "Enabled"
            )

            yield f"{username}:{rid}:{lm_hash}:{nt_hash}::: (pwdLastSet={pwd_last_set}) (status={user_account_status})"

            # Password history output doesn't match what secretsdump.py outputs, but that's because they parse it wrong.
            # Their crypto is flawed and assumes the LM history is always RC4 encrypted. That's not the case,
            # it's just another encrypted blob that has an USHORT AlgoritmId determining the encryption type.
            # Our decryption is handled transparently by the NTDS implementation, so we don't have to worry about it.
            lm_history = [des_decrypt(lm, rid).hex() for lm in obj.get("lmPwdHistory")]
            nt_history = [des_decrypt(nt, rid).hex() for nt in obj.get("ntPwdHistory")]
            for i, (lm_hist, nt_hist) in enumerate(zip_longest(lm_history, nt_history, fillvalue="")):
                yield f"{username}_history{i}:{rid}:{lm_hist}:{nt_hist}:::"

            for supplemental in obj.get("supplementalCredentials") or []:
                if "Primary:Kerberos-Newer-Keys" in supplemental:
                    for cred in supplemental["Primary:Kerberos-Newer-Keys"]["Credentials"]:
                        key_type = kerberos_key_type.get(cred["KeyType"], hex(cred["KeyType"]))
                        key = cred["Key"].hex()
                        yield f"{username}:{key_type}:{key}"

                if "Primary:CLEARTEXT" in supplemental:
                    yield f"{username}:CLEARTEXT:{supplemental['Primary:CLEARTEXT']}"


def extract_object_info(obj: Object) -> dict[str, Any]:
    """Extract generic information from an Object."""
    return {
        "cn": obj.cn,
        "sid": obj.sid,
        "description": obj.get("description"),
        "object_classes": obj.object_class,
        "distinguished_name": obj.distinguished_name,
        "object_guid": obj.guid,
        "creation_time": obj.when_created,
        "last_modified_time": obj.when_changed,
        "is_deleted": obj.is_deleted,
        "nt_security_descriptor": obj.get("nTSecurityDescriptor"),
    }


def extract_security_info(security_obj: SecurityObject) -> dict[str, Any]:
    """Extract generic information from a Security Object."""
    return {
        **extract_object_info(security_obj),
        "rid": security_obj.rid,
        "sam_name": security_obj.sam_account_name,
        "sam_type": security_obj.get("sAMAccountType"),
        "admin_count": security_obj.get("adminCount"),
        "sid_history": security_obj.get("sIDHistory"),
    }


def extract_container_info(container_object: OrganizationalUnit | DomainDNS) -> dict[str, Any]:
    """Extract generic information from a Container Object."""
    return {
        **extract_object_info(container_object),
        "gplink": container_object.get("gPLink"),
        "name": container_object.name,
        "display_name": container_object.display_name,
    }


def extract_user_info(user: User | Computer, target: Target) -> dict[str, Any]:
    """Extract generic information from a User or Computer account."""

    if target.ad.ntds.pek.unlocked:
        decrypt_func = lambda encrypted_hash, rid: des_decrypt(encrypted_hash, rid).hex()  # noqa: E731
    else:
        decrypt_func = lambda *args, **kwargs: None  # noqa: E731

    lm_hash = decrypt_func(lm_pwd, user.rid) if (lm_pwd := user.get("dBCSPwd")) else DEFAULT_LM_HASH
    nt_hash = decrypt_func(nt_pwd, user.rid) if (nt_pwd := user.get("unicodePwd")) else DEFAULT_NT_HASH

    lm_history = [decrypt_func(lm, user.rid) for lm in user.get("lmPwdHistory")]
    nt_history = [decrypt_func(nt, user.rid) for nt in user.get("ntPwdHistory")]

    try:
        member_of = [group.distinguished_name for group in user.groups()]
    except Exception as e:
        member_of = []
        target.log.warning("Failed to extract group membership for user %s: %s", user, e)
        target.log.debug("", exc_info=e)

    return {
        **extract_security_info(user),
        "upn": user.get("userPrincipalName"),
        "password_last_set": user.get("pwdLastSet"),
        "logon_last_failed": user.get("badPasswordTime"),
        "logon_last_success": user.get("lastLogon"),
        "account_expires": user.get("accountExpires") if isinstance(user.get("accountExpires"), datetime) else None,
        "lm": lm_hash,
        "lm_history": lm_history,
        "nt": nt_hash,
        "nt_history": nt_history,
        "supplemental_credentials": user.get("supplementalCredentials"),
        "user_account_control": user.user_account_control.name,
        "primary_group_id": user.primary_group_id,
        "member_of": member_of,
        "allowed_to_delegate": user.get("msDS-AllowedToDelegateTo"),
        "info": user.get("info"),
        "comment": user.get("comment"),
        "telephone_number": user.get("telephoneNumber"),
        "home_directory": user.get("homeDirectory"),
    }
