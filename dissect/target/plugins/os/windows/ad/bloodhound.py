from __future__ import annotations

import json
import re
from functools import cached_property, lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID

from dissect.database.ese.ntds.c_sd import c_sd
from dissect.database.ese.ntds.sd import ACCESS_MASK, ACE_FLAGS, ACE_TYPE
from dissect.database.ese.ntds.util import UserAccountControl

from dissect.target.exceptions import RegistryKeyNotFoundError, RegistryValueNotFoundError
from dissect.target.plugin import Plugin, UnsupportedPluginError, arg, export
from dissect.target.plugins.os.windows.ad.ntds import DEFAULT_LM_HASH, DEFAULT_NT_HASH

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds import Object
    from dissect.database.ese.ntds.sd import SecurityDescriptor
    from flow.record import Record

    from dissect.target import Target


ACL_STANDARD_RIGHTS = {
    ACCESS_MASK.GENERIC_ALL: "GenericAll",
    ACCESS_MASK.GENERIC_WRITE: "GenericWrite",
    ACCESS_MASK.WRITE_DACL: "WriteDacl",
    ACCESS_MASK.WRITE_OWNER: "WriteOwner",
}

ACL_EXTENDED_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DCSync",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DCSync",
    "89e95b76-ce4a-45c9-bbc6-5d6133112a4e": "DCSync",
    "00000000-0000-0000-0000-000000000000": "AllExtendedRights",
}

ACL_WRITE_PROPERTIES = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddMember",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "AddAllowedToAct",
}

# Active Directory Trust Attribute Bitmasks
TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x0001
TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x0004
TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x0008
TRUST_ATTRIBUTE_WITHIN_FOREST = 0x0020

TRUST_DIRECTION_MAP = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
TRUST_TYPE_MAP = {1: "External", 2: "Uplevel", 3: "External"}

BEHAVIOR_VERSION_TO_FUNCTIONAL_LEVEL_MAP = {
    0: "2000",
    1: "2003 Interim",
    2: "2003",
    3: "2008",
    4: "2008 R2",
    5: "2012",
    6: "2012 R2",
    7: "2016",
    10: "2025",
}

DOMAIN_HIGH_VALUE_RIDS = {
    500,  # Administrator
    502,  # krbtgt
    512,  # Domain Admins
    516,  # Domain Controllers
    518,  # Schema Admins
    519,  # Enterprise Admins
    520,  # Group Policy Creator Owners
    521,  # Read-only Domain Controllers
    526,  # Key Admins
    527,  # Enterprise Key Admins
}

# Built-in High-Value RIDs
BUILTIN_HIGH_VALUE_RIDS = {
    544,  # Administrators
    548,  # Account Operators
    549,  # Server Operators
    550,  # Print Operators
    551,  # Backup Operators
}

HIGH_VALUE_RIDS = {*DOMAIN_HIGH_VALUE_RIDS, *BUILTIN_HIGH_VALUE_RIDS}

DEFAULT_GOP_POLICIES = {
    "31B2F340-016D-11D2-945F-00C04FB984F9",  # Domain Policy
    "6AC1786C-016F-11D2-945F-00C04FB984F9",  # DC Policy
}

BLOODHOUND_TIMESTAMP_NEVER = -1


KERBEROS_REGISTRY_PATH = "HKLM\\System\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters"
KERBEROS_CERTIFICATE_VALUE = "CertificateMappingMethods"

KDC_REGISTRY_PATH = "HKLM\\System\\CurrentControlSet\\Services\\Kdc"
KDC_CERTIFICATE_VALUE = "StrongCertificateBindingEnforcement"


def extract_high_value(record: Record) -> bool:
    """Determines if a given AD record is high-value based on various heuristics.

    Args:
        record (Record): The AD record to evaluate.

    Returns:
        high_value (bool): True if the record is considered high-value, False otherwise.
    """
    domain_check = False

    domain_split: list[str] = extract_fqdn_from_dn(record.distinguished_name).split(".")
    distinguished_name_split: list[str] = record.distinguished_name.split(",")
    for domain_component, dn_component in zip(domain_split, distinguished_name_split, strict=False):
        domain_check = f"DC={domain_component.upper()}" == dn_component.upper()

    rid_check = record.rid in HIGH_VALUE_RIDS

    ou_check = record.name.upper() == "DOMAIN CONTROLLERS" and "organizationalUnit" in record.object_classes

    gpo_check = record.guid in DEFAULT_GOP_POLICIES

    admin_check = False
    if hasattr(record, "admin_count"):
        admin_check = record.admin_count.value

    return domain_check or rid_check or ou_check or gpo_check or admin_check


def trust_type_uplevel_to_actual_type(trust_attributes: int) -> str:
    """Convert Uplevel trust with specific attributes to actual trust type for BloodHound purposes.

    Args:
        trust_attributes (int): The bitmask of trust attributes from the AD trust record.

    Returns:
        trust_type (str): The actual trust type for BloodHound purposes.
    """
    if trust_attributes & TRUST_ATTRIBUTE_WITHIN_FOREST:
        return "ParentChild"
    if trust_attributes & TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
        return "Forest"
    return "External"


@lru_cache
def extract_fqdn_from_dn(distinguished_name: str | None) -> str | None:
    """Parses a Distinguished Name and returns the uppercase FQDN.

    Args:
        distinguished_name (str | None): The Distinguished Name to parse.

    Returns:
        fqdn (str | None): The uppercase FQDN or None if not found.
    """
    if not distinguished_name:
        return None

    dc_parts = []

    for part in distinguished_name.split(","):
        part = part.strip().upper()

        if part.startswith("DC="):
            dc_parts.append(part.split("=").pop())

    return ".".join(dc_parts).lower()


class BloodHound(Plugin):
    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.gp_link_pattern: re.Pattern = re.compile(r"\[LDAP://CN=({[A-Fa-f0-9\-]+}),.*?;(\d+)\]")

    def check_compatible(self) -> None:
        if not self.target.has_function("ad"):
            raise UnsupportedPluginError("ad plugin is not initialized")

    @cached_property
    def trusts(self) -> list[dict[str, str | dict[str, Any]]]:
        """Builds trusts list.

        Returns:
            trusts (list[dict[str, str | dict[str, Any]]]): List of dictionaries representing trusts.
        """
        trusts = []

        for trusted_domain in self.target.ad.trusted_domains():
            trust_type = TRUST_TYPE_MAP[trusted_domain.trust_type]
            if trust_type == "Uplevel":
                trust_type = trust_type_uplevel_to_actual_type(trusted_domain.trust_attributes)

            trusts.append(
                {
                    "DistinguishedName": trusted_domain.distinguished_name,
                    "Data": {
                        "TargetDomainName": trusted_domain.trust_partner,
                        "TargetDomainSid": trusted_domain.security_identifier,
                        "TrustDirection": TRUST_DIRECTION_MAP[trusted_domain.trust_direction],
                        "TrustType": trust_type,
                        "IsTransitive": not bool(trusted_domain.trust_attributes & TRUST_ATTRIBUTE_NON_TRANSITIVE),
                        "SidFilteringEnabled": bool(
                            trusted_domain.trust_attributes & TRUST_ATTRIBUTE_QUARANTINED_DOMAIN
                        ),
                    },
                }
            )

        return trusts

    @cached_property
    def dc_registry_data(self) -> dict[str, dict[str, str | None]]:
        """Get DC registry data.

        Returns:
            dc_data (dict[str, dict[str, str | None]]): Dictionary containing DC registry data.
        """
        dc_data = {"DCRegistryData": {"CertificateMappingMethods": None, "StrongCertificateBindingEnforcement": None}}
        reg_data = dc_data["DCRegistryData"]

        if not self.target.has_function("registry"):
            return dc_data

        try:
            reg_data["CertificateMappingMethods"] = self.target.registry.value(
                KERBEROS_REGISTRY_PATH, KERBEROS_CERTIFICATE_VALUE
            ).value
        except (RegistryKeyNotFoundError, RegistryValueNotFoundError):
            pass

        try:
            reg_data["StrongCertificateBindingEnforcement"] = self.target.registry.value(
                KDC_REGISTRY_PATH, KDC_CERTIFICATE_VALUE
            ).value
        except (RegistryKeyNotFoundError, RegistryValueNotFoundError):
            pass

        return dc_data

    def get_trusts(self, domain: Record) -> list[dict[str, Any]]:
        """Given a domain record, return a list of trusts in BloodHound format.

        Args:
            domain (Record): The domain record to find trusts for.

        Returns:
            domain_specific_trusts (list[dict[str, Any]]): List of trusts relevant to the given domain.
        """
        current_domain_fqdn = extract_fqdn_from_dn(domain.distinguished_name)
        domain_specific_trusts = []
        for trust_item in self.trusts:
            # Check if the trust belongs to this domain's System container
            if not trust_item["DistinguishedName"].endswith(domain.distinguished_name):
                continue

            # Prevent Self-Looping Trusts
            if trust_item["Data"]["TargetDomainName"] == current_domain_fqdn:
                continue

            domain_specific_trusts.append(trust_item["Data"])

        return domain_specific_trusts

    def get_gplink(self, gplink_string: str) -> list[dict[str, str | bool]]:
        """Parses an Active Directory gPLink string and extracts the active GPO links
        into a BloodHound-compatible dictionary format.

        Args:
            gplink_string (str): Raw gPLink string from an OU or domain record.

        Returns:
            bloodhound_links (list[dict[str, str | bool]]): List of dictionaries, each containing the GUID of the
                linked GPO and whether it's enforced.
        """
        bloodhound_links = []

        if not gplink_string:
            return bloodhound_links

        for guid, options in self.gp_link_pattern.findall(gplink_string):
            options = int(options)

            is_enforced = options == 2
            is_disabled = options == 1

            # BloodHound only tracks active links in its graph
            if not is_disabled:
                bloodhound_links.append({"GUID": str(UUID(guid)), "IsEnforced": is_enforced})

        return bloodhound_links

    def get_group_members(self, group_record: Record) -> list[dict[str, str]]:
        """Iterates through the members of a group record and returns their identities.

        Args:
            group_record (Record): The group record containing member SIDs.

        Returns:
            members (list[dict[str, str]]): List of member identities in BloodHound format.
        """
        members = []
        for member_sid in group_record.members:
            member_object = next(self.target.ad.ntds.search(objectSid=member_sid))
            members.append(self.get_object_identity(member_object))

        return members

    def get_sd_data(self, record: Record) -> dict[str, bool | list[dict[str, Any]]]:
        """Translate an NT Security Descriptor into BloodHound ACE format.

        Args:
            record (Record): The record containing the security descriptor.

        Returns:
            sd_data (dict[str, bool | list[dict[str, Any]]]): Dictionary containingthe "IsACLProtected" flag
                and a list of ACEs.
        """
        aces = []

        sd: SecurityDescriptor = self.target.ad.ntds.db.sd.sd(record.nt_security_descriptor)

        is_acl_protected = c_sd.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PROTECTED.name in sd.header.Control.name.split("|")

        if sd.dacl is None:
            return {
                "IsACLProtected": is_acl_protected,
                "Aces": aces,
            }

        principal_type = "Unknown"
        if "msDS-GroupManagedServiceAccount" in record.object_classes:
            principal_type = "User"
        elif "computer" in record.object_classes:
            principal_type = "Computer"
        elif "user" in record.object_classes:
            principal_type = "User"
        elif "group" in record.object_classes:
            principal_type = "Group"
        elif {"domain", "domainDNS", "trustedDomain"}.intersection(record.object_classes):
            principal_type = "Domain"

        for ace in sd.dacl.ace:
            if ace.type not in (ACE_TYPE.ACCESS_ALLOWED, ACE_TYPE.ACCESS_ALLOWED_OBJECT):
                continue

            is_inherited = bool(ace.flags & ACE_FLAGS.INHERITED_ACE)

            for mask_flag, right_name in ACL_STANDARD_RIGHTS.items():
                if ace.mask & mask_flag:
                    aces.append(
                        {
                            "PrincipalSID": ace.sid,
                            "PrincipalType": principal_type,
                            "RightName": right_name,
                            "IsInherited": is_inherited,
                        }
                    )

            if not ace.is_object_ace or not ace.object_type:
                continue

            guid = str(ace.object_type).lower()

            if ace.mask & ACCESS_MASK.ADS_RIGHT_DS_CONTROL_ACCESS and guid in ACL_EXTENDED_RIGHTS:
                aces.append(
                    {
                        "PrincipalSID": ace.sid,
                        "PrincipalType": principal_type,
                        "RightName": ACL_EXTENDED_RIGHTS[guid],
                        "IsInherited": is_inherited,
                    }
                )

            if ace.mask & ACCESS_MASK.ADS_RIGHT_DS_WRITE_PROP and guid in ACL_WRITE_PROPERTIES:
                aces.append(
                    {
                        "PrincipalSID": ace.sid,
                        "PrincipalType": principal_type,
                        "RightName": ACL_WRITE_PROPERTIES[guid],
                        "IsInherited": is_inherited,
                    }
                )

        return {
            "IsACLProtected": is_acl_protected,
            "Aces": aces,
        }

    def get_object_identifier(self, ad_object: Object | Record) -> str | None:
        """Get the unique identifier for an AD object, preferring SID over GUID.

        Args:
            ad_object (Object | Record): The AD object or record to extract the identifier from.

        Returns:
            uid (str | None): The unique identifier for the AD object, or None if neither SID nor GUID is available.
        """
        if ad_object.sid is None and ad_object.guid is None:
            return None

        return ad_object.sid if ad_object.sid else str(ad_object.guid)

    def get_object_identity(self, ad_object: Object) -> dict[str, str] | None:
        """Get the unique identity for an AD object.

        Args:
            ad_object (Object): The AD object to extract the identity from.

        Returns:
            identity (dict[str, str] | None): The unique identity for the AD object,
                or ``None`` if object identifier couldn't be resolved.
        """
        object_id = self.get_object_identifier(ad_object)
        if object_id is None:
            return None

        return {
            "ObjectIdentifier": object_id,
            "ObjectType": ad_object.object_category,
        }

    def get_children_identities(self, record: Record) -> list[dict[str, str]]:
        """Get children unique identities for a given record.

        Args:
            record (Record): Record representing an AD object to children identities from.

        Returns:
            child_identities (list[dict[str, str]]): The unique child identities.
        """
        current_object = next(self.target.ad.ntds.search(DNT=record.dnt))
        return [self.get_object_identity(child) for child in current_object.children()]

    def get_parent_identity(self, record: Record) -> dict[str, str] | None:
        """Get parent unique identity for a given record.

        Args:
            record (Record): Record representing an AD object to parent identity from.

        Returns:
            parent_identity (dict[str, str] | None): The unique parent identity,
                or ``None`` if the parent couldn't be resolved.
        """
        if record.pdnt is None:
            return None

        parent_object = next(self.target.ad.ntds.search(DNT=record.pdnt))

        return self.get_object_identity(parent_object)

    def extract_generic_info(self, record: Record) -> dict[str, Any]:
        """Extract generic information for a given record.

        Args:
            record (Record): Record representing an AD object to extract generic information from.

        Returns:
            generic_info (dict[str, Any]): The generic information.
        """
        return {
            "ObjectIdentifier": self.get_object_identifier(record),
            "IsDeleted": record.is_deleted.value,
            **self.get_sd_data(record),
            "ContainedBy": self.get_parent_identity(record),
        }

    def extract_generic_properties(self, record: Record) -> dict[str, Any]:
        """Extract generic properties for a given record.

        Args:
            record (Record): Record representing an AD object to extract generic properties from.

        Returns:
            generic_properties (dict[str, Any]): The generic properties.
        """
        return {
            "domain": extract_fqdn_from_dn(record.distinguished_name),
            "name": record.name,
            "displayname": record.display_name,
            "distinguishedname": record.distinguished_name,
            "domainsid": record.sid.removesuffix(f"-{record.rid}") if record.sid else None,
            "whencreated": int(record.creation_time.timestamp()),
            "description": record.description,
        }

    def extract_security_properties(self, record: Record) -> dict[str, Any]:
        """Extract security properties for a given record.

        Args:
            record (Record): Record representing an AD object to extract security properties from.

        Returns:
            security_properties (dict[str, Any]): The security properties.
        """
        return {
            **self.extract_generic_properties(record),
            "samaccountname": record.sam_name,
            "admincount": record.admin_count.value,
            "highvalue": extract_high_value(record),
        }

    def extract_account_info(self, record: Record) -> dict[str, Any]:
        """Extract account information for a given record.

        Args:
            record (Record): Record representing an AD object to extract account information from.

        Returns:
            account_info (dict[str, Any]): The account information.
        """
        return {
            **self.extract_generic_info(record),
            "PrimaryGroupSID": record.sid.replace(f"-{record.rid}", f"-{record.primary_group_id}"),
            "AllowedToDelegate": record.allowed_to_delegate,
            "HasSIDHistory": record.sid_history,
        }

    def extract_account_properties(self, record: Record) -> dict[str, Any]:
        """Extract account properties for a given record.

        Args:
            record (Record): Record representing an AD object to extract account properties from.

        Returns:
            account_properties (dict[str, Any]): The account properties.
        """
        return {
            **self.extract_security_properties(record),
            "sensitive": UserAccountControl.NOT_DELEGATED.name in record.user_account_control,
            "passwordnotreqd": UserAccountControl.PASSWD_NOTREQD.name in record.user_account_control,
            "pwdneverexpires": UserAccountControl.DONT_EXPIRE_PASSWORD.name in record.user_account_control,
            "enabled": UserAccountControl.ACCOUNTDISABLE.name not in record.user_account_control,
            "unconstraineddelegation": UserAccountControl.TRUSTED_FOR_DELEGATION.name in record.user_account_control,
            "trustedtoauth": bool(record.allowed_to_delegate)
            and UserAccountControl.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION.name in record.user_account_control,
            "lastlogon": int(record.logon_last_local.timestamp())
            if record.logon_last_local
            else BLOODHOUND_TIMESTAMP_NEVER,
            "lastlogontimestamp": int(record.logon_last_replicated.timestamp())
            if record.logon_last_replicated
            else BLOODHOUND_TIMESTAMP_NEVER,
            "pwdlastset": int(record.password_last_set.timestamp())
            if record.password_last_set
            else BLOODHOUND_TIMESTAMP_NEVER,
            "email": record.email,
            "title": record.title,
            "homedirectory": record.home_directory,
            "userpassword": record.user_password,
            "unixpassword": record.unix_password,
            "unicodepassword": record.nt
            if record.nt != DEFAULT_NT_HASH
            else record.lm
            if record.lm != DEFAULT_LM_HASH
            else None,
            "sfupassword": record.sfu_password,
            "logonscript": record.logon_script,
            "serviceprincipalnames": record.service_principal_names,
            "sidhistory": record.sid_history,
        }

    def extract_container_info(self, record: Record) -> dict[str, Any]:
        """Extract container information for a given record.

        Args:
            record (Record): Record representing an AD object to extract container information from.

        Returns:
            container_info (dict[str, Any]): The container information.
        """
        return {
            **self.extract_generic_info(record),
            "Links": self.get_gplink(record.gplink),
            "ChildObjects": self.get_children_identities(record),
            # TODO: Parse extra SYSVOL files for this
            "GPOChanges": {
                "LocalAdmins": [],
                "RemoteDesktopUsers": [],
                "DcomUsers": [],
                "PSRemoteUsers": [],
                "AffectedComputers": [],
            },
        }

    def extract_container_properties(self, record: Record) -> dict[str, Any]:
        """Extract container properties for a given record.

        Args:
            record (Record): Record representing an AD object to extract container properties from.

        Returns:
            container_properties (dict[str, Any]): The container properties.
        """
        return {
            **self.extract_generic_properties(record),
            "highvalue": extract_high_value(record),
        }

    def translate_users(self) -> Iterator[dict[str, Any]]:
        """Translate user records to BloodHound dict.

        Yields:
            user_data (dict[str, Any]): BloodHound user data.
        """
        for user in self.target.ad.users():
            yield {
                **self.extract_account_info(user),
                "SPNTargets": user.service_principal_names,
                "Properties": {
                    **self.extract_account_properties(user),
                    "hasspn": bool(user.service_principal_names),
                },
            }

    def translate_computers(self) -> Iterator[dict[str, Any]]:
        """Translate computer records to BloodHound dict.

        Yields:
            computer_data (dict[str, Any]): BloodHound computer data.
        """
        for computer in self.target.ad.computers():
            yield {
                **self.extract_account_info(computer),
                "AllowedToAct": computer.allowed_to_act,
                "Properties": {
                    **self.extract_account_properties(computer),
                    "unconstraineddelegation": UserAccountControl.TRUSTED_FOR_DELEGATION.name
                    in computer.user_account_control,
                    "operatingsystem": computer.operating_system,
                    "haslaps": computer.has_laps.value,
                    "DumpSMSAPassword": computer.dump_smsa_password,
                    # TODO:
                    # We can't populate Sessions without session data (Offline collection),
                    # so we'll just put a placeholder here for now
                    # We may be able to populate this with some heuristic in the future
                    "Sessions": {"Results": [], "Collected": False, "FailureReason": None},
                    "PrivilegedSessions": {"Results": [], "Collected": False, "FailureReason": None},
                    "RegistrySessions": {"Results": [], "Collected": False, "FailureReason": None},
                    # TODO: Same as last with local groups and user rights
                    "LocalGroups": [],
                    "UserRights": [],
                    **self.dc_registry_data,
                    "Status": None,
                },
            }

    def translate_domains(self) -> Iterator[dict[str, Any]]:
        """Translate domain records to BloodHound dict.

        Yields:
            domain_data (dict[str, Any]): BloodHound domain data.
        """
        for domain in self.target.ad.domains():
            dn = domain.distinguished_name.lower()
            if "dc=domaindnszones" in dn or "dc=forestdnszones" in dn:
                continue

            yield {
                **self.extract_container_info(domain),
                "Trusts": self.get_trusts(domain),
                "Properties": {
                    **self.extract_container_properties(domain),
                    "functionallevel": BEHAVIOR_VERSION_TO_FUNCTIONAL_LEVEL_MAP.get(domain.behavior_version),
                },
            }

    def translate_groups(self) -> Iterator[dict[str, Any]]:
        """Translate group records to BloodHound dict.

        Yields:
            group_data (dict[str, Any]): BloodHound group data.
        """
        for group in self.target.ad.groups():
            yield {
                **self.extract_generic_info(group),
                "Properties": {
                    **self.extract_security_properties(group),
                },
                "Members": self.get_group_members(group),
            }

    def translate_organizational_units(self) -> Iterator[dict[str, Any]]:
        """Translate organizational units records to BloodHound dict.

        Yields:
            organizational_units_data (dict[str, Any]): BloodHound organizational units data.
        """
        for ou in self.target.ad.organizational_units():
            yield {
                **self.extract_container_info(ou),
                "Properties": {
                    **self.extract_container_properties(ou),
                    "blocksinheritance": ou.blocks_inheritance.value,
                },
            }

    def translate_group_policies(self) -> Iterator[dict[str, Any]]:
        """Translate group policies records to BloodHound dict.

        Yields:
            group_policies_data (dict[str, Any]): BloodHound group policies data.
        """
        for gpo in self.target.ad.group_policies():
            yield {
                **self.extract_generic_info(gpo),
                "Properties": {
                    **self.extract_container_properties(gpo),
                    "gpcpath": str(gpo.gpc_path),
                },
            }

    @arg("-o", "--output", dest="output_dir", type=Path, required=True, help="Path to extract BloodHound files to")
    @export(output="none")
    def bloodhound(self, output_dir: Path) -> None:
        """Extract AD objects in BloodHound format and write them iteratively to disk.

        Args:
            output_dir (Path): The directory to write BloodHound JSON files to.
        """
        TYPE_TO_FUNCTION_MAPPING = {
            "users": self.translate_users,
            "computers": self.translate_computers,
            "domains": self.translate_domains,
            "groups": self.translate_groups,
            "ous": self.translate_organizational_units,
            "gpos": self.translate_group_policies,
        }

        output_dir.mkdir(parents=True, exist_ok=True)

        for object_type, translation_function in TYPE_TO_FUNCTION_MAPPING.items():
            output_path = output_dir.joinpath(object_type).with_suffix(".json")

            metadata = {"methods": 0, "type": object_type, "version": 6, "count": 0}
            json_start = '{\n\t"data": [\n\t\t'

            with output_path.open("w", encoding="utf-8") as output_handle:
                output_handle.write(json_start)
                first = True
                for item in translation_function():
                    if not first:
                        output_handle.write(",\n\t\t")

                    metadata["count"] += 1
                    output_handle.write(json.dumps(item))
                    first = False

                json_end = '\n\t\t], \n\t"meta": ' + json.dumps(metadata) + "\n}\n"
                output_handle.write(json_end)
