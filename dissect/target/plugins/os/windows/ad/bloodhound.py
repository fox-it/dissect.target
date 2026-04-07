from __future__ import annotations

import json
import re
from functools import cache, cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dissect.database.ese.ntds.c_sd import c_sd
from dissect.database.ese.ntds.util import UserAccountControl

from dissect.target.plugin import Plugin, UnsupportedPluginError, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds import NTDS, Object
    from dissect.database.ese.ntds.sd import SecurityDescriptor
    from flow.record import Record

    from dissect.target import Target


# Standard BloodHound GUID Mappings
ACL_EXTENDED_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DCSync",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DCSync",
    "89e95b76-ce4a-45c9-bbc6-5d6133112a4e": "DCSync",
}

ACL_WRITE_PROPERTIES = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddMember",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "AddAllowedToAct",
}

# Active Directory Trust Attribute Bitmasks
TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x0001
TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x0004  # SID Filtering Enabled
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


def trust_type_uplevel_to_actual_type(trust_attributes: int) -> str:
    if trust_attributes & TRUST_ATTRIBUTE_WITHIN_FOREST:
        return "ParentChild"
    if trust_attributes & TRUST_ATTRIBUTE_FOREST_TRANSITIVE:
        return "Forest"
    return "External"


@cache
def extract_sd_data(ntds: NTDS, nt_security_descriptor: int | None) -> tuple[bool, list[dict[str, Any]]]:
    """Translate an NT Security Descriptor into BloodHound ACE format.

    Args:
        nt_security_descriptor: Raw nTSecurityDescriptor from dissect.

    Returns:
        A list of dictionaries representing BloodHound Access Control Entries.
    """
    if nt_security_descriptor is None:
        return []

    aces = []

    sd: SecurityDescriptor = ntds.db.sd.sd(nt_security_descriptor)
    if sd.dacl is None:
        return []

    for ace in sd.dacl.ace:
        # We generally only care about ACCESS_ALLOWED_ACE_TYPE (0) and ACCESS_ALLOWED_OBJECT_ACE_TYPE (5)
        # You can check the integer value safely regardless of the Enum naming
        if ace.type.value not in (0, 5):
            continue

        # 1. Determine Inheritance
        # INHERITED_ACE flag is 0x10
        is_inherited = False
        if ace.flags and (ace.flags.value & 0x10):
            is_inherited = True

        # Extract the raw integer mask for bitwise comparison
        mask = ace.mask.value if ace.mask else 0
        sid = ace.sid

        # BloodHound will often resolve "Unknown" internally based on the SID,
        # or you can write a helper function to check well-known SIDs later.
        principal_type = "Unknown"

        # 2. Check Standard Rights
        # GENERIC_ALL
        if mask & 0x10000000:
            aces.append(
                {
                    "PrincipalSID": sid,
                    "PrincipalType": principal_type,
                    "RightName": "GenericAll",
                    "IsInherited": is_inherited,
                }
            )
        # GENERIC_WRITE
        if mask & 0x40000000:
            aces.append(
                {
                    "PrincipalSID": sid,
                    "PrincipalType": principal_type,
                    "RightName": "GenericWrite",
                    "IsInherited": is_inherited,
                }
            )
        # WRITE_DAC
        if mask & 0x00040000:
            aces.append(
                {
                    "PrincipalSID": sid,
                    "PrincipalType": principal_type,
                    "RightName": "WriteDacl",
                    "IsInherited": is_inherited,
                }
            )
        # WRITE_OWNER
        if mask & 0x00080000:
            aces.append(
                {
                    "PrincipalSID": sid,
                    "PrincipalType": principal_type,
                    "RightName": "WriteOwner",
                    "IsInherited": is_inherited,
                }
            )

        # 3. Check Object-Specific Rights (Extended Rights and Properties)
        if ace.is_object_ace and ace.object_type:
            guid_str = str(ace.object_type).lower()

            # ADS_RIGHT_DS_CONTROL_ACCESS (Extended Rights) - 0x00000100
            if mask & 0x00000100:
                if guid_str in ACL_EXTENDED_RIGHTS:
                    aces.append(
                        {
                            "PrincipalSID": sid,
                            "PrincipalType": principal_type,
                            "RightName": ACL_EXTENDED_RIGHTS[guid_str],
                            "IsInherited": is_inherited,
                        }
                    )
                # All zeros means All Extended Rights
                elif guid_str == "00000000-0000-0000-0000-000000000000":
                    aces.append(
                        {
                            "PrincipalSID": sid,
                            "PrincipalType": principal_type,
                            "RightName": "AllExtendedRights",
                            "IsInherited": is_inherited,
                        }
                    )

            # ADS_RIGHT_DS_WRITE_PROP (Write Property) - 0x00000020
            if mask & 0x00000020 and guid_str in ACL_WRITE_PROPERTIES:
                aces.append(
                    {
                        "PrincipalSID": sid,
                        "PrincipalType": principal_type,
                        "RightName": ACL_WRITE_PROPERTIES[guid_str],
                        "IsInherited": is_inherited,
                    }
                )

    return c_sd.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PROTECTED.name in sd.header.Control.name.split("|"), aces


def extract_fqdn_from_dn(distinguished_name: str | None) -> str | None:
    """Parses a Distinguished Name and returns the uppercase FQDN."""
    if not distinguished_name:
        return None

    # Split the DN by commas and filter for parts that start with 'DC='
    dc_parts = [
        part.split("=", 1)[1] for part in distinguished_name.split(",") if part.strip().upper().startswith("DC=")
    ]

    return ".".join(dc_parts).lower()


class BloodHound(Plugin):
    def __init__(self, target: Target) -> None:
        super().__init__(target)
        self.gp_link_pattern: re.Pattern = re.compile(r"\[LDAP://CN=({[A-Fa-f0-9\-]+}),.*?;(\d+)\]")

    def check_compatible(self) -> None:
        if not self.target.has_function("ad"):
            raise UnsupportedPluginError("ad plugin is not initialized")

    @staticmethod
    def extract_high_value(record: Record) -> str | None:
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

    def get_object_identifier(self, ad_object: Object | Record) -> str | None:
        if ad_object.sid is None and ad_object.guid is None:
            return None

        return ad_object.sid if ad_object.sid else str(ad_object.guid)

    def build_container_info(self, ad_object: Object) -> dict[str, str] | None:
        object_id = self.get_object_identifier(ad_object)
        if object_id is None:
            return None

        return {
            "ObjectIdentifier": object_id,
            "ObjectType": ad_object.object_category,
        }

    def extract_children_info(self, record: Record) -> list[dict[str, str]]:
        current_object = next(self.target.ad.ntds.search(DNT=record.dnt))
        return [self.build_container_info(child) for child in current_object.children()]

    def extract_parent_info(self, record: Record) -> dict[str, str] | None:
        if record.pdnt is None:
            return None

        parent_object = next(self.target.ad.ntds.search(DNT=record.pdnt))

        return self.build_container_info(parent_object)

    @staticmethod
    def extract_domain_id(record: Record) -> str | None:
        return record.sid.removesuffix(f"-{record.rid}") if record.sid else None

    @staticmethod
    def extract_flag_from_enum(record: Record, flag: UserAccountControl) -> bool:
        return flag.name in record.user_account_control.split("|")

    def extract_generic_info(self, record: Record) -> dict[str, Any]:
        is_acl_protected, aces = extract_sd_data(self.target.ad.ntds, record.nt_security_descriptor)

        return {
            "ObjectIdentifier": self.get_object_identifier(record),
            "IsDeleted": record.is_deleted.value,
            "IsACLProtected": is_acl_protected,
            "Aces": aces,
            "ContainedBy": self.extract_parent_info(record),
        }

    def extract_generic_properties(self, record: Record) -> dict[str, Any]:
        return {
            "domain": extract_fqdn_from_dn(record.distinguished_name),
            "name": record.name,
            "displayname": record.display_name,
            "distinguishedname": record.distinguished_name,
            "domainsid": self.extract_domain_id(record),
            "whencreated": int(record.creation_time.timestamp()),
            "description": record.description,
        }

    def extract_security_properties(self, record: Record) -> dict[str, Any]:
        return {
            **self.extract_generic_properties(record),
            "samaccountname": record.sam_name,
            "admincount": record.admin_count.value,
            "highvalue": self.extract_high_value(record),
        }

    def extract_account_info(self, record: Record) -> dict[str, Any]:
        return {
            **self.extract_generic_info(record),
            "PrimaryGroupSID": record.sid.replace(f"-{record.rid}", f"-{record.primary_group_id}"),
            "AllowedToDelegate": record.allowed_to_delegate,
            "HasSIDHistory": record.sid_history,
        }

    def extract_account_properties(self, record: Record) -> dict[str, Any]:
        return {
            **self.extract_security_properties(record),
            "sensitive": self.extract_flag_from_enum(record, UserAccountControl.NOT_DELEGATED),
            "passwordnotreqd": self.extract_flag_from_enum(record, UserAccountControl.PASSWD_NOTREQD),
            "pwdneverexpires": self.extract_flag_from_enum(record, UserAccountControl.DONT_EXPIRE_PASSWORD),
            "enabled": not self.extract_flag_from_enum(record, UserAccountControl.ACCOUNTDISABLE),
            "unconstraineddelegation": self.extract_flag_from_enum(record, UserAccountControl.TRUSTED_FOR_DELEGATION),
            "trustedtoauth": bool(record.allowed_to_delegate)
            and self.extract_flag_from_enum(record, UserAccountControl.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION),
            "lastlogon": int(record.logon_last_success_observed.timestamp())
            if record.logon_last_success_observed
            else BLOODHOUND_TIMESTAMP_NEVER,
            "lastlogontimestamp": int(record.logon_last_success_reported.timestamp())
            if record.logon_last_success_reported
            else BLOODHOUND_TIMESTAMP_NEVER,
            "pwdlastset": int(record.password_last_set.timestamp())
            if record.password_last_set
            else BLOODHOUND_TIMESTAMP_NEVER,
            "email": record.email,
            "title": record.title,
            "homedirectory": record.home_directory,
            "userpassword": None,
            "unixpassword": None,
            "unicodepassword": record.nt,  # TODO: Figure out if lm hash goes here or not
            "sfupassword": None,
            "logonscript": record.logon_script,
            "serviceprincipalnames": record.service_principal_names,
            "sidhistory": record.sid_history,
        }

    def extract_container_info(self, record: Record) -> dict[str, Any]:
        return {
            **self.extract_generic_info(record),
            "Links": self.parse_gplink_for_bloodhound(record.gplink),
            "ChildObjects": self.extract_children_info(record),
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
        return {
            **self.extract_generic_properties(record),
            "highvalue": self.extract_high_value(record),
        }

    def translate_users(self) -> Iterator[dict[str, Any]]:
        """Iterate over user records and yield BloodHound-formatted dictionaries."""
        for user in self.target.ad.users():
            yield {
                **self.extract_account_info(user),
                "SPNTargets": user.service_principal_names,  # TODO: Verify this is correct for SPN targeting in BH
                "Properties": {
                    **self.extract_account_properties(user),
                    "hasspn": bool(user.service_principal_names),
                },
            }

    def translate_computers(self) -> Iterator[dict[str, Any]]:
        for computer in self.target.ad.computers():
            yield {
                **self.extract_account_info(computer),
                "AllowedToAct": computer.allowed_to_act,
                "Properties": {
                    **self.extract_account_properties(computer),
                    "unconstraineddelegation": self.extract_flag_from_enum(
                        computer, UserAccountControl.TRUSTED_FOR_DELEGATION
                    ),
                    "operatingsystem": computer.operating_system,
                    "haslaps": computer.has_laps.value,
                    "DumpSMSAPassword": None,  # TODO: Resolve this
                    # We can't populate Sessions without session data (Offline collection),
                    # so we'll just put a placeholder here for now
                    # We may be able to populate this with some heuristic in the future
                    "Sessions": {"Results": [], "Collected": False, "FailureReason": None},
                    "PrivilegedSessions": {"Results": [], "Collected": False, "FailureReason": None},
                    "RegistrySessions": {"Results": [], "Collected": False, "FailureReason": None},
                    # Same with local groups and user rights
                    "LocalGroups": [],
                    "UserRights": [],
                    # This we can probably collect because we have the registry of the DC
                    "DCRegistryData": {"CertificateMappingMethods": None, "StrongCertificateBindingEnforcement": None},
                    "Status": not self.extract_flag_from_enum(computer, UserAccountControl.ACCOUNTDISABLE),
                },
            }

    def parse_gplink_for_bloodhound(self, gplink_string: str) -> list[dict[str, str | bool]]:
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

        matches: list[str] = self.gp_link_pattern.findall(gplink_string)

        for guid_string, options_str in matches:
            options = int(options_str)

            is_enforced = options == 2
            is_disabled = options == 1

            # BloodHound only tracks active links in its graph
            if not is_disabled:
                # Strip the curly braces and ensure it's uppercase for BloodHound standards
                clean_guid = guid_string.strip("{}").upper()

                bloodhound_links.append({"GUID": clean_guid, "IsEnforced": is_enforced})

        return bloodhound_links

    @cached_property
    def trusts(self) -> list[dict[str, str | dict[str, Any]]]:
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

    def get_trusts(self, domain: Record) -> list[dict[str, Any]]:
        """Given a domain record, return a list of trusts in BloodHound format."""
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

    def translate_domains(self) -> Iterator[dict[str, Any]]:
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

    def extract_group_members(self, group_record: Record) -> list[dict[str, str]]:
        members = []
        for member_sid in group_record.members:
            member_object = next(self.target.ad.ntds.search(objectSid=member_sid))
            members.append(self.build_container_info(member_object))

        return members

    def translate_groups(self) -> Iterator[dict[str, Any]]:
        for group in self.target.ad.groups():
            yield {
                **self.extract_generic_info(group),
                "Properties": {
                    **self.extract_security_properties(group),
                },
                "Members": self.extract_group_members(group),
            }

    def translate_organizational_units(self) -> Iterator[dict[str, Any]]:
        for ou in self.target.ad.organizational_units():
            yield {
                **self.extract_container_info(ou),
                "Properties": {
                    **self.extract_container_properties(ou),
                    "blocksinheritance": ou.blocks_inheritance.value,
                },
            }

    def translate_group_policies(self) -> Iterator[dict[str, Any]]:
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
        """Extract AD objects in BloodHound format and write them iteratively to disk."""
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
