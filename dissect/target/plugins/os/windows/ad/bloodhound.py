from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Any

from dissect.database.ese.ntds import NTDS
from dissect.database.ese.ntds.c_sd import c_sd
from dissect.database.ese.ntds.util import UserAccountControl

from dissect.target.plugin import Plugin, UnsupportedPluginError, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.database.ese.ntds import NTDS
    from dissect.database.ese.ntds.sd import SecurityDescriptor
    from flow.record import Record


# Standard BloodHound GUID Mappings
BH_EXTENDED_RIGHTS = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DCSync",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DCSync",
    "89e95b76-ce4a-45c9-bbc6-5d6133112a4e": "DCSync",
}

BH_WRITE_PROPERTIES = {
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "AddMember",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "AddAllowedToAct",
}


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
                if guid_str in BH_EXTENDED_RIGHTS:
                    aces.append(
                        {
                            "PrincipalSID": sid,
                            "PrincipalType": principal_type,
                            "RightName": BH_EXTENDED_RIGHTS[guid_str],
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
            if mask & 0x00000020 and guid_str in BH_WRITE_PROPERTIES:
                aces.append(
                    {
                        "PrincipalSID": sid,
                        "PrincipalType": principal_type,
                        "RightName": BH_WRITE_PROPERTIES[guid_str],
                        "IsInherited": is_inherited,
                    }
                )

    return c_sd.SECURITY_DESCRIPTOR_CONTROL.SE_DACL_PROTECTED.name in sd.header.Control.name.split("|"), aces


class BloodHound(Plugin):
    def check_compatible(self) -> None:
        if not self.target.has_function("ad"):
            raise UnsupportedPluginError("ad plugin is not initialized")

    @staticmethod
    def extract_high_value(record: Record) -> str | None:
        return record.admin_count.value or record.rid in (512, 516)

    @staticmethod
    def extract_domain_id(record: Record) -> str | None:
        return record.sid.removesuffix(f"-{record.rid}") if record.sid else None

    @staticmethod
    def extract_flag_from_enum(record: Record, flag: UserAccountControl) -> bool:
        return flag.name in record.user_account_control.split("|")

    def extract_generic_info(self, record: Record) -> dict[str, Any]:
        is_acl_protected, aces = extract_sd_data(self.target.ad.ntds, record.nt_security_descriptor)

        contained_by = None
        if record.parent_guid and record.parent_type:
            contained_by = {"ObjectIdentifier": record.parent_guid, "ObjectType": record.parent_type}

        return {
            "ObjectIdentifier": record.sid,
            "IsDeleted": record.is_deleted.value,
            "IsACLProtected": is_acl_protected,
            "Aces": aces,
            "ContainedBy": contained_by,
        }

    def extract_generic_properties(self, record: Record) -> dict[str, Any]:
        return {
            "domain": record.domain,  # TODO: Make sure this is robust because it's not from ntds.dit
            "name": record.name,
            "displayname": record.display_name,
            "distinguishedname": record.distinguished_name,
            "domainsid": self.extract_domain_id(record),
            "whencreated": record.creation_time.isoformat(),
            "description": record.description,
        }

    def extract_security_info(self, record: Record) -> dict[str, Any]:
        return {
            **self.extract_generic_info(record),
            "HasSIDHistory": record.sid_history,
        }

    def extract_security_properties(self, record: Record) -> dict[str, Any]:
        return {
            **self.extract_generic_properties(record),
            "samaccountname": record.sam_name,
            "admincount": record.admin_count.value,
            "sidhistory": record.sid_history,
        }

    def extract_account_info(self, record: Record) -> dict[str, Any]:
        return {
            **self.extract_security_info(record),
            "PrimaryGroupSID": record.sid.replace(f"-{record.rid}", f"-{record.primary_group_id}"),
            "AllowedToDelegate": record.allowed_to_delegate,
        }

    def extract_account_properties(self, record: Record) -> dict[str, Any]:
        return {
            **self.extract_security_properties(record),
            "highvalue": self.extract_high_value(record),
            "sensitive": self.extract_flag_from_enum(record, UserAccountControl.NOT_DELEGATED),
            "passwordnotreqd": self.extract_flag_from_enum(record, UserAccountControl.PASSWD_NOTREQD),
            "pwdneverexpires": self.extract_flag_from_enum(record, UserAccountControl.DONT_EXPIRE_PASSWORD),
            "enabled": not self.extract_flag_from_enum(record, UserAccountControl.ACCOUNTDISABLE),
            "unconstraineddelegation": self.extract_flag_from_enum(record, UserAccountControl.TRUSTED_FOR_DELEGATION),
            "trustedtoauth": bool(record.allowed_to_delegate)
            and self.extract_flag_from_enum(record, UserAccountControl.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION),
            "lastlogon": record.logon_last_success_observed.isoformat() if record.logon_last_success_observed else 0,
            "lastlogontimestamp": record.logon_last_success_reported.isoformat()
            if record.logon_last_success_reported
            else -1,
            "pwdlastset": record.password_last_set.isoformat() if record.password_last_set else 0,
            "email": record.email,
            "title": record.title,
            "homedirectory": record.home_directory,
            "userpassword": None,
            "unixpassword": None,
            "unicodepassword": record.nt,  # TODO: Figure out lm hash goes here or not
            "sfupassword": None,
            "logonscript": record.logon_script,
            "serviceprincipalnames": record.service_principal_names,
        }

    def translate_users(self) -> Iterator[dict[str, Any]]:
        """Iterate over user records and yield BloodHound-formatted dictionaries."""
        for user in self.target.ad.users():
            yield {
                **self.extract_account_info(user),
                "SPNTargets": user.service_principal_names,  # TODO: Verify this is correct for SPN targeting in BloodHound
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
                    "haslaps": computer.has_laps,
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

    def translate_domains(self) -> Iterator[dict[str, Any]]:
        for domain in self.target.ad.domains():
            yield {
                "ObjectIdentifier": domain.sid,
                "Properties": {
                    "name": domain.name,
                    "domain": domain.name,
                    "distinguishedname": domain.distinguished_name,
                    "description": domain.description,
                },
                "Aces": extract_sd_data(self.ntds, domain.nt_security_descriptor),
                "ChildObjects": [],
                "Trusts": [],
                "Links": [],
            }

    def translate_groups(self) -> Iterator[dict[str, Any]]:
        for group in self.target.ad.groups():
            yield {
                "ObjectIdentifier": group.sid,
                "Properties": {
                    "domain": self.extract_domain_id(group),
                    "name": group.sam_name,
                    "distinguishedname": group.distinguished_name,
                },
                "Aces": extract_sd_data(self.ntds, group.nt_security_descriptor),
                "Members": group.members,
            }

    def translate_ous(self) -> Iterator[dict[str, Any]]:
        for ou in self.target.ad.ous():
            yield {
                "ObjectIdentifier": ou.sid,
                "Properties": {
                    "domain": self.extract_domain_id(ou),
                    "name": ou.name,
                    "distinguishedname": ou.distinguished_name,
                    "blocksinheritance": ou.blocks_inheritance,
                },
                "Aces": extract_sd_data(self.ntds, ou.nt_security_descriptor),
                "Links": [],
            }

    def translate_gpos(self) -> Iterator[dict[str, Any]]:
        for gpo in self.target.ad.gpos():
            yield {
                "ObjectIdentifier": gpo.sid,
                "Properties": {
                    "domain": self.extract_domain_id(gpo),
                    "name": gpo.name,
                    "distinguishedname": gpo.distinguished_name,
                },
                "Aces": extract_sd_data(self.ntds, gpo.nt_security_descriptor),
            }

    @arg("-o", "--output", dest="output_dir", type=Path, required=True, help="Path to extract BloodHound files to")
    @export(output="none")
    def bloodhound(self, output_dir: Path) -> None:
        """Extract AD objects in BloodHound format and write them iteratively to disk."""

        TYPE_TO_FUNCTION_MAPPING = {
            "users": self.translate_users,
            "computers": self.translate_computers,
            # "domains": self.translate_domains,
            # "groups": self.translate_groups,
            # "ous": self.translate_ous,
            # "gpos": self.translate_gpos,
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
