import io

from dissect import cstruct

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

c_adtev = cstruct.cstruct()
c_adtev.load(
    """
struct header {
    uint16  unk0;
    uint16  unk1;
    uint16  num_categories;
    uint16  unk2;
    uint16  footer_offset;
    uint16  unk3;
};
"""
)

POLICY_CATEGORIES = [
    "System",
    "Logon/Logoff",
    "Object Access",
    "Privilege Use",
    "Detailed Tracking",
    "Policy Change",
    "Account Management",
    "DS Access",
    "Account Logon",
]

POLICY_MAP = {
    "System": [
        "Security State Change",
        "Security System Extension",
        "System Integrity",
        "IPsec Driver",
        "Other System Events",
    ],
    "Logon/Logoff": [
        "Logon",
        "Logoff",
        "Account Lockout",
        "IPsec Main Mode",
        "Special Logon",
        "IPsec Quick Mode",
        "IPsec Extended Mode",
        "Other Logon/Logoff Events",
        "Network Policy Server",
        "User/Device Claims",
        "Group Membership",
    ],
    "Object Access": [
        "File System",
        "Registry",
        "Kernel Object",
        "SAM",
        "Other Object Access Events",
        "Certification Services",
        "Application Generated",
        "Handle Manipulation",
        "File Share",
        "Filtering Platform Packet Drop",
        "Filtering Platform Connection",
        "Detailed File Share",
        "Removable Storage",
        "Central Policy Staging",
    ],
    "Privilege Use": [
        "Sensitive Privilege Use",
        "Non Sensitive Privilege Use",
        "Other Privilege Use Events",
    ],
    "Detailed Tracking": [
        "Process Creation",
        "Process Termination",
        "DPAPI Activity",
        "RPC Events",
        "Plug and Play Events",
        "Token Right Adjusted Events",
    ],
    "Policy Change": [
        "Audit Policy Change",
        "Authentication Policy Change",
        "Authorization Policy Change",
        "MPSSVC Rule-Level Policy Change",
        "Filtering Platform Policy Change",
        "Other Policy Change Events",
    ],
    "Account Management": [
        "User Account Management",
        "Computer Account Management",
        "Security Group Management",
        "Distribution Group Management",
        "Application Group Management",
        "Other Account Management Events",
    ],
    "DS Access": [
        "Directory Service Access",
        "Directory Service Changes",
        "Directory Service Replication",
        "Detailed Directory Service Replication",
    ],
    "Account Logon": [
        "Credential Validation",
        "Kerberos Service Ticket Operations",
        "Other Account Logon Events",
        "Kerberos Authentication Service",
    ],
}

POLICY_VALUES = {
    0: "No auditing",
    1: "Success",
    2: "Failure",
    3: "Success/Failure",
}

AuditPolicyRecord = TargetRecordDescriptor(
    "windows/registry/auditpol",
    [
        ("string", "category"),
        ("string", "name"),
        ("string", "value"),
    ],
)


class AuditpolPlugin(Plugin):
    """Plugin that parses audit policy settings from the registry."""

    KEY = "HKLM\\SECURITY\\Policy\\PolAdtEv"

    def check_compatible(self):
        if not len(list(self.target.registry.keys(self.KEY))) > 0:
            raise UnsupportedPluginError(f"Registry key {self.KEY} not found")

    @export(record=AuditPolicyRecord)
    def auditpol(self):
        """Return audit policy settings from the registry.

        For Windows, the audit policy settings are stored in the HKEY_LOCAL_MACHINE\\Security\\Policy\\PolAdtEv registry
        key. It shows for each possible audit event if it is logged.

        References:
            - https://countuponsecurity.com/tag/poladtev/
        """
        for regf in self.target.registry.keys(self.KEY):
            for entry in regf.values():
                if not len(entry.value):
                    continue

                buf = io.BytesIO(entry.value)
                header = c_adtev.header(buf)
                data_offset = buf.tell()

                buf.seek(header.footer_offset)
                category_counts = c_adtev.uint16[header.num_categories](buf)

                buf.seek(data_offset)
                for i in range(header.num_categories):
                    num_entries = category_counts[i]
                    category_name = POLICY_CATEGORIES[i]
                    labels = POLICY_MAP[category_name]
                    values = c_adtev.uint16[category_counts[i]](buf)

                    for j in range(num_entries):
                        try:
                            label = labels[j]
                        except IndexError:
                            label = "Unknown"

                        yield AuditPolicyRecord(
                            category=category_name,
                            name=label,
                            value=POLICY_VALUES[values[j]],
                            _target=self.target,
                        )
