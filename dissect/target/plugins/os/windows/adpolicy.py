from struct import unpack

from defusedxml import ElementTree
from dissect import cstruct
from dissect.regf.c_regf import (
    REG_BINARY,
    REG_DWORD,
    REG_DWORD_BIG_ENDIAN,
    REG_EXPAND_SZ,
    REG_LINK,
    REG_MULTI_SZ,
    REG_NONE,
    REG_QWORD,
    REG_SZ,
)

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

c_def = """
struct registry_policy_header {
    uint32   signature;
    uint32   version;
};
"""
c_adpolicy = cstruct.cstruct()
c_adpolicy.load(c_def)

ADPolicyRecord = TargetRecordDescriptor(
    "windows/adpolicy",
    [
        ("datetime", "last_modification_time"),
        ("datetime", "last_access_time"),
        ("datetime", "creation_time"),
        ("string", "guid"),
        ("string", "key"),
        ("string", "value"),
        ("uint32", "size"),
        ("dynamic", "data"),
        ("path", "path"),
    ],
)


class ADPolicyPlugin(Plugin):
    """Plugin that parses AD policies present on Windows Server and Desktop systems

    References:
        - https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format
    """

    def __init__(self, target):
        super().__init__(target)
        self.paths = "windows/sysvol/domain/policies/", "windows/system32/GroupPolicy/DataStore/"
        self.dirs = []

        for fs in self.target.filesystems:
            for path in self.paths:
                self.dirs.append(fs.path(path))

    def check_compatible(self):
        if len([d for d in self.dirs if d.exists()]) <= 0:
            raise UnsupportedPluginError("No AD policy directories found")

    def _xmltasks(self, policy_dir):
        for task_file in policy_dir.rglob("ScheduledTasks.xml"):
            try:
                task_file_stat = task_file.stat()
                xml = task_file.read_text()
                tree = ElementTree.fromstring(xml)
                for task in tree.findall(".//{*}Task"):
                    properties = task.find("Properties") or task
                    task_data = ElementTree.tostring(task)
                    yield ADPolicyRecord(
                        last_modification_time=task_file_stat.st_mtime,
                        last_access_time=task_file_stat.st_atime,
                        creation_time=task_file_stat.st_ctime,
                        guid=task.attrib.get("uid"),
                        key="XML",
                        value=properties.attrib.get("appName", None),
                        size=len(task_data),
                        data=task_data,
                        path=task_file,
                        _target=self.target,
                    )
            except Exception as error:
                self.target.log.warning("Unable to read XML policy file: %s", error)

    @export(record=ADPolicyRecord)
    def adpolicy(self):
        """Return all AD policies (also known as GPOs or Group Policy Objects).

        An Active Directory (AD) maintains global policies that should be adhered by all systems in the domain.
        Example policies are password policies, account lockout policies and group policies.

        References:
            - https://www.windows-active-directory.com/windows-active-directory-policies.html
        """
        for policy_dir in self.dirs:
            if not policy_dir.exists():
                continue

            yield from self._xmltasks(policy_dir)

            # The body consists of registry values in the following format.
            # [key;value;type;size;data]
            for policy_file in policy_dir.rglob("*.pol"):
                policy_file_stat = policy_file.stat()
                if policy_file_stat.st_size <= 8:  # skip empty registry.pol files (only header defined)
                    continue

                fh = policy_file.open()
                policy_header = c_adpolicy.registry_policy_header(fh)
                if policy_header.signature != 0x67655250:
                    self.target.log.warning("Invalid Registry.pol header encountered in file %s", policy_file)
                    continue

                policy_body = fh.read()
                policy_body = policy_body.split(b"]\x00[\x00")

                for policy_line in policy_body:
                    policy_line = policy_line.replace(b"[\x00", b"").replace(b"]\x00", b"")
                    values = policy_line.split(b";\x00", maxsplit=4)

                    if len(values) == 4:
                        # policies without data will not split on ;\x00'
                        # thus we have to split the remainder variable on just ';'
                        policy_reg_key, policy_reg_value, policy_reg_type, remainder = values
                        policy_reg_data_size, policy_reg_data = remainder.split(b";")
                    else:
                        (
                            policy_reg_key,
                            policy_reg_value,
                            policy_reg_type,
                            policy_reg_data_size,
                            policy_reg_data,
                        ) = values

                    policy_reg_data_size = unpack("i", policy_reg_data_size)[0]
                    policy_reg_type = unpack("i", policy_reg_type)[0]

                    policy_reg_data = _decode_policy_reg_data(policy_reg_type, policy_reg_data[:policy_reg_data_size])

                    yield ADPolicyRecord(
                        last_modification_time=policy_file_stat.st_mtime,
                        last_access_time=policy_file_stat.st_atime,
                        creation_time=policy_file_stat.st_ctime,
                        guid=policy_file.parts[4],
                        key=policy_reg_key.decode("utf-16-le").rstrip("\x00"),
                        value=policy_reg_value.decode("utf-16-le").rstrip("\x00"),
                        size=policy_reg_data_size,
                        data=policy_reg_data,
                        path=policy_file,
                        _target=self.target,
                    )


def _decode_policy_reg_data(policy_reg_type, policy_reg_data):
    if policy_reg_data is None or policy_reg_type == REG_NONE:
        return policy_reg_data
    elif policy_reg_type in (REG_EXPAND_SZ, REG_SZ, REG_MULTI_SZ, REG_LINK):
        # REG_SZ, REG_MULTI_SZ, and REG_EXPAND_SZ types get a null terminating character added. We remove that here.
        # ref: https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types
        return policy_reg_data.decode("utf-16-le").rstrip("\x00")
    elif policy_reg_type == REG_DWORD:
        return unpack("i", policy_reg_data)[0]
    elif policy_reg_type == REG_DWORD_BIG_ENDIAN:
        return unpack(">i", policy_reg_data)[0]
    elif policy_reg_type == REG_QWORD:
        return unpack("q", policy_reg_data)[0]
    elif policy_reg_type == REG_BINARY:
        return policy_reg_data
