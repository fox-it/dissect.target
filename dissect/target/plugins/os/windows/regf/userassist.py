import codecs

from dissect import cstruct
from dissect.util.ts import wintimestamp

from flow.record.fieldtypes import uri

from dissect.target.exceptions import RegistryValueNotFoundError, UnsupportedPluginError
from dissect.target.helpers.shell_folder_ids import DESCRIPTIONS
from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.descriptor_extensions import (
    UserRecordDescriptorExtension,
    RegistryRecordDescriptorExtension,
)


userassist_def = """
struct VERSION5_ENTRY {
    char padding[4];
    uint32 number_of_executions;
    uint32 application_focus_count;
    uint32 application_focus_duration;
    char padding[44];
    uint64 timestamp;
    char padding[4];
};

struct VERSION3_ENTRY {
    uint32  session_id;
    uint32  number_of_executions;
    uint64  timestamp;
};
"""
c_userassist = cstruct.cstruct()
c_userassist.load(userassist_def)

UserAssistRecordDescriptor = create_extended_descriptor(
    [
        RegistryRecordDescriptorExtension,
        UserRecordDescriptorExtension,
    ]
)

UserAssistRecord = UserAssistRecordDescriptor(
    "windows/registry/userassist",
    [
        ("datetime", "ts"),
        ("uri", "path"),
        ("uint32", "number_of_executions"),
        ("uint32", "application_focus_count"),
        ("uint32", "application_focus_duration"),
    ],
)


class UserAssistPlugin(Plugin):
    """UserAssist plugin."""

    KEY = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"

    def check_compatible(self):
        if not len(list(self.target.registry.keys(self.KEY))) > 0:
            raise UnsupportedPluginError("No UserAssist key found")

    @export(record=UserAssistRecord)
    def userassist(self):
        """Return the UserAssist information for each user.

        The UserAssist registry keys contain information about programs that were recently executed on the system.
        Programs launch via the commandline are not registered within these registry keys.

        Sources:
            - https://www.magnetforensics.com/blog/artifact-profile-userassist/
            - https://www.aldeid.com/wiki/Windows-userassist-keys

        Yields UserAssistRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The entry timestamp.
            path (uri): The entry path.
            number_of_executions (int): The number of executions for this entry.
            application_focus_count (int): The number of focus acount for this entry.
            application_focus_duration (int): The duration of focus for this entry.
        """
        for reg in self.target.registry.keys(self.KEY):
            user = self.target.registry.get_user(reg)
            for subkey in reg.subkeys():
                try:
                    version = subkey.value("Version").value
                except RegistryValueNotFoundError:
                    version = None

                for count in subkey.subkeys():
                    for entry in count.values():
                        timestamp = 0
                        number_of_executions = None
                        application_focus_count = None
                        application_focus_duration = None

                        if version == 5 and len(entry.value) == 72:
                            data = c_userassist.VERSION5_ENTRY(entry.value)
                            timestamp = data.timestamp
                            number_of_executions = data.number_of_executions
                            application_focus_count = data.application_focus_count
                            application_focus_duration = data.application_focus_duration
                        elif version == 3 and len(entry.value) == 16:
                            data = c_userassist.VERSION3_ENTRY(entry.value)
                            timestamp = data.timestamp
                            number_of_executions = data.number_of_executions
                        elif version == 3 and len(entry.value) == 8:
                            # Unknown format?
                            pass
                        elif version is None and len(entry.value) == 16:
                            # Unknown format?
                            pass
                        else:
                            self.target.log.debug(
                                "Invalid userassist value of length %d: %r", len(entry.value), entry.value
                            )
                            continue

                        value = uri.from_windows(codecs.decode(entry.name, "rot-13"))
                        parts = value.split("/")

                        try:
                            value = value.replace(parts[0], DESCRIPTIONS[parts[0][1:-1].lower()])
                        except KeyError:
                            pass

                        yield UserAssistRecord(
                            ts=wintimestamp(timestamp),
                            path=value,
                            number_of_executions=number_of_executions,
                            application_focus_count=application_focus_count,
                            application_focus_duration=application_focus_duration,
                            _target=self.target,
                            _user=user,
                            _key=count,
                        )
