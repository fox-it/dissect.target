from typing import Generator

from flow.record.fieldtypes import uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    UserRecordDescriptorExtension,
    RegistryRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.regutil import RegistryKey
from dissect.target.plugin import Plugin, export

MuicacheRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/registry/muicache",
    [
        ("varint", "index"),
        ("string", "name"),
        ("string", "value"),
        ("uri", "path"),
    ],
)


class MuicachePlugin(Plugin):
    """Plugin that iterates various MUIcache locations."""

    KEYS = [
        "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",  # NT >= 6.0
        "HKCU\\Software\\Classes\\Local Settings\\MuiCache",  # NT >= 6.0
        "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache",  # NT < 6.0
    ]

    FIELD_NAMES = [
        "FriendlyAppName",
        "ApplicationCompany",
    ]

    def check_compatible(self):
        if not len(list(self.target.registry.keys(self.KEYS))) > 0:
            raise UnsupportedPluginError("No registry muicache key found")

    @export(record=MuicacheRecord)
    def muicache(self) -> MuicacheRecord:
        """Iterate various MUIcache key locations.

        The MUIcache registry key stores information about executed GUI-based programs. The key is part of
        the Multilingual User Interface service in Windows. MUIcache references the file description contained within
        the executable's resource section and populates that value.

        Sources:
            - https://www.magnetforensics.com/blog/forensic-analysis-of-muicache-files-in-windows/
            - https://forensafe.com/blogs/muicache.html

        Yields MuicacheRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            index (varint): The index of the entry.
            name (string): The value name.
            value (string): The value.
            path (uri): The executable path.
        """
        for reg_path in self.KEYS:
            for key in self.target.registry.keys(reg_path):
                if len(key.subkeys()):
                    for subkey in key.subkeys():
                        for item in subkey.subkeys():
                            yield from self._get_records(item)
                else:
                    yield from self._get_records(key)

    def _get_records(self, key: RegistryKey) -> Generator[MuicacheRecord, None, None]:
        for index, entry in enumerate(key.values()):
            user = self.target.registry.get_user(key)
            try:
                if entry.name.endswith(tuple(self.FIELD_NAMES)):
                    path, name = entry.name.rsplit(".", 1)
                else:
                    name = None
                    path = entry.name.rsplit(",-", 1)[0]

                value = entry.value
                path = uri.from_windows(path)

                # Filter on the type of the registry value
                if type(value) is bytes:
                    continue

                yield MuicacheRecord(
                    index=index,
                    name=name,
                    value=value,
                    path=path,
                    _target=self.target,
                    _key=key,
                    _user=user,
                )
            except ValueError:
                continue
            except Exception:
                self.target.log.exception("Exception while parsing muicache")
                continue
