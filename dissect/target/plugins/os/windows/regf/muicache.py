from flow.record.fieldtypes import uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    UserRecordDescriptorExtension,
    RegistryRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
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
        "HKCU\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
        # FIXME subkeys, XP, etc
        # "HKCU\\Software\\Classes\\Local Settings\\MuiCache",
        # "HKCU\\Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache",
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

        Yields MuicacheRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            index (varint): The index of the entry.
            name (string): The value name.
            value (string): The value.
            path (uri): The executable path.
        """
        for key in self.KEYS:
            for r in self.target.registry.keys(key):
                user = self.target.registry.get_user(r)
                for index, entry in enumerate(r.values()):
                    try:
                        path, name = entry.name.rsplit(".", 1)
                        path = uri.from_windows(path)
                        yield MuicacheRecord(
                            index=index,
                            name=name,
                            value=entry.value,
                            path=str(path),
                            _target=self.target,
                            _key=r,
                            _user=user,
                        )
                    except ValueError:
                        continue
                    except Exception:
                        self.target.log.exception("Exception while parsing muicache")
                        continue
