from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

CLSIDRecordDescriptor = create_extended_descriptor(
    [
        RegistryRecordDescriptorExtension,
        UserRecordDescriptorExtension,
    ]
)

CLSIDRecord = CLSIDRecordDescriptor(
    "windows/registry/clsid",
    [
        ("datetime", "ts"),
        ("string", "clsid"),
        ("string", "name"),
        ("string", "value"),
    ],
)


class CLSIDPlugin(Plugin):
    """Return all CLSID registry keys.

    A CLSID is a globally unique identifier that identifies a COM class object (program) situated in
    HKEY_CURRENT_USER\\Software\\Classes\\CLSID and HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID. Malware may make use
    of the CLSID system to launch themselves automatically or when certain conditions are triggered.

    Sources:
        - https://docs.microsoft.com/en-us/windows/win32/com/clsid-key-hklm
        - https://www.enigmasoftware.com/what-is-clsid-registry-key/
    """

    __namespace__ = "clsid"

    KEYS = {
        "user": "HKEY_CURRENT_USER\\Software\\Classes\\CLSID",
        "machine": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID",
    }

    def __init__(self, target):
        super().__init__(target)

    def check_compatible(self):
        if not len(list(self.target.registry.keys(list(self.KEYS.values())))) > 0:
            raise UnsupportedPluginError("No CLSID key found")

    def create_records(self, keys):
        """Iterate all CLSID keys from HKEY_CURRENT_USER\\Software\\Classes\\CLSID and
        HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID.

        Yields CLSIDRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): Last modified timestamp of the registry key.
            clsid (string): The CLSID key name.
            path (uri): The CLSID path value.
        """
        names = [
            "InprocServer32",
            "InprocServer",
            "LocalServer",
            "LocalServer32",
        ]

        for reg in self.target.registry.keys(keys):
            user = self.target.registry.get_user(reg)

            for subkey in reg.subkeys():
                try:
                    name = subkey.value("(default)").value
                except RegistryError:
                    name = None

                for entry in subkey.subkeys():
                    if entry.name in names:
                        try:
                            subkey_value = entry.value("(default)")
                        except RegistryError:
                            continue

                        yield CLSIDRecord(
                            ts=entry.ts,
                            clsid=subkey.name,
                            name=name,
                            value=subkey_value.value,
                            _target=self.target,
                            _user=user,
                            _key=entry,
                        )

    @export(record=CLSIDRecord)
    def user(self):
        """Return only the user CLSID registry keys."""
        yield from self.create_records(self.KEYS["user"])

    @export(record=CLSIDRecord)
    def machine(self):
        """Return only the machine CLSID registry keys."""
        yield from self.create_records(self.KEYS["machine"])
