from __future__ import annotations

from typing import TYPE_CHECKING, Final

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.regutil import RegistryKey
    from dissect.target.target import Target

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

    References:
        - https://docs.microsoft.com/en-us/windows/win32/com/clsid-key-hklm
        - https://www.enigmasoftware.com/what-is-clsid-registry-key/
    """

    __namespace__ = "clsid"
    USER_KEY = "HKEY_CURRENT_USER\\Software\\Classes\\CLSID"
    MACHINE_KEY = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID"

    def __init__(self, target: Target):
        super().__init__(target)

    def check_compatible(self) -> None:
        if not len(list(self.target.registry.keys((self.USER_KEY, self.MACHINE_KEY)))) > 0:
            raise UnsupportedPluginError("No CLSID key found")

    def create_records(self, key: RegistryKey) -> Iterator[CLSIDRecord]:
        """Iterates all CLSID keys from any CLSID registry
        Args:
            key: the ``RegistryKey`` to run on
        Yields:
            ``CLSIDRecords`` for each entry
        """

        names = [
            "InprocServer32",
            "InprocServer",
            "LocalServer",
            "LocalServer32",
        ]
        print(dir(self.target.registry))
        key = self.target.registry.key(key)
        for subkey in key.subkeys():
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
    def user(self) -> Iterator[CLSIDRecord]:
        """Return only the user CLSID registry keys."""
        yield from self.create_records(self.USER_KEY)

    @export(record=CLSIDRecord)
    def machine(self) -> Iterator[CLSIDRecord]:
        """Return only the machine CLSID registry keys."""
        yield from self.create_records(self.MACHINE_KEY)
