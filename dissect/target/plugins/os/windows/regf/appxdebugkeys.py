from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.regutil import RegistryKey
from dissect.target.plugin import Plugin, export

AppxDebugKeyRecord = create_extended_descriptor([RegistryRecordDescriptorExtension, UserRecordDescriptorExtension])(
    "windows/registry/appxdebug/key",
    [
        ("datetime", "ts"),
        ("string", "name"),
        ("string", "debug_info"),
    ],
)


class AppxDebugKeysPlugin(Plugin):
    """Plugin that iterates various AppX debug key locations"""

    REGKEY_GLOBS = [
        # The first glob are the AppX package names
        # The "(Default Value)" contains the debugger command
        "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\PackagedAppXDebug\\*",
        # The first glob are the AppX package names
        # The second glob are the AppX package components
        # The "DebugPath" value contains the debugger command
        "HKEY_CURRENT_USER\\Software\\Classes\\ActivatableClasses\\Package\\*\\DebugInformation\\*",
    ]

    def _walk(self, key: RegistryKey) -> Iterator[AppxDebugKeyRecord]:
        user = self.target.registry.get_user(key)

        values = key.values()
        subkeys = key.subkeys()

        if not values and not subkeys:
            yield AppxDebugKeyRecord(
                ts=key.ts,
                name=None,
                debug_info=None,
                _target=self.target,
                _key=key,
                _user=user,
            )

        else:
            for value in values:
                yield AppxDebugKeyRecord(
                    ts=key.ts,
                    name=value.name,
                    debug_info=value.value,
                    _target=self.target,
                    _key=key,
                    _user=user,
                )

            for subkey in subkeys:
                yield from self._walk(subkey)

    def _debug_keys(self) -> Iterator[AppxDebugKeyRecord]:
        for regkey_glob in self.REGKEY_GLOBS:
            for key in self.target.registry.glob_ext(regkey_glob):
                yield from self._walk(key)

    def check_compatible(self) -> None:
        try:
            next(self._debug_keys())
        except StopIteration:
            raise UnsupportedPluginError("No registry AppX debug key found")

    @export(record=AppxDebugKeyRecord)
    def appxdebugkeys(self) -> Iterator[AppxDebugKeyRecord]:
        """Iterate various AppX debug key locations. See source for all locations.

        AppX debug keys are registry keys that attach a debugger executable to
        Universal Windows Platform Apps (AppX). This debugger is executed when
        the program is launched and is often leveraged as a persistence
        mechanism.

        References:
            - https://oddvar.moe/2018/09/06/persistence-using-universal-windows-platform-apps-appx/

        Yields AppXDebugKeyRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The registry key last modified timestamp.
            name (string): The AppX debug key name.
            debug_info (string): The AppX debug info.
            regf_hive_path (string): The hive file that contains the registry key.
            regf_key_path (string): The key's full path in the registry.
            username (string): The name of the user this key belongs to.
            user_id (string): The id of the user this key belongs to.
            user_group (string): The group of the user this key belongs to.
            user_home (string): The home directory of the user this key belongs to.
        """

        yield from self._debug_keys()
