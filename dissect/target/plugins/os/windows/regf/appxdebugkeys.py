from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.descriptor_extensions import (
    RegistryRecordDescriptorExtension,
    UserRecordDescriptorExtension,
)
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.helpers.regutil import RegistryKey, RegistryKeyNotFoundError
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
    """Plugin that iterates various AppX debug key locations."""

    REGKEY_PACKAGED_APPX_DEBUG = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\PackagedAppXDebug"
    REGKEY_ACTIVATABLE_CLASS_PACKAGE = "HKEY_CURRENT_USER\\Software\\Classes\\ActivatableClasses\\Package"
    DEBUG_INFORMATION_KEY_NAME = "DebugInformation"

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

    def _packaged_appx_debug_keys(self) -> Iterator[AppxDebugKeyRecord]:
        # "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\PackagedAppXDebug\\*",
        # the * are AppX package names
        # value_name="(Default Value)", value_data=<debugger cmd>
        for key in self.target.registry.keys(self.REGKEY_PACKAGED_APPX_DEBUG):
            for subkey in key.subkeys():
                yield from self._walk(subkey)

    def _activatable_classes_debug_keys(self) -> Iterator[AppxDebugKeyRecord]:
        # "HKEY_CURRENT_USER\\Software\\Classes\\ActivatableClasses\Package\\*\\DebugInformation\\*",
        # the 1st * are AppX package names
        # the 2nd * look like AppX package components
        # value_name="DebugPath", value_data=<debugger cmd>
        for key in self.target.registry.keys(self.REGKEY_ACTIVATABLE_CLASS_PACKAGE):
            for subkey in key.subkeys():
                try:
                    debug_key = subkey.subkey(self.DEBUG_INFORMATION_KEY_NAME)
                except RegistryKeyNotFoundError:
                    pass
                else:
                    yield from self._walk(debug_key)

    def check_compatible(self) -> None:
        packaged_keys = True
        activatable_keys = True
        try:
            next(self._packaged_appx_debug_keys())
        except StopIteration:
            packaged_keys = False

        try:
            next(self._activatable_classes_debug_keys())
        except StopIteration:
            activatable_keys = False

        if not packaged_keys and not activatable_keys:
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

        yield from self._packaged_appx_debug_keys()
        yield from self._activatable_classes_debug_keys()
