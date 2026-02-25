from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import RegistryError, UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.generic import UserRegistryRecordDescriptor

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.helpers.regutil import RegistryKey
    from dissect.target.target import Target

SessionManagerRecord = UserRegistryRecordDescriptor(
    "windows/registry/sessionmanager",
    [
        ("datetime", "ts"),
        ("command", "command"),
        ("string", "source"),
    ],
)

class SessionManagerPlugin(Plugin):
    """Windows Session Manager (smss.exe) plugin."""

    KEYS = (
        ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager", "BootExecute"),
        ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager", "Execute"),
        ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager", "S0InitialCommand"),
        ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager", "SetupExecute"),
        ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\SubSystems", "windows"),
        ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\WOW", "cmdline"),
        ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Session Manager\\WOW", "wowcmdline"),
        ("HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control", "ServiceControlManagerExtension"),
    )

    def __init__(self, target: Target):
        super().__init__(target)

        self.keys: list[tuple[RegistryKey, str]] = []

        if self.target.has_function("registry"):
            self.keys = [(key, name_str) for key_str, name_str in self.KEYS for key in self.target.registry.keys(key_str)]

    def check_compatible(self) -> None:
        if not self.keys:
            raise UnsupportedPluginError("No session manager keys found on target")

    @export(record=SessionManagerRecord)
    def sessionmanager(self) -> Iterator[SessionManagerRecord]:
        """Return interesting Session Manager (Smss.exe) registry key entries.

        Session Manager (Smss.exe) is the first user-mode process started by the kernel and performs several tasks, such
        as creating environment variables, starts the Windows Logon Manager (winlogon.exe), etc. The BootExecute
        registry key holds the Windows tasks that cannot be performed when Windows is running, the Execute registry key
        should never be populated when Windows is installed. Can be leveraged as persistence mechanisms.

        References:
            - https://en.wikipedia.org/wiki/Session_Manager_Subsystem
            - https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2
        """

        for key, name in self.keys:
            user = self.target.registry.get_user(key)

            try:
                value = key.value(name).value
            except RegistryError:
                continue

            if not isinstance(value, list):
                value = [value]

            for item in value:

                # This is the default value of BootExecute in Windows.
                if item == "autocheck autochk *":
                    continue

                yield SessionManagerRecord(
                    ts=key.ts,
                    command=item,
                    source=f"HKLM\\{key.path}\\{name}",
                    _target=self.target,
                    _user=user,
                    _key=key,
                )
