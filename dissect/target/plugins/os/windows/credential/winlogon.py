from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import RegistryValueNotFoundError, UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.credential.credential import WindowsCredentialPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

WinlogonRecord = TargetRecordDescriptor(
    "windows/credential/winlogon",
    [
        ("datetime", "ts_mtime"),
        ("string", "password"),
        ("path", "source"),
    ]
)


class WinlogonPlugin(WindowsCredentialPlugin):
    """Windows Winlogon plugin."""

    __namespace__ = "winlogon"

    WINLOGON_KEY = "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

    def check_compatible(self) -> None:
        if not self.target.has_function("registry"):
            raise UnsupportedPluginError("Windows registry plugin not available on target")

    @export(record=WinlogonRecord)
    def winlogon(self) -> Iterator[WinlogonRecord]:
        """Yield Windows Winlogon DefaultPassword strings.

        Extracts plaintext ``DefaultPassword`` values from the ``Winlogon`` registry.

        References:
            - https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon
        """

        for key in self.target.registry.keys(self.WINLOGON_KEY):
            try:
                yield WinlogonRecord(
                    ts_mtime=key.ts,
                    password=key.value("DefaultPassword").value,
                    source=self.WINLOGON_KEY,
                    _target=self.target,
                )
            except RegistryValueNotFoundError:  # noqa: PERF203
                pass
