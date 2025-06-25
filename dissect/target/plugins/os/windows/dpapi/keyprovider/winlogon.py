from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import RegistryValueNotFoundError, UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.dpapi.keyprovider.keyprovider import KeyProviderPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator


class WinlogonDefaultPasswordKeyProviderPlugin(KeyProviderPlugin):
    """Windows Winlogon DefaultPassword key provider plugin."""

    __namespace__ = "_dpapi_keyprovider_winlogon_defaultpassword"

    def check_compatible(self) -> None:
        if not self.target.has_function("registry"):
            raise UnsupportedPluginError("Windows registry plugin not available on target")

    @export(output="yield")
    def keys(self) -> Iterator[tuple[str, str]]:
        """Yield Windows Winlogon DefaultPassword strings.

        Extracts plaintext ``DefaultPassword`` values from the ``Winlogon`` registry.

        Resources:
            - https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon
        """

        for key in self.target.registry.keys("HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"):
            try:
                yield self.__namespace__, key.value("DefaultPassword").value
            except RegistryValueNotFoundError:  # noqa: PERF203
                pass
