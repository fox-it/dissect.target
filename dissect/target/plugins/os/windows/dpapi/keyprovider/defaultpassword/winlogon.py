from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.dpapi.keyprovider.defaultpassword.defaultpassword import (
    DefaultPasswordKeyProvider,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class WinlogonDefaultPasswordKeyProviderPlugin(DefaultPasswordKeyProvider):
    """Windows Winlogon DefaultPassword key provider plugin."""

    __namespace__ = "dpapi.keyprovider.defaultpassword.winlogon"

    def check_compatible(self) -> None:
        if not self.target.has_function("registry"):
            raise UnsupportedPluginError("Windows registry plugin not available on target")

    @export(output="yield")
    def keys(self) -> Iterator[tuple[str, str]]:
        """Yield Windows Winlogon DefaultPassword strings."""

        for record in self.target.credential.winlogon():
            yield self.__namespace__, record.password
