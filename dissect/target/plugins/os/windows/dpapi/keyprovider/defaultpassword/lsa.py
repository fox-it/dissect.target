from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.dpapi.keyprovider.defaultpassword.defaultpassword import (
    DefaultPasswordKeyProvider,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class LSADefaultPasswordKeyProviderPlugin(DefaultPasswordKeyProvider):
    """Windows LSA DefaultPassword key provider plugin."""

    __namespace__ = "dpapi.keyprovider.defaultpassword.lsa"

    def check_compatible(self) -> None:
        if not self.target.has_function("lsa"):
            raise UnsupportedPluginError("LSA plugin not available on target")

    @export(output="yield")
    def keys(self) -> Iterator[tuple[str, str]]:
        """Yield Windows LSA DefaultPassword strings."""

        for record in self.target.credential.defaultpassword():
            yield self.__namespace__, record.default_password
