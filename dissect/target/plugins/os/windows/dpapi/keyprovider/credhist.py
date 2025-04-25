from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.dpapi.keyprovider.keyprovider import (
    KeyProviderPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class CredHistKeyProviderPlugin(KeyProviderPlugin):
    """Windows CREDHIST SHA1-hash key provider plugin."""

    __namespace__ = "_dpapi_keyprovider_credhist"

    def check_compatible(self) -> None:
        if not self.target.has_function("credhist"):
            raise UnsupportedPluginError("CREDHIST plugin not available on target")

    @export(output="yield")
    def keys(self) -> Iterator[tuple[str, str]]:
        """Yield Windows CREDHIST SHA1 hashes."""
        for credhist in self.target.credhist():
            if value := credhist.sha1:
                yield self.__namespace__, value
