from typing import Iterator

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.dpapi.keyprovider.keyprovider import (
    KeyProviderPlugin,
)


class CredHistKeyProviderPlugin(KeyProviderPlugin):
    __namespace__ = "_dpapi_keyprovider_credhist"

    def check_compatible(self) -> None:
        if not self.target.has_function("credhist"):
            raise UnsupportedPluginError("CREDHIST plugin not available on target")

    @export(output="yield")
    def keys(self) -> Iterator[tuple[str, str]]:
        for credhist in self.target.credhist():
            if value := getattr(credhist, "sha1"):
                yield self.__namespace__, value
