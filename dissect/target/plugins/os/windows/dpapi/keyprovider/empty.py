from typing import Iterator

from dissect.target.plugin import export
from dissect.target.plugins.os.windows.dpapi.keyprovider.keyprovider import (
    KeyProviderPlugin,
)


class EmptyKeyProviderPlugin(KeyProviderPlugin):
    __namespace__ = "_dpapi_keyprovider_empty"

    def check_compatible(self) -> None:
        return

    @export(output="yield")
    def keys(self) -> Iterator[tuple[str, str]]:
        yield self.__namespace__, ""
