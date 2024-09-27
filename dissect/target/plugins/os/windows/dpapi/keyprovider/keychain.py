from typing import Iterator

from dissect.target.helpers import keychain
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.dpapi.keyprovider.keyprovider import (
    KeyProviderPlugin,
)


class KeychainKeyProviderPlugin(KeyProviderPlugin):
    __namespace__ = "_dpapi_keyprovider_keychain"

    def check_compatible(self) -> None:
        return

    @export(output="yield")
    def keys(self) -> Iterator[tuple[str, str]]:
        for key in keychain.get_keys_for_provider("user") + keychain.get_keys_without_provider():
            if key.key_type == keychain.KeyType.PASSPHRASE:
                yield self.__namespace__, key.value
