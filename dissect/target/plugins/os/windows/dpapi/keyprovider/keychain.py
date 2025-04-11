from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers import keychain
from dissect.target.plugin import export
from dissect.target.plugins.os.windows.dpapi.keyprovider.keyprovider import (
    KeyProviderPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


class KeychainKeyProviderPlugin(KeyProviderPlugin):
    """Keychain key provider plugin."""

    __namespace__ = "_dpapi_keyprovider_keychain"

    def check_compatible(self) -> None:
        return

    @export(output="yield")
    def keys(self) -> Iterator[tuple[str, str]]:
        """Yield keychain passphrases."""
        for key in keychain.get_keys_for_provider("user") + keychain.get_keys_without_provider():
            if key.key_type == keychain.KeyType.PASSPHRASE:
                yield self.__namespace__, key.value
