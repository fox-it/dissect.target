from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.helpers import keychain
from dissect.target.plugins.os.windows.dpapi.keyprovider.keychain import KeychainKeyProviderPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target


def test_dpapi_keyprovider_keychain(target_win: Target) -> None:
    """test if we yield provided keychain items correctly."""
    keychain.register_key(
        key_type=keychain.KeyType.PASSPHRASE,
        value="password1",
        identifier=None,
        provider="user",
    )
    keychain.register_key(
        key_type=keychain.KeyType.PASSPHRASE,
        value="password2",
        identifier=None,
        provider=None,
    )

    target_win.add_plugin(KeychainKeyProviderPlugin)

    keys = list(target_win._dpapi_keyprovider_keychain())

    assert keys == [
        ("_dpapi_keyprovider_keychain", "password1"),
        ("_dpapi_keyprovider_keychain", "password2"),
    ]
