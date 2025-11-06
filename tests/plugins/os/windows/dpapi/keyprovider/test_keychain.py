from __future__ import annotations

import importlib
from typing import TYPE_CHECKING

from dissect.target.helpers import keychain
from dissect.target.plugins.os.windows.dpapi.dpapi import DPAPIPlugin
from dissect.target.plugins.os.windows.dpapi.keyprovider.keychain import KeychainKeyProviderPlugin

if TYPE_CHECKING:
    import pytest

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

    target_win.add_plugin(DPAPIPlugin, check_compatible=False)
    target_win.add_plugin(KeychainKeyProviderPlugin)

    keys = list(target_win.dpapi.keyprovider.keychain())

    assert keys == [
        ("dpapi.keyprovider.keychain", "password1"),
        ("dpapi.keyprovider.keychain", "password2"),
    ]


def test_env_keychain(monkeypatch: pytest.MonkeyPatch) -> None:
    # Set environment variable before module import
    monkeypatch.setenv("DISSECT_KEYCHAIN_VALUE", "envtestpass")
    # Reload keychain module to trigger environment variable registration
    importlib.reload(keychain)
    keys = keychain.get_all_keys()
    # There should be at least one key with value 'envtestpass' and is_wildcard True
    assert any(k.value == "envtestpass" and k.is_wildcard for k in keys)
