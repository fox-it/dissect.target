from __future__ import annotations

import os
import subprocess
import sys
from typing import TYPE_CHECKING

from dissect.target.helpers import keychain
from dissect.target.plugins.os.windows.dpapi.dpapi import DPAPIPlugin
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

    target_win.add_plugin(DPAPIPlugin, check_compatible=False)
    target_win.add_plugin(KeychainKeyProviderPlugin)

    keys = list(target_win.dpapi.keyprovider.keychain())

    assert keys == [
        ("dpapi.keyprovider.keychain", "password1"),
        ("dpapi.keyprovider.keychain", "password2"),
    ]


def test_env_keychain() -> None:
    """test if we can read keychain items from environment variables."""

    # Create a new environment
    env = os.environ.copy()
    env["DISSECT_KEYCHAIN_VALUE"] = "envtestpass"

    # Runs the env test in a separate, isolated process to prevent env var and module cache pollution.
    script = (
        "from dissect.target.helpers import keychain; "
        "keys = keychain.get_all_keys(); "
        "assert any(k.value == 'envtestpass' and k.is_wildcard for k in keys)"
    )

    # sys.executable ensures we use the same Python interpreter
    result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True)

    assert result.returncode == 0, f"Subprocess test failed: {result.stderr}"
