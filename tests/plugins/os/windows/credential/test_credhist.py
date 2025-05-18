from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from Crypto.Hash import MD4

from dissect.target.helpers import keychain
from dissect.target.plugins.os.windows.credential.credhist import (
    CredHistFile,
    CredHistPlugin,
)
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_credhist() -> None:
    """The provided CREDHIST file has the following password history: ``user -> password -> password3``.
    The current password of the user is ``password4``.
    """
    with absolute_path("_data/plugins/os/windows/credhist/CREDHIST").open("rb") as fh:
        ch = CredHistFile(fh)

    assert len(ch.entries) == 3

    for entry in ch.entries:
        assert ch.entries[0].version == 1
        assert entry.user_sid.upper() == "S-1-5-21-1342509979-482553916-3960431919-1000"

    ch.decrypt(password_hash=sha1("password4"))

    assert str(ch.entries[0].guid) == "99ec7176-d16c-41bd-9c94-d3a4c5b94232"
    assert ch.entries[0].sha1 == sha1("user")
    assert ch.entries[0].nt == md4("user")

    assert str(ch.entries[1].guid) == "120a3a30-309c-4fda-bfb8-06f44ea93cb2"
    assert ch.entries[1].sha1 == sha1("password")
    assert ch.entries[1].nt == md4("password")

    assert str(ch.entries[2].guid) == "5657891f-28dd-4f69-baba-95e44bcd178a"
    assert ch.entries[2].sha1 == sha1("password3")
    assert ch.entries[2].nt == md4("password3")


def test_credhist_partial(target_win_users: Target, fs_win: VirtualFilesystem) -> None:
    """Test if we can get a partially decrypted CREDHIST chain if we know an intermediate password.

    The latest entry is encrypted with 'password4' but we provide 'password3'. The plugin
    should decrypt every entry except the latest entry.
    """
    fs_win.map_file(
        "Users/John/AppData/Roaming/Microsoft/Protect/CREDHIST",
        absolute_path("_data/plugins/os/windows/credhist/CREDHIST"),
    )
    target_win_users.add_plugin(CredHistPlugin)

    keychain.KEYCHAIN.clear()
    keychain.register_key(
        key_type=keychain.KeyType.PASSPHRASE,
        value="password3",
        identifier=None,
        provider="user",
    )

    results = list(target_win_users.credhist())
    assert len(results) == 3
    assert [result.nt for result in results] == [md4("user").hex(), md4("password").hex(), None]


def md4(plaintext: str) -> str:
    return MD4.new(plaintext.encode("utf-16-le")).digest()


def sha1(plaintext: str) -> str:
    return hashlib.sha1(plaintext.encode("utf-16-le")).digest()
