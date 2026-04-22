from __future__ import annotations

from typing import TYPE_CHECKING

from Crypto.Cipher import PKCS1_v1_5

from dissect.target.plugins.os.windows.ngc.util import read_dat

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.plugins.os.windows.cng.key import CNGKey
    from dissect.target.plugins.os.windows.ngc.provider import NGCProvider


class NGCProtector:
    """Windows NGC Protector implementation."""

    def __init__(self, provider: NGCProvider, path: Path) -> None:
        self.provider = provider
        self.path = path

        self.name = read_dat(path.joinpath("1.dat"))
        self.key_name = read_dat(path.joinpath("2.dat"))
        self.ciphertext = path.joinpath("15.dat").read_bytes()
        self.plaintext = None
        self.decrypted = False

    def __repr__(self) -> str:
        return f"<NGCProtector name={self.name} key={self.key_name} decrypted={self.decrypted} path={self.path}>"

    def decrypt(self, key: CNGKey) -> None:
        """Decrypt this NGC protector using the provided :class:`CNGKey`."""
        if self.decrypted:
            return

        if key.name != self.key_name:
            raise ValueError(f"Provided CNGKey ({key.name}) is not {self.key_name}")

        if not (rsa := key.get_key("Private Key", type="RSA")):
            raise ValueError("Provided CNGKey does not have a private key")

        cipher = PKCS1_v1_5.new(rsa.key)
        self.plaintext = cipher.decrypt(self.ciphertext, None)
        self.decrypted = bool(self.plaintext)
