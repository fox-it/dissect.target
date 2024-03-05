from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path
from typing import Iterator, Optional
from uuid import UUID

from dissect.cstruct import cstruct
from dissect.util.sid import read_sid

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import InternalPlugin
from dissect.target.plugins.os.windows.dpapi.crypto import (
    CipherAlgorithm,
    HashAlgorithm,
    derive_password_hash,
)
from dissect.target.target import Target

credhist_def = """
struct entry {
    DWORD   dwVersion;
    CHAR    guidLink[16];
    DWORD   dwNextLinkSize;
    DWORD   dwCredLinkType;
    DWORD   algHash;                    // ALG_ID
    DWORD   dwPbkdf2IterationCount;
    DWORD   dwSidSize;
    DWORD   algCrypt;                   // ALG_ID
    DWORD   dwShaHashSize;
    DWORD   dwNtHashSize;
    CHAR    pSalt[16];
    CHAR    pSid[dwSidSize];
    CHAR    encrypted[(dwShaHashSize + dwNtHashSize) + (dwShaHashSize + dwNtHashSize) % 16];
};
"""

c_credhist = cstruct()
c_credhist.load(credhist_def)


@dataclass
class CredHistEntry:
    version: int
    guid: str
    user_sid: str
    hash_alg: any = field(repr=False)
    cipher_alg: any = field(repr=False)
    hash_sha: Optional[str]
    hash_nt: Optional[str]
    raw: c_credhist.entry = field(repr=False)

    def decrypt(self, password_hash: bytes) -> None:
        data = self.cipher_alg.decrypt_with_hmac(
            data=self.raw.encrypted,
            key=derive_password_hash(password_hash, self.user_sid),
            iv=self.raw.pSalt,
            hash_algorithm=self.hash_alg,
            rounds=self.raw.dwPbkdf2IterationCount,
        )

        sha_size = self.raw.dwShaHashSize
        nt_size = self.raw.dwNtHashSize

        self.hash_sha = data[:sha_size].hex()
        self.hash_nt = data[sha_size : sha_size + nt_size].rstrip(b"\x00").hex()


class CredHistFile:
    def __init__(self, fh: BytesIO) -> None:
        self.fh = fh
        self.entries = list(self._parse())

    def __repr__(self) -> str:
        return f"<CredHistFile path='{self.fh.name}'>"

    def _parse(self) -> Iterator[CredHistEntry]:
        self.fh.seek(0)
        try:
            while True:
                entry = c_credhist.entry(self.fh)
                yield CredHistEntry(
                    version=entry.dwVersion,
                    guid=str(UUID(bytes_le=entry.guidLink)),
                    user_sid=read_sid(entry.pSid),
                    hash_alg=HashAlgorithm.from_id(entry.algHash),
                    cipher_alg=CipherAlgorithm.from_id(entry.algCrypt),
                    hash_sha=None,
                    hash_nt=None,
                    raw=entry,
                )
        except EOFError:
            pass

    def decrypt(self, password_hash: bytes | str) -> None:
        """Decrypt a CREDHIST chain using the provided password hash (SHA1 or MD4)."""

        if isinstance(password_hash, str):
            password_hash = bytes.fromhex(password_hash)

        for entry in reversed(self.entries):
            entry.decrypt(password_hash)
            password_hash = bytes.fromhex(entry.hash_sha)


class CredHistPlugin(InternalPlugin):
    """Windows CREDHIST file parser.

    Windows XP:         ``C:/Documents and Settings/username/Application Data/Microsoft/Protect/CREDHIST``
    Windows 7 and up:   ``C:/Users/username/AppData/Roaming/Microsoft/Protect/CREDHIST``

    Resources:
        - https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#41
    """

    __namespace__ = "credhist"

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = list(self._find_files())

    def _find_files(self) -> Iterator[Path]:
        for user in self.target.user_details.all_with_home():
            for path in ["AppData/Roaming/Microsoft/Protect/CREDHIST", "Application Data/Microsoft/Protect/CREDHIST"]:
                if (credhist_path := user.home_path.joinpath(path)).exists():
                    yield credhist_path

    def check_compatible(self) -> None:
        if not any(self.files):
            raise UnsupportedPluginError("No CREDHIST files found on target")

    def all(self) -> Iterator[CredHistFile]:
        for path in self.files:
            yield CredHistFile(path.open("rb"))

