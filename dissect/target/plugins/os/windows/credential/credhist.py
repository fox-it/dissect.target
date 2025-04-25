from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, BinaryIO
from uuid import UUID

from dissect.cstruct import cstruct
from dissect.util.sid import read_sid

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import keychain
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.windows.dpapi.crypto import (
    CipherAlgorithm,
    HashAlgorithm,
    derive_password_hash,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.plugins.general.users import UserDetails
    from dissect.target.target import Target

log = logging.getLogger(__name__)


CredHistRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/credential/history",
    [
        ("string", "guid"),
        ("boolean", "decrypted"),
        ("string", "sha1"),
        ("string", "nt"),
    ],
)


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
    CHAR    encrypted[0];
};
"""

c_credhist = cstruct().load(credhist_def)


@dataclass
class CredHistEntry:
    version: int
    guid: str
    user_sid: str
    sha1: bytes | None
    nt: bytes | None
    hash_alg: HashAlgorithm = field(repr=False)
    cipher_alg: CipherAlgorithm = field(repr=False)
    raw: c_credhist.entry = field(repr=False)
    decrypted: bool = False

    def decrypt(self, password_hash: bytes) -> None:
        """Decrypt this CREDHIST entry using the provided password hash. Modifies ``CredHistEntry.sha1``
        and ``CredHistEntry.nt`` values.

        If the decrypted ``nt`` value is 16 bytes we assume the decryption was successful.

        Args:
            password_hash: Bytes of SHA1 password hash digest.

        Raises:
            ValueError: If the decryption seems to have failed.
        """
        data = self.cipher_alg.decrypt_with_hmac(
            data=self.raw.encrypted,
            key=derive_password_hash(password_hash, self.user_sid),
            iv=self.raw.pSalt,
            hash_algorithm=self.hash_alg,
            rounds=self.raw.dwPbkdf2IterationCount,
        )

        sha_size = self.raw.dwShaHashSize
        nt_size = self.raw.dwNtHashSize

        sha1 = data[:sha_size]
        nt = data[sha_size : sha_size + nt_size].rstrip(b"\x00")

        if len(nt) != 16:
            raise ValueError("Decrypting failed, invalid password hash?")

        self.decrypted = True
        self.sha1 = sha1
        self.nt = nt


class CredHistFile:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.entries = list(self._parse())

    def __repr__(self) -> str:
        return f"<CredHistFile fh='{self.fh}' entries={len(self.entries)}>"

    def _parse(self) -> Iterator[CredHistEntry]:
        self.fh.seek(0)
        try:
            while True:
                entry = c_credhist.entry(self.fh)

                # determine size of encrypted data and add to entry
                cipher_alg = CipherAlgorithm.from_id(entry.algCrypt)
                enc_size = entry.dwShaHashSize + entry.dwNtHashSize
                enc_size += enc_size % cipher_alg.block_length
                entry.encrypted = self.fh.read(enc_size)

                yield CredHistEntry(
                    version=entry.dwVersion,
                    guid=UUID(bytes_le=entry.guidLink),
                    user_sid=read_sid(entry.pSid) if entry.pSid else None,
                    hash_alg=HashAlgorithm.from_id(entry.algHash),
                    cipher_alg=cipher_alg,
                    sha1=None,
                    nt=None,
                    raw=entry,
                )
        except EOFError:
            # An empty CREDHIST file will be 24 bytes long and has dwNextLinkSize set to 0.
            pass

    def decrypt(self, password_hash: bytes) -> None:
        """Decrypt a CREDHIST chain using the provided password SHA1 hash."""

        for entry in reversed(self.entries):
            try:
                entry.decrypt(password_hash)
            except ValueError as e:
                log.warning("Could not decrypt entry %s with password %s", entry.guid, password_hash.hex())
                log.debug("", exc_info=e)
                continue
            password_hash = entry.sha1


class CredHistPlugin(Plugin):
    """Windows CREDHIST file parser.

    Windows XP:         ``C:\\Documents and Settings\\username\\Application Data\\Microsoft\\Protect\\CREDHIST``
    Windows 7 and up:   ``C:\\Users\\username\\AppData\\Roaming\\Microsoft\\Protect\\CREDHIST``

    Resources:
        - https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#41
    """

    def __init__(self, target: Target):
        super().__init__(target)
        self.files = list(self._find_files())

    def _find_files(self) -> Iterator[tuple[UserDetails, Path]]:
        hashes = set()
        for user_details in self.target.user_details.all_with_home():
            for path in ["AppData/Roaming/Microsoft/Protect/CREDHIST", "Application Data/Microsoft/Protect/CREDHIST"]:
                credhist_path = user_details.home_path.joinpath(path)
                if credhist_path.exists() and (hash := credhist_path.get().hash()) not in hashes:
                    hashes.add(hash)
                    yield user_details.user, credhist_path

    def check_compatible(self) -> None:
        if not self.files:
            raise UnsupportedPluginError("No CREDHIST files found on target.")

    @export(record=CredHistRecord)
    def credhist(self) -> Iterator[CredHistRecord]:
        """Yield and decrypt all Windows CREDHIST entries on the target."""

        passwords = keychain_passwords()

        if not passwords:
            self.target.log.warning("No passwords provided in keychain, cannot decrypt CREDHIST hashes")

        for user, path in self.files:
            credhist = CredHistFile(path.open("rb"))

            for password in passwords:
                credhist.decrypt(hashlib.sha1(password.encode("utf-16-le")).digest())

            for entry in credhist.entries:
                yield CredHistRecord(
                    guid=entry.guid,
                    decrypted=entry.decrypted,
                    sha1=entry.sha1.hex() if entry.sha1 else None,
                    nt=entry.nt.hex() if entry.nt else None,
                    _user=user,
                    _target=self.target,
                )


def keychain_passwords() -> set:
    passphrases = set()
    for key in keychain.get_keys_for_provider("user") + keychain.get_keys_without_provider():
        if key.key_type == keychain.KeyType.PASSPHRASE:
            passphrases.add(key.value)
    passphrases.add("")
    return passphrases
