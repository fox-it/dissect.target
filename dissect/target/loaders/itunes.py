from __future__ import annotations

import hashlib
import plistlib
import struct
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator, Optional, Union

from dissect.sql import sqlite3
from dissect.util.plist import NSKeyedArchiver

from dissect.target.exceptions import LoaderError
from dissect.target.filesystems.itunes import ITunesFilesystem
from dissect.target.helpers import fsutil, keychain
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from dissect.target.target import Target

try:
    import _pystandalone

    HAS_PYSTANDALONE = True
except ImportError:
    HAS_PYSTANDALONE = False

try:
    from Crypto.Cipher import AES

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False


DOMAIN_TRANSLATION = {
    "AppDomain": "/private/var/mobile/Containers/Data/Application",
    "AppDomainGroup": "/private/var/mobile/Containers/Shared/AppGroup",
    "AppDomainPlugin": "/private/var/mobile/Containers/Data/PluginKitPlugin",
    "SysContainerDomain": "/private/var/containers/Data/System",
    "SysSharedContainerDomain": "/private/var/containers/Shared/SystemGroup",
    "KeychainDomain": "/private/var/Keychains",
    "CameraRollDomain": "/private/var/mobile",
    "MobileDeviceDomain": "/private/var/MobileDevice",
    "WirelessDomain": "/private/var/wireless",
    "InstallDomain": "/private/var/installd",
    "KeyboardDomain": "/private/var/mobile",
    "HomeDomain": "/private/var/mobile",
    "SystemPreferencesDomain": "/private/var/preferences",
    "DatabaseDomain": "/private/var/db",
    "TonesDomain": "/private/var/mobile",
    "RootDomain": "/private/var/root",
    "BooksDomain": "/private/var/mobile/Media/Books",
    "ManagedPreferencesDomain": "/private/var/Managed Preferences",
    "HomeKitDomain": "/private/var/mobile",
    "MediaDomain": "/private/var/mobile",
    "HealthDomain": "/private/var/mobile/Library",
}


class ITunesLoader(Loader):
    """Load iTunes backup files.

    References:
        - https://support.apple.com/en-us/HT204215
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path)

        self.backup = ITunesBackup(self.path)

        if self.backup.encrypted:
            for key in keychain.get_keys_for_provider("itunes") + keychain.get_keys_without_provider():
                if key.key_type == keychain.KeyType.PASSPHRASE:
                    if key.identifier == self.backup.identifier:
                        self.backup.open(key.value)
                        break
                    elif not key.identifier:
                        try:
                            self.backup.open(key.value)
                            break
                        except ValueError:
                            continue
            else:
                raise LoaderError(f"No password for encrypted iTunes backup: {self.path}")
        else:
            self.backup.open()

    @staticmethod
    def detect(path: Path) -> bool:
        return path.is_dir() and path.joinpath("Manifest.plist").exists()

    def map(self, target: Target) -> None:
        target.filesystems.add(ITunesFilesystem(self.backup))


class ITunesBackup:
    """Parse a directory as an iTunes backup directory."""

    def __init__(self, root: Path):
        self.root = root
        self.manifest = plistlib.load(self.root.joinpath("Manifest.plist").open("rb"))
        self.info = plistlib.load(self.root.joinpath("Info.plist").open("rb"))
        self.status = plistlib.load(self.root.joinpath("Status.plist").open("rb"))

        self.encrypted = self.manifest["IsEncrypted"]

        self.kek = None
        self.key_bag = None

        if self.encrypted:
            self.key_bag = KeyBag(self.manifest["BackupKeyBag"])

        self.manifest_db = None

    @property
    def identifier(self) -> str:
        return self.info["Unique Identifier"]

    def open(self, password: Optional[str] = None, kek: Optional[bytes] = None) -> None:
        """Open the backup.

        Opens the Manifest.db file. Requires a password if the backup is encrypted.

        Args:
            password: Optional backup password if the backup is encrypted.
            kek: Optional kek if the password is unknown, but the derived key is known.
        """
        if self.encrypted:
            if not password and not kek:
                raise ValueError("Either password or kek is required for encrypted backups")

            self.kek = kek
            if not self.kek:
                self.kek = self.derive_key(password)

            self.key_bag.unlock_with_passcode_key(self.kek)

        self.manifest_db = self._open_manifest_db()

    def _open_manifest_db(self) -> sqlite3.SQLite3:
        path = self.root.joinpath("Manifest.db")
        if not self.encrypted or self.manifest["Lockdown"]["ProductVersion"] < "10.2":
            fh = path.open("rb")
        else:
            key = self.key_bag.unwrap(self.manifest["ManifestKey"])
            fh = BytesIO(aes_decrypt(path.read_bytes(), key))

        return sqlite3.SQLite3(fh)

    def derive_key(self, password: str) -> bytes:
        """Derive the key bag encryption key from a given password."""
        password = password.encode()
        if self.manifest["Lockdown"]["ProductVersion"] < "10.2":
            first_round = password
        else:
            first_round = hashlib.pbkdf2_hmac(
                "sha256", password, self.key_bag.attr["DPSL"], self.key_bag.attr["DPIC"], 32
            )

        return hashlib.pbkdf2_hmac("sha1", first_round, self.key_bag.attr["SALT"], self.key_bag.attr["ITER"], 32)

    def files(self) -> Iterator[FileInfo]:
        """Iterate all the files in this backup."""
        for row in self.manifest_db.table("Files").rows():
            yield FileInfo(self, row.fileID, row.domain, row.relativePath, row.flags, row.file)


class FileInfo:
    """Utility class that represents a file in a iTunes backup."""

    def __init__(
        self, backup: ITunesBackup, file_id: str, domain: str, relative_path: str, flags: int, metadata: bytes
    ):
        self.backup = backup
        self.file_id = file_id
        self.domain = domain
        self.relative_path = relative_path
        self.flags = flags
        self.metadata = NSKeyedArchiver(BytesIO(metadata))["root"]

        self.translated_path = translate_file_path(self.domain, self.relative_path)

    def __repr__(self) -> str:
        return f"<FileInfo {self.translated_path}>"

    @property
    def mode(self) -> int:
        return self.metadata["Mode"]

    @property
    def size(self) -> int:
        return self.metadata["Size"]

    @property
    def encryption_key(self) -> Optional[str]:
        return self.metadata.get("EncryptionKey")

    def get(self) -> Path:
        """Return a Path object to the underlying file."""
        return self.backup.root / self.file_id[:2] / self.file_id

    def create_cipher(self):
        """Return a new AES cipher for this file."""
        if not self.backup.encrypted:
            raise TypeError("File is not encrypted")

        if not self.encryption_key:
            raise ValueError("File has no encryption key")

        key = self.backup.key_bag.unwrap(self.encryption_key)
        return _create_cipher(key)


class KeyBag:
    """Parse and implements a simple key bag."""

    def __init__(self, buf: bytes):
        self.attr, self.keys = parse_key_bag(buf)

    def unlock_with_passcode_key(self, key: bytes) -> None:
        """Attempt to unlock the passcode protected keys in this key bag with the given decryption key."""
        for class_key in self.keys.values():
            if class_key.wrap_type != ClassKey.WRAP_PASSCODE:
                continue

            class_key.unwrap(key)

    def unwrap(self, key: bytes) -> bytes:
        """Unwrap a given key.

        Wrapped keys are prefixed with a 32bit protection class.
        """
        protection_class, wrapped_key = struct.unpack("<I", key[:4])[0], key[4:]
        return aes_unwrap_key(self.keys[protection_class].key, wrapped_key)


class ClassKey:
    """Represent a class key that is stored in a key bag."""

    WRAP_PASSCODE = 2

    def __init__(
        self,
        uuid: bytes,
        protection_class: int,
        wrap_type: int,
        key_type: int,
        wrapped_key: bytes,
        public_key: Optional[bytes] = None,
    ):
        self.uuid = uuid
        self.protection_class = protection_class
        self.wrap_type = wrap_type
        self.key_type = key_type
        self.wrapped_key = wrapped_key
        self.public_key = public_key

        self.key = None

    @classmethod
    def from_bag_dict(cls, data: dict[str, Union[bytes, int]]) -> ClassKey:
        return cls(
            data.get("UUID"),
            data.get("CLAS"),
            data.get("WRAP"),
            data.get("KTYP"),
            data.get("WPKY"),
            data.get("PBKY"),
        )

    @property
    def unwrapped(self) -> bool:
        """Return whether this key is already unwrapped."""
        return self.key is not None

    def unwrap(self, kek: bytes) -> None:
        """Attempt to unwrap this key."""
        self.key = aes_unwrap_key(kek, self.wrapped_key)


def translate_file_path(domain: str, relative_path: str) -> str:
    """Translate a domain and relative path (as stored in iTunes backups) to an absolute path on an iOS device."""
    try:
        domain, _, package_name = domain.partition("-")
    except ValueError:
        package_name = ""

    domain_path = fsutil.join(DOMAIN_TRANSLATION.get(domain, domain), package_name)
    return fsutil.join(domain_path, relative_path)


def parse_key_bag(buf: bytes) -> tuple[dict[str, bytes, int], dict[str, ClassKey]]:
    """Parse the BackupKeyBag buffer. Simple TLV format."""
    attr = {}
    class_keys = {}
    current_class_key = {}

    fh = BytesIO(buf)
    while True:
        header = fh.read(8)
        if len(header) != 8:
            break

        key, length = struct.unpack(">4sI", header)

        key = key.decode()
        value = fh.read(length)
        if length == 4:
            value = struct.unpack(">I", value)[0]

        # The order here is important
        # There are some fields which qualify as a "header" of the key bag, which we name attributes
        # Among these "header" fields is a UUID field that acts as the UUID for the key bag
        # After this header comes a list of class keys. Each class key starts with a UUID
        # We only want to start parsing class keys from the second UUID we encounter, because
        # the first UUID we encounter will be from the "header"
        if key == "UUID" and "UUID" in attr:
            if current_class_key:
                ckey = ClassKey.from_bag_dict(current_class_key)
                class_keys[ckey.protection_class] = ckey

            current_class_key = {
                "UUID": value,
            }
        elif current_class_key and key in ("CLAS", "WRAP", "KTYP", "WPKY", "PKBY"):
            current_class_key[key] = value
        else:
            attr[key] = value

    if current_class_key:
        ckey = ClassKey.from_bag_dict(current_class_key)
        class_keys[ckey.protection_class] = ckey

    return attr, class_keys


def aes_decrypt(data: bytes, key: bytes, iv: bytes = b"\x00" * 16) -> bytes:
    """Helper function to easily decrypt some data with a default IV."""
    return _create_cipher(key, iv).decrypt(data)


def aes_unwrap_key(kek: bytes, wrapped: bytes, iv: int = 0xA6A6A6A6A6A6A6A6) -> bytes:
    """AES key unwrapping algorithm.

    Derived from https://github.com/kurtbrose/aes_keywrap/blob/master/aes_keywrap.py
    """
    QUAD = struct.Struct(">Q")

    n = len(wrapped) // 8 - 1

    # NOTE: R[0] is never accessed, left in for consistency with RFC indices
    R = [None] + [wrapped[i * 8 : i * 8 + 8] for i in range(1, n + 1)]
    A = QUAD.unpack(wrapped[:8])[0]

    decrypt = _create_cipher(kek, mode="ecb").decrypt

    for j in range(5, -1, -1):  # counting down
        for i in range(n, 0, -1):  # (n, n-1, ..., 1)
            ciphertext = QUAD.pack(A ^ (n * j + i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]

    key, key_iv = b"".join(R[1:]), A

    if key_iv != iv:
        raise ValueError(f"Unwrapping failed: 0x{key_iv:x} (expected 0x{iv:x})")

    return key


def _create_cipher(key: bytes, iv: bytes = b"\x00" * 16, mode: str = "cbc") -> Any:
    """Create a cipher object.

    Dynamic based on the available crypto module.
    """

    if HAS_PYSTANDALONE:
        key_size = len(key)
        if key_size not in (32, 24, 16):
            raise ValueError(f"Invalid key size: {key_size}")

        return _pystandalone.cipher(f"aes-{key_size * 8}-{mode}", key, iv)
    elif HAS_PYCRYPTODOME:
        mode_map = {
            "cbc": (AES.MODE_CBC, True),
            "ecb": (AES.MODE_ECB, False),
        }
        mode_id, has_iv = mode_map[mode]
        kwargs = {"iv": iv} if has_iv else {}
        return AES.new(key, mode_id, **kwargs)
    else:
        raise RuntimeError("No crypto module available")
