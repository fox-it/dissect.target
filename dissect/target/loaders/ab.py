import hashlib
import io
import posixpath
import shutil
import struct
import sys
import zlib
from pathlib import Path
from typing import BinaryIO, Optional

try:
    from Crypto.Cipher import AES

    HAS_PYCRYPTODOME = True
except ImportError:
    HAS_PYCRYPTODOME = False

from dissect.util.stream import AlignedStream, RelativeStream

from dissect.target.exceptions import LoaderError
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.tar import TarFilesystem
from dissect.target.helpers import keychain
from dissect.target.loader import Loader
from dissect.target.plugins.os.unix.linux.android._os import AndroidPlugin
from dissect.target.target import Target

DIRECTORY_MAPPING = {
    "a": "/data/app/{id}",
    "f": "/data/data/{id}/files",
    "db": "/data/data/{id}/databases",
    "ef": "/storage/emulated/0/Android/data/{id}",
    "sp": "/data/data/{id}/shared_preferences",
    "r": "/data/data/{id}",
    "obb": "/storage/emulated/0/Android/obb/{id}",
}


class AndroidBackupLoader(Loader):
    """Load Android backup files.

    References:
        - http://fileformats.archiveteam.org/wiki/Android_ADB_Backup
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path)
        self.ab = AndroidBackup(path.open("rb"))

        if self.ab.encrypted:
            for key in keychain.get_keys_for_provider("ab") + keychain.get_keys_without_provider():
                if key.key_type == keychain.KeyType.PASSPHRASE:
                    try:
                        self.ab.unlock(key.value)
                        break
                    except ValueError:
                        continue
            else:
                raise LoaderError(f"Missing password for encrypted Android Backup: {self.path}")

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".ab"

    def map(self, target: Target) -> None:
        if self.ab.compressed or self.ab.encrypted:
            if self.ab.compressed and not self.ab.encrypted:
                word = "compressed"
            elif self.ab.encrypted and not self.ab.compressed:
                word = "encrypted"
            else:
                word = "compressed and encrypted"

            target.log.warning(
                f"Backup file is {word}, consider unwrapping with "
                "`python -m dissect.target.loaders.ab <path/to/backup.ab>`"
            )

        vfs = VirtualFilesystem(case_sensitive=False)

        fs = TarFilesystem(self.ab.open())
        for app in fs.path("/apps").iterdir():
            for subdir in app.iterdir():
                if subdir.name not in DIRECTORY_MAPPING:
                    continue

                path = DIRECTORY_MAPPING[subdir.name].format(id=app.name)

                # TODO: Remove once we move towards "directory entries"
                entry = subdir.get()
                entry.name = posixpath.basename(path)

                vfs.map_file_entry(path, entry)

        target.filesystems.add(vfs)

        target.fs.mount("/", vfs)
        target._os_plugin = AndroidPlugin(target)


class AndroidBackup:
    def __init__(self, fh: BinaryIO):
        self.fh = fh

        size = fh.seek(0, io.SEEK_END)
        fh.seek(0)

        # Don't readline() straight away as we may be reading something other than a backup file
        magic = fh.read(15)
        if magic != b"ANDROID BACKUP\n":
            raise ValueError("Not a valid Android Backup file")

        self.version = int(fh.read(2)[:1])
        self.compressed = bool(int(fh.read(2)[:1]))

        self.encrypted = False
        self.unlocked = True
        self.encryption = fh.readline().strip().decode()

        if self.encryption != "none":
            self.encrypted = True
            self.unlocked = False
            self._user_salt = bytes.fromhex(fh.readline().strip().decode())
            self._ck_salt = bytes.fromhex(fh.readline().strip().decode())
            self._rounds = int(fh.readline().strip())
            self._user_iv = bytes.fromhex(fh.readline().strip().decode())
            self._master_key = bytes.fromhex(fh.readline().strip().decode())

            self._mk = None
            self._iv = None

        self._data_offset = fh.tell()
        self.size = size - self._data_offset

    def unlock(self, password: str) -> None:
        if not self.encrypted:
            raise ValueError("Android Backup is not encrypted")

        self._mk, self._iv = self._decrypt_mk(password)
        self.unlocked = True

    def _decrypt_mk(self, password: str) -> tuple[bytes, bytes]:
        user_key = hashlib.pbkdf2_hmac("sha1", password.encode(), self._user_salt, self._rounds, 32)

        blob = AES.new(user_key, AES.MODE_CBC, iv=self._user_iv).decrypt(self._master_key)
        blob = blob[: -blob[-1]]

        offset = 0
        iv_len = blob[offset]
        offset += 1
        iv = blob[offset : offset + iv_len]

        offset += iv_len
        mk_len = blob[offset]
        offset += 1
        mk = blob[offset : offset + mk_len]

        offset += mk_len
        checksum_len = blob[offset]
        offset += 1
        checksum = blob[offset : offset + checksum_len]

        ck_mk = _encode_bytes(mk) if self.version >= 2 else mk
        our_checksum = hashlib.pbkdf2_hmac("sha1", ck_mk, self._ck_salt, self._rounds, 32)
        if our_checksum != checksum:
            # Try reverse encoding for good measure
            ck_mk = mk if self.version >= 2 else _encode_bytes(mk)
            our_checksum = hashlib.pbkdf2_hmac("sha1", ck_mk, self._ck_salt, self._rounds, 32)

        if our_checksum != checksum:
            raise ValueError("Invalid password: master key checksum does not match")

        return mk, iv

    def open(self) -> BinaryIO:
        fh = RelativeStream(self.fh, self._data_offset)

        if self.encrypted:
            if not self.unlocked:
                raise ValueError("Missing password for encrypted Android Backup")
            fh = CipherStream(fh, self._mk, self._iv, self.size)

        if self.compressed:
            fh = ZlibStream(fh)

        return fh


class ZlibStream(AlignedStream):
    def __init__(self, fh: BinaryIO, size: Optional[int] = None, **kwargs):
        self._fh = fh

        self._zlib = None
        self._zlib_args = kwargs
        self._zlib_offset = 0
        self._zlib_prepend = b""
        self._zlib_prepend_offset = None
        self._rewind()

        super().__init__(size)

    def _rewind(self) -> None:
        self._fh.seek(0)
        self._zlib = zlib.decompressobj(**self._zlib_args)
        self._zlib_offset = 0
        self._zlib_prepend = b""
        self._zlib_prepend_offset = None

    def _seek_zlib(self, offset: int) -> None:
        if offset < self._zlib_offset:
            self._rewind()

        while self._zlib_offset < offset:
            read_size = min(offset - self._zlib_offset, self.align)
            if self._read_zlib(read_size) == b"":
                break

    def _read_fh(self, length: int) -> bytes:
        if self._zlib_prepend_offset is None:
            return self._fh.read(length)

        if self._zlib_prepend_offset + length <= len(self._zlib_prepend):
            offset = self._zlib_prepend_offset
            self._zlib_prepend_offset += length
            return self._zlib_prepend_offset[offset : self._zlib_prepend_offset]
        else:
            offset = self._zlib_prepend_offset
            self._zlib_prepend_offset = None
            return self._zlib_prepend[offset:] + self._fh.read(length - len(self._zlib_prepend) + offset)

    def _read_zlib(self, length: int) -> bytes:
        if length < 0:
            return self.readall()

        result = []
        while length > 0:
            buf = self._read_fh(io.DEFAULT_BUFFER_SIZE)
            decompressed = self._zlib.decompress(buf, length)

            if self._zlib.unconsumed_tail != b"":
                self._zlib_prepend = self._zlib.unconsumed_tail
                self._zlib_prepend_offset = 0

            if buf == b"":
                break

            result.append(decompressed)
            length -= len(decompressed)

        buf = b"".join(result)
        self._zlib_offset += len(buf)
        return buf

    def _read(self, offset: int, length: int) -> bytes:
        self._seek_zlib(offset)
        return self._read_zlib(length)

    def readall(self) -> bytes:
        chunks = []
        # sys.maxsize means the max length of output buffer is unlimited,
        # so that the whole input buffer can be decompressed within one
        # .decompress() call.
        while data := self._read_zlib(sys.maxsize):
            chunks.append(data)

        return b"".join(chunks)


class CipherStream(AlignedStream):
    """Transparently AES-CBC decrypted stream."""

    def __init__(self, fh: BinaryIO, key: bytes, iv: bytes, size: int):
        self._fh = fh

        self._key = key
        self._iv = iv
        self._cipher = None
        self._cipher_offset = 0
        self._reset_cipher()

        super().__init__(size)

    def _reset_cipher(self) -> None:
        self._cipher = AES.new(self._key, AES.MODE_CBC, iv=self._iv)
        self._cipher_offset = 0

    def _seek_cipher(self, offset: int) -> None:
        """CBC is dependent on previous blocks so to seek the cipher, decrypt and discard to the wanted offset."""
        if offset < self._cipher_offset:
            self._reset_cipher()
            self._fh.seek(0)

        while self._cipher_offset < offset:
            read_size = min(offset - self._cipher_offset, self.align)
            self._cipher.decrypt(self._fh.read(read_size))
            self._cipher_offset += read_size

    def _read(self, offset: int, length: int) -> bytes:
        self._seek_cipher(offset)

        data = self._cipher.decrypt(self._fh.read(length))
        if offset + length >= self.size:
            # Remove padding
            data = data[: -data[-1]]

        self._cipher_offset += len(data)

        return data


def _encode_bytes(buf: bytes) -> bytes:
    # Emulate byte[] -> char[] -> utf8 byte[] casting
    return struct.pack(">32h", *struct.unpack(">32b", buf)).decode("utf-16-be").encode("utf-8")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path, help="source path")
    parser.add_argument("-p", "--password", help="encryption password")
    parser.add_argument("-t", "--tar", action="store_true", help="write a tar file instead of a plain Android Backup")
    parser.add_argument("-o", "--output", type=Path, help="output path")
    args = parser.parse_args()

    if not args.path.is_file():
        parser.exit("source path does not exist or is not a file")

    ext = ".tar" if args.tar else ".plain.ab"
    if args.output is None:
        output = args.path.with_suffix(ext)
    elif args.output.is_dir():
        output = args.output.joinpath(args.path.name).with_suffix(ext)
    else:
        output = args.output

    if output.exists():
        parser.exit(f"output path already exists: {output}")

    print(f"unwrapping {args.path} -> {output}")
    with args.path.open("rb") as fh:
        ab = AndroidBackup(fh)

        if ab.encrypted:
            if not args.password:
                parser.exit("missing password for encrypted Android Backup")
            ab.unlock(args.password)

        with ab.open() as fhab, output.open("wb") as fhout:
            if not args.tar:
                fhout.write(b"ANDROID BACKUP\n")  # header
                fhout.write(b"5\n")  # version
                fhout.write(b"0\n")  # compressed
                fhout.write(b"none\n")  # encryption

            shutil.copyfileobj(fhab, fhout, 1024 * 1024 * 64)
