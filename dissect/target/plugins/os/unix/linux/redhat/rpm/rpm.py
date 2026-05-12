from __future__ import annotations

import argparse
import stat
import sys
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.database.bsd import DB
from dissect.database.sqlite3 import SQLite3
from flow.record.fieldtypes import digest

from dissect.target.helpers.logging import get_logger
from dissect.target.plugins.os.unix.linux.redhat.rpm.c_rpm import c_rpm
from dissect.target.plugins.os.unix.linux.redhat.rpm.ndb import NDB
from dissect.target.tools.utils.cli import catch_sigpipe

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

log = get_logger(__name__)


class Packages:
    """Parses a RPM Packages file. Supports NDB, SQLite3 and BerkleyDB formats."""

    def __init__(self, input: Path) -> None:
        """Initializes :class:`Packages` using ``Path`` as input. In the future we should also support ``BinaryIO``."""
        self.path = None
        self.db = None

        self.blobs: set[bytes] = set()

        if not isinstance(input, Path):
            raise TypeError(f"Unexpected input: {input!r}")

        self.path = input

        # SQLite3 format
        if self.path.suffix == ".sqlite":
            self.db = SQLite3(self.path)
            self.blobs.update(row.blob for row in self.db.table("Packages").rows())

        # Native DB (NDB) format
        elif self.path.suffix == ".db":
            self.db = NDB(input.open("rb"))
            self.blobs.update(self.db.records())

        # Berkley DB format
        else:
            self.db = DB(input.open("rb"))
            self.blobs.update(blob for i, (_, blob) in enumerate(self.db.records()) if i > 0)

    def __repr__(self) -> str:
        return f"<Packages type={self.db.__class__.__name__} size={len(self.blobs)}>"

    def __iter__(self):
        for blob in self.blobs:
            yield Package(blob)


class Package:
    """RPM Package."""

    def __init__(self, blob: BinaryIO | bytes) -> None:
        self.blob = blob
        self.package = parse_blob(blob)

    def __repr__(self) -> str:
        return f"<Package name={self.name} version={self.version} release={self.release} arch={self.arch} files=#{len(self.entry_paths)}>"  # noqa: E501

    def __iter__(self) -> Iterator[File | Directory]:
        return self.entries()

    @property
    def name(self) -> str:
        """Return the simple name of the RPM package."""
        return self.package["name"]

    @property
    def version(self) -> str | None:
        """Return the version of the RPM package."""
        return self.package.get("version")

    @property
    def release(self) -> str | None:
        """Return the release of the RPM package."""
        return self.package.get("release")

    @property
    def arch(self) -> str | None:
        """Return the architecture of the RPM package."""
        return self.package.get("arch")

    @property
    def full_name(self) -> str:
        """Reconstruct the full name of the RPM package."""
        full_name = "-".join([self.package.get(name, "") for name in ("name", "version", "release")])
        if arch := self.package.get("arch"):
            full_name += f".{arch}"
        return full_name

    @property
    def digest(self) -> digest:
        """Group the digests of the packed package."""
        package_digest = digest()
        for hexdigest, algo_num in zip(
            self.package.get("packagedigests", []), self.package.get("packagedigestalgos", []), strict=True
        ):
            setattr(package_digest, c_rpm.HashAlgo(algo_num).name.lower(), hexdigest)

        return package_digest

    @property
    def install_time(self) -> datetime:
        """Return the install time of the package."""
        return datetime.fromtimestamp(self.package.get("installtime", 0), tz=timezone.utc)

    @property
    def vendor(self) -> str | None:
        return self.package.get("vendor")

    @property
    def summary(self) -> str | None:
        return self.package.get("summary")

    @property
    def description(self) -> str | None:
        return self.package.get("description")

    @property
    def size(self) -> int | None:
        return self.package.get("size")

    @property
    def source(self) -> str | None:
        return self.package.get("sourcerpm")

    @property
    def entry_paths(self) -> list[str]:
        """Reconstruct the full file paths for all files contained in the package."""
        dirnames = self.package.get("dirnames", [])
        basenames = self.package.get("basenames", [])
        dirindexes = self.package.get("dirindexes", [])

        if not isinstance(dirindexes, list) and len(dirnames) == 1:
            dirindexes = [0]

        return [f"{dirnames[dirindexes[i]]}{file}" for i, file in enumerate(basenames)]

    @property
    def entry_sizes(self) -> list[int]:
        """Get file sizes of files in the package."""
        file_sizes = self.package.get("filesizes", [])
        if not isinstance(file_sizes, list):
            file_sizes = [file_sizes]

        return file_sizes

    @property
    def entry_digest_algo(self) -> c_rpm.HashAlgo:
        """Return the digest algorithm used for entries in this package."""
        return c_rpm.HashAlgo(self.package.get("filedigestalgo", 1))

    @property
    def entry_digests(self) -> list[digest]:
        """Group digests of the files in the package together.

        Digest by default are sha256 (8). For backwards compatibility if no int is set md5 should be selected.

        References:
            - docs/manual/tags.md
        """
        digests = []

        for hexdigest in self.package.get("filedigests", []):
            if not hexdigest:
                continue
            d = digest()
            setattr(d, self.entry_digest_algo.name.lower(), hexdigest)
            digests.append(d)

        return digests

    @property
    def entry_modes(self) -> list[int]:
        """Get stat file modes of the files in the package."""
        filemodes = self.package.get("filemodes", [])
        if not isinstance(filemodes, list):
            filemodes = [filemodes]
        return filemodes

    def entries(self) -> Iterator[File | Directory]:
        """Iterate over all files and directories in the package."""
        for i, _ in enumerate(self.entry_paths):
            mode = self.entry_modes[i]
            yield Directory(self, i) if stat.S_ISDIR(mode) else File(self, i)


class Entry:
    def __init__(self, package: Package, index: int) -> None:
        self.package = package
        self.index = index

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} path={self.path}>"

    @property
    def path(self) -> str:
        return self.package.entry_paths[self.index]

    @property
    def size(self) -> int:
        return self.package.entry_sizes[self.index]

    @property
    def digest(self) -> digest | None:
        try:
            return self.package.entry_digests[self.index]
        except IndexError:
            return None

    @property
    def mode(self) -> int:
        return self.package.entry_modes[self.index]

    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)

    def is_file(self) -> bool:
        return stat.S_ISREG(self.mode)

    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.mode)


class Directory(Entry):
    pass


class File(Entry):
    def __repr__(self) -> str:
        return f"<File path={self.path} size={self.size}>"


def parse_blob(blob: BinaryIO | bytes) -> dict:
    """Parse a RPM package blob. Does not parse dribble entries (yet).

    References:
        - https://github.com/rpm-software-management/rpm/blob/master/lib/backend/ndb/rpmpkg.c
        - https://github.com/rpm-software-management/rpm/blob/master/lib/tagexts.cc @ getNEVRA
        - https://github.com/knqyf263/go-rpmdb
    """
    fh = BytesIO(blob) if isinstance(blob, (bytes, bytearray, memoryview)) else blob
    header = c_rpm.Header(fh)
    offset = fh.tell()
    package = {}

    for entry in header.pe_list:
        fh.seek(offset + entry.offset)

        type_size = c_rpm.TypeSizes[entry.type.name]

        # Read null terminated strings n-times for string-types.
        if entry.type in (c_rpm.TagType.STRING, c_rpm.TagType.STRING_ARRAY, c_rpm.TagType.I18NSTRING):
            data = b"".join([c_rpm.NullTerminatedStr(fh).dumps() for _ in range(entry.count)])

        else:
            # In theory entry.type.value can be above 16, so value & 0xf to keep value below 16?
            size = type_size * entry.count
            data = fh.read(size)

        if entry.tag.name:
            result = deserialize(entry.type, type_size, entry.count, data)

            if entry.count > 1 and len(result) != entry.count:
                raise ValueError(f"Deserialization of array failed, mismatch in count and array length: {entry!r}")

            package[entry.tag.name.lower()] = result

        else:
            # We should have all tags, log if we encounter a new one that should be added.
            log.warning("Encountered unknown RPM tag value %r in: %r", entry.tag.value, entry)

    return package


DESERIALIZE_MAP: dict[c_rpm.TagType, Callable] = {
    c_rpm.TagType.NULL: lambda _: None,
    c_rpm.TagType.CHAR: lambda b, _: c_rpm.char(b),
    c_rpm.TagType.INT8: lambda b, _: c_rpm.uint8(b),
    c_rpm.TagType.INT16: lambda b, _: c_rpm.uint16(b),
    c_rpm.TagType.INT32: lambda b, _: c_rpm.uint32(b),
    c_rpm.TagType.INT64: lambda b, _: c_rpm.uint64(b),
    c_rpm.TagType.STRING: lambda b, _: b.split(b"\x00", maxsplit=1)[0].decode().strip("\x00"),
    c_rpm.TagType.BIN: lambda b, _: b,
    c_rpm.TagType.STRING_ARRAY: lambda b, c: [i.decode().strip("\x00") for i in b.split(b"\x00", maxsplit=c - 1)],
    c_rpm.TagType.I18NSTRING: lambda b, _: b.split(b"\x00", maxsplit=1)[0].decode().strip("\x00"),
}


def deserialize(type: c_rpm.TagType, size: int, count: int, enc: bytes) -> Any:
    """Deserialize the provided value."""
    if func := DESERIALIZE_MAP.get(type):
        # Handle single types, treat binary as one to get a neat bytes object
        if count == 1 or type == c_rpm.TagType.BIN:
            return func(enc, 1)

        # Handle string arrays
        if count > 1 and type == c_rpm.TagType.STRING_ARRAY:
            return func(enc, count)

        # Handle implicit arrays (count > 1 and not string array)
        buf = BytesIO(enc)
        return [func(inp, 1) for _ in range(count) if (inp := buf.read(size))]

    raise ValueError(f"Unknown TagType {type!s} with value {enc!r}")


@catch_sigpipe
def main() -> int:
    """Utility RPM package tool ported from ``dissect.database.bsd.tools.rpm``."""
    parser = argparse.ArgumentParser()
    parser.add_argument("input", metavar="INPUT", type=Path, help="input Packages file (EseDB, NDB or SQLite3)")
    args = parser.parse_args()

    path: Path = args.input
    if not path.is_file():
        print(f"Provided path is not a file: {path}")
        return 1

    for package in Packages(path):
        print(package)
        for entry in package.entries():
            print(entry)
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
