"""Filesystem and path related utilities."""

from __future__ import annotations

import fnmatch
import gzip
import hashlib
import io
import logging
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, Callable, TextIO

try:
    import lzma

    HAS_XZ = True
except ImportError:
    HAS_XZ = False

try:
    import bz2

    HAS_BZ2 = True
except ImportError:
    HAS_BZ2 = False

try:
    import zstandard

    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False

from dissect.target.exceptions import FileNotFoundError, SymlinkRecursionError
from dissect.target.helpers.polypath import (
    abspath,
    basename,
    commonpath,
    dirname,
    isabs,
    isreserved,
    join,
    normalize,
    normpath,
    relpath,
    split,
    splitdrive,
    splitext,
    splitroot,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from typing_extensions import Self

    import dissect.target.filesystem as filesystem

if sys.version_info >= (3, 13):
    from dissect.target.helpers.compat.path_313 import PureDissectPath, TargetPath
elif sys.version_info >= (3, 12):
    from dissect.target.helpers.compat.path_312 import PureDissectPath, TargetPath
elif sys.version_info >= (3, 11):
    from dissect.target.helpers.compat.path_311 import PureDissectPath, TargetPath
elif sys.version_info >= (3, 10):
    from dissect.target.helpers.compat.path_310 import PureDissectPath, TargetPath
elif sys.version_info >= (3, 9):  # noqa: UP036
    from dissect.target.helpers.compat.path_39 import PureDissectPath, TargetPath
else:
    raise RuntimeError("dissect.target requires at least Python 3.9")


log = logging.getLogger(__name__)

re_glob_magic = re.compile(r"[*?[]")
re_glob_index = re.compile(r"(?<=\/)[^\/]*[*?[]")

__all__ = [
    "PureDissectPath",
    "TargetPath",
    "abspath",
    "basename",
    "commonpath",
    "dirname",
    "fs_attrs",
    "generate_addr",
    "glob_ext",
    "glob_split",
    "has_glob_magic",
    "isabs",
    "isreserved",
    "join",
    "normalize",
    "normpath",
    "open_decompress",
    "recurse",
    "relpath",
    "resolve_link",
    "reverse_read",
    "reverse_readlines",
    "split",
    "splitdrive",
    "splitext",
    "splitroot",
    "stat_result",
    "walk",
    "walk_ext",
]


def generate_addr(path: str | Path, alt_separator: str = "") -> int:
    if not alt_separator and isinstance(path, Path):
        alt_separator = (getattr(path, "parser", None) or path._flavour).altsep
    path = normalize(str(path), alt_separator=alt_separator)
    return int(hashlib.sha256(path.encode()).hexdigest()[:8], 16)


class stat_result:
    """Custom stat_result object, designed to mimick os.stat_result.

    The real stat_result is a CPython internal StructSeq, which kind of behaves like a namedtuple on steroids.
    We try to emulate some of that behaviour here.

    For consistency this class is also called stat_result.
    """

    __slots__ = {  # noqa: RUF023
        # Regular fields
        "st_mode": "protection bits",
        "st_ino": "inode",
        "st_dev": "device",
        "st_nlink": "number of hard links",
        "st_uid": "user ID of owner",
        "st_gid": "group ID of owner",
        "st_size": "total size, in bytes",
        # Regular timestamp fields (integer, float, nanosecond)
        "_st_atime": "integer time of last access",
        "_st_mtime": "integer time of last modification",
        "_st_ctime": "integer time of last change",
        "st_atime": "time of last access",
        "st_mtime": "time of last modification",
        "st_ctime": "time of last change",
        "st_atime_ns": "time of last access in nanoseconds",
        "st_mtime_ns": "time of last modification in nanoseconds",
        "st_ctime_ns": "time of last change in nanoseconds",
        # Extra optional fields
        "st_blksize": "blocksize for filesystem I/O",
        "st_blocks": "number of blocks allocated",
        "st_rdev": "device type (if inode device)",
        "st_flags": "user defined flags for file",
        "st_gen": "generation number",
        "st_birthtime": "time of creation",
        "st_file_attributes": "Windows file attribute bits",
        "st_fstype": "Type of filesystem",
        "st_reparse_tag": "Windows reparse tag",
        "st_birthtime_ns": "time of creation in nanoseconds",
        # Internal fields
        "_s": "internal tuple",
    }
    _field_count = len(__slots__) - 1

    def __init__(self, s: Sequence[Any]):
        if not isinstance(s, (list, tuple)) or not len(s) >= 10:
            raise TypeError(f"dissect.target.stat_result() takes an at least 10-sequence ({len(s)}-sequence given)")

        if len(s) > self._field_count:
            raise TypeError(
                f"dissect.target.stat_result() takes an at most {self._field_count}-sequence ({len(s)}-sequence given)"
            )

        s = tuple(s)
        if len(s) < self._field_count:
            s = s + ((None,) * (self._field_count - len(s)))

        self.st_mode = s[0]
        self.st_ino = s[1]
        self.st_dev = s[2]
        self.st_nlink = s[3]
        self.st_uid = s[4]
        self.st_gid = s[5]
        self.st_size = s[6]

        # Parse the values given to us in the "integer" field and calculate
        # the integer, float and nanosecond timestamps from there.
        self._st_atime, self.st_atime, self.st_atime_ns = self._parse_time(s[7])
        self._st_mtime, self.st_mtime, self.st_mtime_ns = self._parse_time(s[8])
        self._st_ctime, self.st_ctime, self.st_ctime_ns = self._parse_time(s[9])

        # Allow overriding the calculated values so a more accurate nanosecond timestamp can be specified
        self.st_atime = s[10] or self.st_atime
        self.st_mtime = s[11] or self.st_mtime
        self.st_ctime = s[12] or self.st_ctime
        self.st_atime_ns = s[13] or self.st_atime_ns
        self.st_mtime_ns = s[14] or self.st_mtime_ns
        self.st_ctime_ns = s[15] or self.st_ctime_ns

        self.st_blksize = s[16]
        self.st_blocks = s[17]
        self.st_rdev = s[18]
        self.st_flags = s[19]
        self.st_gen = s[20]
        self.st_birthtime = s[21]
        self.st_file_attributes = s[22]
        self.st_fstype = s[23]
        self.st_reparse_tag = s[24]
        self.st_birthtime_ns = s[25]

        # stat_result behaves like a tuple, but only with the first 10 fields
        # Note that this means it specifically uses the integer variants of the timestamps
        self._s = (
            self.st_mode,
            self.st_ino,
            self.st_dev,
            self.st_nlink,
            self.st_uid,
            self.st_gid,
            self.st_size,
            self._st_atime,
            self._st_mtime,
            self._st_ctime,
        )

    def __eq__(self, other: object) -> bool:
        if isinstance(other, stat_result):
            other = other._s

        return self._s == other

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __getitem__(self, item: int) -> int:
        return self._s[item]

    def __iter__(self) -> Iterator[int]:
        return iter(self._s)

    def __repr__(self) -> str:
        values = ", ".join(
            f"{k}={getattr(self, k)}" for k in self.__slots__ if k.startswith("st_") and getattr(self, k) is not None
        )
        return f"dissect.target.stat_result({values})"

    def _parse_time(self, ts: float) -> tuple[int, float, int]:
        ts_int = int(ts)
        ts_ns = int(ts * 1e9)

        return ts_int, ts_ns * 1e-9, ts_ns

    @classmethod
    def copy(cls, other: stat_result) -> Self:
        # First copy the basic 10 fields
        st = cls(list(other))
        # Then iterate and copy any other
        for attr in list(cls.__slots__.keys())[10 : cls._field_count]:
            try:
                setattr(st, attr, getattr(other, attr))
            except AttributeError:  # noqa: PERF203
                pass
        return st


def walk(
    path_entry: filesystem.FilesystemEntry,
    topdown: bool = True,
    onerror: Callable[[Exception], None] | None = None,
    followlinks: bool = False,
) -> Iterator[
    tuple[list[filesystem.FilesystemEntry], list[filesystem.FilesystemEntry], list[filesystem.FilesystemEntry]]
]:
    for path_list, dirs, files in walk_ext(path_entry, topdown, onerror, followlinks):
        dir_names = [d.name for d in dirs]
        file_names = [f.name for f in files]

        walk_path = join(path_entry.path, *[p.name for p in path_list[1:]])
        yield walk_path, dir_names, file_names

        if len(dir_names) != len(dirs):
            dirs[:] = [d for d in dirs if d.name in dir_names]


def walk_ext(
    path_entry: filesystem.FilesystemEntry,
    topdown: bool = True,
    onerror: Callable[[Exception], None] | None = None,
    followlinks: bool = False,
) -> Iterator[
    tuple[list[filesystem.FilesystemEntry], list[filesystem.FilesystemEntry], list[filesystem.FilesystemEntry]]
]:
    dirs = []
    files = []

    try:
        for entry in path_entry.scandir():
            if entry.is_dir():
                dirs.append(entry)
            else:
                files.append(entry)
    except Exception as e:
        if onerror is not None and callable(onerror):
            e.entry = path_entry
            onerror(e)
        return

    if topdown:
        yield [path_entry], dirs, files

    for direntry in dirs:
        if followlinks or not direntry.is_symlink():
            for xpath, xdirs, xfiles in walk_ext(direntry, topdown, onerror, followlinks):
                yield [path_entry, *xpath], xdirs, xfiles

    if not topdown:
        yield [path_entry], dirs, files


def recurse(path_entry: filesystem.FilesystemEntry) -> Iterator[filesystem.FilesystemEntry]:
    """Recursively walk the given :class:`FilesystemEntry`, yields :class:`FilesystemEntry` instances."""
    yield path_entry

    if not path_entry.is_dir():
        return

    for child_entry in path_entry.scandir():
        if child_entry.is_dir() and not child_entry.is_symlink():
            yield from recurse(child_entry)
        else:
            yield child_entry


def glob_split(pattern: str, alt_separator: str = "") -> tuple[str, str]:
    """Split a pattern on path part boundaries on the first path part with a glob pattern.

    Args:
        pattern: A glob pattern to match names of filesystem entries against.
        alt_separator: An alternative path separator in use by the filesystem being matched.

    Returns:
        A tuple of a string with path parts up to the first path part that has a glob pattern and a string of
        the remaining path parts.
    """
    # re_glob_index expects a normalized pattern
    pattern = normalize(pattern, alt_separator=alt_separator)

    first_glob = re_glob_index.search(pattern)

    if not first_glob:
        return pattern, ""

    pos = first_glob.start()
    return pattern[:pos], pattern[pos:]


def glob_ext(direntry: filesystem.FilesystemEntry, pattern: str) -> Iterator[filesystem.FilesystemEntry]:
    """Recursively search and return filesystem entries matching a given glob pattern.

    Args:
        direntry: The filesystem entry relative to which to search.
        pattern: A glob pattern to match names of filesystem entries against.

    Yields:
        Matching filesystem entries (files and/or directories).
    """

    # Split the pattern on the last path part. base_name will contain the last path part (which is
    # '' if pattern ends with a /) and dir_name will contain the other parts.
    dir_name, base_name = split(pattern, alt_separator=direntry.fs.alt_separator)

    # The simple case where there are no globs.
    if not has_glob_magic(pattern):
        try:
            entry = direntry.get(pattern)
        except FileNotFoundError:
            pass
        else:
            # Patterns ending with a slash, so without a base_name, should match only directories.
            if base_name or entry.is_dir():
                yield entry
        return

    # The pattern has only one path part, so we can match directly against the files in direntry.
    if not dir_name:
        for entry in glob_ext1(direntry, base_name):
            yield entry
        return

    # If the pattern has more than one path part and these parts (dir_name) contain globs, we
    # recursively go over all the path parts and match them (glob_ext).
    # If these path parts have no globs, we get the path directly by name (glob_ext0).
    glob_in_dir = glob_ext if has_glob_magic(dir_name) else glob_ext0

    # If the pattern's last path part (base_name) has globs, we fnmatch it against the entries in
    # direntry (glob_ext1), otherwise we get the part directly by name (glob_ext0).
    glob_in_base = glob_ext1 if has_glob_magic(base_name) else glob_ext0

    for entry in glob_in_dir(direntry, dir_name):
        yield from glob_in_base(entry, base_name)


# These 2 helper functions non-recursively glob inside a literal directory.
def glob_ext1(direntry: filesystem.FilesystemEntry, pattern: str) -> Iterator[filesystem.FilesystemEntry]:
    """Match and return filesystem entries in a given filesystem entry based on pattern.

    Args:
        direntry: The filesystem entry relative to which to match the entries.
        pattern: A glob pattern to match names of filesystem entries against.

    Yields:
        Matching filesystem entries (files and/or directories).
    """
    if not direntry.is_dir():
        return

    entries = direntry.scandir()

    if pattern[0] != ".":
        # Do not return dot-files, unless they are explicitly searched for.
        entries = filter(lambda x: x.name[0] != ".", entries)

    for entry in entries:
        case_sensitive = entry.fs.case_sensitive
        name = entry.name if case_sensitive else entry.name.lower()
        pattern = pattern if case_sensitive else pattern.lower()
        if fnmatch.fnmatch(name, pattern):
            yield entry


def glob_ext0(direntry: filesystem.FilesystemEntry, path: str) -> Iterator[filesystem.FilesystemEntry]:
    """Return the filesystem entry equal to the given path relative to direntry.

    Args:
        direntry: The filesystem entry relative to which to return the path.
        path: The path to the filesystem entry to return (if present). If path
              is an empty string (``''``) the ``direntry`` itself is returned.

    Yields:
        The matching filesystem entry (file or directory).
    """
    if path == "":
        # os.path.split() returns an empty path for paths ending with a directory separator.
        # E.g. 'q*x/' should match only directories.
        if direntry.is_dir():
            yield direntry
    elif direntry.is_dir():
        try:
            yield direntry.get(path)
        except FileNotFoundError:
            pass


def has_glob_magic(s: str) -> bool:
    return re_glob_magic.search(s) is not None


def resolve_link(
    fs: filesystem.Filesystem,
    link: str,
    path: str,
    *,
    alt_separator: str = "",
    previous_links: set[str] | None = None,
) -> filesystem.FilesystemEntry:
    """Resolves a symlink to its actual path.

    It stops resolving once it detects an infinite recursion loop.
    """

    link = normalize(link, alt_separator=alt_separator)
    path = normalize(path, alt_separator=alt_separator)

    # Create hash for entry based on path and link
    link_id = f"{path}{link}"
    hash_entry = hash(link_id)

    if not previous_links:
        previous_links = set()

    # Check whether the current entry was already resolved once.
    if hash_entry in previous_links:
        raise SymlinkRecursionError(f"Symlink loop detected for {link_id}")

    previous_links.add(hash_entry)

    if not isabs(link):
        cur_dirname = dirname(normpath(path))
        link = normpath(join(cur_dirname, link))

    # retrieve file from root
    entry = fs.get(link)

    if entry.is_symlink():
        entry = resolve_link(
            fs,
            entry.readlink(),
            link,
            alt_separator=entry.fs.alt_separator,
            previous_links=previous_links,
        )

    return entry


def open_decompress(
    path: TargetPath | None = None,
    mode: str = "rb",
    *,
    fileobj: BinaryIO | None = None,
    encoding: str | None = "UTF-8",
    errors: str | None = "backslashreplace",
    newline: str | None = None,
) -> BinaryIO | TextIO:
    """Open and decompress a file. Handles gz, bz2 and zstd files. Uncompressed files are opened as-is.

    When passing in an already opened ``fileobj``, the mode, encoding, errors and newline arguments are ignored.

    Args:
        path: The path to the file to open and decompress. It is assumed this path exists.
        mode: The mode in which to open the file.
        fileobj: The file-like object to open and decompress. This is mutually exclusive with path.
        encoding: The decoding for text streams. By default UTF-8 encoding is used.
        errors: The error handling for text streams. By default we're more lenient and use ``backslashreplace``.
        newline: How newlines are handled for text streams.

    Returns:
        An binary or text IO stream, depending on the mode with which the file was opened.

    Example:
        .. code-block:: python

            bytes_buf = open_decompress(Path("/dir/file.gz")).read()

            for line in open_decompress(Path("/dir/file.gz"), "rt"):
                print(line)
    """
    if path and fileobj:
        raise ValueError("path and fileobj are mutually exclusive")

    if not path and not fileobj:
        raise ValueError("path or fileobj is required")

    if path:
        file = path.open("rb")
    else:
        file = fileobj
        file.seek(0)

    magic = file.read(5)
    file.seek(0)

    if "b" in mode:
        # Reset the default encoding and errors mode in case of a binary stream
        encoding = None
        errors = None

    if magic[:2] == b"\x1f\x8b":
        return gzip.open(file, mode, encoding=encoding, errors=errors, newline=newline)

    if HAS_XZ and magic[:5] == b"\xfd7zXZ":
        return lzma.open(file, mode, encoding=encoding, errors=errors, newline=newline)

    if HAS_BZ2 and magic[:3] == b"BZh" and 0x31 <= magic[3] <= 0x39:
        # In a valid bz2 header the 4th byte is in the range b'1' ... b'9'.
        return bz2.open(file, mode, encoding=encoding, errors=errors, newline=newline)

    if HAS_ZSTD and magic[:4] in [b"\xfd\x2f\xb5\x28", b"\x28\xb5\x2f\xfd"]:
        # stream_reader is not seekable, so we have to resort to the less
        # efficient decompressor which returns bytes.
        return io.BytesIO(zstandard.decompress(file.read()))

    if path:
        file.close()
        return path.open(mode, encoding=encoding, errors=errors, newline=newline)

    return file


def reverse_read(fh: BinaryIO, chunk_size: int = io.DEFAULT_BUFFER_SIZE, reverse_chunk: bool = True) -> Iterator[bytes]:
    """Like iterating over chunks of a binary file-like object, but starting from the end of the file.

    Args:
        fh: The file-like object (opened in binary mode) to read from.
        chunk_size: The chunk size to use for iterating over bytes (default: 8KB).
        reverse_chunk: Whether we should reverse the bytes of each chunk (default: True).

    Returns:
        An iterator of byte chunks, starting from the end of the file-like object and moving to the start.
    """

    offset = fh.seek(0, io.SEEK_END)

    while offset > 0:
        if offset < chunk_size:
            chunk_size = offset
        offset -= chunk_size
        fh.seek(offset)
        buf = fh.read(chunk_size)
        yield bytes(reversed(buf)) if reverse_chunk else buf


def reverse_readlines(fh: TextIO, chunk_size: int = 1024 * 1024 * 8) -> Iterator[str]:
    """Like iterating over a ``TextIO`` file-like object, but starting from the end of the file.

    Args:
        fh: The file-like object (opened in text mode) to iterate lines from.
        chunk_size: The chunk size to use for iterating over lines.

    Returns:
        An iterator of lines from the file-like object, in reverse.
    """
    offset = fh.seek(0, io.SEEK_END) & ((1 << 64) - 1)
    lines = []

    prev_offset = offset
    while offset > 0:
        if offset < chunk_size:
            chunk_size = offset
        offset -= chunk_size
        fh.seek(offset)

        lines = []
        # tell() on TextIO returns a cookie which includes encode/decoder state
        # Lower 64 bit are the file position
        # https://peps.python.org/pep-3116/#text-i-o
        # See TextIOWrapper._pack_cookie in _pyio.py for more detail
        while (fh.tell() & ((1 << 64) - 1)) < prev_offset:
            try:
                lines.append(fh.readline())
            except UnicodeDecodeError:  # noqa: PERF203
                offset += 1
                fh.seek(offset)

        yield from reversed(lines[1:])

        if prev_offset == offset:
            # Previous lines are unreadable due to decoding errors
            raise UnicodeDecodeError(fh.encoding, b"", 0, offset + 1, "failed to decode line")

        prev_offset = offset

    if lines:
        yield lines[0]


def fs_attrs(
    path: os.PathLike | str | bytes,
    follow_symlinks: bool = True,
) -> dict[os.PathLike | str | bytes, bytes]:
    """Return the extended attributes for a given path on the local filesystem.

    This is currently only implemented for Linux using os.listxattr and related functions.

    Args:
        path: The path to get the extended attributes for.
        follow_symlinks: Wether to follow the symlink if the given path is a symlink.

    Returns:
        A dict containing the attribute names as keys and their values.
    """
    attrs = {}
    if hasattr(os, "listxattr"):
        # os.listxattr etc. are only available on Linux
        attr_names = os.listxattr(path, follow_symlinks=follow_symlinks)
        for attr_name in attr_names:
            attrs[attr_name] = os.getxattr(path, attr_name, follow_symlinks=follow_symlinks)

    return attrs
