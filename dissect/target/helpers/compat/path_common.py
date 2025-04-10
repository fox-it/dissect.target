from __future__ import annotations

import io
import posixpath
import stat
import sys
from typing import IO, TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.filesystem import Filesystem, FilesystemEntry
    from dissect.target.helpers.fsutil import TargetPath

from dissect.target.exceptions import FilesystemError, SymlinkRecursionError
from dissect.target.helpers.polypath import abspath, normalize

try:
    # Up until CPython 3.12, pathlib._PathParents requires subclassing to inject the filesystem and flavour
    # into each parent path component. Since CPython 3.12, this is no longer necessary.
    # In CPython 3.13, _PathParents was moved to a different file, so this will result in an import error.
    # Since we no longer need it in CPython 3.13, we can just ignore the error.
    from pathlib import _PathParents

    class _DissectPathParents(_PathParents):
        __slots__ = ("_flavour", "_fs")

        def __init__(self, path: TargetPath):
            super().__init__(path)
            self._fs = path._fs
            self._flavour = path._flavour

        if sys.version_info >= (3, 10):

            def __getitem__(self, idx: int) -> TargetPath:
                result = super().__getitem__(idx)
                result._fs = self._fs
                result._flavour = self._flavour
                return result

        else:

            def __getitem__(self, idx: int) -> TargetPath:
                if idx < 0:
                    idx = len(self) + idx

                result = super().__getitem__(idx)
                result._fs = self._fs
                result._flavour = self._flavour
                return result

except ImportError:
    pass


class _DissectScandirIterator:
    """This class implements a ScandirIterator for dissect's scandir()

    The _DissectScandirIterator provides a context manager, so scandir can be called as:

    .. code-block:: python

        with scandir(path) as it:
            for entry in it
                print(entry.name)

    similar to os.scandir() behaviour since Python 3.6.
    """

    def __init__(self, iterator: Iterator[FilesystemEntry]):
        self._iterator = iterator

    def __del__(self) -> None:
        self.close()

    def __enter__(self) -> Iterator[FilesystemEntry]:
        return self._iterator

    def __exit__(self, *args, **kwargs) -> Literal[False]:
        return False

    def __iter__(self) -> Iterator[FilesystemEntry]:
        return self._iterator

    def __next__(self, *args) -> FilesystemEntry:
        return next(self._iterator, *args)

    def close(self) -> None:
        # close() is not defined in the various filesystem implementations. The
        # python ScandirIterator does define the interface however.
        pass


def scandir(path: TargetPath) -> _DissectScandirIterator:
    return _DissectScandirIterator(path.get().scandir())


def realpath(path: TargetPath, *, strict: bool = False) -> str:
    """Return the canonical path of the specified filename, eliminating any symbolic links encountered in the path."""
    filename = str(path)
    path, _ = _joinrealpath(path._fs, filename[:0], filename, strict, {})
    return abspath(path)


def isjunction(path: TargetPath) -> bool:
    """Return True if the path is a junction."""
    try:
        from dissect.target.filesystems.ntfs import NtfsFilesystemEntry
    except ImportError:
        return False

    entry = path.get()
    # Python's ntpath isjunction() only checks for mount point reparse tags
    return isinstance(entry, NtfsFilesystemEntry) and entry.dereference().is_mount_point()


# Join two paths, normalizing and eliminating any symbolic links
# encountered in the second path.
# NOTE: This is a copy of posixpath._joinrealpath with some small tweaks
def _joinrealpath(fs: Filesystem, path: str, rest: str, strict: bool, seen: dict[str, str]) -> tuple[str, bool]:
    if posixpath.isabs(rest):
        rest = rest[1:]
        path = "/"

    while rest:
        name, _, rest = rest.partition("/")
        if not name or name == ".":
            # current dir
            continue
        if name == "..":
            # parent dir
            if path:
                path, name = posixpath.split(path)
                if name == "..":
                    path = posixpath.join(path, "..", "..")
            else:
                path = ".."
            continue
        newpath = posixpath.join(path, name)
        try:
            st = fs.get(newpath).lstat()
        except FilesystemError:
            if strict:
                raise
            is_link = False
        else:
            is_link = stat.S_ISLNK(st.st_mode)
        if not is_link:
            path = newpath
            continue
        # Resolve the symbolic link
        if newpath in seen:
            # Already seen this path
            path = seen[newpath]
            if path is not None:
                # use cached value
                continue
            # The symlink is not resolved, so we must have a symlink loop.
            if strict:
                # Raise OSError(errno.ELOOP)
                raise SymlinkRecursionError(newpath)
            # Return already resolved part + rest of the path unchanged.
            return posixpath.join(newpath, rest), False
        seen[newpath] = None  # not resolved symlink
        path, ok = _joinrealpath(fs, path, normalize(fs.readlink(newpath)), strict, seen)
        if not ok:
            return posixpath.join(path, rest), False
        seen[newpath] = path  # resolved symlink

    return path, True


def io_open(
    path: TargetPath,
    mode: str = "rb",
    buffering: int = 0,
    encoding: str | None = None,
    errors: str | None = None,
    newline: str | None = None,
) -> IO:
    """Open file and return a stream.

    Supports a subset of features of the real pathlib.open/io.open.

    Note: in contrast to regular Python, the mode is binary by default. Text mode
    has to be explicitly specified. Buffering is also disabled by default.
    """
    modes = set(mode)
    if modes - set("rbt") or len(mode) > len(modes):
        raise ValueError(f"invalid mode: {mode!r}")

    reading = "r" in modes
    binary = "b" in modes
    text = "t" in modes or "b" not in modes

    if "b" not in mode:
        encoding = encoding or "UTF-8"
        # CPython >= 3.10
        if hasattr(io, "text_encoding"):
            # Vermin linting needs to be skipped for this line as this is
            # guarded by an explicit check for availability.
            # novermin
            encoding = io.text_encoding(encoding)

    if not reading:
        raise ValueError("must be reading mode")
    if text and binary:
        raise ValueError("can't have text and binary mode at once")
    if binary and encoding is not None:
        raise ValueError("binary mode doesn't take an encoding argument")
    if binary and errors is not None:
        raise ValueError("binary mode doesn't take an errors argument")
    if binary and newline is not None:
        raise ValueError("binary mode doesn't take a newline argument")

    raw = path.get().open()
    result = raw

    line_buffering = False
    if buffering == 1 or (buffering < 0 and raw.isatty()):
        buffering = -1
        line_buffering = True
    if buffering < 0 or (text and buffering == 0):
        buffering = io.DEFAULT_BUFFER_SIZE
    if buffering == 0:
        if binary:
            return result
        raise ValueError("can't have unbuffered text I/O")

    buffer = io.BufferedReader(raw, buffering)
    result = buffer
    if binary:
        return result

    result = io.TextIOWrapper(buffer, encoding, errors, newline, line_buffering)
    result.mode = mode

    return result
