"""A pathlib.Path compatible implementation for dissect.target.

This allows for the majority of the pathlib.Path API to "just work" on dissect.target filesystems.

Most of this consists of subclassed internal classes with dissect.target specific patches,
but sometimes the change to a function is small, so the entire internal function is copied
and only a small part changed. To ease updating this code, the order of functions, comments
and code style is kept largely the same as the original pathlib.py.

Yes, we know, this is playing with fire and it can break on new CPython releases.

The implementation is split up in multiple files, one for each CPython version.
You're currently looking at the CPython 3.12 implementation.

Commit hash we're in sync with:

Notes:
    - CPython 3.12 changed a lot in preparation of proper subclassing, so our patches differ
      a lot from previous versions
    - Flavours don't really exist anymore, but since we kind of "multi-flavour" we need to emulate it
"""

from __future__ import annotations

import posixpath
import sys
from pathlib import Path, PurePath
from stat import S_ISBLK, S_ISCHR, S_ISFIFO, S_ISSOCK
from typing import IO, TYPE_CHECKING, Iterator, Optional

from dissect.target import filesystem
from dissect.target.exceptions import FilesystemError, SymlinkRecursionError
from dissect.target.helpers import polypath
from dissect.target.helpers.compat.path_common import (
    io_open,
    isjunction,
    realpath,
    scandir,
)

if TYPE_CHECKING:
    from dissect.target.filesystem import Filesystem, FilesystemEntry
    from dissect.target.helpers.compat.path_common import _DissectScandirIterator
    from dissect.target.helpers.fsutil import stat_result


class _DissectFlavour:
    sep = "/"
    altsep = ""
    case_sensitive = False

    __variant_instances = {}

    def __new__(cls, case_sensitive: bool = False, alt_separator: str = ""):
        idx = (case_sensitive, alt_separator)
        instance = cls.__variant_instances.get(idx, None)
        if instance is None:
            instance = object.__new__(cls)
            cls.__variant_instances[idx] = instance

        return instance

    def __init__(self, case_sensitive: bool = False, alt_separator: str = ""):
        self.altsep = alt_separator
        self.case_sensitive = case_sensitive

    def normcase(self, s: str) -> str:
        return s if self.case_sensitive else s.lower()

    splitdrive = staticmethod(posixpath.splitdrive)

    def splitroot(self, part: str) -> tuple[str, str]:
        return polypath.splitroot(part, alt_separator=self.altsep)

    def join(self, *args) -> str:
        return polypath.join(*args, alt_separator=self.altsep)

    # NOTE: Fallback implementation from older versions of pathlib.py
    def ismount(self, path: TargetPath) -> bool:
        # Need to exist and be a dir
        if not path.exists() or not path.is_dir():
            return False

        try:
            parent_dev = path.parent.stat().st_dev
        except FilesystemError:
            return False

        dev = path.stat().st_dev
        if dev != parent_dev:
            return True
        ino = path.stat().st_ino
        parent_ino = path.parent.stat().st_ino
        return ino == parent_ino

    isjunction = staticmethod(isjunction)

    samestat = staticmethod(posixpath.samestat)

    def isabs(self, path: str) -> bool:
        return polypath.isabs(path, alt_separator=self.altsep)

    realpath = staticmethod(realpath)


class PureDissectPath(PurePath):
    _fs: Filesystem
    _flavour = _DissectFlavour(case_sensitive=False)

    def __reduce__(self) -> tuple:
        raise TypeError("TargetPath pickling is currently not supported")

    def __init__(self, fs: Filesystem, *pathsegments):
        if not isinstance(fs, filesystem.Filesystem):
            raise TypeError(
                "invalid PureDissectPath initialization: missing filesystem, "
                "got %r (this might be a bug, please report)" % pathsegments
            )

        alt_separator = fs.alt_separator
        path_args = []
        for arg in pathsegments:
            if isinstance(arg, str):
                arg = polypath.normalize(arg, alt_separator=alt_separator)
            path_args.append(arg)

        super().__init__(*path_args)
        self._fs = fs
        self._flavour = _DissectFlavour(alt_separator=fs.alt_separator, case_sensitive=fs.case_sensitive)

    def with_segments(self, *pathsegments) -> TargetPath:
        return type(self)(self._fs, *pathsegments)

    # NOTE: This is copied from pathlib.py but turned into an instance method so we get access to the correct flavour
    def _parse_path(self, path: str) -> tuple[str, str, list[str]]:
        if not path:
            return "", "", []
        sep = self._flavour.sep
        altsep = self._flavour.altsep
        if altsep:
            path = path.replace(altsep, sep)
        drv, root, rel = self._flavour.splitroot(path)
        if not root and drv.startswith(sep) and not drv.endswith(sep):
            drv_parts = drv.split(sep)
            if len(drv_parts) == 4 and drv_parts[2] not in "?.":
                # e.g. //server/share
                root = sep
            elif len(drv_parts) == 6:
                # e.g. //?/unc/server/share
                root = sep
        parsed = [sys.intern(str(x)) for x in rel.split(sep) if x and x != "."]
        return drv, root, parsed

    def is_reserved(self) -> bool:
        """Return True if the path contains one of the special names reserved
        by the system, if any."""
        return False


class TargetPath(Path, PureDissectPath):
    __slots__ = ("_entry",)

    def get(self) -> FilesystemEntry:
        try:
            return self._entry
        except AttributeError:
            self._entry = self._fs.get(str(self))
            return self._entry

    def stat(self, *, follow_symlinks: bool = True) -> stat_result:
        """
        Return the result of the stat() system call on this path, like
        os.stat() does.
        """
        if follow_symlinks:
            return self.get().stat()
        else:
            return self.get().lstat()

    def exists(self, *, follow_symlinks: bool = True) -> bool:
        """
        Whether this path exists.

        This method normally follows symlinks; to check whether a symlink exists,
        add the argument follow_symlinks=False.
        """
        try:
            # .exists() must resolve possible symlinks
            self.stat(follow_symlinks=follow_symlinks)
            return True
        except (FilesystemError, ValueError):
            return False

    def is_dir(self) -> bool:
        """
        Whether this path is a directory.
        """
        try:
            return self.get().is_dir()
        except (FilesystemError, ValueError):
            return False

    def is_file(self) -> bool:
        """
        Whether this path is a regular file (also True for symlinks pointing
        to regular files).
        """
        try:
            return self.get().is_file()
        except (FilesystemError, ValueError):
            return False

    def is_symlink(self) -> bool:
        """
        Whether this path is a symbolic link.
        """
        try:
            return self.get().is_symlink()
        except (FilesystemError, ValueError):
            return False

    def is_block_device(self) -> bool:
        """
        Whether this path is a block device.
        """
        try:
            return S_ISBLK(self.stat().st_mode)
        except (FilesystemError, ValueError):
            return False

    def is_char_device(self) -> bool:
        """
        Whether this path is a character device.
        """
        try:
            return S_ISCHR(self.stat().st_mode)
        except (FilesystemError, ValueError):
            return False

    def is_fifo(self) -> bool:
        """
        Whether this path is a FIFO.
        """
        try:
            return S_ISFIFO(self.stat().st_mode)
        except (FilesystemError, ValueError):
            return False

    def is_socket(self) -> bool:
        """
        Whether this path is a socket.
        """
        try:
            return S_ISSOCK(self.stat().st_mode)
        except (FilesystemError, ValueError):
            return False

    def open(
        self,
        mode: str = "rb",
        buffering: int = 0,
        encoding: Optional[str] = None,
        errors: Optional[str] = None,
        newline: Optional[str] = None,
    ) -> IO:
        """Open file and return a stream.

        Supports a subset of features of the real pathlib.open/io.open.

        Note: in contrast to regular Python, the mode is binary by default. Text mode
        has to be explicitly specified. Buffering is also disabled by default.
        """
        return io_open(self, mode, buffering, encoding, errors, newline)

    def write_bytes(self, data: bytes) -> int:
        """
        Open the file in bytes mode, write to it, and close the file.
        """
        raise NotImplementedError("TargetPath.write_bytes() is unsupported")

    def write_text(
        self, data: str, encoding: Optional[str] = None, errors: Optional[str] = None, newline: Optional[str] = None
    ) -> int:
        """
        Open the file in text mode, write to it, and close the file.
        """
        raise NotImplementedError("TargetPath.write_text() is unsupported")

    def iterdir(self) -> Iterator[TargetPath]:
        """Iterate over the files in this directory.  Does not yield any
        result for the special paths '.' and '..'.
        """
        for entry in scandir(self):
            if entry.name in {".", ".."}:
                # Yielding a path object for these makes little sense
                continue
            child_path = self._make_child_relpath(entry.name)
            child_path._entry = entry
            yield child_path

    def _scandir(self) -> _DissectScandirIterator:
        return scandir(self)

    @classmethod
    def cwd(cls) -> TargetPath:
        """Return a new path pointing to the current working directory."""
        raise NotImplementedError("TargetPath.cwd() is unsupported")

    @classmethod
    def home(cls) -> TargetPath:
        """Return a new path pointing to the user's home directory (as
        returned by os.path.expanduser('~')).
        """
        raise NotImplementedError("TargetPath.home() is unsupported")

    def absolute(self) -> TargetPath:
        """Return an absolute version of this path by prepending the current
        working directory. No normalization or symlink resolution is performed.

        Use resolve() to get the canonical path to a file.
        """
        raise NotImplementedError("TargetPath.absolute() is unsupported in Dissect")

    # NOTE: We changed some of the error handling here to deal with our own exception types
    def resolve(self, strict: bool = False) -> TargetPath:
        """
        Make the path absolute, resolving all symlinks on the way and also
        normalizing it.
        """

        s = self._flavour.realpath(self, strict=strict)
        p = self.with_segments(s)

        # In non-strict mode, realpath() doesn't raise on symlink loops.
        # Ensure we get an exception by calling stat()
        if not strict:
            try:
                p.stat()
            except FilesystemError as e:
                if isinstance(e, SymlinkRecursionError):
                    raise
        return p

    def owner(self) -> str:
        """
        Return the login name of the file owner.
        """
        raise NotImplementedError("TargetPath.owner() is unsupported")

    def group(self) -> str:
        """
        Return the group name of the file gid.
        """
        raise NotImplementedError("TargetPath.group() is unsupported")

    def readlink(self) -> TargetPath:
        """
        Return the path to which the symbolic link points.
        """
        return self.with_segments(self.get().readlink())

    def touch(self, mode: int = 0o666, exist_ok: bool = True) -> None:
        """
        Create this file with the given access mode, if it doesn't exist.
        """
        raise NotImplementedError("TargetPath.touch() is unsupported")

    def mkdir(self, mode: int = 0o777, parents: bool = False, exist_ok: bool = False) -> None:
        """
        Create a new directory at this given path.
        """
        raise NotImplementedError("TargetPath.mkdir() is unsupported")

    def chmod(self, mode: int, *, follow_symlinks: bool = True) -> None:
        """
        Change the permissions of the path, like os.chmod().
        """
        raise NotImplementedError("TargetPath.chmod() is unsupported")

    def lchmod(self, mode: int) -> None:
        """
        Like chmod(), except if the path points to a symlink, the symlink's
        permissions are changed, rather than its target's.
        """
        raise NotImplementedError("TargetPath.lchmod() is unsupported")

    def unlink(self, missing_ok: bool = False) -> None:
        """
        Remove this file or link.
        If the path is a directory, use rmdir() instead.
        """
        raise NotImplementedError("TargetPath.unlink() is unsupported")

    def rmdir(self) -> None:
        """
        Remove this directory.  The directory must be empty.
        """
        raise NotImplementedError("TargetPath.rmdir() is unsupported")

    def rename(self, target: str) -> TargetPath:
        """
        Rename this path to the target path.

        The target path may be absolute or relative. Relative paths are
        interpreted relative to the current working directory, *not* the
        directory of the Path object.

        Returns the new Path instance pointing to the target path.
        """
        raise NotImplementedError("TargetPath.rename() is unsupported")

    def replace(self, target: str) -> TargetPath:
        """
        Rename this path to the target path, overwriting if that path exists.

        The target path may be absolute or relative. Relative paths are
        interpreted relative to the current working directory, *not* the
        directory of the Path object.

        Returns the new Path instance pointing to the target path.
        """
        raise NotImplementedError("TargetPath.replace() is unsupported")

    def symlink_to(self, target: str, target_is_directory: bool = False) -> None:
        """
        Make this path a symlink pointing to the target path.
        Note the order of arguments (link, target) is the reverse of os.symlink.
        """
        raise NotImplementedError("TargetPath.symlink_to() is unsupported")

    def hardlink_to(self, target: str) -> None:
        """
        Make this path a hard link pointing to the same file as *target*.

        Note the order of arguments (self, target) is the reverse of os.link's.
        """
        raise NotImplementedError("TargetPath.hardlink_to() is unsupported")

    def expanduser(self) -> TargetPath:
        """Return a new path with expanded ~ and ~user constructs
        (as returned by os.path.expanduser)
        """
        raise NotImplementedError("TargetPath.expanduser() is unsupported")
