"""A pathlib.Path compatible implementation for dissect.target.

This allows for the majority of the pathlib.Path API to "just work" on dissect.target filesystems.

Most of this consists of subclassed internal classes with dissect.target specific patches,
but sometimes the change to a function is small, so the entire internal function is copied
and only a small part changed. To ease updating this code, the order of functions, comments
and code style is kept largely the same as the original pathlib.py.

Yes, we know, this is playing with fire and it can break on new CPython releases.

The implementation is split up in multiple files, one for each CPython version.
You're currently looking at the CPython 3.13 implementation.

Commit hash we're in sync with: 094d95f

Notes:
    - https://docs.python.org/3.13/whatsnew/3.13.html#pathlib
    - https://github.com/python/cpython/blob/3.13/Lib/pathlib/_local.py
"""

from __future__ import annotations

import posixpath
import sys
from glob import _Globber
from pathlib import Path, PurePath
from pathlib._abc import PathBase, UnsupportedOperation
from typing import IO, TYPE_CHECKING, Callable, ClassVar

from dissect.target import filesystem
from dissect.target.exceptions import FilesystemError, SymlinkRecursionError
from dissect.target.helpers import polypath
from dissect.target.helpers.compat import path_common

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem, FilesystemEntry
    from dissect.target.helpers.fsutil import stat_result


class _DissectParser:
    sep = "/"
    altsep = ""
    case_sensitive = False

    __variant_instances: ClassVar[dict[tuple[bool, str], _DissectParser]] = {}

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

    def split(self, part: str) -> tuple[str, str]:
        return polypath.split(part, alt_separator=self.altsep)

    splitdrive = staticmethod(posixpath.splitdrive)

    def splitroot(self, part: str) -> tuple[str, str, str]:
        return polypath.splitroot(part, alt_separator=self.altsep)

    def join(self, *args) -> str:
        return polypath.join(*args, alt_separator=self.altsep)

    isjunction = staticmethod(path_common.isjunction)

    def isabs(self, path: str) -> bool:
        return polypath.isabs(str(path), alt_separator=self.altsep)

    realpath = staticmethod(path_common.realpath)


class _DissectGlobber(_Globber):
    @staticmethod
    def add_slash(path: TargetPath) -> TargetPath:
        return _GlobberTargetPath(path._fs, path, "")


class PureDissectPath(PurePath):
    _fs: Filesystem
    parser: _DissectParser = _DissectParser(case_sensitive=False)
    _globber = _DissectGlobber

    def __reduce__(self) -> tuple:
        raise TypeError("TargetPath pickling is currently not supported")

    def __init__(self, fs: Filesystem, *pathsegments):
        if not isinstance(fs, filesystem.Filesystem):
            raise TypeError(
                "invalid PureDissectPath initialization: missing filesystem, "
                "got {!r} (this might be a bug, please report)".format(fs, *pathsegments)
            )

        alt_separator = fs.alt_separator
        path_args = []
        for arg in pathsegments:
            if isinstance(arg, str):
                arg = polypath.normalize(arg, alt_separator=alt_separator)
            path_args.append(arg)

        super().__init__(*path_args)
        self._fs = fs
        self.parser = _DissectParser(alt_separator=fs.alt_separator, case_sensitive=fs.case_sensitive)

    def with_segments(self, *pathsegments) -> Self:
        return type(self)(self._fs, *pathsegments)

    # NOTE: This is copied from pathlib/_local.py
    # but turned into an instance method so we get access to the correct flavour
    def _parse_path(self, path: str) -> tuple[str, str, list[str]]:
        if not path:
            return "", "", []
        sep = self.parser.sep
        altsep = self.parser.altsep
        if altsep:
            path = path.replace(altsep, sep)
        drv, root, rel = self.parser.splitroot(path)
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


class TargetPath(Path, PureDissectPath):
    __slots__ = ("_entry",)

    @classmethod
    def _unsupported_msg(cls, attribute: str) -> str:
        return f"{cls.__name__}.{attribute} is unsupported"

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
        except (FilesystemError, ValueError):
            return False
        else:
            return True

    is_mount = PathBase.is_mount

    def is_junction(self) -> bool:
        """
        Whether this path is a junction.
        """
        return self.parser.isjunction(self)

    def open(
        self,
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
        return path_common.io_open(self, mode, buffering, encoding, errors, newline)

    def write_bytes(self, data: bytes) -> int:
        """
        Open the file in bytes mode, write to it, and close the file.
        """
        raise UnsupportedOperation(self._unsupported_msg("write_bytes()"))

    def write_text(
        self, data: str, encoding: str | None = None, errors: str | None = None, newline: str | None = None
    ) -> int:
        """
        Open the file in text mode, write to it, and close the file.
        """
        raise UnsupportedOperation(self._unsupported_msg("write_text()"))

    def iterdir(self) -> Iterator[Self]:
        """Yield path objects of the directory contents.

        The children are yielded in arbitrary order, and the
        special entries '.' and '..' are not included.
        """
        with path_common.scandir(self) as scandir_it:
            for entry in scandir_it:
                name = entry.name
                child_path = self.joinpath(name)
                child_path._entry = entry
                yield child_path

    def glob(
        self, pattern: str, *, case_sensitive: bool | None = None, recurse_symlinks: bool = False
    ) -> Iterator[Self]:
        """Iterate over this subtree and yield all existing files (of any
        kind, including directories) matching the given relative pattern.
        """
        return PathBase.glob(self, pattern, case_sensitive=case_sensitive, recurse_symlinks=recurse_symlinks)

    def rglob(
        self, pattern: str, *, case_sensitive: bool | None = None, recurse_symlinks: str = False
    ) -> Iterator[Self]:
        """Recursively yield all existing files (of any kind, including
        directories) matching the given relative pattern, anywhere in
        this subtree.
        """
        return PathBase.rglob(self, pattern, case_sensitive=case_sensitive, recurse_symlinks=recurse_symlinks)

    def walk(
        self, top_down: bool = True, on_error: Callable[[Exception], None] | None = None, follow_symlinks: bool = False
    ) -> Iterator[tuple[Self, list[str], list[str]]]:
        """Walk the directory tree from this directory, similar to os.walk()."""
        return PathBase.walk(self, top_down=top_down, on_error=on_error, follow_symlinks=follow_symlinks)

    def absolute(self) -> Self:
        """Return an absolute version of this path
        No normalization or symlink resolution is performed.

        Use resolve() to resolve symlinks and remove '..' segments.
        """
        raise UnsupportedOperation(self._unsupported_msg("absolute()"))

    @classmethod
    def cwd(cls) -> Self:
        """Return a new path pointing to the current working directory."""
        raise UnsupportedOperation(cls._unsupported_msg("cwd()"))

    def expanduser(self) -> Self:
        """Return a new path with expanded ~ and ~user constructs
        (as returned by os.path.expanduser)
        """
        raise UnsupportedOperation(self._unsupported_msg("expanduser()"))

    @classmethod
    def home(cls) -> Self:
        """Return a new path pointing to the user's home directory (as
        returned by os.path.expanduser('~')).
        """
        raise UnsupportedOperation(cls._unsupported_msg("home()"))

    def readlink(self) -> Self:
        """
        Return the path to which the symbolic link points.
        """
        return self.with_segments(self.get().readlink())

    # NOTE: We changed some of the error handling here to deal with our own exception types
    def resolve(self, strict: bool = False) -> Self:
        """
        Make the path absolute, resolving all symlinks on the way and also
        normalizing it.
        """

        s = self.parser.realpath(self, strict=strict)
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

    def symlink_to(self, target: str, target_is_directory: bool = False) -> None:
        """
        Make this path a symlink pointing to the target path.
        Note the order of arguments (link, target) is the reverse of os.symlink.
        """
        raise UnsupportedOperation(self._unsupported_msg("symlink_to()"))

    def hardlink_to(self, target: str) -> None:
        """
        Make this path a hard link pointing to the same file as *target*.

        Note the order of arguments (self, target) is the reverse of os.link's.
        """
        raise UnsupportedOperation(self._unsupported_msg("hardlink_to()"))

    def touch(self, mode: int = 0o666, exist_ok: bool = True) -> None:
        """
        Create this file with the given access mode, if it doesn't exist.
        """
        raise UnsupportedOperation(self._unsupported_msg("touch()"))

    def mkdir(self, mode: int = 0o777, parents: bool = False, exist_ok: bool = False) -> None:
        """
        Create a new directory at this given path.
        """
        raise UnsupportedOperation(self._unsupported_msg("mkdir()"))

    def rename(self, target: str) -> Self:
        """
        Rename this path to the target path.

        The target path may be absolute or relative. Relative paths are
        interpreted relative to the current working directory, *not* the
        directory of the Path object.

        Returns the new Path instance pointing to the target path.
        """
        raise UnsupportedOperation(self._unsupported_msg("rename()"))

    def replace(self, target: str) -> Self:
        """
        Rename this path to the target path, overwriting if that path exists.

        The target path may be absolute or relative. Relative paths are
        interpreted relative to the current working directory, *not* the
        directory of the Path object.

        Returns the new Path instance pointing to the target path.
        """
        raise UnsupportedOperation(self._unsupported_msg("replace()"))

    def chmod(self, mode: int, *, follow_symlinks: bool = True) -> None:
        """
        Change the permissions of the path, like os.chmod().
        """
        raise UnsupportedOperation(self._unsupported_msg("chmod()"))

    def lchmod(self, mode: int) -> None:
        """
        Like chmod(), except if the path points to a symlink, the symlink's
        permissions are changed, rather than its target's.
        """
        raise UnsupportedOperation(self._unsupported_msg("lchmod()"))

    def unlink(self, missing_ok: bool = False) -> None:
        """
        Remove this file or link.
        If the path is a directory, use rmdir() instead.
        """
        raise UnsupportedOperation(self._unsupported_msg("unlink()"))

    def rmdir(self) -> None:
        """
        Remove this directory.  The directory must be empty.
        """
        raise UnsupportedOperation(self._unsupported_msg("rmdir()"))

    def owner(self) -> str:
        """
        Return the login name of the file owner.
        """
        raise UnsupportedOperation(self._unsupported_msg("owner()"))

    def group(self) -> str:
        """
        Return the group name of the file gid.
        """
        raise UnsupportedOperation(self._unsupported_msg("group()"))


class _GlobberTargetPath(TargetPath):
    def __str__(self) -> str:
        # This is necessary because the _Globber class expects an added `/` at the end
        # However, only PurePathBase properly adds that, PurePath doesn't
        # We do want to operate on Path objects rather than strings, so do a little hack here
        return self._raw_path
