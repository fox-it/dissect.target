"""A pathlib.Path compatible implementation for dissect.target.

This allows for the majority of the pathlib.Path API to "just work" on dissect.target filesystems.

Most of this consists of subclassed internal classes with dissect.target specific patches,
but sometimes the change to a function is small, so the entire internal function is copied
and only a small part changed. To ease updating this code, the order of functions, comments
and code style is kept largely the same as the original pathlib.py.

Yes, we know, this is playing with fire and it can break on new CPython releases.

The implementation is split up in multiple files, one for each CPython version.
You're currently looking at the CPython 3.14 implementation.

Commit hash we're in sync with: f59236b

Notes:
    - https://docs.python.org/3.14/whatsnew/3.14.html#pathlib
    - https://github.com/python/cpython/blob/3.14/Lib/pathlib/_local.py
"""

from __future__ import annotations

import posixpath
from glob import _no_recurse_symlinks, _PathGlobber
from pathlib import Path, PurePath, UnsupportedOperation
from pathlib._os import DirEntryInfo, _PosixPathInfo
from pathlib.types import _ReadablePath
from stat import S_ISDIR, S_ISLNK, S_ISREG
from typing import IO, TYPE_CHECKING, ClassVar

from dissect.target import filesystem
from dissect.target.exceptions import FilesystemError, SymlinkRecursionError
from dissect.target.helpers import polypath
from dissect.target.helpers.compat import path_common

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

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


class PureDissectPath(PurePath):
    _fs: Filesystem
    parser: _DissectParser = _DissectParser(case_sensitive=False)

    def __reduce__(self) -> tuple:
        raise TypeError("TargetPath pickling is currently not supported")

    def __init__(self, fs: Filesystem, *args):
        if not isinstance(fs, filesystem.Filesystem):
            raise TypeError(
                "invalid PureDissectPath initialization: missing filesystem, "
                "got {!r} (this might be a bug, please report)".format(fs, *args)
            )

        self._fs = fs
        self.parser = _DissectParser(alt_separator=fs.alt_separator, case_sensitive=fs.case_sensitive)
        super().__init__(
            *[polypath.normalize(arg, alt_separator=fs.alt_separator) if isinstance(arg, str) else arg for arg in args]
        )

    def with_segments(self, *pathsegments) -> Self:
        return type(self)(self._fs, *pathsegments)

    # NOTE: This is copied from pathlib/__init__.py
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
        return drv, root, [x for x in rel.split(sep) if x and x != "."]

    # NOTE: This is copied from pathlib/__init__.py
    # but turned into an instance method so we get access to the correct flavour
    def _parse_pattern(self, pattern: str) -> list[str]:
        """Parse a glob pattern to a list of parts. This is much like
        _parse_path, except:

        - Rather than normalizing and returning the drive and root, we raise
          NotImplementedError if either are present.
        - If the path has no real parts, we raise ValueError.
        - If the path ends in a slash, then a final empty part is added.
        """
        drv, root, rel = self.parser.splitroot(pattern)
        if root or drv:
            raise NotImplementedError("Non-relative patterns are unsupported")
        sep = self.parser.sep
        altsep = self.parser.altsep
        if altsep:
            rel = rel.replace(altsep, sep)
        parts = [x for x in rel.split(sep) if x and x != "."]
        if not parts:
            raise ValueError(f"Unacceptable pattern: {str(pattern)!r}")
        if rel.endswith(sep):
            # GH-65238: preserve trailing slash in glob patterns.
            parts.append("")
        return parts


class TargetPath(Path, PureDissectPath):
    __slots__ = ("_direntry", "_entry")

    @classmethod
    def _unsupported_msg(cls, attribute: str) -> str:
        return f"{cls.__name__}.{attribute} is unsupported"

    def get(self) -> FilesystemEntry:
        """Return the :class:`FilesystemEntry` for this path."""
        if not hasattr(self, "_entry"):
            self._entry = self._direntry.get() if hasattr(self, "_direntry") else self._fs.get(str(self))
        return self._entry

    @property
    def info(self) -> TargetPathInfo:
        """
        A PathInfo object that exposes the file type and other file attributes
        of this path.
        """
        try:
            return self._info
        except AttributeError:
            self._info = TargetPathInfo(self)
            return self._info

    def stat(self, *, follow_symlinks: bool = True) -> stat_result:
        """
        Return the result of the stat() system call on this path, like
        os.stat() does.
        """
        if follow_symlinks:
            return self.get().stat()
        return self.get().lstat()

    def lstat(self) -> stat_result:
        """
        Like stat(), except if the path points to a symlink, the symlink's
        status information is returned, rather than its target's.
        """
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

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        """
        Whether this path is a directory.
        """
        try:
            return S_ISDIR(self.stat(follow_symlinks=follow_symlinks).st_mode)
        except (OSError, ValueError):
            return False

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        """
        Whether this path is a regular file (also True for symlinks pointing
        to regular files).
        """
        try:
            return S_ISREG(self.stat(follow_symlinks=follow_symlinks).st_mode)
        except (OSError, ValueError):
            return False

    def is_mount(self) -> bool:
        """
        Check if this path is a mount point
        """
        # Need to exist and be a dir
        if not self.exists() or not self.is_dir():
            return False

        try:
            parent_dev = self.parent.stat().st_dev
        except OSError:
            return False

        dev = self.stat().st_dev
        if dev != parent_dev:
            return True
        ino = self.stat().st_ino
        parent_ino = self.parent.stat().st_ino
        return ino == parent_ino

    def is_symlink(self) -> bool:
        """
        Whether this path is a symbolic link.
        """
        try:
            return S_ISLNK(self.lstat().st_mode)
        except (OSError, ValueError):
            return False

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

    # NOTE: Pathlib originally takes the DirEntry path as the new name,
    # but since we're not very consistent on that (yet), we change this to use joinpath instead
    def _from_dir_entry(self, dir_entry: filesystem.DirEntry, name: str) -> Self:
        path = self.joinpath(name)
        path._info = DirEntryInfo(dir_entry)
        path._direntry = dir_entry
        return path

    def iterdir(self) -> Iterator[Self]:
        """Yield path objects of the directory contents.

        The children are yielded in arbitrary order, and the
        special entries '.' and '..' are not included.
        """
        with path_common.scandir(self) as scandir_it:
            entries = list(scandir_it)
        # NOTE: We pass the entry name here instead of the path
        return (self._from_dir_entry(e, e.name) for e in entries)

    def _reset_class(self, paths: Iterator[_GlobberTargetPath]) -> Iterator[Self]:
        for p in paths:
            p.__class__ = self.__class__
            yield p

    def glob(
        self, pattern: str, *, case_sensitive: bool | None = None, recurse_symlinks: bool = False
    ) -> Iterator[Self]:
        """Iterate over this subtree and yield all existing files (of any
        kind, including directories) matching the given relative pattern.
        """
        if case_sensitive is None:
            case_sensitive = self._fs.case_sensitive
            case_pedantic = False
        else:
            # The user has expressed a case sensitivity choice, but we don't
            # know the case sensitivity of the underlying filesystem, so we
            # must use scandir() for everything, including non-wildcard parts.
            case_pedantic = True
        parts = self._parse_pattern(pattern)
        recursive = True if recurse_symlinks else _no_recurse_symlinks
        globber = _DissectGlobber(self.parser.sep, case_sensitive, case_pedantic, recursive)
        select = globber.selector(parts[::-1])
        paths = select(globber.concat_path(self, "/"))
        return self._reset_class(paths)

    def walk(
        self, top_down: bool = True, on_error: Callable[[Exception], None] | None = None, follow_symlinks: bool = False
    ) -> Iterator[tuple[Self, list[str], list[str]]]:
        """Walk the directory tree from this directory, similar to os.walk()."""
        return _ReadablePath.walk(self, top_down=top_down, on_error=on_error, follow_symlinks=follow_symlinks)

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

    def owner(self, *, follow_symlinks: bool = True) -> str:
        """
        Return the login name of the file owner.
        """
        raise UnsupportedOperation(self._unsupported_msg("owner()"))

    def group(self, *, follow_symlinks: bool = True) -> str:
        """
        Return the group name of the file gid.
        """
        raise UnsupportedOperation(self._unsupported_msg("group()"))

    def readlink(self) -> Self:
        """
        Return the path to which the symbolic link points.
        """
        return self.with_segments(self.get().readlink())

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

    def _delete(self) -> None:
        """
        Delete this file or directory (including all sub-directories).
        """
        raise UnsupportedOperation(self._unsupported_msg("_delete()"))

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

    def copy(self, target: str, **kwargs) -> Self:
        """
        Recursively copy this file or directory tree to the given destination.
        """
        raise UnsupportedOperation(self._unsupported_msg("copy()"))

    def copy_into(self, target_dir: str, **kwargs) -> Self:
        """
        Copy this file or directory tree into the given existing directory.
        """
        raise UnsupportedOperation(self._unsupported_msg("copy_into()"))

    def _copy_from(self, source: Path, follow_symlinks: bool = True, preserve_metadata: bool = False) -> None:
        """
        Recursively copy the given path to this path.
        """
        raise UnsupportedOperation(self._unsupported_msg("_copy_from()"))

    def _copy_from_file(self, source: Path, preserve_metadata: bool = False) -> None:
        raise UnsupportedOperation(self._unsupported_msg("_copy_from_file()"))

    def _copy_from_symlink(self, source: Path, preserve_metadata: bool = False) -> None:
        raise UnsupportedOperation(self._unsupported_msg("_copy_from_symlink()"))

    def move(self, target: str) -> Self:
        """
        Recursively move this file or directory tree to the given destination.
        """
        raise UnsupportedOperation(self._unsupported_msg("move()"))

    def move_into(self, target_dir: str) -> Self:
        """
        Move this file or directory tree into the given existing directory.
        """
        raise UnsupportedOperation(self._unsupported_msg("move_into()"))

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


class TargetPathInfo(_PosixPathInfo):
    def __init__(self, path: TargetPath):
        self._path = path

    def __repr__(self) -> str:
        return "<TargetPath.info>"

    def _stat(self, *, follow_symlinks: bool = True, ignore_errors: bool = False) -> stat_result | None:
        """Return the status as an os.stat_result, or None if stat() fails and
        ignore_errors is true."""
        if follow_symlinks:
            try:
                result = self._stat_result
            except AttributeError:
                pass
            else:
                if ignore_errors or result is not None:
                    return result
            try:
                self._stat_result = self._path.stat()
            except (OSError, ValueError):
                self._stat_result = None
                if not ignore_errors:
                    raise
            return self._stat_result

        try:
            result = self._lstat_result
        except AttributeError:
            pass
        else:
            if ignore_errors or result is not None:
                return result
        try:
            self._lstat_result = self._path.lstat()
        except (OSError, ValueError):
            self._lstat_result = None
            if not ignore_errors:
                raise
        return self._lstat_result


class _DissectGlobber(_PathGlobber):
    @staticmethod
    def concat_path(path: Path, text: str) -> _GlobberTargetPath:
        return _GlobberTargetPath(path._fs, str(path) + text)


class _GlobberTargetPath(TargetPath):
    def __str__(self) -> str:
        # This is necessary because the _GlobberBase class expects an added `/` at the end to calculate the starting
        # match position for a recursive glob
        return self._raw_path
