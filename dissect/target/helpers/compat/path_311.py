"""A pathlib.Path compatible implementation for dissect.target.

This allows for the majority of the pathlib.Path API to "just work" on dissect.target filesystems.

Most of this consists of subclassed internal classes with dissect.target specific patches,
but sometimes the change to a function is small, so the entire internal function is copied
and only a small part changed. To ease updating this code, the order of functions, comments
and code style is kept largely the same as the original pathlib.py.

Yes, we know, this is playing with fire and it can break on new CPython releases.

The implementation is split up in multiple files, one for each CPython version.
You're currently looking at the CPython 3.11 implementation.

Commit hash we're in sync with: 846a23d

Notes:
    - CPython 3.11 ditched the _Accessor class, so we override the methods that should use it
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path, PurePath, _PosixFlavour
from typing import IO, TYPE_CHECKING, Any, Callable, ClassVar

from dissect.target import filesystem
from dissect.target.exceptions import FilesystemError, SymlinkRecursionError
from dissect.target.helpers import polypath
from dissect.target.helpers.compat import path_common

if TYPE_CHECKING:
    from collections.abc import Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem, FilesystemEntry
    from dissect.target.helpers.fsutil import stat_result


class _DissectFlavour(_PosixFlavour):
    is_supported = True

    __variant_instances: ClassVar[dict[tuple[bool, str], _DissectFlavour]] = {}

    def __new__(cls, case_sensitive: bool = False, alt_separator: str = ""):
        idx = (case_sensitive, alt_separator)
        instance = cls.__variant_instances.get(idx, None)
        if instance is None:
            instance = _PosixFlavour.__new__(cls)
            cls.__variant_instances[idx] = instance

        return instance

    def __init__(self, case_sensitive: bool = False, alt_separator: str = ""):
        super().__init__()
        self.altsep = alt_separator
        self.case_sensitive = case_sensitive

    def casefold(self, s: str) -> str:
        return s if self.case_sensitive else s.lower()

    def casefold_parts(self, parts: list[str]) -> list[str]:
        return parts if self.case_sensitive else [p.lower() for p in parts]

    def compile_pattern(self, pattern: str) -> Callable[..., Any]:
        return re.compile(fnmatch.translate(pattern), 0 if self.case_sensitive else re.IGNORECASE).fullmatch

    def is_reserved(self, parts: list[str]) -> bool:
        return False


class PureDissectPath(PurePath):
    _fs: Filesystem
    _flavour = _DissectFlavour(case_sensitive=False)

    def __reduce__(self) -> tuple:
        raise TypeError("TargetPath pickling is currently not supported")

    @classmethod
    def _from_parts(cls, args: list) -> Self:
        fs = args[0]

        if not isinstance(fs, filesystem.Filesystem):
            raise TypeError(
                "invalid PureDissectPath initialization: missing filesystem, "
                f"got {args!r} (this might be a bug, please report)"
            )

        alt_separator = fs.alt_separator
        path_args = []
        for arg in args[1:]:
            if isinstance(arg, str):
                arg = polypath.normalize(arg, alt_separator=alt_separator)
            path_args.append(arg)

        self = super()._from_parts(path_args)
        self._fs = fs

        self._flavour = _DissectFlavour(alt_separator=fs.alt_separator, case_sensitive=fs.case_sensitive)

        return self

    def _make_child(self, args: list) -> Self:
        child = super()._make_child(args)
        child._fs = self._fs
        child._flavour = self._flavour
        return child

    def with_name(self, name: str) -> Self:
        result = super().with_name(name)
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    def with_stem(self, stem: str) -> Self:
        result = super().with_stem(stem)
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    def with_suffix(self, suffix: str) -> Self:
        result = super().with_suffix(suffix)
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    def relative_to(self, *other) -> Self:
        result = super().relative_to(*other)
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    def __rtruediv__(self, key: str) -> Self:
        try:
            return self._from_parts([self._fs, key, *self._parts])
        except TypeError:
            return NotImplemented

    @property
    def parent(self) -> Self:
        result = super().parent
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    @property
    def parents(self) -> path_common._DissectPathParents:
        return path_common._DissectPathParents(self)


class TargetPath(Path, PureDissectPath):
    __slots__ = ("_entry",)

    def _make_child_relpath(self, part: str) -> Self:
        child = super()._make_child_relpath(part)
        child._fs = self._fs
        child._flavour = self._flavour
        return child

    def get(self) -> FilesystemEntry:
        try:
            return self._entry
        except AttributeError:
            self._entry = self._fs.get(str(self))
            return self._entry

    @classmethod
    def cwd(cls) -> Self:
        """Return a new path pointing to the current working directory
        (as returned by os.getcwd()).
        """
        raise NotImplementedError("TargetPath.cwd() is unsupported")

    @classmethod
    def home(cls) -> Self:
        """Return a new path pointing to the user's home directory (as
        returned by os.path.expanduser('~')).
        """
        raise NotImplementedError("TargetPath.home() is unsupported")

    def iterdir(self) -> Iterator[Self]:
        """Iterate over the files in this directory.  Does not yield any
        result for the special paths '.' and '..'.
        """
        for entry in path_common.scandir(self):
            if entry.name in {".", ".."}:
                # Yielding a path object for these makes little sense
                continue
            child_path = self._make_child_relpath(entry.name)
            child_path._entry = entry
            yield child_path

    def _scandir(self) -> path_common._DissectScandirIterator:
        return path_common.scandir(self)

    # NOTE: Forward compatibility with CPython >= 3.12
    def walk(
        self, top_down: bool = True, on_error: Callable[[Exception], None] | None = None, follow_symlinks: bool = False
    ) -> Iterator[tuple[Self, list[str], list[str]]]:
        """Walk the directory tree from this directory, similar to os.walk()."""
        paths = [self]

        while paths:
            path = paths.pop()
            if isinstance(path, tuple):
                yield path
                continue

            # We may not have read permission for self, in which case we can't
            # get a list of the files the directory contains. os.walk()
            # always suppressed the exception in that instance, rather than
            # blow up for a minor reason when (say) a thousand readable
            # directories are still left to visit. That logic is copied here.
            try:
                scandir_it = path._scandir()
            except OSError as e:
                if on_error is not None:
                    on_error(e)
                continue

            with scandir_it:
                dirnames = []
                filenames = []
                for entry in scandir_it:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=follow_symlinks)
                    except OSError:
                        # Carried over from os.path.isdir().
                        is_dir = False

                    if is_dir:
                        dirnames.append(entry.name)
                    else:
                        filenames.append(entry.name)

            if top_down:
                yield path, dirnames, filenames
            else:
                paths.append((path, dirnames, filenames))

            paths += [path._make_child_relpath(d) for d in reversed(dirnames)]

    def absolute(self) -> Self:
        """Return an absolute version of this path.  This function works
        even if the path doesn't point to anything.

        No normalization is done, i.e. all '.' and '..' will be kept along.
        Use resolve() to get the canonical path to a file.
        """
        raise NotImplementedError("TargetPath.absolute() is unsupported in Dissect")

    # NOTE: We changed some of the error handling here to deal with our own exception types
    def resolve(self, strict: bool = False) -> Self:
        """
        Make the path absolute, resolving all symlinks on the way and also
        normalizing it.
        """

        s = path_common.realpath(self, strict=strict)
        p = self._from_parts((self._fs, s))

        # In non-strict mode, realpath() doesn't raise on symlink loops.
        # Ensure we get an exception by calling stat()
        if not strict:
            try:
                p.stat()
            except FilesystemError as e:
                if isinstance(e, SymlinkRecursionError):
                    raise
        return p

    def stat(self, *, follow_symlinks: bool = True) -> stat_result:
        """
        Return the result of the stat() system call on this path, like
        os.stat() does.
        """
        if follow_symlinks:
            return self.get().stat()
        return self.get().lstat()

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
        raise NotImplementedError("TargetPath.write_bytes() is unsupported")

    def write_text(
        self, data: str, encoding: str | None = None, errors: str | None = None, newline: str | None = None
    ) -> int:
        """
        Open the file in text mode, write to it, and close the file.
        """
        raise NotImplementedError("TargetPath.write_text() is unsupported")

    def readlink(self) -> Self:
        """
        Return the path to which the symbolic link points.
        """
        return self._from_parts((self._fs, self.get().readlink()))

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

    def rename(self, target: str) -> Self:
        """
        Rename this path to the target path.

        The target path may be absolute or relative. Relative paths are
        interpreted relative to the current working directory, *not* the
        directory of the Path object.

        Returns the new Path instance pointing to the target path.
        """
        raise NotImplementedError("TargetPath.rename() is unsupported")

    def replace(self, target: str) -> Self:
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

    def link_to(self, target: str) -> None:
        """
        Make the target path a hard link pointing to this path.

        Note this function does not make this path a hard link to *target*,
        despite the implication of the function and argument names. The order
        of arguments (target, link) is the reverse of Path.symlink_to, but
        matches that of os.link.

        Deprecated since Python 3.10 and scheduled for removal in Python 3.12.
        Use `hardlink_to()` instead.
        """
        raise NotImplementedError("TargetPath.link_to() is unsupported")

    def is_mount(self) -> bool:
        """
        Check if this path is a POSIX mount point
        """
        # Need to exist and be a dir
        if not self.exists() or not self.is_dir():
            return False

        try:
            parent_dev = self.parent.stat().st_dev
        except FilesystemError:
            return False

        dev = self.stat().st_dev
        if dev != parent_dev:
            return True
        ino = self.stat().st_ino
        parent_ino = self.parent.stat().st_ino
        return ino == parent_ino

    # NOTE: Forward compatibility with CPython >= 3.12
    def is_junction(self) -> bool:
        """
        Whether this path is a junction.
        """
        return path_common.isjunction(self)

    def expanduser(self) -> Self:
        """Return a new path with expanded ~ and ~user constructs
        (as returned by os.path.expanduser)
        """
        raise NotImplementedError("TargetPath.expanduser() is unsupported")
