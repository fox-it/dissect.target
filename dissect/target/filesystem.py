from __future__ import annotations

import gzip
import io
import logging
import os
import pathlib
import stat
from collections import defaultdict
from typing import TYPE_CHECKING, Any, BinaryIO, Callable, Final

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.helpers import fsutil, hashutil
from dissect.target.helpers.lazy import import_lazy

TarFilesystem = import_lazy("dissect.target.filesystems.tar").TarFilesystem

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.target import Target

FILESYSTEMS: list[type[Filesystem]] = []
MODULE_PATH = "dissect.target.filesystems"

log = logging.getLogger(__name__)


class Filesystem:
    """Base class for filesystems."""

    # Due to lazy importing we generally can't use isinstance(), so we add a short identifying string to each class
    # This has the added benefit of having a readily available "pretty name" for each implementation
    __type__: str = None
    """A short string identifying the type of filesystem."""
    __multi_volume__: bool = False
    """Whether this filesystem supports multiple volumes (disks)."""

    def __init__(
        self,
        volume: BinaryIO | list[BinaryIO] | None = None,
        alt_separator: str = "",
        case_sensitive: bool = True,
    ) -> None:
        """The base initializer for the class.

        Args:
            volume: A volume or other file-like object associated with the filesystem.
            case_sensitive: Defines if the paths in the filesystem are case sensitive or not.
            alt_separator: The alternative separator used to distingish between directories in a path.

        Raises:
            NotImplementedError: When the internal ``__type__`` of the class is not defined.
        """
        self.volume = volume
        self.case_sensitive = case_sensitive
        self.alt_separator = alt_separator

        if self.__type__ is None:
            raise NotImplementedError(f"{self.__class__.__name__} must define __type__")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"

    def path(self, *args) -> fsutil.TargetPath:
        """Instantiate a new path-like object on this filesystem."""
        return fsutil.TargetPath(self, *args)

    @classmethod
    def detect(cls, fh: BinaryIO) -> bool:
        """Detect whether the ``fh`` file-handle is supported by this ``Filesystem`` implementation.

        The position of ``fh`` will be restored before returning.

        Args:
            fh: A file-like object, usually a disk or partition.

        Returns:
            ``True`` if ``fh`` is supported, ``False`` otherwise.
        """
        offset = fh.tell()
        try:
            fh.seek(0)
            return cls._detect(fh)
        except NotImplementedError:
            raise
        except Exception as e:
            log.warning("Failed to detect %s filesystem", cls.__type__)
            log.debug("", exc_info=e)
        finally:
            fh.seek(offset)

        return False

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        """Detect whether the ``fh`` file-handle is supported by this ``Filesystem`` implementation.

        This method should be implemented by subclasses. The position of ``fh`` is guaranteed to be ``0``.

        Args:
            fh: A file-like object, usually a disk or partition.

        Returns:
            ``True`` if ``fh`` is supported, ``False`` otherwise.
        """
        raise NotImplementedError

    @classmethod
    def detect_id(cls, fh: BinaryIO) -> bytes | None:
        """Return a filesystem set identifier.

        Only used in filesystems that support multiple volumes (disks) to find all volumes
        belonging to a single filesystem.

        Args:
            fh: A file-like object, usually a disk or partition.
        """
        if not cls.__multi_volume__:
            return None

        offset = fh.tell()
        try:
            fh.seek(0)
            return cls._detect_id(fh)
        except NotImplementedError:
            raise
        except Exception as e:
            log.warning("Failed to detect ID on %s filesystem", cls.__type__)
            log.debug("", exc_info=e)
        finally:
            fh.seek(offset)

        return None

    @staticmethod
    def _detect_id(fh: BinaryIO) -> bytes | None:
        """Return a filesystem set identifier.

        This method should be implemented by subclasses of filesystems that support multiple volumes (disks).
        The position of ``fh`` is guaranteed to be ``0``.

        Args:
            fh: A file-like object, usually a disk or partition.

        Returns:
            An identifier that can be used to combine the given ``fh`` with others beloning to the same set.
        """
        raise NotImplementedError

    def iter_subfs(self) -> Iterator[Filesystem]:
        """Yield possible sub-filesystems."""
        yield from ()

    def get(self, path: str) -> FilesystemEntry:
        """Retrieve a :class:`FilesystemEntry` from the filesystem.

        Args:
            path: The path which we want to retrieve.

        Returns:
            A :class:`FilesystemEntry` for the path.
        """
        raise NotImplementedError

    def open(self, path: str) -> BinaryIO:
        """Open a filesystem entry.

        Args:
            path: The location on the filesystem to open.

        Returns:
            A file-like object. Resolves symlinks when possible.
        """
        return self.get(path).open()

    def iterdir(self, path: str) -> Iterator[str]:
        """Iterate over the contents of a directory, return them as strings.

        Args:
            path: The location on the filesystem to iterate over.

        Returns:
            An iterator of directory entries as path strings.
        """
        return self.get(path).iterdir()

    def scandir(self, path: str) -> Iterator[FilesystemEntry]:
        """Iterate over the contents of a directory, return them as FilesystemEntry's.

        Args:
            path: The directory to scan.

        Returns:
            An iterator of directory entries as FilesystemEntry's.
        """
        return self.get(path).scandir()

    def listdir(self, path: str) -> list[str]:
        """List the contents of a directory as strings.

        Args:
            path: The directory to get the listing from.

        Returns:
            A list of path strings.
        """
        return list(self.iterdir(path))

    def listdir_ext(self, path: str) -> list[FilesystemEntry]:
        """List the contents of a directory as FilesystemEntry's.

        Args:
            path: The directory to get the listing from.

        Returns:
            A list of FilesystemEntry's.
        """
        return list(self.scandir(path))

    def walk(
        self,
        path: str,
        topdown: bool = True,
        onerror: Callable[[Exception], None] | None = None,
        followlinks: bool = False,
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        """Recursively walk a directory pointed to by ``path``, returning the string representation of both files
        and directories.

        Args:
            path: The path to walk on the filesystem.
            topdown: ``True`` puts the ``path`` at the top, ``False`` puts the ``path`` at the bottom.
            onerror: A method to execute when an error occurs.
            followlinks: ``True`` if we want to follow any symbolic link.

        Returns:
            An iterator of directory entries as path strings.
        """
        return self.get(path).walk(topdown, onerror, followlinks)

    def walk_ext(
        self,
        path: str,
        topdown: bool = True,
        onerror: Callable[[Exception], None] | None = None,
        followlinks: bool = False,
    ) -> Iterator[tuple[list[FilesystemEntry], list[FilesystemEntry], list[FilesystemEntry]]]:
        """Recursively walk a directory pointed to by ``path``, returning :class:`FilesystemEntry` of files
        and directories.

        Args:
            path: The path to walk on the filesystem.
            topdown: ``True`` puts the ``path`` at the top, ``False`` puts the ``path`` at the bottom.
            onerror: A method to execute when an error occurs.
            followlinks: ``True`` if we want to follow any symbolic link.

        Returns:
            An iterator of directory entries as FilesystemEntry's.
        """
        return self.get(path).walk_ext(topdown, onerror, followlinks)

    def recurse(self, path: str) -> Iterator[FilesystemEntry]:
        """Recursively walk a directory and yield contents as :class:`FilesystemEntry`.

        Does not follow symbolic links.

        Args:
            path: The path to recursively walk on the target filesystem.

        Returns:
            An iterator of :class:`FilesystemEntry`.
        """
        return self.get(path).recurse()

    def glob(self, pattern: str) -> Iterator[str]:
        """Iterate over the directory part of ``pattern``, returning entries matching ``pattern`` as strings.

        Args:
            pattern: The pattern to match.

        Returns:
            An iterator of path strings that match the pattern.
        """
        for entry in self.glob_ext(pattern):
            yield entry.path

    def glob_ext(self, pattern: str) -> Iterator[FilesystemEntry]:
        """Iterate over the directory part of ``pattern``, returning entries matching ``pattern`` as FilesysmteEntry's.


        Args:
            pattern: The pattern to match.

        Returns:
            An iterator of FilesystemEntry's that match the pattern.
        """
        path, pattern = fsutil.glob_split(pattern, alt_separator=self.alt_separator)
        try:
            entry = self.get(path)
        except FileNotFoundError:
            return
        else:
            yield from fsutil.glob_ext(entry, pattern)

    def exists(self, path: str) -> bool:
        """Determines whether ``path`` exists on a filesystem.

        If the ``path`` is a symbolic link, it will attempt to resolve it to find the FilesystemEntry it points to.

        Args:
            path: a path on the filesystem.

        Returns:
            ``True`` if the given path exists, ``False`` otherwise.
        """
        try:
            entry = self.get(path)
            if entry.is_symlink():
                entry.readlink_ext()
        except Exception:
            return False
        else:
            return True

    def lexists(self, path: str) -> bool:
        """Determines if a ``path`` exists on the filesystem without resolving links.

        Args:
            path: A path on the filesystem.

        Returns:
            ``True`` if the given path is a file, ``False`` otherwise.
        """
        try:
            self.get(path)
        except Exception:
            return False
        else:
            return True

    def is_file(self, path: str, follow_symlinks: bool = True) -> bool:
        """Determine if ``path`` is a file on the filesystem.

        Args:
            path: The path on the filesystem.
            follow_symlinks: Whether to resolve the path if it is a symbolic link.

        Returns:
            ``True`` if the given path is a file or a symbolic link to a file, return ``False`` otherwise.  If
            ``follow_symlinks`` is ``False``, return ``True`` only if the given path is a file (without
            following symlinks).
        """
        try:
            return self.get(path).is_file(follow_symlinks=follow_symlinks)
        except FileNotFoundError:
            return False

    def is_dir(self, path: str, follow_symlinks: bool = True) -> bool:
        """Determine whether the given ``path`` is a directory on the filesystem.

        Args:
            path: The path on the filesystem.
            follow_symlinks: Whether to resolve the path if it is a symbolic link.

        Returns:
            ``True`` if the given path is a directory or a symbolic link to a directory, return ``False``
            otherwise.
            If ``follow_symlinks`` is ``False``, return ``True`` only if the given path is a directory
            (without following symlinks).
        """
        try:
            return self.get(path).is_dir(follow_symlinks=follow_symlinks)
        except FileNotFoundError:
            return False

    def is_symlink(self, path: str) -> bool:
        """Determine wether the given ``path`` is a symlink on the filesystem.

        Args:
            path: The path on the filesystem.

        Returns:
            ``True`` if the given path is a symbolic link, ``False`` otherwise.
        """
        try:
            return self.get(path).is_symlink()
        except FileNotFoundError:
            return False

    def readlink(self, path: str) -> str:
        """Read the link where the given ``path`` points to, return the resulting path as string.

        If it is a symlink and returns the string that corresponds to that path.
        This means it follows the path a link points to, it tries to do it recursively.

        Args:
            path: The symbolic link to read.

        Returns:
            The path the link points to.
        """
        return self.get(path).readlink()

    def readlink_ext(self, path: str) -> FilesystemEntry:
        """Read the link where the given ``path`` points to, return the resulting path as FilesystemEntry.

        If it is a symlink and returns the entry that corresponds to that path.
        This means it follows the path a link points to, it tries to do it recursively.

        Args:
            path: The symbolic link to read.

        Returns:
            The ``FilesystemEntry`` where the symbolic link points to.
        """
        return self.get(path).readlink_ext()

    def stat(self, path: str, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Determine the stat information of a ``path`` on the filesystem.

        If ``path`` is a symlink and ``follow_symlinks`` is ``True``, it gets resolved, attempting to stat the
        path where it points to.

        Args:
            path: The filesystem path we want the stat information from.
            follow_symlinks: Whether to resolve the path if it is a symbolic link.

        Returns:
            The stat information of the given path.
        """
        return self.get(path).stat(follow_symlinks=follow_symlinks)

    def lstat(self, path: str) -> fsutil.stat_result:
        """Determine the stat information of a ``path`` on the filesystem, **without** resolving symlinks.

        When it detects a symlink, it will stat the information of the symlink, not the path it points to.

        Args:
            path: The filesystem path we want the stat information from.

        Returns:
            The stat information of the given path.
        """
        return self.get(path).lstat()

    def md5(self, path: str) -> str:
        """Calculate the MD5 digest of the contents of the file ``path`` points to.

        Args:
            path: The filesystem path to get the digest from.

        Returns:
            The MD5 digest of the contents of ``path``.
        """
        return self.get(path).md5()

    def sha1(self, path: str) -> str:
        """Calculate the SHA1 digest of the contents of the file ``path`` points to.

        Args:
            path: The filesystem path to get the digest from.

        Returns:
            The SHA1 digest of the contents of ``path``.
        """
        return self.get(path).sha1()

    def sha256(self, path: str) -> str:
        """Calculate the SHA256 digest of the contents of the file ``path`` points to.

        Args:
            path: The filesystem path to get the digest from.

        Returns:
            The SHA256 digest of the contents of ``path``.
        """
        return self.get(path).sha256()

    def hash(self, path: str, algos: list[str] | list[Callable] | None = None) -> tuple[str]:
        """Calculate the digest of the contents of ``path``, using the ``algos`` algorithms.

        Args:
            path: The filesystem path to get the digest from.
            algos: The types of hashes to calculate. If ``None`` it will use the common set of algorithms defined in
                        :py:func:`dissect.target.helpers.hashutil.common` as ``[MD5, SHA1, SHA256]``.

        Returns:
            The digests of the contents of ``path``.
        """
        return self.get(path).hash(algos)


class FilesystemEntry:
    """Base class for filesystem entries."""

    def __init__(self, fs: Filesystem, path: str, entry: Any):
        """Initialize the base filesystem entry class.

        Args:
            fs: The filesystem to get data from.
            path: The path of the entry mapped on ``fs``.
            entry: The raw entry backing this filesystem entry.
        """
        self.fs = fs
        self.path = path
        self.name = fsutil.basename(path, alt_separator=self.fs.alt_separator)
        self.entry = entry

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.path!r}>"

    def __str__(self) -> str:
        return str(self.path)

    def _resolve(self, follow_symlinks: bool = True) -> FilesystemEntry:
        """Helper method to resolve symbolic links.

        If ``follow_symlinks`` is ``False``, this function is effectively a no-op.

        Args:
            follow_symlinks: Whether to resolve the entry if it is a symbolic link.

        Returns:
            The resolved symbolic link if ``follow_symlinks`` is ``True`` and the :class:`FilesystemEntry` is a
            symbolic link or else the :class:`FilesystemEntry` itself.
        """
        if follow_symlinks and self.is_symlink():
            return self.readlink_ext()
        return self

    def get(self, path: str) -> FilesystemEntry:
        """Retrieve a :class:`FilesystemEntry` relative to this entry.

        Args:
            path: The path relative to this filesystem entry.

        Returns:
            A relative :class:`FilesystemEntry`.
        """
        raise NotImplementedError

    def open(self) -> BinaryIO:
        """Open this filesystem entry.

        Returns:
            A file-like object. Resolves symlinks when possible
        """
        raise NotImplementedError

    def iterdir(self) -> Iterator[str]:
        """Iterate over the contents of a directory, return them as strings.

        Returns:
            An iterator of directory entries as path strings.
        """
        raise NotImplementedError

    def scandir(self) -> Iterator[FilesystemEntry]:
        """Iterate over the contents of a directory, yields :class:`FilesystemEntry`.

        Returns:
            An iterator of :class:`FilesystemEntry`.
        """
        raise NotImplementedError

    def listdir(self) -> list[str]:
        """List the contents of a directory as strings.

        Returns:
            A list of path strings.
        """
        return list(self.iterdir())

    def listdir_ext(self) -> list[FilesystemEntry]:
        """List the contents of a directory as a list of :class:`FilesystemEntry`.

        Returns:
            A list of :class:`FilesystemEntry`.
        """
        return list(self.scandir())

    def walk(
        self,
        topdown: bool = True,
        onerror: Callable[[Exception], None] | None = None,
        followlinks: bool = False,
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        """Recursively walk a directory and yield its contents as strings split in a tuple
        of lists of files, directories and symlinks.

        These contents include::
          -files
          -directories
          -symboliclinks

        Args:
            topdown: ``True`` puts this entry at the top of the list, ``False`` puts this entry at the bottom.
            onerror: A method to execute when an error occurs.
            followlinks: ``True`` if we want to follow any symbolic link.

        Returns:
            An iterator of directory entries as path strings.
        """
        yield from fsutil.walk(self, topdown, onerror, followlinks)

    def walk_ext(
        self,
        topdown: bool = True,
        onerror: Callable[[Exception], None] | None = None,
        followlinks: bool = False,
    ) -> Iterator[tuple[list[FilesystemEntry], list[FilesystemEntry], list[FilesystemEntry]]]:
        """Recursively walk a directory and yield its contents as :class:`FilesystemEntry` split in a tuple of
        lists of files, directories and symlinks.

        Args:
            topdown: ``True`` puts this entry at the top of the list, ``False`` puts this entry at the bottom.
            onerror: A method to execute when an error occurs.
            followlinks: ``True`` if we want to follow any symbolic link

        Returns:
            An iterator of tuples :class:`FilesystemEntry`.
        """
        yield from fsutil.walk_ext(self, topdown, onerror, followlinks)

    def recurse(self) -> Iterator[FilesystemEntry]:
        """Recursively walk a directory and yield its contents as :class:`FilesystemEntry`.

        Does not follow symbolic links.

        Returns:
            An iterator of :class:`FilesystemEntry`.
        """
        yield from fsutil.recurse(self)

    def glob(self, pattern: str) -> Iterator[str]:
        """Iterate over this directory part of ``patern``, returning entries matching ``pattern`` as strings.

        Args:
            pattern: The pattern to match.

        Returns:
            An iterator of path strings that match the pattern.
        """
        for entry in self.glob_ext(pattern):
            yield entry.path

    def glob_ext(self, pattern: str) -> Iterator[FilesystemEntry]:
        """Iterate over the directory part of ``pattern``, returning entries matching
        ``pattern`` as :class:`FilesysmteEntry`.

        Args:
            pattern: The pattern to glob for.

        Returns:
            An iterator of :class:`FilesystemEntry` that match the pattern.
        """
        yield from fsutil.glob_ext(self, pattern)

    def exists(self, path: str) -> bool:
        """Determines whether a ``path``, relative to this entry, exists.

        If the `path` is a symbolic link, it will attempt to resolve it to find
        the :class:`FilesystemEntry` it points to.

        Args:
            path: The path relative to this entry.

        Returns:
            ``True`` if the path exists, ``False`` otherwise.
        """
        try:
            entry = self.get(path)
            if entry.is_symlink():
                entry.readlink_ext()
        except Exception:
            return False
        else:
            return True

    def lexists(self, path: str) -> bool:
        """Determine wether a ``path`` relative to this enty, exists without resolving links.

        Args:
            path: The path relative to this entry.

        Returns:
            ``True`` if the path exists, ``False`` otherwise.
        """
        try:
            self.get(path)
        except Exception:
            return False
        else:
            return True

    def is_file(self, follow_symlinks: bool = True) -> bool:
        """Determine if this entry is a file.

        Args:
            follow_symlinks: Whether to resolve the entry if it is a symbolic link.

        Returns:
            ``True`` if the entry is a file or a symbolic link to a file, return ``False`` otherwise.
            If ``follow_symlinks`` is ``False``, return ``True`` only if the entry is a file (without
            following symlinks).
        """
        raise NotImplementedError

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        """Determine if this entry is a directory.

        Args:
            follow_symlinks: Whether to resolve the entry if it is a symbolic link.

        Returns:
            ``True`` if the entry is a directory or a symbolic link to a directory, return ``False``
            otherwise.
            If ``follow_symlinks`` is ``False``, return ``True`` only if the entry is a directory (without
            following symlinks).

        """
        raise NotImplementedError

    def is_symlink(self) -> bool:
        """Determine whether this entry is a symlink.

        Returns:
            ``True`` if the entry is a symbolic link, ``False`` otherwise.
        """
        raise NotImplementedError

    def readlink(self) -> str:
        """Read the link where this entry points to, return the resulting path as string.

        If it is a symlink and returns the entry that corresponds to that path.
        This means it follows the path a link points to, it tries to do it recursively.

        Returns:
            The path the link points to."""
        raise NotImplementedError

    def readlink_ext(self) -> FilesystemEntry:
        """Read the link where this entry points to, return the resulting path as :class:`FilesystemEntry`.

        If it is a symlink and returns the string that corresponds to that path.
        This means it follows the path a link points to, it tries to do it recursively.

        Returns:
            The filesystem entry the link points to.
        """
        log.debug("%r::readlink_ext()", self)
        # Default behavior, resolve link own filesystem.
        return fsutil.resolve_link(self.fs, self.readlink(), self.path, alt_separator=self.fs.alt_separator)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        """Determine the stat information of this entry.

        If the entry is a symlink and ``follow_symlinks`` is ``True``, it gets resolved, attempting to stat
        the path where it points to.

        Args:
            follow_symlinks: Whether to resolve the symbolic link if this entry is a symbolic link.

        Returns:
            The stat information of this entry.
        """
        raise NotImplementedError

    def lstat(self) -> fsutil.stat_result:
        """Determine the stat information of this entry, **without** resolving the symlinks.

        When it detects a symlink, it will stat the information of the symlink, not the path it points to.

        Returns:
            The stat information of this entry.
        """
        raise NotImplementedError

    def attr(self) -> Any:
        """The attributes related to this entry, resolving any symlinks.

        If the entry is a symbolic link, it will attempt to resolve it first.
        Resulting in the attr information of the entry it points to.

        Returns:
            The attributes of this entry.
        """
        raise NotImplementedError

    def lattr(self) -> Any:
        """The attributes related to this current entry, **without** resolving links.

        Returns:
            The attributes of this entry.
        """
        raise NotImplementedError

    def md5(self) -> str:
        """Calculates the MD5 digest of this entry.

        Returns:
            The MD5 digest of this entry.
        """
        return hashutil.md5(self.open())

    def sha1(self) -> str:
        """Calculates the SHA1 digest of this entry.

        Returns:
            The SHA1 digest of this entry.
        """
        return hashutil.sha1(self.open())

    def sha256(self) -> str:
        """Calculates the SHA256 digest of this entry.

        Returns:
            The SHA256 digest of this entry.
        """
        return hashutil.sha256(self.open())

    def hash(self, algos: list[str] | list[Callable] | None = None) -> tuple[str]:
        """Calculate the digest of this entry, using the ``algos`` algorithms.

        Args:
            algos: The types of hashes to calculate. If ``None`` it will use the common set of algorithms defined in
                   :py:func:`dissect.target.helpers.hashutil.common` as ``[MD5, SHA1, SHA256]``.

        Returns:
            The various digests of this entry.
        """
        if algos:
            return hashutil.custom(self.open(), algos)
        return hashutil.common(self.open())


class VirtualDirectory(FilesystemEntry):
    """Virtual directory implementation. Backed by a dict."""

    def __init__(self, fs: VirtualFilesystem, path: str):
        super().__init__(fs, path, None)
        self.up = None
        self.top = None
        self.entries = {}

    def __getitem__(self, item: str) -> FilesystemEntry:
        if not self.fs.case_sensitive:
            item = item.lower()
        return self.entries[item]

    def __contains__(self, item: str) -> bool:
        if not self.fs.case_sensitive:
            item = item.lower()
        return item in self.entries

    def open(self) -> BinaryIO:
        raise IsADirectoryError(f"{self.path} is a directory")

    def attr(self) -> Any:
        raise TypeError(f"attr is not allowed on VirtualDirectory: {self.path}")

    def lattr(self) -> Any:
        raise TypeError(f"lattr is not allowed on VirtualDirectory: {self.path}")

    def add(self, name: str, entry: FilesystemEntry) -> None:
        """Add an entry to this :class:`VirtualDirectory`."""
        if not self.fs.case_sensitive:
            name = name.lower()

        self.entries[name] = entry

    def get(self, path: str) -> FilesystemEntry:
        return self.fs.get(path, relentry=self)

    def iterdir(self) -> Iterator[str]:
        yielded = set()
        for entry in self.entries:
            yield entry
            yielded.add(entry)

        # self.top used to be a reference to a filesystem. This is now a reference to
        # any filesystem entry, usually the root of a filesystem.
        if self.top:
            for entry in self.top.iterdir():
                if entry in yielded or (not self.fs.case_sensitive and entry.lower() in yielded):
                    continue
                yield entry

    def scandir(self) -> Iterator[FilesystemEntry]:
        yielded = set()
        for entry in self.entries.values():
            yield entry
            yielded.add(entry.name)

        # self.top used to be a reference to a filesystem. This is now a reference to
        # any filesystem entry, usually the root of a filesystem.
        if self.top:
            for entry in self.top.scandir():
                if entry.name in yielded or (not self.fs.case_sensitive and entry.name.lower() in yielded):
                    continue
                yield entry

    def _stat(self) -> fsutil.stat_result:
        path_addr = fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator)
        return fsutil.stat_result([stat.S_IFDIR, path_addr, id(self.fs), 1, 0, 0, 0, 0, 0, 0])

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        if self.top:
            return self.top.stat(follow_symlinks=follow_symlinks)
        return self._stat()

    def lstat(self) -> fsutil.stat_result:
        if self.top:
            return self.top.lstat()
        return self._stat()

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return True

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return False

    def is_symlink(self) -> bool:
        return False

    def readlink(self) -> str:
        raise NotASymlinkError(self.path)

    def readlink_ext(self) -> FilesystemEntry:
        raise NotASymlinkError(self.path)


class VirtualFileHandle(io.RawIOBase):
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.seek(0)

    def readinto(self, b: bytearray) -> int:
        return self.fh.readinto(b)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return self.fh.seek(offset, whence)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True


class VirtualFile(FilesystemEntry):
    """Virtual file backed by a file-like object."""

    def attr(self) -> Any:
        raise TypeError(f"attr is not allowed on {self.__class__.__name__}: {self.path}")

    def lattr(self) -> Any:
        raise TypeError(f"lattr is not allowed on {self.__class__.__name__}: {self.path}")

    def get(self, path: str) -> FilesystemEntry:
        path = fsutil.normalize(path, alt_separator=self.fs.alt_separator).strip("/")
        if not path:
            return self
        raise NotADirectoryError(f"'{self.path}' is not a directory")

    def iterdir(self) -> Iterator[str]:
        raise NotADirectoryError(f"'{self.path}' is not a directory")

    def scandir(self) -> Iterator[FilesystemEntry]:
        raise NotADirectoryError(f"'{self.path}' is not a directory")

    def open(self) -> BinaryIO:
        return VirtualFileHandle(self.entry)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        size = getattr(self.entry, "size", 0)
        file_addr = fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator)
        return fsutil.stat_result([stat.S_IFREG, file_addr, id(self.fs), 1, 0, 0, size, 0, 0, 0])

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return True

    def is_symlink(self) -> bool:
        return False

    def readlink(self) -> str:
        raise NotASymlinkError(self.path)

    def readlink_ext(self) -> FilesystemEntry:
        raise NotASymlinkError(self.path)


class MappedFile(VirtualFile):
    """Virtual file backed by a file on the host machine."""

    entry: str

    def open(self) -> BinaryIO:
        return pathlib.Path(self.entry).open("rb")

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        # Python 3.9 does not support follow_symlinks in stat()
        if follow_symlinks:
            return fsutil.stat_result.copy(pathlib.Path(self.entry).stat())

        return self.lstat()

    def lstat(self) -> fsutil.stat_result:
        return fsutil.stat_result.copy(pathlib.Path(self.entry).lstat())

    def attr(self) -> dict[str, bytes]:
        return fsutil.fs_attrs(self.entry, follow_symlinks=True)

    def lattr(self) -> dict[str, bytes]:
        return fsutil.fs_attrs(self.entry, follow_symlinks=False)


class MappedCompressedFile(MappedFile):
    """Virtual file backed by a compressed file on the host machine."""

    entry: str
    _compressors: Final[dict[str, Any]] = {"gzip": gzip}

    def __init__(self, fs: Filesystem, path: str, entry: str, algo: str = "gzip"):
        super().__init__(fs, path, entry)
        self._compressor = self._compressors.get(algo)
        if self._compressor is None:
            raise ValueError(f"Unsupported compression algorithm {algo}")

    def open(self) -> BinaryIO:
        return self._compressor.open(self.entry, "rb")


class VirtualSymlink(FilesystemEntry):
    """Virtual symlink implementation."""

    def __init__(self, fs: Filesystem, path: str, target: str):
        super().__init__(fs, path, None)
        self.target = target

    def attr(self) -> Any:
        return self.readlink_ext().attr()

    def lattr(self) -> Any:
        raise TypeError(f"lattr is not allowed on VirtualSymlink: {self.path}")

    def get(self, path: str) -> FilesystemEntry:
        return self.fs.get(path, self)

    def iterdir(self) -> Iterator[str]:
        yield from self.readlink_ext().iterdir()

    def scandir(self) -> Iterator[FilesystemEntry]:
        yield from self.readlink_ext().scandir()

    def open(self) -> BinaryIO:
        return self.readlink_ext().open()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        link_addr = fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator)
        return fsutil.stat_result([stat.S_IFLNK, link_addr, id(self.fs), 1, 0, 0, len(self.target), 0, 0, 0])

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        if not follow_symlinks:
            return False

        try:
            return self.readlink_ext().is_dir()
        except FileNotFoundError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        if not follow_symlinks:
            return False

        try:
            return self.readlink_ext().is_file()
        except FileNotFoundError:
            return False

    def is_symlink(self) -> bool:
        return True

    def readlink(self) -> str:
        return self.target


class VirtualFilesystem(Filesystem):
    __type__ = "virtual"

    def __init__(self, **kwargs):
        super().__init__(None, **kwargs)
        self.root = VirtualDirectory(self, "/")

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on VirtualFilesystem class")

    def get(self, path: str, relentry: FilesystemEntry | None = None) -> FilesystemEntry:
        entry = relentry or self.root
        path = fsutil.normalize(path, alt_separator=self.alt_separator).strip("/")
        full_path = fsutil.join(entry.path, path, alt_separator=self.alt_separator)

        if not path:
            return entry

        parts = path.split("/")

        for i, part in enumerate(parts):
            # If the entry of the previous part (or the starting relentry /
            # root entry) is a symlink, resolve it first so things like entry.up
            # work if it is a symlink to a directory.
            # Note that this will never resolve the final part of the path if
            # that happens to be a symlink, so things like fs.is_symlink() will
            # work.
            if entry.is_symlink():
                entry = entry.readlink_ext()

            if not entry.is_dir():
                # An entry for the current part can only be retrieved if the
                # entry of the previous part (or the starting relentry / root
                # entry) is a directory.
                raise NotADirectoryError(full_path)
            if part == ".":
                continue
            if part == "..":
                entry = entry.up
                if not entry:
                    entry = self.root
            else:
                if part in entry:
                    entry = entry[part]
                elif entry.top:
                    try:
                        return entry.top.get(fsutil.join(*parts[i:], alt_separator=self.alt_separator))
                    except FilesystemError as e:
                        raise FileNotFoundError(full_path) from e
                else:
                    raise FileNotFoundError(full_path)

        return entry

    def makedirs(self, path: str) -> VirtualDirectory:
        """Create virtual directories into the VFS from the given path."""
        path = fsutil.normalize(path, alt_separator=self.alt_separator).strip("/")
        directory = self.root

        if not path:
            return directory

        parts = path.split("/")
        for i, part in enumerate(parts):
            if part not in directory:
                vdir = VirtualDirectory(self, fsutil.join(*parts[: i + 1], alt_separator=self.alt_separator))
                vdir.up = directory

                directory.add(part, vdir)

            directory = directory[part]

        return directory

    def map_fs(self, vfspath: str, fs: Filesystem, base: str = "/") -> None:
        """Mount a dissect filesystem to a directory in the VFS."""
        directory = self.makedirs(vfspath)
        directory.top = fs.get(base)

    mount = map_fs

    def map_dir(self, vfspath: str, realpath: pathlib.Path | str) -> None:
        """Recursively map a directory from the host machine into the VFS."""
        if not isinstance(realpath, pathlib.Path):
            realpath = pathlib.Path(realpath)

        vfspath = fsutil.normalize(vfspath, alt_separator=self.alt_separator).strip("/")
        base = realpath.resolve()

        # Compatibility walk until we are base 3.12
        def _walk_compat(path: pathlib.Path) -> Iterator[tuple[pathlib.Path, list[str], list[str]]]:
            """Compatibility function to walk a directory."""
            for root, dirs, files in os.walk(path):
                yield pathlib.Path(root), dirs, files

        for root, dirs, files in base.walk() if hasattr(base, "walk") else _walk_compat(base):
            relroot = str(root.relative_to(base))
            if relroot == ".":
                relroot = ""

            relroot = fsutil.normalize(relroot, alt_separator=os.path.sep)
            vfsroot = fsutil.join(vfspath, relroot, alt_separator=self.alt_separator)
            directory = self.makedirs(vfsroot)

            for dir_ in dirs:
                vfs_dir = fsutil.join(vfsroot, dir_, alt_separator=self.alt_separator)
                self.makedirs(vfs_dir)

            for file_ in files:
                vfs_file_path = fsutil.join(vfsroot, file_, alt_separator=self.alt_separator)
                real_file_path = root.joinpath(file_)
                directory.add(file_, MappedFile(self, vfs_file_path, str(real_file_path)))

    def map_file(self, vfspath: str, realpath: str, compression: str | None = None) -> None:
        """Map a file from the host machine into the VFS."""
        vfspath = fsutil.normalize(vfspath, alt_separator=self.alt_separator)
        if vfspath[-1] == "/":
            raise AttributeError(f"Can't map a file onto a directory: {vfspath}")
        file_path = vfspath.lstrip("/")

        if compression is not None:
            mapped_file = MappedCompressedFile(self, file_path, realpath, algo=compression)
        else:
            mapped_file = MappedFile(self, file_path, realpath)
        self.map_file_entry(vfspath, mapped_file)

    def map_file_fh(self, vfspath: str, fh: BinaryIO) -> None:
        """Map a file handle into the VFS."""
        vfspath = fsutil.normalize(vfspath, alt_separator=self.alt_separator)
        if vfspath[-1] == "/":
            raise AttributeError(f"Can't map a file onto a directory: {vfspath}")
        file_path = vfspath.lstrip("/")
        self.map_file_entry(vfspath, VirtualFile(self, file_path, fh))

    def map_file_entry(self, vfspath: str, entry: FilesystemEntry) -> None:
        """Map a :class:`FilesystemEntry` into the VFS.

        Any missing subdirectories up to, but not including, the last part of
        ``vfspath`` will be created.
        """
        vfspath = fsutil.normalize(vfspath, alt_separator=self.alt_separator).strip("/")
        if not vfspath:
            self.root.top = entry
        else:
            if "/" in vfspath:
                sub_dirs = fsutil.dirname(vfspath, alt_separator=self.alt_separator)
                directory = self.makedirs(sub_dirs)
            else:
                directory = self.root

            entry_name = fsutil.basename(vfspath, alt_separator=self.alt_separator)
            directory.add(entry_name, entry)

    def map_dir_from_tar(self, vfspath: str, tar_file: str | pathlib.Path, map_single_file: bool = False) -> None:
        """Map files in a tar onto the VFS.

        Args:
            vfspath: Destination path in the virtual filesystem.
            tar_file: Source path of the tar file to map.
            map_single_file: Only mount a single file found inside the tar at the specified path.
        """

        if not isinstance(tar_file, pathlib.Path):
            try:
                tar_file = pathlib.Path(tar_file)
            except TypeError:
                raise ValueError("tar_file should be a string or Path instance")

        vfspath = fsutil.normalize(vfspath, alt_separator=self.alt_separator)
        tfs = TarFilesystem(tar_file.open("rb"))

        if map_single_file:
            # We map the first file we find in the tar to the provided vfspath.
            for file in [f[0] for _, _, f in tfs.walk_ext("/") if f]:
                file.name = fsutil.basename(vfspath)
                self.map_file_entry(vfspath, file)
                return
        else:
            self.mount(vfspath, tfs)

    def map_file_from_tar(self, vfspath: str, tar_file: str | pathlib.Path) -> None:
        """Map a single file in a tar archive to the given path in the VFS.

        The provided tar archive should contain *one* file.

        Args:
            vfspath: Destination path in the virtual filesystem.
            tar_file: Source path of the tar file to map.
        """
        return self.map_dir_from_tar(vfspath.lstrip("/"), tar_file, map_single_file=True)

    def link(self, src: str, dst: str) -> None:
        """Hard link a :class:`FilesystemEntry` to another location.

        Args:
            src: The path to the target of the link.
            dst: The path to the link.
        """
        self.map_file_entry(dst, self.get(src))

    def symlink(self, src: str, dst: str) -> None:
        """Create a symlink to another location.

        Args:
            src: The path to the target of the symlink.
            dst: The path to the symlink.
        """
        src = fsutil.normalize(src, alt_separator=self.alt_separator).rstrip("/")
        dst = fsutil.normalize(dst, alt_separator=self.alt_separator).strip("/")
        self.map_file_entry(dst, VirtualSymlink(self, dst, src))


class LayerFilesystem(Filesystem):
    __type__ = "layer"

    def __init__(self, **kwargs):
        self.layers: list[Filesystem] = []
        self.mounts = {}
        self._alt_separator = "/"
        self._case_sensitive = True
        self._root_entry = LayerFilesystemEntry(self, "/", [])
        self.root = self.append_layer()
        super().__init__(None, **kwargs)

    def __getattr__(self, attr: str) -> Any:
        """Provide "magic" access to filesystem specific attributes from any of the layers.

        For example, on a :class:`LayerFilesystem` ``fs``, you can do ``fs.ntfs`` to access the
        internal NTFS object if it has an NTFS layer.
        """
        for fs in self.layers:
            try:
                return getattr(fs, attr)
            except AttributeError:  # noqa: PERF203
                continue
        else:
            return object.__getattribute__(self, attr)

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on LayerFilesystem class")

    def mount(self, path: str, fs: Filesystem, ignore_existing: bool = True) -> None:
        """Mount a filesystem at a given path.

        If there's an overlap with an existing mount, creates a new layer.

        Args:
            path: The path to mount the filesystem at.
            fs: The filesystem to mount.
            ignore_existing: Whether to ignore existing mounts and create a new layer. Defaults to ``True``.
        """
        root = self.root
        for mount in self.mounts:
            if ignore_existing and path == mount:
                continue

            if path.startswith(mount):
                root = self.append_layer()
                break

        root.map_fs(path, fs)
        self.mounts[path] = fs

    def link(self, dst: str, src: str) -> None:
        """Hard link a :class:`FilesystemEntry` to another location."""
        self.root.map_file_entry(dst, self.get(src))

    def symlink(self, dst: str, src: str) -> None:
        """Create a symlink to another location."""
        self.root.symlink(dst, src)

    def append_layer(self, **kwargs) -> VirtualFilesystem:
        """Append a new layer."""
        layer = VirtualFilesystem(case_sensitive=self.case_sensitive, alt_separator=self.alt_separator, **kwargs)
        self.append_fs_layer(layer)
        return layer

    add_layer = append_layer

    def prepend_layer(self, **kwargs) -> VirtualFilesystem:
        """Prepend a new layer."""
        layer = VirtualFilesystem(case_sensitive=self.case_sensitive, alt_separator=self.alt_separator, **kwargs)
        self.prepend_fs_layer(layer)
        return layer

    def append_fs_layer(self, fs: Filesystem) -> None:
        """Append a filesystem as a layer.

        Args:
            fs: The filesystem to append.
        """
        # Counterintuitively, we prepend the filesystem to the list of layers
        # We could reverse the list of layers upon iteration, but that is a hot path
        self.layers.insert(0, fs)
        self._root_entry.entries.insert(0, fs.get("/"))

    def prepend_fs_layer(self, fs: Filesystem) -> None:
        """Prepend a filesystem as a layer.

        Args:
            fs: The filesystem to prepend.
        """
        # Counterintuitively, we append the filesystem to the list of layers
        # We could reverse the list of layers upon iteration, but that is a hot path
        self.layers.append(fs)
        self._root_entry.entries.append(fs.get("/"))

    def remove_fs_layer(self, fs: Filesystem) -> None:
        """Remove a filesystem layer.

        Args:
            fs: The filesystem to remove.
        """
        self.remove_layer(self.layers.index(fs))

    def remove_layer(self, idx: int) -> None:
        """Remove a layer by index.

        Args:
            idx: The index of the layer to remove.
        """
        del self.layers[idx]
        del self._root_entry.entries[idx]

    @property
    def case_sensitive(self) -> bool:
        """Whether the filesystem is case sensitive."""
        return self._case_sensitive

    @property
    def alt_separator(self) -> str:
        """The alternative separator of the filesystem."""
        return self._alt_separator

    @case_sensitive.setter
    def case_sensitive(self, value: bool) -> None:
        """Set the case sensitivity of the filesystem (and all layers)."""
        self._case_sensitive = value
        self.root.case_sensitive = value
        for layer in self.layers:
            layer.case_sensitive = value

    @alt_separator.setter
    def alt_separator(self, value: str) -> None:
        """Set the alternative separator of the filesystem (and all layers)."""
        self._alt_separator = value
        self.root.alt_separator = value
        for layer in self.layers:
            layer.alt_separator = value

    def get(self, path: str, relentry: LayerFilesystemEntry | None = None) -> LayerFilesystemEntry:
        """Get a :class:`FilesystemEntry` from the filesystem."""
        entry = relentry or self._root_entry
        path = fsutil.normalize(path, alt_separator=self.alt_separator).strip("/")
        full_path = fsutil.join(entry.path, path, alt_separator=self.alt_separator)

        if not path:
            return entry

        exc = []
        entries = []

        for sub_entry in entry.entries:
            try:
                entries.append(self._get_from_entry(path, sub_entry))
            except FilesystemError as e:  # noqa: PERF203
                exc.append(e)

        if not entries:
            if all(isinstance(ex, NotADirectoryError) for ex in exc):
                raise NotADirectoryError(full_path)
            if all(isinstance(ex, NotASymlinkError) for ex in exc):
                raise NotASymlinkError(full_path)
            raise FileNotFoundError(full_path)

        return LayerFilesystemEntry(self, full_path, entries)

    def _get_from_entry(self, path: str, entry: FilesystemEntry) -> FilesystemEntry:
        """Get a :class:`FilesystemEntry` relative to a specific entry."""
        parts = path.split("/")

        for i, part in enumerate(parts):
            if entry.is_symlink():
                # Resolve using the RootFilesystem instead of the entry's Filesystem
                entry = fsutil.resolve_link(
                    self,
                    entry.readlink(),
                    "/".join(parts[:i]),
                    alt_separator=entry.fs.alt_separator,
                )
            entry = entry.get(part)

        return entry


class EntryList(list):
    """Wrapper list for filesystem entries.

    Exposes a ``__getattr__`` on a list of items. Useful to access internal objects from filesystem implementations.
    For example, access the underlying NTFS object from a list of virtual and NTFS entries.
    """

    def __init__(self, value: FilesystemEntry | list[FilesystemEntry]):
        if not isinstance(value, list):
            value = [value]
        super().__init__(value)

    def __getattr__(self, attr: str) -> Any:
        for entry in self:
            try:
                return getattr(entry, attr)
            except AttributeError:  # noqa: PERF203
                continue
        else:
            return object.__getattribute__(self, attr)


class LayerFilesystemEntry(FilesystemEntry):
    def __init__(self, fs: Filesystem, path: str, entry: FilesystemEntry):
        super().__init__(fs, path, EntryList(entry))
        self.entries: EntryList = self.entry
        self._link = None

    def _exec(self, func: str, *args, **kwargs) -> Any:
        """Helper method to execute a method over all contained entries."""
        exc = []
        for entry in self.entries:
            try:
                return getattr(entry, func)(*args, **kwargs)
            except (AttributeError, NotImplementedError) as e:  # noqa: PERF203
                exc.append(str(e))

        exceptions = ",".join(exc) if exc else "No entries"

        raise FilesystemError(f"Can't resolve {func} for {self}: {exceptions}")

    def get(self, path: str) -> FilesystemEntry:
        return self.fs.get(path, self._resolve())

    def open(self) -> BinaryIO:
        return self._resolve()._exec("open")

    def iterdir(self) -> Iterator[str]:
        yielded = {".", ".."}
        selfentry = self._resolve()
        for fsentry in selfentry.entries:
            for entry_name in fsentry.iterdir():
                name = entry_name if selfentry.fs.case_sensitive else entry_name.lower()
                if name in yielded:
                    continue

                yield entry_name
                yielded.add(name)

    def scandir(self) -> Iterator[LayerFilesystemEntry]:
        # Every entry is actually a list of entries from the different
        # overlaying FSes, of which each may implement a different function
        # like .stat() or .open()
        items = defaultdict(list)
        selfentry = self._resolve()
        for fsentry in selfentry.entries:
            for entry in fsentry.scandir():
                name = entry.name if selfentry.fs.case_sensitive else entry.name.lower()
                if name in (".", ".."):
                    continue

                items[name].append(entry)

        for entries in items.values():
            # The filename for the first entry is taken. Note that in case of
            # non case-sensitive FSes, the different entries from the
            # overlaying FSes may have different casing of the name.
            entry_name = entries[0].name
            path = fsutil.join(selfentry.path, entry_name, alt_separator=selfentry.fs.alt_separator)
            yield LayerFilesystemEntry(selfentry.fs, path, entries)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks)._exec("is_file", follow_symlinks=follow_symlinks)
        except FileNotFoundError:
            return False

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks)._exec("is_dir", follow_symlinks=follow_symlinks)
        except FileNotFoundError:
            return False

    def is_symlink(self) -> bool:
        return self._exec("is_symlink")

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError(f"Not a link: {self}")
        return self._exec("readlink")

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks)._exec("stat", follow_symlinks=follow_symlinks)

    def lstat(self) -> fsutil.stat_result:
        return self._exec("lstat")

    def attr(self) -> Any:
        return self._resolve()._exec("attr")

    def lattr(self) -> Any:
        return self._exec("lattr")


class RootFilesystem(LayerFilesystem):
    __type__ = "root"

    def __init__(self, target: Target):
        self.target = target
        super().__init__()

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on RootFilesystem class")

    def get(self, path: str, relentry: LayerFilesystemEntry | None = None) -> RootFilesystemEntry:
        self.target.log.debug("%r::get(%r)", self, path)
        entry = super().get(path, relentry)
        entry.__class__ = RootFilesystemEntry
        return entry


class RootFilesystemEntry(LayerFilesystemEntry):
    fs: RootFilesystem

    def get(self, path: str) -> RootFilesystemEntry:
        self.fs.target.log.debug("%r::get(%r)", self, path)
        entry = super().get(path)
        entry.__class__ = RootFilesystemEntry
        return entry

    def open(self) -> BinaryIO:
        self.fs.target.log.debug("%r::open()", self)
        return super().open()

    def iterdir(self) -> Iterator[str]:
        self.fs.target.log.debug("%r::iterdir()", self)
        yield from super().iterdir()

    def scandir(self) -> Iterator[RootFilesystemEntry]:
        self.fs.target.log.debug("%r::scandir()", self)
        for entry in super().scandir():
            entry.__class__ = RootFilesystemEntry
            yield entry

    def is_file(self, follow_symlinks: bool = True) -> bool:
        self.fs.target.log.debug("%r::is_file()", self)
        return super().is_file(follow_symlinks=follow_symlinks)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        self.fs.target.log.debug("%r::is_dir()", self)
        return super().is_dir(follow_symlinks=follow_symlinks)

    def is_symlink(self) -> bool:
        self.fs.target.log.debug("%r::is_symlink()", self)
        return super().is_symlink()

    def readlink(self) -> str:
        self.fs.target.log.debug("%r::readlink()", self)
        return super().readlink()

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        self.fs.target.log.debug("%r::stat()", self)
        return super().stat(follow_symlinks=follow_symlinks)

    def lstat(self) -> fsutil.stat_result:
        self.fs.target.log.debug("%r::lstat()", self)
        return super().lstat()

    def attr(self) -> Any:
        self.fs.target.log.debug("%r::attr()", self)
        return super().attr()

    def lattr(self) -> Any:
        self.fs.target.log.debug("%r::lattr()", self)
        return super().lattr()


def register(module: str, class_name: str, internal: bool = True) -> None:
    """Register a filesystem implementation to use when opening a filesystem.

    This function registers a filesystem using ``module`` relative to the ``MODULE_PATH``.
    It lazily imports the module, and retrieves the specific class from it.

    Args:
        module: The module where to find the filesystem.
        class_name: The class to load.
        internal: Whether it is an internal module or not.
    """

    if internal:
        module = f"{MODULE_PATH}.{module}"

    FILESYSTEMS.append(getattr(import_lazy(module), class_name))


def is_multi_volume_filesystem(fh: BinaryIO) -> bool:
    for filesystem in FILESYSTEMS:
        try:
            if filesystem.__multi_volume__ and filesystem.detect(fh):
                return True
        except ImportError as e:  # noqa: PERF203
            log.info("Failed to import %s", filesystem)
            log.debug("", exc_info=e)

    return False


def open(fh: BinaryIO, *args, **kwargs) -> Filesystem:
    offset = fh.tell()
    fh.seek(0)

    try:
        for filesystem in FILESYSTEMS:
            try:
                if filesystem.detect(fh):
                    return filesystem(fh, *args, **kwargs)
            except ImportError as e:  # noqa: PERF203
                log.info("Failed to import %s", filesystem)
                log.debug("", exc_info=e)
            except Exception as e:
                raise FilesystemError(f"Failed to open filesystem for {fh}") from e
    finally:
        fh.seek(offset)

    raise FilesystemError(f"Failed to open filesystem for {fh}")


def open_multi_volume(fhs: list[BinaryIO], *args, **kwargs) -> Iterator[Filesystem]:
    for filesystem in FILESYSTEMS:
        try:
            if not filesystem.__multi_volume__:
                continue

            volumes = defaultdict(list)
            for fh in fhs:
                if not filesystem.detect(fh):
                    continue

                identifier = filesystem.detect_id(fh)
                volumes[identifier].append(fh)

            for vols in volumes.values():
                yield filesystem(vols, *args, **kwargs)

        except ImportError as e:
            log.info("Failed to import %s", filesystem)
            log.debug("", exc_info=e)


register("ntfs", "NtfsFilesystem")
register("extfs", "ExtFilesystem")
register("xfs", "XfsFilesystem")
register("fat", "FatFilesystem")
register("ffs", "FfsFilesystem")
register("vmfs", "VmfsFilesystem")
register("btrfs", "BtrfsFilesystem")
register("exfat", "ExfatFilesystem")
register("squashfs", "SquashFSFilesystem")
register("jffs", "JffsFilesystem")
register("qnxfs", "QnxFilesystem")
register("zip", "ZipFilesystem")
register("tar", "TarFilesystem")
register("vmtar", "VmtarFilesystem")
register("cpio", "CpioFilesystem")
register("vbk", "VbkFilesystem")
register("ad1", "AD1Filesystem")
