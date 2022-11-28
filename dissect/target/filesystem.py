from __future__ import annotations

import io
import logging
import os
import stat
from collections import defaultdict
from typing import Any, BinaryIO, Callable, Iterator, List, Optional, Type, Union

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.helpers import fsutil, hashutil
from dissect.target.helpers.lazy import import_lazy
from dissect.target.volume import Volume

FILESYSTEMS: list[Type[Filesystem]] = []
MODULE_PATH = "dissect.target.filesystems"

log = logging.getLogger(__name__)


class Filesystem:
    """Base class for filesystems."""

    __fstype__: str = None
    """Defines the type of filesystem it is."""

    def __init__(
        self,
        alt_separator: str = "",
        case_sensitive: bool = True,
        volume: Optional[Volume] = None,
    ) -> None:
        """The base initializer for the class.

        Args:
            case_sensitive: Defines if the paths in the Filesystem are case sensitive or not.
            alt_separator: The alternative separator used to distingish between directories in a path.
            volume: A volume associated with the filesystem.

        Raises:
            NotImplementedError: When the internal ``__fstype__`` of the class is not defined.
        """
        self.case_sensitive = case_sensitive
        self.alt_separator = alt_separator
        self.volume = volume
        if self.__fstype__ is None:
            raise NotImplementedError(f"{self.__class__.__name__} must define __fstype__")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"

    def path(self, *args) -> fsutil.TargetPath:
        """Get a specific path from the filesystem."""
        return fsutil.TargetPath(self, *args)

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        """Detect whether the ``fh`` file-handle contains a Filesystem implementation.

        Args:
            fh: A file-like object, usually an image of a disk.

        Returns:
            ``True`` if ``fh`` contains the filesystem, ``False`` otherwise.
        """
        raise NotImplementedError()

    def get(self, path: str) -> FilesystemEntry:
        """Retrieve a FilesystemEntry from the filesystem.

        Args:
            path: the path which we want retrieve.

        Returns:
            A FilesystemEntry(path) kind of object.
        """
        raise NotImplementedError()

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

    def listdir(self, path: str) -> List[str]:
        """List the contents of a directory as strings.

        Args:
            path: The directory to get the listing from.

        Returns:
            A list of path strings.
        """
        return list(self.iterdir(path))

    def listdir_ext(self, path: str) -> List[FilesystemEntry]:
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
        onerror: Optional[Callable] = None,
        followlinks: bool = False,
    ) -> Iterator[str]:
        """Walk a directory pointed to by ``path``, returning the string representation of both files and directories.

        It walks across all the files inside ``path`` recursively.

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
        onerror: Optional[Callable] = None,
        followlinks: bool = False,
    ) -> Iterator[FilesystemEntry]:
        """Walk a directory pointed to by ``path``, returning FilesystemEntry's of both files and directories.

        It walks across all the files inside ``path`` recursively.

        Args:
            path: The path to walk on the filesystem.
            topdown: ``True`` puts the ``path`` at the top, ``False`` puts the ``path`` at the bottom.
            onerror: A method to execute when an error occurs.
            followlinks: ``True`` if we want to follow any symbolic link.

        Returns:
            An iterator of directory entries as FilesystemEntry's.
        """
        return self.get(path).walk_ext(topdown, onerror, followlinks)

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
            for entry in fsutil.glob_ext(entry, pattern):
                yield entry

    def exists(self, path: str) -> bool:
        """
        Determines whether ``path`` exists on a filesystem.

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
            return True
        except Exception:
            return False

    def lexists(self, path: str) -> bool:
        """Determines if a ``path`` exists on the filesystem without resolving links.

        Args:
            path: A path on the filesystem.

        Returns:
            ``True`` if the given path is a file, ``False`` otherwise.
        """
        try:
            self.get(path)
            return True
        except Exception:
            return False

    def is_file(self, path: str) -> bool:
        """Determine if ``path`` is a file on the filesystem, resolving symlinks when possible.

        Args:
            path: the path on the filesystem.

        Returns:
            ``True`` if the given path is a file, ``False`` otherwise.
        """
        try:
            return self.get(path).is_file()
        except FileNotFoundError:
            return False

    def is_dir(self, path: str) -> bool:
        """Determine whether the given ``path`` is a directory on the filesystem, resolving symlinks when possible.

        Args:
            path: the path on the filesystem.

        Returns:
            ``True`` if the given path is a directory, ``False`` otherwise.
        """
        try:
            return self.get(path).is_dir()
        except FileNotFoundError:
            return False

    def is_symlink(self, path: str) -> bool:
        """Determine wether the given ``path`` is a symlink on the filesystem.

        Args:
            path: the path on the filesystem.

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
            path: the symbolic link to read.

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

    def stat(self, path: str) -> fsutil.stat_result:
        """Determine the stat information of a ``path`` on the filesystem, resolving any symlinks.

        If the path is a symlink, it gets resolved, attempting to stat the path where to points to.

        Args:
            path: The filesystem path we want the stat information from.

        Returns:
            The stat information of the given path.
        """
        return self.get(path).stat()

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

    def hash(self, path: str, algos: Optional[Union[List[str], List[Callable]]] = None) -> tuple[str]:
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

    def __init__(self, fs: Filesystem, path: str, entry: FilesystemEntry) -> None:
        """Initialize the base filesystem entry class.

        Args:
            fs: The filesystem to get data from.
            path: The path of the entry mapped on ``fs``.
            entry: The entry relative to this one.
        """
        self.fs = fs
        self.path = path
        self.name = fsutil.basename(path, alt_separator=self.fs.alt_separator)
        self.entry = entry

    def __repr__(self):
        return f"<{self.__class__.__name__} {self.path!r}>"

    def __str__(self):
        return str(self.path)

    def get(self, path: str) -> FilesystemEntry:
        """Retrieve a FilesystemEntry relative to this entry.

        Args:
            path: The path relative to this filesystem entry.

        Returns:
            A relative FilesystemEntry.
        """
        raise NotImplementedError()

    def open(self) -> BinaryIO:
        """Open this filesystem entry.

        Returns:
            A file-like object. Resolves symlinks when possible
        """
        raise NotImplementedError()

    def iterdir(self) -> Iterator[str]:
        """Iterate over the contents of a directory, return them as strings.

        Returns:
            An iterator of directory entries as path strings.
        """
        raise NotImplementedError()

    def scandir(self) -> Iterator[FilesystemEntry]:
        """Iterate over the contents of a directory, return them as FilesystemEntry's.

        Returns:
            An iterator of directory entries as FilesystemEntry's.
        """
        raise NotImplementedError()

    def listdir(self) -> List[str]:
        """List the contents of a directory as strings.

        Returns:
            A list of path strings.
        """
        return list(self.iterdir())

    def listdir_ext(self) -> List[FilesystemEntry]:
        """List the contents of a directory as FilesystemEntry's.

        Returns:
            A list of FilesystemEntry's.
        """
        return list(self.scandir())

    def walk(
        self,
        topdown: bool = True,
        onerror: Optional[Callable] = None,
        followlinks: bool = False,
    ) -> Iterator[str]:
        """Walk a directory and list its contents as strings.

        It walks across all the files inside the entry recursively.

        These contents include::
          - files
          - directories
          - symboliclinks

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
        onerror: Optional[Callable] = None,
        followlinks: bool = False,
    ) -> Iterator[FilesystemEntry]:
        """Walk a directory and show its contents as FilesystemEntry's.

        It walks across all the files inside the entry recursively.

        These contents include::
          - files
          - directories
          - symboliclinks

        Args:
            topdown: ``True`` puts this entry at the top of the list, ``False`` puts this entry at the bottom.
            onerror: A method to execute when an error occurs.
            followlinks: ``True`` if we want to follow any symbolic link

        Returns:
            An iterator of directory entries as FilesystemEntry's.
        """
        yield from fsutil.walk_ext(self, topdown, onerror, followlinks)

    def glob(self, pattern) -> Iterator[str]:
        """Iterate over this directory part of ``patern``, returning entries matching ``pattern`` as strings.

        Args:
            pattern: The pattern to match.

        Returns:
            An iterator of path strings that match the pattern.
        """
        for entry in self.glob_ext(pattern):
            yield entry.path

    def glob_ext(self, pattern) -> Iterator[FilesystemEntry]:
        """Iterate over the directory part of ``pattern``, returning entries matching ``pattern`` as FilesysmteEntry's.

        Args:
            pattern: The pattern to glob for.

        Returns:
            An iterator of FilesystemEntry's that match the pattern.
        """
        yield from fsutil.glob_ext(self, pattern)

    def exists(self, path: str) -> bool:
        """Determines whether a ``path``, relative to this entry, exists.

        If the `path` is a symbolic link, it will attempt to resolve it to find the FilesystemEntry it points to.

        Args:
            path: The path relative to this entry.

        Returns:
            ``True`` if the path exists, ``False`` otherwise.
        """
        try:
            entry = self.get(path)
            if entry.is_symlink():
                entry.readlink_ext()
            return True
        except Exception:
            return False

    def lexists(self, path: str) -> bool:
        """Determine wether a ``path`` relative to this enty, exists without resolving links.

        Args:
            path: The path relative to this entry.

        Returns:
            ``True`` if the path exists, ``False`` otherwise.
        """
        try:
            self.get(path)
            return True
        except Exception:
            return False

    def is_file(self) -> bool:
        """Determine if this entry is a file, resolving symlinks when possible.

        Returns:
            ``True`` if the entry is a file, ``False`` otherwise.
        """
        raise NotImplementedError()

    def is_dir(self) -> bool:
        """Determine if this entry is a directory, resolving symlinks when possible.

        Returns:
            ``True`` if the entry is a directory, ``False`` otherwise.
        """
        raise NotImplementedError()

    def is_symlink(self) -> bool:
        """Determine wether this entry is a symlink.

        Returns:
            ``True`` if the entry is a symbolic link, ``False`` otherwise.
        """
        raise NotImplementedError()

    def readlink(self) -> str:
        """Read the link where this entry points to, return the resulting path as string.

        If it is a symlink and returns the entry that corresponds to that path.
        This means it follows the path a link points to, it tries to do it recursively.

        Returns:
            The path the link points to."""
        raise NotImplementedError()

    def readlink_ext(self) -> FilesystemEntry:
        """Read the link where this entry points to, return the resulting path as FilesystemEntry.

        If it is a symlink and returns the string that corresponds to that path.
        This means it follows the path a link points to, it tries to do it recursively.

        Returns:
            The filesystem entry the link points to.
        """
        log.debug("%r::readlink_ext()", self)
        # Default behavior, resolve link own filesystem.
        return fsutil.resolve_link(fs=self.fs, entry=self)

    def stat(self) -> fsutil.stat_result:
        """Determine the stat information of this entry, resolving any symlinks.

        If the entry is a symlink, it gets resolved, attempting to stat the path where to points to.

        Returns:
            The stat information of this entry.
        """
        raise NotImplementedError()

    def lstat(self) -> fsutil.stat_result:
        """Determine the stat information of this entry, **without** resolving the symlinks.

        When it detects a symlink, it will stat the information of the symlink, not the path it points to.

        Returns:
            The stat information of this entry.
        """
        raise NotImplementedError()

    def attr(self) -> Any:
        """The attributes related to this entry, resolving any symlinks.

        If the entry is a symbolic link, it will attempt to resolve it first.
        Resulting in the attr information of the entry it points to.

        Returns:
            The attributes of this entry.
        """
        raise NotImplementedError()

    def lattr(self) -> Any:
        """The attributes related to this current entry, **without** resolving links.

        Returns:
            The attributes of this entry.
        """
        raise NotImplementedError()

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

    def hash(self, algos: Optional[Union[List[str], List[Callable]]] = None) -> tuple[str]:
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

    def __init__(self, fs, path):
        super().__init__(fs, path, None)
        self.up = None
        self.top = None
        self.entries = {}

    def __getitem__(self, item):
        if not self.fs.case_sensitive:
            item = item.lower()
        return self.entries[item]

    def __contains__(self, item):
        if not self.fs.case_sensitive:
            item = item.lower()
        return item in self.entries

    def open(self):
        raise IsADirectoryError(f"{self.path} is a directory")

    def attr(self):
        raise TypeError(f"attr is not allowed on VirtualDirectory: {self.path}")

    def lattr(self):
        raise TypeError(f"lattr is not allowed on VirtualDirectory: {self.path}")

    def add(self, name, entry):
        """Add an entry to this VirtualDirectory."""
        if not self.fs.case_sensitive:
            name = name.lower()

        self.entries[name] = entry

    def get(self, path):
        return self.fs.get(path, relentry=self)

    def iterdir(self):
        yielded = set()
        for entry in self.entries.keys():
            yield entry
            yielded.add(entry)

        # self.top used to be a reference to a filesystem. This is now a reference to
        # any filesystem entry, usually the root of a filesystem.
        if self.top:
            for entry in self.top.iterdir():
                if entry in yielded or (not self.fs.case_sensitive and entry.lower() in yielded):
                    continue
                yield entry

    def scandir(self):
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

    def _stat(self):
        path_addr = fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator)
        return fsutil.stat_result([stat.S_IFDIR, path_addr, id(self.fs), 0, 0, 0, 0, 0, 0, 0])

    def stat(self):
        if self.top:
            return self.top.stat()
        return self._stat()

    def lstat(self):
        if self.top:
            return self.top.lstat()
        return self._stat()

    def is_dir(self):
        return True

    def is_file(self):
        return False

    def is_symlink(self):
        return False

    def readlink(self):
        raise NotASymlinkError()

    def readlink_ext(self):
        raise NotASymlinkError()


class MappedFile(FilesystemEntry):
    """Virtual file backed by a file on the host machine."""

    def __init__(self, fs, path, realpath):
        super().__init__(fs, path, realpath)

    def attr(self):
        raise NotADirectoryError(f"'{self.path}' is not a directory")

    def iterdir(self):
        raise NotADirectoryError(f"'{self.path}' is not a directory")

    def scandir(self):
        raise NotADirectoryError(f"'{self.path}' is not a directory")

    def open(self):
        return io.open(self.entry, "rb")

    def stat(self):
        return fsutil.stat_result.copy(os.stat(self.entry))

    def lstat(self):
        return fsutil.stat_result.copy(os.lstat(self.entry))

    def is_dir(self):
        return False

    def is_file(self):
        return True

    def is_symlink(self):
        return False

    def readlink(self):
        raise FilesystemError("MappedFile does not support symlinks.")

    def readlink_ext(self):
        raise FilesystemError("MappedFile does not support symlinks.")


class VirtualFileHandle(io.RawIOBase):
    def __init__(self, fh):
        self.fh = fh
        self.seek(0)

    def readinto(self, b: bytearray) -> int:
        return self.fh.readinto(b)

    def seek(self, offset, whence=io.SEEK_SET):
        return self.fh.seek(offset, whence)

    def readable(self):
        return True

    def seekable(self):
        return True


class VirtualFile(FilesystemEntry):
    """Virtual file backed by a file-like object."""

    def __init__(self, fs, path, fileobject):
        super().__init__(fs, path, fileobject)

    def attr(self):
        raise TypeError(f"attr is not allowed on VirtualFile: {self.path}")

    def lattr(self):
        raise TypeError(f"lattr is not allowed on VirtualFile: {self.path}")

    def get(self, path):
        path = fsutil.normalize(path, alt_separator=self.fs.alt_separator).strip("/")
        if not path:
            return self
        raise NotADirectoryError(f"'{self.path}' is not a directory")

    def iterdir(self):
        raise NotADirectoryError(f"'{self.path}' is not a directory")

    def scandir(self):
        raise NotADirectoryError(f"'{self.path}' is not a directory")

    def open(self):
        return VirtualFileHandle(self.entry)

    def stat(self):
        size = getattr(self.entry, "size", 0)
        file_addr = fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator)
        return fsutil.stat_result([stat.S_IFREG, file_addr, id(self.fs), 0, 0, 0, size, 0, 0, 0])

    lstat = stat

    def is_dir(self):
        return False

    def is_file(self):
        return True

    def is_symlink(self):
        return False

    def readlink(self):
        raise FilesystemError("VirtualFile does not support symlinks.")

    def readlink_ext(self):
        raise FilesystemError("VirtualFile does not support symlinks.")


class VirtualSymlink(FilesystemEntry):
    """Virtual symlink implementation."""

    def __init__(self, fs, path, target):
        super().__init__(fs, path, None)
        self.target = target

    def attr(self):
        return self.readlink_ext().attr()

    def lattr(self):
        raise TypeError(f"lattr is not allowed on VirtualSymlink: {self.path}")

    def get(self, path):
        return self.fs.get(path, self)

    def iterdir(self):
        yield from self.readlink_ext().iterdir()

    def scandir(self):
        yield from self.readlink_ext().scandir()

    def open(self):
        return self.readlink_ext().open()

    def stat(self):
        return self.readlink_ext().stat()

    def lstat(self):
        link_addr = fsutil.generate_addr(self.path, alt_separator=self.fs.alt_separator)
        return fsutil.stat_result([stat.S_IFLNK, link_addr, id(self.fs), 0, 0, 0, len(self.target), 0, 0, 0])

    def is_dir(self):
        return self.readlink_ext().is_dir()

    def is_file(self):
        return self.readlink_ext().is_file()

    def is_symlink(self):
        return True

    def readlink(self):
        return self.target


class VirtualFilesystem(Filesystem):
    __fstype__ = "virtual"

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.root = VirtualDirectory(self, "/")

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on VirtualFilesystem class")

    def get(self, path: str, relentry: FilesystemEntry = None) -> FilesystemEntry:
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
            elif part == ".":
                continue
            elif part == "..":
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
                        raise FileNotFoundError(full_path, cause=e)
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

    def map_fs(self, vfspath: str, fs: Filesystem) -> None:
        """Mount a dissect filesystem to a directory in the VFS"""
        directory = self.makedirs(vfspath)
        directory.top = fs.get("/")

    mount = map_fs

    def map_dir(self, vfspath: str, realpath: str) -> None:
        """Recursively map a directory from the host machine into the VFS."""
        vfspath = fsutil.normalize(vfspath, alt_separator=self.alt_separator).strip("/")
        base = os.path.abspath(realpath)

        for root, dirs, files in os.walk(base):
            relroot = os.path.relpath(root, base)
            if relroot == ".":
                relroot = ""

            vfsroot = fsutil.join(vfspath, relroot, alt_separator=self.alt_separator)
            directory = self.makedirs(vfsroot)

            for dir_ in dirs:
                vfs_dir = fsutil.join(vfsroot, dir_, alt_separator=self.alt_separator)
                self.makedirs(vfs_dir)

            for file_ in files:
                vfs_file_path = fsutil.join(vfsroot, file_, alt_separator=self.alt_separator)
                real_file_path = os.path.join(root, file_)
                directory.add(file_, MappedFile(self, vfs_file_path, real_file_path))

    def map_file(self, vfspath: str, realpath: str) -> None:
        """Map a file from the host machine into the VFS."""
        vfspath = fsutil.normalize(vfspath, alt_separator=self.alt_separator)
        if vfspath[-1] == "/":
            raise AttributeError(f"Can't map a file onto a directory: {vfspath}")
        file_path = vfspath.lstrip("/")
        self.map_file_entry(vfspath, MappedFile(self, file_path, realpath))

    def map_file_fh(self, vfspath: str, fh: BinaryIO) -> None:
        """Map a file handle into the VFS."""
        vfspath = fsutil.normalize(vfspath, alt_separator=self.alt_separator)
        if vfspath[-1] == "/":
            raise AttributeError(f"Can't map a file onto a directory: {vfspath}")
        file_path = vfspath.lstrip("/")
        self.map_file_entry(vfspath, VirtualFile(self, file_path, fh))

    def map_file_entry(self, vfspath: str, entry: FilesystemEntry) -> None:
        """Map a FilesystemEntry into the VFS.

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

    def link(self, src: str, dst: str) -> None:
        """Hard link a FilesystemEntry to another location."""
        self.map_file_entry(dst, self.get(src))

    def symlink(self, src: str, dst: str) -> None:
        """Create a symlink to another location."""
        src = fsutil.normalize(src, alt_separator=self.alt_separator).strip("/")
        dst = fsutil.normalize(dst, alt_separator=self.alt_separator).strip("/")
        self.map_file_entry(dst, VirtualSymlink(self, dst, src))


class RootFilesystem(Filesystem):
    __fstype__ = "root"

    def __init__(self, target):
        self.target = target
        self.layers = []
        self.mounts = {}
        self._alt_separator = "/"
        self._case_sensitive = True
        self._root_entry = RootFilesystemEntry(self, "/", [])
        self.root = self.add_layer()
        super().__init__()

    @staticmethod
    def detect(fh):
        raise TypeError("Detect is not allowed on RootFilesystem class")

    def mount(self, path, fs):
        """Mount a filesystem at a given path.

        If there's an overlap with an existing mount, creates a new layer.
        """
        root = self.root
        for mount in self.mounts.keys():
            if path == mount:
                continue

            if path.startswith(mount):
                root = self.add_layer()
                break

        root.map_fs(path, fs)
        self.mounts[path] = fs

    def link(self, dst, src):
        """Hard link a RootFilesystemEntry to another location."""
        dst = fsutil.normalize(dst, alt_separator=self.alt_separator)
        self.root.map_file_entry(dst, self.get(src))

    def symlink(self, dst, src):
        """Create a symlink to another location."""
        self.root.symlink(dst, src)

    def add_layer(self, **kwargs):
        layer = VirtualFilesystem(case_sensitive=self.case_sensitive, alt_separator=self.alt_separator, **kwargs)
        self.layers.append(layer)
        self._root_entry.entries.append(layer.root)
        return layer

    @property
    def case_sensitive(self):
        return self._case_sensitive

    @property
    def alt_separator(self):
        return self._alt_separator

    @case_sensitive.setter
    def case_sensitive(self, value):
        self._case_sensitive = value
        self.root.case_sensitive = value
        for layer in self.layers:
            layer.case_sensitive = value

    @alt_separator.setter
    def alt_separator(self, value):
        self._alt_separator = value
        self.root.alt_separator = value
        for layer in self.layers:
            layer.alt_separator = value

    def get(self, path, relentry=None):
        self.target.log.debug("%r::get(%r)", self, path)

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
            except FilesystemError as e:
                exc.append(e)

        if not entries:
            if all([isinstance(ex, NotADirectoryError) for ex in exc]):
                raise NotADirectoryError(full_path)
            elif all([isinstance(ex, NotASymlinkError) for ex in exc]):
                raise NotASymlinkError(full_path)
            raise FileNotFoundError(full_path)

        return RootFilesystemEntry(self, full_path, entries)

    def _get_from_entry(self, path, entry):
        parts = path.split("/")

        for part in parts:
            if entry.is_symlink():
                # Resolve using the RootFilesystem instead of the entry's Filesystem
                entry = fsutil.resolve_link(fs=self, entry=entry)
            entry = entry.get(part)

        return entry


class EntryList(list):
    """Wrapper list for filesystem entries.

    Expose a getattr on a list of items. Useful in cases where
    there's a virtual filesystem entry as well as a real one.
    """

    def __init__(self, value, subattribute=None):
        if not isinstance(value, list):
            value = [value]
        self._sub = subattribute
        super().__init__(value)

    def __getattr__(self, attr):
        for e in self:
            if self._sub:
                try:
                    e = getattr(e, self._sub)
                except AttributeError:
                    continue

            try:
                return getattr(e, attr)
            except AttributeError:
                continue
        else:
            return object.__getattribute__(self, attr)


class RootFilesystemEntry(FilesystemEntry):
    def __init__(self, fs, path, entry):
        super().__init__(fs, path, EntryList(entry, "entry"))
        self.entries = self.entry
        self._link = None

    def __getattr__(self, attr):
        for entry in self.entries:
            try:
                return getattr(entry, attr)
            except AttributeError:
                continue

        return object.__getattribute__(self, attr)

    def _exec(self, func, *args, **kwargs):
        """Helper method to execute a method over all contained entries."""
        exc = []
        for entry in self.entries:
            try:
                return getattr(entry, func)(*args, **kwargs)
            except (AttributeError, NotImplementedError) as e:
                exc.append(str(e))

        if exc:
            exceptions = ",".join(exc)
        else:
            exceptions = "No entries"
        raise FilesystemError(f"Can't resolve {func} for {self}: {exceptions}")

    def _resolve(self):
        """Helper method to resolve symbolic links."""
        if self.is_symlink():
            return self.readlink_ext()
        return self

    def get(self, path):
        self.fs.target.log.debug("%r::get(%r)", self, path)
        return self.fs.get(path, self._resolve())

    def open(self):
        self.fs.target.log.debug("%r::open()", self)
        return self._resolve()._exec("open")

    def iterdir(self):
        self.fs.target.log.debug("%r::iterdir()", self)
        yielded = {".", ".."}
        selfentry = self._resolve()
        for fsentry in selfentry.entries:
            for entry_name in fsentry.iterdir():
                name = entry_name if selfentry.fs.case_sensitive else entry_name.lower()
                if name in yielded:
                    continue

                yield entry_name
                yielded.add(name)

    def scandir(self):
        self.fs.target.log.debug("%r::scandir()", self)
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
            yield RootFilesystemEntry(selfentry.fs, path, entries)

    def is_file(self):
        self.fs.target.log.debug("%r::is_file()", self)
        try:
            return self._resolve()._exec("is_file")
        except FileNotFoundError:
            return False

    def is_dir(self):
        self.fs.target.log.debug("%r::is_dir()", self)
        try:
            return self._resolve()._exec("is_dir")
        except FileNotFoundError:
            return False

    def is_symlink(self):
        self.fs.target.log.debug("%r::is_symlink()", self)
        return self._exec("is_symlink")

    def readlink(self):
        self.fs.target.log.debug("%r::readlink()", self)
        if not self.is_symlink():
            raise FilesystemError(f"Not a link: {self}")
        return self._exec("readlink")

    def stat(self):
        self.fs.target.log.debug("%r::stat()", self)
        return self._resolve()._exec("stat")

    def lstat(self):
        self.fs.target.log.debug("%r::lstat()", self)
        return self._exec("lstat")

    def attr(self):
        self.fs.target.log.debug("%r::attr()", self)
        return self._resolve()._exec("attr")

    def lattr(self):
        self.fs.target.log.debug("%r::lattr()", self)
        return self._exec("attr")


def register(module: str, class_name: str, internal: bool = True):
    """Register a filesystem implementation to use when opening a filesystem.

    This function registers a filesystem using ``module`` relative to the ``MODULE_PATH``.
    It lazily imports the module, and retrieves the specific class from it.

    Args:
        module: The module where to find the filesystem.
        class_name: The class to load.
        internal: Whether it is an internal module or not.
    """

    if internal:
        module = ".".join([MODULE_PATH, module])

    FILESYSTEMS.append(getattr(import_lazy(module), class_name))


def open(fh, *args, **kwargs):

    for filesystem in FILESYSTEMS:
        try:
            if filesystem.detect(fh):
                instance = filesystem(fh, *args, **kwargs)
                instance.volume = fh
                return instance
        except ImportError as e:
            log.warning("Failed to import %s", filesystem)
            log.debug("", exc_info=e)

    raise FilesystemError(f"Failed to open filesystem for {fh}")


register("ntfs", "NtfsFilesystem")
register("extfs", "ExtFilesystem")
register("xfs", "XfsFilesystem")
register("fat", "FatFilesystem")
register("ffs", "FfsFilesystem")
register("vmfs", "VmfsFilesystem")
register("exfat", "ExfatFilesystem")
register("ad1", "AD1Filesystem")
