from __future__ import annotations

import logging
import re
import stat
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.util.stream import AlignedStream

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry
from dissect.target.helpers import fsutil

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

log = logging.getLogger(__name__)


def ttl_cache(ttl: int = 60) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Decorator to cache the result of a function for a specified time-to-live (TTL).

    Args:
        ttl (int): Time-to-live in seconds for the cache. Default is 60 seconds.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        cache = {}

        def wrapper(*args, **kwargs) -> Any:
            if (key := (args, frozenset(kwargs.items()))) in cache:
                ts, result = cache[key]
                if time.monotonic() - ts < ttl:
                    return result
                del cache[key]

            result = func(*args, **kwargs)
            cache[key] = (time.monotonic(), result)
            return result

        return wrapper

    return decorator


class ShellFilesystem(Filesystem):
    """Base class for shell-based filesystems.

    This class provides a common interface for filesystems that interact with the shell, such as SSH, Netcat, or other
    remote execution environments.
    It uses a dialect system to handle different shell command sets and behaviors.

    Args:
        dialect: The dialect to use for shell commands. Can be a string name, a dialect class, or an instance.
                 Default is "auto", which will try to select a suitable dialect automatically.
        ttl: Time-to-live for cached results. Default is 60 seconds.
    """

    __fstype__ = "shell"

    def __init__(self, dialect: type[Dialect] | Dialect | str = "auto", ttl: int = 60, *args, **kwargs):
        super().__init__(None, *args, **kwargs)

        if isinstance(dialect, type) and issubclass(dialect, Dialect):
            # If a dialect class is provided, use it directly
            self.dialect = dialect(self)
        elif isinstance(dialect, Dialect):
            # If a dialect instance is provided, use it directly
            self.dialect = dialect
        elif dialect in DIALECT_MAP:
            # Use a predefined dialect by name
            self.dialect = DIALECT_MAP[dialect](self)
        elif dialect == "auto":
            # Automatically try to select a dialect
            self.dialect = self._select_dialect(DIALECT_MAP.keys())
        else:
            raise FilesystemError(f"Invalid dialect specified: {dialect}")

        log.debug("Using dialect %r for ShellFilesystem", self.dialect.__type__)

        self.execute = ttl_cache(ttl)(self.execute)

    def _select_dialect(self, dialect: Iterator[str]) -> Dialect:
        for name in dialect:
            if name not in DIALECT_MAP:
                raise FilesystemError(f"Invalid dialect specified: {name}")
            if (obj := DIALECT_MAP[name](self)).detect():
                return obj
        raise FilesystemError(f"No compatible dialect found from {dialect}")

    @staticmethod
    def detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on ShellFilesystem class")

    def execute(self, command: str) -> tuple[bytes, bytes]:
        """Execute a shell command and return its stdout and stderr streams.

        Args:
            command: The shell command to execute.
        """
        raise NotImplementedError

    def get(self, path: str) -> ShellFilesystemEntry:
        path = fsutil.normalize(path, self.alt_separator)

        try:
            return ShellFilesystemEntry(self, path, self.dialect.lstat(path))
        except FilesystemError:
            raise
        except Exception as e:
            raise FilesystemError(f"Failed to get entry for {path}: {e}") from e


class Dialect:
    """Base class for shell dialects.

    Dialects define how to interact with the shell filesystem, including commands for listing directories,
    reading files, and handling symlinks. Each dialect should implement the methods defined here.

    Args:
        fs: The shell filesystem instance that this dialect operates on.
    """

    __type__ = None

    def __init__(self, fs: ShellFilesystem):
        self.fs = fs

    def detect(self) -> bool:
        """Detect if this dialect is compatible with the current shell environment.

        Returns:
            ``True`` if the dialect is compatible, ``False`` otherwise.
        """
        raise NotImplementedError

    def open(self, path: str) -> BinaryIO:
        """Open a file at the given path.

        Args:
            path: The path to the file to open.

        Returns:
            A file-like object for reading the file.
        """
        raise NotImplementedError

    def iterdir(self, path: str) -> Iterator[str]:
        """Iterate over the entries in a directory.

        Args:
            path: The path to the directory to list.

        Returns:
            An iterator over the names of entries in the directory.
        """
        raise NotImplementedError

    def scandir(self, path: str) -> Iterator[tuple[str, fsutil.stat_result]]:
        """Scan a directory and yield name and stat result tuples.

        Args:
            path: The path to the directory to scan.

        Returns:
            An iterator over tuples containing the name of each entry and its stat result.
        """
        raise NotImplementedError

    def readlink(self, path: str) -> str:
        """Read the target of a symlink.

        Args:
            path: The path to the symlink.

        Returns:
            The target of the symlink.
        """
        raise NotImplementedError

    def lstat(self, path: str) -> fsutil.stat_result:
        """Get the status of a file or symlink without following the symlink.

        Args:
            path: The path to the file or symlink.

        Returns:
            A :class:`fsutil.stat_result` object containing file metadata.
        """
        raise NotImplementedError


RE_LINUX_STAT = re.compile(
    r"""
    \s*File:\s
        [\'\"]?(?P<filename>[\S\s]+?)[\'\"]?
        # Optional target for symlinks
        (\s -> \s[\'\"]?(?P<target>[\S\s]+?)[\'\"]?)?
    \n
    \s*Size:\s(?P<size>\d+)\s+
        Blocks:\s(?P<blocks>\d+)\s+
        # Can be either 'IO Block' or 'IO Blocks'
        IO\sBlock(s)?:\s(?P<io_blocks>\d+)\s+
        (?P<type_str>[^\n]+)
    \n
    \s*Device:\s(?P<device>[^\s]+)\s+
        Inode:\s(?P<inode>\d+)\s+
        Links:\s(?P<links>\d+)\s*
        # Device type is not always present
        (?:Device\stype:\s(?P<device_type>[^\n]+))?
    \n
    \s*Access:\s\((?P<permissions>\d+)/(?P<filemode>[^\)]+)\)\s+
        Uid:\s\((\s*)?(?P<uid>\d+)/(\s*)?(?P<username>[^\)]+)\)\s+
        Gid:\s\((\s*)?(?P<gid>\d+)/(\s*)?(?P<groupname>[^\)]+)\)
    \n
    \s*Access:\s
        (?P<atime>[^\n]+)
    \n
    \s*Modify:\s
        (?P<mtime>[^\n]+)
    \n
    \s*Change:\s
        (?P<ctime>[^\n]+)
    (?:\s*Birth:\s
        (?P<btime>[^\n]+)
    )?
    (?:\s|\n|$)
    """,
    re.VERBOSE,
)
RE_LINUX_TS = re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(?P<ns>\d+)(?: (?P<tz>.+))?")


class LinuxDialect(Dialect):
    """A basic Linux shell dialect, using ``find``, ``readlink``, and ``stat`` commands."""

    __type__ = "linux"

    def detect(self) -> bool:
        try:
            return next(self.iterdir("/"), None) is not None
        except Exception:
            return False

    def open(self, path: str, size: int) -> DdStream:
        return DdStream(self.fs, path, size)

    def iterdir(self, path: str) -> Iterator[str]:
        path = _escape_path(path)
        stdout, stderr = self.fs.execute(f"find {path}/ -mindepth 1 -maxdepth 1 -print0")

        if not stdout and stderr:
            exc, msg = _stderr_to_exception(stderr.decode())
            raise exc(f"Failed to list directory {path}: {msg}")

        for line in stdout.decode().split("\x00"):
            if not (line := line.strip()) or line in (".", ".."):
                continue

            yield fsutil.basename(line, self.fs.alt_separator)

    def scandir(self, path: str) -> Iterator[tuple[str, fsutil.stat_result]]:
        for name in self.iterdir(path):
            entry_path = fsutil.join(path, name, alt_separator=self.fs.alt_separator)
            yield name, self.lstat(entry_path)

    def readlink(self, path: str) -> str:
        path = _escape_path(path)
        stdout, stderr = self.fs.execute(f"readlink -n {path}")
        if not stdout:
            exc, msg = _stderr_to_exception(stderr.decode())
            raise exc(f"Failed to read symlink {path}: {msg}")
        return stdout.decode().strip()

    def lstat(self, path: str) -> str:
        path = _escape_path(path)
        stdout, stderr = self.fs.execute(f"stat {path}")

        if not stdout:
            exc, msg = _stderr_to_exception(stderr.decode())
            raise exc(f"Failed to list directory {path}: {msg}")

        if not (match := RE_LINUX_STAT.match(stdout.decode())):
            raise FilesystemError(f"Failed to parse stat output for {path}")

        return self._parse_stat(match)

    def _parse_stat(self, match: re.Match) -> fsutil.stat_result | None:
        if "h/" in match.group("device"):
            # Format (#h/#d), hex / decimal device number
            dev = int(match.group("device").split("h", 1)[0], 16)
        if "," in match.group("device"):
            # Format (#,#), major, minor device number
            major, minor = map(int, match.group("device").split(","))
            dev = ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & 0xFFF00) << 12)

        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        st_info = fsutil.stat_result(
            [
                _parse_filemode(match.group("filemode")) | int(match.group("permissions"), 8),
                int(match.group("inode")),
                dev,
                int(match.group("links")),
                int(match.group("uid")),
                int(match.group("gid")),
                int(match.group("size")),
                self._parse_ts(match.group("atime")).timestamp(),
                self._parse_ts(match.group("mtime")).timestamp(),
                self._parse_ts(match.group("ctime")).timestamp(),
            ]
        )

        if (btime := match.group("btime")) and btime != "-":
            st_info.st_birthtime = self._parse_ts(match.group("btime")).timestamp()

        return st_info

    def _parse_ts(self, ts: str) -> datetime:
        fmt = "%Y-%m-%d %H:%M:%S"

        ns = 0
        tz = None
        if match := RE_LINUX_TS.match(ts):
            ts = match.group("ts")
            ns = int(match.group("ns"))
            tz = match.group("tz")

        if tz:
            # If a timezone is provided, append it to the timestamp
            ts = f"{ts} {match.group('tz')}"
            fmt += " %z"

        parsed = datetime.strptime(ts, fmt)  # noqa: DTZ007
        if ns:
            # Add nanoseconds to the parsed datetime
            parsed = parsed.replace(microsecond=ns // 1000)

        if not tz:
            # If no timezone is provided, assume UTC
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed


class LinuxFastDialect(LinuxDialect):
    """A faster Linux shell dialect, using a ``stat 'path'/*`` wildcard expansion trick to list directories and get
    stat information in a single command."""

    __type__ = "linux-fast"

    def detect(self) -> bool:
        try:
            return next(self.scandir("/"), None) is not None
        except Exception:
            return False

    def scandir(self, path: str) -> Iterator[tuple[str, fsutil.stat_result]]:
        path = _escape_path(path)
        stdout, stderr = self.fs.execute(f"stat {path}/*")

        if not stdout and stderr:
            exc, msg = _stderr_to_exception(stderr.decode())
            raise exc(f"Failed to list directory {path}: {msg}")

        for match in RE_LINUX_STAT.finditer(stdout.decode()):
            filename = fsutil.basename(match.group("filename"), self.fs.alt_separator)
            yield filename, self._parse_stat(match)


def _blockdev_size(fs: ShellFilesystem, path: str) -> int:
    """Get the size of a block device using ``blockdev --getsize64``."""
    path = _escape_path(path)
    stdout, stderr = fs.execute(f"blockdev --getsize64 {path}")
    if not stdout:
        exc, msg = _stderr_to_exception(stderr.decode())
        raise exc(f"Failed to get size of block device {path}: {msg}")

    try:
        return int(stdout.decode().strip())
    except ValueError as e:
        raise FilesystemError(f"Invalid size for block device {path}: {e}") from e


def _escape_path(path: str) -> str:
    escaped = path.replace("'", "\\'")
    return f"'{escaped}'"


DIALECT_MAP: dict[str, type[Dialect]] = {
    "linux-fast": LinuxFastDialect,
    "linux": LinuxDialect,
}


def _parse_filemode(mode: str) -> int:
    filetype_map = {
        "-": stat.S_IFREG,  # Regular file
        "d": stat.S_IFDIR,  # Directory
        "l": stat.S_IFLNK,  # Symlink
        "s": stat.S_IFSOCK,  # Socket
        "b": stat.S_IFBLK,  # Block device
        "c": stat.S_IFCHR,  # Character device
        "p": stat.S_IFIFO,  # Named pipe (FIFO)
    }

    return filetype_map.get(mode[0], 0)


def _stderr_to_exception(stderr: str) -> tuple[type[FilesystemError], str]:
    if not stderr:
        return FilesystemError, "Unknown error"

    # Extract the error message from the stderr output
    err_msg = stderr.strip().rsplit(":", 1)[-1].strip()

    if err_msg == "No such file or directory":
        return FileNotFoundError, err_msg

    if err_msg == "Not a directory":
        return NotADirectoryError, err_msg

    if err_msg == "Is a directory":
        return IsADirectoryError, err_msg

    return FilesystemError, f"Filesystem error: {err_msg}"


class ShellFilesystemEntry(FilesystemEntry):
    """A filesystem entry for shell-based filesystems."""

    fs: ShellFilesystem
    entry: fsutil.stat_result

    def get(self, path: str) -> FilesystemEntry:
        return self.fs.get(fsutil.join(self.path, path, alt_separator=self.fs.alt_separator))

    def iterdir(self) -> Iterator[str]:
        yield from self.fs.dialect.iterdir(self.path)

    def scandir(self) -> Iterator[FilesystemEntry]:
        for name, stat_result in self.fs.dialect.scandir(self.path):
            entry_path = fsutil.join(self.path, name, alt_separator=self.fs.alt_separator)
            yield ShellFilesystemEntry(self.fs, entry_path, stat_result)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self.fs.dialect.open(self.path, self._resolve().lstat().st_size)

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        return stat.S_ISDIR(self.stat(follow_symlinks).st_mode)

    def is_file(self, follow_symlinks: bool = True) -> bool:
        return stat.S_ISREG(self.stat(follow_symlinks).st_mode)

    def is_symlink(self) -> bool:
        return stat.S_ISLNK(self.entry.st_mode)

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError

        return self.fs.dialect.readlink(self.path)

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).lstat()

    def lstat(self) -> fsutil.stat_result:
        if stat.S_ISBLK(self.entry.st_mode) and not self.entry.st_size:
            # On most Linux systems, block devices have a size of 0
            # Patch up the size if we can
            try:
                self.entry.st_size = _blockdev_size(self.fs, self.path)
            except Exception as e:
                log.info("Failed to get size of block device %r", self.path)
                log.debug("", exc_info=e)
        return self.entry


class DdStream(AlignedStream):
    """A stream for reading files using the ``dd`` command in a shell filesystem."""

    def __init__(self, fs: ShellFilesystem, path: str, size: int):
        self.fs = fs
        self.path = _escape_path(path)
        super().__init__(size)

    def _read(self, offset: int, length: int) -> bytes:
        count = (length + self.align - 1) // self.align
        skip = offset // self.align

        stdout, stderr = self.fs.execute(f"dd if={self.path} bs={self.align} skip={skip} count={count} status=none")
        if stderr:
            exc, msg = _stderr_to_exception(stderr.decode())
            raise exc(f"Failed to read from {self.path}: {msg}")
        return stdout
