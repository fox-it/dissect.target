"""Pathlib like abstraction helpers for target filesystem.

Also contains some other filesystem related utilities.
"""

from __future__ import annotations

import errno
import fnmatch
import hashlib
import io
import logging
import posixpath
import re
from pathlib import Path, PurePath, _Accessor, _PathParents, _PosixFlavour
from typing import Any, BinaryIO, Iterator, List, Sequence, Set, TextIO, Tuple, Union

import dissect.target.filesystem as filesystem
from dissect.target.exceptions import (
    FileNotFoundError,
    NotADirectoryError,
    NotASymlinkError,
    SymlinkRecursionError,
)

log = logging.getLogger(__name__)

re_normalize_path = re.compile(r"[/]+")
re_normalize_sbs_path = re.compile(r"[\\/]+")
re_glob_magic = re.compile(r"[*?[]")
re_glob_index = re.compile(r"(?<=\/)[^\/]*[*?[]\/?")


def normalize(path: str, alt_separator: str = "") -> str:
    if alt_separator == "\\":
        return re_normalize_sbs_path.sub("/", path)
    else:
        return re_normalize_path.sub("/", path)


def join(*args, alt_separator: str = "") -> str:
    return posixpath.join(*[normalize(part, alt_separator=alt_separator) for part in args])


def dirname(path: str, alt_separator: str = "") -> str:
    return posixpath.dirname(normalize(path, alt_separator=alt_separator))


def basename(path: str, alt_separator: str = "") -> str:
    return posixpath.basename(normalize(path, alt_separator=alt_separator))


def split(path: str, alt_separator: str = "") -> str:
    return posixpath.split(normalize(path, alt_separator=alt_separator))


def isabs(path: str, alt_separator: str = "") -> str:
    return posixpath.isabs(normalize(path, alt_separator=alt_separator))


def normpath(path: str, alt_separator: str = "") -> str:
    return posixpath.normpath(normalize(path, alt_separator=alt_separator))


def abspath(path: str, cwd: str = "", alt_separator: str = "") -> str:
    cwd = cwd or "/"
    cwd = normalize(cwd, alt_separator=alt_separator)
    path = normalize(path, alt_separator=alt_separator)
    if not isabs(path):
        path = join(cwd, path)
    return posixpath.normpath(path)


def relpath(path: str, start: str, alt_separator: str = "") -> str:
    return posixpath.relpath(
        normalize(path, alt_separator=alt_separator),
        normalize(start, alt_separator=alt_separator),
    )


def generate_addr(path: Union[str, Path], alt_separator: str = "") -> int:
    if not alt_separator and isinstance(path, Path):
        alt_separator = path._flavour.altsep
    path = normalize(str(path), alt_separator=alt_separator)
    return int(hashlib.sha256(path.encode()).hexdigest()[:8], 16)


splitext = posixpath.splitext


class stat_result:  # noqa
    """Custom stat_result object, designed to mimick os.stat_result.

    The real stat_result is a CPython internal StructSeq, which kind of behaves like a namedtuple on steroids.
    We try to emulate some of that behaviour here.

    For consistency this class is also called stat_result.
    """

    __slots__ = {
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

    def __eq__(self, other):
        if isinstance(other, stat_result):
            other = other._s

        return self._s == other

    def __ne__(self, other):
        return not self == other

    def __getitem__(self, item):
        return self._s[item]

    def __iter__(self):
        return iter(self._s)

    def __repr__(self):
        values = ", ".join(
            f"{k}={getattr(self, k)}" for k in self.__slots__ if k.startswith("st_") and getattr(self, k) is not None
        )
        return f"dissect.target.stat_result({values})"

    def _parse_time(self, ts: Union[int, float]) -> Tuple[int, float, int]:
        ts_int = int(ts)
        ts_ns = int(ts * 1e9)

        return ts_int, ts_ns * 1e-9, ts_ns

    @classmethod
    def copy(cls, other):
        # First copy the basic 10 fields
        st = cls(list(other))
        # Then iterate and copy any other
        for attr in list(cls.__slots__.keys())[10 : cls._field_count]:
            try:
                setattr(st, attr, getattr(other, attr))
            except AttributeError:
                pass
        return st


# fmt: off
"""
A pathlib.Path compatible implementation for dissect.target starts here. This allows for the
majority of the pathlib.Path API to "just work" on dissect.target filesystems.

Most of this consists of subclassed internal classes with dissect.target specific patches,
but sometimes the change to a function is small, so the entire internal function is copied
and only a small part changed. To ease updating this code, the order of functions, comments
and code style is kept exactly the same as the original pathlib.py.

Yes, we know, this is playing with fire and it can break on new CPython releases.

Commit hash of CPython we're currently in sync with: b382bf50c53e6eab09f3e3bf0802ab052cb0289d
"""


class _DissectFlavour(_PosixFlavour):
    is_supported = True

    __variant_instances = {}

    def __new__(cls, case_sensitive=False, alt_separator=None):
        idx = (case_sensitive, alt_separator)
        instance = cls.__variant_instances.get(idx, None)
        if instance is None:
            instance = _PosixFlavour.__new__(cls)
            cls.__variant_instances[idx] = instance

        return instance

    def __init__(self, case_sensitive=False, alt_separator=""):
        super().__init__()
        self.altsep = alt_separator
        self.case_sensitive = case_sensitive

    def casefold(self, s):
        return s if self.case_sensitive else s.lower()

    def casefold_parts(self, parts):
        return parts if self.case_sensitive else [p.lower() for p in parts]

    def compile_pattern(self, pattern):
        return re.compile(fnmatch.translate(pattern), 0 if self.case_sensitive else re.IGNORECASE).fullmatch

    # CPython <= 3.9
    def resolve(self, path, strict=False):
        sep = self.sep
        accessor = path._accessor
        seen = {}

        def _resolve(fs, path, rest):
            if rest.startswith(sep):
                path = ''

            for name in rest.split(sep):
                if not name or name == '.':
                    # current dir
                    continue
                if name == '..':
                    # parent dir
                    path, _, _ = path.rpartition(sep)
                    continue
                if path.endswith(sep):
                    newpath = path + name
                else:
                    newpath = path + sep + name
                if newpath in seen:
                    # Already seen this path
                    path = seen[newpath]
                    if path is not None:
                        # use cached value
                        continue
                    # The symlink is not resolved, so we must have a symlink loop.
                    raise RuntimeError("Symlink loop from %r" % newpath)
                # Resolve the symbolic link
                try:
                    target = accessor.readlink(fs.path(newpath))
                except OSError as e:
                    if e.errno != errno.EINVAL and strict:
                        raise
                    # Not a symlink, or non-strict mode. We just leave the path
                    # untouched.
                    path = newpath
                else:
                    seen[newpath] = None  # not resolved symlink
                    path = _resolve(fs, path, target)
                    seen[newpath] = path  # resolved symlink

            return path

        return _resolve(path._fs, '', str(path)) or sep

    # CPython <= 3.9
    def gethomedir(self, username):
        raise NotImplementedError()


def _get_oserror(path):
    # We emulate some OSError exceptions to play nice with pathlib
    try:
        return path.get()
    except FileNotFoundError:
        e = OSError(errno.ENOENT)
        e.errno = errno.ENOENT
        raise e
    except NotADirectoryError:
        e = OSError(errno.ENOTDIR)
        e.errno = errno.ENOTDIR
        raise e


class _DissectScandirIterator:
    """This class implements a ScandirIterator for dissect's scandir()

    The _DissectScandirIterator provides a context manager, so scandir can be called as:

    ```
    with scandir(path) as it:
        for entry in it
            print(entry.name)
    ```

    similar to os.scandir() behaviour since Python 3.6.
    """

    def __init__(self, iterator):
        self._iterator = iterator

    def __del__(self):
        self.close()

    def __enter__(self):
        return self._iterator

    def __exit__(self, *args, **kwargs):
        return False

    def __iter__(self):
        return self._iterator

    def __next__(self, *args):
        return next(self._iterator, *args)

    def close(self):
        # close() is not defined in the various filesystem implementations. The
        # python ScandirIterator does define the interface however.
        pass


class _DissectAccessor(_Accessor):
    # CPython >= 3.10
    @staticmethod
    def stat(path, follow_symlinks=True):
        if follow_symlinks:
            return path.get().stat()
        else:
            return path.get().lstat()

    # CPython <= 3.9
    @staticmethod
    def lstat(path):
        return path.get().lstat()

    @staticmethod
    def open(path, mode='rb', buffering=0, encoding=None,
             errors=None, newline=None, *args, **kwargs):
        """Open file and return a stream.

        Supports a subset of features of the real pathlib.open/io.open.

        Note: in contrast to regular Python, the mode is binary by default. Text mode
        has to be explicitly specified. Buffering is also disabled by default.
        """
        modes = set(mode)
        if modes - set('rbt') or len(mode) > len(modes):
            raise ValueError("invalid mode: %r" % mode)

        reading = 'r' in modes
        binary = 'b' in modes
        text = 't' in modes or 'b' not in modes

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
        if buffering == 1 or buffering < 0 and raw.isatty():
            buffering = -1
            line_buffering = True
        if buffering < 0 or text and buffering == 0:
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

    @staticmethod
    def listdir(path):
        return path.get().listdir()

    @staticmethod
    def scandir(path):
        return _DissectScandirIterator(path.get().scandir())

    @staticmethod
    def chmod(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def lchmod(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def mkdir(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def unlink(*args, **kwargs):
        raise NotImplementedError()

    # CPython >= 3.10
    @staticmethod
    def link(*args, **kwargs):
        raise NotImplementedError()

    # CPython <= 3.9
    @staticmethod
    def link_to(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def rmdir(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def rename(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def replace(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def symlink(*args, **kwargs):
        raise NotImplementedError()

    # CPython >= 3.10
    @staticmethod
    def touch(*args, **kwargs):
        raise NotImplementedError()

    # CPython <= 3.9
    @staticmethod
    def utime(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def readlink(path):
        entry = _get_oserror(path)
        if not entry.is_symlink():
            e = OSError(errno.EINVAL)
            e.errno = errno.EINVAL
            raise e
        return entry.readlink()

    @staticmethod
    def owner(*args, **kwargs):
        raise NotImplementedError()

    @staticmethod
    def group(*args, **kwargs):
        raise NotImplementedError()

    # CPython >= 3.10
    @staticmethod
    def getcwd(*args, **kwargs):
        raise NotImplementedError()

    # CPython >= 3.10
    @staticmethod
    def expanduser(*args, **kwargs):
        raise NotImplementedError()

    # CPython >= 3.10
    @staticmethod
    def realpath(*args, **kwargs):
        raise NotImplementedError()


_dissect_accessor = _DissectAccessor()


class _DissectPathParents(_PathParents):
    __slots__ = ('_fs')

    def __init__(self, path):
        super().__init__(path)
        self._fs = path._fs
        self._flavour = path._flavour

    def __getitem__(self, idx):
        result = super().__getitem__(idx)
        result._fs = self._fs
        result._flavour = self._flavour
        return result


class PureDissectPath(PurePath):
    _flavour = _DissectFlavour(case_sensitive=False)

    def __reduce__(self):
        raise TypeError("pickling is currently not supported")

    @classmethod
    def _from_parts(cls, args, *_args, **_kwargs):
        fs = args[0]

        if not isinstance(fs, filesystem.Filesystem):
            raise TypeError(
                "invalid PureDissectPath initialization: missing filesystem, "
                "got %r (this might be a bug, please report)"
                % args
            )

        alt_separator = fs.alt_separator
        path_args = []
        for arg in args[1:]:
            if isinstance(arg, str):
                arg = normalize(arg, alt_separator=alt_separator)
            path_args.append(arg)

        self = super()._from_parts(path_args, *_args, **_kwargs)
        self._fs = fs

        self._flavour = _DissectFlavour(
            alt_separator=fs.alt_separator,
            case_sensitive=fs.case_sensitive
        )

        return self

    def _make_child(self, args):
        child = super()._make_child(args)  # noqa
        child._fs = self._fs
        child._flavour = self._flavour
        return child

    def with_name(self, name):
        result = super().with_name(name)
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    def with_stem(self, stem):
        result = super().with_stem(stem)
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    def with_suffix(self, suffix):
        result = super().with_suffix(suffix)
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    def relative_to(self, *other):
        result = super().relative_to(*other)
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    def __rtruediv__(self, key):
        try:
            return self._from_parts([self._fs, key] + self._parts)
        except TypeError:
            return NotImplemented

    @property
    def parent(self):
        result = super().parent
        result._fs = self._fs
        result._flavour = self._flavour
        return result

    @property
    def parents(self):
        return _DissectPathParents(self)


class TargetPath(Path, PureDissectPath):
    # CPython >= 3.10
    _accessor = _dissect_accessor
    __slots__ = '_entry'

    # CPython <= 3.9
    def _init(self, template=None):  # noqa
        self._accessor = _dissect_accessor

    def _make_child_relpath(self, part):
        child = super()._make_child_relpath(part)  # noqa
        child._fs = self._fs
        child._flavour = self._flavour
        return child

    def get(self):
        try:
            return self._entry
        except AttributeError:
            self._entry = self._fs.get(str(self))  # noqa
            return self._entry

    @classmethod
    def cwd(cls):
        raise NotImplementedError()

    @classmethod
    def home(cls):
        raise NotImplementedError()

    def iterdir(self):
        for entry in self._accessor.scandir(self):
            if entry.name in {'.', '..'}:
                # Yielding a path object for these makes little sense
                continue
            child_path = self._make_child_relpath(entry.name)
            child_path._entry = entry
            yield child_path

    def absolute(self):
        raise NotImplementedError()

    def resolve(self, strict=False):
        s = self._flavour.resolve(self)
        if s is None:
            # No symlink resolution => for consistency, raise an error if
            # the path doesn't exist or is forbidden
            self.stat()
            s = str(self.absolute())
        # Now we have no symlinks in the path, it's safe to normalize it.
        normed = self._flavour.pathmod.normpath(s)
        obj = self._from_parts((self._fs, normed,))
        return obj

    def owner(self):
        raise NotImplementedError()

    def group(self):
        raise NotImplementedError()

    def open(self, mode='rb', buffering=0, encoding=None,
             errors=None, newline=None):
        # CPython >= 3.10
        if "b" not in mode and hasattr(io, "text_encoding"):
            # Vermin linting needs to be skipped for this line as this is
            # guarded by an explicit check for availability.
            # novermin
            encoding = io.text_encoding(encoding)
        return self._accessor.open(self, mode, buffering, encoding, errors,
                                   newline)

    def write_bytes(self, *args, **kwargs):
        raise NotImplementedError()

    def write_text(self, *args, **kwargs):
        raise NotImplementedError()

    def readlink(self):
        """
        Return the path to which the symbolic link points.
        """
        path = self._accessor.readlink(self)
        obj = self._from_parts((self._fs, path,))
        return obj

    def touch(self, *args, **kwargs):
        raise NotImplementedError()

    def mkdir(self, *args, **kwargs):
        raise NotImplementedError()

    def chmod(self, *args, **kwargs):
        raise NotImplementedError()

    def lchmod(self, *args, **kwargs):
        raise NotImplementedError()

    def unlink(self):
        raise NotImplementedError()

    def rmdir(self):
        raise NotImplementedError()

    def rename(self, *args, **kwargs):
        raise NotImplementedError()

    def replace(self, *args, **kwargs):
        raise NotImplementedError()

    def symlink_to(self, *args, **kwargs):
        raise NotImplementedError()

    def link_to(self, *args, **kwargs):
        raise NotImplementedError()

    def exists(self):
        try:
            # .exists() must resolve possible symlinks
            self.get().stat()
            return True
        except (FileNotFoundError, NotADirectoryError, NotASymlinkError, SymlinkRecursionError, ValueError):
            return False

    def is_dir(self):
        try:
            return self.get().is_dir()
        except (FileNotFoundError, NotADirectoryError, NotASymlinkError, SymlinkRecursionError, ValueError):
            return False

    def is_file(self):
        try:
            return self.get().is_file()
        except (FileNotFoundError, NotADirectoryError, NotASymlinkError, SymlinkRecursionError, ValueError):
            return False

    def is_symlink(self):
        try:
            return self.get().is_symlink()
        except (FileNotFoundError, NotADirectoryError, NotASymlinkError, SymlinkRecursionError, ValueError):
            return False

    def is_block_device(self):
        raise NotImplementedError()

    def is_char_device(self):
        raise NotImplementedError()

    def is_fifo(self):
        raise NotImplementedError()

    def is_socket(self):
        raise NotImplementedError()

    def expanduser(self):
        raise NotImplementedError()


# fmt: on


def walk(path_entry, topdown=True, onerror=None, followlinks=False):
    for path_list, dirs, files in walk_ext(path_entry, topdown, onerror, followlinks):
        dir_names = [d.name for d in dirs]
        file_names = [f.name for f in files]

        walk_path = join(path_entry.path, *[p.name for p in path_list[1:]])
        yield walk_path, dir_names, file_names

        if len(dir_names) != len(dirs):
            dirs[:] = [d for d in dirs if d.name in dir_names]


def walk_ext(path_entry, topdown=True, onerror=None, followlinks=False):
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
                yield [path_entry] + xpath, xdirs, xfiles

    if not topdown:
        yield [path_entry], dirs, files


def glob_split(pattern: str, alt_separator: str = "") -> str:
    # re_glob_index expects a normalized pattern
    pattern = normalize(pattern, alt_separator=alt_separator)

    first_glob = re_glob_index.search(pattern)

    if not first_glob:
        return pattern, ""

    pos = first_glob.start()
    return pattern[:pos], pattern[pos:]


def glob_ext(direntry: filesystem.FilesystemEntry, pattern: str) -> filesystem.FilesystemEntry:
    dir_name, base_name = split(pattern, alt_separator=direntry.fs.alt_separator)

    if not has_glob_magic(pattern):
        try:
            entry = direntry.get(pattern)
        except FileNotFoundError:
            pass
        else:
            if base_name:
                yield entry
            # Patterns ending with a slash should match only directories
            elif entry.is_dir():
                yield entry
        return

    if not dir_name:
        for entry in glob_ext1(direntry, base_name):
            yield entry
        return

    if dir_name != pattern and has_glob_magic(dir_name):
        dirs = glob_ext(direntry, dir_name)
    else:
        dirs = [dir_name]

    if has_glob_magic(base_name):
        glob_in_dir = glob_ext1
    else:
        glob_in_dir = glob_ext0

    for direntry in dirs:
        for entry in glob_in_dir(direntry, base_name):
            yield entry


# These 2 helper functions non-recursively glob inside a literal directory.
# They return a list of basenames. `glob1` accepts a pattern while `glob0`
# takes a literal base_name (so it only has to check for its existence).


def glob_ext1(direntry: filesystem.FilesystemEntry, pattern: str) -> filesystem.FilesystemEntry:
    if not direntry.is_dir():
        return

    entries = direntry.scandir()

    if pattern[0] != ".":
        entries = filter(lambda x: x.name[0] != ".", entries)

    for e in entries:
        name = e.name if e.fs.case_sensitive else e.name.lower()
        pattern = pattern if e.fs.case_sensitive else pattern.lower()
        if fnmatch.fnmatch(name, pattern):
            yield e


def glob_ext0(direntry: filesystem.FilesystemEntry, base_name: str) -> List[filesystem.FilesystemEntry]:
    if base_name == "":
        # `os.path.split()` returns an empty base_name for paths ending with a
        # directory separator.  'q*x/' should match only directories.
        if direntry.is_dir():
            return [direntry]
    elif direntry.is_dir():
        try:
            return [direntry.get(base_name)]
        except FileNotFoundError:
            pass
    return []


def has_glob_magic(s):
    return re_glob_magic.search(s) is not None


def resolve_link(
    fs: filesystem.Filesystem, entry: filesystem.FilesystemEntry, previous_links: Set[str] = None
) -> filesystem.FilesystemEntry:
    """Resolves a symlink to its actual path.

    It stops resolving once it detects an infinite recursion loop.
    """

    link = normalize(entry.readlink(), alt_separator=entry.fs.alt_separator)
    path = normalize(entry.path, alt_separator=entry.fs.alt_separator)

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
        entry = resolve_link(fs, entry, previous_links)

    return entry


def open_decompress(path: TargetPath, mode: str = "rb") -> Union[BinaryIO, TextIO]:
    """Open and decompress a file. Handles gz and bz2 files. Uncompressed files are opened as-is.

    Assumes that the ``path`` exists.

    Example:
        bytes_buf = open_decompress(Path("/dir/file.gz")).read()

        for line in open_decompress(Path("/dir/file.gz"), "rt"):
            print(line)
    """

    if path.suffix == ".gz":
        import gzip

        return gzip.open(path.open(), mode)
    elif path.suffix == ".bz2":
        import bz2

        return bz2.open(path.open(), mode)
    else:
        return path.open(mode)


def reverse_readlines(fh: TextIO, chunk_size: int = io.DEFAULT_BUFFER_SIZE) -> Iterator[str]:
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
            except UnicodeDecodeError:
                offset += 1
                fh.seek(offset)

        yield from reversed(lines[1:])
        prev_offset = offset

    if lines:
        yield lines[0]
