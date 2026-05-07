"""A pathlib compatible implementation for dissect.target.

This allows for the majority of the pathlib.Path API to "just work" on dissect.target filesystems.

Historically, we replied on subclassing pathlib classes directly and applying some patches to make it work.
However, this approach has become increasingly difficult to maintain as the pathlib implementation in the
standard library changes dramatically between CPython versions, and there's often a big delay between the
release of a new CPython version and the update of our code to support it.

(Yes, I burned my hands on the fire I was playing with)

For that reason, we've decided to basically copy-paste the entirety of pathlib's implementation from CPython's main
branch, and then apply the necessary changes to make it work with dissect.target. This has several benefits:

- Since we no longer rely on subclassed standard library code, there should be no more issues with running on
  newer CPython versions
- Newer pathlib features will become available even on older CPython versions, as we will always be running the latest
  pathlib code on all CPython versions

There will still be the burden of having to manually update our code with changes from the standard library,
but at least in this way it **shouldn't** break on newer CPython versions. Worst case scenario, we miss some
new features, optimizations or bug fixes, but at least it won't break entirely.

To ease updating this code, the order of functions, comments and code style is kept largely the same as the
original pathlib code, except for linting and formatting rules.

Changes will be marked with a comment starting with `# PATCH`. The largest structural changes being:

- Instead of having just two variants (Posix and Windows), we have a polypath parser that deals with
  both styles of separators and case sensitivity
- The "pure" path (PureTargetPath) is mostly copied straight from PurePath, but has a few important distinctions
  (most of which derive from polypath rules):

  - All paths are normalized to POSIX-style paths internally
  - For Windows-style paths, we also consider paths starting with a separator to be absolute, and we have
    a few more possible "drive letter" names (see polypath.ALLOWED_DRIVE_NAMES)

- All variations of path (i.e. the product of all case sensitivity and separator styles) are pre-created as subclasses,
  and the correct class will be selected during TargetPath initialization

Commit hash we're in sync with: 1bfe86c

Notes:
    - https://github.com/python/cpython/blob/main/Lib/pathlib
"""

from __future__ import annotations

import io
import os
import pathlib
from collections.abc import Sequence
from itertools import chain
from stat import S_IMODE, S_ISBLK, S_ISCHR, S_ISDIR, S_ISFIFO, S_ISLNK, S_ISREG, S_ISSOCK
from typing import IO, TYPE_CHECKING, Literal

from dissect.target.exceptions import FilesystemError
from dissect.target.filesystem import Filesystem
from dissect.target.helpers import polypath
from dissect.target.helpers.compat.glob import _no_recurse_symlinks, _PathGlobber, _StringGlobber

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from typing_extensions import Self

    from dissect.target.filesystem import DirEntry, FilesystemEntry
    from dissect.target.helpers.fsutil import stat_result


class UnsupportedOperation(NotImplementedError):
    """An exception that is raised when an unsupported operation is attempted."""


def _create_error_method(key: str) -> Callable[..., None]:
    def _error(self, *args, **kwargs) -> None:  # noqa: ANN001
        f = f"{type(self).__name__}.{key}()"
        raise UnsupportedOperation(f"{f} is not yet supported in Dissect, please open an issue")

    return _error


class _ScandirIterator:
    """This class implements a ScandirIterator for our own scandir().

    The _ScandirIterator provides a context manager, so scandir can be called as:

    .. code-block:: python

        with scandir(path) as it:
            for entry in it
                print(entry.name)

    Similar to os.scandir() behaviour since Python 3.6.
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


class _PolyParser:
    """Path parser that supports both POSIX and Windows paths and varying case-sensitivity.

    We normalize to POSIX-style paths at the end of parsing in certain places in ``PureTargetPath``.
    """

    sep = "/"
    altsep = ""
    case_sensitive = False

    def __init__(self, case_sensitive: bool = False, sep: str = "/", altsep: str = ""):
        self.case_sensitive = case_sensitive
        self.sep = sep
        self.altsep = altsep

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _PolyParser):
            return NotImplemented
        return (self.case_sensitive, self.sep, self.altsep) == (other.case_sensitive, other.sep, other.altsep)

    def normcase(self, s: str) -> str:
        return s if self.case_sensitive else s.lower()

    def split(self, part: str) -> tuple[str, str]:
        return polypath.split(part, sep=self.sep)

    def splitdrive(self, part: str) -> tuple[str, str]:
        return polypath.splitdrive(part, sep=self.sep)

    def splitroot(self, part: str) -> tuple[str, str, str]:
        return polypath.splitroot(part, sep=self.sep)

    def join(self, *args) -> str:
        return polypath.join(*args, sep=self.sep)

    def isabs(self, path: str) -> bool:
        return polypath.isabs(path, sep=self.sep)


class _PathParents(Sequence):
    """This object provides sequence-like access to the logical ancestors
    of a path.  Don't try to construct it yourself.
    """

    __slots__ = ("_drv", "_path", "_root", "_tail")

    def __init__(self, path: PureTargetPath):
        self._path = path
        self._drv = path.drive
        self._root = path.root
        self._tail = path._tail

    def __len__(self) -> int:
        return len(self._tail)

    def __getitem__(self, idx: int | slice) -> PureTargetPath | tuple[PureTargetPath, ...]:
        if isinstance(idx, slice):
            return tuple(self[i] for i in range(*idx.indices(len(self))))

        if idx >= len(self) or idx < -len(self):
            raise IndexError(idx)
        if idx < 0:
            idx += len(self)
        return self._path._from_parsed_parts(self._drv, self._root, self._tail[: -idx - 1])

    def __repr__(self) -> str:
        # PATCH: hardcode TargetPath as class name if it's a subclass of TargetPath
        if isinstance(self._path, TargetPath):
            return "<TargetPath.parents>"
        # Otherwise leave the original class name to ease debugging
        return f"<{type(self._path).__name__}.parents>"


# To be compatible with things like isinstance checks, we _do_ actually subclass from stdlib pathlib
# However, since we basically override everything that makes PurePath works, it shouldn't cause any issues
class PureTargetPath(pathlib.PurePath):
    """Base class for manipulating paths without I/O.

    PurePath represents a filesystem path and offers operations which
    don't imply any actual filesystem I/O.
    """

    # fmt: off
    __slots__ = tuple({
        # The `_raw_paths` slot stores unjoined string paths. This is set in
        # the `__init__()` method.
        "_raw_paths",

        # The `_drv`, `_root` and `_tail_cached` slots store parsed and
        # normalized parts of the path. They are set when any of the `drive`,
        # `root` or `_tail` properties are accessed for the first time. The
        # three-part division corresponds to the result of
        # `os.path.splitroot()`, except that the tail is further split on path
        # separators (i.e. it is a list of strings), and that the root and
        # tail are normalized.
        "_drv", "_root", "_tail_cached",

        # The `_str` slot stores the string representation of the path,
        # computed from the drive, root and tail when `__str__()` is called
        # for the first time. It's used to implement `_str_normcase`
        "_str",

        # The `_str_normcase_cached` slot stores the string path with
        # normalized case. It is set when the `_str_normcase` property is
        # accessed for the first time. It's used to implement `__eq__()`
        # `__hash__()`, and `_parts_normcase`
        "_str_normcase_cached",

        # The `_parts_normcase_cached` slot stores the case-normalized
        # string path after splitting on path separators. It's set when the
        # `_parts_normcase` property is accessed for the first time. It's used
        # to implement comparison methods like `__lt__()`.
        "_parts_normcase_cached",

        # The `_hash` slot stores the hash of the case-normalized string
        # path. It's set when `__hash__()` is called for the first time.
        "_hash",
    } - set(getattr(pathlib.PurePath, "__slots__", ())))
    # fmt: on

    parser: _PolyParser = _PolyParser(case_sensitive=False)
    # PATCH: hack for compatibility with flow.record paths on <=3.12
    _flavour = None

    def __new__(cls, *args, **kwargs):
        # PATCH: Always create a new instance of this class
        return object.__new__(cls)

    def __init__(self, *args):
        paths = []
        for arg in args:
            if isinstance(arg, PureTargetPath):
                if arg.parser is not self.parser:
                    # GH-103631: Convert separators for backwards compatibility.
                    paths.append(arg.as_posix())
                else:
                    paths.extend(arg._raw_paths)
            else:
                try:
                    path = os.fspath(arg)
                except TypeError:
                    path = arg
                if not isinstance(path, str):
                    raise TypeError(
                        "argument should be a str or an os.PathLike "
                        "object where __fspath__ returns a str, "
                        f"not {type(path).__name__!r}"
                    )
                paths.append(path)
        self._raw_paths = paths

    def with_segments(self, *pathsegments) -> Self:
        """Construct a new path object from any number of path-like objects.
        Subclasses may override this method to customize how new path objects
        are created from methods like `iterdir()`.
        """
        return type(self)(*pathsegments)

    def joinpath(self, *pathsegments) -> Self:
        """Combine this path with one or several arguments, and return a
        new path representing either a subpath (if all arguments are relative
        paths) or a totally different path (if one of the arguments is
        anchored).
        """
        return self.with_segments(self, *pathsegments)

    def __truediv__(self, key: str | os.PathLike[str]) -> Self:
        try:
            return self.with_segments(self, key)
        except TypeError:
            return NotImplemented

    def __rtruediv__(self, key: str | os.PathLike[str]) -> Self:
        try:
            return self.with_segments(key, self)
        except TypeError:
            return NotImplemented

    def __reduce__(self) -> tuple[type[Self], tuple]:
        return self.__class__, tuple(self._raw_paths)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.as_posix()!r})"

    def __bytes__(self) -> bytes:
        """Return the bytes representation of the path. This is only recommended to use under Unix."""
        # PATCH: always encode using UTF-8
        return str(self).encode()

    @property
    def _str_normcase(self) -> str:
        # String with normalized case, for hashing and equality checks
        try:
            return self._str_normcase_cached
        except AttributeError:
            # PATCH: check against case sensitivity of the parser
            if self.parser.case_sensitive:
                self._str_normcase_cached = str(self)
            else:
                self._str_normcase_cached = str(self).lower()
            return self._str_normcase_cached

    def __hash__(self) -> int:
        try:
            return self._hash
        except AttributeError:
            self._hash = hash(self._str_normcase)
            return self._hash

    def __eq__(self, other: object) -> bool:
        # PATCH: allow comparison with strings
        if isinstance(other, str):
            return str(self) == other or self == self.with_segments(other)
        if not isinstance(other, PureTargetPath):
            return NotImplemented
        return self._str_normcase == other._str_normcase and self.parser is other.parser

    @property
    def _parts_normcase(self) -> list[str]:
        # Cached parts with normalized case, for comparisons.
        try:
            return self._parts_normcase_cached
        except AttributeError:
            self._parts_normcase_cached = self._str_normcase.split(self.parser.sep)
            return self._parts_normcase_cached

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, PureTargetPath) or self.parser is not other.parser:
            return NotImplemented
        return self._parts_normcase < other._parts_normcase

    def __le__(self, other: object) -> bool:
        if not isinstance(other, PureTargetPath) or self.parser is not other.parser:
            return NotImplemented
        return self._parts_normcase <= other._parts_normcase

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, PureTargetPath) or self.parser is not other.parser:
            return NotImplemented
        return self._parts_normcase > other._parts_normcase

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, PureTargetPath) or self.parser is not other.parser:
            return NotImplemented
        return self._parts_normcase >= other._parts_normcase

    def __str__(self) -> str:
        """Return the string representation of the path, suitable for passing to system calls."""
        try:
            return self._str
        except AttributeError:
            # PATCH: default to "" for empty paths, instead of "."
            self._str = self._format_parsed_parts(self.drive, self.root, self._tail) or ""
            return self._str

    __fspath__ = __str__
    __vfspath__ = __str__

    @classmethod
    def _format_parsed_parts(cls, drv: str, root: str, tail: list[str]) -> str:
        # PATCH: normalize to POSIX-style paths, and ignore the drive if there is one (we also include it in the tail)
        if drv:
            return "/".join(tail)
        if root:
            return root + "/".join(tail)
        if tail and cls.parser.splitdrive(tail[0])[0]:
            tail = [".", *tail]
        return "/".join(tail)

    def _from_parsed_parts(self, drv: str, root: str, tail: list[str]) -> Self:
        path = self._from_parsed_string(self._format_parsed_parts(drv, root, tail))
        path._drv = drv
        path._root = root
        path._tail_cached = tail
        return path

    def _from_parsed_string(self, path_str: str) -> Self:
        path = self.with_segments(path_str)
        # PATCH: default to "/" or "" for empty paths, instead of "."
        path._str = path_str or ("/" if self.parser.sep == "/" else "")
        return path

    @classmethod
    def _parse_path(cls, path: str) -> tuple[str, str, list[str]]:
        if not path:
            return "", "", []
        sep = cls.parser.sep
        altsep = cls.parser.altsep
        if altsep:
            path = path.replace(altsep, sep)
        drv, root, rel = cls.parser.splitroot(path)
        if not root and drv.startswith(sep) and not drv.endswith(sep):
            drv_parts = drv.split(sep)
            if len(drv_parts) == 4 and drv_parts[2] not in "?.":
                # e.g. //server/share
                root = sep
            elif len(drv_parts) == 6:
                # e.g. //?/unc/server/share
                root = sep

        # PATCH: normalize to POSIX-style paths, and add the drive to the relative part
        drv = drv.replace(cls.parser.sep, "/")
        root = root.replace(cls.parser.sep, "/")
        return (
            drv,
            root,
            ([drv] if drv else []) + [x for x in rel.split(sep) if x and x != "."],
        )

    @classmethod
    def _parse_pattern(cls, pattern: str) -> list[str]:
        """Parse a glob pattern to a list of parts.

        This is much like _parse_path, except:

        - Rather than normalizing and returning the drive and root, we raise
          NotImplementedError if either are present.
        - If the path has no real parts, we raise ValueError.
        - If the path ends in a slash, then a final empty part is added.
        """
        # PATCH: we don't care about the drive and root for glob patterns
        # patterns such as "C:/*.txt" should work, since all our operations are POSIX-style internally
        if pattern[:1] in (cls.parser.sep, cls.parser.altsep):
            raise NotImplementedError("Non-relative patterns are unsupported")
        rel = pattern
        sep = cls.parser.sep
        altsep = cls.parser.altsep
        if altsep:
            rel = rel.replace(altsep, sep)
        parts = [x for x in rel.split(sep) if x and x != "."]
        if not parts:
            raise ValueError(f"Unacceptable pattern: {str(pattern)!r}")
        if rel.endswith(sep):
            # GH-65238: preserve trailing slash in glob patterns.
            parts.append("")
        return parts

    def as_posix(self) -> str:
        """Return the string representation of the path with forward (/) slashes."""
        return str(self).replace(self.parser.sep, "/")

    @property
    def _raw_path(self) -> str:
        paths = self._raw_paths
        if len(paths) == 1:
            return paths[0]
        if paths:
            # Join path segments from the initializer.
            return self.parser.join(*paths)
        return ""

    @property
    def drive(self) -> str:
        """The drive prefix (letter or UNC path), if any."""
        try:
            return self._drv
        except AttributeError:
            self._drv, self._root, self._tail_cached = self._parse_path(self._raw_path)
            return self._drv

    @property
    def root(self) -> str:
        """The root of the path, if any."""
        try:
            return self._root
        except AttributeError:
            self._drv, self._root, self._tail_cached = self._parse_path(self._raw_path)
            return self._root

    @property
    def _tail(self) -> list[str]:
        try:
            return self._tail_cached
        except AttributeError:
            self._drv, self._root, self._tail_cached = self._parse_path(self._raw_path)
            return self._tail_cached

    @property
    def anchor(self) -> str:
        """The concatenation of the drive and root, or ''."""
        return self.drive + self.root

    @property
    def parts(self) -> tuple[str, ...]:
        """An object providing sequence-like access to the components in the filesystem path."""
        # PATCH: never include drive, it's included in the tail
        if not self.drive and self.root:
            return (self.root, *tuple(self._tail))
        return tuple(self._tail)

    @property
    def parent(self) -> Self:
        """The logical parent of the path."""
        drv = self.drive
        root = self.root
        tail = self._tail
        if not tail:
            return self
        return self._from_parsed_parts(drv, root, tail[:-1])

    @property
    def parents(self) -> _PathParents:
        """A sequence of this path's logical parents."""
        # The value of this property should not be cached on the path object,
        # as doing so would introduce a reference cycle.
        return _PathParents(self)

    @property
    def name(self) -> str:
        """The final path component, if any."""
        tail = self._tail
        if not tail:
            return ""
        return tail[-1]

    def with_name(self, name: str) -> Self:
        """Return a new path with the file name changed."""
        p = self.parser
        if not name or p.sep in name or (p.altsep and p.altsep in name) or name == ".":
            raise ValueError(f"Invalid name {name!r}")
        tail = self._tail.copy()
        if not tail:
            raise ValueError(f"{self!r} has an empty name")
        tail[-1] = name
        # PATCH: only include drive if we don't replace it
        if self.drive and len(tail) == 1:
            # We have to re-parse the new path to determine if the new name is a drive component
            drive, _, _ = self._parse_path(name)
        else:
            drive = self.drive
        return self._from_parsed_parts(drive, self.root, tail)

    def with_stem(self, stem: str) -> Self:
        """Return a new path with the stem changed."""
        suffix = self.suffix
        if not suffix:
            return self.with_name(stem)
        if not stem:
            # If the suffix is non-empty, we can't make the stem empty.
            raise ValueError(f"{self!r} has a non-empty suffix")
        return self.with_name(stem + suffix)

    def with_suffix(self, suffix: str) -> Self:
        """Return a new path with the file suffix changed.  If the path
        has no suffix, add given suffix.  If the given suffix is an empty
        string, remove the suffix from the path.
        """
        stem = self.stem
        if not stem:
            # If the stem is empty, we can't make the suffix non-empty.
            raise ValueError(f"{self!r} has an empty name")
        if suffix and not suffix.startswith("."):
            raise ValueError(f"Invalid suffix {suffix!r}")
        return self.with_name(stem + suffix)

    @property
    def stem(self) -> str:
        """The final path component, minus its last suffix."""
        name = self.name
        i = name.rfind(".")
        if i != -1:
            stem = name[:i]
            # Stem must contain at least one non-dot character.
            if stem.lstrip("."):
                return stem
        return name

    @property
    def suffix(self) -> str:
        """The final component's last suffix, if any.

        This includes the leading period. For example: '.txt'
        """
        name = self.name.lstrip(".")
        i = name.rfind(".")
        if i != -1:
            return name[i:]
        return ""

    @property
    def suffixes(self) -> list[str]:
        """A list of the final component's suffixes, if any.

        These include the leading periods. For example: ['.tar', '.gz']
        """
        return ["." + ext for ext in self.name.lstrip(".").split(".")[1:]]

    def relative_to(self, other: str | os.PathLike[str], *, walk_up: bool = False) -> Self:
        """Return the relative path to another path identified by the passed
        arguments.  If the operation is not possible (because this is not
        related to the other path), raise ValueError.

        The *walk_up* parameter controls whether `..` may be used to resolve
        the path.
        """
        if not hasattr(other, "with_segments"):
            other = self.with_segments(other)
        parts = []
        for path in chain([other], other.parents):
            if path == self or path in self.parents:
                break
            if not walk_up:
                raise ValueError(f"{str(self)!r} is not in the subpath of {str(other)!r}")
            if path.name == "..":
                raise ValueError(f"'..' segment in {str(other)!r} cannot be walked")
            parts.append("..")
        else:
            raise ValueError(f"{str(self)!r} and {str(other)!r} have different anchors")
        parts.extend(self._tail[len(path._tail) :])
        return self._from_parsed_parts("", "", parts)

    def is_relative_to(self, other: str | os.PathLike[str]) -> bool:
        """Return True if the path is relative to another path or False."""
        if not hasattr(other, "with_segments"):
            other = self.with_segments(other)
        return other == self or other in self.parents

    def is_absolute(self) -> bool:
        """True if the path is absolute (has both a root and, if applicable, a drive)."""
        # PATCH: we consider paths absolute if they've been constructed with a leading slash,
        # or if we've already determined that they have a drive (for Windows-style paths)
        seps = (self.parser.sep, self.parser.altsep) if self.parser.altsep else (self.parser.sep,)
        return self.drive != "" or any(path[:1] in seps for path in self._raw_paths)

    def as_uri(self) -> str:
        """Return the path as a URI."""
        # PATCH: remove the deprecation warning as this is our preferred way to get a URI
        drive = self.drive
        # PATCH: treat anything that doesn't start with a slash as a "drive"
        if drive and not drive.startswith("/"):
            # It's a path on a local drive => 'file:///c:/a/b'
            prefix = "file:///" + drive
            path = self.as_posix()[len(drive) :]
        elif drive:
            # It's a path on a network drive => 'file://host/share/a/b'
            prefix = "file:"
            path = self.as_posix()
        else:
            # It's a posix path => 'file:///etc/hosts'
            prefix = "file://"
            path = str(self)
        from urllib.parse import quote_from_bytes

        return prefix + quote_from_bytes(os.fsencode(path))

    def full_match(self, pattern: str | os.PathLike[str], *, case_sensitive: bool | None = None) -> bool:
        """Return True if this path matches the given glob-style pattern.

        The pattern is matched against the entire path.
        """
        if not hasattr(pattern, "with_segments"):
            pattern = self.with_segments(pattern)
        if case_sensitive is None:
            # PATCH: check against case sensitivity of the parser
            case_sensitive = self.parser.case_sensitive

        # The string representation of an empty path is a single dot ('.'). Empty
        # paths shouldn't match wildcards, so we change it to the empty string.
        path = str(self) if self.parts else ""
        pattern = str(pattern) if pattern.parts else ""
        globber = _StringGlobber(self.parser.sep, case_sensitive, recursive=True)
        return globber.compile(pattern)(path) is not None

    def match(self, path_pattern: str | os.PathLike[str], *, case_sensitive: bool | None = None) -> bool:
        """Return True if this path matches the given pattern.

        If the pattern is relative, matching is done from the right; otherwise, the entire path
        is matched. The recursive wildcard '**' is *not* supported by this method.
        """
        if not hasattr(path_pattern, "with_segments"):
            path_pattern = self.with_segments(path_pattern)
        if case_sensitive is None:
            # PATCH: check against case sensitivity of the parser
            case_sensitive = self.parser.case_sensitive
        path_parts = self.parts[::-1]
        pattern_parts = path_pattern.parts[::-1]
        if not pattern_parts:
            raise ValueError("empty pattern")
        if len(path_parts) < len(pattern_parts):
            return False
        if len(path_parts) > len(pattern_parts) and path_pattern.anchor:
            return False
        globber = _StringGlobber(self.parser.sep, case_sensitive)
        for path_part, pattern_part in zip(path_parts, pattern_parts, strict=False):
            match = globber.compile(pattern_part)
            if match(path_part) is None:
                return False
        return True

    @property
    def _parts(self) -> list[str]:
        # PATCH: compatibility with 3.10 pathlib
        return list(self.parts)

    # Substitute methods and properties that we do not support with ones that raise errors
    # If any code tries to use unsupported features, it will get a clear error instead of silently doing the wrong thing
    for key, value in pathlib.PurePath.__dict__.items():
        if key in locals() or key.startswith("_"):
            continue

        if callable(value):
            locals()[key] = _create_error_method(key)
        elif isinstance(value, property):
            locals()[key] = property(_create_error_method(key))


# Subclassing os.PathLike makes isinstance() checks slower,
# which in turn makes Path construction slower. Register instead!
os.PathLike.register(PureTargetPath)


_STAT_RESULT_ERROR = []  # falsy sentinel indicating stat() failed.


class _Info:
    """Implementation of pathlib.types.PathInfo that provides status
    information by querying a wrapped os.stat_result object. Don't try to
    construct it yourself.
    """

    __slots__ = ("_entry", "_lstat_result", "_path", "_stat_result")

    def __init__(self, path: TargetPath, entry: DirEntry | None = None):
        self._path = path
        self._entry = entry
        self._stat_result = None
        self._lstat_result = None

    def __repr__(self) -> str:
        # PATCH: hardcode to TargetPath
        return "<TargetPath.info>"

    def _stat(self, *, follow_symlinks: bool = True) -> os.stat_result:
        """Return the status as an os.stat_result."""
        if self._entry:
            return self._entry.stat(follow_symlinks=follow_symlinks)

        # PATCH: call stat/lstat from the path object
        if follow_symlinks:
            if not self._stat_result:
                try:
                    self._stat_result = self._path.stat()
                except (OSError, ValueError):
                    self._stat_result = _STAT_RESULT_ERROR
                    raise
            return self._stat_result

        if not self._lstat_result:
            try:
                self._lstat_result = self._path.lstat()
            except (OSError, ValueError):
                self._lstat_result = _STAT_RESULT_ERROR
                raise
        return self._lstat_result

    def exists(self, *, follow_symlinks: bool = True) -> bool:
        """Whether this path exists."""
        if self._entry and not follow_symlinks:
            return True
        if follow_symlinks:
            if self._stat_result is _STAT_RESULT_ERROR:
                return False
        else:
            if self._lstat_result is _STAT_RESULT_ERROR:
                return False
        try:
            self._stat(follow_symlinks=follow_symlinks)
        except (OSError, ValueError):
            return False
        return True

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        """Whether this path is a directory."""
        if self._entry:
            try:
                return self._entry.is_dir(follow_symlinks=follow_symlinks)
            except OSError:
                return False
        if follow_symlinks:
            if self._stat_result is _STAT_RESULT_ERROR:
                return False
        else:
            if self._lstat_result is _STAT_RESULT_ERROR:
                return False
        try:
            st = self._stat(follow_symlinks=follow_symlinks)
        except (OSError, ValueError):
            return False
        return S_ISDIR(st.st_mode)

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        """Whether this path is a regular file."""
        if self._entry:
            try:
                return self._entry.is_file(follow_symlinks=follow_symlinks)
            except OSError:
                return False
        if follow_symlinks:
            if self._stat_result is _STAT_RESULT_ERROR:
                return False
        else:
            if self._lstat_result is _STAT_RESULT_ERROR:
                return False
        try:
            st = self._stat(follow_symlinks=follow_symlinks)
        except (OSError, ValueError):
            return False
        return S_ISREG(st.st_mode)

    def is_symlink(self) -> bool:
        """Whether this path is a symbolic link."""
        if self._entry:
            try:
                return self._entry.is_symlink()
            except OSError:
                return False
        if self._lstat_result is _STAT_RESULT_ERROR:
            return False
        try:
            st = self._stat(follow_symlinks=False)
        except (OSError, ValueError):
            return False
        return S_ISLNK(st.st_mode)

    def _posix_permissions(self, *, follow_symlinks: bool = True) -> int:
        """Return the POSIX file permissions."""
        return S_IMODE(self._stat(follow_symlinks=follow_symlinks).st_mode)

    def _file_id(self, *, follow_symlinks: bool = True) -> tuple[int, int]:
        """Returns the identifier of the file."""
        st = self._stat(follow_symlinks=follow_symlinks)
        return st.st_dev, st.st_ino

    def _access_time_ns(self, *, follow_symlinks: bool = True) -> int:
        """Return the access time in nanoseconds."""
        return self._stat(follow_symlinks=follow_symlinks).st_atime_ns

    def _mod_time_ns(self, *, follow_symlinks: bool = True) -> int:
        """Return the modify time in nanoseconds."""
        return self._stat(follow_symlinks=follow_symlinks).st_mtime_ns

    def _bsd_flags(self, *, follow_symlinks: bool = True) -> int:
        """Return the flags."""
        return self._stat(follow_symlinks=follow_symlinks).st_flags

    # PATCH: remove xattr support for now


class TargetPath(PureTargetPath, pathlib.Path):
    """PurePath subclass that can make system calls.

    Path represents a filesystem path but unlike PurePath, also offers
    methods to do system calls on path objects. Depending on your system,
    instantiating a Path will return either a PosixPath or a WindowsPath
    object. You can also instantiate a PosixPath or WindowsPath directly,
    but cannot instantiate a WindowsPath on a POSIX system or vice versa.
    """

    __slots__ = tuple({"_fs", "_info", "_entry"} - set(getattr(pathlib.Path, "__slots__", ())))

    def __new__(cls, fs: Filesystem, *args, **kwargs):
        if not isinstance(fs, Filesystem):
            raise TypeError(
                "invalid TargetPath initialization: missing filesystem, "
                "got {!r} (this might be a bug, please report)".format(fs, *args)
            )

        key = (fs.case_sensitive, fs.sep, fs.altsep)
        if (cls := _path_variants.get(key)) is None:
            raise TypeError(
                f"unsupported filesystem variant: case_sensitive={key[0]}, sep={key[1]!r}, altsep={key[2]!r}"
            )

        return object.__new__(cls)

    def __init__(self, fs: Filesystem, *args):
        self._fs = fs
        super().__init__(*args)

    def __repr__(self) -> str:
        # PATCH: hardcode TargetPath as class name
        return f"TargetPath({self.as_posix()!r})"

    def with_segments(self, *pathsegments) -> Self:
        return type(self)(self._fs, *pathsegments)

    def get(self) -> FilesystemEntry:
        """Return the :class:`FilesystemEntry` for this path."""
        if not hasattr(self, "_entry"):
            if hasattr(self, "_info") and self._info._entry is not None:
                self._entry = self._info._entry.get()
            else:
                self._entry = self._fs.get(str(self))
        return self._entry

    @property
    def info(self) -> _Info:
        """A PathInfo object that exposes the file type and other file attributes of this path."""
        try:
            return self._info
        except AttributeError:
            # PATCH: pass the path object instead of a string
            self._info = _Info(self)
            return self._info

    def stat(self, *, follow_symlinks: bool = True) -> stat_result:
        """Return the result of the stat() system call on this path, like os.stat() does."""
        # PATCH: call stat/lstat from the filesystem entry
        if follow_symlinks:
            return self.get().stat()
        return self.get().lstat()

    def lstat(self) -> stat_result:
        """Like stat(), except if the path points to a symlink, the symlink's status information is returned,
        rather than its target's.
        """
        # PATCH: call stat/lstat from the filesystem entry
        return self.get().lstat()

    def exists(self, *, follow_symlinks: bool = True) -> bool:
        """Whether this path exists.

        This method normally follows symlinks; to check whether a symlink exists,
        add the argument follow_symlinks=False.
        """
        # PATCH: use stat to check for existence
        try:
            # .exists() must resolve possible symlinks
            self.stat(follow_symlinks=follow_symlinks)
        except (FilesystemError, ValueError):
            return False
        else:
            return True

    def is_dir(self, *, follow_symlinks: bool = True) -> bool:
        """Whether this path is a directory."""
        # PATCH: always use stat to determine file type
        try:
            return S_ISDIR(self.stat(follow_symlinks=follow_symlinks).st_mode)
        except (OSError, ValueError):
            return False

    def is_file(self, *, follow_symlinks: bool = True) -> bool:
        """Whether this path is a regular file (also True for symlinks pointing to regular files)."""
        # PATCH: always use stat to determine file type
        try:
            return S_ISREG(self.stat(follow_symlinks=follow_symlinks).st_mode)
        except (OSError, ValueError):
            return False

    def is_mount(self) -> bool:
        """Check if this path is a mount point."""
        # PATCH: implement our own logic for checking mount points
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
        """Whether this path is a symbolic link."""
        # PATCH: always use stat to determine file type
        try:
            return S_ISLNK(self.lstat().st_mode)
        except (OSError, ValueError):
            return False

    def is_junction(self) -> bool:
        """Whether this path is a junction."""
        # PATCH: implement our own logic for checking junctions
        try:
            return self.get().entry.is_mount_point()
        except (FilesystemError, AttributeError):
            return False

    def is_block_device(self) -> bool:
        """Whether this path is a block device."""
        try:
            return S_ISBLK(self.stat().st_mode)
        except (OSError, ValueError):
            return False

    def is_char_device(self) -> bool:
        """Whether this path is a character device."""
        try:
            return S_ISCHR(self.stat().st_mode)
        except (OSError, ValueError):
            return False

    def is_fifo(self) -> bool:
        """Whether this path is a FIFO."""
        try:
            return S_ISFIFO(self.stat().st_mode)
        except (OSError, ValueError):
            return False

    def is_socket(self) -> bool:
        """Whether this path is a socket."""
        try:
            return S_ISSOCK(self.stat().st_mode)
        except (OSError, ValueError):
            return False

    def samefile(self, other_path: str | os.PathLike[str]) -> bool:
        """Return whether other_path is the same or not as this file."""
        st = self.stat()
        try:
            other_st = other_path.stat()
        except AttributeError:
            other_st = self.with_segments(other_path).stat()
        return st.st_ino == other_st.st_ino and st.st_dev == other_st.st_dev

    def open(
        self,
        # PATCH: default to binary mode
        mode: str = "rb",
        # PATCH: default to unbuffered
        # TODO: can we change this?
        buffering: int = 0,
        encoding: str | None = None,
        errors: str | None = None,
        newline: str | None = None,
    ) -> IO:
        """Open the file pointed to by this path and return a file object, as the built-in open() function does.

        Note: in contrast to regular Python, the mode is binary by default. Text mode
        has to be explicitly specified. Buffering is also disabled by default.
        """
        if "b" not in mode:
            # PATCH: default to UTF-8
            encoding = io.text_encoding(encoding or "UTF-8")
            # PATCH: default to select default buffering behavior
            buffering = buffering if buffering != 0 else -1

        # PATCH: custom open implementation, derived from _pyio.open()
        modes = set(mode)
        if modes - set("rbt") or len(mode) > len(modes):
            raise ValueError(f"invalid mode: {mode!r}")

        reading = "r" in modes
        binary = "b" in modes
        text = "t" in modes or "b" not in modes

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

        raw = self.get().open()
        result = raw

        try:
            line_buffering = False
            if buffering == 1 or (buffering < 0 and raw.isatty()):
                buffering = -1
                line_buffering = True
            if buffering < 0:
                buffering = io.DEFAULT_BUFFER_SIZE
            if buffering < 0:
                raise ValueError("invalid buffering size")
            if buffering == 0:
                if binary:
                    return result
                raise ValueError("can't have unbuffered text I/O")

            buffer = io.BufferedReader(raw, buffering)
            result = buffer
            if binary:
                return result

            text = io.TextIOWrapper(buffer, encoding, errors, newline, line_buffering)
            result = text
            text.mode = mode
        except:
            result.close()
            raise
        else:
            return result

    def read_bytes(self) -> bytes:
        """Open the file in bytes mode, read it, and close the file."""
        with self.open(mode="rb", buffering=0) as f:
            return f.read()

    def read_text(self, encoding: str | None = None, errors: str | None = None, newline: str | None = None) -> str:
        """Open the file in text mode, read it, and close the file."""
        # Call io.text_encoding() here to ensure any warning is raised at an
        # appropriate stack level.
        encoding = io.text_encoding(encoding)
        with self.open(mode="r", encoding=encoding, errors=errors, newline=newline) as f:
            return f.read()

    def write_bytes(self, data: bytes) -> int:
        """Open the file in bytes mode, write to it, and close the file."""
        f = f"{type(self).__name__}.write_bytes()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def write_text(
        self, data: str, encoding: str | None = None, errors: str | None = None, newline: str | None = None
    ) -> int:
        """Open the file in text mode, write to it, and close the file."""
        f = f"{type(self).__name__}.write_text()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def _from_dir_entry(self, dir_entry: DirEntry, name: str) -> Self:
        # PATCH: we use the entry name here and a joinpath instead of the full path
        # Read the reasoning in iterdir as to why
        path = self.joinpath(name)
        path._info = _Info(path, dir_entry)
        return path

    def iterdir(self) -> Iterator[Self]:
        """Yield path objects of the directory contents.

        The children are yielded in arbitrary order, and the
        special entries '.' and '..' are not included.
        """
        with _ScandirIterator(self.get().scandir()) as scandir_it:
            entries = list(scandir_it)
        # NOTE: We pass the entry name here instead of the path
        # TODO: Once we are more consistent on DirEntry paths, we can revert back to passing the full path
        # Requires a rework of the virtual, layer and root filesystems
        return (self._from_dir_entry(e, e.name) for e in entries)

    def glob(
        self, pattern: str | os.PathLike[str], *, case_sensitive: bool | None = None, recurse_symlinks: bool = False
    ) -> Iterator[Self]:
        """Iterate over this subtree and yield all existing files (of any
        kind, including directories) matching the given relative pattern.
        """
        if case_sensitive is None:
            # PATCH: take case sensitivity from the parser
            case_sensitive = self.parser.case_sensitive
            case_pedantic = False
        else:
            # The user has expressed a case sensitivity choice, but we don't
            # know the case sensitivity of the underlying filesystem, so we
            # must use scandir() for everything, including non-wildcard parts.
            case_pedantic = True
        parts = self._parse_pattern(pattern)
        recursive = True if recurse_symlinks else _no_recurse_symlinks
        # PATCH: use a custom path-based globber so we can override how the path is stringified
        globber = _TargetGlobber(self.parser.sep, case_sensitive, case_pedantic, recursive)
        select = globber.selector(parts[::-1])
        return select(globber.concat_path(self, "/"))

    def rglob(
        self, pattern: str | os.PathLike[str], *, case_sensitive: bool | None = None, recurse_symlinks: bool = False
    ) -> Iterator[Self]:
        """Recursively yield all existing files (of any kind, including
        directories) matching the given relative pattern, anywhere in
        this subtree.
        """
        pattern = self.parser.join("**", pattern)
        return self.glob(pattern, case_sensitive=case_sensitive, recurse_symlinks=recurse_symlinks)

    def walk(
        self, top_down: bool = True, on_error: Callable[[OSError], object] | None = None, follow_symlinks: bool = False
    ) -> Iterator[tuple[Self, list[str], list[str]]]:
        """Walk the directory tree from this directory, similar to os.walk()."""
        # PATCH: copied from _ReadablePath.walk
        paths = [self]
        while paths:
            path = paths.pop()
            if isinstance(path, tuple):
                yield path
                continue
            dirnames = []
            filenames = []
            if not top_down:
                paths.append((path, dirnames, filenames))
            try:
                for child in path.iterdir():
                    if child.info.is_dir(follow_symlinks=follow_symlinks):
                        if not top_down:
                            paths.append(child)
                        dirnames.append(child.name)
                    else:
                        filenames.append(child.name)
            except OSError as error:
                if on_error is not None:
                    on_error(error)
                if not top_down:
                    while not isinstance(paths.pop(), tuple):
                        pass
                continue
            if top_down:
                yield path, dirnames, filenames
                paths += [path.joinpath(d) for d in reversed(dirnames)]

    def absolute(self) -> Self:
        """Return an absolute version of this path
        No normalization or symlink resolution is performed.

        Use resolve() to resolve symlinks and remove '..' segments.
        """
        if self.is_absolute():
            return self
        # PATCH: just construct a new path from the existing parts, but with a root set
        # No need to play with drive here, since we would have taken the branch above if we had a drive
        return self._from_parsed_parts(self.drive, self.parser.sep, self.parts)

    @classmethod
    def cwd(cls) -> Self:
        """Return a new path pointing to the current working directory."""
        f = f"{type(cls).__name__}.cwd()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def resolve(self, strict: bool = False) -> Self:
        """Make the path absolute, resolving all symlinks on the way and also normalizing it."""
        return self.with_segments(polypath.realpath(str(self), fs=self._fs, strict=strict))

    def owner(self, *, follow_symlinks: bool = True) -> str:
        """Return the login name of the file owner."""
        f = f"{type(self).__name__}.owner()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def group(self, *, follow_symlinks: bool = True) -> str:
        """Return the group name of the file gid."""
        f = f"{type(self).__name__}.group()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def readlink(self) -> Self:
        """Return the path to which the symbolic link points."""
        # PATCH: read the link from the filesystem entry
        return self.with_segments(self.get().readlink())

    def touch(self, mode: int = 0o666, exist_ok: bool = True) -> None:
        """Create this file with the given access mode, if it doesn't exist."""
        f = f"{type(self).__name__}.touch()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def mkdir(self, mode: int = 0o777, parents: bool = False, exist_ok: bool = False) -> None:
        """Create a new directory at this given path."""
        f = f"{type(self).__name__}.mkdir()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def chmod(self, mode: int, *, follow_symlinks: bool = True) -> None:
        """Change the permissions of the path, like os.chmod()."""
        f = f"{type(self).__name__}.chmod()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def lchmod(self, mode: int) -> None:
        """Like chmod(), except if the path points to a symlink, the symlink's
        permissions are changed, rather than its target's.
        """
        f = f"{type(self).__name__}.lchmod()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def unlink(self, missing_ok: bool = False) -> None:
        """Remove this file or link. If the path is a directory, use rmdir() instead."""
        f = f"{type(self).__name__}.unlink()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def rmdir(self) -> None:
        """Remove this directory.  The directory must be empty."""
        f = f"{type(self).__name__}.rmdir()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def rename(self, target: str | os.PathLike[str]) -> Self:
        """Rename this path to the target path.

        The target path may be absolute or relative. Relative paths are
        interpreted relative to the current working directory, *not* the
        directory of the Path object.

        Returns the new Path instance pointing to the target path.
        """
        f = f"{type(self).__name__}.rename()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def replace(self, target: str | os.PathLike[str]) -> Self:
        """Rename this path to the target path, overwriting if that path exists.

        The target path may be absolute or relative. Relative paths are
        interpreted relative to the current working directory, *not* the
        directory of the Path object.

        Returns the new Path instance pointing to the target path.
        """
        f = f"{type(self).__name__}.replace()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def copy(self, target: str | os.PathLike[str], **kwargs) -> Self:
        """Recursively copy this file or directory tree to the given destination."""
        f = f"{type(self).__name__}.copy()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def copy_into(self, target_dir: str | os.PathLike[str], **kwargs) -> Self:
        """Copy this file or directory tree into the given existing directory."""
        f = f"{type(self).__name__}.copy_into()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def move(self, target: str | os.PathLike[str]) -> Self:
        """Recursively move this file or directory tree to the given destination."""
        f = f"{type(self).__name__}.move()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def move_into(self, target_dir: str | os.PathLike[str]) -> Self:
        """Move this file or directory tree into the given existing directory."""
        f = f"{type(self).__name__}.move_into()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def symlink_to(self, target: str | os.PathLike[str], target_is_directory: bool = False) -> None:
        """Make this path a symlink pointing to the target path.

        Note the order of arguments (link, target) is the reverse of os.symlink.
        """
        f = f"{type(self).__name__}.symlink_to()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def hardlink_to(self, target: str | os.PathLike[str]) -> None:
        """Make this path a hard link pointing to the same file as *target*.

        Note the order of arguments (self, target) is the reverse of os.link's.
        """
        f = f"{type(self).__name__}.hardlink_to()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def expanduser(self) -> Self:
        """Return a new path with expanded ~ and ~user constructs (as returned by os.path.expanduser)."""
        f = f"{type(self).__name__}.expanduser()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    @classmethod
    def home(cls) -> Self:
        """Return a new path pointing to expanduser('~')."""
        f = f"{type(cls).__name__}.home()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    def as_uri(self) -> str:
        """Return the path as a URI."""
        return super().as_uri()

    @classmethod
    def from_uri(cls, uri: str) -> Self:
        """Return a new path from the given 'file' URI."""
        f = f"{type(cls).__name__}.from_uri()"
        raise UnsupportedOperation(f"{f} is unsupported in Dissect")

    # PATCH: Substitute methods and properties that we do not support with ones that raise errors
    # If any code tries to use unsupported features, it will get a clear error instead of silently doing the wrong thing
    for key, value in pathlib.Path.__dict__.items():
        if key in locals() or key.startswith("_"):
            continue

        if callable(value):
            locals()[key] = _create_error_method(key)
        elif isinstance(value, property):
            locals()[key] = property(_create_error_method(key))


class _TargetGlobber(_PathGlobber):
    @staticmethod
    def concat_path(path: pathlib.Path, text: str) -> pathlib.Path:
        # Prevent double leading slashes
        s = _TargetGlobber.stringify_path(path)
        return path.with_segments((s + text) if s != text else text)

    @staticmethod
    def stringify_path(path: TargetPath) -> str:
        # This is necessary because the _GlobberBase class expects an added `/` at the end to calculate the starting
        # match position for a recursive glob
        return path._raw_path


# Pre-create variants
# Do this statically instead of dynamically so that it's a bit easier to reason about
# We could patch the class names up but, as I found out the hard way, that makes debugging harder
class PureCaseSensitivePosixTargetPath(PureTargetPath):
    parser = _PolyParser(case_sensitive=True, sep="/", altsep="")
    __slots__ = ()


class PureCaseInsensitivePosixTargetPath(PureTargetPath):
    parser = _PolyParser(case_sensitive=False, sep="/", altsep="")
    __slots__ = ()


class PureCaseSensitiveWindowsTargetPath(PureTargetPath):
    parser = _PolyParser(case_sensitive=True, sep="\\", altsep="/")
    __slots__ = ()


class PureCaseInsensitiveWindowsTargetPath(PureTargetPath):
    parser = _PolyParser(case_sensitive=False, sep="\\", altsep="/")
    __slots__ = ()


class PureCaseSensitiveDumbTargetPath(PureTargetPath):
    parser = _PolyParser(case_sensitive=True, sep="\\", altsep="")
    __slots__ = ()


class PureCaseInsensitiveDumbTargetPath(PureTargetPath):
    parser = _PolyParser(case_sensitive=False, sep="\\", altsep="")
    __slots__ = ()


class PureCaseSensitiveDumberTargetPath(PureTargetPath):
    parser = _PolyParser(case_sensitive=True, sep="/", altsep="\\")
    __slots__ = ()


class PureCaseInsensitiveDumberTargetPath(PureTargetPath):
    parser = _PolyParser(case_sensitive=False, sep="/", altsep="\\")
    __slots__ = ()


class CaseSensitivePosixTargetPath(TargetPath, PureCaseSensitivePosixTargetPath):
    __slots__ = ()


class CaseInsensitivePosixTargetPath(TargetPath, PureCaseInsensitivePosixTargetPath):
    __slots__ = ()


class CaseSensitiveWindowsTargetPath(TargetPath, PureCaseSensitiveWindowsTargetPath):
    __slots__ = ()


class CaseInsensitiveWindowsTargetPath(TargetPath, PureCaseInsensitiveWindowsTargetPath):
    __slots__ = ()


class CaseSensitiveDumbTargetPath(TargetPath, PureCaseSensitiveDumbTargetPath):
    __slots__ = ()


class CaseInsensitiveDumbTargetPath(TargetPath, PureCaseInsensitiveDumbTargetPath):
    __slots__ = ()


class CaseSensitiveDumberTargetPath(TargetPath, PureCaseSensitiveDumberTargetPath):
    __slots__ = ()


class CaseInsensitiveDumberTargetPath(TargetPath, PureCaseInsensitiveDumberTargetPath):
    __slots__ = ()


_path_variants = {
    (True, "/", ""): CaseSensitivePosixTargetPath,
    (False, "/", ""): CaseInsensitivePosixTargetPath,
    (True, "\\", "/"): CaseSensitiveWindowsTargetPath,
    (False, "\\", "/"): CaseInsensitiveWindowsTargetPath,
    (True, "\\", ""): CaseSensitiveDumbTargetPath,
    (False, "\\", ""): CaseInsensitiveDumbTargetPath,
    (True, "/", "\\"): CaseSensitiveDumberTargetPath,
    (False, "/", "\\"): CaseInsensitiveDumberTargetPath,
}
