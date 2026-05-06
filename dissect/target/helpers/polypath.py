"""Filesystem path manipulation functions.

Similar to posixpath and ntpath, but with support for alternative separators.

Dissect paths support both POSIX and Windows formats for parsing and visual
representation, but always normalize to a POSIX standard for internal operations.
Most path operations follow POSIX semantics, with the main exception being
that for Windows-style paths, we consider paths starting with a separator to
be absolute, and we have a few more possible "drive letter" names (see ALLOWED_DRIVE_NAMES).
All other path manipulations (joining, splitting, etc.) follow POSIX semantics
regardless of the separator style.

The path manipulations in this module should be primarily viewed as manipulations
according to these rules, while preserving the formatting of the input path as
much as possible.

Normalization to the internal POSIX standard is done at a higher level
(for example, in TargetPath), but can be performed manually if needed
using :meth:`fsutil.normalize`.
"""

from __future__ import annotations

import ntpath
import os
import posixpath
import re
import stat
from typing import TYPE_CHECKING

from dissect.target.exceptions import FileNotFoundError, FilesystemError, NotADirectoryError, SymlinkRecursionError

# ALLOW_MISSING was added in 3.14
try:
    from genericpath import ALLOW_MISSING
except ImportError:
    # A singleton with a true boolean value.
    @object.__new__
    class ALLOW_MISSING:
        """Special value for use in realpath()."""

        def __repr__(self) -> str:
            return "os.path.ALLOW_MISSING"

        def __reduce__(self) -> str:
            return self.__class__.__name__


# splitroot was added in 3.12
try:
    from posixpath import splitroot as posix_splitroot
except ImportError:
    try:
        from posix import _path_splitroot_ex as posix_splitroot
    except ImportError:

        def posix_splitroot(p: str | bytes, /) -> tuple[str | bytes, str | bytes, str | bytes]:
            """Split a pathname into drive, root and tail.

            The tail contains anything after the root.
            """
            p = os.fspath(p)
            if isinstance(p, bytes):
                sep = b"/"
                empty = b""
            else:
                sep = "/"
                empty = ""
            if p[:1] != sep:
                # Relative path, e.g.: 'foo'
                return empty, empty, p
            if p[1:2] != sep or p[2:3] == sep:
                # Absolute path, e.g.: '/foo', '///foo', '////foo', etc.
                return empty, sep, p[1:]
            # Precisely two leading slashes, e.g.: '//foo'. Implementation defined per POSIX, see
            # https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/V1_chap04.html#tag_04_13
            return empty, p[:2], p[2:]


try:
    from ntpath import splitroot as nt_splitroot
except ImportError:
    try:
        from nt import _path_splitroot_ex as nt_splitroot
    except ImportError:

        def nt_splitroot(p: str | bytes, /) -> tuple[str | bytes, str | bytes, str | bytes]:
            """Split a pathname into drive, root and tail.

            The tail contains anything after the root.
            """
            p = os.fspath(p)
            if isinstance(p, bytes):
                sep = b"\\"
                altsep = b"/"
                colon = b":"
                unc_prefix = b"\\\\?\\UNC\\"
                empty = b""
            else:
                sep = "\\"
                altsep = "/"
                colon = ":"
                unc_prefix = "\\\\?\\UNC\\"
                empty = ""
            normp = p.replace(altsep, sep)
            if normp[:1] == sep:
                if normp[1:2] == sep:
                    # UNC drives, e.g. \\server\share or \\?\UNC\server\share
                    # Device drives, e.g. \\.\device or \\?\device
                    start = 8 if normp[:8].upper() == unc_prefix else 2
                    index = normp.find(sep, start)
                    if index == -1:
                        return p, empty, empty
                    index2 = normp.find(sep, index + 1)
                    if index2 == -1:
                        return p, empty, empty
                    return p[:index2], p[index2 : index2 + 1], p[index2 + 1 :]
                # Relative path with root, e.g. \Windows
                return empty, p[:1], p[1:]
            if normp[1:2] == colon:
                if normp[2:3] == sep:
                    # Absolute drive-letter path, e.g. X:\Windows
                    return p[:2], p[2:3], p[3:]
                # Relative path with drive, e.g. X:Windows
                return p[:2], empty, p[2:]
            # Relative path, e.g. Windows
            return empty, empty, p


if TYPE_CHECKING:
    from collections.abc import Sequence

    from dissect.target.filesystem import Filesystem

# Additional drive names we allow besides traditional drive letters
# Keep in sync with plugins/os/windows/_os.py
ALLOWED_DRIVE_NAMES = ("$fs", "sysvol", "efi", "winre")

RE_NORMALIZE_PATH = re.compile(r"[/]+")
RE_NORMALIZE_SBS_PATH = re.compile(r"[\\/]+")


def normalize(path: str, *, sep: str = "/") -> str:
    """Normalize a path to the internal standard format.

    All separators will be deduplicated and replaced with the internal standard separator (POSIX-style "/").
    """
    # TODO: consider using normpath here, but that might be a bit too opinionated for a general normalization function
    if sep == "\\":
        return RE_NORMALIZE_SBS_PATH.sub("/", path)
    return RE_NORMALIZE_PATH.sub("/", path)


def isabs(path: str, *, sep: str = "/") -> bool:
    """Test whether a path is absolute."""
    # We only consider paths starting with a separator to be absolute
    if sep == "\\":
        if path[:1] in ("\\", "/"):
            return True
        # For Windows-style paths, we also consider paths with a drive to be absolute
        # Check splitroot for our definition of a drive
        drive, _, _ = splitroot(path, sep=sep)
        if drive:
            return True
    return path[:1] == "/"


def join(*args: str, sep: str = "/") -> str:
    """Join two or more pathname components, inserting '/' as needed.
    If any component is an absolute path, all previous path components will be discarded.
    An empty last part will result in a path that ends with a separator.

    Joining always follows POSIX rules, even for Windows-style separators.
    This means that joining with a "Windows-style absolute path" such as a drive letter,
    will not discard the previous components. It will simply be joined as a normal path component.
    """
    # Copy of posixpath.join that uses the given separator
    seps = ("\\", "/") if sep == "\\" else ("/",)
    path = args[0] if args else ""
    for part in args[1:]:
        if part.startswith(seps) or not path:
            path = part
        elif path.endswith(seps):
            path += part
        else:
            path += sep + part
    return path


def split(path: str, *, sep: str = "/") -> str:
    """Split a pathname. Returns tuple "(head, tail)" where "tail" is
    everything after the final slash. Either part may be empty.
    """
    return ntpath.split(path) if sep == "\\" else posixpath.split(path)


def splitext(path: str, *, sep: str = "/") -> tuple[str, str]:
    """Split the extension from a pathname.

    Extension is everything from the last dot to the end, ignoring
    leading dots. Returns "(root, ext)"; ext may be empty.
    """
    if sep == "\\":
        root, ext = ntpath.splitext(path)
        return root, ext
    return posixpath.splitext(path)


def splitdrive(path: str, *, sep: str = "/") -> tuple[str, str]:
    """Split a pathname into drive and path. On POSIX separators, drive is always empty."""
    if sep == "\\":
        drive, root, tail = splitroot(path, sep=sep)
        return drive, root + tail
    return posixpath.splitdrive(path)


def splitroot(path: str, *, sep: str = "/") -> tuple[str, str, str]:
    """Split a pathname into drive, root and tail.

    The tail contains anything after the root.
    """
    if sep == "\\":
        removed_leading_sep = False
        # Only split using ntpath rules if the path starts with a separator (i.e. it's an absolute path)
        if path[:1] in ("\\", "/") and path[1:2] not in ("\\", "/"):
            # We need to strip the leading separator for ntpath to correctly parse drive letters
            # Multiple leading separators could be UNC or device paths, so preserve them for correct parsing
            path = path[1:]
            removed_leading_sep = True

        drive, root, rel = nt_splitroot(path)
        if not drive and rel:
            # ntpath only splts drives for UNC, device or drive letter paths
            # We want to support a few other drive names too (ALLOWED_DRIVE_NAMES)
            # Since we only take this path on absolute paths (and absolute paths are guaranteed by fs.path()),
            # we can treat the first part of the path as a drive, and the rest as a relative path
            index = rel.replace("/", "\\").find("\\")
            if (new_drive := rel[: index if index != -1 else None]).lower() in ALLOWED_DRIVE_NAMES:
                drive = new_drive
                if not root:
                    root = rel[index : index + 1] if index != -1 else "\\"
                rel = rel[index + 1 :] if index != -1 else ""

        if (not drive and not rel) or (removed_leading_sep and not drive and not root):
            # E.g. bare separator path like "\" or "/"
            root = "\\"

        elif drive and not root:
            # E.g. c:path/to/file
            # While this is technically legal in Windows, we don't support relative paths so this is only confusing
            for candidate in (drive, rel):
                # Try to find an existing separator in either the drive or the relative part
                if (index := candidate.find("\\")) != -1:
                    root = candidate[index : index + 1]
                    break
            else:
                root = "\\"
    else:
        # Any other path is parsed using POSIX rules
        drive, root, rel = posix_splitroot(path)

    return drive, root, rel


def basename(path: str, *, sep: str = "/") -> str:
    """Returns the final component of a pathname."""
    # Copy of posixpath.basename that uses the given separator
    path = os.fspath(path)
    normpath = path.replace("/", "\\") if sep == "\\" else path
    i = normpath.rfind(sep) + 1
    return path[i:]


def dirname(path: str, *, sep: str = "/") -> str:
    """Returns the directory component of a pathname."""
    # Copy of posixpath.dirname that uses the given separator
    path = os.fspath(path)
    normpath = path.replace("/", "\\") if sep == "\\" else path
    i = normpath.rfind(sep) + 1
    head = normpath[:i]
    if head and head != sep * len(head):
        head = head.rstrip(sep)
    return path[: len(head)]


def normpath(path: str, *, sep: str = "/") -> str:
    """Normalize path, eliminating double slashes, etc."""
    path = ntpath.normpath(path) if sep == "\\" else posixpath.normpath(path)
    if path == ".":
        path = ""
    return path


def abspath(path: str, *, cwd: str = "", sep: str = "/") -> str:
    """Return an absolute path."""
    cwd = cwd or sep
    if not isabs(path, sep=sep):
        path = join(cwd, path, sep=sep)
    return normpath(path, sep=sep)


def realpath(filename: str, *, fs: Filesystem, strict: bool = False, sep: str = "/") -> str:
    """Return the canonical path of the specified filename, eliminating any symbolic links encountered in the path."""
    # Copy of posixpath.realpath with some small tweaks
    if sep == "\\":
        filename = filename.replace("/", "\\")

    curdir = "."
    pardir = ".."

    if strict is ALLOW_MISSING:
        ignored_error = FileNotFoundError
        strict = True
    elif strict:
        ignored_error = ()
    else:
        ignored_error = FilesystemError

    lstat = fs.lstat
    readlink = fs.readlink
    maxlinks = None

    # The stack of unresolved path parts. When popped, a special value of None
    # indicates that a symlink target has been resolved, and that the original
    # symlink path can be retrieved by popping again. The [::-1] slice is a
    # very fast way of spelling list(reversed(...)).
    rest = filename.split(sep)[::-1]

    # Number of unprocessed parts in 'rest'. This can differ from len(rest)
    # later, because 'rest' might contain markers for unresolved symlinks.
    part_count = len(rest)

    # The resolved path, which is absolute throughout this function.
    path = sep

    # Mapping from symlink paths to *fully resolved* symlink targets. If a
    # symlink is encountered but not yet resolved, the value is None. This is
    # used both to detect symlink loops and to speed up repeated traversals of
    # the same links.
    seen = {}

    # Number of symlinks traversed. When the number of traversals is limited
    # by *maxlinks*, this is used instead of *seen* to detect symlink loops.
    link_count = 0

    while part_count:
        name = rest.pop()
        if name is None:
            # resolved symlink target
            seen[rest.pop()] = path
            continue
        part_count -= 1
        if not name or name == curdir:
            # current dir
            continue
        if name == pardir:
            # parent dir
            path = path[: path.rindex(sep)] or sep
            continue
        newpath = path + name if path == sep else path + sep + name
        try:
            st_mode = lstat(newpath).st_mode
            if not stat.S_ISLNK(st_mode):
                if strict and part_count and not stat.S_ISDIR(st_mode):
                    raise NotADirectoryError(newpath)
                path = newpath
                continue
            if maxlinks is not None:
                link_count += 1
                if link_count > maxlinks:
                    if strict:
                        raise SymlinkRecursionError(newpath)
                    path = newpath
                    continue
            elif newpath in seen:
                # Already seen this path
                path = seen[newpath]
                if path is not None:
                    # use cached value
                    continue
                # The symlink is not resolved, so we must have a symlink loop.
                if strict:
                    raise SymlinkRecursionError(newpath)
                path = newpath
                continue
            target = readlink(newpath)
        except ignored_error:
            pass
        else:
            # Resolve the symbolic link
            if target.startswith(sep):
                # Symlink target is absolute; reset resolved path.
                path = sep
            if maxlinks is None:
                # Mark this symlink as seen but not fully resolved.
                seen[newpath] = None
                # Push the symlink path onto the stack, and signal its specialness
                # by also pushing None. When these entries are popped, we'll
                # record the fully-resolved symlink target in the 'seen' mapping.
                rest.append(newpath)
                rest.append(None)
            # Push the unresolved symlink target parts onto the stack.
            target_parts = target.split(sep)[::-1]
            rest.extend(target_parts)
            part_count += len(target_parts)
            continue
        # An error occurred and was ignored.
        path = newpath

    return path


def _commonprefix(m: Sequence[str], /) -> str:
    """Internal implementation of commonprefix()."""
    # Copy of genericpath._commonprefix
    if not m:
        return ""
    # Some people pass in a list of pathname parts to operate in an OS-agnostic
    # fashion; don't try to translate in that case as that's an abuse of the
    # API and they are already doing what they need to be OS-agnostic and so
    # they most likely won't be using an os.PathLike object in the sublists.
    if not isinstance(m[0], (list, tuple)):
        m = tuple(map(os.fspath, m))
    s1 = min(m)
    s2 = max(m)
    for i, c in enumerate(s1):
        if c != s2[i]:
            return s1[:i]
    return s1


def relpath(path: str, start: str, *, sep: str = "/", case_sensitive: bool | None = None) -> str:
    """Return a relative version of a path."""
    # Copy of posixpath.relpath with pieces of ntpath.relpath
    path = os.fspath(path)
    if not path:
        raise ValueError("no path specified")

    # PATCH: explicitly require a starting path
    if not start:
        raise ValueError("no start specified")

    # PATCH: automatically determine case sensitivity if not given
    if case_sensitive is None:
        case_sensitive = sep != "\\"

    if isinstance(path, bytes):
        sep = sep.encode()
        pardir = b".."
    else:
        pardir = ".."

    start = os.fspath(start)

    start_tail = abspath(start, sep=sep).lstrip(sep)
    path_tail = abspath(path, sep=sep).lstrip(sep)
    start_list = start_tail.split(sep) if start_tail else []
    path_list = path_tail.split(sep) if path_tail else []
    # Work out how much of the filepath is shared by start and path.
    if case_sensitive:
        i = len(_commonprefix([start_list, path_list]))
    else:
        i = 0
        for e1, e2 in zip(start_list, path_list, strict=False):
            if e1.lower() != e2.lower():
                break
            i += 1

    rel_list = [pardir] * (len(start_list) - i) + path_list[i:]
    if not rel_list:
        return ""
    return sep.join(rel_list)


def commonpath(paths: list[str], *, sep: str = "/", case_sensitive: bool | None = None) -> str:
    """Given a sequence of path names, returns the longest common sub-path."""
    # Copy of posixpath.commonpath with pieces of ntpath.commonpath
    paths = tuple(map(os.fspath, paths))
    if not paths:
        raise ValueError("commonpath() arg is an empty sequence")

    # PATCH: automatically determine case sensitivity if not given
    if case_sensitive is None:
        case_sensitive = sep != "\\"

    if isinstance(paths[0], bytes):
        sep = sep.encode()
        curdir = b"."
    else:
        sep = sep
        curdir = "."

    if sep == "\\":
        paths = [p.replace("/", "\\") for p in paths]

    split_paths = [(path.lower() if not case_sensitive else path).split(sep) for path in paths]

    try:
        (isabs,) = {p.startswith(sep) for p in paths}
    except ValueError:
        raise ValueError("Can't mix absolute and relative paths") from None

    common = paths[0].split(sep)
    common = [c for c in common if c and c != curdir]

    split_paths = [[c for c in s if c and c != curdir] for s in split_paths]
    s1 = min(split_paths)
    s2 = max(split_paths)
    for i, c in enumerate(s1):
        if c != s2[i]:
            common = common[:i]
            break
    else:
        common = common[: len(s1)]

    prefix = sep if isabs else sep[:0]
    return prefix + sep.join(common)
