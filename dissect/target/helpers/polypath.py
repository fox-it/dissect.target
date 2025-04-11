"""Filesystem path manipulation functions.

Similar to posixpath and ntpath, but with support for alternative separators.
"""

from __future__ import annotations

import posixpath
import re

re_normalize_path = re.compile(r"[/]+")
re_normalize_sbs_path = re.compile(r"[\\/]+")


def normalize(path: str, alt_separator: str = "") -> str:
    if alt_separator == "\\":
        return re_normalize_sbs_path.sub("/", path)
    return re_normalize_path.sub("/", path)


def isabs(path: str, alt_separator: str = "") -> bool:
    return posixpath.isabs(normalize(path, alt_separator=alt_separator))


def join(*args, alt_separator: str = "") -> str:
    return posixpath.join(*[normalize(part, alt_separator=alt_separator) for part in args])


def split(path: str, alt_separator: str = "") -> str:
    return posixpath.split(normalize(path, alt_separator=alt_separator))


splitext = posixpath.splitext


splitdrive = posixpath.splitdrive


def splitroot(path: str, alt_separator: str = "") -> tuple[str, str, str]:
    return posixpath.splitroot(normalize(path, alt_separator=alt_separator))


def basename(path: str, alt_separator: str = "") -> str:
    return posixpath.basename(normalize(path, alt_separator=alt_separator))


def dirname(path: str, alt_separator: str = "") -> str:
    return posixpath.dirname(normalize(path, alt_separator=alt_separator))


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


def commonpath(paths: list[str], alt_separator: str = "") -> str:
    return posixpath.commonpath([normalize(path, alt_separator=alt_separator) for path in paths])


def isreserved(path: str) -> bool:
    """Return True if the path is a reserved name.

    We currently do not have any reserved names.
    """
    return False
