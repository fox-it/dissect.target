"""The necessary glob internals for our pathlib implementation. Copied from Lib/glob.py.

Update periodically.

Commit we're in sync with:
Hash:       e54225545866d780b12d8e70c33d25fc13b2c3a9
Date:       2026-03-02T11:56:28.000Z
Branch:     main (3.15)
URL:        https://github.com/python/cpython/commit/e54225545866d780b12d8e70c33d25fc13b2c3a9

Notes:
    - https://github.com/python/cpython/blob/main/Lib/glob.py
"""

from __future__ import annotations

import functools
import operator
import os
import re
from typing import TYPE_CHECKING, Any

from dissect.target.helpers.compat import fnmatch

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator, Sequence
    from pathlib import Path

magic_check = re.compile("([*?[])")

_special_parts = ("", ".", "..")
_no_recurse_symlinks = object()


# NOTE: Copied from glob.py >=3.13
def translate(
    pat: str, *, recursive: bool = False, include_hidden: bool = False, seps: Sequence[str] | None = None
) -> str:
    """Translate a pathname with shell wildcards to a regular expression.

    If `recursive` is true, the pattern segment '**' will match any number of
    path segments.

    If `include_hidden` is true, wildcards can match path segments beginning
    with a dot ('.').

    If a sequence of separator characters is given to `seps`, they will be
    used to split the pattern into segments and match path separators. If not
    given, os.path.sep and os.path.altsep (where available) are used.
    """
    if not seps:
        seps = (os.path.sep, os.path.altsep) if os.path.altsep else os.path.sep
    escaped_seps = "".join(map(re.escape, seps))
    any_sep = f"[{escaped_seps}]" if len(seps) > 1 else escaped_seps
    not_sep = f"[^{escaped_seps}]"
    if include_hidden:
        one_last_segment = f"{not_sep}+"
        one_segment = f"{one_last_segment}{any_sep}"
        any_segments = f"(?:.+{any_sep})?"
        any_last_segments = ".*"
    else:
        one_last_segment = f"[^{escaped_seps}.]{not_sep}*"
        one_segment = f"{one_last_segment}{any_sep}"
        any_segments = f"(?:{one_segment})*"
        any_last_segments = f"{any_segments}(?:{one_last_segment})?"

    results = []
    parts = re.split(any_sep, pat)
    last_part_idx = len(parts) - 1
    for idx, part in enumerate(parts):
        if part == "*":
            results.append(one_segment if idx < last_part_idx else one_last_segment)
        elif recursive and part == "**":
            if idx < last_part_idx:
                if parts[idx + 1] != "**":
                    results.append(any_segments)
            else:
                results.append(any_last_segments)
        else:
            if part:
                if not include_hidden and part[0] in "*?":
                    results.append(r"(?!\.)")
                results.extend(fnmatch._translate(part, f"{not_sep}*", not_sep)[0])
            if idx < last_part_idx:
                results.append(any_sep)
    res = "".join(results)
    # PATCH: Change \z to \Z for backwards compatibility
    return rf"(?s:{res})\Z"


@functools.lru_cache(maxsize=512)
def _compile_pattern(
    pat: str, seps: Sequence[str], case_sensitive: bool, recursive: bool = True
) -> Callable[[str, int | None], bool]:
    """Compile given glob pattern to a re.Pattern object (observing case sensitivity)."""
    # PATCH: NOFLAG was added in 3.11
    flags = getattr(re, "NOFLAG", 0) if case_sensitive else re.IGNORECASE
    regex = translate(pat, recursive=recursive, include_hidden=True, seps=seps)
    return re.compile(regex, flags=flags).match


class _GlobberBase:
    """Abstract class providing shell-style pattern matching and globbing."""

    def __init__(self, sep: str, case_sensitive: bool, case_pedantic: bool = False, recursive: bool = False):
        self.sep = sep
        self.case_sensitive = case_sensitive
        self.case_pedantic = case_pedantic
        self.recursive = recursive

    # Abstract methods

    @staticmethod
    def lexists(path: Any) -> bool:
        """Implements os.path.lexists()."""
        raise NotImplementedError

    @staticmethod
    def scandir(path: Any) -> Iterator[tuple[os.DirEntry, str, Any]]:
        """Like os.scandir(), but generates (entry, name, path) tuples."""
        raise NotImplementedError

    @staticmethod
    def concat_path(path: Any, text: str) -> Any:
        """Implements path concatenation."""
        raise NotImplementedError

    @staticmethod
    def stringify_path(path: Any) -> str:
        """Converts the path to a string object."""
        raise NotImplementedError

    # High-level methods

    def compile(self, pat: str, altsep: str | None = None) -> Callable[[str, int | None], bool]:
        seps = (self.sep, altsep) if altsep else self.sep
        return _compile_pattern(pat, seps, self.case_sensitive, self.recursive)

    def selector(self, parts: list[str]) -> Callable[[Any, int | None], Iterator[Any]]:
        """Returns a function that selects from a given path, walking and
        filtering according to the glob-style pattern parts in *parts*.
        """
        if not parts:
            return self.select_exists
        part = parts.pop()
        if self.recursive and part == "**":
            selector = self.recursive_selector
        elif part in _special_parts:
            selector = self.special_selector
        elif not self.case_pedantic and magic_check.search(part) is None:
            selector = self.literal_selector
        else:
            selector = self.wildcard_selector
        return selector(part, parts)

    def special_selector(self, part: str, parts: list[str]) -> Callable[[Any, int | None], Iterator[Any]]:
        """Returns a function that selects special children of the given path."""
        if parts:
            part += self.sep
        select_next = self.selector(parts)

        def select_special(path: Any, exists: bool = False) -> Iterator[Any]:
            path = self.concat_path(path, part)
            return select_next(path, exists)

        return select_special

    def literal_selector(self, part: str, parts: list[str]) -> Callable[[Any, int | None], Iterator[Any]]:
        """Returns a function that selects a literal descendant of a path."""
        # Optimization: consume and join any subsequent literal parts here,
        # rather than leaving them for the next selector. This reduces the
        # number of string concatenation operations.
        while parts and magic_check.search(parts[-1]) is None:
            part += self.sep + parts.pop()
        if parts:
            part += self.sep

        select_next = self.selector(parts)

        def select_literal(path: Any, exists: bool = False) -> Iterator[Any]:
            path = self.concat_path(path, part)
            return select_next(path, exists=False)

        return select_literal

    def wildcard_selector(self, part: str, parts: list[str]) -> Callable[[Any, int | None], Iterator[Any]]:
        """Returns a function that selects direct children of a given path, filtering by pattern."""
        match = None if part == "*" else self.compile(part)
        dir_only = bool(parts)
        if dir_only:
            select_next = self.selector(parts)

        def select_wildcard(path: Any, exists: bool = False) -> Iterator[Any]:
            try:
                entries = self.scandir(path)
            except OSError:
                pass
            else:
                for entry, entry_name, entry_path in entries:
                    if match is None or match(entry_name):
                        if dir_only:
                            try:
                                if not entry.is_dir():
                                    continue
                            except OSError:
                                continue
                            entry_path = self.concat_path(entry_path, self.sep)
                            yield from select_next(entry_path, exists=True)
                        else:
                            yield entry_path

        return select_wildcard

    def recursive_selector(self, part: str, parts: list[str]) -> Callable[[str, int | None], Iterator[Any]]:
        """Returns a function that selects a given path and all its children,
        recursively, filtering by pattern.
        """
        # Optimization: consume following '**' parts, which have no effect.
        while parts and parts[-1] == "**":
            parts.pop()

        # Optimization: consume and join any following non-special parts here,
        # rather than leaving them for the next selector. They're used to
        # build a regular expression, which we use to filter the results of
        # the recursive walk. As a result, non-special pattern segments
        # following a '**' wildcard don't require additional filesystem access
        # to expand.
        follow_symlinks = self.recursive is not _no_recurse_symlinks
        if follow_symlinks:
            while parts and parts[-1] not in _special_parts:
                part += self.sep + parts.pop()

        match = None if part == "**" else self.compile(part)
        dir_only = bool(parts)
        select_next = self.selector(parts)

        def select_recursive(path: Any, exists: bool = False) -> Iterator[Any]:
            path_str = self.stringify_path(path)
            match_pos = len(path_str)
            if match is None or match(path_str, match_pos):
                yield from select_next(path, exists)
            stack = [path]
            while stack:
                yield from select_recursive_step(stack, match_pos)

        def select_recursive_step(stack: list[Any], match_pos: int) -> Iterator[Any]:
            path = stack.pop()
            try:
                entries = self.scandir(path)
            except OSError:
                pass
            else:
                for entry, _entry_name, entry_path in entries:
                    is_dir = False
                    try:
                        if entry.is_dir(follow_symlinks=follow_symlinks):
                            is_dir = True
                    except OSError:
                        pass

                    if is_dir or not dir_only:
                        entry_path_str = self.stringify_path(entry_path)
                        if dir_only:
                            entry_path = self.concat_path(entry_path, self.sep)
                        if match is None or match(entry_path_str, match_pos):
                            if dir_only:
                                yield from select_next(entry_path, exists=True)
                            else:
                                # Optimization: directly yield the path if this is
                                # last pattern part.
                                yield entry_path
                        if is_dir:
                            stack.append(entry_path)

        return select_recursive

    def select_exists(self, path: Any, exists: bool = False) -> Iterator[Any]:
        """Yields the given path, if it exists."""
        if exists:
            # Optimization: this path is already known to exist, e.g. because
            # it was returned from os.scandir(), so we skip calling lstat().
            yield path
        elif self.lexists(path):
            yield path


class _StringGlobber(_GlobberBase):
    """Provides shell-style pattern matching and globbing for string paths."""

    lexists = staticmethod(os.path.lexists)
    concat_path = operator.add

    @staticmethod
    def scandir(path: str) -> Iterator[tuple[os.DirEntry, str, str]]:
        # We must close the scandir() object before proceeding to
        # avoid exhausting file descriptors when globbing deep trees.
        with os.scandir(path) as scandir_it:
            entries = list(scandir_it)
        return ((entry, entry.name, entry.path) for entry in entries)

    @staticmethod
    def stringify_path(path: str) -> str:
        return path  # Already a string.


# NOTE: This is copied from Lib/pathlib/_os.py
def vfspath(obj: Any) -> str:
    """Return the string representation of a virtual path object."""
    cls = type(obj)
    try:
        vfspath_method = cls.__vfspath__
    except AttributeError:
        cls_name = cls.__name__
        raise TypeError(f"expected JoinablePath object, not {cls_name}") from None
    else:
        return vfspath_method(obj)


# NOTE: This is copied from Lib/pathlib/types.py
class _PathGlobber(_GlobberBase):
    """Provides shell-style pattern matching and globbing for ReadablePath."""

    @staticmethod
    def lexists(path: Path) -> bool:
        return path.info.exists(follow_symlinks=False)

    @staticmethod
    def scandir(path: Path) -> Iterator[tuple[os.DirEntry, str, Path]]:
        return ((child.info, child.name, child) for child in path.iterdir())

    @staticmethod
    def concat_path(path: Path, text: str) -> Path:
        return path.with_segments(vfspath(path) + text)

    stringify_path = staticmethod(vfspath)
