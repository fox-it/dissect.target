from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystems.config import (
    ConfigurationEntry,
    ConfigurationFilesystem,
)
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.plugin import Plugin, internal

if TYPE_CHECKING:
    from collections.abc import Iterable

    from dissect.target.target import Target


class ConfigurationTreePlugin(Plugin):
    __namespace__ = "config_tree"

    def __init__(self, target: Target, dir_path: str = "/"):
        super().__init__(target)
        self.dir_path = dir_path
        self.config_fs = None

        target_dir_path = self.target.fs.path(dir_path)
        if target_dir_path.is_dir():
            self.config_fs = ConfigurationFilesystem(target, dir_path)

        self._get = lru_cache(128)(self._get)

    def check_compatible(self) -> None:
        # This should be able to be retrieved, regardless of OS
        if self.config_fs is None:
            raise UnsupportedPluginError(f"{self.dir_path!r} could not be found.")
        return

    def __call__(
        self,
        path: TargetPath | str | None = None,
        hint: str | None = None,
        collapse: bool | Iterable[str] | None = None,
        collapse_inverse: bool | None = None,
        separator: tuple[str] | None = None,
        comment_prefixes: tuple[str] | None = None,
        as_dict: bool = False,
    ) -> ConfigurationFilesystem | ConfigurationEntry | dict:
        """Create a configuration entry from a file, or a :class:`.ConfigurationFilesystem` from a directory.

        If a directory is specified in ``path``, the other arguments should be provided in the ``get`` call if needed.

        Args:
            path: The path to either a directory or file.
            hint: What kind of parser it should use.
            collapse: Whether it should collapse everything or just a certain set of keys.
            collapse_inverse: Invert the collapse function to collapse everything but the keys inside ``collapse``.
            separator: The separator that should be used for parsing.
            comment_prefixes: What is specified as a comment.
            as_dict: Return a dictionary instead of an entry.
        """
        return self.get(
            path=path,
            as_dict=as_dict,
            hint=hint,
            collapse=collapse,
            collapse_inverse=collapse_inverse,
            separator=separator,
            comment_prefixes=comment_prefixes,
        )

    @internal
    def get(
        self, path: TargetPath | str | None = None, as_dict: bool = False, *args, **kwargs
    ) -> ConfigurationFilesystem | ConfigurationEntry | dict:
        if collapse := kwargs.pop("collapse", None):
            kwargs.update({"collapse": frozenset(collapse)})

        return self._get(path, as_dict, *args, **kwargs)

    def _get(
        self, path: TargetPath | str | None = None, as_dict: bool = False, *args, **kwargs
    ) -> ConfigurationFilesystem | ConfigurationEntry | dict:
        if not path:
            return self.config_fs

        if isinstance(path, TargetPath):
            path = str(path)

        entry = self.config_fs.get(path, None, *args, **kwargs)

        if as_dict:
            return entry.as_dict()

        return entry

    get.__doc__ = __call__.__doc__
