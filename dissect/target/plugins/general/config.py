from __future__ import annotations

from functools import lru_cache
from typing import Optional, Union

from dissect.target import Target
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystems.config import (
    ConfigurationEntry,
    ConfigurationFilesystem,
)
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.plugin import Plugin, internal


class ConfigurationTreePlugin(Plugin):
    __namespace__ = "config_tree"

    def __init__(self, target: Target, dir_path: str = "/"):
        super().__init__(target)
        self.config_fs = None

        target_dir_path = self.target.fs.path(dir_path)
        if target_dir_path.is_dir():
            self.config_fs = ConfigurationFilesystem(target, dir_path)

    def check_compatible(self) -> None:
        # This should be able to be retrieved, regardless of OS
        if self.config_fs is None:
            raise UnsupportedPluginError("The dir_path was")
        return None

    @lru_cache(128)
    def __call__(
        self,
        path: Optional[Union[TargetPath, str]] = None,
        hint: Optional[str] = None,
        collapse: Optional[Union[bool, set]] = None,
        seperator: Optional[tuple[str]] = None,
        comment_prefixes: Optional[tuple[str]] = None,
    ) -> Union[ConfigurationFilesystem, ConfigurationEntry]:
        """Create a configuration entry from a file, or a ConfigurationFilesystem from a directory.

        If a directory is specified in ``path``, the other arguments should be provided in the ``get`` call if needed.

        Args:
            path: The path to either a directory or file
            hint: What kind of parser it should use
            collapse: Wether it should collapse all or only certain keys.
            seperator: What seperator should be used for the parser.
            comment_prefixes: What is specified as a comment.

        """
        if not path:
            return self.config_fs

        if isinstance(path, TargetPath):
            path = str(path)

        return self.config_fs.get(path, None, hint, collapse, seperator, comment_prefixes)

    @internal
    def get(
        self,
        path: Optional[Union[TargetPath, str]] = None,
        hint: Optional[str] = None,
        collapse: Optional[set] = None,
        seperator: Optional[tuple[str]] = None,
        comment_prefixes: Optional[tuple[str]] = None,
    ) -> Union[ConfigurationFilesystem, ConfigurationEntry]:
        return self.__call__(path, hint, collapse, seperator, comment_prefixes)

    get.__doc__ = __call__.__doc__
