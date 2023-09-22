from __future__ import annotations

from functools import lru_cache
from typing import Union, Optional

from dissect.target import Target
from dissect.target.plugin import Plugin, internal
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.filesystems.config import ConfigurationFilesystem, ConfigurationEntry
from dissect.target.exceptions import UnsupportedPluginError


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
        path: Union[str, TargetPath] = "/",
        hint: Optional[str] = None,
        collapse: Optional[Union[bool, set]] = None,
        seperator: Optional[tuple[str]] = None,
        comment_prefixes: Optional[tuple[str]] = None,
    ) -> ConfigurationEntry:
        """Create a configuration entry from a file, or a COnfigurationFilesystem from a directory.

        If a directory is specified in ``path``, please provide the other arguments in the ``get`` call.

        Args:
            path: The path to either a directory or file
            hint: What kind of parser it should use
            collapse: Wether it should collapse all or only certain keys.
            seperator: What seperator should be used for the parser.
            comment_prefixes: What is specified as a comment.

        """

        if not path:
            return self.config_fs.get("/")

        target_path = path
        if isinstance(target_path, str):
            target_path = self.target.fs.path(path)

        return self.config_fs.get(str(target_path), None, hint, collapse, seperator, comment_prefixes)

    @internal
    def get(
        self,
        path: Optional[str] = None,
        hint: Optional[str] = None,
        collapse: Optional[set] = None,
        seperator: Optional[tuple[str]] = None,
        comment_prefixes: Optional[tuple[str]] = None,
    ) -> ConfigurationEntry:
        return self.__call__(path or "/", hint, collapse, seperator, comment_prefixes)

    get.__doc__ = __call__.__doc__
