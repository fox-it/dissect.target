from dissect.target import Target
from dissect.target.plugin import Plugin, internal
from functools import lru_cache

from typing import Optional
from dissect.target.plugins.os.unix.config import ConfigurationFilesystem, ConfigurationEntry
from dissect.target.exceptions import UnsupportedPluginError


class EtcTree(Plugin):
    __namespace__ = "etc"

    def __init__(self, target: Target):
        super().__init__(target)
        self.config_fs = None
        if self.target.fs.path("/etc").exists():
            self.config_fs = ConfigurationFilesystem(target, "/etc")

    def check_compatible(self) -> None:
        if self.config_fs is None:
            raise UnsupportedPluginError()
        return None

    @lru_cache(128)
    def __call__(
        self,
        path: Optional[str] = None,
        hint: Optional[str] = None,
        collapse: Optional[set] = None,
        seperator: Optional[tuple[str]] = None,
        comment_prefixes: Optional[tuple[str]] = None,
    ) -> ConfigurationEntry:
        return self.config_fs.get(path, hint, collapse, seperator, comment_prefixes)

    @internal
    def get(
        self,
        path: Optional[str] = None,
        hint: Optional[str] = None,
        collapse: Optional[set] = None,
        seperator: Optional[tuple[str]] = None,
        comment_prefixes: Optional[tuple[str]] = None,
    ) -> ConfigurationEntry:
        return self.__call__(path, hint, collapse, seperator, comment_prefixes)
