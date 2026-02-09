from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.helpers.record import WindowsUserRecord
from dissect.target.loader import Loader
from dissect.target.plugin import OSPlugin, export
from dissect.target.plugins.os.windows.registry import RegistryPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from typing_extensions import Self

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class ProfileLoader(Loader):
    """Load NTUSER.DAT files."""

    @staticmethod
    def detect(path: Path) -> bool:
        return bool(path.is_dir() and path.joinpath("NTUSER.DAT").exists())

    def map(self, target: Target) -> None:
        username = self.path.name

        dfs = DirectoryFilesystem(self.absolute_path, case_sensitive=False)
        target.filesystems.add(dfs)
        target.fs.mount(f"sysvol/users/{username}", dfs)

        target._os_plugin = ProfileOSPlugin
        target.add_plugin(RegistryPlugin, check_compatible=False)


class ProfileOSPlugin(OSPlugin):
    @classmethod
    def detect(cls, target: Target) -> bool:
        return True

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> Self:
        return cls(target)

    @export(property=True)
    def hostname(self) -> str:
        return self.target._generic_name

    @export(property=True)
    def ips(self) -> list:
        return []

    @export(property=True)
    def version(self) -> None:
        return None

    @export
    def users(self) -> Iterator[WindowsUserRecord]:
        yield WindowsUserRecord(
            sid="0",
            name=self.hostname,
            home=f"sysvol/users/{self.hostname}",
            _target=self.target,
        )

    @export(property=True)
    def os(self) -> str:
        return "windows"
