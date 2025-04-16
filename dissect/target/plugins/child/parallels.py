from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target

PARALLELS_USER_PATHS = [
    "Parallels",
    "Documents/Parallels",
    "Library/Group Containers/*.com.parallels.desktop.appstore/Shared/Parallels",
]

PARALLELS_SYSTEM_PATHS = [
    "/Users/Shared/Parallels",
]


def find_pvms(target: Target) -> Iterator[TargetPath]:
    """Finds virtual machines located in default folders on a macOS target.

    Resources:
        - https://kb.parallels.com/117333
    """
    for user_details in target.user_details.all_with_home():
        for parallels_path in PARALLELS_SYSTEM_PATHS:
            if (path := target.fs.path(parallels_path)).exists():
                yield from iter_vms(path)

        for parallels_path in PARALLELS_USER_PATHS:
            if "*" in parallels_path:
                start_path, pattern = parallels_path.split("*", 1)
                for path in user_details.home_path.joinpath(start_path).rglob("*" + pattern):
                    yield from iter_vms(path)
            else:
                if (path := user_details.home_path.joinpath(parallels_path)).exists():
                    yield from iter_vms(path)


def iter_vms(path: Path) -> Iterator[TargetPath]:
    """Glob for .pvm folders in the provided folder."""
    for file in path.rglob("*.pvm"):
        if file.is_dir():
            yield file


class ParallelsChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields Parallels Desktop VM files."""

    __type__ = "parallels"

    def __init__(self, target: Target):
        super().__init__(target)
        self.pvms = list(find_pvms(target))

    def check_compatible(self) -> None:
        if not self.pvms:
            raise UnsupportedPluginError("No Parallels pvm file(s) found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for pvm in self.pvms:
            yield ChildTargetRecord(
                type=self.__type__,
                path=pvm,
                _target=self.target,
            )
