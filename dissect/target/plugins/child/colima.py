from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target import Target


def find_containers(paths: list[Path]) -> Iterator[Path]:
    for path in paths:
        for config_path in path.iterdir():
            if (config_file := config_path.joinpath("colima.yaml")).exists():
                name = f"-{config_file.parts[-2]}" if config_file.parts[-2] != "default" else ""
                if (disk_path := path.joinpath("_lima", f"colima{name}", "diffdisk")).exists():
                    yield disk_path


class ColimaChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields Colima containers.

    Colima is a container runtime for macOS and Linux.

    Resources:
        - https://github.com/abiosoft/colima/blob/5d2e91c4a491d4ae35d69fb2583f4f959401bc37
    """

    __type__ = "colima"

    def __init__(self, target: Target):
        super().__init__(target)
        self.paths = [
            path
            for user in self.target.user_details.all_with_home()
            if (path := user.home_path.joinpath(".colima")).exists()
        ]

    def check_compatible(self) -> None:
        if not self.paths:
            raise UnsupportedPluginError("No Colima configurations found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for container in find_containers(self.paths):
            yield ChildTargetRecord(
                type=self.__type__,
                path=container,
                _target=self.target,
            )
