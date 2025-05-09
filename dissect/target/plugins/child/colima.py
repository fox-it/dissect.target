from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target import Target


class ColimaChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields Colima configuration.

    Resources:
        - https://github.com/abiosoft/colima/blob/5d2e91c4a491d4ae35d69fb2583f4f959401bc37
    """

    __type__ = "colima"

    def __init__(self, target: Target):
        super().__init__(target)
        self.configuration_paths = list(self.find_configurations())

    def find_configurations(self) -> Iterator[Path]:
        for user_details in self.target.user_details.all_with_home():
            if (path := user_details.home_path.joinpath(".colima")).exists():
                yield path

    def find_vms(self, configuration_paths: list[Path]) -> Iterator[Path]:
        for config_path in configuration_paths:
            for path in config_path.iterdir():
                if (path := path.joinpath("colima.yaml")).exists():
                    name = f"-{path.parts[-2]}" if path.parts[-2] != "default" else ""
                    if (disk_path := config_path.joinpath(f"_lima/colima{name}/diffdisk")).exists():
                        yield disk_path

    def check_compatible(self) -> None:
        if not self.configuration_paths:
            raise UnsupportedPluginError("No Colima configurations found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for vm in self.find_vms(self.configuration_paths):
            yield ChildTargetRecord(
                type=self.__type__,
                path=vm,
                _target=self.target,
            )
