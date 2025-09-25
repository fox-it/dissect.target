from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target import Target


def find_vms(path: Path) -> Iterator[tuple[str, Path, Path]]:
    """Find the Lima VMs from Colima and yield the name, Colima configuration path and Lima VM path.

    References:
        - https://github.com/abiosoft/colima/blob/5ddf1e0dc67772f6e28f84c7c7b32f2343ad4bfb/config/profile.go#L19-L39
    """
    for config_file in path.glob("*/colima.yaml"):
        profile = config_file.parent.name
        if profile == "default":
            lima_id = "colima"
        else:
            profile = profile.removeprefix("colima-")
            lima_id = f"colima-{profile}"

        if (lima_path := path.joinpath("_lima", lima_id)).exists():
            yield profile, config_file, lima_path


class ColimaChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields Colima VMs.

    Colima is a container runtime for macOS and Linux.

    References:
        - https://github.com/abiosoft/colima
    """

    __type__ = "colima"

    def __init__(self, target: Target):
        super().__init__(target)
        self.paths = []
        for user in self.target.user_details.all_with_home():
            # check .colima folder in ~/
            if (path := user.home_path.joinpath(".colima")).exists():
                self.paths.append(path)
            # check .colima folder in ~/.config/
            if (path := user.home_path.joinpath(".config", "colima")).exists():
                self.paths.append(path)

    def check_compatible(self) -> None:
        if not self.paths:
            raise UnsupportedPluginError("No Colima configurations found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for path in self.paths:
            for name, _, lima_path in find_vms(path):
                yield ChildTargetRecord(
                    type=self.__type__,
                    name=name,
                    path=lima_path.joinpath("diffdisk"),
                    _target=self.target,
                )
