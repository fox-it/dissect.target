from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target


class LimaChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields Lima VMs.

    Lima (Linux Machines) is a Linux VM or container runtime for macOS and Linux.

    References:
        - https://github.com/lima-vm/lima
    """

    __type__ = "lima"

    def __init__(self, target: Target):
        super().__init__(target)
        self.paths = []
        for user in self.target.user_details.all_with_home():
            # check .lima folder in ~/
            if (path := user.home_path.joinpath(".lima")).exists():
                self.paths.append(path)
            # check .lima folder in ~/.config/
            if (path := user.home_path.joinpath(".config", "lima")).exists():
                self.paths.append(path)

    def check_compatible(self) -> None:
        if not self.paths:
            raise UnsupportedPluginError("No Lima configurations found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for path in self.paths:
            for instance in path.iterdir():
                if instance.name.startswith((".", "_")) or not instance.is_dir():
                    continue

                yield ChildTargetRecord(
                    type=self.__type__,
                    name=instance.name,
                    path=instance.joinpath("diffdisk"),
                    _target=self.target,
                )
