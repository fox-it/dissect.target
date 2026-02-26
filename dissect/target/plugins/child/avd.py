from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import ChildTargetRecord
from dissect.target.plugin import ChildTargetPlugin

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target import Target


def find_devices(paths: list[Path]) -> Iterator[str, Path]:
    for path in paths:
        for config_path in path.glob("*.ini"):
            with config_path.open("rt") as fh:
                for line in fh:
                    if not (line := line.strip()):
                        continue

                    key, _, value = line.partition("=")
                    if key == "path":
                        path = value.strip('"')
                        yield config_path.stem, path


class AVDChildTargetPlugin(ChildTargetPlugin):
    """Child target plugin that yields Android Virtual Devices.

    Resources:
        - https://developer.android.com/studio/run/emulator-commandline
    """

    __type__ = "avd"

    def __init__(self, target: Target):
        super().__init__(target)
        # TODO: Windows
        self.paths = [
            path
            for user in self.target.user_details.all_with_home()
            if (path := user.home_path.joinpath(".android/avd")).exists()
        ]

    def check_compatible(self) -> None:
        if not self.paths:
            raise UnsupportedPluginError("No AVD folders found")

    def list_children(self) -> Iterator[ChildTargetRecord]:
        for device_name, device_path in find_devices(self.paths):
            yield ChildTargetRecord(
                type=self.__type__,
                name=device_name,
                path=device_path,
                _target=self.target,
            )
