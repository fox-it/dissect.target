from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.overlay import Overlay2Filesystem
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target


class Overlay2Loader(Loader):
    """Load overlay2 filesystems."""

    @staticmethod
    def detect(path: TargetPath) -> bool:
        # path should be a folder
        if not path.is_dir():
            return False

        # with the following three files
        for required_file in ["init-id", "parent", "mount-id"]:
            if not path.joinpath(required_file).exists():
                return False

        # and should have the following parent folders
        return not "image/overlay2/layerdb/mounts/" not in path.as_posix()

    def map(self, target: Target) -> None:
        target.filesystems.add(Overlay2Filesystem(self.absolute_path))
