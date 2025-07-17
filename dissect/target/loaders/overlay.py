from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.overlay import OverlayFilesystem
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from dissect.target.helpers.fsutil import TargetPath
    from dissect.target.target import Target


class OverlayLoader(Loader):
    """Load Podman OCI overlay filesystems."""

    @staticmethod
    def detect(path: TargetPath) -> bool:
        # path should be a folder
        if not path.is_dir():
            return False

        # with the following files
        for file in ["diff", "link", "lower", "work"]:  # "merged" is optional
            if not path.joinpath(file).exists():
                return False

        # and should have the following parent folders
        return "containers/storage/overlay/" in path.as_posix()

    def map(self, target: Target) -> None:
        target.filesystems.add(OverlayFilesystem(self.absolute_path))
