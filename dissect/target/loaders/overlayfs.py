from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.filesystems.overlay import OverlayFsFilesystem
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from dissect.target.helpers.compat.pathlib import TargetPath
    from dissect.target.target import Target


class OverlayFsLoader(Loader):
    """Load containerd OCI overlay filesystems."""

    @staticmethod
    def detect(path: TargetPath) -> bool:
        """Detect an ``overlayfs`` bbolt ``meta.db`` path.

        Example::
            /var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db/<container_id>
        """
        # The filename should be 64 characters long (full sha256 container id)
        if len(path.name) != 64:
            return False

        # The parent should be a bbolt meta.db file
        if not path.parent or path.parent.name != "meta.db":
            return False

        # The path should contain the containerd metadata folder
        return "io.containerd.metadata.v1.bolt/meta.db" in path.as_posix()

    def map(self, target: Target) -> None:
        target.filesystems.add(OverlayFsFilesystem(self.absolute_path))
