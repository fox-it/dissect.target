from __future__ import annotations

from pathlib import Path

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader
from dissect.target.target import SINGLE_FILE_DIR


class SingleFileLoader(Loader):
    """Load single file without a target.

    Usage:

    ``target-query --single-file /evtx/* -f evtx``

    """

    @staticmethod
    def detect(_: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        """Maps the contents of the target path recursively into a special drop folder"""

        vfs = VirtualFilesystem(case_sensitive=False, alt_separator=target.fs.alt_separator)
        target.filesystems.add(vfs)
        target.fs.mount("/", vfs)
        for entry in self.path.parent.glob(self.path.name):
            mapping = vfs.path(SINGLE_FILE_DIR).joinpath(entry.name)
            vfs.map_file(str(mapping), str(entry))
