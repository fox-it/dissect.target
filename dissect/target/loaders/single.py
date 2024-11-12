from __future__ import annotations

from pathlib import Path

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader


DROP_FILE_DIR = "$drop$"


class SingleFileLoader(Loader):
    """Load single file without a target.

    Usage:

    ``target-query --single-file /evtx/* -f evtx``

    """

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        vfs = VirtualFilesystem(case_sensitive=False, alt_separator=target.fs.alt_separator)
        target.filesystems.add(vfs)
        target.fs.mount("/", vfs)
        for entry in self.path.parent.glob(self.path.name):
            mapping = str(vfs.path(DROP_FILE_DIR).joinpath(entry.name))
            vfs.map_file(mapping, str(entry))
