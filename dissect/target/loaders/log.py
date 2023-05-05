from pathlib import Path

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader


class LogLoader(Loader):
    LOGS_DIRS = {
        ".evtx": "sysvol/windows/system32/winevt/logs",
        ".evt": "sysvol/windows/system32/config",
    }

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        self.target = target
        vfs = VirtualFilesystem(case_sensitive=False)
        for entry in self.path.parent.glob(self.path.name):
            ext = entry.suffix.lower()
            if (mapping := self.LOGS_DIRS.get(ext, None)) is None:
                continue
            mapping = str(Path(mapping).joinpath(entry.name))
            vfs.map_file(mapping, str(entry))
        target.filesystems.add(vfs)
        target.fs = vfs
