import urllib
from pathlib import Path
from typing import Union

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader


class LogLoader(Loader):
    LOGS_DIRS = {
        "evtx": "sysvol/windows/system32/winevt/logs",
        "evt": "sysvol/windows/system32/config",
        "iis": "sysvol/files/logs/",
    }

    def __init__(self, path: Union[Path, str], parsed_path=None):
        super().__init__(path)
        self.options = {}
        if parsed_path:
            self.options = dict(urllib.parse.parse_qsl(parsed_path.query, keep_blank_values=True))

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        self.target = target
        vfs = VirtualFilesystem(case_sensitive=False)
        for entry in self.path.parent.glob(self.path.name):
            ext = self.options.get("hint", entry.suffix.lower()).strip(".")
            if (mapping := self.LOGS_DIRS.get(ext, None)) is None:
                continue
            mapping = str(Path(mapping).joinpath(entry.name))
            vfs.map_file(mapping, str(entry))
        target.filesystems.add(vfs)
        target.fs = vfs
