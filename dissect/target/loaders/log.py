from __future__ import annotations

import urllib
from pathlib import Path
from typing import Union

from dissect.target import Target
from dissect.target.filesystem import RootFilesystem, VirtualFilesystem
from dissect.target.loader import Loader

logloader_option_hint = "hint"


class LogLoader(Loader):
    __loader_args__ = {
        logloader_option_hint: {"help": "Hint for file type"},
    }

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
        vfs = RootFilesystem(self.target)
        mnt = VirtualFilesystem(case_sensitive=False, alt_separator=target.fs.alt_separator)
        target.filesystems.add(mnt)
        vfs.mount("/", mnt)
        for entry in self.path.parent.glob(self.path.name):
            ext = self.options.get(logloader_option_hint, entry.suffix.lower()).strip(".")
            if (mapping := self.LOGS_DIRS.get(ext, None)) is None:
                continue
            mapping = str(mnt.path(mapping).joinpath(entry.name))
            mnt.map_file(mapping, str(entry))
        target.filesystems.add(vfs)
        target.fs = vfs
