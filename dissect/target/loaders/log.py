from __future__ import annotations

import urllib
from pathlib import Path
from typing import Union

from dissect.target import Target
from dissect.target.filesystem import RootFilesystem, VirtualFilesystem
from dissect.target.loader import Loader
from dissect.target.plugin import arg

logloader_option_hint = "hint"


@arg("--log-hint", dest=logloader_option_hint, help="hint for file type")
class LogLoader(Loader):
    """Load separate log files without a target. Usage: target-query /evtx/* -L log -f evtx (-L log -h for options)."""

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
        vfs = self.target.fs
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

