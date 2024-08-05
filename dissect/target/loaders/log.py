from __future__ import annotations

import urllib
from pathlib import Path
from typing import Union

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader
from dissect.target.plugin import arg


@arg("--log-hint", dest="hint", help="hint for file type")
@arg("--path", dest="path", help="Map log file(s) to a specific path in the target filesystem")
class LogLoader(Loader):
    """Load separate log files without a target. By default attempts to map discovered log files based on their file
    extension. The loader can also map log files to a specific path in the target filesystem using the ``--path``
    option.

    Usage:

    ``target-query /evtx/* -L log -f evtx``

    or by specifying a manual path, which can be a directory or a single file:

    * ``target-query log://evidence/extracted_wtmp?path=/var/log/wtmp -f wtmp``
    * ``target-query log://evidence/apache?path=/var/log/apache2 -f apache.access``
    """

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
        vfs = VirtualFilesystem(case_sensitive=False, alt_separator=target.fs.alt_separator)
        target.filesystems.add(vfs)
        target.fs.mount("/", vfs)
        if manual_path := self.options.get("path"):
            if self.path.is_dir():
                for entry in self.path.glob("*"):
                    # Map every entry in the directory to the manual path
                    mapping = str(vfs.path(manual_path).joinpath(entry.name))
                    vfs.map_file(mapping, str(entry))
            else:
                # Manual path is a single file, map it into the virtual filesystem
                vfs.map_file(manual_path, str(self.path))
        else:
            for entry in self.path.parent.glob(self.path.name):
                ext = self.options.get("hint", entry.suffix.lower()).strip(".")
                if (mapping := self.LOGS_DIRS.get(ext, None)) is None:
                    continue
                mapping = str(vfs.path(mapping).joinpath(entry.name))
                vfs.map_file(mapping, str(entry))
