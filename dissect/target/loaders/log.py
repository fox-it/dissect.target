from __future__ import annotations

import urllib.parse
import warnings
from typing import TYPE_CHECKING, Final

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loader import Loader
from dissect.target.plugin import arg

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


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

    LOGS_DIRS: Final[dict[str, str]] = {
        "evtx": "sysvol/windows/system32/winevt/logs",
        "evt": "sysvol/windows/system32/config",
        "iis": "sysvol/files/logs/",
    }

    def __init__(self, path: Path, parsed_path: urllib.parse.ParseResult | None = None):
        super().__init__(path, parsed_path)
        warnings.warn(
            "The LogLoader is deprecated in favor of single files (`--single-file`)"
            " and will be removed in dissect.target 3.24",
            FutureWarning,
            stacklevel=2,
        )
        self.options = dict(urllib.parse.parse_qsl(parsed_path.query, keep_blank_values=True)) if parsed_path else {}

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
