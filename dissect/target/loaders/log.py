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
class LogLoader(Loader):
    """Load separate log files without a target.

    Usage:

    ``target-query /evtx/* -L log -f evtx``

    """

    LOGS_DIRS: Final[dict[str, str]] = {
        "evtx": "sysvol/windows/system32/winevt/logs",
        "evt": "sysvol/windows/system32/config",
        "iis": "sysvol/files/logs/",
    }

    def __init__(self, path: Path, parsed_path: urllib.parse.ParseResult | None = None):
        super().__init__(path, parsed_path)
        warnings.warn(
            "The LogLoader is deprecated in favor of direct files (`--direct`)"
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
        for entry in self.path.parent.glob(self.path.name):
            ext = self.options.get("hint", entry.suffix.lower()).strip(".")
            if (mapping := self.LOGS_DIRS.get(ext, None)) is None:
                continue
            mapping = str(vfs.path(mapping).joinpath(entry.name))
            vfs.map_file(mapping, str(entry))
