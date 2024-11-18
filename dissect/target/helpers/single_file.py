from __future__ import annotations

from pathlib import Path
from typing import Iterable

from dissect.target import plugin
from dissect.target.target import SINGLE_FILE_DIR


class SingleFileMixin:
    @plugin.internal
    def get_drop_files(self, drop_pattern: str = "*") -> Iterable[Path]:
        " Return all files in the drop directory matching the given pattern."

        entries = self.target.fs.path(SINGLE_FILE_DIR).rglob(drop_pattern)
        return filter(lambda entry: entry.is_file(), entries)

    @property
    @plugin.internal
    def single_file_mode(self) -> bool:
        "Indicate if single file mode is enabled."

        return self.target.fs.exists(SINGLE_FILE_DIR)
