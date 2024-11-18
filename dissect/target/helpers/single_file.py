from __future__ import annotations

from pathlib import Path
from typing import Iterable

from dissect.target import plugin
from dissect.target.target import SINGLE_FILE_DIR


class SingleFileMixin:
    """Companion mixin to the SingleFileLoader that provides a way to access files in the drop directory.

    Simultaneously, this marks a plugin as compatible with single file mode.
    """

    @plugin.internal
    def get_drop_files(self, drop_pattern: str = "*") -> Iterable[Path]:
        """Return all files in the drop directory by recursively matching against the given pattern.

        Args:
            drop_pattern: The pattern to match files against.

        Returns:
            An iterable of paths to files in the drop directory matching the pattern.
        """

        entries = self.target.fs.path(SINGLE_FILE_DIR).rglob(drop_pattern)
        return filter(lambda entry: entry.is_file(), entries)

    @property
    @plugin.internal
    def single_file_mode(self) -> bool:
        """Indicate if single file mode is enabled."""

        return self.target.fs.exists(SINGLE_FILE_DIR)
