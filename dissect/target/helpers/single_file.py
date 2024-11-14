from __future__ import annotations

from dissect.target import plugin


class SingleFileMixin:
    @plugin.internal
    def get_single_files(self, pattern: str = "*") -> None:
        entries = self.target.fs.path("$drop$").rglob(pattern)
        return filter(lambda entry: entry.is_file(), entries)

    @property
    @plugin.internal
    def single_file_mode(self) -> bool:
        return self.target.fs.exists("$drop$")
