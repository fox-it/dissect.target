from __future__ import annotations

import functools
import operator
from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers.logging import get_logger
from dissect.target.loader import Loader
from dissect.target.plugins.os.default._os import DefaultOSPlugin

if TYPE_CHECKING:
    from dissect.target.target import Target

log = get_logger(__name__)


class DirectLoader(Loader):
    def __init__(self, paths: list[str | Path], case_sensitive: bool = False):
        self.case_sensitive = case_sensitive
        self.paths = [(Path(path) if not isinstance(path, Path) else path).resolve() for path in paths]

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        if not self.case_sensitive and self.check_case_insensitive_overlap():
            log.warning(
                "Direct mode used in case insensitive mode, but this will cause files overlap, "
                "consider using --direct-sensitive"
            )
        vfs = VirtualFilesystem(case_sensitive=self.case_sensitive)
        for path in self.paths:
            if path.is_file():
                vfs.map_file(str(path), str(path))
            elif path.is_dir():
                vfs.map_dir(str(path), str(path))

        target.filesystems.add(vfs)
        target._os_plugin = DefaultOSPlugin

    def check_case_insensitive_overlap(self) -> bool:
        """Verify if two differents files will have the same path in a case-insensitive fs"""
        all_files_list = set(functools.reduce(operator.iadd, (list(p.rglob("*")) for p in self.paths), []))
        return len({str(p).lower() for p in all_files_list}) != len(all_files_list)
