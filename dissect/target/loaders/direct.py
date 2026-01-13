from __future__ import annotations

import functools
import operator
from itertools import chain
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
                vfs.map_file(str(path), path)
            elif path.is_dir():
                vfs.map_dir(str(path), path)

        target.filesystems.add(vfs)
        target._os_plugin = DefaultOSPlugin

    def check_case_insensitive_overlap(self) -> bool:
        """Verify if two differents files will have the same path in a case-insensitive fs"""

        def get_files(path: Path) -> list[Path]:
            if not path.exists():
                return []
            if path.is_file():
                return [path]
            # Recursively find all files in the directory
            return list(path.rglob("*"))

        # Create a flat list of all file paths from all input directories
        all_paths = chain.from_iterable(get_files(p) for p in self.paths)
        # Filter out directories, keeping only files
        all_files = [p for p in all_paths if p.is_file()]
        # Compare the count of all files with the count of unique, lowercased file paths

        return len({str(p).lower() for p in all_files}) != len(all_files)

    def __repr__(self) -> str:
        """
        As DirectLoader does not call super().__init__() self.path is not defined, we need to redefine the __repr__ func
        :return:
        """
        return f"{self.__class__.__name__}({str(self.paths)!r})"
