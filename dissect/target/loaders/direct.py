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
    from collections.abc import Iterator

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

    def yield_all_file_recursively(self, base_path: Path, max_depth: int = 7) -> Iterator[Path]:
        """
        Return list of all files recursively, as rglob is not case-sensitive until python 3.12

        :param base_path:
        :param max_depth: max depth, prevent infinite recursion
        :return:
        """
        if max_depth == 0:
            return
        if not base_path.exists():
            return
        if base_path.is_file():
            yield base_path
            return
        for f in base_path.iterdir():
            if f.is_dir():
                yield from self.yield_all_file_recursively(f, max_depth=max_depth - 1)
            else:
                yield f

    def check_case_insensitive_overlap(self) -> bool:
        """Verify if two differents files will have the same path in a case-insensitive fs"""
        all_files_list = list(
            functools.reduce(operator.iadd, (list(self.yield_all_file_recursively(p)) for p in self.paths), [])
        )
        return len({str(p).lower() for p in all_files_list}) != len(all_files_list)

    def __repr__(self) -> str:
        """
        As DirectLoader does not call super().__init__() self.path is not defined, we need to redefine the __repr__ func
        :return:
        """
        return f"{self.__class__.__name__}({str(self.paths)!r})"
