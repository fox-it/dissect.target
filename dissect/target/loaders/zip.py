from __future__ import annotations

import zipfile as zf
from typing import TYPE_CHECKING

from dissect.target.helpers.lazy import import_lazy
from dissect.target.loader import Loader, SubLoader
from dissect.target.loaders.dir import find_and_map_dirs

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import target


ZIP_EXT = (".zip",)


class ZipSubLoader(SubLoader[zf.Path]):
    """Zip implementation of a :class:`SubLoader`."""

    def __init__(self, zipfile: zf.Path, *args, **kwargs):
        super().__init__(zipfile, *args, **kwargs)
        self.zip = zipfile

    @staticmethod
    def detect(zipfile: zf.Path) -> bool:
        """Only to be called internally by :class:`ZipLoader`."""
        raise NotImplementedError

    def map(self, target: target.Target) -> None:
        """Only to be called internally by :class:`ZipLoader`."""
        raise NotImplementedError


class GenericZipSubLoader(ZipSubLoader):
    """Generic zip sub loader."""

    @staticmethod
    def detect(zipfile: zf.Path) -> bool:
        return True

    def map(self, target: target.Target) -> None:
        find_and_map_dirs(target, self.zip)


class ZipLoader(Loader):
    """Load zip files."""

    __subloaders__ = (
        import_lazy("dissect.target.loaders.acquire").AcquireZipSubLoader,
        import_lazy("dissect.target.loaders.uac").UacZipSubLoader,
        GenericZipSubLoader,  # should be last
    )

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)

        self.fh = path.open("rb")
        self.zip = zf.Path(self.fh)
        self.subloader = None

    @staticmethod
    def detect(path: Path) -> bool:
        return path.name.lower().endswith(ZIP_EXT)

    def map(self, target: target.Target) -> None:
        for candidate in self.__subloaders__:
            if candidate.detect(self.zip):
                self.subloader = candidate(self.zip)
                self.subloader.map(target)
                break
