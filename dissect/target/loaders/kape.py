from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from dissect.target import filesystem, volume
from dissect.target.containers.vhdx import VhdxContainer
from dissect.target.filesystem import Filesystem
from dissect.target.loaders.dir import DirLoader, find_and_map_dirs, find_dirs
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    from dissect.target import Target


# KAPE doesn't have the correct filenames for several files, like $J or $Secure_$SDS
# The same applies to Velociraptor offline collector Windows.KapeFiles.Targets
USNJRNL_PATHS = ["$Extend/$J", "$Extend/$UsnJrnl$J"]


def open_vhdx(path: Path) -> Iterator[Filesystem]:
    container = VhdxContainer(path)
    volume_system = volume.open(container)
    for vol in volume_system.volumes:
        yield filesystem.open(vol)


def is_drive_letter(path: str) -> bool:
    return len(path) == 1 or (len(path) == 2 and path[1] == ":")


def is_valid_kape_dir(path: Path) -> bool:
    os_type, dirs = find_dirs(path)
    if os_type == OperatingSystem.WINDOWS:
        for dir_path in dirs:
            for path in USNJRNL_PATHS:
                if dir_path.joinpath(path).exists():
                    return True

    return False


def is_valid_kape_vhdx(path: Path) -> bool:
    if path.suffix == ".vhdx":
        for fs in open_vhdx(path):
            return is_valid_kape_dir(fs.path())

    return False


class KapeLoader(DirLoader):
    """Load KAPE forensic image format files.

    References:
        - https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape
    """

    def __init__(self, path, **kwargs):
        super().__init__(path)

        if path.is_dir():
            self.map = self.map_dir
        if path.suffix == ".vhdx":
            self.map = self.map_vhdx

    @staticmethod
    def detect(path: Path) -> bool:
        if path.is_dir():
            return is_valid_kape_dir(path)
        if path.suffix == ".vhdx":
            return is_valid_kape_vhdx(path)

    def map_vhdx(self, target: Target) -> None:
        for fs in open_vhdx(self.path):
            self.path = fs.path()
            self.map_dir(target)

    def map_dir(self, target: Target) -> None:
        find_and_map_dirs(
            target,
            self.path,
            sds_path="$Secure_$SDS",
            usnjrnl_path=USNJRNL_PATHS,
        )
