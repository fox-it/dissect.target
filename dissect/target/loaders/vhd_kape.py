from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target import filesystem, volume
from dissect.target.containers.vhd import VhdContainer
from dissect.target.loader import Loader
from dissect.target.loaders.dir import find_and_map_dirs, find_dirs
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


# KAPE doesn't have the correct filenames for several files, like $J or $Secure_$SDS
# The same applies to Velociraptor offline collector Windows.KapeFiles.Targets
USNJRNL_PATHS = ["$Extend/$J", "$Extend/$UsnJrnl$J"]


def open_vhd(path: Path) -> Iterator[Filesystem]:
    container = VhdContainer(path)
    volume_system = volume.open(container)
    for vol in volume_system.volumes:
        yield filesystem.open(vol)


def is_valid_kape_dir(path: Path) -> bool:
    os_type, dirs = find_dirs(path)
    if os_type == OperatingSystem.WINDOWS:
        for dir_path in dirs:
            for path in USNJRNL_PATHS:
                if dir_path.joinpath(path).exists():
                    return True

    return False


def is_valid_kape_vhd(path: Path) -> bool:
    if path.suffix == ".vhd":
        try:
            for fs in open_vhd(path):
                return is_valid_kape_dir(fs.path())
        except Exception:
            return False

    return False


class VhdKapeLoader(Loader):
    """Load VHD KAPE forensic image format files.

    References:
        - https://www.kroll.com/en/insights/publications/cyber/kroll-artifact-parser-extractor-kape
    """

    @staticmethod
    def detect(path: Path) -> bool:
        if path.is_dir():
            return is_valid_kape_dir(path)
        if path.suffix.lower() == ".vhd":
            return is_valid_kape_vhd(path)
        return False

    def map(self, target: Target) -> None:
        path = self.absolute_path if self.absolute_path.is_dir() else next(open_vhd(self.absolute_path)).path()

        find_and_map_dirs(
            target,
            path,
            sds_path="$Secure_$SDS",
            usnjrnl_path=USNJRNL_PATHS,
        )
