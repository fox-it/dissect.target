from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.loaders.dir import DirLoader, find_and_map_dirs, find_dirs
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    from dissect.target import Target


# KAPE doesn't have the correct filenames for several files, like $J or $Secure_$SDS
# The same applies to Velociraptor offline collector Windows.KapeFiles.Targets
USNJRNL_PATHS = ["$Extend/$J", "$Extend/$UsnJrnl$J"]


class KapeLoader(DirLoader):
    @staticmethod
    def detect(path: Path) -> bool:
        os_type, dirs = find_dirs(path)
        if os_type == OperatingSystem.WINDOWS:
            for dir_path in dirs:
                for path in USNJRNL_PATHS:
                    if dir_path.joinpath(path).exists():
                        return True

        return False

    def map(self, target: Target) -> None:
        find_and_map_dirs(
            target,
            self.path,
            sds_path="$Secure_$SDS",
            usnjrnl_path=USNJRNL_PATHS,
        )
