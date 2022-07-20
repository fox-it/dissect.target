from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from dissect.target.loaders.dir import DirLoader, find_dirs, map_dirs

if TYPE_CHECKING:
    from dissect.target import Target


class KapeLoader(DirLoader):
    @staticmethod
    def detect(path: Path) -> bool:
        os_type, dirs = find_dirs(path)
        if os_type == "windows":
            for dir_path in dirs:
                # KAPE doesn't have the correct filenames for several files, like $J or $Secure_$SDS
                if dir_path.joinpath("$Extend/$J").exists():
                    return True

        return False

    def map(self, target: Target) -> None:
        map_dirs(
            target,
            self.path,
            sds_path="$Secure_$SDS",
            usnjrnl_path="$Extend/$J",
        )
