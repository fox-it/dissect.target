from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.loaders.dir import DirLoader, find_and_map_dirs, find_dirs
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class TaniumLoader(DirLoader):
    """Load Tanium forensic image format files."""

    @staticmethod
    def detect(path: Path) -> bool:
        # A Tanium package is very similar to a Kape package.
        # The 'file' folder contains the disk data acquired using the Tanium client.
        # The 'collector' folder contains parsed, interpreted and collected host info
        # TIMESTAMP-HOSTNAME/
        #   collector/
        #       shell_bags.txt
        #       network_connections.txt
        #       processes.txt
        #       handles.txt
        #   file/
        #       C/
        #           Windows/
        #           Users/
        #           ...../
        #       D/
        file_path = path.joinpath("file")
        os_type, dirs = find_dirs(file_path)
        if file_path and os_type == OperatingSystem.WINDOWS:
            for path in dirs:
                # Tanium doesn't have the correct filenames for several files, like $J
                if path.joinpath("$Extend/$UsnJrnl_$J").exists():
                    return True

        return False

    def map(self, target: Target) -> None:
        find_and_map_dirs(
            target,
            self.absolute_path.joinpath("file"),
            sds_path="$Secure_$SDS",
            usnjrnl_path="$Extend/$UsnJrnl_$J",
        )
