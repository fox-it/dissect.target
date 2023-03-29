from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Optional

from dissect.target.loaders.dir import DirLoader, find_dirs, map_dirs
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    from dissect.target import Target

FILESYSTEMS_ROOT = "uploads"


def find_fs_directories(path: Path) -> tuple[Optional[OperatingSystem], Optional[list[Path]]]:
    # As of Velociraptor version 0.6.7 the structure of the Velociraptor Offline Collector varies by operating system
    # Generic.Collectors.File (Linux and OS-X) root filesystem is 'uploads/file/'
    # Generic.Collectors.File (Windows) and Windows.KapeFiles.Targets (Windows) root filesystem is
    # 'uploads/<file-accessor>/<drive-name>/'
    fs_root = path.joinpath(FILESYSTEMS_ROOT)

    # Linux and OS-X
    file_root = fs_root.joinpath("file")
    if file_root.exists():
        os_type, dirs = find_dirs(file_root)
        if os_type in [OperatingSystem.LINUX, OperatingSystem.OSX]:
            return os_type, [dirs[0]]

    # This suppports usage of the ntfs accessor 'uploads/mft/%5C%5C.%5CC%3A' not the accessors lazy_ntfs or auto
    mft_root = fs_root.joinpath("mft")
    if mft_root.exists():
        # If the `mft` directory exists, assume all the subdirectories are volumes
        return OperatingSystem.WINDOWS, list(mft_root.iterdir())

    return None, None


class VelociraptorLoader(DirLoader):
    @staticmethod
    def detect(path: Path) -> bool:
        # The 'uploads' folder contains the data acquired
        # The 'results' folder contains information about the used Velociraptor artifacts e.g. Generic.Collectors.File
        # The 'uploads.json' file contains information about the collected files
        # Collection-HOSTNAME-TIMESTAMP/
        #   uploads/
        #   results/
        #   uploads.json
        #   [...] other files related to the collection
        if path.joinpath(FILESYSTEMS_ROOT).exists() and path.joinpath("uploads.json").exists():
            _, dirs = find_fs_directories(path)
            return bool(dirs)
        return False

    def map(self, target: Target) -> None:
        os_type, dirs = find_fs_directories(self.path)
        if os_type == OperatingSystem.WINDOWS:
            # Velociraptor doesn't have the correct filenames for several files, like $J
            map_dirs(
                target,
                dirs,
                os_type,
                usnjrnl_path="$Extend/$UsnJrnl%3A$J",
            )
        else:
            map_dirs(target, dirs, os_type)
