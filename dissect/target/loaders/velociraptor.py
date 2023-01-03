from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Optional

from dissect.target.loaders.dir import DirLoader, find_dirs, map_dirs

if TYPE_CHECKING:
    from dissect.target import Target

FILESYSTEMS_ROOT = "uploads"


def find_os_directory(path: Path) -> Optional[Path]:
    # As of Velociraptor version 0.6.7 the structure of the Velociraptor Offline Collector varies by operating system
    # Generic.Collectors.File (Unix, OS-X) root filesystem is 'uploads/'
    # Generic.Collectors.File (Windows) and Windows.KapeFiles.Targets (Windows) root filesystem is
    # 'uploads/<file-accessor>/<drive-name>/'
    fs_root = path.joinpath(FILESYSTEMS_ROOT)
    os_type, dirs = find_dirs(fs_root)
    if os_type in ["linux", "osx"]:
        return dirs[0]
    # This suppports usage of the ntfs accessor 'uploads/mft/%5C%5C.%5CC%3A' not the accessors lazy_ntfs or auto
    mft_root = fs_root.joinpath("mft")
    if not os_type and mft_root.exists():
        # Filter out files that start with '.'
        windows_path = [p for p in mft_root.iterdir() if not p.name.startswith(".")][0]
        os_type, dirs = find_dirs(windows_path)
        if os_type == "windows":
            return dirs[0]
    return None


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
            return bool(find_os_directory(path))
        return False

    def map(self, target: Target) -> None:
        map_dirs(
            target,
            find_os_directory(self.path),
        )
