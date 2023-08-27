from __future__ import annotations

import logging
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from dissect.target.loaders.dir import DirLoader, find_dirs, map_dirs
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    from dissect.target import Target

log = logging.getLogger(__name__)

FILESYSTEMS_ROOT = "uploads"
UNIX_ACCESSORS = ["file", "auto"]
WINDOWS_ACCESSORS = ["mft", "ntfs", "lazy_ntfs", "ntfs_vss", "auto"]


def find_fs_directories(path: Path) -> tuple[Optional[OperatingSystem], Optional[list[Path]]]:
    # As of Velociraptor version 0.7.0 the structure of the Velociraptor Offline Collector varies by operating system.
    # Generic.Collectors.File (Unix) uses the accessors file and auto.
    # Generic.Collectors.File (Windows) and Windows.KapeFiles.Targets (Windows) uses the accessors
    # mft, ntfs, lazy_ntfs, ntfs_vss and auto.

    fs_root = path.joinpath(FILESYSTEMS_ROOT)

    # Unix
    for accessor in UNIX_ACCESSORS:
        accessor_root = fs_root.joinpath(accessor)
        if accessor_root.exists():
            os_type, dirs = find_dirs(accessor_root)
            if os_type in [OperatingSystem.UNIX, OperatingSystem.LINUX, OperatingSystem.OSX]:
                return os_type, [dirs[0]]

    # Windows
    volumes = set()
    for accessor in WINDOWS_ACCESSORS:
        accessor_root = fs_root.joinpath(accessor)
        if accessor_root.exists():
            # If the accessor directory exists, assume all the subdirectories are volumes
            volumes.update(accessor_root.iterdir())

    if volumes:
        return OperatingSystem.WINDOWS, list(volumes)

    return None, None


class VelociraptorLoader(DirLoader):
    """Load Rapid7 Velociraptor forensic image files.

    References:
        - https://www.rapid7.com/products/velociraptor/
        - https://docs.velociraptor.app/
        - https://github.com/Velocidex/velociraptor
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path)

        if path.suffix == ".zip":
            log.warning(
                f"Velociraptor target {path!r} is compressed, which will slightly affect performance. "
                "Consider uncompressing the archive and passing the uncompressed folder to Dissect."
            )
            self.root = zipfile.Path(path)
        else:
            self.root = path

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
        if path.suffix == ".zip":  # novermin
            path = zipfile.Path(path)

        if path.joinpath(FILESYSTEMS_ROOT).exists() and path.joinpath("uploads.json").exists():
            _, dirs = find_fs_directories(path)
            return bool(dirs)

        return False

    def map(self, target: Target) -> None:
        os_type, dirs = find_fs_directories(self.root)
        if os_type == OperatingSystem.WINDOWS:
            # Velociraptor doesn't have the correct filenames for the paths "$J" and "$Secure:$SDS"
            map_dirs(
                target,
                dirs,
                os_type,
                usnjrnl_path="$Extend/$UsnJrnl%3A$J",
                sds_path="$Secure%3A$SDS",
            )
        else:
            map_dirs(target, dirs, os_type)
