from __future__ import annotations

import logging
import zipfile

from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

from dissect.target import filesystem, target
from dissect.target.loaders.dir import DirLoader, find_dirs, map_dirs
from dissect.target.filesystems.zip import (
    ZipFilesystemDirectoryEntry,
    ZipFilesystemEntry,
)
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.helpers import fsutil, loaderutil
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    from dissect.target import Target

log = logging.getLogger(__name__)

FILESYSTEMS_ROOT = "uploads"
UNIX_ACCESSORS = ["file", "auto"]
WINDOWS_ACCESSORS = ["mft", "ntfs", "lazy_ntfs", "ntfs_vss", "auto"]


def find_fs_directories(path: Path, is_zip: bool) -> tuple[Optional[OperatingSystem], Optional[list[Path]]]:
    # As of Velociraptor version 0.7.0 the structure of the Velociraptor Offline Collector varies by operating system.
    # Generic.Collectors.File (Unix) uses the accessors file and auto.
    # Generic.Collectors.File (Windows) and Windows.KapeFiles.Targets (Windows) uses the accessors
    # mft, ntfs, lazy_ntfs and ntfs_vss.

    fs_root = zipfile.Path(path, at=FILESYSTEMS_ROOT) if is_zip else path.joinpath(FILESYSTEMS_ROOT)

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

    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)

        self.is_zip = str(path).lower().endswith(".zip")

        if self.is_zip:
            log.warning(
                f"Zip file {path!r} is compressed, which will slightly affect performance. "
                "Consider uncompressing the archive before passing the unzipped folder to Dissect."
            )

            self.zip = zipfile.ZipFile(path)

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
        if (
            str(path).lower().endswith(".zip")
            and zipfile.Path(path, at="uploads/").exists()
            and zipfile.Path(path, at="uploads.json").exists()
        ):
            _, dirs = find_fs_directories(path, True)
            return bool(dirs)
        else:
            if path.joinpath(FILESYSTEMS_ROOT).exists() and path.joinpath("uploads.json").exists():
                _, dirs = find_fs_directories(path, False)
                return bool(dirs)
            return False

    def map(self, target: target.Target) -> None:
        os_type, dirs = find_fs_directories(self.path, self.is_zip)
        if os_type == OperatingSystem.WINDOWS:
            # Velociraptor doesn't have the correct filenames the paths $J and $Secure:$SDS".
            if not self.is_zip:
                # map_dirs(
                #     target,
                #     dirs,
                #     os_type,
                #     usnjrnl_path="$Extend/$UsnJrnl%3A$J",
                #     sds_path="$Secure%3A$SDS",
                # )
                for path in dirs:
                    dfs = DirectoryFilesystem(path, alt_separator="\\", case_sensitive=False)
                    target.filesystems.add(dfs)

                    if os_type == OperatingSystem.WINDOWS:
                        loaderutil.add_virtual_ntfs_filesystem(
                            target,
                            dfs,
                            os_type,
                            usnjrnl_path="$Extend/$UsnJrnl%3A$J",
                            sds_path="$Secure%3A$SDS",
                        )

                        volume_name = parts[2].strip("%3A")[-1].lower()

                        target.fs.mount(vol_name, vol)
                        if vol_name == "sysvol":
                            target.fs.mount("c:", vol)
            else:
                volumes = {}

                for zipinfo in self.zip.infolist():
                    filename = zipinfo.filename
                    if not any([filename.startswith(dir.at) for dir in dirs]):
                        continue

                    parts = filename.split("/")
                    volume_name = parts[2].strip("%3A")[-1].lower()
                    if volume_name == "c":
                        volume_name = "sysvol"

                    if volume_name not in volumes:
                        vol = filesystem.VirtualFilesystem(case_sensitive=False)
                        vol.zip = self.zip
                        volumes[volume_name] = vol
                        target.filesystems.add(vol)

                    volume = volumes[volume_name]
                    mname = "/".join(parts[3:])

                    entry_cls = ZipFilesystemDirectoryEntry if zipinfo.is_dir() else ZipFilesystemEntry
                    entry = entry_cls(volume, fsutil.normpath(mname), zipinfo)
                    volume.map_file_entry(entry.path, entry)

                for vol_name, vol in volumes.items():
                    loaderutil.add_virtual_ntfs_filesystem(
                        target,
                        vol,
                        usnjrnl_path="$Extend/$UsnJrnl%3A$J",
                        sds_path="$Secure%3A$SDS",
                    )

                    target.fs.mount(vol_name, vol)
                    if vol_name == "sysvol":
                        target.fs.mount("c:", vol)
        else:
            map_dirs(target, dirs, os_type)
