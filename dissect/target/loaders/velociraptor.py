from __future__ import annotations

import logging
import zipfile
from typing import TYPE_CHECKING
from urllib.parse import quote, unquote

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem
from dissect.target.filesystems.zip import ZipFilesystem
from dissect.target.helpers.fsutil import basename, dirname, join
from dissect.target.loaders.dir import DirLoader, find_dirs, map_dirs
from dissect.target.plugin import OperatingSystem
from dissect.target.plugins.apps.edr.velociraptor import VELOCIRAPTOR_RESULTS

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target

log = logging.getLogger(__name__)

FILESYSTEMS_ROOT = "uploads"
UNIX_ACCESSORS = ["file", "auto"]
WINDOWS_ACCESSORS = ["mft", "ntfs", "lazy_ntfs", "ntfs_vss", "auto"]


def find_fs_directories(path: Path) -> tuple[OperatingSystem | None, list[Path] | None]:
    fs_root = path.joinpath(FILESYSTEMS_ROOT)

    # Unix
    for accessor in UNIX_ACCESSORS:
        accessor_root = fs_root.joinpath(accessor)
        if accessor_root.exists():
            os_type, dirs = find_dirs(accessor_root)
            if os_type in [
                OperatingSystem.UNIX,
                OperatingSystem.LINUX,
                OperatingSystem.OSX,
            ]:
                return os_type, [dirs[0]]

    # Windows
    volumes = set()
    vss_volumes = set()
    for accessor in WINDOWS_ACCESSORS:
        accessor_root = fs_root.joinpath(accessor)
        if accessor_root.exists():
            # If the accessor directory exists, assume all the subdirectories are volumes
            for volume in accessor_root.iterdir():
                if not volume.is_dir():
                    continue

                # https://github.com/Velocidex/velociraptor/blob/87368e7cc678144592a1614bb3bbd0a0f900ded9/accessors/ntfs/vss.go#L82
                if "HarddiskVolumeShadowCopy" in volume.name:
                    vss_volumes.add(volume)
                elif (drive_letter := extract_drive_letter(volume.name)) is not None:
                    volumes.add((drive_letter, volume))
                else:
                    volumes.add(volume)

    if volumes:
        # The volumes that represent drives (C, D) are mounted first,
        # otherwise one of the volume shadow copies could be detected as the root filesystem which results in errors.
        return OperatingSystem.WINDOWS, list(volumes) + list(vss_volumes)

    return None, None


def extract_drive_letter(name: str) -> str | None:
    # \\.\X: in URL encoding
    if len(name) == 14 and name.startswith("%5C%5C.%5C") and name.endswith("%3A"):
        return name[10].lower()

    # X: in URL encoding
    if len(name) == 4 and name.endswith("%3A"):
        return name[0].lower()
    return None


class VelociraptorLoader(DirLoader):
    """Load Rapid7 Velociraptor forensic image files.

    As of Velociraptor version 0.7.0 the structure of the Velociraptor Offline Collector varies by operating system.
    Generic.Collectors.File (Unix) uses the accessors file and auto. The loader supports the following configuration::

        {"Generic.Collectors.File": {"Root": "/", "collectionSpec": "Glob\\netc/**\\nvar/log/**"}}

    Generic.Collectors.File (Windows) and Windows.KapeFiles.Targets (Windows) uses the accessors mft, ntfs, lazy_ntfs,
    ntfs_vss and auto. The loader supports a collection where multiple accessors were used.

    References:
        - https://www.rapid7.com/products/velociraptor/
        - https://docs.velociraptor.app/
        - https://github.com/Velocidex/velociraptor
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)

        if path.suffix == ".zip":
            self.root = zipfile.Path(path.open("rb"))
            if self.root.root.getinfo("uploads.json").compress_type > 0:
                log.warning(
                    "Velociraptor target '%s' is compressed, which will slightly affect performance. "
                    "Consider uncompressing the archive and passing the uncompressed folder to Dissect.",
                    path,
                )
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
        if path.exists() and path.suffix == ".zip":  # novermin
            path = zipfile.Path(path.open("rb"))

        if path.joinpath(FILESYSTEMS_ROOT).exists() and path.joinpath("uploads.json").exists():
            _, dirs = find_fs_directories(path)
            return bool(dirs)

        return False

    def map(self, target: Target) -> None:
        os_type, dirs = find_fs_directories(self.root)

        # Velociraptor URL encodes paths before storing these in a collection, this leads plugins not being able to find
        # these paths. To circumvent this issue, for a zip file the path names are URL decoded before mapping into the
        # VFS and for a directory the paths are URL encoded at lookup time.
        map_dirs(
            target,
            dirs,
            os_type,
            dirfs=VelociraptorDirectoryFilesystem,
            zipfs=VelociraptorZipFilesystem,
        )

        if (results := self.root.joinpath("results")).is_dir():
            # Map artifact results collected by Velociraptor
            vfs = VirtualFilesystem()

            for artifact in results.iterdir():
                if not artifact.name.endswith(".json"):
                    continue

                vfs.map_file_fh(artifact.name, artifact.open("rb"))

            if (uploads := self.root.joinpath("uploads.json")).exists():
                vfs.map_file_fh(uploads.name, uploads.open("rb"))

            target.fs.mount(VELOCIRAPTOR_RESULTS, vfs)


class VelociraptorDirectoryFilesystem(DirectoryFilesystem):
    def _resolve_path(self, path: str) -> Path:
        path = quote(path, safe="$/% ")
        if (fname := basename(path)).startswith("."):
            path = join(dirname(path), fname.replace(".", "%2E", 1))

        return super()._resolve_path(path)


class VelociraptorZipFilesystem(ZipFilesystem):
    def _resolve_path(self, path: str) -> str:
        return unquote(super()._resolve_path(path))
