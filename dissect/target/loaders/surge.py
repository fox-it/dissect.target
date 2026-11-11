from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem, DirectoryFilesystemEntry
from dissect.target.filesystems.zip import ZipFilesystem, ZipFilesystemEntry
from dissect.target.helpers import fsutil, loaderutil
from dissect.target.loader import Loader
from dissect.target.loaders.zip import ZipSubLoader
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
    import zipfile
    from pathlib import Path

    from dissect.target import Target
    from dissect.target.filesystem import Filesystem

log = logging.getLogger(__name__)

META_FILE_PATH = "meta.json"
REQUIRED_FILES = [META_FILE_PATH, "log.txt"]
LOOKUP_OS = {
    "linux": OperatingSystem.LINUX,
    "darwin": OperatingSystem.OSX,
    "windows": OperatingSystem.WINDOWS,
}
LOOKUP_REQUIRED_DIRECTORIES = {
    OperatingSystem.LINUX: ["files/proc"],
    OperatingSystem.OSX: ["api/darwin"],
    OperatingSystem.WINDOWS: ["api/windows"],
}
SURGE_USNJRNLJ = "__$UsnJrnl$J"
FILENAMES_USNJRNLJ = [SURGE_USNJRNLJ, "$Extend/$UsnJrnl$J"]
FILENAMES_SECURESDS = ["$Secure$SDS"]


def get_os_from_meta(path: Path) -> OperatingSystem | None:
    """Get the operating system from the mandatory meta.json file."""
    with (path / META_FILE_PATH).open() as file:
        meta_data = json.load(file)
        os_name = meta_data["platform"]["os"]
        if os_name is None:
            return None

    os = None
    if os_name.lower() in LOOKUP_OS:
        os = LOOKUP_OS[os_name.lower()]

    return os


def contains_all_required_files(path: Path) -> bool:
    """Check whether all required files are present."""
    return all((path / file_name).is_file() for file_name in REQUIRED_FILES)


def contains_all_required_directories(path: Path, operating_system: OperatingSystem) -> bool:
    """Check whether all required directories are present."""
    return all((path / dir_name).is_dir() for dir_name in LOOKUP_REQUIRED_DIRECTORIES[operating_system])


def find_surge_root(path: Path) -> Path | None:
    """Find the Surge root (dir with all required files) from a given path.
    For files created on S3, this is the root of path.
    For files created locally, the Surge root is a subdirectory.
    """
    if contains_all_required_files(path=path):
        return path

    try:
        for subdir in path.iterdir():
            if subdir.is_dir() and contains_all_required_files(path=subdir):
                return subdir
    except Exception:
        return None

    return None


def map_surge(loader: SurgeLoader, target: Target, fs_factory: tuple[Filesystem, Filesystem], is_zip: bool) -> None:
    """Shared mapping logic for both Directory and Zip loaders."""
    files_root = loader.root.joinpath("files")

    if loader.os == OperatingSystem.WINDOWS:
        # 1. Iterate through volumes (e.g., 'c', 'd')
        for volume in filter(lambda x: x.is_dir(), files_root.iterdir()):
            vol_name = volume.name.lower()

            # Create the specific FS (and get a reference for manual entry mapping)
            main_fs, entry_fs = fs_factory(volume)

            target.filesystems.add(main_fs)
            target.fs.mount(f"{vol_name}:", main_fs)

            # 2. Handle extracted UsnJrnl if present
            usnjrnl_path = loader.root.joinpath("usn-journals", volume.name)
            if usnjrnl_path.is_file():
                norm_name = fsutil.normpath(SURGE_USNJRNLJ)

                if is_zip:
                    # Zip specific entry creation
                    entry = ZipFilesystemEntry(entry_fs, norm_name, loader.zip.getinfo(str(usnjrnl_path)))
                    entry_fs._fs.map_file_entry(norm_name, entry)
                else:
                    # Directory specific entry creation
                    entry = DirectoryFilesystemEntry(entry_fs, norm_name, usnjrnl_path)
                    main_fs.map_file_entry(norm_name, entry)

                log.warning("Surge: Using extracted UsnJrnl for volume '%s'.", vol_name)

            # 3. Apply NTFS virtual filesystem helpers
            loaderutil.add_virtual_ntfs_filesystem(
                target, main_fs, usnjrnl_path=FILENAMES_USNJRNLJ, sds_path=FILENAMES_SECURESDS
            )
    else:
        # Non-Windows logic (flat mount)
        fs, _ = fs_factory(files_root)
        target.filesystems.add(fs)
        target.fs.mount("", fs)


class SurgeLoader(Loader):
    """Loader for Surge forensic images, as directory. The Surge root directory
    can be at the root level or in a subdirectory.

    A Surge package is very similar to a Kape / Velociraptor package. The
    'files' directory contains the disk data acquired using the Surge-collect.
    The 'api' directory contains parsed, interpreted and collected host info.

    See test_surge.py for directory tree examples for Linux, MacOS and Windows
    surge targets.

    The 'files' directory is not mandatory as it will not be created when only
    collecting memory.

    By default, a Surge package is a directory containing files. As an option,
    the complete directory with subdirectories can be zipped. For this purpose,
    a SurgeZipSubLoader (also in this file) is available.
    """

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)

        self.root = find_surge_root(path)
        self.os = get_os_from_meta(self.root)

    @staticmethod
    def detect(path: Path) -> bool:
        """Detect whether a Surge image is provided."""
        if not path.exists():
            return False

        if not path.is_dir():
            return False

        surge_root = find_surge_root(path=path)
        if surge_root is None:
            return False

        operating_system = get_os_from_meta(path=surge_root)
        if operating_system is None:
            return False

        return contains_all_required_directories(surge_root, operating_system)

    def map(self, target: Target) -> None:
        """Map the Surge directory-based forensic image to the target."""

        def fs_factory(volume_path: str) -> tuple[VirtualFilesystem, DirectoryFilesystem]:
            # For directories, we wrap in VirtualFilesystem to allow manual file mapping (UsnJrnl)
            dir_fs = DirectoryFilesystem(volume_path, alt_separator="\\", case_sensitive=False)
            vfs = VirtualFilesystem(alt_separator="\\", case_sensitive=False)
            vfs.map_fs("", dir_fs)
            return vfs, dir_fs

        map_surge(self, target, fs_factory, is_zip=False)


class SurgeZipSubLoader(ZipSubLoader):
    """Loader for Surge forensic images, as a zip-file. The Surge root
    directory can be at the root level or in a subdirectory.
    """

    def __init__(self, path: Path, zipfile: zipfile.Path, **kwargs):
        super().__init__(path, zipfile, **kwargs)

        fs = ZipFilesystem(zipfile.root.fp)
        self.zip = fs.zip
        self.root = find_surge_root(fs.path())
        self.os = get_os_from_meta(self.root)

    @staticmethod
    def detect(path: Path, zip_path: zipfile.Path) -> bool:
        """Detect whether a Surge image is provided."""
        if not path.exists():
            return False

        surge_root = find_surge_root(path=zip_path)
        if surge_root is None:
            return False

        operating_system = get_os_from_meta(path=surge_root)
        if operating_system is None:
            return False

        return contains_all_required_directories(surge_root, operating_system)

    def map(self, target: Target) -> None:
        """Map the Surge ZIP-based forensic image to the target."""

        def fs_factory(volume_path: str) -> tuple[ZipFilesystem, ZipFilesystem]:
            # ZipFilesystem already contains an internal VirtualFilesystem (_fs)
            zip_fs = ZipFilesystem(self.zip.fp, str(volume_path), alt_separator="\\", case_sensitive=False)
            return zip_fs, zip_fs

        map_surge(self, target, fs_factory, is_zip=True)
