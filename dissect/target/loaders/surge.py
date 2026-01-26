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
        """Map the data such as volumes and filesystems.

        For Windows, first iterate through first level children of the files/
        directory. These represent the volumes on the system, indicated by a
        driveletter, without the colon.

        For every iteration we build a DirectoryFileSystem of all the volume
        content. We create a VirtualFileSystem around it to allow us to add
        entries.

        When instructed to do so, Surge adds a sparse version of the UsnJrnl as
        a file. If such a file exists, we add the file to the VirtualFilesystem.
        We use a distinct name to make sure it does not interfere with the
        actual data.

        Other operating systems do not require such logic.
        """
        if self.os == OperatingSystem.WINDOWS:
            volumes = filter(lambda x: x.is_dir(), self.root.joinpath("files").iterdir())
            for volume in volumes:
                volume_name = volume.name.lower()

                dir_fs = DirectoryFilesystem(volume, alt_separator="\\", case_sensitive=False)
                virtual_fs = VirtualFilesystem(alt_separator="\\", case_sensitive=False)
                virtual_fs.map_fs("", dir_fs)

                target.filesystems.add(virtual_fs)
                target.fs.mount(volume_name + ":", virtual_fs)

                usnjrnl_path = self.root.joinpath("usn-journals", volume.name)
                if usnjrnl_path.is_file():
                    usnjrnl_name = fsutil.normpath(SURGE_USNJRNLJ)
                    usnjrnl_entry = DirectoryFilesystemEntry(dir_fs, usnjrnl_name, usnjrnl_path)
                    virtual_fs.map_file_entry(usnjrnl_name, usnjrnl_entry)

                    log.warning(
                        (
                            "Surge collection contains an extracted UsnJrnl for volume '%s'. "
                            "Note that it will take precedence over any $Extend/$UsnJrnl:$J."
                        ),
                        volume_name,
                    )

                loaderutil.add_virtual_ntfs_filesystem(
                    target,
                    virtual_fs,
                    usnjrnl_path=FILENAMES_USNJRNLJ,
                    sds_path=FILENAMES_SECURESDS,
                )
        else:
            dir_fs = DirectoryFilesystem(self.root.joinpath("files"))
            target.filesystems.add(dir_fs)
            target.fs.mount("", dir_fs)


class SurgeZipSubLoader(ZipSubLoader):
    """Loader for Surge forensic images, as a zip-file. The Surge root
    directory can be at the root level or in a subdirectory.

    A Surge package is very similar to a Kape / Velociraptor package. The
    'files' directory contains the disk data acquired using the Surge-collect.
    The 'api' directory contains parsed, interpreted and collected host info.

    See test_surge.py for directory tree examples for Linux, MacOS and Windows
    surge targets.

    The 'files' directory is not mandatory as it will not be created when only
    collecting memory.

    By default, a Surge package is a directory containing files. As an option,
    the complete directory with subdirectories can be zipped. The ziploader
    will load this SurgeZipSubLoader to handle these files.
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
        """Map the data such as volumes and filesystems.

        For Windows, first iterate through first level children of the files/
        directory. These represent the volumes on the system, indicated by a
        driveletter, without the colon.

        For every iteration we build a DirectoryFileSystem of all the volume
        content. We create a VirtualFileSystem around it to allow us to add
        entries.

        When instructed to do so, Surge adds a sparse version of the UsnJrnl as
        a file. If such a file exists, we add the file to the VirtualFilesystem.
        We use a distinct name to make sure it does not interfere with the
        actual data.

        Other operating systems do not require such logic.
        """
        if self.os == OperatingSystem.WINDOWS:
            volumes = filter(lambda x: x.is_dir(), self.root.joinpath("files").iterdir())
            for volume in volumes:
                volume_name = volume.name.lower()

                zip_fs = ZipFilesystem(self.zip.fp, str(volume), alt_separator="\\", case_sensitive=False)

                target.filesystems.add(zip_fs)
                target.fs.mount(volume_name + ":", zip_fs)

                usnjrnl_path = self.root.joinpath("usn-journals", volume.name)
                if usnjrnl_path.is_file():
                    usnjrnl_name = fsutil.normpath(SURGE_USNJRNLJ)
                    usnjrnl_entry = ZipFilesystemEntry(zip_fs, usnjrnl_name, self.zip.getinfo(str(usnjrnl_path)))
                    # Map entry to the virtualfilesystem under the ZipFilesystem
                    zip_fs._fs.map_file_entry(usnjrnl_name, usnjrnl_entry)

                    log.warning(
                        (
                            "Surge collection contains an extracted UsnJrnl for volume '%s'. "
                            "Note that it will take precedence over any $Extend/$UsnJrnl:$J."
                        ),
                        volume_name,
                    )

                loaderutil.add_virtual_ntfs_filesystem(
                    target,
                    zip_fs,
                    usnjrnl_path=FILENAMES_USNJRNLJ,
                    sds_path=FILENAMES_SECURESDS,
                )
        else:
            zip_fs = ZipFilesystem(self.zip.fp, str(self.root.joinpath("files")), alt_separator="", case_sensitive=True)

            target.filesystems.add(zip_fs)
            target.fs.mount("", zip_fs)
