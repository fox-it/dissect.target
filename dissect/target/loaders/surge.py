from __future__ import annotations

import json
import logging
import zipfile
from functools import partial
from typing import TYPE_CHECKING

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.filesystems.dir import DirectoryFilesystem, DirectoryFilesystemEntry
from dissect.target.filesystems.zip import ZipFilesystem, ZipFilesystemEntry
from dissect.target.helpers import fsutil, loaderutil
from dissect.target.loader import Loader
from dissect.target.plugin import OperatingSystem

if TYPE_CHECKING:
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


class SurgeLoader(Loader):
    """
    Load Surge forensic images, either as directory or zip.
    The Surge root directory can be at the root level or in a subdirectory.

    A Surge package is very similar to a Kape / Velociraptor package. The
    'files' directory contains the disk data acquired using the Surge-collect.
    The 'api' directory contains parsed, interpreted and collected host info.

    See test_surge.py for directory tree examples for Linux, MacOS and Windows surge targets.

    The 'files' directory is not mandatory as it will not be created when only collecting
    memory.

    By default, a Surge package is a directory containing files. As an option,
    the complete directory with subdirectories can be zipped. Both options are
    accepted in this loader.
    """

    @staticmethod
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

    @staticmethod
    def contains_all_required_files(path: Path) -> bool:
        """Check whether all required files are present."""
        return all((path / file_name).is_file() for file_name in REQUIRED_FILES)

    @staticmethod
    def contains_all_required_directories(path: Path, operating_system: OperatingSystem) -> bool:
        """Check whether all required directories are present."""
        return all((path / dir_name).is_dir() for dir_name in LOOKUP_REQUIRED_DIRECTORIES[operating_system])

    @staticmethod
    def find_surge_root(path: Path) -> Path | None:
        """Find the Surge root (dir with all required files) from a given path.
        For files created on S3, this is the root of path.
        For files created locally, the Surge root is a subdirectory.
        """
        if SurgeLoader.contains_all_required_files(path=path):
            return path

        try:
            for subdir in path.iterdir():
                if subdir.is_dir() and SurgeLoader.contains_all_required_files(path=subdir):
                    return subdir
        except Exception:
            return None

        return None

    @staticmethod
    def detect(path: Path) -> bool:
      """Detect whether a Surge image is provided."""
        if not path.exists():
            return False

        if path.suffix.lower().endswith(".zip") and zipfile.is_zipfile(filename=path):
            fs = ZipFilesystem(fh=path.open(mode="rb"))
            path = fs.path()
        elif not path.is_dir():
            return False

        surge_root = SurgeLoader.find_surge_root(path=path)
        if surge_root is None:
            return False

        operating_system = SurgeLoader.get_os_from_meta(path=surge_root)
        if operating_system is None:
            return False

        return SurgeLoader.contains_all_required_directories(surge_root, operating_system)

    def __init__(self, path: Path, **kwargs):
        super().__init__(path, **kwargs)

        if path.suffix.lower().endswith(".zip") and zipfile.is_zipfile(path):
            self.fs = ZipFilesystem(path.open(mode="rb"))
            self.path = self.fs.path()
            self.fse_type = ZipFilesystemEntry
        elif path.is_dir():
            self.path = path
            self.fse_type = DirectoryFilesystemEntry

        self.root = SurgeLoader.find_surge_root(self.path)
        self.os = SurgeLoader.get_os_from_meta(self.root)
        if self.os == OperatingSystem.WINDOWS:
            self.alt_separator = "\\"
            self.case_sensitive = False
        else:
            self.alt_separator = ""
            self.case_sensitive = True

        if self.fse_type == ZipFilesystemEntry:
            fs_type = partial(
                ZipFilesystem, self.fs.zip.fp, alt_separator=self.alt_separator, case_sensitive=self.case_sensitive
            )
            self.create_fs = lambda volume: fs_type(str(volume))
            self.get_usnjrnl_entry = lambda usnjrnl: self.fs.zip.getinfo(str(usnjrnl))
        elif self.fse_type == DirectoryFilesystemEntry:
            fs_type = partial(DirectoryFilesystem, alt_separator=self.alt_separator, case_sensitive=self.case_sensitive)
            self.create_fs = lambda volume: fs_type(volume)
            self.get_usnjrnl_entry = lambda usnjrnl: usnjrnl

    def map(self, target: Target) -> None:
        """Map the data such as volumes and filesystems.
        
        For Windows, first iterate through first level children of the files/ directory.
        These represent the volumes on the system, indicated by a driveletter, without the colon.
        
        For every iteration we build a filesystem of all the volume content, and set a
        classtype for a FilesystemEntry of the appropriate filesystem type.

        Not all filesystems allow us to add a FilesystemEntry, so create a
        VirtualFileSystem around it which would allow adding entries.

        If the usnjrnl exists, then create an actual FilesystemEntry of the appropriate 
        class and add it to file VirtualFilesystem. Use a distinct name to make sure it
        does not interfere with the actual data.

        Other operating systems do not require such logic.
        """
        if self.os == OperatingSystem.WINDOWS:
            volumes = filter(lambda x: x.is_dir(), self.path.joinpath(self.root, "files").iterdir())
            for volume in volumes:
                volume_name = volume.name.lower()

                sub_fs = self.create_fs(volume)

                virtual_fs = VirtualFilesystem(case_sensitive=self.case_sensitive, alt_separator=self.alt_separator)
                virtual_fs.map_fs("", sub_fs)

                target.filesystems.add(virtual_fs)
                target.fs.mount(volume_name + ":", virtual_fs)
                usnjrnl = self.path.joinpath(self.root, "usn-journals", volume.name)
                if usnjrnl.is_file():
                    usn_name = fsutil.normpath(SURGE_USNJRNLJ)
                    usnjrnl_entry = self.get_usnjrnl_entry(usnjrnl)
                    fse = self.fse_type(sub_fs, usn_name, usnjrnl_entry)
                    virtual_fs.map_file_entry(usn_name, fse)
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
            sub_fs = self.create_fs(self.root.joinpath("files"))
            target.filesystems.add(sub_fs)
            target.fs.mount("", sub_fs)
