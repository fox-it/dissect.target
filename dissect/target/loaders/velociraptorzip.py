import logging
import zipfile
from pathlib import Path
from typing import Union

from dissect.target import filesystem, target
from dissect.target.filesystems.zip import (
    ZipFilesystemDirectoryEntry,
    ZipFilesystemEntry,
)
from dissect.target.helpers import fsutil, loaderutil
from dissect.target.loader import Loader

log = logging.getLogger(__name__)


class VelociraptorZipLoader(Loader):
    """Load zip files."""

    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)

        self.zip = zipfile.ZipFile(path)

    @staticmethod
    def detect(path: Path) -> bool:
        return (
            path.name.lower().endswith(".zip")
            and zipfile.Path(path, at="uploads.json").exists()
            and zipfile.Path(path, at="uploads/").exists()
        )

    def map(self, target: target.Target) -> None:
        volumes = {}

        for member in self.zip.infolist():
            # Process Windows targets for Velociraptor
            # Generic.Collectors.File (Windows) and Windows.KapeFiles.Targets (Windows) root filesystem is
            # 'uploads/<file-accessor>/<drive-name>/'
            if not member.filename.startswith("uploads/"):
                continue

            # Supported prefixes with their sysvol drive letter
            supported_prefixes = {
                "uploads/auto/": "C%3A/",
                "uploads/ntfs/": "%5C%5C.%5CC%3A/",
                "uploads/lazy_ntfs": "%5C%5C.%5CC%3A/",
                "uploads/mft/": "%5C%5C.%5CC%3A/",
            }

            parts = None

            for prefix, sysvol in supported_prefixes.items():
                if member.filename.startswith(prefix):
                    if member.filename == prefix:
                        continue
                    elif member.filename.startswith(f"{prefix}{sysvol}"):
                        parts = member.filename.replace(f"{prefix}{sysvol}", "sysvol/").split("/")
                    else:
                        parts = member.filename.replace(prefix, "/").split("/")

            if not parts:
                continue

            volume_name = parts[0]

            if volume_name not in volumes:
                vol = filesystem.VirtualFilesystem(case_sensitive=False)
                vol.zip = self.zip
                volumes[volume_name] = vol
                target.filesystems.add(vol)

            volume = volumes[volume_name]
            mname = "/".join(parts[1:])

            entry_cls = ZipFilesystemDirectoryEntry if member.is_dir() else ZipFilesystemEntry
            entry = entry_cls(volume, fsutil.normpath(mname), member)
            volume.map_file_entry(entry.path, entry)

        for vol_name, vol in volumes.items():
            loaderutil.add_virtual_ntfs_filesystem(
                target,
                vol,
                usnjrnl_path="$Extend/$UsnJrnl%3A$J",
            )

            target.fs.mount(vol_name, vol)
            if vol_name == "sysvol":
                target.fs.mount("c:", vol)
