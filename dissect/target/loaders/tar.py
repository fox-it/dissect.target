import logging
import re
import tarfile
from pathlib import Path
from typing import Union

from dissect.target import filesystem, target
from dissect.target.filesystems.tar import (
    TarFilesystemDirectoryEntry,
    TarFilesystemEntry,
)
from dissect.target.helpers import fsutil, loaderutil
from dissect.target.loader import Loader

log = logging.getLogger(__name__)


ANON_FS_RE = re.compile(r"^fs[0-9]+$")


class TarLoader(Loader):
    """Load tar files."""

    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)

        if self.is_compressed(path):
            log.warning(
                f"Tar file {path!r} is compressed, which will affect performance. "
                "Consider uncompressing the archive before passing the tar file to Dissect."
            )

        self.tar = tarfile.open(path)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.name.lower().endswith((".tar", ".tar.gz", ".tgz"))

    def is_compressed(self, path: Union[Path, str]) -> bool:
        return str(path).lower().endswith((".tar.gz", ".tgz"))

    def map(self, target: target.Target) -> None:
        volumes = {}

        for member in self.tar.getmembers():
            if member.name == ".":
                continue

            if not member.name.startswith(("/fs/", "fs/", "/sysvol/", "sysvol/")):
                # Not an acquire tar
                if "/" not in volumes:
                    vol = filesystem.VirtualFilesystem(case_sensitive=True)
                    vol.tar = self.tar
                    volumes["/"] = vol
                    target.filesystems.add(vol)

                volume = volumes["/"]
                mname = member.name
            else:
                if member.name.startswith(("/fs/", "fs/")):
                    # Current acquire
                    parts = member.name.replace("fs/", "").split("/")
                    if parts[0] == "":
                        parts.pop(0)
                else:
                    # Legacy acquire
                    parts = member.name.lstrip("/").split("/")
                volume_name = parts[0].lower()

                # NOTE: older versions of acquire would write to "sysvol" instead of a driver letter
                # Figuring out the sysvol from the drive letters is easier than the drive letter from "sysvol",
                # so this was swapped in acquire 3.12. Now we map all volumes to a drive letter and let the
                # Windows OS plugin figure out which is the sysvol
                # For backwards compatibility we're forced to keep this check, and assume that "c:" is our sysvol
                if volume_name == "sysvol":
                    volume_name = "c:"

                if volume_name == "$fs$":
                    if len(parts) == 1:
                        # The fs/$fs$ entry is ignored, only the directories below it are processed.
                        continue
                    fs_name = parts[1]
                    if ANON_FS_RE.match(fs_name):
                        parts.pop(0)
                        volume_name = f"{volume_name}/{fs_name}"

                if volume_name not in volumes:
                    vol = filesystem.VirtualFilesystem(case_sensitive=False)
                    vol.tar = self.tar
                    volumes[volume_name] = vol
                    target.filesystems.add(vol)

                volume = volumes[volume_name]
                mname = "/".join(parts[1:])

            entry_cls = TarFilesystemDirectoryEntry if member.isdir() else TarFilesystemEntry
            entry = entry_cls(volume, fsutil.normpath(mname), member)
            volume.map_file_entry(entry.path, entry)

        for vol_name, vol in volumes.items():
            loaderutil.add_virtual_ntfs_filesystem(
                target,
                vol,
                usnjrnl_path=[
                    "$Extend/$Usnjrnl:$J",
                    "$Extend/$Usnjrnl:J",  # Old versions of acquire used $Usnjrnl:J
                ],
            )

            target.fs.mount(vol_name, vol)
