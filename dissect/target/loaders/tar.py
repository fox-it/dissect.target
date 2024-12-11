from __future__ import annotations

import logging
import re
import tarfile
from pathlib import Path

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

    def __init__(self, path: Path | str, **kwargs):
        super().__init__(path)

        if isinstance(path, str):
            path = Path(path)

        if self.is_compressed(path):
            log.warning(
                f"Tar file {path!r} is compressed, which will affect performance. "
                "Consider uncompressing the archive before passing the tar file to Dissect."
            )

        self.tar = tarfile.open(fileobj=path.open("rb"))

    @staticmethod
    def detect(path: Path) -> bool:
        if not path.name.lower().endswith((".tar", ".tar.gz", ".tgz")):
            return False

        # Check that this is not an acquire collect, that is handled by AcquireLoader
        tar = tarfile.open(fileobj=path.open("rb"))
        acquire_members = [m for m in tar.getmembers() if m.name.startswith(("/fs/", "fs/", "/sysvol/", "sysvol/"))]

        return len(acquire_members) == 0

    def is_compressed(self, path: Path | str) -> bool:
        return str(path).lower().endswith((".tar.gz", ".tgz"))

    def map(self, target: target.Target) -> None:
        volumes = {}

        for member in self.tar.getmembers():
            if member.name == ".":
                continue

            if "/" not in volumes:
                vol = filesystem.VirtualFilesystem(case_sensitive=True)
                vol.tar = self.tar
                volumes["/"] = vol
                target.filesystems.add(vol)

            volume = volumes["/"]
            mname = member.name

            entry_cls = TarFilesystemDirectoryEntry if member.isdir() else TarFilesystemEntry
            entry = entry_cls(volume, fsutil.normpath(mname), member)
            volume.map_file_entry(entry.path, entry)

        for vol_name, vol in volumes.items():
            loaderutil.add_virtual_ntfs_filesystem(
                target,
                vol,
                usnjrnl_path=[
                    "$Extend/$Usnjrnl:$J",
                ],
            )

            target.fs.mount(vol_name, vol)
