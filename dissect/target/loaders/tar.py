import logging
import tarfile
from pathlib import Path
from typing import Union

from dissect.target import filesystem, target
from dissect.target.filesystems.tar import TarFilesystemEntry
from dissect.target.helpers import loaderutil
from dissect.target.loader import Loader

log = logging.getLogger(__name__)


class TarLoader(Loader):
    def __init__(self, path: Union[Path, str], **kwargs):
        super().__init__(path)

        if self.is_compressed(path):
            log.warning(
                f"Tar file {path!r} is compressed, which will affect performance. "
                "Consider uncompressing the archive before passing the tar file to Dissect."
            )

        self.tar = tarfile.open(path)

    @staticmethod
    def detect(path: Path):
        return path.name.lower().endswith((".tar", ".tar.gz"))

    def is_compressed(self, path: Union[Path, str]) -> bool:
        return str(path).lower().endswith(".tar.gz")

    def map(self, target: target.Target):
        volumes = {}

        for member in self.tar.getmembers():
            if member.isdir():
                continue

            if not member.name.startswith("fs/") and not member.name.startswith("/sysvol"):
                if "/" not in volumes:
                    vol = filesystem.VirtualFilesystem(case_sensitive=True)
                    vol.tar = self.tar
                    volumes["/"] = vol
                    target.filesystems.add(vol)

                volume = volumes["/"]
                entry = TarFilesystemEntry(volume, member.name, member)
            else:
                if not member.name.startswith("/sysvol"):
                    parts = member.name.replace("fs/", "").split("/")
                else:
                    parts = member.name.lstrip("/").split("/")
                volume_name = parts[0]

                if volume_name.lower() == "c:":
                    volume_name = "sysvol"

                if volume_name not in volumes:
                    vol = filesystem.VirtualFilesystem(case_sensitive=False)
                    vol.tar = self.tar
                    volumes[volume_name] = vol
                    target.filesystems.add(vol)

                volume = volumes[volume_name]

                entry = TarFilesystemEntry(volume, "/".join(parts[1:]), member)
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
            if vol_name == "sysvol":
                target.fs.mount("c:", vol)
