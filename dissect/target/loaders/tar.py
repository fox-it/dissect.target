import stat
import tarfile
import logging
from typing import Union
from pathlib import Path

from dissect.util.stream import BufferedStream

from dissect.target import filesystem, target
from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers import fsutil, loaderutil
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
                    volumes["/"] = vol
                    target.filesystems.add(vol)

                volume = volumes["/"]
                entry = TarFile(vol, member.name, member.name, self.tar)
            else:
                if not member.name.startswith("/sysvol"):
                    parts = member.name.replace("fs/", "").split("/")
                else:
                    parts = member.name.lstrip("/").split("/")
                volume_name = parts[0]

                if volume_name == "c:":
                    volume_name = "sysvol"

                if volume_name not in volumes:
                    vol = filesystem.VirtualFilesystem(case_sensitive=False)
                    volumes[volume_name] = vol
                    target.filesystems.add(vol)

                volume = volumes[volume_name]

                entry = TarFile(volume, "/".join(parts[1:]), member.name, self.tar)
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


class TarFile(filesystem.VirtualFile):
    def __init__(self, fs, path, tar_path, tar_file):
        super().__init__(fs, path, tar_path)
        self.tar = tar_file

    def open(self):
        try:
            f = self.tar.extractfile(self.entry)
            if hasattr(f, "raw"):
                f.size = f.raw.size
            return BufferedStream(f, size=f.size)
        except Exception:
            raise FileNotFoundError()

    def stat(self):
        info = self.tar.getmember(self.entry)
        mode = (stat.S_IFDIR if info.isdir() else stat.S_IFREG) | info.mode
        # mode, ino, dev, nlink, uid, gid, size, atime, mtime, ctime
        return fsutil.stat_result(
            [
                mode,
                info.offset,
                id(self.fs),
                0,
                info.uid,
                info.gid,
                info.size,
                0,
                info.mtime,
                0,
            ]
        )
