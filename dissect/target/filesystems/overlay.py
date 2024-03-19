from pathlib import Path
from typing import BinaryIO, Iterator

from dissect.target.exceptions import (
    FileNotFoundError,
    FilesystemError,
    IsADirectoryError,
    NotADirectoryError,
    NotASymlinkError,
)
from dissect.target.filesystem import Filesystem, FilesystemEntry, LayerFilesystem
from dissect.target.helpers import fsutil


class Overlay2Filesystem(LayerFilesystem):
    __type__ = "overlay2"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.mounts["/"] = []

    def mount(self, fs: Filesystem) -> None:
        """Mount a filesystem layer at the root path."""
        root = self.add_layer()
        root.map_fs("/", fs)
        self.mounts["/"].append(fs)


class Overlay2LayerFilesystem(Filesystem):
    """Based on DirectoryFilesystem."""

    __type__ = "overlay2"

    def __init__(self, path: Path, *args, **kwargs):
        super().__init__(None, *args, **kwargs)
        self.base_path = path

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.base_path}>"

    @staticmethod
    def _detect(fh: BinaryIO) -> bool:
        raise TypeError("Detect is not allowed on OverlayLayerFilesystem class")

    def get(self, path: str) -> FilesystemEntry:
        path = path.strip("/")

        if not path:
            return Overlay2LayerFilesystemEntry(self, "/", self.base_path)

        if not self.case_sensitive:
            searchpath = self.base_path

            for p in path.split("/"):
                match = [d for d in searchpath.iterdir() if d.name.lower() == p.lower()]

                if not match or len(match) > 1:
                    raise FileNotFoundError(path)

                searchpath = match[0]

            entry = searchpath
        else:
            entry = self.base_path.joinpath(path.strip("/"))

        try:
            entry.lstat()
            return Overlay2LayerFilesystemEntry(self, path, entry)
        except Exception:
            raise FileNotFoundError(path)


class Overlay2LayerFilesystemEntry(FilesystemEntry):
    """Based on DirectoryFilesystemEntry."""

    def get(self, path: str) -> FilesystemEntry:
        path = fsutil.join(self.path, path, alt_separator=self.fs.alt_separator)
        return self.fs.get(path)

    def open(self) -> BinaryIO:
        if self.is_dir():
            raise IsADirectoryError(self.path)
        return self._resolve().entry.open("rb")

    def iterdir(self) -> Iterator[str]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext().iterdir()
        else:
            for item in self.entry.iterdir():
                yield item.name

    def scandir(self) -> Iterator[FilesystemEntry]:
        if not self.is_dir():
            raise NotADirectoryError(self.path)

        if self.is_symlink():
            yield from self.readlink_ext().scandir()
        else:
            for item in self.entry.iterdir():
                path = fsutil.join(self.path, item.name, alt_separator=self.fs.alt_separator)
                yield Overlay2LayerFilesystemEntry(self.fs, path, item)

    def exists(self) -> bool:
        try:
            return self._resolve().entry.exists()
        except FilesystemError:
            return False

    def is_dir(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_dir()
        except FilesystemError:
            return False

    def is_file(self, follow_symlinks: bool = True) -> bool:
        try:
            return self._resolve(follow_symlinks=follow_symlinks).entry.is_file()
        except FilesystemError:
            return False

    def is_symlink(self) -> bool:
        return self.entry.is_symlink()

    def readlink(self) -> str:
        if not self.is_symlink():
            raise NotASymlinkError()
        return str(self.entry.readlink())

    def stat(self, follow_symlinks: bool = True) -> fsutil.stat_result:
        return self._resolve(follow_symlinks=follow_symlinks).entry.lstat()

    def lstat(self) -> fsutil.stat_result:
        return fsutil.stat_result.copy(self.entry.lstat())

    def attr(self) -> dict[str, bytes]:
        return fsutil.fs_attrs(self.entry, follow_symlinks=True)

    def lattr(self) -> dict[str, bytes]:
        return fsutil.fs_attrs(self.entry, follow_symlinks=False)
