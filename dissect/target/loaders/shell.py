from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import ParseResult, parse_qsl

from dissect.target.exceptions import LoaderError
from dissect.target.loader import Loader, find_loader
from dissect.target.loaders.dir import DirLoader
from dissect.target.loaders.local import map_esxi_drives, map_linux_drives, map_solaris_drives
from dissect.target.loaders.raw import RawLoader
from dissect.target.plugin import os_plugins

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import Filesystem
    from dissect.target.target import Target


class ShellLoader(Loader):
    """Base class for loaders that utilize :class:`ShellFilesystem` or subclasses of it."""

    def __init__(self, path: Path, parsed_path: ParseResult | None = None):
        super().__init__(path, parsed_path=parsed_path, resolve=False)

        if parsed_path is None:
            raise LoaderError("Missing URI connection details")

        self._params = dict(parse_qsl(parsed_path.query, keep_blank_values=False))

    @staticmethod
    def detect(path: Path) -> bool:
        return False

    def map(self, target: Target) -> None:
        raise NotImplementedError("Subclasses must implement this method")


def map_shell(target: Target, fs: Filesystem, path: str, map: str, os: str) -> None:
    # If we have a path component, use that and try to find a loader for it
    if path not in ("", "/"):
        path = fs.path(path)

        if loader := find_loader(path, fallbacks=[DirLoader, RawLoader]):
            loader(path).map(target)

    # Otherwise, try one of the mapping methods
    elif map == "dir":
        target.filesystems.add(fs)

    # Try to load the local disks, emulating the local loader
    elif map == "local":
        root = fs.path("/")

        # ESXi
        if root.joinpath("vmfs/devices/disks").exists():
            map_esxi_drives(root, target)

        # Solaris
        elif root.joinpath("dev/dsk").exists():
            map_solaris_drives(root, target)

        # Linux
        elif root.joinpath("dev").exists():
            map_linux_drives(root, target)

    if os != "auto":
        for descriptor in os_plugins():
            if descriptor.module.split(".")[-2] == os:
                target._os_plugin = descriptor.cls
                break
